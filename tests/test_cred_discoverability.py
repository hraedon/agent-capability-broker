"""Plan 004: cred discoverability = shim presence + broker reachability.

A credential is ABSENT in a harness until that harness exposes a shim surfacing
`acb exec cred:<name>`; once present, broker reachability decides PRESENT_OK vs
PRESENT_BROKEN. Reachability is injected (monkeypatched / env source) so these
run in CI with no live Vault.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker import cred_vault
from agent_capability_broker.adapters import ClaudeAdapter, OpencodeAdapter
from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability, Status
from agent_capability_broker.providers import CredProvider, _cred_shim_name, _render_cred_shim

VAULT_CAP = Capability("cred:svc-bot", "cred", ("opencode",), {"vault": "kv/example/ad/svc-bot"})


def _opencode(root: Path, *, shims: list[str] | None = None) -> OpencodeAdapter:
    if shims is not None:
        (root / "command").mkdir(parents=True, exist_ok=True)
        for name in shims:
            (root / "command" / f"{name}.md").write_text("# shim\n", encoding="utf-8")
    return OpencodeAdapter(config_path=root / "opencode.json")


# --- naming ----------------------------------------------------------------

def test_shim_name_default_and_override() -> None:
    assert _cred_shim_name(VAULT_CAP) == "cred-svc-bot"
    override = Capability("cred:svc-bot", "cred", ("opencode",), {"shim": "my-bot"})
    assert _cred_shim_name(override) == "my-bot"


# --- inspect: the four verdicts -------------------------------------------

def test_inspect_absent_when_no_shim(tmp_path: Path) -> None:
    adapter = _opencode(tmp_path, shims=[])  # command dir exists, but no cred shim
    v = CredProvider().inspect(VAULT_CAP, "opencode", adapter)
    assert v.status is Status.ABSENT
    assert "cred-svc-bot" in v.detail and "acb exec cred:svc-bot" in v.detail


def test_inspect_present_ok_when_shim_and_broker_reachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cred_vault, "reachable", lambda cap: True)
    adapter = _opencode(tmp_path, shims=["cred-svc-bot"])
    v = CredProvider().inspect(VAULT_CAP, "opencode", adapter)
    assert v.status is Status.PRESENT_OK
    assert "shim present" in v.detail


def test_inspect_present_broken_when_shim_but_broker_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cred_vault, "reachable", lambda cap: False)
    adapter = _opencode(tmp_path, shims=["cred-svc-bot"])
    v = CredProvider().inspect(VAULT_CAP, "opencode", adapter)
    assert v.status is Status.PRESENT_BROKEN


def test_inspect_unknown_when_reachability_uncheckable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(cap: Capability) -> bool:
        raise RuntimeError("no [cred] extra")

    monkeypatch.setattr(cred_vault, "reachable", _boom)
    adapter = _opencode(tmp_path, shims=["cred-svc-bot"])
    v = CredProvider().inspect(VAULT_CAP, "opencode", adapter)
    assert v.status is Status.UNKNOWN
    assert "not checked" in v.detail


def test_inspect_env_source_reachability(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cap = Capability("cred:db", "cred", ("opencode",), {"source": "env", "from_env": "ACB_T"})
    adapter = _opencode(tmp_path, shims=["cred-db"])
    monkeypatch.delenv("ACB_T", raising=False)
    assert CredProvider().inspect(cap, "opencode", adapter).status is Status.PRESENT_BROKEN
    monkeypatch.setenv("ACB_T", "x")
    assert CredProvider().inspect(cap, "opencode", adapter).status is Status.PRESENT_OK


# --- render ----------------------------------------------------------------

def test_render_shim_per_harness_carries_no_secret() -> None:
    ve = Path("/tmp/vault.env")
    claude = _render_cred_shim(VAULT_CAP, "claude", "cred-svc-bot", ve)
    opencode = _render_cred_shim(VAULT_CAP, "opencode", "cred-svc-bot", ve)
    assert claude.startswith("---\nname: cred-svc-bot\n")  # Claude SKILL.md needs name:
    assert "name:" not in opencode.split("---\n\n")[0]      # opencode command does not
    for text in (claude, opencode):
        assert "acb exec cred:svc-bot" in text
        assert "ACB_VAULT_ENV=" in text  # per-harness AppRole resolution
        # the vault *path* may appear, but never a secret value (there is none here)
        assert "password" not in text.lower()


# --- reconcile: render the missing shim ------------------------------------

def test_plan_absent_renders_add_cred_shim(tmp_path: Path) -> None:
    adapter = _opencode(tmp_path, shims=[])
    plan = CredProvider().plan_reconcile(VAULT_CAP, "opencode", adapter)
    assert [a.kind for a in plan] == ["add_cred_shim"]
    assert "acb exec cred:svc-bot" in str(plan[0].payload["content"])


def test_plan_present_ok_is_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cred_vault, "reachable", lambda cap: True)
    adapter = _opencode(tmp_path, shims=["cred-svc-bot"])
    assert CredProvider().plan_reconcile(VAULT_CAP, "opencode", adapter) == []


def test_plan_broken_broker_is_manual(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cred_vault, "reachable", lambda cap: False)
    adapter = _opencode(tmp_path, shims=["cred-svc-bot"])
    plan = CredProvider().plan_reconcile(VAULT_CAP, "opencode", adapter)
    assert plan[0].kind == "manual" and "unreachable" in plan[0].summary


def test_apply_renders_opencode_shim_idempotently(tmp_path: Path) -> None:
    adapter = _opencode(tmp_path, shims=[])
    plan = CredProvider().plan_reconcile(VAULT_CAP, "opencode", adapter)

    res = CredProvider().apply(plan[0], adapter)
    assert res.status == "applied"
    shim_file = tmp_path / "command" / "cred-svc-bot.md"
    assert "acb exec cred:svc-bot" in shim_file.read_text()
    assert adapter.command_shims() == {"cred-svc-bot"}

    # Re-applying is a skipped no-op (never clobbers a hand-editable shim).
    assert CredProvider().apply(plan[0], adapter).status == "skipped"


def test_apply_renders_claude_skill(tmp_path: Path) -> None:
    cap = Capability("cred:svc-bot", "cred", ("claude",))
    adapter = ClaudeAdapter(settings_path=tmp_path / "settings.json")
    plan = CredProvider().plan_reconcile(cap, "claude", adapter)
    CredProvider().apply(plan[0], adapter)
    skill = tmp_path / "skills" / "cred-svc-bot" / "SKILL.md"
    assert skill.is_file() and skill.read_text().startswith("---\nname: cred-svc-bot\n")


# --- CLI end-to-end: ABSENT -> reconcile --apply -> PRESENT_OK -------------

def test_cli_doctor_reconcile_roundtrip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    (oc_root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")  # adapter.available()
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ACB_SECRET", "p@ss-not-leaked")

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_SECRET"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )

    # Before: no shim -> ABSENT -> non-zero exit.
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest)])
    assert rc == 1 and "absent" in buf.getvalue().lower()

    # Reconcile --apply renders the discovery shim.
    with redirect_stdout(io.StringIO()):
        rc = main(["reconcile", "-m", str(manifest), "--apply"])
    assert rc == 0
    assert (oc_root / "command" / "cred-svc-bot.md").is_file()

    # After: shim present + env source set -> PRESENT_OK -> clean exit, no secret leaked.
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest)])
    out = buf.getvalue()
    assert rc == 0 and "present_ok" in out.lower()
    assert "p@ss-not-leaked" not in out
