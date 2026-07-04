"""Act path: e2e reconcile. Proves the safety invariants (spine §7 / Plan 002).

Crucially: a reconcile that pins the Playwright launcher must leave a sibling
server's bearer token intact, write nothing in dry-run, be idempotent, and emit
provenance that contains no secret.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_capability_broker.adapters import OpencodeAdapter
from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability
from agent_capability_broker.providers import E2eProvider

SECRET = "Bearer super-secret-token-value"

CAP = Capability(
    id="e2e:chromium", provider="e2e", harnesses=("opencode",), options={"pin": "1.43.0"}
)


def _config_with_token(tmp_path: Path) -> Path:
    """An opencode.json with a broken Playwright block AND a token-bearing sibling."""
    cfg = {
        "mcp": {
            "sibling": {"type": "remote", "url": "https://api.example/mcp",
                    "headers": {"Authorization": SECRET}},
            "playwright": {"type": "local", "enabled": True,
                           "command": ["npx", "-y", "@playwright/mcp@latest", "--headless"]},
        }
    }
    p = tmp_path / "opencode.json"
    p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return p


@pytest.fixture
def browsers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "ms-playwright"
    (cache / "chromium-1223").mkdir(parents=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))


def test_plan_emits_pin_action(tmp_path: Path, browsers: None) -> None:
    adapter = OpencodeAdapter(config_path=_config_with_token(tmp_path))
    plan = E2eProvider().plan_reconcile(CAP, "opencode", adapter)
    assert [a.kind for a in plan] == ["pin_npx_version"]
    assert plan[0].payload["argv"] == ["npx", "-y", "@playwright/mcp@1.43.0", "--headless"]


def test_apply_pins_and_preserves_sibling_secret(tmp_path: Path, browsers: None) -> None:
    cfg_path = _config_with_token(tmp_path)
    adapter = OpencodeAdapter(config_path=cfg_path)
    plan = E2eProvider().plan_reconcile(CAP, "opencode", adapter)

    res = E2eProvider().apply(plan[0], adapter)
    assert res.status == "applied" and res.backup_path

    after = json.loads(cfg_path.read_text())
    # launcher pinned...
    assert after["mcp"]["playwright"]["command"][2] == "@playwright/mcp@1.43.0"
    # ...and the sibling's bearer token survived untouched.
    assert after["mcp"]["sibling"]["headers"]["Authorization"] == SECRET
    # backup captured the pre-edit content (still @latest).
    assert "@playwright/mcp@latest" in Path(res.backup_path).read_text()  # type: ignore[arg-type]


def test_apply_is_idempotent(tmp_path: Path, browsers: None) -> None:
    adapter = OpencodeAdapter(config_path=_config_with_token(tmp_path))
    first = E2eProvider().plan_reconcile(CAP, "opencode", adapter)
    E2eProvider().apply(first[0], adapter)
    # Now PRESENT_OK -> empty plan; a stray re-apply is a skipped no-op.
    assert E2eProvider().plan_reconcile(CAP, "opencode", adapter) == []
    again = E2eProvider().apply(first[0], adapter)
    assert again.status == "skipped"


def test_cli_dry_run_writes_nothing(
    tmp_path: Path, browsers: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _config_with_token(tmp_path)
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:chromium"]\nprovider="e2e"\npin="1.43.0"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(cfg))
    before = cfg.read_text()

    rc = main(["reconcile", "-m", str(manifest)])  # no --apply
    assert rc == 1  # an actionable fix remains
    assert cfg.read_text() == before  # untouched
    assert not list(tmp_path.glob("opencode.json.bak-*"))


def test_cli_apply_emits_clean_provenance(
    tmp_path: Path, browsers: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _config_with_token(tmp_path)
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:chromium"]\nprovider="e2e"\npin="1.43.0"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(cfg))
    monkeypatch.setenv("ACB_STATE_DIR", str(state))

    rc = main(["reconcile", "-m", str(manifest), "--apply"])
    assert rc == 0

    log = (state / "provenance.jsonl").read_text()
    event = json.loads(log.strip())
    assert event["action"] == "pin_npx_version"
    assert event["result"] == "applied"
    # provenance must never carry a secret.
    assert SECRET not in log and "Authorization" not in log


def test_reconcile_apply_error_is_handled(
    tmp_path: Path, browsers: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If provider.apply() raises during reconcile --apply, the command reports
    a failure instead of crashing with an unhandled traceback."""
    cfg = _config_with_token(tmp_path)
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:chromium"]\nprovider="e2e"\npin="1.43.0"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(cfg))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

    from agent_capability_broker.providers import E2eProvider

    original_apply = E2eProvider.apply

    def raising_apply(self: E2eProvider, action: object, adapter: object) -> object:
        raise OSError("simulated disk error")

    monkeypatch.setattr(E2eProvider, "apply", raising_apply)

    import io
    from contextlib import redirect_stdout

    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["reconcile", "-m", str(manifest), "--apply"])

        out = buf.getvalue()
        assert "FAILED" in out.upper() or "failed" in out
        assert rc != 0
    finally:
        monkeypatch.setattr(E2eProvider, "apply", original_apply)
