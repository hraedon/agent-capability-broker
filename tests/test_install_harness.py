"""Plan 005 WI-2.1: install-harness command.

One idempotent command that installs acb's shims into a named harness and
verifies each declared capability is reachable. Re-runnable; --dry-run;
reports per-capability status; a missing credential is a named, actionable
status, not a silent skip.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.cli import main


def _setup_oc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, shims: list[str] | None = None
) -> Path:
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    (oc_root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    if shims:
        cmd_dir = oc_root / "command"
        cmd_dir.mkdir()
        for name in shims:
            (cmd_dir / f"{name}.md").write_text("# shim\n", encoding="utf-8")
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    return oc_root


def _cred_manifest(tmp_path: Path) -> Path:
    m = tmp_path / "capabilities.toml"
    m.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    return m


def test_install_harness_creates_shims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])

    out = buf.getvalue()
    assert rc == 0
    assert (tmp_path / "oc" / "command" / "cred-svc-bot.md").is_file()
    assert "present_ok" in out.lower()


def test_install_harness_dry_run_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--dry-run"])

    out = buf.getvalue()
    assert rc == 1
    assert "would apply" in out.lower()
    assert not (tmp_path / "oc" / "command" / "cred-svc-bot.md").exists()


def test_install_harness_rerun_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        rc1 = main(["install-harness", "opencode", "-m", str(manifest)])
    assert rc1 == 0

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc2 = main(["install-harness", "opencode", "-m", str(manifest)])

    assert rc2 == 0
    assert "present_ok" in buf.getvalue().lower()


def test_install_harness_unknown_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _cred_manifest(tmp_path)

    rc = main(["install-harness", "zsh", "-m", str(manifest)])
    assert rc == 2
    assert "unknown harness" in capsys.readouterr().err.lower()


def test_install_harness_missing_credential_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing credential is a named, actionable status, not a silent skip."""
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.delenv("ACB_TEST_SECRET", raising=False)
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])

    out = buf.getvalue()
    assert "applied" in out.lower()          # shim was installed
    assert "present_broken" in out.lower()    # broker unreachable (env not set)
    assert rc == 1


def test_install_harness_reports_per_capability_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["install-harness", "opencode", "-m", str(manifest)])

    out = buf.getvalue()
    assert "cred:svc-bot" in out
    assert "opencode" in out
    assert "present_ok" in out.lower()
    assert "capability status" in out.lower()


def test_install_harness_only_provisions_named_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    (oc_root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    claude_root = tmp_path / "claude"
    claude_root.mkdir()
    (claude_root / "settings.json").write_text('{}', encoding="utf-8")

    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(claude_root / "settings.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["claude", "opencode"]\n',
        encoding="utf-8",
    )

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])
    assert rc == 0

    assert (oc_root / "command" / "cred-svc-bot.md").is_file()
    assert not (claude_root / "skills").exists()


def test_install_harness_provisioned_harness_dry_run_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--dry-run on a fully-provisioned harness reports nothing to install."""
    _setup_oc(tmp_path, monkeypatch, shims=["cred-svc-bot"])
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--dry-run"])

    assert rc == 0
    assert "nothing to install" in buf.getvalue().lower()


def test_install_harness_emits_provenance_for_manual_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MEDIUM-3 fix: manual actions emit provenance (matching reconcile)."""
    # Shim already present but broker unreachable → manual action in the plan.
    _setup_oc(tmp_path, monkeypatch, shims=["cred-svc-bot"])
    monkeypatch.delenv("ACB_TEST_SECRET", raising=False)
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])

    assert rc == 1  # PRESENT_BROKEN
    log = (tmp_path / "state" / "provenance.jsonl").read_text()
    event = json.loads(log.strip())
    assert event["action"] == "manual"
    assert event["result"] == "skipped"
