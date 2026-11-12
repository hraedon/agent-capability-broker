"""Suite-wide test isolation.

acb's acting verbs write into harness configuration. A test that forgets to
point a harness somewhere else would write into the developer's real one (this
happened: a `register --apply` test left a skill in a real `~/.claude/skills`).
So every harness location and acb's state directory default to a per-test
temporary path; tests that care set their own.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from agent_capability_broker import cred_vault


@pytest.fixture(autouse=True)
def _isolated_harnesses(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    root: Path = tmp_path_factory.mktemp("harnesses")
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(root / "claude" / "settings.json"))
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(root / "opencode" / "opencode.json"))
    monkeypatch.setenv("ACB_HERMES_CONFIG", str(root / "hermes" / "config.yaml"))
    monkeypatch.setenv("ACB_ZCODE_CONFIG", str(root / "zcode" / "cli" / "config.json"))
    monkeypatch.setenv("ACB_CODEX_HOME", str(root / "codex"))
    monkeypatch.setenv("ACB_CODEX_SKILLS", str(root / "codex-skills"))
    monkeypatch.setenv("ACB_AGY_CONFIG_DIR", str(root / "agy" / "config"))
    monkeypatch.setenv("ACB_STATE_DIR", str(root / "state"))


@pytest.fixture(autouse=True)
def _no_live_grant_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """The grant check behind `doctor` logs in to Vault. Tests that stub
    `reachable` must not fall through to a real login with whatever access
    plane the developer's machine has, so by default the check answers "could
    not be asked". Tests of the check itself call the function they imported,
    or patch it again."""
    monkeypatch.setattr(cred_vault, "read_granted", lambda cap, **_: None)
