"""Provenance sink: identity attribution and the value-free event shape."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_capability_broker import provenance
from agent_capability_broker.model import Action, ActionResult


def _result() -> ActionResult:
    return ActionResult(Action("cred:x", "local", "exec", "cred:x", "summary"), "applied", "ok")


@pytest.fixture(autouse=True)
def _state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    for var in ("ACB_AGENT", "USER", "USERNAME"):
        monkeypatch.delenv(var, raising=False)


def _agent() -> str:
    log = provenance.emit(_result())
    return str(json.loads(log.read_text(encoding="utf-8").splitlines()[-1])["agent"])


def test_agent_prefers_explicit_then_user_then_username(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _agent() == "unknown"
    monkeypatch.setenv("USERNAME", "win-user")  # Windows has USERNAME, not USER
    assert _agent() == "win-user"
    monkeypatch.setenv("USER", "posix-user")
    assert _agent() == "posix-user"
    monkeypatch.setenv("ACB_AGENT", "harness-a")
    assert _agent() == "harness-a"


def test_emit_appends_one_json_line_per_event(tmp_path: Path) -> None:
    provenance.emit(_result())
    log = provenance.emit(_result())
    lines = log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    event = json.loads(lines[0])
    assert event["capability"] == "cred:x" and event["result"] == "applied"
    assert set(event) == {
        "ts", "agent", "capability", "harness", "action", "target",
        "summary", "result", "detail", "purpose",
    }
