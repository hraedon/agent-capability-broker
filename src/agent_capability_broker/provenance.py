"""Provenance sink. Stdlib-only.

Every act-path verb emits an event here. This module is the always-available
local fallback (append-only JSONL); a forwarder to regista / agent-provenance is
Plan 002 WI-5 and never blocks an act on the sink being reachable.

By contract an event carries no secret value and no config token — only the
identity of the act (who/which capability/which harness/what action/when/result).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from .model import ActionResult, _user_state_root


def state_dir() -> Path:
    """Where provenance is recorded. Overridable for tests / non-default hosts."""
    env = os.environ.get("ACB_STATE_DIR")
    if env:
        return Path(env)
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg) if xdg else _user_state_root()
    return base / "acb"


def _agent_identity() -> str:
    """Best-effort: which agent/harness performed the act."""
    return os.environ.get("ACB_AGENT") or os.environ.get("USER") or "unknown"


def emit(result: ActionResult, *, purpose: str = "") -> Path:
    """Append one provenance event and return the log path."""
    a = result.action
    event = {
        "ts": datetime.now(UTC).isoformat(),
        "agent": _agent_identity(),
        "capability": a.capability,
        "harness": a.harness,
        "action": a.kind,
        "target": a.target,
        "summary": a.summary,
        "result": result.status,
        "detail": result.detail,
        "purpose": purpose,
    }
    d = state_dir()
    d.mkdir(parents=True, exist_ok=True)
    log = d / "provenance.jsonl"
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")
    return log
