"""Advisory harness attribution from the socket peer's process ancestry.

Plan 011 §6.4: walk from the peer PID up the parent chain to the first known
harness binary; else trust ``ACB_HARNESS`` (sent by the client); else
``shell``. **This is not a security boundary** — any process in the VM can
impersonate any harness. It drives attribution, per-harness accident
prevention, and session anchoring (a checkout bound to a harness process is
revoked when that process exits).

Linux ``/proc`` only. ``proc_root`` is injectable so tests can build a fake
process tree in a tmpdir.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

KNOWN_HARNESSES = ("claude", "codex", "opencode", "zcode")
DEFAULT_LABEL = "shell"
_MAX_DEPTH = 64
_HINT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
_SCRIPT_SUFFIXES = (".js", ".mjs", ".cjs", ".exe")
PROC = Path("/proc")


@dataclass(frozen=True)
class Attribution:
    harness: str
    source: str                   # "process" | "hint" | "default"
    anchor_pid: int | None = None  # the harness process, when found by the walk
    anchor_start: int | None = None  # its start time (clock ticks), guards PID reuse


def proc_stat(pid: int, proc_root: Path = PROC) -> tuple[int, int] | None:
    """``(ppid, starttime)`` for ``pid``, or ``None`` if it is gone/unreadable."""
    try:
        text = (proc_root / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # comm (field 2) may contain spaces and parens; everything after the last ')'
    # is space-separated starting at field 3 (state).
    rest = text.rpartition(")")[2].split()
    try:
        return int(rest[1]), int(rest[19])
    except (IndexError, ValueError):
        return None


def _base(name: str) -> str:
    b = name.rsplit("/", 1)[-1]
    for suffix in _SCRIPT_SUFFIXES:
        if b.endswith(suffix):
            return b[: -len(suffix)]
    return b


def proc_names(pid: int, proc_root: Path = PROC) -> list[str]:
    """Candidate program names: comm, exe basename, argv[0] and argv[1] basenames.

    argv[1] covers interpreter-hosted CLIs (``node .../codex.js``).
    """
    d = proc_root / str(pid)
    names: list[str] = []
    try:
        names.append((d / "comm").read_text(encoding="utf-8", errors="replace").strip())
    except OSError:
        pass
    try:
        names.append(_base(os.readlink(d / "exe")))
    except OSError:
        pass
    try:
        argv = (d / "cmdline").read_bytes().split(b"\0")
        for arg in argv[:2]:
            if arg:
                names.append(_base(arg.decode("utf-8", errors="replace")))
    except OSError:
        pass
    return [n for n in names if n]


def attribute(
    peer_pid: int | None,
    hint: str | None = None,
    *,
    proc_root: Path = PROC,
    known: tuple[str, ...] = KNOWN_HARNESSES,
) -> Attribution:
    """Label the caller. Never raises; worst case is ``shell``."""
    pid = peer_pid
    depth = 0
    while pid is not None and pid > 1 and depth < _MAX_DEPTH:
        stat = proc_stat(pid, proc_root)
        if stat is None:
            break
        for name in proc_names(pid, proc_root):
            if name in known:
                return Attribution(name, "process", pid, stat[1])
        pid = stat[0]
        depth += 1
    if hint and _HINT_RE.match(hint):
        return Attribution(hint, "hint")
    return Attribution(DEFAULT_LABEL, "default")


def pid_alive(pid: int, start: int | None, proc_root: Path = PROC) -> bool:
    """Is the anchored process still the same process? (PID reuse safe via start time.)"""
    stat = proc_stat(pid, proc_root)
    if stat is None:
        return False
    return start is None or stat[1] == start


__all__ = [
    "DEFAULT_LABEL",
    "KNOWN_HARNESSES",
    "Attribution",
    "attribute",
    "pid_alive",
    "proc_names",
    "proc_stat",
]
