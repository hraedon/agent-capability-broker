"""Where the broker's socket and state file live. Shared by server and clients."""

from __future__ import annotations

import os
from pathlib import Path

from ..provenance import state_dir


def default_socket_path() -> Path:
    """``$ACB_BROKER_SOCKET``, else ``$XDG_RUNTIME_DIR/acb/broker.sock``.

    Without ``XDG_RUNTIME_DIR`` (a system service): ``/run/acb/broker.sock`` for
    root, ``/tmp/acb-<uid>/broker.sock`` otherwise. The server creates the
    directory 0700 and refuses one it does not own.
    """
    env = os.environ.get("ACB_BROKER_SOCKET")
    if env:
        return Path(env)
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        return Path(runtime) / "acb" / "broker.sock"
    uid = os.getuid() if hasattr(os, "getuid") else 0
    if uid == 0:
        return Path("/run/acb/broker.sock")
    return Path(f"/tmp/acb-{uid}/broker.sock")


def default_state_path() -> Path:
    """``$ACB_BROKER_STATE``, else ``<acb state dir>/broker/checkouts.json``."""
    env = os.environ.get("ACB_BROKER_STATE")
    if env:
        return Path(env)
    return state_dir() / "broker" / "checkouts.json"


__all__ = ["default_socket_path", "default_state_path"]
