"""Socket client for ``acb.broker.v1``: used by the helper front-ends and the
read/act functions the CLI will wire up (``acb checkouts`` / ``acb revoke``).

Fails closed: if the broker is unreachable, every call raises
:class:`BrokerUnavailable`; nothing here ever falls back to another source.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any

from .paths import default_socket_path
from .protocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    PROTOCOL,
    ProtocolError,
    make_request,
    read_frame,
    write_frame,
)

#: Helpers sit in front of git/kubectl; a hung broker must not hang them for long.
DEFAULT_TIMEOUT = 5.0


class BrokerUnavailable(Exception):
    """The broker could not be reached or did not answer. Message is value-free."""


class BrokerError(Exception):
    """The broker answered with an error envelope."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def call(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    front_end: str | None = None,
    socket_path: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[dict[str, Any], bool]:
    """One request, one response. Returns ``(result, carries_secret)``.

    The advisory ``ACB_SESSION_ID`` / ``ACB_HARNESS`` of the calling
    environment are forwarded; the broker prefers its own process-tree
    attribution over the hint.
    """
    path = socket_path or default_socket_path()
    req = make_request(
        method,
        params,
        front_end=front_end,
        session=os.environ.get("ACB_SESSION_ID") or None,
        harness_hint=os.environ.get("ACB_HARNESS") or None,
    )
    family = getattr(socket, "AF_UNIX", None)
    if family is None:
        raise BrokerUnavailable("this platform has no unix sockets; acb-broker is Linux-only")
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.connect(str(path))
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            raise BrokerUnavailable(f"acb-broker is not reachable at {path} ({reason})") from exc
        try:
            write_frame(sock, req, limit=MAX_REQUEST_BYTES)
            resp = read_frame(sock, limit=MAX_RESPONSE_BYTES)
        except ProtocolError as exc:
            raise BrokerUnavailable(f"bad response from acb-broker ({exc.code})") from exc
        except OSError as exc:
            raise BrokerUnavailable(
                f"acb-broker did not answer ({type(exc).__name__})"
            ) from exc
    finally:
        sock.close()
    if resp.get("v") != PROTOCOL or not isinstance(resp.get("ok"), bool):
        raise BrokerUnavailable("acb-broker answered with an unknown protocol")
    if not resp["ok"]:
        err = resp.get("error")
        if not isinstance(err, dict):
            raise BrokerUnavailable("acb-broker answered with a malformed error")
        raise BrokerError(str(err.get("code", "unknown")), str(err.get("message", "")))
    result = resp.get("result")
    if not isinstance(result, dict):
        raise BrokerUnavailable("acb-broker answered with a malformed result")
    return result, resp.get("carries_secret") is True


# ---------------------------------------------------------------- CLI-facing functions
# The follow-up wires these as `acb checkouts` (read) and `acb revoke` (act).
# None of them requests a value: they never pass a front_end.


def broker_status(*, socket_path: Path | None = None) -> dict[str, Any]:
    result, _ = call("status", socket_path=socket_path)
    return result


def list_checkouts(
    *,
    capability: str | None = None,
    session: str | None = None,
    socket_path: Path | None = None,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {}
    if capability is not None:
        params["capability"] = capability
    if session is not None:
        params["session"] = session
    result, _ = call("list", params, socket_path=socket_path)
    rows = result.get("checkouts", [])
    return [r for r in rows if isinstance(r, dict)]


def revoke_checkouts(
    *,
    checkout_id: str | None = None,
    capability: str | None = None,
    all_checkouts: bool = False,
    dry_run: bool = True,
    socket_path: Path | None = None,
) -> dict[str, Any]:
    """An act: dry-run by default (``dry_run=False`` to revoke). Exactly one selector."""
    params: dict[str, Any] = {"dry_run": dry_run}
    if checkout_id is not None:
        params["checkout_id"] = checkout_id
    if capability is not None:
        params["capability"] = capability
    if all_checkouts:
        params["all"] = True
    result, _ = call("revoke", params, socket_path=socket_path)
    return result


__all__ = [
    "DEFAULT_TIMEOUT",
    "BrokerError",
    "BrokerUnavailable",
    "broker_status",
    "call",
    "list_checkouts",
    "revoke_checkouts",
]
