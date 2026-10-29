"""``acb-git-credential``: git's credential-helper protocol, served by acb-broker.

Configure (rendered by a later ``install-harness``)::

    [credential "https://forge.example"]
        helper = /path/to/acb-git-credential

- ``get``: asks the broker for a checkout of the capability whose
  ``delivery = {rung = "helper", tool = "git", hosts = [...]}`` lists the host;
  prints ``username=`` / ``password=`` / ``password_expiry_utc=``.
- ``store``: no-op (the broker issues; git never stores).
- ``erase``: revokes this session's checkout for the host (git calls it when a
  credential was rejected, so the next ``get`` issues a fresh one).

A thin client: no policy, no manifest reading, no fallback. If the broker is
down it prints one line to stderr, nothing to stdout, and exits 1. A host no
capability serves gets no output and exit 0, so git moves to its next helper.
Only ``https`` is served.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import IO

from .client import BrokerError, BrokerUnavailable, call
from .protocol import ErrorCode

PROG = "acb-git-credential"


def parse_attributes(stream: IO[str]) -> dict[str, str]:
    """``key=value`` lines up to a blank line or EOF. Array keys (``k[]``) are ignored."""
    attrs: dict[str, str] = {}
    for line in stream:
        line = line.rstrip("\r\n")
        if not line:
            break
        key, sep, value = line.partition("=")
        if not sep or key.endswith("[]"):
            continue
        attrs[key] = value
    return attrs


def _clean(value: object) -> str | None:
    # A newline or NUL would let a value inject extra attributes into git.
    if not isinstance(value, str) or not value or "\n" in value or "\0" in value:
        return None
    return value


def _err(stderr: IO[str], msg: str) -> int:
    stderr.write(f"{PROG}: {msg}\n")
    return 1


def main(
    argv: list[str] | None = None,
    *,
    stdin: IO[str] | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    socket_path: Path | None = None,
) -> int:
    args = sys.argv[1:] if argv is None else argv
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    op = args[0] if args else ""
    if op not in {"get", "store", "erase"}:
        return 0  # git's protocol: ignore operations we do not implement
    attrs = parse_attributes(stdin)
    if op == "store":
        return 0
    host = attrs.get("host")
    if not host:
        return 0
    protocol = attrs.get("protocol")
    if protocol is not None and protocol != "https":
        return _err(stderr, f"refusing to serve a credential over {protocol!r} (https only)")
    match = {"tool": "git", "host": host.lower()}

    if op == "erase":
        try:
            call(
                "revoke",
                {"match": match, "own_session": True},
                front_end="git",
                socket_path=socket_path,
            )
        except BrokerUnavailable as exc:
            return _err(stderr, str(exc))
        except BrokerError as exc:
            if exc.code == ErrorCode.NO_MATCH:
                return 0
            return _err(stderr, f"revoke refused: {exc.code}: {exc.message}")
        return 0

    try:
        result, carries_secret = call(
            "checkout", {"match": match}, front_end="git", socket_path=socket_path
        )
    except BrokerUnavailable as exc:
        return _err(stderr, str(exc))
    except BrokerError as exc:
        if exc.code == ErrorCode.NO_MATCH:
            return 0
        return _err(stderr, f"checkout refused: {exc.code}: {exc.message}")
    value = result.get("value")
    if not carries_secret or not isinstance(value, dict):
        return _err(stderr, "broker returned no credential")
    password = _clean(value.get("password")) or _clean(value.get("token"))
    username = _clean(value.get("username")) or _clean(result.get("username"))
    if password is None:
        return _err(stderr, "capability provides no usable 'password' or 'token' field")
    if username is None:
        return _err(stderr, "capability provides no username (set delivery.username)")
    lines = [f"username={username}", f"password={password}"]
    expires = result.get("expires_at")
    if isinstance(expires, (int, float)) and not isinstance(expires, bool):
        lines.append(f"password_expiry_utc={int(expires)}")
    stdout.write("\n".join(lines) + "\n")
    stdout.flush()
    return 0



__all__ = ["main", "parse_attributes"]
