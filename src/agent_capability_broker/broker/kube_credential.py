"""``acb-kube-credential <capability>``: a client-go exec credential plugin.

Kubeconfig (rendered by a later ``install-harness``)::

    users:
    - name: agent
      user:
        exec:
          apiVersion: client.authentication.k8s.io/v1
          command: acb-kube-credential
          args: ["cred:example-k8s"]
          interactiveMode: Never

Prints one ``ExecCredential`` with ``status.token`` and
``status.expirationTimestamp``; kubectl caches it until expiry and calls again.
A thin client: no policy, no fallback. If the broker is down it prints one
line to stderr, nothing to stdout, and exits 1.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

from .client import BrokerError, BrokerUnavailable, call

PROG = "acb-kube-credential"
API_VERSION = "client.authentication.k8s.io/v1"


def _err(stderr: IO[str], msg: str, code: int = 1) -> int:
    stderr.write(f"{PROG}: {msg}\n")
    return code


def main(
    argv: list[str] | None = None,
    *,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    socket_path: Path | None = None,
) -> int:
    args = sys.argv[1:] if argv is None else argv
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    if len(args) != 1 or not args[0] or args[0].startswith("-"):
        return _err(stderr, "usage: acb-kube-credential <capability>", 2)
    capability = args[0]
    try:
        result, carries_secret = call(
            "checkout", {"capability": capability}, front_end="kube", socket_path=socket_path
        )
    except BrokerUnavailable as exc:
        return _err(stderr, str(exc))
    except BrokerError as exc:
        return _err(stderr, f"checkout refused: {exc.code}: {exc.message}")
    value = result.get("value")
    token = value.get("token") if isinstance(value, dict) else None
    if not carries_secret or not isinstance(token, str) or not token:
        return _err(stderr, f"{capability} did not yield a token")
    status: dict[str, str] = {"token": token}
    expires = result.get("expires_at")
    if isinstance(expires, (int, float)) and not isinstance(expires, bool):
        status["expirationTimestamp"] = (
            datetime.fromtimestamp(int(expires), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        )
    cred = {"apiVersion": API_VERSION, "kind": "ExecCredential", "status": status}
    stdout.write(json.dumps(cred) + "\n")
    stdout.flush()
    return 0



__all__ = ["API_VERSION", "main"]
