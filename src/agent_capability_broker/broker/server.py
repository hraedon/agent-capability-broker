"""``acb-broker``: the AF_UNIX server and process entry point. Linux only.

- Socket in a 0700 directory the broker owns; the socket itself is 0600.
- Peer credentials from ``SO_PEERCRED``; a peer whose uid is neither the
  broker's nor root's is refused before its request is read.
- One request per connection, bounded by a per-connection deadline and a
  bounded worker pool (excess connections get ``busy``).
- Core dumps disabled and the process marked non-dumpable at startup.
- A reaper thread revokes expired / session-ended checkouts.
- SIGTERM / SIGINT: stop accepting, drain briefly, revoke every live checkout,
  remove the socket.

The trust boundary is the VM (Plan 012 §1): root inside it is accepted and
can read this process's memory. The uid check only keeps *other* non-root
users of the VM out.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import logging
import os
import signal
import socket
import stat
import struct
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from types import FrameType

from .protocol import (
    MAX_REQUEST_BYTES,
    ErrorCode,
    ProtocolError,
    encode_response,
    error_response,
)
from .service import Broker, Peer

log = logging.getLogger("acb.broker")

DEFAULT_CONN_TIMEOUT = 5.0
DEFAULT_MAX_WORKERS = 16
DEFAULT_REAP_INTERVAL = 5.0
_HEADER = struct.Struct(">I")
_PR_SET_DUMPABLE = 4


class BrokerStartupError(RuntimeError):
    """The broker cannot start safely (bad socket dir, already running, ...)."""


_POSIX_ONLY = "acb-broker is POSIX-only (it needs AF_UNIX peer credentials and uids)"
# Every function below that touches an AF_UNIX / uid / rlimit API opens with
# `if sys.platform == "win32": raise ...`. That is not just a runtime refusal:
# mypy narrows on a literal `sys.platform` comparison, so the POSIX-only
# attributes are not type-checked (and not reported missing) on the Windows lane.


def peercred(conn: socket.socket) -> Peer:
    """``SO_PEERCRED`` on Linux: the connecting process's pid/uid/gid."""
    if sys.platform == "win32":
        raise BrokerStartupError(_POSIX_ONLY)
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return Peer(pid=pid, uid=uid, gid=gid)


def harden_process() -> list[str]:
    """No core dumps; non-dumpable (keeps same-uid, non-root ptrace and /proc/<pid>/mem out).

    Best effort; returns what could not be applied. Root in the VM is not
    stopped by either — that is the accepted boundary.
    """
    if sys.platform == "win32":
        return ["RLIMIT_CORE", "PR_SET_DUMPABLE"]  # neither exists; nothing was applied
    failed: list[str] = []
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError):
        failed.append("RLIMIT_CORE")
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            failed.append("PR_SET_DUMPABLE")
    except (OSError, AttributeError):
        failed.append("PR_SET_DUMPABLE")
    return failed


def _default_allowed_uids() -> frozenset[int]:
    """The broker's own uid and root's (the VM is the trust boundary)."""
    if sys.platform == "win32":
        raise BrokerStartupError(_POSIX_ONLY)
    return frozenset({os.geteuid(), 0})


def _prepare_socket_dir(directory: Path) -> None:
    if sys.platform == "win32":
        raise BrokerStartupError(_POSIX_ONLY)
    euid = os.geteuid()
    if not directory.exists():
        directory.mkdir(mode=0o700, parents=True)
    st = os.lstat(directory)
    if not stat.S_ISDIR(st.st_mode):
        raise BrokerStartupError(f"socket directory {directory} is not a directory")
    if st.st_uid != euid:
        raise BrokerStartupError(
            f"socket directory {directory} is owned by uid {st.st_uid}, not {euid}"
        )
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.chmod(directory, 0o700)


def _clear_stale_socket(path: Path) -> None:
    if sys.platform == "win32":
        raise BrokerStartupError(_POSIX_ONLY)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(st.st_mode):
        raise BrokerStartupError(f"{path} exists and is not a socket; refusing to replace it")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(0.5)
    try:
        probe.connect(str(path))
    except OSError:
        os.unlink(path)  # nobody listening: a leftover from a crash
        return
    finally:
        probe.close()
    raise BrokerStartupError(f"another broker is already listening on {path}")


class BrokerServer:
    def __init__(
        self,
        broker: Broker,
        socket_path: Path,
        *,
        peer_cred: Callable[[socket.socket], Peer] = peercred,
        conn_timeout: float = DEFAULT_CONN_TIMEOUT,
        max_workers: int = DEFAULT_MAX_WORKERS,
        reap_interval: float = DEFAULT_REAP_INTERVAL,
        allowed_uids: frozenset[int] | None = None,
    ) -> None:
        self.broker = broker
        self.socket_path = socket_path
        self._peer_cred = peer_cred
        self._timeout = conn_timeout
        self._slots = threading.BoundedSemaphore(max_workers)
        self._reap_interval = reap_interval
        self._allowed = allowed_uids if allowed_uids is not None else _default_allowed_uids()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._workers: set[threading.Thread] = set()
        self._workers_lock = threading.Lock()
        self._reaper: threading.Thread | None = None
        self._closed = False

    # ------------------------------------------------------------ lifecycle

    def bind(self) -> None:
        if sys.platform == "win32":
            raise BrokerStartupError(_POSIX_ONLY)
        _prepare_socket_dir(self.socket_path.parent)
        _clear_stale_socket(self.socket_path)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            sock.bind(str(self.socket_path))
        finally:
            os.umask(old)
        os.chmod(self.socket_path, 0o600)
        sock.listen(64)
        sock.settimeout(0.25)
        self._sock = sock
        log.info("listening on %s", self.socket_path)

    def start_reaper(self) -> None:
        def loop() -> None:
            while not self._stop.wait(self._reap_interval):
                try:
                    self.broker.registry.reap()
                except Exception as exc:
                    log.error("reaper error: %s", type(exc).__name__)

        self._reaper = threading.Thread(target=loop, name="acb-broker-reaper", daemon=True)
        self._reaper.start()

    def stop(self) -> None:
        self._stop.set()

    def serve_forever(self) -> None:
        if self._sock is None:
            raise BrokerStartupError("bind() first")
        self.start_reaper()
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            if not self._slots.acquire(blocking=False):
                self._reply_and_close(conn, error_response(ErrorCode.BUSY, "broker is busy"))
                continue
            t = threading.Thread(target=self._worker, args=(conn,), daemon=True)
            with self._workers_lock:
                self._workers.add(t)
            t.start()

    def close(self, *, drain: float = 2.0) -> list[str]:
        """Stop, drain in-flight requests briefly, revoke everything, remove the socket."""
        if self._closed:
            return []
        self._closed = True
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
        deadline = time.monotonic() + drain
        with self._workers_lock:
            workers = list(self._workers)
        for t in workers:
            t.join(max(0.0, deadline - time.monotonic()))
        if self._reaper is not None:
            self._reaper.join(1.0)
        revoked = self.broker.registry.revoke_all(reason="shutdown")
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        log.info("shut down; revoked %d checkout(s)", len(revoked))
        return revoked

    # ------------------------------------------------------------ connections

    def _reply_and_close(self, conn: socket.socket, resp: dict[str, object]) -> None:
        """Send an error envelope without reading the request, then close.

        The unread request is drained (bounded) first: on Linux, closing an
        AF_UNIX socket with unread data resets the peer, which could make the
        client miss the envelope we just sent.
        """
        try:
            conn.settimeout(self._timeout)
            conn.sendall(encode_response("", None, dict(resp)))
            conn.shutdown(socket.SHUT_WR)
            conn.settimeout(0.2)
            budget = MAX_REQUEST_BYTES + _HEADER.size
            while budget > 0:
                chunk = conn.recv(min(budget, 65536))
                if not chunk:
                    break
                budget -= len(chunk)
        except OSError:
            pass
        finally:
            conn.close()

    def _worker(self, conn: socket.socket) -> None:
        try:
            self.handle_connection(conn)
        finally:
            self._slots.release()
            with self._workers_lock:
                self._workers.discard(threading.current_thread())

    def handle_connection(self, conn: socket.socket) -> None:
        try:
            try:
                peer = self._peer_cred(conn)
            except OSError:
                self._reply_and_close(
                    conn, error_response(ErrorCode.FORBIDDEN_PEER, "no peer credentials")
                )
                return
            if peer.uid not in self._allowed:
                log.warning("refused peer uid %d (pid %d)", peer.uid, peer.pid)
                self._reply_and_close(
                    conn,
                    error_response(ErrorCode.FORBIDDEN_PEER, "peer uid is not allowed"),
                )
                return
            deadline = time.monotonic() + self._timeout
            try:
                body = _read_body(conn, deadline)
            except ProtocolError as exc:
                self._reply_and_close(conn, error_response(exc.code, exc.message))
                return
            except TimeoutError:
                self._reply_and_close(
                    conn, error_response(ErrorCode.TIMEOUT, "request not received in time")
                )
                return
            except OSError:
                return
            reply = self.broker.respond(body, peer)
            conn.settimeout(max(0.05, deadline - time.monotonic()) + self._timeout)
            try:
                conn.sendall(reply)
            except OSError:
                pass
        finally:
            conn.close()


def _read_body(conn: socket.socket, deadline: float) -> bytes:
    """One frame's body, under a whole-request deadline (no slow-loris holds a slot)."""

    def recv_exact(n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            conn.settimeout(remaining)
            chunk = conn.recv(min(n - len(buf), 65536))
            if not chunk:
                raise ProtocolError(
                    ErrorCode.BAD_FRAME, f"connection closed after {len(buf)} of {n} bytes"
                )
            buf.extend(chunk)
        return bytes(buf)

    (length,) = _HEADER.unpack(recv_exact(_HEADER.size))
    if length > MAX_REQUEST_BYTES:
        raise ProtocolError(
            ErrorCode.TOO_LARGE, f"request of {length} bytes exceeds {MAX_REQUEST_BYTES}"
        )
    if length == 0:
        raise ProtocolError(ErrorCode.BAD_FRAME, "empty frame")
    return recv_exact(length)


# ---------------------------------------------------------------- entry point


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="acb-broker",
        description="In-VM credential broker (acb.broker.v1 on a unix socket).",
    )
    p.add_argument("--manifest", "-m", help="capabilities.toml (default: acb's usual search)")
    p.add_argument("--socket", help="socket path (default: $ACB_BROKER_SOCKET or runtime dir)")
    p.add_argument("--state-file", help="checkout state file (default: $ACB_BROKER_STATE)")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p


def main(argv: list[str] | None = None) -> int:
    if not sys.platform.startswith("linux"):
        print(
            "acb-broker: unsupported platform "
            f"({sys.platform}); the broker needs Linux (AF_UNIX + SO_PEERCRED)",
            file=sys.stderr,
        )
        return 2
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        stream=sys.stderr,
        format="%(asctime)s acb-broker %(levelname)s %(message)s",
    )
    for what in harden_process():
        log.warning("could not apply %s hardening", what)

    from .config import BrokerConfigError, load_broker_config
    from .issuers import default_issuers
    from .paths import default_socket_path, default_state_path
    from .registry import Registry
    from .service import provenance_events

    try:
        config = load_broker_config(args.manifest)
    except BrokerConfigError as exc:
        print(f"acb-broker: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:  # ManifestError (no manifest found, ...)
        print(f"acb-broker: {exc}", file=sys.stderr)
        return 2
    socket_path = Path(args.socket) if args.socket else default_socket_path()
    state_path = Path(args.state_file) if args.state_file else default_state_path()

    issuers = default_issuers()
    registry = Registry(state_path, issuers, events=provenance_events)
    registry.recover()
    broker = Broker(config, registry, issuers, socket_path=socket_path)
    server = BrokerServer(broker, socket_path)
    try:
        server.bind()
    except (BrokerStartupError, OSError) as exc:
        print(f"acb-broker: {exc}", file=sys.stderr)
        return 1

    def on_signal(signum: int, frame: FrameType | None) -> None:
        server.stop()

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)
    log.info("serving %d capability(ies) from %s", len(config.capabilities), config.source)
    try:
        server.serve_forever()
    finally:
        server.close()
    return 0


__all__ = [
    "BrokerServer",
    "BrokerStartupError",
    "harden_process",
    "main",
    "peercred",
]
