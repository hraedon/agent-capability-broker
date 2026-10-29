"""Checkout registry: values in memory, revocation metadata on disk.

Each checkout's **value** lives only in this process's memory
(``Checkout.value``). The **state file** holds what revocation needs to
survive a restart — checkout id, capability, harness label, session,
issued/expiry, issuer kind and an opaque revocation handle (e.g. a Vault
lease id) — and never a value. It is JSON, mode 0600, written atomically
(temp file + fsync + rename) under a directory created 0700.

Lifecycle:

- ``recover()`` on startup revokes everything left in the state file (crash
  cleanup). Checkouts whose revocation fails stay recorded as
  ``revoke_pending`` and are retried by the reaper.
- ``reap()`` revokes checkouts past expiry, checkouts whose anchoring harness
  process has exited (session end), and retries pending revocations.
- ``revoke_all()`` runs on graceful shutdown.

A value is dropped from memory the moment its revocation starts, whether or
not the issuer-side revocation succeeds.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .harness import pid_alive
from .issuers import Issuer

log = logging.getLogger("acb.broker")

STATE_SCHEMA = "acb.broker-state.v1"

#: (event kind, checkout, result, detail) -> None. Must not raise; must not block long.
EventSink = Callable[[str, "Checkout", str, str], None]


def _no_events(kind: str, co: Checkout, result: str, detail: str) -> None:
    return None


def new_checkout_id() -> str:
    return "co_" + secrets.token_hex(8)


@dataclass
class Checkout:
    id: str
    capability: str
    harness: str
    session: str
    issued_at: float
    expires_at: float
    issuer_kind: str
    assurance: str
    revocation_handle: str | None = None
    anchor_pid: int | None = None
    anchor_start: int | None = None
    revoke_pending: bool = False
    # In memory only. Never serialized, never in repr, never in metadata().
    value: dict[str, str] | None = field(default=None, repr=False, compare=False)

    _RECORD_KEYS = (
        "id", "capability", "harness", "session", "issued_at", "expires_at",
        "issuer_kind", "assurance", "revocation_handle", "anchor_pid", "anchor_start",
        "revoke_pending",
    )

    def record(self) -> dict[str, Any]:
        """The persisted, value-free form."""
        return {k: getattr(self, k) for k in self._RECORD_KEYS}

    def metadata(self) -> dict[str, Any]:
        """The value-free form returned over IPC (no revocation handle either)."""
        rec = self.record()
        rec.pop("revocation_handle")
        rec.pop("anchor_start")
        rec["live"] = self.value is not None and not self.revoke_pending
        return rec

    @classmethod
    def from_record(cls, rec: object) -> Checkout:
        if not isinstance(rec, dict):
            raise ValueError("checkout record is not an object")
        try:
            co = cls(
                id=str(rec["id"]),
                capability=str(rec["capability"]),
                harness=str(rec.get("harness", "")),
                session=str(rec.get("session", "")),
                issued_at=float(rec["issued_at"]),
                expires_at=float(rec["expires_at"]),
                issuer_kind=str(rec["issuer_kind"]),
                assurance=str(rec.get("assurance", "")),
                revocation_handle=(
                    None if rec.get("revocation_handle") is None
                    else str(rec["revocation_handle"])
                ),
                revoke_pending=bool(rec.get("revoke_pending", False)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("checkout record is malformed") from exc
        return co


def write_state(path: Path, checkouts: Iterable[Checkout]) -> None:
    """Atomically replace the state file with the value-free records."""
    if not path.parent.exists():
        path.parent.mkdir(mode=0o700, parents=True)
    doc = {"schema": STATE_SCHEMA, "checkouts": [co.record() for co in checkouts]}
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".acb-broker-state.", suffix=".tmp")
    try:
        if sys.platform != "win32":
            # mkstemp already creates the file owner-only on POSIX; this makes
            # that explicit. Windows has no fchmod (and no mode bits to set).
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def read_state(path: Path) -> list[Checkout]:
    """Load records; a missing file is empty, a corrupt one is set aside and logged."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    try:
        doc = json.loads(text)
        if not isinstance(doc, dict) or doc.get("schema") != STATE_SCHEMA:
            raise ValueError("unexpected schema")
        raw = doc.get("checkouts", [])
        if not isinstance(raw, list):
            raise ValueError("checkouts is not a list")
    except ValueError:
        aside = path.with_name(f"{path.name}.corrupt-{int(time.time())}")
        try:
            os.replace(path, aside)
        except OSError:
            aside = path
        log.error("broker state file %s is unreadable; set aside as %s", path, aside)
        return []
    out: list[Checkout] = []
    for rec in raw:
        try:
            out.append(Checkout.from_record(rec))
        except ValueError:
            log.error("skipping a malformed checkout record in %s", path)
    return out


class Registry:
    def __init__(
        self,
        state_path: Path,
        issuers: Mapping[str, Issuer],
        *,
        clock: Callable[[], float] = time.time,
        events: EventSink = _no_events,
        alive: Callable[[int, int | None], bool] = pid_alive,
    ) -> None:
        self.state_path = state_path
        self._issuers = issuers
        self._clock = clock
        self._events = events
        self._alive = alive
        self._live: dict[str, Checkout] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------ persistence

    def _persist(self) -> None:
        with self._lock:
            write_state(self.state_path, list(self._live.values()))

    def recover(self) -> list[str]:
        """Revoke everything a previous run left behind. Returns revoked ids."""
        stale = read_state(self.state_path)
        with self._lock:
            for co in stale:
                co.revoke_pending = True  # no value: it died with the old process
                self._live[co.id] = co
        if stale:
            log.info("recovering %d checkout(s) from a previous run", len(stale))
        return self.revoke([co.id for co in stale], reason="recovered")

    # ------------------------------------------------------------ lookups

    def add(self, co: Checkout) -> None:
        if co.value is None:
            raise ValueError("a new checkout must carry its in-memory value")
        with self._lock:
            self._live[co.id] = co
            self._persist()
        self._emit("broker_checkout", co, "applied", "")

    def find_reusable(
        self, capability: str, session: str, harness: str, *, min_remaining: float
    ) -> tuple[Checkout, dict[str, str]] | None:
        """A live checkout this caller can share, with a copy of its value."""
        now = self._clock()
        with self._lock:
            for co in self._live.values():
                if (
                    co.capability == capability
                    and co.session == session
                    and co.harness == harness
                    and co.value is not None
                    and not co.revoke_pending
                    and co.expires_at - now >= min_remaining
                ):
                    return co, dict(co.value)
        return None

    def get(self, checkout_id: str) -> Checkout | None:
        with self._lock:
            return self._live.get(checkout_id)

    def select(
        self,
        *,
        checkout_id: str | None = None,
        capability: str | None = None,
        session: str | None = None,
    ) -> list[Checkout]:
        with self._lock:
            out = list(self._live.values())
        if checkout_id is not None:
            out = [c for c in out if c.id == checkout_id]
        if capability is not None:
            out = [c for c in out if c.capability == capability]
        if session is not None:
            out = [c for c in out if c.session == session]
        return sorted(out, key=lambda c: c.issued_at)

    def listing(
        self, *, capability: str | None = None, session: str | None = None
    ) -> list[dict[str, Any]]:
        return [c.metadata() for c in self.select(capability=capability, session=session)]

    def counts(self) -> tuple[int, int]:
        with self._lock:
            pending = sum(1 for c in self._live.values() if c.revoke_pending)
            return len(self._live) - pending, pending

    # ------------------------------------------------------------ revocation

    def revoke(self, ids: Iterable[str], *, reason: str) -> list[str]:
        """Revoke ``ids``. Returns those fully revoked; failures stay pending."""
        with self._lock:
            targets = [self._live[i] for i in dict.fromkeys(ids) if i in self._live]
            for co in targets:
                co.value = None  # forget the value first, whatever happens next
        done: list[str] = []
        for co in targets:
            issuer = self._issuers.get(co.issuer_kind)
            detail = f"reason={reason}"
            try:
                if issuer is None:
                    raise LookupError(f"issuer kind {co.issuer_kind!r} is not available")
                issuer.revoke(co.revocation_handle)
            except Exception as exc:
                with self._lock:
                    co.revoke_pending = True
                log.warning(
                    "revoke of %s (%s) failed: %s; will retry",
                    co.id, co.capability, type(exc).__name__,
                )
                self._emit("broker_revoke", co, "failed", f"{detail} error={type(exc).__name__}")
                continue
            with self._lock:
                self._live.pop(co.id, None)
            done.append(co.id)
            log.info("revoked %s (%s, %s)", co.id, co.capability, reason)
            self._emit("broker_revoke", co, "applied", detail)
        if targets:
            self._persist()
        return done

    def reap(self) -> list[str]:
        """Expiry, session end, and pending retries. Returns revoked ids."""
        now = self._clock()
        reasons: dict[str, str] = {}
        with self._lock:
            snapshot = list(self._live.values())
        for co in snapshot:
            if co.expires_at <= now:
                reasons.setdefault(co.id, "expired")
            elif co.anchor_pid is not None and not self._alive(co.anchor_pid, co.anchor_start):
                reasons.setdefault(co.id, "session_end")
            elif co.revoke_pending:
                reasons.setdefault(co.id, "retry")
        done: list[str] = []
        for reason in ("expired", "session_end", "retry"):
            ids = [i for i, r in reasons.items() if r == reason]
            if ids:
                done.extend(self.revoke(ids, reason=reason))
        return done

    def revoke_all(self, *, reason: str) -> list[str]:
        with self._lock:
            ids = list(self._live)
        return self.revoke(ids, reason=reason)

    # ------------------------------------------------------------ events

    def _emit(self, kind: str, co: Checkout, result: str, detail: str) -> None:
        try:
            self._events(kind, co, result, detail)
        except Exception as exc:  # provenance is non-blocking by charter
            log.warning("provenance sink failed: %s", type(exc).__name__)


__all__ = [
    "STATE_SCHEMA",
    "Checkout",
    "EventSink",
    "Registry",
    "new_checkout_id",
    "read_state",
    "write_state",
]
