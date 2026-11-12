"""Request handling for ``acb.broker.v1``, independent of sockets.

``Broker.respond`` is the whole request path: validate, attribute the caller
(advisory), dispatch, and encode — with the value rule checked on the way out
(``protocol.encode_response``). The server only moves bytes and peer
credentials.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import provenance
from ..model import Action, ActionResult
from .config import BrokerCapability, BrokerConfig
from .harness import Attribution, attribute
from .issuers import IssueContext, Issuer, IssuerError
from .protocol import (
    FRONT_ENDS,
    ErrorCode,
    ProtocolError,
    decode_body,
    encode_response,
    error_response,
    ok_response,
    validate_request,
)
from .registry import Checkout, Registry, new_checkout_id

log = logging.getLogger("acb.broker")

#: A helper call reuses a live checkout with at least this much life left, so
#: `git fetch && git push` does not mint two credentials.
REUSE_MIN_REMAINING = 60.0


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


def provenance_events(kind: str, co: Checkout, result: str, detail: str) -> None:
    """Value-free provenance for every checkout/revoke (non-blocking: never raises)."""
    try:
        provenance.emit(
            ActionResult(
                action=Action(
                    capability=co.capability,
                    harness=co.harness,
                    kind=kind,
                    target=co.id,
                    summary=(
                        f"{kind} {co.capability} via {co.issuer_kind} "
                        f"(session {co.session}, assurance {co.assurance})"
                    ),
                ),
                status=result,
                detail=detail,
            ),
            purpose="acb-broker",
        )
    except Exception as exc:
        log.warning("provenance emit failed: %s", type(exc).__name__)


class Broker:
    def __init__(
        self,
        config: BrokerConfig,
        registry: Registry,
        issuers: Mapping[str, Issuer],
        *,
        attribute_fn: Callable[[int | None, str | None], Attribution] = attribute,
        clock: Callable[[], float] = time.time,
        socket_path: Path | None = None,
    ) -> None:
        self.config = config
        self.registry = registry
        self.issuers = issuers
        self._attribute = attribute_fn
        self._clock = clock
        self.socket_path = socket_path
        self.started_at = clock()

    # ------------------------------------------------------------ entry points

    def respond(self, body: bytes, peer: Peer) -> bytes:
        """Raw request body in, encoded response frame out. Never raises."""
        method: str | None = None
        front_end: str | None = None
        try:
            raw = decode_body(body)
            req = validate_request(raw)
            method, front_end = req["method"], req["front_end"]
            resp = self._dispatch(req, peer)
        except ProtocolError as exc:
            resp = error_response(exc.code, exc.message)
        try:
            return encode_response(method or "", front_end, resp)
        except ProtocolError as exc:
            log.error("response rejected by the value rule: %s", exc.message)
            return encode_response("", None, error_response(ErrorCode.INTERNAL, exc.message))

    def handle(self, raw: dict[str, Any], peer: Peer) -> dict[str, Any]:
        """Decoded-request convenience for tests: same path, minus framing."""
        try:
            req = validate_request(raw)
        except ProtocolError as exc:
            return error_response(exc.code, exc.message)
        return self._dispatch(req, peer)

    def _dispatch(self, req: dict[str, Any], peer: Peer) -> dict[str, Any]:
        method = req["method"]
        try:
            if method == "checkout":
                return self._checkout(req, peer)
            if method == "revoke":
                return self._revoke(req, peer)
            if method == "list":
                p = req["params"]
                return ok_response(
                    {"checkouts": self.registry.listing(
                        capability=p["capability"], session=p["session"]
                    )}
                )
            return ok_response(self._status())
        except IssuerError as exc:
            return error_response(exc.code, exc.message)
        except ProtocolError as exc:
            return error_response(exc.code, exc.message)
        except Exception as exc:
            # Type name only: an exception message is not guaranteed value-free.
            log.error("internal error in %s: %s", method, type(exc).__name__)
            return error_response(ErrorCode.INTERNAL, f"internal error ({type(exc).__name__})")

    # ------------------------------------------------------------ helpers

    def _caller(self, req: dict[str, Any], peer: Peer) -> tuple[Attribution, str]:
        attr = self._attribute(peer.pid, req["harness_hint"])
        session = req["session"]
        if session is None:
            session = (
                f"{attr.harness}-{attr.anchor_pid}-{attr.anchor_start}"
                if attr.anchor_pid is not None
                else f"adhoc-{attr.harness}"
            )
        return attr, session

    def _resolve(self, params: dict[str, Any]) -> BrokerCapability:
        cap_id = params.get("capability")
        if cap_id is not None:
            cap = self.config.capabilities.get(cap_id)
            if cap is None:
                raise ProtocolError(
                    ErrorCode.UNKNOWN_CAPABILITY,
                    f"{cap_id!r} is not a broker-served capability",
                )
            return cap
        match = params["match"]
        found = self.config.match(match["tool"], match.get("host"))
        if found is None:
            raise ProtocolError(
                ErrorCode.NO_MATCH, f"no capability is delivered to {match['tool']} for that host"
            )
        return found

    # ------------------------------------------------------------ methods

    def _checkout(self, req: dict[str, Any], peer: Peer) -> dict[str, Any]:
        params = req["params"]
        front_end = req["front_end"]
        cap = self._resolve(params)
        attr, session = self._caller(req, peer)
        if cap.harnesses and attr.harness not in cap.harnesses:
            raise ProtocolError(
                ErrorCode.HARNESS_NOT_ALLOWED,
                f"{cap.id} is not declared for harness {attr.harness!r} (advisory allowlist)",
            )
        if front_end is not None:
            tool = FRONT_ENDS[front_end]
            if cap.delivery.rung != "helper" or cap.delivery.tool != tool:
                raise ProtocolError(
                    ErrorCode.DELIVERY_MISMATCH,
                    f"{cap.id} is not delivered by the {tool} helper",
                )
        issuer = self.issuers.get(cap.issuer.kind)
        if issuer is None:
            raise IssuerError(
                ErrorCode.ISSUER_ERROR,
                f"issuer kind {cap.issuer.kind!r} is not available in this broker",
            )
        ttl = cap.issuer.ttl if params["ttl"] is None else min(cap.issuer.ttl, params["ttl"])

        found = self.registry.find_reusable(
            cap.id, session, attr.harness, min_remaining=min(REUSE_MIN_REMAINING, ttl / 4)
        )
        if found is not None:
            co, value = found
        else:
            ctx = IssueContext(capability_id=cap.id, harness=attr.harness, session=session, ttl=ttl)
            issued = issuer.issue(cap, ctx)
            now = self._clock()
            co = Checkout(
                id=new_checkout_id(),
                capability=cap.id,
                harness=attr.harness,
                session=session,
                issued_at=now,
                expires_at=now + max(1, min(ttl, issued.ttl)),
                issuer_kind=cap.issuer.kind,
                assurance=cap.effective_assurance,
                revocation_handle=issued.revocation_handle,
                accessor=issued.accessor,
                anchor_pid=attr.anchor_pid,
                anchor_start=attr.anchor_start,
                value=dict(issued.value_fields),
            )
            value = dict(issued.value_fields)
            self.registry.add(co)

        result = co.metadata()
        result["reused"] = found is not None
        result["harness_source"] = attr.source
        if front_end is None:
            return ok_response(result)
        # Rung 1 by design: the helper hands this value to git/kubectl.
        result["value"] = value
        if cap.delivery.username is not None:
            result["username"] = cap.delivery.username
        return ok_response(result, carries_secret=True)

    def _revoke(self, req: dict[str, Any], peer: Peer) -> dict[str, Any]:
        p = req["params"]
        session: str | None = None
        if p["own_session"]:
            _, session = self._caller(req, peer)
        if p["all"]:
            targets = self.registry.select(session=session)
        elif p["checkout_id"] is not None:
            targets = self.registry.select(checkout_id=p["checkout_id"], session=session)
            if not targets:
                raise ProtocolError(ErrorCode.NOT_FOUND, f"no checkout {p['checkout_id']!r}")
        else:
            cap = self._resolve(p)
            targets = self.registry.select(capability=cap.id, session=session)
        if p["dry_run"]:
            return ok_response(
                {"dry_run": True, "would_revoke": [c.metadata() for c in targets]}
            )
        ids = [c.id for c in targets]
        done = self.registry.revoke(ids, reason="requested")
        return ok_response(
            {"dry_run": False, "revoked": done, "pending": [i for i in ids if i not in done]}
        )

    def _status(self) -> dict[str, Any]:
        live, pending = self.registry.counts()
        now = self._clock()
        return {
            "protocol": "acb.broker.v1",
            "pid": os.getpid(),
            "uptime_s": int(now - self.started_at),
            "live_checkouts": live,
            "revoke_pending": pending,
            "manifest": str(self.config.source) if self.config.source else None,
            "socket": str(self.socket_path) if self.socket_path else None,
            "state_file": str(self.registry.state_path),
            "issuers": sorted(self.issuers),
            "capabilities": [
                {
                    "id": c.id,
                    "issuer": c.issuer.kind,
                    "rung": c.delivery.rung,
                    "tool": c.delivery.tool,
                    "assurance": c.assurance,
                    "effective_assurance": c.effective_assurance,
                    "meets_floor": c.meets_floor,
                    "issuer_available": c.issuer.kind in self.issuers,
                }
                for c in sorted(self.config.capabilities.values(), key=lambda c: c.id)
            ],
        }


__all__ = ["REUSE_MIN_REMAINING", "Broker", "Peer", "provenance_events"]
