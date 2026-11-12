"""``acb.broker.v1`` — the broker's local IPC protocol. Stdlib-only.

Wire format: one request per connection. Each direction carries exactly one
frame — a 4-byte big-endian unsigned length followed by that many bytes of
UTF-8 JSON (an object). No pipelining, no streaming, no keep-alive.

Request::

    {"v": "acb.broker.v1", "method": "checkout" | "revoke" | "status" | "list",
     "params": {...},                       # method-specific, strictly validated
     "front_end": "git" | "kube",           # optional: a helper asking for the value
     "session": "<ACB_SESSION_ID>",         # optional, advisory
     "harness_hint": "<ACB_HARNESS>"}       # optional, advisory

Response::

    {"v": "acb.broker.v1", "ok": true,  "result": {...}, "carries_secret": false}
    {"v": "acb.broker.v1", "ok": false, "error": {"code": "...", "message": "..."}}

**Value rule.** No response carries a secret value except a successful
``checkout`` answered to a helper front-end. That response — and only that
one — has ``carries_secret: true`` and holds the value under
``result.value``. :func:`encode_response` refuses to serialize any other
shape, so the rule is enforced at the one place every response passes
through, and tests can audit it with :func:`response_carries_secret`.
"""

from __future__ import annotations

import json
import socket
import struct
from typing import Any

PROTOCOL = "acb.broker.v1"

#: A request is small: a method, a capability id, a few selectors.
MAX_REQUEST_BYTES = 64 * 1024
#: A response may list many checkouts; still bounded.
MAX_RESPONSE_BYTES = 1024 * 1024

_HEADER = struct.Struct(">I")

METHODS = frozenset({"checkout", "revoke", "status", "list"})
READ_ONLY_METHODS = frozenset({"status", "list"})
#: Helper front-ends allowed to receive a value, and the delivery tool each serves.
FRONT_ENDS: dict[str, str] = {"git": "git", "kube": "kubectl"}

_REQUEST_KEYS = frozenset({"v", "method", "params", "front_end", "session", "harness_hint"})
_LABEL_MAX = 128
_ID_MAX = 256


class ErrorCode:
    """Stable error codes. Clients may branch on these; never rename one."""

    BAD_FRAME = "bad_frame"
    TOO_LARGE = "too_large"
    BAD_REQUEST = "bad_request"
    UNKNOWN_METHOD = "unknown_method"
    FORBIDDEN_PEER = "forbidden_peer"
    UNKNOWN_CAPABILITY = "unknown_capability"
    NO_MATCH = "no_match"
    HARNESS_NOT_ALLOWED = "harness_not_allowed"
    DELIVERY_MISMATCH = "delivery_mismatch"
    NOT_FOUND = "not_found"
    NOT_IMPLEMENTED = "not_implemented"
    ISSUER_ERROR = "issuer_error"
    BUSY = "busy"
    TIMEOUT = "timeout"
    INTERNAL = "internal"


class ProtocolError(Exception):
    """A request or frame that violates ``acb.broker.v1``. Message is value-free."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------- framing


def encode_frame(obj: dict[str, Any], *, limit: int) -> bytes:
    """Serialize ``obj`` as one length-prefixed frame, refusing anything over ``limit``."""
    body = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(body) > limit:
        raise ProtocolError(ErrorCode.TOO_LARGE, f"frame of {len(body)} bytes exceeds {limit}")
    return _HEADER.pack(len(body)) + body


def decode_body(body: bytes) -> dict[str, Any]:
    """Parse one frame body; it must be a UTF-8 JSON object."""
    try:
        obj = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(ErrorCode.BAD_FRAME, "frame body is not UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise ProtocolError(ErrorCode.BAD_FRAME, "frame body must be a JSON object")
    return obj


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), 65536))
        if not chunk:
            raise ProtocolError(
                ErrorCode.BAD_FRAME, f"connection closed after {len(buf)} of {n} bytes"
            )
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock: socket.socket, *, limit: int) -> dict[str, Any]:
    """Read exactly one frame from ``sock``. The length is checked before the body is read."""
    (length,) = _HEADER.unpack(_recv_exact(sock, _HEADER.size))
    if length > limit:
        raise ProtocolError(ErrorCode.TOO_LARGE, f"frame of {length} bytes exceeds {limit}")
    if length == 0:
        raise ProtocolError(ErrorCode.BAD_FRAME, "empty frame")
    return decode_body(_recv_exact(sock, length))


def write_frame(sock: socket.socket, obj: dict[str, Any], *, limit: int) -> None:
    sock.sendall(encode_frame(obj, limit=limit))


# ---------------------------------------------------------------- requests


def _opt_label(raw: dict[str, Any], key: str, *, max_len: int = _LABEL_MAX) -> str | None:
    val = raw.get(key)
    if val is None:
        return None
    if not isinstance(val, str) or not val or len(val) > max_len or not val.isprintable():
        raise ProtocolError(ErrorCode.BAD_REQUEST, f"{key!r} must be a short printable string")
    return val


def _check_keys(where: str, params: dict[str, Any], allowed: frozenset[str]) -> None:
    extra = set(params) - allowed
    if extra:
        raise ProtocolError(ErrorCode.BAD_REQUEST, f"{where}: unknown key(s) {sorted(extra)}")


def _match(params: dict[str, Any]) -> dict[str, str] | None:
    m = params.get("match")
    if m is None:
        return None
    if not isinstance(m, dict):
        raise ProtocolError(ErrorCode.BAD_REQUEST, "'match' must be an object")
    _check_keys("match", m, frozenset({"tool", "host"}))
    tool = _opt_label(m, "tool")
    if tool is None:
        raise ProtocolError(ErrorCode.BAD_REQUEST, "'match.tool' is required")
    out = {"tool": tool}
    host = _opt_label(m, "host", max_len=_ID_MAX)
    if host is not None:
        out["host"] = host
    return out


def _validate_checkout(params: dict[str, Any]) -> dict[str, Any]:
    _check_keys("checkout", params, frozenset({"capability", "match", "ttl"}))
    cap = _opt_label(params, "capability", max_len=_ID_MAX)
    match = _match(params)
    if (cap is None) == (match is None):
        raise ProtocolError(
            ErrorCode.BAD_REQUEST, "checkout needs exactly one of 'capability' or 'match'"
        )
    ttl = params.get("ttl")
    if ttl is not None and (
        not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 86400
    ):
        raise ProtocolError(ErrorCode.BAD_REQUEST, "'ttl' must be an integer number of seconds")
    return {"capability": cap, "match": match, "ttl": ttl}


def _validate_revoke(params: dict[str, Any]) -> dict[str, Any]:
    _check_keys(
        "revoke",
        params,
        frozenset({"checkout_id", "capability", "match", "all", "own_session", "dry_run"}),
    )
    checkout_id = _opt_label(params, "checkout_id", max_len=_ID_MAX)
    cap = _opt_label(params, "capability", max_len=_ID_MAX)
    match = _match(params)
    all_ = params.get("all", False)
    own = params.get("own_session", False)
    dry = params.get("dry_run", False)
    for key, val in (("all", all_), ("own_session", own), ("dry_run", dry)):
        if not isinstance(val, bool):
            raise ProtocolError(ErrorCode.BAD_REQUEST, f"{key!r} must be a boolean")
    selectors = sum(x is not None for x in (checkout_id, cap, match)) + (1 if all_ else 0)
    if selectors != 1:
        raise ProtocolError(
            ErrorCode.BAD_REQUEST,
            "revoke needs exactly one of 'checkout_id', 'capability', 'match' or 'all'",
        )
    return {
        "checkout_id": checkout_id,
        "capability": cap,
        "match": match,
        "all": all_,
        "own_session": own,
        "dry_run": dry,
    }


def _validate_list(params: dict[str, Any]) -> dict[str, Any]:
    _check_keys("list", params, frozenset({"capability", "session"}))
    return {
        "capability": _opt_label(params, "capability", max_len=_ID_MAX),
        "session": _opt_label(params, "session", max_len=_ID_MAX),
    }


def _validate_status(params: dict[str, Any]) -> dict[str, Any]:
    _check_keys("status", params, frozenset())
    return {}


_VALIDATORS = {
    "checkout": _validate_checkout,
    "revoke": _validate_revoke,
    "list": _validate_list,
    "status": _validate_status,
}


def validate_request(raw: dict[str, Any]) -> dict[str, Any]:
    """Strictly validate a decoded request; return a normalized copy.

    Unknown top-level or param keys are refused (a typo is an error, never a
    silent default).
    """
    if raw.get("v") != PROTOCOL:
        raise ProtocolError(ErrorCode.BAD_REQUEST, f"'v' must be {PROTOCOL!r}")
    _check_keys("request", raw, _REQUEST_KEYS)
    method = raw.get("method")
    if not isinstance(method, str):
        raise ProtocolError(ErrorCode.BAD_REQUEST, "'method' must be a string")
    if method not in METHODS:
        raise ProtocolError(ErrorCode.UNKNOWN_METHOD, f"unknown method {method[:64]!r}")
    params = raw.get("params", {})
    if not isinstance(params, dict):
        raise ProtocolError(ErrorCode.BAD_REQUEST, "'params' must be an object")
    front_end = _opt_label(raw, "front_end")
    if front_end is not None and front_end not in FRONT_ENDS:
        raise ProtocolError(ErrorCode.BAD_REQUEST, f"unknown front_end {front_end!r}")
    if front_end is not None and method not in {"checkout", "revoke"}:
        raise ProtocolError(ErrorCode.BAD_REQUEST, "'front_end' applies to checkout/revoke only")
    return {
        "method": method,
        "params": _VALIDATORS[method](params),
        "front_end": front_end,
        "session": _opt_label(raw, "session", max_len=_ID_MAX),
        "harness_hint": _opt_label(raw, "harness_hint"),
    }


def make_request(
    method: str,
    params: dict[str, Any] | None = None,
    *,
    front_end: str | None = None,
    session: str | None = None,
    harness_hint: str | None = None,
) -> dict[str, Any]:
    req: dict[str, Any] = {"v": PROTOCOL, "method": method, "params": params or {}}
    if front_end is not None:
        req["front_end"] = front_end
    if session:
        req["session"] = session
    if harness_hint:
        req["harness_hint"] = harness_hint
    return req


# ---------------------------------------------------------------- responses


def ok_response(
    result: dict[str, Any], *, carries_secret: bool = False
) -> dict[str, Any]:
    return {"v": PROTOCOL, "ok": True, "result": result, "carries_secret": carries_secret}


def error_response(code: str, message: str) -> dict[str, Any]:
    return {"v": PROTOCOL, "ok": False, "error": {"code": code, "message": message}}


def response_carries_secret(resp: dict[str, Any]) -> bool:
    """True iff ``resp`` is the one shape allowed to hold a value."""
    return bool(resp.get("ok")) and resp.get("carries_secret") is True


def check_response_shape(method: str, front_end: str | None, resp: dict[str, Any]) -> None:
    """Enforce the value rule; raises ``ProtocolError`` on a violation.

    A value (``result.value``) may appear only in a successful ``checkout``
    answered to a helper front-end, and that response must be marked
    ``carries_secret``. Every other response must be unmarked and value-free.
    """
    result = resp.get("result")
    has_value = isinstance(result, dict) and "value" in result
    allowed = method == "checkout" and front_end is not None and bool(resp.get("ok"))
    if has_value and not (allowed and resp.get("carries_secret") is True):
        raise ProtocolError(ErrorCode.INTERNAL, "refusing to send a value on this response")
    if resp.get("carries_secret") is True and not (allowed and has_value):
        raise ProtocolError(ErrorCode.INTERNAL, "carries_secret set on a value-free response")


def encode_response(
    method: str, front_end: str | None, resp: dict[str, Any]
) -> bytes:
    """The single exit point for responses: shape check, then frame."""
    check_response_shape(method, front_end, resp)
    return encode_frame(resp, limit=MAX_RESPONSE_BYTES)


__all__ = [
    "FRONT_ENDS",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "METHODS",
    "PROTOCOL",
    "READ_ONLY_METHODS",
    "ErrorCode",
    "ProtocolError",
    "check_response_shape",
    "decode_body",
    "encode_frame",
    "encode_response",
    "error_response",
    "make_request",
    "ok_response",
    "read_frame",
    "response_carries_secret",
    "validate_request",
    "write_frame",
]
