"""acb.broker.v1 framing, request validation and the value rule (WI-012-3).

Pure protocol: no server, no issuer. Runs on any platform (socketpair).
"""

from __future__ import annotations

import socket
import struct
from typing import Any

import pytest

from agent_capability_broker.broker import protocol as P
from agent_capability_broker.broker.protocol import ErrorCode, ProtocolError


def _pair() -> tuple[socket.socket, socket.socket]:
    a, b = socket.socketpair()
    a.settimeout(2)
    b.settimeout(2)
    return a, b


class TestFraming:
    def test_round_trip(self) -> None:
        a, b = _pair()
        msg = {"v": P.PROTOCOL, "method": "status", "params": {}, "x": "ünïcode"}
        P.write_frame(a, msg, limit=P.MAX_REQUEST_BYTES)
        assert P.read_frame(b, limit=P.MAX_REQUEST_BYTES) == msg
        a.close()
        b.close()

    def test_header_is_four_byte_big_endian(self) -> None:
        frame = P.encode_frame({"a": 1}, limit=100)
        (n,) = struct.unpack(">I", frame[:4])
        assert n == len(frame) - 4 == len(b'{"a":1}')

    def test_encode_refuses_oversize(self) -> None:
        with pytest.raises(ProtocolError) as ei:
            P.encode_frame({"pad": "x" * 200}, limit=100)
        assert ei.value.code == ErrorCode.TOO_LARGE

    def test_read_refuses_oversize_header_before_reading_body(self) -> None:
        a, b = _pair()
        a.sendall(struct.pack(">I", P.MAX_REQUEST_BYTES + 1))  # no body at all
        with pytest.raises(ProtocolError) as ei:
            P.read_frame(b, limit=P.MAX_REQUEST_BYTES)
        assert ei.value.code == ErrorCode.TOO_LARGE
        a.close()
        b.close()

    def test_limits_are_sane(self) -> None:
        assert P.MAX_REQUEST_BYTES == 64 * 1024
        assert P.MAX_RESPONSE_BYTES == 1024 * 1024

    @pytest.mark.parametrize(
        "payload",
        [
            struct.pack(">I", 0),                                 # empty frame
            struct.pack(">I", 10) + b"abc",                       # truncated body
            b"\x00\x00",                                          # truncated header
            struct.pack(">I", 3) + b"\xff\xfe\xfd",               # not UTF-8
            struct.pack(">I", 4) + b"nope",                       # not JSON
            struct.pack(">I", 2) + b"[]",                         # JSON, not an object
        ],
    )
    def test_malformed_frames(self, payload: bytes) -> None:
        a, b = _pair()
        a.sendall(payload)
        a.shutdown(socket.SHUT_WR)
        with pytest.raises(ProtocolError) as ei:
            P.read_frame(b, limit=P.MAX_REQUEST_BYTES)
        assert ei.value.code == ErrorCode.BAD_FRAME
        a.close()
        b.close()


def _req(method: str, params: dict[str, Any] | None = None, **top: Any) -> dict[str, Any]:
    r: dict[str, Any] = {"v": P.PROTOCOL, "method": method, "params": params or {}}
    r.update(top)
    return r


class TestRequestValidation:
    def test_valid_checkout_by_capability(self) -> None:
        out = P.validate_request(_req("checkout", {"capability": "cred:x", "ttl": 60}))
        assert out["params"] == {"capability": "cred:x", "match": None, "ttl": 60}
        assert out["front_end"] is None

    def test_valid_checkout_by_match_from_helper(self) -> None:
        out = P.validate_request(
            _req("checkout", {"match": {"tool": "git", "host": "h"}}, front_end="git")
        )
        assert out["params"]["match"] == {"tool": "git", "host": "h"}
        assert out["front_end"] == "git"

    @pytest.mark.parametrize(
        ("raw", "code"),
        [
            ({"method": "status", "params": {}}, ErrorCode.BAD_REQUEST),           # no v
            (_req("status", v="acb.broker.v0"), ErrorCode.BAD_REQUEST),
            (_req("status", extra=1), ErrorCode.BAD_REQUEST),                     # unknown key
            (_req("explode"), ErrorCode.UNKNOWN_METHOD),
            ({"v": P.PROTOCOL, "method": 7}, ErrorCode.BAD_REQUEST),
            (_req("status", {"x": 1}), ErrorCode.BAD_REQUEST),
            ({"v": P.PROTOCOL, "method": "list", "params": []}, ErrorCode.BAD_REQUEST),
            (_req("checkout", {}), ErrorCode.BAD_REQUEST),
            (
                _req("checkout", {"capability": "a", "match": {"tool": "git"}}),
                ErrorCode.BAD_REQUEST,
            ),
            (_req("checkout", {"capability": "a", "ttl": True}), ErrorCode.BAD_REQUEST),
            (_req("checkout", {"capability": "a", "ttl": 0}), ErrorCode.BAD_REQUEST),
            (_req("checkout", {"capability": ""}), ErrorCode.BAD_REQUEST),
            (_req("checkout", {"capability": "a\nb"}), ErrorCode.BAD_REQUEST),
            (_req("checkout", {"match": {"host": "h"}}), ErrorCode.BAD_REQUEST),
            (_req("checkout", {"match": {"tool": "git", "x": 1}}), ErrorCode.BAD_REQUEST),
            (_req("checkout", {"capability": "a"}, front_end="ssh"), ErrorCode.BAD_REQUEST),
            (_req("list", front_end="git"), ErrorCode.BAD_REQUEST),
            (_req("revoke", {}), ErrorCode.BAD_REQUEST),
            (_req("revoke", {"all": True, "capability": "a"}), ErrorCode.BAD_REQUEST),
            (_req("revoke", {"all": "yes"}), ErrorCode.BAD_REQUEST),
            (_req("revoke", {"checkout_id": "c", "dry_run": 1}), ErrorCode.BAD_REQUEST),
            (_req("status", harness_hint="x" * 500), ErrorCode.BAD_REQUEST),
        ],
    )
    def test_rejects(self, raw: dict[str, Any], code: str) -> None:
        with pytest.raises(ProtocolError) as ei:
            P.validate_request(raw)
        assert ei.value.code == code


CANARY = "canary-protocol-7c1f"


class TestValueRule:
    def test_only_helper_checkout_may_carry_a_value(self) -> None:
        ok = P.ok_response({"value": {"password": CANARY}}, carries_secret=True)
        P.check_response_shape("checkout", "git", ok)
        assert P.response_carries_secret(ok)

    @pytest.mark.parametrize(
        ("method", "front_end"),
        [("checkout", None), ("list", None), ("status", None), ("revoke", "git")],
    )
    def test_value_refused_elsewhere(self, method: str, front_end: str | None) -> None:
        resp = P.ok_response({"value": {"password": CANARY}}, carries_secret=True)
        with pytest.raises(ProtocolError):
            P.encode_response(method, front_end, resp)

    def test_unmarked_value_refused(self) -> None:
        resp = P.ok_response({"value": {"password": CANARY}}, carries_secret=False)
        with pytest.raises(ProtocolError):
            P.encode_response("checkout", "git", resp)

    def test_marker_without_value_refused(self) -> None:
        with pytest.raises(ProtocolError):
            P.encode_response("status", None, P.ok_response({}, carries_secret=True))

    def test_error_envelope_shape(self) -> None:
        e = P.error_response(ErrorCode.NO_MATCH, "nothing")
        assert e == {
            "v": P.PROTOCOL,
            "ok": False,
            "error": {"code": "no_match", "message": "nothing"},
        }
        assert not P.response_carries_secret(e)
