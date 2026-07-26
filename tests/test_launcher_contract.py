"""WI-3.2 Slice 2: Qualified launcher contract conformance.

Tests the published request/result schemas and provides a fake launcher that
conforms to the contract.  A consuming component validates its real launcher
against the same schema; ACB's CI proves the contract itself is self-consistent
and that a conforming fake launcher round-trips correctly through acb exec.
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from agent_capability_broker import secret_sources
from agent_capability_broker.launcher_contract import (
    LAUNCHER_RESULT_SCHEMA,
    LauncherRequest,
    LauncherResult,
    OperationResult,
)
from agent_capability_broker.model import Capability
from agent_capability_broker.providers import CredProvider

USER_CANARY = "user-canary-launch-not-for-output"
PASS_CANARY = "password-canary-launch-not-for-output"

FAKE_LAUNCHER_SOURCE = textwrap.dedent("""\
    import json, os, sys

    receipt_raw = os.environ.get("ACB_CHECKOUT_RECEIPT", "")
    if not receipt_raw:
        print(json.dumps({
            "schema": "acb.launcher-result.v1",
            "invocation_id": "unknown",
            "status": "failure",
            "operations": [],
            "evidence_hash": "",
            "cleanup_verified": False,
            "detail": "ACB_CHECKOUT_RECEIPT not set",
        }))
        raise SystemExit(1)

    receipt = json.loads(receipt_raw)
    invocation_id = receipt["invocation_id"]
    checkout = receipt["checkouts"][0]
    field_map = checkout["fields"]

    fields = {}
    for semantic, env_name in field_map.items():
        value = os.environ.get(env_name)
        if not value:
            print(json.dumps({
                "schema": "acb.launcher-result.v1",
                "invocation_id": invocation_id,
                "status": "failure",
                "operations": [],
                "evidence_hash": "",
                "cleanup_verified": False,
                "detail": f"field {semantic} not injected",
            }))
            raise SystemExit(1)
        fields[semantic] = value

    for name in field_map.values():
        del os.environ[name]
    del os.environ["ACB_CHECKOUT_RECEIPT"]

    result = {
        "schema": "acb.launcher-result.v1",
        "invocation_id": invocation_id,
        "status": "success",
        "operations": [
            {"operation": "identity-check", "status": "ok",
             "detail": "authenticated principal verified"},
            {"operation": "cleanup", "status": "ok", "detail": "credentials zeroed"},
        ],
        "evidence_hash": "sha256:fake-evidence-hash",
        "cleanup_verified": True,
        "detail": "",
    }
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
""")


class FakeResolver:
    API_VERSION = 1

    def __init__(self, values: dict[str, bytes]) -> None:
        self.values = values

    def available_providers(self) -> list[str]:
        return ["vault"]

    def reference_provider(self, ref: str, *, require_explicit: bool = False) -> str:
        scheme, sep, tail = ref.partition(":")
        if not sep or not tail:
            raise ValueError("invalid")
        return scheme

    def resolve(self, ref: str) -> bytes:
        return self.values[ref]


def _install_fake(monkeypatch: pytest.MonkeyPatch, fake: FakeResolver) -> None:
    monkeypatch.setattr(secret_sources, "_suite_resolver", lambda: fake)


def _launcher_cap(launcher_path: str) -> Capability:
    return Capability(
        "cred:lab-control",
        "cred",
        ("opencode",),
        {
            "source": "suite",
            "refs": {
                "username": "vault:kv/example/lab/username",
                "password": "vault:kv/example/lab/password",
            },
            "inject": {"username": "LAB_USERNAME", "password": "LAB_PASSWORD"},
            "trusted_argv": [sys.executable, launcher_path],
        },
    )


# ---------------------------------------------------------------------------
# LauncherRequest parsing
# ---------------------------------------------------------------------------


class TestLauncherRequest:
    def _make_env(self) -> dict[str, str]:
        receipt = json.dumps({
            "schema": "acb.checkout-receipt.v1",
            "invocation_id": "abc123",
            "issued_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-01-01T01:00:00Z",
            "checkouts": [{
                "capability_id": "cred:lab-control",
                "fields": {"username": "LAB_USERNAME", "password": "LAB_PASSWORD"},
            }],
        })
        return {
            "ACB_CHECKOUT_RECEIPT": receipt,
            "LAB_USERNAME": "testuser",
            "LAB_PASSWORD": "testpass",
        }

    def test_parses_valid_environment(self) -> None:
        env = self._make_env()
        req = LauncherRequest.from_environ(env)
        assert req.invocation_id == "abc123"
        assert req.capability_id == "cred:lab-control"
        assert req.fields == {"username": "testuser", "password": "testpass"}

    def test_rejects_missing_receipt(self) -> None:
        with pytest.raises(ValueError, match="not set"):
            LauncherRequest.from_environ({})

    def test_rejects_invalid_json(self) -> None:
        with pytest.raises(ValueError, match="not valid JSON"):
            LauncherRequest.from_environ({"ACB_CHECKOUT_RECEIPT": "not-json"})

    def test_rejects_wrong_schema(self) -> None:
        receipt = json.dumps({"schema": "wrong.v1", "invocation_id": "x"})
        with pytest.raises(ValueError, match="unexpected schema"):
            LauncherRequest.from_environ({"ACB_CHECKOUT_RECEIPT": receipt})

    def test_rejects_missing_invocation_id(self) -> None:
        receipt = json.dumps({
            "schema": "acb.checkout-receipt.v1",
            "checkouts": [{"capability_id": "cred:x", "fields": {"a": "B"}}],
        })
        with pytest.raises(ValueError, match="invocation_id"):
            LauncherRequest.from_environ({
                "ACB_CHECKOUT_RECEIPT": receipt,
                "B": "val",
            })

    def test_rejects_multiple_checkouts(self) -> None:
        receipt = json.dumps({
            "schema": "acb.checkout-receipt.v1",
            "invocation_id": "x",
            "checkouts": [
                {"capability_id": "cred:a", "fields": {"f": "A"}},
                {"capability_id": "cred:b", "fields": {"g": "B"}},
            ],
        })
        with pytest.raises(ValueError, match="exactly one"):
            LauncherRequest.from_environ({
                "ACB_CHECKOUT_RECEIPT": receipt,
                "A": "1", "B": "2",
            })

    def test_rejects_missing_field_env_var(self) -> None:
        env = self._make_env()
        del env["LAB_PASSWORD"]
        with pytest.raises(ValueError, match="not set"):
            LauncherRequest.from_environ(env)

    def test_expected_capability_id_matches(self) -> None:
        env = self._make_env()
        req = LauncherRequest.from_environ(
            env, expected_capability_id="cred:lab-control"
        )
        assert req.capability_id == "cred:lab-control"

    def test_expected_capability_id_mismatch_rejected(self) -> None:
        env = self._make_env()
        with pytest.raises(ValueError, match="does not match"):
            LauncherRequest.from_environ(
                env, expected_capability_id="cred:other-capability"
            )


# ---------------------------------------------------------------------------
# LauncherResult round-trip
# ---------------------------------------------------------------------------


class TestLauncherResult:
    def test_round_trip(self) -> None:
        result = LauncherResult(
            invocation_id="abc123",
            status="success",
            operations=(
                OperationResult("identity-check", "ok", "authenticated"),
                OperationResult("cleanup", "ok", "zeroed"),
            ),
            evidence_hash="sha256:deadbeef",
            cleanup_verified=True,
        )
        raw = result.to_json()
        parsed = LauncherResult.from_json(raw)
        assert parsed.invocation_id == "abc123"
        assert parsed.status == "success"
        assert len(parsed.operations) == 2
        assert parsed.operations[0].operation == "identity-check"
        assert parsed.evidence_hash == "sha256:deadbeef"
        assert parsed.cleanup_verified is True

    def test_rejects_invalid_status(self) -> None:
        with pytest.raises(ValueError, match="status must be one of"):
            LauncherResult(invocation_id="x", status="bogus")

    def test_from_json_rejects_wrong_schema(self) -> None:
        raw = json.dumps({"schema": "wrong", "invocation_id": "x", "status": "success"})
        with pytest.raises(ValueError, match="schema"):
            LauncherResult.from_json(raw)

    def test_from_json_rejects_invalid_json(self) -> None:
        with pytest.raises(ValueError, match="not valid JSON"):
            LauncherResult.from_json("not-json")

    def test_from_json_rejects_missing_invocation_id(self) -> None:
        raw = json.dumps({"schema": LAUNCHER_RESULT_SCHEMA, "status": "success"})
        with pytest.raises(ValueError, match="invocation_id"):
            LauncherResult.from_json(raw)

    def test_authorization_denied_is_valid(self) -> None:
        result = LauncherResult(
            invocation_id="x",
            status="authorization_denied",
            detail="standard user cannot perform privileged operation",
        )
        parsed = LauncherResult.from_json(result.to_json())
        assert parsed.status == "authorization_denied"

    def test_result_never_contains_canary(self) -> None:
        result = LauncherResult(
            invocation_id="abc",
            status="success",
            operations=(OperationResult("check", "ok", "done"),),
        )
        raw = result.to_json()
        assert USER_CANARY not in raw
        assert PASS_CANARY not in raw


# ---------------------------------------------------------------------------
# Fake launcher conformance through acb exec
# ---------------------------------------------------------------------------


class TestFakeLauncherConformance:
    def test_fake_launcher_conforms_through_exec(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capfd: pytest.CaptureFixture[str],
    ) -> None:
        fake = FakeResolver({
            "vault:kv/example/lab/username": USER_CANARY.encode(),
            "vault:kv/example/lab/password": PASS_CANARY.encode(),
        })
        _install_fake(monkeypatch, fake)
        monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

        launcher_script = tmp_path / "fake_launcher.py"
        launcher_script.write_text(FAKE_LAUNCHER_SOURCE)
        argv = [sys.executable, str(launcher_script)]
        cap = _launcher_cap(str(launcher_script))

        rc = CredProvider().exec(cap, argv)
        assert rc == 0

        captured = capfd.readouterr()
        output_lines = [line for line in captured.out.strip().splitlines() if line]
        result_json = output_lines[-1]
        result = LauncherResult.from_json(result_json)
        assert result.status == "success"
        assert result.cleanup_verified is True
        assert len(result.operations) == 2

        provenance_text = (tmp_path / "state" / "provenance.jsonl").read_text()
        assert USER_CANARY not in provenance_text
        assert PASS_CANARY not in provenance_text
        for canary in (USER_CANARY, PASS_CANARY):
            assert canary not in captured.out
            assert canary not in captured.err

    def test_fake_launcher_result_correlates_with_receipt(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capfd: pytest.CaptureFixture[str],
    ) -> None:
        fake = FakeResolver({
            "vault:kv/example/lab/username": USER_CANARY.encode(),
            "vault:kv/example/lab/password": PASS_CANARY.encode(),
        })
        _install_fake(monkeypatch, fake)
        monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

        launcher_script = tmp_path / "fake_launcher.py"
        launcher_script.write_text(FAKE_LAUNCHER_SOURCE)
        argv = [sys.executable, str(launcher_script)]
        cap = _launcher_cap(str(launcher_script))

        CredProvider().exec(cap, argv)
        captured = capfd.readouterr()
        output_lines = [line for line in captured.out.strip().splitlines() if line]
        result = LauncherResult.from_json(output_lines[-1])

        provenance_text = (tmp_path / "state" / "provenance.jsonl").read_text()
        events = [json.loads(line) for line in provenance_text.splitlines()]
        invocation_id = result.invocation_id
        assert any(invocation_id in event["summary"] for event in events)

    def test_fake_launcher_clears_credentials_from_own_env(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        checker_source = textwrap.dedent("""\
            import json, os, sys, subprocess
            launcher = sys.argv[1]
            result = subprocess.run(
                [sys.executable, launcher],
                capture_output=True, text=True,
                env=os.environ,
            )
            parsed = json.loads(result.stdout.strip().splitlines()[-1])
            assert parsed["cleanup_verified"] is True
            assert parsed["status"] == "success"
        """)
        fake = FakeResolver({
            "vault:kv/example/lab/username": USER_CANARY.encode(),
            "vault:kv/example/lab/password": PASS_CANARY.encode(),
        })
        _install_fake(monkeypatch, fake)
        monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

        launcher_script = tmp_path / "fake_launcher.py"
        launcher_script.write_text(FAKE_LAUNCHER_SOURCE)

        checker = tmp_path / "checker.py"
        checker.write_text(checker_source)
        checker_argv = [sys.executable, str(checker), str(launcher_script)]
        cap = Capability(
            "cred:lab-control",
            "cred",
            ("opencode",),
            {
                "source": "suite",
                "refs": {
                    "username": "vault:kv/example/lab/username",
                    "password": "vault:kv/example/lab/password",
                },
                "inject": {"username": "LAB_USERNAME", "password": "LAB_PASSWORD"},
                "trusted_argv": checker_argv,
            },
        )

        rc = CredProvider().exec(cap, checker_argv)
        assert rc == 0


# ---------------------------------------------------------------------------
# Contract schema stability
# ---------------------------------------------------------------------------


class TestContractSchemaStability:
    def test_request_schema_constant(self) -> None:
        from agent_capability_broker.launcher_contract import LAUNCHER_REQUEST_SCHEMA

        assert LAUNCHER_REQUEST_SCHEMA == "acb.launcher-request.v1"

    def test_result_schema_constant(self) -> None:
        assert LAUNCHER_RESULT_SCHEMA == "acb.launcher-result.v1"

    def test_result_statuses_are_closed(self) -> None:
        from agent_capability_broker.launcher_contract import _RESULT_STATUSES

        assert _RESULT_STATUSES == frozenset(
            {"success", "failure", "authorization_denied"}
        )
