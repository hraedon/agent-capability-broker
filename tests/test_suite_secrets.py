"""Provider-neutral suite injection: fail-closed, multi-field, non-leaking."""

from __future__ import annotations

import json
import os
import sys
import time
import tomllib
from pathlib import Path

import pytest

from agent_capability_broker import providers, secret_sources
from agent_capability_broker.model import Capability, Status
from agent_capability_broker.providers import CredProvider
from agent_capability_broker.secret_sources import (
    SecretResolutionError,
    SecretSourceConfigError,
    SecretSourceUnavailable,
    suite_spec,
)

USER_CANARY = "user-canary-742e-not-for-output"
PASS_CANARY = "password-canary-a91c-not-for-output"


class FakeResolver:
    API_VERSION = 1

    def __init__(
        self,
        values: dict[str, bytes] | None = None,
        *,
        available: set[str] | None = None,
        failure: Exception | None = None,
    ) -> None:
        self.values = values or {}
        self.available = available if available is not None else {"vault"}
        self.failure = failure
        self.resolve_calls: list[str] = []

    def available_providers(self) -> list[str]:
        return sorted(self.available)

    def reference_provider(self, ref: str, *, require_explicit: bool = False) -> str:
        assert require_explicit
        scheme, sep, tail = ref.partition(":")
        if not sep or not tail:
            raise ValueError("invalid")
        return scheme

    def resolve(self, ref: str) -> bytes:
        self.resolve_calls.append(ref)
        if self.failure is not None:
            raise self.failure
        return self.values[ref]


def _cap(**overrides: object) -> Capability:
    options: dict[str, object] = {
        "source": "suite",
        "refs": {
            "username": "vault:kv/example/lab/username",
            "password": "vault:kv/example/lab/password",
        },
        "inject": {"username": "LAB_USERNAME", "password": "LAB_PASSWORD"},
        "trusted_argv": [sys.executable, "-c", "pass"],
    }
    options.update(overrides)
    return Capability("cred:lab-control", "cred", ("opencode",), options)


def _install_fake(monkeypatch: pytest.MonkeyPatch, fake: FakeResolver) -> None:
    monkeypatch.setattr(secret_sources, "_suite_resolver", lambda: fake)


def _synthetic_receipt() -> str:
    return providers._checkout_receipt(
        _cap(),
        {"username": "LAB_USERNAME", "password": "LAB_PASSWORD"},
        invocation_id="8c03d42017fe4e538ea58cfe18b6d999",
        timeout_seconds=120,
    )


def test_suite_exec_injects_multiple_fields_and_leaks_no_canary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = FakeResolver(
        {
            "vault:kv/example/lab/username": USER_CANARY.encode(),
            "vault:kv/example/lab/password": PASS_CANARY.encode(),
        }
    )
    _install_fake(monkeypatch, fake)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    out = tmp_path / "seen.json"
    code = (
        "import json,os,pathlib;"
        f"pathlib.Path({str(out)!r}).write_text(json.dumps("
        "[os.environ['LAB_USERNAME'],os.environ['LAB_PASSWORD']]))"
    )

    argv = [sys.executable, "-c", code]
    assert CredProvider().exec(_cap(trusted_argv=argv), argv) == 0
    assert json.loads(out.read_text()) == [USER_CANARY, PASS_CANARY]
    captured = capsys.readouterr()
    provenance = (tmp_path / "state" / "provenance.jsonl").read_text()
    for canary in (USER_CANARY, PASS_CANARY):
        assert canary not in captured.out
        assert canary not in captured.err
        assert canary not in provenance
    assert "LAB_USERNAME" in provenance and "LAB_PASSWORD" in provenance


def test_suite_child_failure_returns_code_and_provenance_remains_value_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeResolver(
        {
            "vault:kv/example/lab/username": USER_CANARY.encode(),
            "vault:kv/example/lab/password": PASS_CANARY.encode(),
        }
    )
    _install_fake(monkeypatch, fake)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

    argv = [sys.executable, "-c", "raise SystemExit(23)"]
    rc = CredProvider().exec(_cap(trusted_argv=argv), argv)

    assert rc == 23
    log = (tmp_path / "state" / "provenance.jsonl").read_text()
    assert "qualified child exited 23" in log
    events = [json.loads(line) for line in log.splitlines()]
    assert [event["result"] for event in events] == ["started", "failed"]
    assert USER_CANARY not in log and PASS_CANARY not in log


def test_suite_collision_refuses_before_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeResolver()
    _install_fake(monkeypatch, fake)
    monkeypatch.setenv("LAB_PASSWORD", "pre-existing")

    with pytest.raises(SecretSourceConfigError, match="already exists"):
        CredProvider().exec(_cap(), [sys.executable, "-c", "pass"])
    assert fake.resolve_calls == []


@pytest.mark.parametrize(
    "refs, message",
    [
        ({"password": "bare-reference"}, "explicit"),
        ({"password": "typo:anything"}, "unsupported"),
        ({"password": "vault:"}, "explicit"),
        ({"password": "env:RAW_SECRET"}, "unsupported"),
    ],
)
def test_suite_malformed_or_unsafe_refs_fail_closed(
    refs: dict[str, str], message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeResolver()
    _install_fake(monkeypatch, fake)
    with pytest.raises(SecretSourceConfigError, match=message):
        suite_spec(
            _cap(refs=refs, inject={name: f"LAB_{name.upper()}" for name in refs}),
            require_available=True,
        )
    assert fake.resolve_calls == []


def test_suite_refuses_unknown_and_duplicate_injection_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeResolver()
    _install_fake(monkeypatch, fake)
    with pytest.raises(SecretSourceConfigError, match="exactly match"):
        suite_spec(_cap(inject={"username": "LAB_USERNAME"}), require_available=True)
    with pytest.raises(SecretSourceConfigError, match="duplicate inject"):
        CredProvider().exec(
            _cap(inject={"username": "LAB_CRED", "password": "LAB_CRED"}),
            [sys.executable, "-c", "pass"],
        )
    assert fake.resolve_calls == []


def test_suite_missing_extra_and_provider_are_actionable_but_do_not_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable() -> FakeResolver:
        raise SecretSourceUnavailable("install the suite-secrets extra")

    monkeypatch.setattr(secret_sources, "_suite_resolver", unavailable)
    status, detail = CredProvider()._reachability(_cap())
    assert status is Status.UNKNOWN and "suite-secrets" in detail

    fake = FakeResolver(available=set())
    _install_fake(monkeypatch, fake)
    status, detail = CredProvider()._reachability(_cap())
    assert status is Status.UNKNOWN and "unavailable suite provider" in detail
    assert fake.resolve_calls == []


def test_suite_extra_pins_public_facade_release_and_api_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    extra = project["project"]["optional-dependencies"]["suite-secrets"]
    assert extra == ["regista>=0.5.1,<0.6"]

    fake = FakeResolver()
    fake.API_VERSION = 2
    monkeypatch.setattr(secret_sources.importlib, "import_module", lambda _: fake)
    with pytest.raises(SecretSourceUnavailable, match="API_VERSION 1"):
        secret_sources._suite_resolver()


def test_suite_doctor_probe_never_resolves_values(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeResolver(failure=AssertionError("read path resolved a value"))
    _install_fake(monkeypatch, fake)

    status, detail = CredProvider()._reachability(_cap())

    assert status is Status.UNKNOWN
    assert "intentionally unproven" in detail
    assert fake.resolve_calls == []


def test_suite_resolution_failure_redacts_ref_backend_error_and_canary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    sensitive_ref = "vault:kv/example/private/password"
    fake = FakeResolver(
        available={"vault"},
        failure=RuntimeError(f"backend included {sensitive_ref} and {PASS_CANARY}"),
    )
    _install_fake(monkeypatch, fake)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    cap = _cap(refs={"password": sensitive_ref}, inject={"password": "LAB_PASSWORD"})

    with pytest.raises(SecretResolutionError) as exc_info:
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])
    rendered = str(exc_info.value)
    assert "password" in rendered and "vault" in rendered
    assert sensitive_ref not in rendered and PASS_CANARY not in rendered
    assert exc_info.value.__context__ is None
    provenance_text = (tmp_path / "state" / "provenance.jsonl").read_text()
    assert sensitive_ref not in provenance_text and PASS_CANARY not in provenance_text
    events = [
        json.loads(line)
        for line in provenance_text.splitlines()
    ]
    assert [event["result"] for event in events] == ["started", "failed"]
    assert events[-1]["detail"] == "qualified credential resolution failed"


def test_suite_rejects_missing_relative_or_mismatched_trusted_command_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeResolver()
    _install_fake(monkeypatch, fake)
    command = [sys.executable, "-c", "pass"]

    with pytest.raises(SecretSourceConfigError, match="trusted_argv"):
        CredProvider().exec(_cap(trusted_argv=None), command)
    with pytest.raises(SecretSourceConfigError, match="absolute"):
        CredProvider().exec(_cap(trusted_argv=["python", "-c", "pass"]), command)
    with pytest.raises(SecretSourceConfigError, match="does not match") as exc_info:
        CredProvider().exec(_cap(), [sys.executable, "-c", "print('arbitrary')"])
    assert "arbitrary" not in str(exc_info.value)
    assert fake.resolve_calls == []


def test_suite_child_receives_minimal_env_and_value_free_checkout_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeResolver(
        {
            "vault:kv/example/lab/username": USER_CANARY.encode(),
            "vault:kv/example/lab/password": PASS_CANARY.encode(),
        }
    )
    _install_fake(monkeypatch, fake)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("UNRELATED_PARENT_CANARY", "must-not-be-inherited")
    monkeypatch.setenv("USERNAME", "stale-parent-username")
    monkeypatch.setenv("PASSWORD", "stale-parent-password")
    out = tmp_path / "receipt.json"
    code = (
        "import json,os,pathlib;"
        f"pathlib.Path({str(out)!r}).write_text(json.dumps({{"
        "'unrelated':os.environ.get('UNRELATED_PARENT_CANARY'),"
        "'stale_username':os.environ.get('USERNAME'),"
        "'stale_password':os.environ.get('PASSWORD'),"
        "'receipt':json.loads(os.environ['ACB_CHECKOUT_RECEIPT'])}))"
    )
    argv = [sys.executable, "-c", code]

    assert CredProvider().exec(_cap(trusted_argv=argv), argv) == 0

    seen = json.loads(out.read_text())
    assert seen["unrelated"] is None
    assert seen["stale_username"] is None
    assert seen["stale_password"] is None
    receipt = seen["receipt"]
    assert receipt["schema"] == "acb.checkout-receipt.v1"
    assert set(receipt) == {
        "schema", "invocation_id", "issued_at", "expires_at", "checkouts"
    }
    assert receipt["checkouts"] == [
        {
            "capability_id": "cred:lab-control",
            "fields": {
                "password": "LAB_PASSWORD",
                "username": "LAB_USERNAME",
            },
        }
    ]
    serialized = json.dumps(receipt)
    assert USER_CANARY not in serialized and PASS_CANARY not in serialized
    assert "kv/example" not in serialized
    events = [
        json.loads(line)
        for line in (tmp_path / "state" / "provenance.jsonl").read_text().splitlines()
    ]
    assert len(events) == 2
    assert all(receipt["invocation_id"] in event["summary"] for event in events)


def test_checkout_receipt_uses_canonical_z_timestamps() -> None:
    raw = _synthetic_receipt()
    decoded = json.loads(raw)
    for field in ("issued_at", "expires_at"):
        assert decoded[field].endswith("Z")
        assert "+00:00" not in decoded[field]


def test_checkout_receipt_parses_in_composed_evidence_lab() -> None:
    raw = _synthetic_receipt()
    lab_src = Path(__file__).resolve().parents[2] / "windows-evidence-lab" / "src"
    if not lab_src.is_dir():
        pytest.skip("composed windows-evidence-lab checkout is not present")
    sys.path.insert(0, str(lab_src))
    try:
        from windows_evidence_lab.capabilities import parse_checkout_receipt

        parsed = parse_checkout_receipt(raw)
    finally:
        sys.path.remove(str(lab_src))
        sys.modules.pop("windows_evidence_lab.capabilities", None)
        sys.modules.pop("windows_evidence_lab", None)
    assert parsed.invocation_id == json.loads(raw)["invocation_id"]


def test_suite_refuses_receipt_collision_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeResolver()
    _install_fake(monkeypatch, fake)
    monkeypatch.setenv("ACB_CHECKOUT_RECEIPT", "parent-receipt")

    with pytest.raises(SecretSourceConfigError, match="nested checkout"):
        CredProvider().exec(_cap(), [sys.executable, "-c", "pass"])
    assert fake.resolve_calls == []

    monkeypatch.delenv("ACB_CHECKOUT_RECEIPT")
    with pytest.raises(SecretSourceConfigError, match="reserved"):
        CredProvider().exec(
            _cap(inject={"username": "LAB_USERNAME", "password": "ACB_CHECKOUT_RECEIPT"}),
            [sys.executable, "-c", "pass"],
        )
    assert fake.resolve_calls == []


def test_suite_launch_failure_and_timeout_emit_value_free_terminal_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeResolver(
        {
            "vault:kv/example/lab/username": USER_CANARY.encode(),
            "vault:kv/example/lab/password": PASS_CANARY.encode(),
        }
    )
    _install_fake(monkeypatch, fake)
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))

    missing = str(tmp_path / "does-not-exist")
    with pytest.raises(RuntimeError, match="launch failed"):
        CredProvider().exec(_cap(trusted_argv=[missing]), [missing])

    slow = [sys.executable, "-c", "import time; time.sleep(1)"]
    with pytest.raises(RuntimeError, match="timed out"):
        CredProvider().exec(_cap(trusted_argv=slow, timeout_seconds=0.01), slow)

    log = (state / "provenance.jsonl").read_text()
    events = [json.loads(line) for line in log.splitlines()]
    assert [event["result"] for event in events] == [
        "started", "failed", "started", "failed"
    ]
    assert "launch failed" in events[1]["detail"]
    assert "timed out" in events[3]["detail"]
    assert USER_CANARY not in log and PASS_CANARY not in log


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group containment")
def test_suite_timeout_terminates_grandchild_before_canary_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeResolver(
        {
            "vault:kv/example/lab/username": USER_CANARY.encode(),
            "vault:kv/example/lab/password": PASS_CANARY.encode(),
        }
    )
    _install_fake(monkeypatch, fake)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    leaked = tmp_path / "grandchild-leak.txt"
    grandchild = (
        "import os,pathlib,time;time.sleep(0.4);"
        f"pathlib.Path({str(leaked)!r}).write_text(os.environ['LAB_PASSWORD'])"
    )
    parent = (
        "import subprocess,time;"
        f"subprocess.Popen([{sys.executable!r},'-c',{grandchild!r}]);"
        "time.sleep(5)"
    )
    argv = [sys.executable, "-c", parent]

    with pytest.raises(RuntimeError, match="timed out"):
        CredProvider().exec(_cap(trusted_argv=argv, timeout_seconds=0.1), argv)
    time.sleep(0.6)

    assert not leaked.exists()
    log = (tmp_path / "state" / "provenance.jsonl").read_text()
    assert PASS_CANARY not in log


def test_windows_tree_termination_uses_taskkill_tree_force(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeProcess:
        pid = 4242

        def __init__(self) -> None:
            self.waits: list[float | None] = []
            self.killed = False

        def poll(self) -> int | None:
            return None

        def kill(self) -> None:
            self.killed = True

        def wait(self, timeout: float | None = None) -> int:
            self.waits.append(timeout)
            return 0

    seen: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> object:
        seen.append(argv)
        return providers.subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(providers.subprocess, "run", fake_run)
    process = FakeProcess()
    providers._terminate_process_tree(  # type: ignore[arg-type]
        process,
        platform_name="nt",
        taskkill_path=r"C:\Windows\System32\taskkill.exe",
        grace_seconds=0.1,
    )

    assert seen == [
        [r"C:\Windows\System32\taskkill.exe", "/PID", "4242", "/T", "/F"]
    ]
    assert process.waits == [0.1]
    assert process.killed is False


def test_windows_suite_is_gated_when_taskkill_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(providers.shutil, "which", lambda _: None)
    monkeypatch.delenv("SystemRoot", raising=False)
    with pytest.raises(SecretSourceUnavailable, match="disabled on Windows"):
        providers._windows_taskkill_path()

    monkeypatch.setattr(providers.subprocess, "CREATE_NEW_PROCESS_GROUP", 0, raising=False)
    with pytest.raises(SecretSourceUnavailable, match="process-group creation"):
        providers._windows_containment_preflight()
