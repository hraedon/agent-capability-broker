"""WI-3.2 Slice 1: Windows-host conformance (synthetic/mocked).

Proves: manifest discovery, suite-provider resolution, Windows absolute-path
trusted_argv matching, minimal child environment, process-tree
timeout/cancellation, redacted failures, and provenance — all without a real
Windows host.  Live Windows proof is a separately gated credential job.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from agent_capability_broker import providers, secret_sources
from agent_capability_broker.model import Capability, Status
from agent_capability_broker.providers import CredProvider
from agent_capability_broker.secret_sources import (
    SecretSourceConfigError,
    SecretSourceUnavailable,
)

USER_CANARY = "user-canary-w1n32-not-for-output"
PASS_CANARY = "password-canary-w1n32-not-for-output"


class FakeResolver:
    API_VERSION = 1

    def __init__(
        self,
        values: dict[str, bytes] | None = None,
        *,
        available: set[str] | None = None,
    ) -> None:
        self.values = values or {}
        self.available = available if available is not None else {"vault", "windows"}
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
        return self.values[ref]


def _install_fake(monkeypatch: pytest.MonkeyPatch, fake: FakeResolver) -> None:
    monkeypatch.setattr(secret_sources, "_suite_resolver", lambda: fake)


def _windows_cap(**overrides: object) -> Capability:
    options: dict[str, object] = {
        "source": "suite",
        "refs": {
            "username": "windows:credential/example/lab/username",
            "password": "windows:credential/example/lab/password",
        },
        "inject": {"username": "LAB_USERNAME", "password": "LAB_PASSWORD"},
        "trusted_argv": [r"C:\opt\example\bin\lab-control.exe", "--validate"],
    }
    options.update(overrides)
    return Capability("cred:lab-control", "cred", ("opencode",), options)


# ---------------------------------------------------------------------------
# Windows absolute-path trusted_argv matching
# ---------------------------------------------------------------------------


class TestWindowsTrustedArgv:
    def test_accepts_windows_absolute_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeResolver()
        _install_fake(monkeypatch, fake)
        cap = _windows_cap()
        from agent_capability_broker.secret_sources import validate_suite_command

        validate_suite_command(cap, [r"C:\opt\example\bin\lab-control.exe", "--validate"])

    def test_rejects_relative_windows_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeResolver()
        _install_fake(monkeypatch, fake)
        cap = _windows_cap(trusted_argv=["lab-control.exe", "--validate"])
        with pytest.raises(SecretSourceConfigError, match="absolute"):
            from agent_capability_broker.secret_sources import validate_suite_command

            validate_suite_command(cap, ["lab-control.exe", "--validate"])

    def test_rejects_mismatched_argv(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeResolver()
        _install_fake(monkeypatch, fake)
        cap = _windows_cap()
        from agent_capability_broker.secret_sources import validate_suite_command

        with pytest.raises(SecretSourceConfigError, match="does not match"):
            validate_suite_command(
                cap, [r"C:\opt\example\bin\lab-control.exe", "--different-flag"]
            )
        assert fake.resolve_calls == []

    def test_shell_as_trusted_argv_is_not_code_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeResolver()
        _install_fake(monkeypatch, fake)
        shell = r"C:\Windows\System32\cmd.exe"
        cap = _windows_cap(trusted_argv=[shell, "/c", "echo hello"])
        from agent_capability_broker.secret_sources import validate_suite_command

        validate_suite_command(cap, [shell, "/c", "echo hello"])

    @pytest.mark.skipif(os.name == "nt", reason="POSIX paths are not absolute on Windows")
    def test_accepts_posix_absolute_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeResolver()
        _install_fake(monkeypatch, fake)
        cap = _windows_cap(trusted_argv=["/opt/example/bin/lab-control", "--validate"])
        from agent_capability_broker.secret_sources import validate_suite_command

        validate_suite_command(cap, ["/opt/example/bin/lab-control", "--validate"])

    def test_rejects_platform_relative_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeResolver()
        _install_fake(monkeypatch, fake)
        relative = "opt/example/bin/lab-control"
        cap = _windows_cap(trusted_argv=[relative, "--validate"])
        from agent_capability_broker.secret_sources import validate_suite_command

        with pytest.raises(SecretSourceConfigError, match="absolute"):
            validate_suite_command(cap, [relative, "--validate"])
        assert fake.resolve_calls == []

    @pytest.mark.skipif(os.name != "nt", reason="Windows-only: drive-less path")
    def test_rejects_drive_less_windows_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeResolver()
        _install_fake(monkeypatch, fake)
        cap = _windows_cap(trusted_argv=[r"\opt\example\lab-control.exe", "--validate"])
        from agent_capability_broker.secret_sources import validate_suite_command

        with pytest.raises(SecretSourceConfigError, match="absolute"):
            validate_suite_command(cap, [r"\opt\example\lab-control.exe", "--validate"])

    def test_accepts_windows_forward_slash_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeResolver()
        _install_fake(monkeypatch, fake)
        cap = _windows_cap(
            trusted_argv=["C:/opt/example/bin/lab-control.exe", "--validate"]
        )
        from agent_capability_broker.secret_sources import validate_suite_command

        validate_suite_command(cap, ["C:/opt/example/bin/lab-control.exe", "--validate"])


# ---------------------------------------------------------------------------
# Windows containment preflight
# ---------------------------------------------------------------------------


class TestWindowsContainmentPreflight:
    def test_fails_closed_when_taskkill_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("SystemRoot", raising=False)
        monkeypatch.delenv("WINDIR", raising=False)
        monkeypatch.setattr(providers.Path, "is_file", lambda self: False)
        with pytest.raises(SecretSourceUnavailable, match="disabled on Windows"):
            providers._windows_taskkill_path()

    def test_finds_taskkill_via_systemroot(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        system32 = tmp_path / "System32"
        system32.mkdir()
        taskkill = system32 / "taskkill.exe"
        taskkill.write_bytes(b"MZ")
        monkeypatch.setenv("SystemRoot", str(tmp_path))
        monkeypatch.delenv("WINDIR", raising=False)
        result = providers._windows_taskkill_path()
        assert result == str(taskkill)

    def test_fails_closed_when_process_group_unavailable(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        system32 = tmp_path / "System32"
        system32.mkdir()
        taskkill = system32 / "taskkill.exe"
        taskkill.write_bytes(b"MZ")
        monkeypatch.setenv("SystemRoot", str(tmp_path))
        monkeypatch.setattr(
            providers.subprocess, "CREATE_NEW_PROCESS_GROUP", 0, raising=False
        )
        with pytest.raises(SecretSourceUnavailable, match="process-group creation"):
            providers._windows_containment_preflight()


# ---------------------------------------------------------------------------
# Windows process-tree termination
# ---------------------------------------------------------------------------


class TestWindowsProcessTreeTermination:
    def test_taskkill_tree_force_invocation(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeProcess:
            pid = 9999

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
            [r"C:\Windows\System32\taskkill.exe", "/PID", "9999", "/T", "/F"]
        ]
        assert process.killed is False

    def test_taskkill_failure_falls_back_to_direct_kill(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeProcess:
            pid = 8888

            def __init__(self) -> None:
                self.killed = False
                self.wait_count = 0

            def poll(self) -> int | None:
                return None

            def kill(self) -> None:
                self.killed = True

            def wait(self, timeout: float | None = None) -> int:
                self.wait_count += 1
                return 0

        def fake_run(argv: list[str], **_: object) -> object:
            return providers.subprocess.CompletedProcess(argv, 1)

        monkeypatch.setattr(providers.subprocess, "run", fake_run)
        process = FakeProcess()
        with pytest.raises(RuntimeError, match="termination failed"):
            providers._terminate_process_tree(  # type: ignore[arg-type]
                process,
                platform_name="nt",
                taskkill_path=r"C:\Windows\System32\taskkill.exe",
                grace_seconds=0.1,
            )
        assert process.killed is True

    def test_taskkill_oserror_falls_back_to_direct_kill(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class FakeProcess:
            pid = 7777

            def __init__(self) -> None:
                self.killed = False

            def poll(self) -> int | None:
                return None

            def kill(self) -> None:
                self.killed = True

            def wait(self, timeout: float | None = None) -> int:
                return 0

        def fake_run(argv: list[str], **_: object) -> object:
            raise OSError("taskkill not found")

        monkeypatch.setattr(providers.subprocess, "run", fake_run)
        process = FakeProcess()
        with pytest.raises(RuntimeError, match="termination failed"):
            providers._terminate_process_tree(  # type: ignore[arg-type]
                process,
                platform_name="nt",
                taskkill_path=r"C:\Windows\System32\taskkill.exe",
                grace_seconds=0.1,
            )
        assert process.killed is True

    def test_missing_taskkill_path_raises(self) -> None:
        class FakeProcess:
            pid = 1111

            def poll(self) -> int | None:
                return None

            def kill(self) -> None:
                pass

            def wait(self, timeout: float | None = None) -> int:
                return 0

        with pytest.raises(RuntimeError, match="unavailable"):
            providers._terminate_process_tree(  # type: ignore[arg-type]
                FakeProcess(),
                platform_name="nt",
                taskkill_path=None,
                grace_seconds=0.1,
            )


# ---------------------------------------------------------------------------
# Minimal child environment
# ---------------------------------------------------------------------------


class TestWindowsMinimalChildEnv:
    def test_suite_child_env_is_minimal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("LAB_USERNAME", "stale")
        monkeypatch.setenv("LAB_PASSWORD", "stale")
        monkeypatch.setenv("USERNAME", "parent-user")
        monkeypatch.setenv("PATH", "/usr/bin")
        monkeypatch.setenv("SECRET_THING", "must-not-pass")
        monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
        monkeypatch.setenv("TEMP", r"C:\Temp")

        plan = {"username": "LAB_USERNAME", "password": "LAB_PASSWORD"}
        env = providers._suite_child_env(plan, ["username", "password"])

        assert "LAB_USERNAME" not in env
        assert "LAB_PASSWORD" not in env
        assert "USERNAME" not in env
        assert "PATH" not in env
        assert "SECRET_THING" not in env
        assert env.get("SYSTEMROOT") == r"C:\Windows"
        assert env.get("TEMP") == r"C:\Temp"

    def test_suite_child_env_allowlist(self) -> None:
        assert providers._SUITE_CHILD_ENV_ALLOWLIST == frozenset(
            {"LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "TZ", "WINDIR"}
        )


# ---------------------------------------------------------------------------
# Redacted failures on Windows paths
# ---------------------------------------------------------------------------


class TestWindowsRedactedFailures:
    def test_resolution_failure_redacts_on_windows_scheme(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        sensitive_ref = "windows:credential/example/private/password"

        class FailingResolver(FakeResolver):
            def resolve(self, ref: str) -> bytes:
                self.resolve_calls.append(ref)
                if "private" in ref:
                    raise PermissionError(f"access denied to {ref} with {PASS_CANARY}")
                return self.values[ref]

        fake = FailingResolver(
            values={
                "windows:credential/example/lab/username": USER_CANARY.encode(),
            }
        )
        _install_fake(monkeypatch, fake)
        monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
        argv = [sys.executable, "-c", "pass"]
        cap = _windows_cap(
            refs={
                "username": "windows:credential/example/lab/username",
                "password": sensitive_ref,
            },
            trusted_argv=argv,
        )

        from agent_capability_broker.secret_sources import SecretResolutionError

        with pytest.raises(SecretResolutionError) as exc_info:
            CredProvider().exec(cap, argv)
        rendered = str(exc_info.value)
        assert sensitive_ref not in rendered
        assert PASS_CANARY not in rendered
        assert exc_info.value.__context__ is None
        assert exc_info.value.__cause__ is None


# ---------------------------------------------------------------------------
# Provenance correlation
# ---------------------------------------------------------------------------


class TestWindowsProvenance:
    def test_provenance_shares_invocation_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeResolver(
            values={
                "windows:credential/example/lab/username": USER_CANARY.encode(),
                "windows:credential/example/lab/password": PASS_CANARY.encode(),
            }
        )
        _install_fake(monkeypatch, fake)
        monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
        out = tmp_path / "out.txt"
        code = f"import pathlib; pathlib.Path({str(out)!r}).write_text('ok')"
        argv = [sys.executable, "-c", code]
        cap = _windows_cap(trusted_argv=argv)

        assert CredProvider().exec(cap, argv) == 0
        log = (tmp_path / "state" / "provenance.jsonl").read_text()
        events = [json.loads(line) for line in log.splitlines()]
        assert len(events) == 2
        assert events[0]["result"] == "started"
        assert events[1]["result"] == "applied"
        invocation_ids = set()
        for event in events:
            summary = event["summary"]
            assert "invocation" in summary
            parts = summary.split("invocation ")
            if len(parts) > 1:
                invocation_ids.add(parts[1].rstrip(")"))
        assert len(invocation_ids) == 1
        assert USER_CANARY not in log
        assert PASS_CANARY not in log

    def test_provenance_on_ssh_trigger_is_value_free(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeResolver(
            values={
                "windows:credential/example/lab/username": USER_CANARY.encode(),
                "windows:credential/example/lab/password": PASS_CANARY.encode(),
            }
        )
        _install_fake(monkeypatch, fake)
        monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
        monkeypatch.setenv("SSH_CONNECTION", "192.168.1.100 54321 192.168.1.50 22")
        monkeypatch.setenv("SSH_CLIENT", "192.168.1.100 54321 22")

        argv = [sys.executable, "-c", "pass"]
        cap = _windows_cap(trusted_argv=argv)
        assert CredProvider().exec(cap, argv) == 0

        log = (tmp_path / "state" / "provenance.jsonl").read_text()
        assert USER_CANARY not in log
        assert PASS_CANARY not in log
        assert "SSH_CONNECTION" not in log


# ---------------------------------------------------------------------------
# Doctor on Windows scheme
# ---------------------------------------------------------------------------


class TestWindowsDoctor:
    def test_doctor_reports_unknown_for_windows_backend(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = FakeResolver(available={"vault", "windows"})
        _install_fake(monkeypatch, fake)
        cap = _windows_cap()

        status, detail = CredProvider()._reachability(cap)
        assert status is Status.UNKNOWN
        assert "intentionally unproven" in detail
        assert fake.resolve_calls == []
