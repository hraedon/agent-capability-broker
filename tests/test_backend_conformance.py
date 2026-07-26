"""WI-1.3: Backend conformance through the public resolver.

Each backend (vault, azure, windows) passes: unavailable, unauthorized,
missing-ref, valid use, rotation, and redacted-failure — all via synthetic
providers.  No live backend is contacted; live conformance is a separately
gated credential job.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_capability_broker import providers, secret_sources
from agent_capability_broker.model import Capability, Status
from agent_capability_broker.providers import CredProvider
from agent_capability_broker.secret_sources import (
    SecretResolutionError,
    SecretSourceConfigError,
    resolve_suite,
    suite_spec,
)

USER_CANARY = "user-canary-b3f1-not-for-output"
PASS_CANARY = "password-canary-e7d2-not-for-output"
TOKEN_CANARY = "token-canary-9a4c-not-for-output"

_BACKENDS = ("vault", "azure", "windows")


class ConformanceResolver:
    """Synthetic resolver that exercises each backend's conformance path."""

    API_VERSION = 1

    def __init__(
        self,
        *,
        available: set[str] | None = None,
        values: dict[str, bytes] | None = None,
        unauthorized_refs: set[str] | None = None,
        failure_ref: str | None = None,
        failure_exc: Exception | None = None,
    ) -> None:
        self.available = available if available is not None else set(_BACKENDS)
        self.values = values or {}
        self.unauthorized_refs = unauthorized_refs or set()
        self.failure_ref = failure_ref
        self.failure_exc = failure_exc
        self.resolve_calls: list[str] = []

    def available_providers(self) -> list[str]:
        return sorted(self.available)

    def reference_provider(self, ref: str, *, require_explicit: bool = False) -> str:
        assert require_explicit
        scheme, sep, tail = ref.partition(":")
        if not sep or not tail:
            raise ValueError("invalid reference")
        return scheme

    def resolve(self, ref: str) -> bytes:
        self.resolve_calls.append(ref)
        if self.failure_ref is not None and ref == self.failure_ref:
            raise self.failure_exc or RuntimeError("backend failure")
        if ref in self.unauthorized_refs:
            raise PermissionError("access denied")
        if ref not in self.values:
            raise KeyError(f"ref not found: {ref}")
        return self.values[ref]


def _cap_for_backend(
    backend: str,
    *,
    fields: dict[str, str] | None = None,
    inject: dict[str, str] | None = None,
    trusted_argv: list[str] | None = None,
) -> Capability:
    if fields is None:
        fields = {
            "username": f"{backend}:kv/example/lab/username",
            "password": f"{backend}:kv/example/lab/password",
        }
    if inject is None:
        inject = {name: f"LAB_{name.upper()}" for name in fields}
    if trusted_argv is None:
        trusted_argv = [sys.executable, "-c", "pass"]
    return Capability(
        "cred:lab-control",
        "cred",
        ("opencode",),
        {
            "source": "suite",
            "refs": fields,
            "inject": inject,
            "trusted_argv": trusted_argv,
        },
    )


def _install(monkeypatch: pytest.MonkeyPatch, resolver: ConformanceResolver) -> None:
    monkeypatch.setattr(secret_sources, "_suite_resolver", lambda: resolver)


# ---------------------------------------------------------------------------
# Unavailable backend
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", _BACKENDS)
def test_unavailable_backend_is_actionable(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolver = ConformanceResolver(available=set())
    _install(monkeypatch, resolver)
    cap = _cap_for_backend(backend)

    status, detail = CredProvider()._reachability(cap)
    assert status is Status.UNKNOWN
    assert "unavailable" in detail
    assert resolver.resolve_calls == []


# ---------------------------------------------------------------------------
# Unauthorized
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", _BACKENDS)
def test_unauthorized_ref_redacts_and_fails_closed(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    ref = f"{backend}:kv/example/lab/password"
    resolver = ConformanceResolver(
        available={backend},
        unauthorized_refs={ref},
        values={f"{backend}:kv/example/lab/username": USER_CANARY.encode()},
    )
    _install(monkeypatch, resolver)
    cap = _cap_for_backend(backend)

    with pytest.raises(SecretResolutionError) as exc_info:
        resolve_suite(cap)
    rendered = str(exc_info.value)
    assert "password" in rendered and backend in rendered
    assert ref not in rendered
    assert PASS_CANARY not in rendered
    assert exc_info.value.__context__ is None
    assert exc_info.value.__cause__ is None


# ---------------------------------------------------------------------------
# Missing ref
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", _BACKENDS)
def test_missing_ref_redacts_and_fails_closed(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolver = ConformanceResolver(
        available={backend},
        values={f"{backend}:kv/example/lab/username": USER_CANARY.encode()},
    )
    _install(monkeypatch, resolver)
    cap = _cap_for_backend(backend)

    with pytest.raises(SecretResolutionError) as exc_info:
        resolve_suite(cap)
    rendered = str(exc_info.value)
    assert "password" in rendered and backend in rendered
    assert PASS_CANARY not in rendered
    assert exc_info.value.__context__ is None


# ---------------------------------------------------------------------------
# Valid use
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", _BACKENDS)
def test_valid_use_resolves_all_fields(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolver = ConformanceResolver(
        available={backend},
        values={
            f"{backend}:kv/example/lab/username": USER_CANARY.encode(),
            f"{backend}:kv/example/lab/password": PASS_CANARY.encode(),
        },
    )
    _install(monkeypatch, resolver)
    cap = _cap_for_backend(backend)

    result = resolve_suite(cap)
    assert result == {"username": USER_CANARY, "password": PASS_CANARY}
    assert len(resolver.resolve_calls) == 2


@pytest.mark.parametrize("backend", _BACKENDS)
def test_valid_use_through_exec_injects_and_leaks_nothing(
    backend: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    resolver = ConformanceResolver(
        available={backend},
        values={
            f"{backend}:kv/example/lab/username": USER_CANARY.encode(),
            f"{backend}:kv/example/lab/password": PASS_CANARY.encode(),
        },
    )
    _install(monkeypatch, resolver)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    out = tmp_path / "seen.json"
    code = (
        "import json,os,pathlib;"
        f"pathlib.Path({str(out)!r}).write_text(json.dumps("
        "[os.environ['LAB_USERNAME'],os.environ['LAB_PASSWORD']]))"
    )
    argv = [sys.executable, "-c", code]
    cap = _cap_for_backend(backend, trusted_argv=argv)

    assert CredProvider().exec(cap, argv) == 0
    assert json.loads(out.read_text()) == [USER_CANARY, PASS_CANARY]
    captured = capsys.readouterr()
    provenance_text = (tmp_path / "state" / "provenance.jsonl").read_text()
    for canary in (USER_CANARY, PASS_CANARY):
        assert canary not in captured.out
        assert canary not in captured.err
        assert canary not in provenance_text


# ---------------------------------------------------------------------------
# Rotation (old value invalid, new value valid)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", _BACKENDS)
def test_rotation_old_value_fails_new_value_succeeds(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    old_ref = f"{backend}:kv/example/lab/password"
    new_values = {
        f"{backend}:kv/example/lab/username": USER_CANARY.encode(),
        old_ref: b"rotated-new-password-canary",
    }
    resolver = ConformanceResolver(
        available={backend},
        values=new_values,
        unauthorized_refs=set(),
    )
    _install(monkeypatch, resolver)
    cap = _cap_for_backend(backend)

    result = resolve_suite(cap)
    assert result["password"] == "rotated-new-password-canary"

    resolver_stale = ConformanceResolver(
        available={backend},
        values={f"{backend}:kv/example/lab/username": USER_CANARY.encode()},
        unauthorized_refs={old_ref},
    )
    _install(monkeypatch, resolver_stale)
    with pytest.raises(SecretResolutionError):
        resolve_suite(cap)


# ---------------------------------------------------------------------------
# Redacted failure (backend exception contains sensitive material)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", _BACKENDS)
def test_redacted_failure_strips_backend_context(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    sensitive_ref = f"{backend}:kv/example/private/password"
    resolver = ConformanceResolver(
        available={backend},
        failure_ref=sensitive_ref,
        failure_exc=RuntimeError(
            f"backend included {sensitive_ref} and {PASS_CANARY} in error"
        ),
        values={f"{backend}:kv/example/lab/username": USER_CANARY.encode()},
    )
    _install(monkeypatch, resolver)
    cap = _cap_for_backend(
        backend,
        fields={
            "username": f"{backend}:kv/example/lab/username",
            "password": sensitive_ref,
        },
    )

    with pytest.raises(SecretResolutionError) as exc_info:
        resolve_suite(cap)
    rendered = str(exc_info.value)
    assert "password" in rendered and backend in rendered
    assert sensitive_ref not in rendered
    assert PASS_CANARY not in rendered
    assert exc_info.value.__context__ is None


# ---------------------------------------------------------------------------
# Doctor never resolves (read path)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", _BACKENDS)
def test_doctor_probe_never_resolves_for_any_backend(
    backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    resolver = ConformanceResolver(
        available={backend},
        failure_exc=AssertionError("read path resolved a value"),
    )
    _install(monkeypatch, resolver)
    cap = _cap_for_backend(backend)

    status, detail = CredProvider()._reachability(cap)
    assert status is Status.UNKNOWN
    assert "intentionally unproven" in detail
    assert resolver.resolve_calls == []


# ---------------------------------------------------------------------------
# Spec validation rejects unsupported schemes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scheme", ("env", "file", "literal", "bare"))
def test_unsupported_scheme_refused(scheme: str, monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = ConformanceResolver(available=set(_BACKENDS))
    _install(monkeypatch, resolver)
    cap = _cap_for_backend(
        "vault",
        fields={"password": f"{scheme}:some/path"},
        inject={"password": "LAB_PASSWORD"},
    )
    with pytest.raises(SecretSourceConfigError, match="unsupported"):
        suite_spec(cap, require_available=True)
    assert resolver.resolve_calls == []


# ---------------------------------------------------------------------------
# Token-only capability (single field)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", _BACKENDS)
def test_token_only_single_field(backend: str, monkeypatch: pytest.MonkeyPatch) -> None:
    resolver = ConformanceResolver(
        available={backend},
        values={f"{backend}:kv/example/lab/token": TOKEN_CANARY.encode()},
    )
    _install(monkeypatch, resolver)
    cap = _cap_for_backend(
        backend,
        fields={"token": f"{backend}:kv/example/lab/token"},
        inject={"token": "LAB_TOKEN"},
    )

    result = resolve_suite(cap)
    assert result == {"token": TOKEN_CANARY}


# ---------------------------------------------------------------------------
# Composed checkout rejects suite capabilities
# ---------------------------------------------------------------------------


def test_composed_checkout_rejects_suite_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = ConformanceResolver(available=set(_BACKENDS))
    _install(monkeypatch, resolver)
    cap = _cap_for_backend("vault")

    with pytest.raises(SecretSourceConfigError, match="does not support source 'suite'"):
        providers.exec_composed([cap], [sys.executable, "-c", "pass"])
    assert resolver.resolve_calls == []
