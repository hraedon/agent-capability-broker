"""Closed credential-source dispatch and the optional suite resolver edge.

This module is stdlib-only.  Regista is imported lazily only for
``source = "suite"`` validation/resolution, keeping ACB's doctor and legacy
Vault/environment paths usable without the optional extra.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PureWindowsPath
from typing import Protocol, cast

from .model import Capability


class SecretSourceKind(StrEnum):
    ENV = "env"
    VAULT = "vault"
    SUITE = "suite"


class SecretSourceError(RuntimeError):
    """Base class for redacted source failures."""


class SecretSourceConfigError(SecretSourceError):
    """The capability's source declaration is unsafe or malformed."""


class SecretSourceUnavailable(SecretSourceError):
    """The optional resolver or requested provider is unavailable."""


class SecretResolutionError(SecretSourceError):
    """A value could not be resolved; message never contains a ref or value."""


class ResolverFacade(Protocol):
    API_VERSION: int

    def available_providers(self) -> list[str]: ...
    def reference_provider(self, ref: str, *, require_explicit: bool = False) -> str: ...
    def resolve(self, ref: str) -> bytes: ...


@dataclass(frozen=True)
class SuiteSecretSpec:
    refs: dict[str, str]
    inject: dict[str, str]
    providers: dict[str, str]
    trusted_argv: tuple[str, ...]
    timeout_seconds: float


_SUITE_PROVIDER_SCHEMES = frozenset({"vault", "azure", "windows"})
_LITERAL_OPTION_NAMES = frozenset({"value", "values", "raw", "literal", "secret"})
_DEFAULT_TIMEOUT_SECONDS = 300.0
_MAX_TIMEOUT_SECONDS = 900.0


def source_kind(cap: Capability) -> SecretSourceKind:
    raw = cap.options.get("source", "vault")
    if not isinstance(raw, str):
        raise SecretSourceConfigError(
            f"{cap.id}: credential source must be a string (got {type(raw).__name__})"
        )
    try:
        kind = SecretSourceKind(raw)
    except ValueError:
        kind = None
    if kind is None:
        raw = ""
        raise SecretSourceConfigError(
            f"{cap.id}: unknown credential source; expected env, vault, or suite"
        )
    return kind


def _suite_resolver() -> ResolverFacade:
    try:
        secrets = importlib.import_module("regista.secrets")
    except (ImportError, AttributeError) as exc:
        raise SecretSourceUnavailable(
            "source 'suite' needs the suite-secrets extra: "
            "pip install 'agent-capability-broker[suite-secrets]'"
        ) from exc
    required = ("API_VERSION", "available_providers", "reference_provider", "resolve")
    if any(not hasattr(secrets, name) for name in required):
        raise SecretSourceUnavailable(
            "source 'suite' needs a Regista release with the public regista.secrets facade"
        )
    if secrets.API_VERSION != 1:
        raise SecretSourceUnavailable(
            "source 'suite' needs regista.secrets API_VERSION 1"
        )
    return cast(ResolverFacade, secrets)


def _mapping(cap: Capability, name: str) -> dict[str, str]:
    raw = cap.options.get(name)
    if not isinstance(raw, dict) or not raw:
        raise SecretSourceConfigError(
            f"{cap.id}: source 'suite' requires a non-empty options.{name} mapping"
        )
    out: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key:
            raise SecretSourceConfigError(
                f"{cap.id}: options.{name} field names must be non-empty strings"
            )
        if not isinstance(value, str) or not value:
            raise SecretSourceConfigError(
                f"{cap.id}: options.{name}[{key!r}] must be a non-empty string"
            )
        out[key] = value
    return out


def _trusted_argv(cap: Capability) -> tuple[str, ...]:
    raw = cap.options.get("trusted_argv")
    if not isinstance(raw, list) or not raw:
        raise SecretSourceConfigError(
            f"{cap.id}: source 'suite' requires a non-empty options.trusted_argv list"
        )
    if any(not isinstance(part, str) or not part for part in raw):
        raise SecretSourceConfigError(
            f"{cap.id}: options.trusted_argv entries must be non-empty strings"
        )
    argv = tuple(raw)
    executable = argv[0]
    if not (Path(executable).is_absolute() or PureWindowsPath(executable).is_absolute()):
        raise SecretSourceConfigError(
            f"{cap.id}: options.trusted_argv must name an absolute executable path"
        )
    return argv


def validate_suite_command(cap: Capability, argv: list[str]) -> None:
    """Require the exact pre-qualified child command before touching a value."""
    trusted = _trusted_argv(cap)
    if tuple(argv) != trusted:
        raise SecretSourceConfigError(
            f"{cap.id}: requested command does not match options.trusted_argv"
        )


def _timeout_seconds(cap: Capability) -> float:
    raw = cap.options.get("timeout_seconds", _DEFAULT_TIMEOUT_SECONDS)
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        raise SecretSourceConfigError(
            f"{cap.id}: options.timeout_seconds must be a number"
        )
    value = float(raw)
    if not 0 < value <= _MAX_TIMEOUT_SECONDS:
        raise SecretSourceConfigError(
            f"{cap.id}: options.timeout_seconds must be greater than zero and at most "
            f"{int(_MAX_TIMEOUT_SECONDS)}"
        )
    return value


def suite_spec(cap: Capability, *, require_available: bool) -> SuiteSecretSpec:
    """Validate suite wiring without resolving any value."""
    forbidden = sorted(_LITERAL_OPTION_NAMES.intersection(cap.options))
    if forbidden:
        raise SecretSourceConfigError(
            f"{cap.id}: source 'suite' refuses literal/raw value option(s) {forbidden!r}"
        )
    refs = _mapping(cap, "refs")
    inject = _mapping(cap, "inject")
    trusted_argv = _trusted_argv(cap)
    timeout_seconds = _timeout_seconds(cap)
    if set(refs) != set(inject):
        missing = sorted(set(refs) - set(inject))
        unknown = sorted(set(inject) - set(refs))
        raise SecretSourceConfigError(
            f"{cap.id}: options.inject fields must exactly match options.refs "
            f"(missing={missing!r}, unknown={unknown!r})"
        )

    # Parse locally first. This fail-closed gate prevents an unknown or bare
    # reference from reaching Regista's backwards-compatible literal fallback.
    providers: dict[str, str] = {}
    for field, ref in refs.items():
        scheme, sep, tail = ref.partition(":")
        if not sep or not scheme or not tail:
            raise SecretSourceConfigError(
                f"{cap.id}: field {field!r} requires an explicit non-empty provider reference"
            )
        if scheme not in _SUITE_PROVIDER_SCHEMES:
            raise SecretSourceConfigError(
                f"{cap.id}: field {field!r} uses an unsupported suite provider; "
                f"expected {sorted(_SUITE_PROVIDER_SCHEMES)!r}"
            )
        providers[field] = scheme

    resolver = _suite_resolver()
    available = set(resolver.available_providers())
    for field, ref in refs.items():
        scheme = providers[field]
        canonical: str | None = None
        try:
            canonical = resolver.reference_provider(ref, require_explicit=True)
        except Exception:
            # Raise outside the except block so the redacted ACB exception does
            # not retain a backend exception/context that may contain the ref.
            pass
        if canonical is None:
            raise SecretSourceConfigError(
                f"{cap.id}: field {field!r} has an invalid {scheme!r} reference"
            )
        if canonical != scheme:
            raise SecretSourceConfigError(
                f"{cap.id}: field {field!r} provider validation disagreed with its reference"
            )
        if require_available and scheme not in available:
            raise SecretSourceUnavailable(
                f"{cap.id}: field {field!r} needs unavailable suite provider {scheme!r}"
            )
    return SuiteSecretSpec(
        refs=refs,
        inject=inject,
        providers=providers,
        trusted_argv=trusted_argv,
        timeout_seconds=timeout_seconds,
    )


def resolve_suite(cap: Capability, spec: SuiteSecretSpec | None = None) -> dict[str, str]:
    """Resolve suite fields as UTF-8 text, returning only redacted failures."""
    spec = spec or suite_spec(cap, require_available=True)
    resolver = _suite_resolver()
    resolved: dict[str, str] = {}
    for field, ref in spec.refs.items():
        provider = spec.providers[field]
        failed = False
        raw: bytes | None = None
        try:
            raw = resolver.resolve(ref)
            if not isinstance(raw, bytes):
                raise TypeError("resolver returned a non-bytes value")
            resolved[field] = raw.decode("utf-8")
        except Exception:
            failed = True
        finally:
            raw = None
        if failed:
            # Clear earlier fields before raising and raise outside the backend
            # exception handler: the ACB error and traceback retain neither a
            # value nor a value-bearing backend exception/context.
            for prior in resolved:
                resolved[prior] = ""
            raise SecretResolutionError(
                f"{cap.id}: field {field!r} could not be resolved by provider {provider!r}"
            )
    return resolved


__all__ = [
    "SecretResolutionError",
    "SecretSourceConfigError",
    "SecretSourceError",
    "SecretSourceKind",
    "SecretSourceUnavailable",
    "SuiteSecretSpec",
    "resolve_suite",
    "source_kind",
    "suite_spec",
    "validate_suite_command",
]
