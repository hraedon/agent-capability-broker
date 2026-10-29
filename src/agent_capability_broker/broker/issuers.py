"""Issuers: where a checkout's value comes from, and how it is revoked.

Plan 012 §2: **the VM's identity may obtain issued credentials, never the
means to issue them.** So the in-VM issuers are thin:

- ``vault-k8s-token`` — Vault's Kubernetes secrets engine mints a short-lived
  service-account token inside Vault (``<mount>/creds/<role>``); the broker
  revokes the lease. ``D1``.
- ``vault-kv`` — a legacy static KV v2 read. ``D0`` by definition: the value
  is a standing secret and revoking the checkout only forgets the in-memory
  copy; nothing in Vault can be revoked.
- ``remote-mint`` — declared for manifests, served by ``acb-ops`` off the VM
  (Plan 012 P2). Here it refuses with ``not_implemented``.
- ``fake`` — tests only; never registered by the entry point.

Vault access goes through ``cred_vault`` (lazily imported — the broker never
imports ``hvac`` at module import time), reusing its WI-016 fail-closed auth
invariants. The broker additionally refuses a bare ``VAULT_TOKEN``: it runs
on the VM's AppRole or Kubernetes identity only (Plan 012 §1).

An :class:`Issued` holds the value in ``value_fields`` with ``repr=False`` so
an accidental log of the object does not print it. Error messages never
interpolate a value or a Vault response body.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .config import BrokerCapability
from .protocol import ErrorCode


class IssuerError(Exception):
    """An issuer refused or failed. ``message`` is value-free."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class IssueContext:
    """Advisory facts about the caller, plus the TTL the broker will honour."""

    capability_id: str
    harness: str
    session: str
    ttl: int


@dataclass(frozen=True)
class Issued:
    value_fields: dict[str, str] = field(repr=False)
    ttl: int
    revocation_handle: str | None  # e.g. a Vault lease id; never a value


class Issuer(Protocol):
    kind: str

    def issue(self, cap: BrokerCapability, ctx: IssueContext) -> Issued: ...

    def revoke(self, handle: str | None) -> None: ...


# ---------------------------------------------------------------- fake


class FakeIssuer:
    """Deterministic in-memory issuer for tests. Records issue/revoke calls."""

    kind = "fake"

    def __init__(
        self,
        value_factory: Callable[[BrokerCapability, int], dict[str, str]] | None = None,
        *,
        ttl: int | None = None,
        fail_revoke: bool = False,
    ) -> None:
        self._factory = value_factory
        self._ttl = ttl
        self.fail_revoke = fail_revoke
        self.issued: list[str] = []
        self.revoked: list[str] = []
        self._n = 0
        self._lock = threading.Lock()

    def issue(self, cap: BrokerCapability, ctx: IssueContext) -> Issued:
        with self._lock:
            self._n += 1
            n = self._n
        handle = f"fake/creds/{cap.id}/{n}"
        fields = (
            self._factory(cap, n)
            if self._factory
            else {"username": "fake-user", "password": f"fake-value-{n}"}
        )
        self.issued.append(handle)
        ttl = min(ctx.ttl, self._ttl) if self._ttl is not None else ctx.ttl
        return Issued(value_fields=dict(fields), ttl=ttl, revocation_handle=handle)

    def revoke(self, handle: str | None) -> None:
        if self.fail_revoke:
            raise IssuerError(ErrorCode.ISSUER_ERROR, "fake revoke failure")
        if handle is not None:
            self.revoked.append(handle)


# ---------------------------------------------------------------- Vault


def _default_vault_client() -> Any:
    """The VM's one Vault identity, via ``cred_vault`` (lazy import, no ambient token)."""
    from .. import cred_vault

    return cred_vault.authenticated_client(allow_token=False)


def _is_auth_error(exc: BaseException) -> bool:
    # hvac.exceptions.{Forbidden,Unauthorized}, matched by name so this module
    # never imports hvac. An expired broker token surfaces as one of these.
    return type(exc).__name__ in {"Forbidden", "Unauthorized"}


class VaultSession:
    """One cached, authenticated client shared by every Vault issuer.

    On an auth error the client is dropped, re-authenticated once, and the call
    retried once — enough to survive a token that expired between checkouts
    without ever looping on a real policy denial.
    """

    def __init__(self, factory: Callable[[], Any] | None = None) -> None:
        self._factory = factory or _default_vault_client
        self._client: Any = None
        self._lock = threading.Lock()

    def _get(self) -> Any:
        with self._lock:
            if self._client is None:
                try:
                    self._client = self._factory()
                except RuntimeError as exc:
                    # cred_vault's refusals are value-free by contract.
                    raise IssuerError(ErrorCode.ISSUER_ERROR, f"vault auth: {exc}") from exc
            return self._client

    def invalidate(self) -> None:
        with self._lock:
            self._client = None

    def call(self, what: str, fn: Callable[[Any], Any]) -> Any:
        try:
            return fn(self._get())
        except IssuerError:
            raise
        except Exception as exc:
            if not _is_auth_error(exc):
                raise IssuerError(
                    ErrorCode.ISSUER_ERROR, f"{what} failed ({type(exc).__name__})"
                ) from exc
        self.invalidate()
        try:
            return fn(self._get())
        except IssuerError:
            raise
        except Exception as exc:
            raise IssuerError(
                ErrorCode.ISSUER_ERROR, f"{what} failed ({type(exc).__name__})"
            ) from exc


# Lease ids look like `kubernetes/creds/<role>/<random>`. They are spliced into a
# request path (`sys/leases/revoke/<lease_id>`), so anything else is refused.
_LEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]{0,511}$")


def _valid_lease(handle: str) -> str:
    if not _LEASE_RE.match(handle) or ".." in handle.split("/"):
        raise IssuerError(ErrorCode.ISSUER_ERROR, "revocation handle is not a Vault lease id")
    return handle


class VaultKvIssuer:
    """Legacy static KV v2 read. ``D0``: revocation only forgets the value."""

    kind = "vault-kv"

    def __init__(self, session: VaultSession) -> None:
        self._session = session

    def issue(self, cap: BrokerCapability, ctx: IssueContext) -> Issued:
        p = cap.issuer.params
        mount, _, sub = str(p["path"]).partition("/")
        want = [str(f) for f in p["fields"]]
        resp = self._session.call(
            f"vault read for {cap.id}",
            lambda c: c.secrets.kv.v2.read_secret_version(
                mount_point=mount, path=sub, raise_on_deleted_version=True
            ),
        )
        try:
            data = resp["data"]["data"]
        except (KeyError, TypeError) as exc:
            raise IssuerError(
                ErrorCode.ISSUER_ERROR, f"vault read for {cap.id}: unexpected response shape"
            ) from exc
        if not isinstance(data, dict):
            raise IssuerError(
                ErrorCode.ISSUER_ERROR, f"vault read for {cap.id}: unexpected response shape"
            )
        missing = [f for f in want if f not in data]
        if missing:
            raise IssuerError(ErrorCode.ISSUER_ERROR, f"fields {missing!r} not found for {cap.id}")
        out: dict[str, str] = {}
        for f in want:
            if not isinstance(data[f], str):
                raise IssuerError(
                    ErrorCode.ISSUER_ERROR, f"field {f!r} for {cap.id} is not a string"
                )
            out[f] = data[f]
        return Issued(value_fields=out, ttl=ctx.ttl, revocation_handle=None)

    def revoke(self, handle: str | None) -> None:
        # A static value cannot be revoked from here; the registry drops the
        # in-memory copy. This is exactly why vault-kv is D0.
        return None


class VaultK8sTokenIssuer:
    """Vault Kubernetes secrets engine: ``<mount>/creds/<role>``. ``D1``."""

    kind = "vault-k8s-token"

    def __init__(self, session: VaultSession) -> None:
        self._session = session

    def issue(self, cap: BrokerCapability, ctx: IssueContext) -> Issued:
        p = cap.issuer.params
        mount = str(p.get("mount", "kubernetes"))
        role = str(p["role"])
        data: dict[str, Any] = {
            "kubernetes_namespace": str(p["namespace"]),
            "ttl": f"{ctx.ttl}s",
        }
        if "audiences" in p:
            data["audiences"] = ",".join(str(a) for a in p["audiences"])
        if "cluster_role_binding" in p:
            data["cluster_role_binding"] = bool(p["cluster_role_binding"])
        resp = self._session.call(
            f"vault k8s creds for {cap.id}",
            lambda c: c.write_data(f"{mount}/creds/{role}", data=data),
        )
        shape_err = IssuerError(
            ErrorCode.ISSUER_ERROR, f"vault k8s creds for {cap.id}: unexpected response shape"
        )
        if not isinstance(resp, dict):
            raise shape_err
        lease_id = resp.get("lease_id")
        duration = resp.get("lease_duration")
        body = resp.get("data")
        token = body.get("service_account_token") if isinstance(body, dict) else None
        if not isinstance(lease_id, str) or not lease_id or not isinstance(token, str) or not token:
            raise shape_err
        ttl = ctx.ttl
        if isinstance(duration, int) and not isinstance(duration, bool) and duration > 0:
            ttl = min(ttl, duration)
        return Issued(value_fields={"token": token}, ttl=ttl, revocation_handle=lease_id)

    def revoke(self, handle: str | None) -> None:
        if handle is None:
            return
        lease = _valid_lease(handle)
        # The URL form (`sys/leases/revoke/<lease_id>`) lets the VM policy scope
        # revocation to its own engine paths: `sys/leases/revoke/<mount>/creds/<role>/*`.
        self._session.call("vault lease revoke", lambda c: c.write_data(
            f"sys/leases/revoke/{lease}"
        ))


class RemoteMintIssuer:
    """Placeholder for ``acb-ops`` mint endpoints (Plan 012 §2, phase P2)."""

    kind = "remote-mint"

    def issue(self, cap: BrokerCapability, ctx: IssueContext) -> Issued:
        raise IssuerError(
            ErrorCode.NOT_IMPLEMENTED,
            f"{cap.id}: remote-mint issuers are served by acb-ops (Plan 012 P2), "
            f"which this broker does not implement yet",
        )

    def revoke(self, handle: str | None) -> None:
        if handle is not None:
            raise IssuerError(ErrorCode.NOT_IMPLEMENTED, "remote-mint revocation not implemented")


def default_issuers(session: VaultSession | None = None) -> dict[str, Issuer]:
    """The production issuer table. ``fake`` is deliberately absent."""
    s = session or VaultSession()
    return {
        "vault-kv": VaultKvIssuer(s),
        "vault-k8s-token": VaultK8sTokenIssuer(s),
        "remote-mint": RemoteMintIssuer(),
    }


__all__ = [
    "FakeIssuer",
    "IssueContext",
    "Issued",
    "Issuer",
    "IssuerError",
    "RemoteMintIssuer",
    "VaultK8sTokenIssuer",
    "VaultKvIssuer",
    "VaultSession",
    "default_issuers",
]
