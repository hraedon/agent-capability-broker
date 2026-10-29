"""Issuers: where a checkout's value comes from, and how it is revoked.

Plan 012 §2: **the VM's identity may obtain issued credentials, never the
means to issue them.** So the in-VM issuers are thin:

- ``vault-k8s-token`` — Vault's Kubernetes secrets engine mints a short-lived
  service-account token inside Vault (``<mount>/creds/<role>``). The creds are
  read with a per-checkout **child token** of the broker's own token, and
  revoked with ``auth/token/revoke-self`` called by that child (Vault revokes
  every lease the token created). The VM policy therefore needs nothing under
  ``sys/leases`` and not ``auth/token/revoke-accessor``. ``D1``.
- ``vault-kv`` — a legacy static KV v2 read. ``D0`` by definition: the value
  is a standing secret and revoking the checkout only forgets the in-memory
  copy; nothing in Vault can be revoked.
- ``remote-mint`` — declared for manifests, served by ``acb-ops`` off the VM
  (Plan 012 P2). Here it refuses with ``not_implemented``.
- ``fake`` — tests only; never registered by the entry point.

Child tokens live only in this process's memory. If the broker restarts, the
token is gone and its lease simply expires with the token's TTL (at most 15
minutes); only the token *accessor* and the checkout expiry are persisted, for
``checkouts`` display. See ``docs/broker.md``.

Vault access goes through ``cred_vault`` (lazily imported — the broker never
imports ``hvac`` at module import time), reusing its WI-016 fail-closed auth
invariants. The broker additionally refuses a bare ``VAULT_TOKEN``: it runs
on the VM's AppRole or Kubernetes identity only (Plan 012 §1).

An :class:`Issued` holds the value in ``value_fields`` with ``repr=False`` so
an accidental log of the object does not print it. Error messages never
interpolate a value or a Vault response body.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .config import BrokerCapability
from .protocol import ErrorCode

log = logging.getLogger("acb.broker")


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
    revocation_handle: str | None  # opaque, e.g. a Vault child-token accessor; never a value
    accessor: str | None = None    # non-secret reference persisted for `checkouts` display


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


#: A child token (and so the lease read with it) never outlives the checkout, and
#: never lives longer than this regardless of the manifest (Plan 012 section 6).
CHILD_TOKEN_MAX_TTL = 15 * 60
#: Uses a child token is allowed: the creds read, ``revoke-self``, and one retry of
#: either. Bounded so a leaked token cannot be replayed freely. It must stay above
#: the number of uses the broker itself needs: a token whose last use is spent is
#: revoked by Vault, and that revokes its leases.
CHILD_TOKEN_NUM_USES = 3


def _default_child_client(parent: Any, token: str) -> Any:
    """A client authenticated with ``token`` only (lazy ``hvac`` import).

    Built like ``cred_vault.authenticated_client``: ``token`` is passed explicitly
    (never ``None``, which would make hvac read ``$VAULT_TOKEN`` and
    ``~/.vault-token``) and nothing else is inherited from the parent.
    """
    import hvac

    return hvac.Client(url=parent.url, token=token)


@dataclass
class _Child:
    """A live per-checkout child token. In-memory only; never persisted or logged."""

    client: Any = field(repr=False)
    expires_at: float


class ChildTokenLeases:
    """Token-bound lease management for dynamic Vault engines.

    ``sys/leases/revoke`` would let the VM identity revoke *other* identities'
    leases, and ``auth/token/revoke-accessor`` would let it revoke any token it
    can learn the accessor of -- both broader than the VM needs. Instead, each
    checkout gets its own child token (``auth/token/create``: non-orphan,
    policies a subset of the parent's, ttl = the checkout's, capped at 15 min,
    bounded ``num_uses``, not renewable, service type). The creds are read with
    the child token, so Vault ties the lease to it, and revocation is the child
    calling ``auth/token/revoke-self``, which revokes everything the token
    created. Letting the token expire does the same, so a broker restart (the
    token held in memory is lost) leaves the lease to die with the TTL.
    """

    def __init__(
        self,
        session: VaultSession,
        *,
        clock: Callable[[], float] = time.time,
        client_factory: Callable[[Any, str], Any] | None = None,
    ) -> None:
        self._session = session
        self._clock = clock
        self._client_factory = client_factory or _default_child_client
        self._held: dict[str, _Child] = {}
        self._lock = threading.Lock()

    @property
    def clock(self) -> Callable[[], float]:
        return self._clock

    def held(self) -> int:
        """How many child tokens this process currently holds (for tests/status)."""
        with self._lock:
            return len(self._held)

    def issue(
        self,
        what: str,
        ttl: int,
        policies: list[str] | None,
        read: Callable[[Any], Any],
    ) -> tuple[Any, str, float]:
        """Mint a child token, run ``read(child_client)`` with it.

        Returns ``(result, accessor, expires_at)``. On any failure after the token
        exists it is revoked straight away (best effort) so nothing dangles.
        """
        child_ttl = max(1, min(ttl, CHILD_TOKEN_MAX_TTL))
        body: dict[str, Any] = {
            "ttl": f"{child_ttl}s",
            "num_uses": CHILD_TOKEN_NUM_USES,
            "renewable": False,
            "type": "service",
            "no_parent": False,      # explicit: a child, never an orphan
            "display_name": "acb-broker",
        }
        if policies:
            body["policies"] = list(policies)  # must be a subset of the parent's
        parent: list[Any] = []

        def mint(c: Any) -> Any:
            parent[:] = [c]
            return c.write_data("auth/token/create", data=body)

        resp = self._session.call(f"vault child token for {what}", mint)
        auth = resp.get("auth") if isinstance(resp, dict) else None
        token = auth.get("client_token") if isinstance(auth, dict) else None
        accessor = auth.get("accessor") if isinstance(auth, dict) else None
        if (
            not isinstance(auth, dict)
            or not isinstance(token, str) or not token
            or not isinstance(accessor, str) or not accessor
        ):
            raise IssuerError(
                ErrorCode.ISSUER_ERROR, f"vault child token for {what}: unexpected response shape"
            )
        duration = auth.get("lease_duration")
        if isinstance(duration, int) and not isinstance(duration, bool) and duration > 0:
            child_ttl = min(child_ttl, duration)
        child = _Child(
            client=self._client_factory(parent[0], token), expires_at=self._clock() + child_ttl
        )
        try:
            result = read(child.client)
        except Exception as exc:
            self._revoke_quietly(child)
            if isinstance(exc, IssuerError):
                raise
            raise IssuerError(
                ErrorCode.ISSUER_ERROR, f"{what} failed ({type(exc).__name__})"
            ) from exc
        with self._lock:
            self._held[accessor] = child
        return result, accessor, child.expires_at

    def revoke(self, accessor: str | None) -> None:
        """``auth/token/revoke-self`` with the checkout's own child token.

        An accessor this process does not hold (it restarted) is not an error:
        the lease dies with the token's TTL, and that is all that can be done
        without a broader Vault capability.
        """
        if accessor is None:
            return
        with self._lock:
            child = self._held.get(accessor)
        if child is None:
            log.info(
                "child token %s is not held (broker restarted?); its lease expires with the "
                "token TTL (<= %ds)", accessor, CHILD_TOKEN_MAX_TTL,
            )
            return
        if self._clock() >= child.expires_at:
            # Vault already revoked the token (and so its leases) at expiry.
            with self._lock:
                self._held.pop(accessor, None)
            return
        try:
            child.client.write_data("auth/token/revoke-self")
        except Exception as exc:
            raise IssuerError(
                ErrorCode.ISSUER_ERROR, f"vault token revoke-self failed ({type(exc).__name__})"
            ) from exc
        with self._lock:
            self._held.pop(accessor, None)

    def _revoke_quietly(self, child: _Child) -> None:
        try:
            child.client.write_data("auth/token/revoke-self")
        except Exception as exc:
            log.warning(
                "could not revoke an unused child token (%s); it expires with its TTL",
                type(exc).__name__,
            )


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
    """Vault Kubernetes secrets engine: ``<mount>/creds/<role>``. ``D1``.

    Read with a per-checkout child token; revoked with that token's
    ``revoke-self`` (see :class:`ChildTokenLeases`). Needs no ``sys/leases``.
    """

    kind = "vault-k8s-token"

    def __init__(self, session: VaultSession, *, leases: ChildTokenLeases | None = None) -> None:
        self._session = session
        self._leases = leases or ChildTokenLeases(session)

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
        policies = [str(x) for x in p["token_policies"]] if "token_policies" in p else None
        resp, accessor, token_expiry = self._leases.issue(
            f"vault k8s creds for {cap.id}",
            ctx.ttl,
            policies,
            lambda child: child.write_data(f"{mount}/creds/{role}", data=data),
        )
        shape_err = IssuerError(
            ErrorCode.ISSUER_ERROR, f"vault k8s creds for {cap.id}: unexpected response shape"
        )
        body = resp.get("data") if isinstance(resp, dict) else None
        token = body.get("service_account_token") if isinstance(body, dict) else None
        if not isinstance(resp, dict) or not isinstance(token, str) or not token:
            self._leases.revoke(accessor)
            raise shape_err
        duration = resp.get("lease_duration")
        ttl = ctx.ttl
        if isinstance(duration, int) and not isinstance(duration, bool) and duration > 0:
            ttl = min(ttl, duration)
        # The lease cannot outlive the child token that created it.
        ttl = max(1, min(ttl, int(token_expiry - self._leases.clock())))
        return Issued(
            value_fields={"token": token}, ttl=ttl, revocation_handle=accessor, accessor=accessor
        )

    def revoke(self, handle: str | None) -> None:
        self._leases.revoke(handle)


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
    "CHILD_TOKEN_MAX_TTL",
    "CHILD_TOKEN_NUM_USES",
    "ChildTokenLeases",
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
