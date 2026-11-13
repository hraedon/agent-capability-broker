"""`acb kube-token`: a standalone kubectl exec-credential plugin. No daemon.

kubectl runs ``acb kube-token <capability-id>`` (a kubeconfig ``exec`` block),
reads one ``ExecCredential`` JSON document from stdout, and uses the token.
Unlike the ``acb-broker`` daemon path (Linux, socket, per-checkout child token,
checkout registry), this authenticates to Vault exactly the way ``acb exec``
does for a vault-sourced credential (``cred_vault.authenticated_client``: the
WI-016 ``token=""`` and fail-closed AppRole invariants), makes **one** write to
``<mount>/creds/<role>`` with that login token, and prints the result. It does
not create a child token. The owned Vault login is revoked after the request
(best effort); the issued Kubernetes token for a pre-existing ServiceAccount
remains valid until its own expiry. The policy also needs ``revoke-self``
(normally supplied by Vault's default policy).

The issuer/delivery declaration is validated by the broker's own parser
(``broker.config``, stdlib-only, importable on Windows) so there is one parser,
including its 15-minute TTL cap. ``hvac`` is reached lazily through
``cred_vault``.

The token is only ever held in a local variable and written once to stdout. Any
failure is reduced to the exception *class name* on stderr: an upstream
exception string can embed the request body or an address.
"""

from __future__ import annotations

import json
import math
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from .broker.config import (
    DEFAULT_TTL_SECONDS,
    BrokerConfigError,
    _parse_delivery,
    _parse_issuer,
)
from .model import Capability, ManifestError, parse_manifest, resolve_manifest

#: Subtracted from the lease so kubectl never presents a token at the edge of expiry.
SAFETY_MARGIN_SECONDS = 30
_API_VERSION = "client.authentication.k8s.io/v1"


class KubeTokenConfigError(Exception):
    """The capability cannot be served by ``acb kube-token`` (usage/config; exit 2)."""


def _find_capability(cap_id: str, manifest: str | None) -> Capability:
    try:
        caps = parse_manifest(resolve_manifest(manifest))
    except ManifestError as exc:
        raise KubeTokenConfigError(str(exc)) from exc
    cap = next((c for c in caps if c.id == cap_id), None)
    if cap is None:
        raise KubeTokenConfigError(f"capability {cap_id!r} not in manifest")
    return cap


def validate(cap: Capability) -> dict[str, Any]:
    """Check `cap` is a kubectl helper-rung ``vault-k8s-token`` capability and
    return the validated issuer params (``mount``/``role``/``namespace``/...)
    plus ``ttl`` (seconds, only when declared) under ``"_ttl"``."""
    if cap.provider != "cred":
        raise KubeTokenConfigError(f"{cap.id}: provider must be 'cred' (got {cap.provider!r})")
    if cap.issuer is None or cap.issuer_kind != "vault-k8s-token":
        raise KubeTokenConfigError(
            f"{cap.id}: issuer.kind must be 'vault-k8s-token' (got {cap.issuer_kind!r})"
        )
    if cap.rung != "helper" or cap.delivery.get("tool") != "kubectl":
        raise KubeTokenConfigError(
            f"{cap.id}: delivery must be rung 'helper' with tool 'kubectl' "
            f"(got rung {cap.rung!r}, tool {cap.delivery.get('tool')!r})"
        )
    try:
        issuer = _parse_issuer(cap.id, cap.issuer)
        _parse_delivery(cap.id, cap.delivery)
    except BrokerConfigError as exc:
        raise KubeTokenConfigError(str(exc)) from exc
    params = dict(issuer.params)
    params["_ttl"] = issuer.ttl
    params["_ttl_declared"] = "ttl" in cap.issuer
    return params


def request_body(params: dict[str, Any]) -> dict[str, Any]:
    """The write body for ``<mount>/creds/<role>``."""
    body: dict[str, Any] = {"kubernetes_namespace": str(params["namespace"])}
    if params["_ttl_declared"]:
        body["ttl"] = f"{int(params['_ttl'])}s"
    if "audiences" in params:
        body["audiences"] = ",".join(str(a) for a in params["audiences"])
    if "cluster_role_binding" in params:
        body["cluster_role_binding"] = bool(params["cluster_role_binding"])
    return body


def exec_credential(token: str, now: float, lease_seconds: int) -> dict[str, Any]:
    """The kubectl ``ExecCredential`` document; expiry is ``now + lease - margin``,
    never earlier than ``now``."""
    expiry = max(math.floor(now), math.floor(now + lease_seconds - SAFETY_MARGIN_SECONDS))
    stamp = datetime.fromtimestamp(expiry, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "apiVersion": _API_VERSION,
        "kind": "ExecCredential",
        "status": {"token": token, "expirationTimestamp": stamp},
    }


def mint(
    params: dict[str, Any],
    *,
    client: Any = None,
    clock: Callable[[], float] = time.time,
    revoke: bool = False,
) -> dict[str, Any]:
    """One Vault write with the login token; returns the ExecCredential document.

    ``client`` is an authenticated hvac client (tests inject a fake); production
    builds one through ``cred_vault.authenticated_client``.
    """
    from . import cred_vault  # lazy: the [cred] extra stays optional

    path = f"{params.get('mount', 'kubernetes')}/creds/{params['role']}"
    # Injected clients are borrowed by default; callers can opt into cleanup.
    with cred_vault.client_session(client, allow_token=False, revoke=revoke) as active:
        resp = active.write_data(path, data=request_body(params))  # type: ignore[attr-defined]
    data = resp.get("data") if isinstance(resp, dict) else None
    token = data.get("service_account_token") if isinstance(data, dict) else None
    if not isinstance(token, str) or not token:
        raise ValueError("unexpected response shape")
    duration = resp.get("lease_duration")
    if isinstance(duration, int) and not isinstance(duration, bool) and duration > 0:
        lease = duration
    else:
        lease = int(params["_ttl"]) if params["_ttl_declared"] else DEFAULT_TTL_SECONDS
    return exec_credential(token, clock(), lease)


def run(
    cap_id: str,
    manifest: str | None = None,
    *,
    client: Any | None = None,
    clock: Callable[[], float] = time.time,
) -> int:
    """Entry point for ``acb kube-token``: 0 ok, 1 operational failure, 2 usage/config.

    stdout carries the single JSON line on success and nothing otherwise; stderr
    carries one line on failure."""
    try:
        params = validate(_find_capability(cap_id, manifest))
    except KubeTokenConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        doc = mint(params, client=client, clock=clock)
    except Exception as exc:
        # Class name only: upstream text can embed the request body or an address.
        print(f"error: kube-token failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    sys.stdout.write(json.dumps(doc, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0
