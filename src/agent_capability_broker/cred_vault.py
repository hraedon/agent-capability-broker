"""Vault backend for the `cred` provider. NOT part of the stdlib-only core.

Imported lazily by `providers.CredProvider` only when a capability uses
`source = "vault"`. Requires the `[cred]` extra (hvac). Auth resolves inside the
provider — the agent never thinks about how it authenticated:

    in-cluster k8s service-account token  ->  AppRole (env)  ->  VAULT_TOKEN

`resolve` returns the requested field(s); it never logs or returns anything to
the model context (the caller injects into a child process).
"""

from __future__ import annotations

import os
from pathlib import Path

from .model import Capability

_K8S_TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")


def _authenticate(client: object) -> None:
    """Log `client` in by the first available method. Raises if none work."""
    # 1. In-cluster Kubernetes auth (no secret_id on disk).
    if _K8S_TOKEN.is_file():
        role = os.environ.get("VAULT_K8S_ROLE")
        if role:
            jwt = _K8S_TOKEN.read_text(encoding="utf-8").strip()
            client.auth.kubernetes.login(role=role, jwt=jwt)  # type: ignore[attr-defined]
            return
    # 2. AppRole (role_id + secret_id from env / the .env file).
    role_id = os.environ.get("VAULT_ROLE_ID")
    secret_id = os.environ.get("VAULT_SECRET_ID")
    if role_id and secret_id:
        client.auth.approle.login(role_id=role_id, secret_id=secret_id)  # type: ignore[attr-defined]
        return
    # 3. A pre-existing token (VAULT_TOKEN handled by hvac.Client init).
    if getattr(client, "token", None):
        return
    raise RuntimeError(
        "no Vault auth available (tried k8s service-account, AppRole, VAULT_TOKEN)"
    )


def _split_mount(path: str) -> tuple[str, str]:
    """`kv/example/ad/svc-bot` -> (`kv`, `example/ad/svc-bot`)."""
    head, _, tail = path.partition("/")
    if not head or not tail:
        raise RuntimeError(f"vault path {path!r} must be '<mount>/<path>'")
    return head, tail


def resolve(cap: Capability) -> dict[str, str]:
    """Read the capability's secret field(s) from Vault (KV v2)."""
    try:
        import hvac
    except ImportError as exc:
        raise RuntimeError(
            "cred source 'vault' needs the [cred] extra: "
            "pip install 'agent-capability-broker[cred]'"
        ) from exc

    addr = os.environ.get("VAULT_ADDR")
    if not addr:
        raise RuntimeError("VAULT_ADDR is not set")
    path = cap.options.get("vault")
    if not isinstance(path, str) or not path:
        raise RuntimeError(f"capability {cap.id!r} has no 'vault' path")

    client = hvac.Client(url=addr, token=os.environ.get("VAULT_TOKEN"))
    _authenticate(client)

    mount, secret_path = _split_mount(path)
    resp = client.secrets.kv.v2.read_secret_version(
        mount_point=mount, path=secret_path, raise_on_deleted_version=True
    )
    data = resp["data"]["data"]

    field = str(cap.options.get("field", "password"))
    out: dict[str, str] = {}
    if field in data:
        out[field] = str(data[field])
    if not out:
        raise RuntimeError(f"field {field!r} not found at {path}")
    return out
