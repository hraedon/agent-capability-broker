"""Vault backend for the `cred` provider. NOT part of the stdlib-only core.

Imported lazily by `providers.CredProvider` only when a capability uses
`source = "vault"`. Requires the `[cred]` extra (hvac). Auth resolves inside the
provider — the agent never thinks about how it authenticated:

    in-cluster k8s service-account token  ->  AppRole (env / .env file)  ->  VAULT_TOKEN

`resolve` returns the requested field(s); it never logs or returns anything to
the model context (the caller injects into a child process).
"""

from __future__ import annotations

import os
from pathlib import Path

from .model import Capability

_K8S_TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")


def _load_env_file(env_path: str | os.PathLike[str] | None = None) -> dict[str, str]:
    """Load `VAULT_*` vars from the AppRole `.env` file, if present.

    The charter calls for an "AppRole `.env`" auth path: the role_id/secret_id
    live in a file (not the shell env) so they don't persist in process tables.
    Path precedence: an explicit `env_path` (e.g. `doctor` probing a capability's
    *declared* access plane, independent of the shell), else `$ACB_VAULT_ENV`,
    else `~/.config/acb/vault.env`. Each harness points `ACB_VAULT_ENV` at its own
    file for role separation.

    Handles bash-style `export KEY=val` prefixes and a UTF-8 BOM. A malformed or
    unreadable file raises `RuntimeError` with the path (never the file's
    contents) so `doctor`/`exec` can surface an actionable diagnostic.
    """
    path = str(env_path) if env_path else (
        os.environ.get("ACB_VAULT_ENV") or str(Path.home() / ".config" / "acb" / "vault.env")
    )
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return {}
    except OSError as exc:
        reason = exc.strerror or str(exc)
        raise RuntimeError(f"cannot read ACB_VAULT_ENV file {path!r}: {reason}") from exc
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            f"ACB_VAULT_ENV file {path!r} is not valid UTF-8 (byte offset {exc.start})"
        ) from exc
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        val = val.strip().strip('"').strip("'")
        if key and key.startswith("VAULT"):
            out[key] = val
    return out


def _vault_env(env_path: str | os.PathLike[str] | None = None) -> dict[str, str]:
    """Merged Vault config: the `.env` file is the fallback; process env wins.

    `env_path` selects a specific `.env` (a capability's declared access plane);
    without it the `$ACB_VAULT_ENV`/default convention applies.
    """
    merged = _load_env_file(env_path)
    merged.update({k: v for k, v in os.environ.items() if k.startswith("VAULT")})
    return merged


def _authenticate(client: object, env: dict[str, str]) -> None:
    """Log `client` in by the first available method using the resolved `env`
    (passed in so the same access plane drives both addr lookup and auth). Raises
    if none work."""
    # 1. In-cluster Kubernetes auth (no secret_id on disk).
    if _K8S_TOKEN.is_file():
        role = env.get("VAULT_K8S_ROLE")
        if role:
            jwt = _K8S_TOKEN.read_text(encoding="utf-8").strip()
            client.auth.kubernetes.login(role=role, jwt=jwt)  # type: ignore[attr-defined]
            return
    # 2. AppRole (role_id + secret_id from env / the .env file).
    role_id = env.get("VAULT_ROLE_ID")
    secret_id = env.get("VAULT_SECRET_ID")
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


def reachable(cap: Capability, *, vault_env: str | os.PathLike[str] | None = None) -> bool:
    """Read-only broker reachability: authenticate, then a **token self-lookup**
    only — never reads the capability's secret (that would be a *use*, spine §4).

    `vault_env` pins the probe to a specific access-plane `.env` — `doctor` passes
    the capability's *declared* plane (the same file its shim embeds) so a
    multi-plane estate is checked per-plane instead of all capabilities being
    probed through whatever single `ACB_VAULT_ENV` the shell happens to hold
    (WI-008: that single-env probe over-claimed PRESENT_OK across planes).

    Raises `RuntimeError` when reachability cannot be determined (no `[cred]`
    extra, no `VAULT_ADDR`, or auth fails) so the caller maps it to `UNKNOWN`
    rather than over-claiming a verdict.
    """
    try:
        import hvac
    except ImportError as exc:
        raise RuntimeError(
            "cred reachability needs the [cred] extra: "
            "pip install 'agent-capability-broker[cred]'"
        ) from exc

    env = _vault_env(vault_env)
    addr = env.get("VAULT_ADDR")
    if not addr:
        raise RuntimeError("VAULT_ADDR is not set")

    client = hvac.Client(url=addr, token=env.get("VAULT_TOKEN"))
    _authenticate(client, env)
    return bool(client.is_authenticated())  # token self-lookup; no secret read


def resolve(cap: Capability) -> dict[str, str]:
    """Read the capability's secret field(s) from Vault (KV v2).

    Field selection is **required** (fail-closed): `options.fields` (a list)
    selects specific fields, or `options.field` (singular) reads one. When
    neither is set the call raises — a Vault secret is not curated for injection
    and defaulting to "all fields" risks over-exposing side-channel material
    (rotation notes, audit IDs, tokens stored alongside the password). Explicit
    selection is the safe default.
    """
    try:
        import hvac
    except ImportError as exc:
        raise RuntimeError(
            "cred source 'vault' needs the [cred] extra: "
            "pip install 'agent-capability-broker[cred]'"
        ) from exc

    fields_opt = cap.options.get("fields")
    if "fields" in cap.options and not isinstance(fields_opt, list):
        raise RuntimeError(
            f"capability {cap.id!r}: options.fields must be a list "
            f"(got {type(fields_opt).__name__})"
        )
    field_opt = cap.options.get("field")
    if field_opt is not None and not isinstance(field_opt, str):
        raise RuntimeError(
            f"capability {cap.id!r}: options.field must be a string "
            f"(got {type(field_opt).__name__})"
        )
    if isinstance(fields_opt, list):
        want = [str(f) for f in fields_opt]
    elif field_opt is not None:
        want = [field_opt]
    else:
        raise RuntimeError(
            f"capability {cap.id!r}: field selection required — set options.field "
            f"or options.fields (an explicit list of Vault secret keys to inject)"
        )

    env = _vault_env()
    addr = env.get("VAULT_ADDR")
    if not addr:
        raise RuntimeError("VAULT_ADDR is not set")
    path = cap.options.get("vault")
    if not isinstance(path, str) or not path:
        raise RuntimeError(f"capability {cap.id!r} has no 'vault' path")

    try:
        client = hvac.Client(url=addr, token=env.get("VAULT_TOKEN"))
        _authenticate(client, env)
        mount, secret_path = _split_mount(path)
        resp = client.secrets.kv.v2.read_secret_version(
            mount_point=mount, path=secret_path, raise_on_deleted_version=True
        )
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError(
            f"vault read failed for {cap.id} ({type(exc).__name__})"
        ) from exc
    data = resp["data"]["data"]

    out: dict[str, str] = {}
    missing: list[str] = []
    for f in want:
        if f in data:
            raw = data[f]
            if not isinstance(raw, str):
                raise RuntimeError(
                    f"capability {cap.id!r}: field {f!r} at {path} is "
                    f"{type(raw).__name__}, not str — only string fields can be injected"
                )
            out[f] = raw
        else:
            missing.append(f)
    if missing:
        raise RuntimeError(f"fields {missing!r} not found at {path}")
    return out
