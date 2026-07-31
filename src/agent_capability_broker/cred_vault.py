"""Vault backend for the `cred` provider. NOT part of the stdlib-only core.

Imported lazily by `providers.CredProvider` only when a capability uses
`source = "vault"`. Requires the `[cred]` extra (hvac). Auth resolves inside the
provider — the agent never thinks about how it authenticated:

    in-cluster k8s service-account token  ->  AppRole (env / .env file)  ->  VAULT_TOKEN

Two invariants a change here must preserve (WI-016; the admin-plane half of the
same pair is `onboard._admin_client`):

  1. No ambient credential. The client is constructed with ``token=""``, never
     ``None`` — ``None`` makes hvac read ``$VAULT_TOKEN`` *and*
     ``~/.vault-token``, so a stray developer token in a home directory could
     make a capability look reachable on an AppRole-only host.
  2. AppRole material that is declared but incomplete or unreadable **fails
     closed**. It never falls through to token auth: a silent downgrade from
     AppRole to whatever token is lying around is the exact failure AppRole
     exists to prevent, and `regista._secrets` makes the same call so the two
     components on one host cannot disagree about the host's posture.

`resolve` returns the requested field(s); it never logs or returns anything to
the model context (the caller injects into a child process).
"""

from __future__ import annotations

import os
from pathlib import Path

from .model import Capability, _user_config_root, suite_config_dir
from .secret_sources import SecretSourceConfigError

_K8S_TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")

# Vault's own default, and the same default `regista._secrets` uses, so one
# plane file that omits `VAULT_APPROLE_MOUNT_POINT` means the same thing to both.
_APPROLE_DEFAULT_MOUNT = "approle"

# Setting *any* of these means "this host authenticates by AppRole" — which is
# what makes incomplete material a refusal rather than a fall-through.
_APPROLE_VARS = (
    "VAULT_ROLE_ID",
    "VAULT_ROLE_ID_FILE",
    "VAULT_SECRET_ID",
    "VAULT_SECRET_ID_FILE",
)

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _default_vault_env_paths() -> list[Path]:
    """Ordered fallback paths for the Vault AppRole ``.env`` file (Plan 005).

    Precedence mirrors the manifest resolution: ``$ACB_VAULT_ENV`` (explicit
    shell override) → suite config dir / ``vault.env`` → suite config dir /
    ``suite.env`` (may also carry ``VAULT_*`` vars) → acb-private
    ``acb/vault.env`` under the platform config root
    (``~/.config/acb/vault.env`` on Linux, ``%APPDATA%/acb/vault.env`` on
    Windows).  Only files that *exist* are loaded by the
    caller; this list may include non-existent paths.  ``_parse_env_text``
    filters to ``VAULT*`` keys so loading ``suite.env`` is safe — ``REGISTA_*``
    and other suite vars are ignored.
    """
    paths: list[Path] = []
    env = os.environ.get("ACB_VAULT_ENV")
    if env:
        paths.append(Path(env))
    suite = suite_config_dir()
    if suite is not None:
        paths.append(suite / "vault.env")
        paths.append(suite / "suite.env")
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else _user_config_root()
    paths.append(base / "acb" / "vault.env")
    return paths


def _parse_env_text(text: str) -> dict[str, str]:
    """Parse ``KEY=val`` lines, returning only ``VAULT*`` keys.

    Handles bash-style ``export KEY=val`` prefixes.  Strips surrounding quotes.
    Strips inline comments (``# ...`` after the value) — but only when the
    ``#`` is preceded by whitespace, so values like ``https://vault#fragment``
    are preserved (LOW-3).
    """
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        val = val.strip()
        # Handle quoted values: "value" or 'value' (possibly followed by # comment).
        # The closing quote ends the value; anything after is a comment (HIGH-2).
        if val and val[0] in ('"', "'"):
            quote = val[0]
            end = val.find(quote, 1)
            if end != -1:
                val = val[1:end]
            else:
                val = val.strip('"').strip("'")
        else:
            # Unquoted: strip inline comments (# preceded by whitespace).
            if " #" in val or "\t#" in val:
                val = val.split(" #", 1)[0].split("\t#", 1)[0].rstrip()
        if key and key.startswith("VAULT"):
            out[key] = val
    return out


def _load_env_file(env_path: str | os.PathLike[str] | None = None) -> dict[str, str]:
    """Load ``VAULT_*`` vars from the AppRole ``.env`` file, if present.

    The charter calls for an "AppRole ``.env``" auth path: the role_id/secret_id
    live in a file (not the shell env) so they don't persist in process tables.
    Path precedence (Plan 005 WI-1.1/WI-3.1): an explicit ``env_path`` (e.g.
    ``doctor`` probing a capability's *declared* access plane, independent of
    the shell), else ``$ACB_VAULT_ENV``, else the suite config dir's
    ``vault.env``, else ``acb/vault.env`` under the platform config root.  Each
    harness points
    ``ACB_VAULT_ENV`` at its own file for role separation.

    Handles bash-style ``export KEY=val`` prefixes and a UTF-8 BOM.  A malformed
    or unreadable file raises ``RuntimeError`` with the path (never the file's
    contents) so ``doctor``/``exec`` can surface an actionable diagnostic.
    """
    if env_path:
        candidate_paths = [Path(env_path)]
    else:
        candidate_paths = _default_vault_env_paths()

    for p in candidate_paths:
        try:
            text = p.read_text(encoding="utf-8-sig")
        except FileNotFoundError:
            continue
        except OSError as exc:
            reason = exc.strerror or str(exc)
            raise RuntimeError(f"cannot read Vault env file {p!r}: {reason}") from exc
        except UnicodeDecodeError as exc:
            raise RuntimeError(
                f"Vault env file {p!r} is not valid UTF-8 (byte offset {exc.start})"
            ) from exc
        return _parse_env_text(text)
    return {}


def _vault_env(env_path: str | os.PathLike[str] | None = None) -> dict[str, str]:
    """Merged Vault config: the `.env` file is the fallback; process env wins.

    When ``env_path`` is **explicit** (per-plane probing, WI-008), the file is
    authoritative — process env is **not** merged on top, so a stray
    ``VAULT_ADDR`` in the shell can't make every plane probe through one
    credential set.  Without ``env_path`` (the ``resolve``/``exec`` path), the
    normal merge applies so a ``VAULT_TOKEN`` from a prior login still works.
    """
    merged = _load_env_file(env_path)
    if env_path is None:
        merged.update({k: v for k, v in os.environ.items() if k.startswith("VAULT")})
    return merged


def _vault_env_source(env_path: str | os.PathLike[str] | None = None) -> str:
    """Where Vault vars were looked for, phrased for an operator-facing refusal.

    Mirrors `_vault_env`'s own precedence, so a refusal names the file the
    operator should actually edit.  Only paths and variable *names* ever appear
    in diagnostics — never a value.
    """
    if env_path is not None:
        return f"the plane file {str(env_path)!r} (an explicit plane, so $VAULT_* is not merged)"
    for p in _default_vault_env_paths():
        if p.is_file():
            return f"the process environment and the Vault env file {str(p)!r}"
    return "the process environment (no Vault env file was found)"


def _auth_source(
    env: dict[str, str], env_path: str | os.PathLike[str] | None = None
) -> str | None:
    """`_vault_env_source`, resolved only when an AppRole refusal is possible.

    Nothing else needs it, and the lookup stats candidate config paths — no
    reason to do that on every k8s or token auth.
    """
    if not any(env.get(k) for k in _APPROLE_VARS):
        return None
    return _vault_env_source(env_path)


def _credential_file_value(path: str, *, var: str) -> str:
    """Read one credential out of the file named by `var`.

    The *path* is named in every error (a path is not a secret); the file's
    contents never are.  Every failure is a refusal, not a fall-through: the
    operator asked for AppRole, so an undelivered SecretID is a broken host, not
    an invitation to use a token instead.
    """
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"{var} names {path!r}, which does not exist — AppRole material was "
            f"declared but never delivered (refusing to fall back to VAULT_TOKEN)"
        ) from exc
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise RuntimeError(
            f"cannot read {var} file {path!r}: {reason} (refusing to fall back to "
            f"VAULT_TOKEN)"
        ) from exc
    except UnicodeDecodeError as exc:
        raise RuntimeError(
            f"{var} file {path!r} is not valid UTF-8 (byte offset {exc.start})"
        ) from exc
    value = text.strip()
    if not value:
        raise RuntimeError(
            f"{var} file {path!r} is empty — a delivery that failed silently "
            f"(refusing to fall back to VAULT_TOKEN)"
        )
    return value


def _approle_material(
    env: dict[str, str], *, source: str | None = None
) -> tuple[str, str, str] | None:
    """`(role_id, secret_id, mount_point)`, or `None` when no AppRole was declared.

    **Fails closed** (WI-016).  Once any of `_APPROLE_VARS` is set the operator
    asked for AppRole, so material that is incomplete or unreadable raises here
    instead of letting `_authenticate` fall through to token auth.  A host with a
    RoleID and no SecretID silently downgrading to whatever token it can find is
    the precise failure AppRole exists to prevent, and `regista._secrets`
    (WI-228) refuses identically — two components on one host disagreeing about
    the host's posture is worse than either choice alone.

    The `*_FILE` forms win over the inline ones, matching regista: the file is
    the channel a mode-0600 delivery writes to, and it keeps the SecretID out of
    `/proc/<pid>/environ`.  `source` describes where the vars were looked for so
    the refusal is actionable; no value is ever interpolated into a message.
    """
    role_id = env.get("VAULT_ROLE_ID") or None
    role_id_file = env.get("VAULT_ROLE_ID_FILE") or None
    secret_id = env.get("VAULT_SECRET_ID") or None
    secret_id_file = env.get("VAULT_SECRET_ID_FILE") or None
    if not any((role_id, role_id_file, secret_id, secret_id_file)):
        return None

    where = f"looked in {source}" if source else "looked in the resolved Vault environment"
    mount = env.get("VAULT_APPROLE_MOUNT_POINT") or _APPROLE_DEFAULT_MOUNT

    if not (role_id or role_id_file):
        raise RuntimeError(
            f"AppRole is configured for this host (a SecretID is set) but no RoleID "
            f"is available: set VAULT_ROLE_ID, or VAULT_ROLE_ID_FILE to a file "
            f"holding it ({where}). Refusing to fall back to VAULT_TOKEN — that "
            f"would silently downgrade this host from AppRole to an ambient token."
        )
    if not (secret_id or secret_id_file):
        raise RuntimeError(
            f"AppRole is configured for this host (a RoleID is set) but no SecretID "
            f"is available: set VAULT_SECRET_ID_FILE to the file the SecretID is "
            f"delivered into (preferred — it keeps the value out of the process "
            f"table), or VAULT_SECRET_ID for an inline value ({where}). Refusing to "
            f"fall back to VAULT_TOKEN — that would silently downgrade this host "
            f"from AppRole to an ambient token."
        )
    if (env.get("VAULT_SECRET_ID_RESPONSE_WRAPPED") or "").strip().lower() in _TRUTHY:
        # regista unwraps response-wrapped SecretIDs; acb does not. Say so
        # instead of handing Vault a wrapping token and reporting its 400.
        raise RuntimeError(
            "VAULT_SECRET_ID_RESPONSE_WRAPPED is set, but acb does not unwrap "
            "response-wrapped SecretIDs (regista does). Point acb at an unwrapped "
            "SecretID, or unset the flag. Refusing to fall back to VAULT_TOKEN."
        )

    role = (
        _credential_file_value(role_id_file, var="VAULT_ROLE_ID_FILE")
        if role_id_file
        else role_id
    )
    secret = (
        _credential_file_value(secret_id_file, var="VAULT_SECRET_ID_FILE")
        if secret_id_file
        else secret_id
    )
    if role is None or secret is None:  # pragma: no cover — the guards above ensure both
        raise RuntimeError("incomplete AppRole material (refusing to fall back to VAULT_TOKEN)")
    return role, secret, mount


def _authenticate(client: object, env: dict[str, str], *, source: str | None = None) -> None:
    """Log `client` in by the first available method using the resolved `env`
    (passed in so the same access plane drives both addr lookup and auth). Raises
    if none work.

    Precedence is k8s → AppRole → token, the same order `regista._secrets` uses
    (it has no k8s path, but AppRole strictly precedes token there too).
    """
    # 1. In-cluster Kubernetes auth (no secret_id on disk). Checked and returned
    #    before AppRole is even inspected, so a k8s-authenticated host — which
    #    has neither AppRole material nor a token — is untouched by the
    #    fail-closed rule below.
    if _K8S_TOKEN.is_file():
        role = env.get("VAULT_K8S_ROLE")
        if role:
            jwt = _K8S_TOKEN.read_text(encoding="utf-8").strip()
            client.auth.kubernetes.login(role=role, jwt=jwt)  # type: ignore[attr-defined]
            return
    # 2. AppRole (role_id + secret_id from env / the .env file / the *_FILE
    #    paths). Declared-but-incomplete material raises out of here.
    material = _approle_material(env, source=source)
    if material is not None:
        role_id, secret_id, mount = material
        client.auth.approle.login(  # type: ignore[attr-defined]
            role_id=role_id, secret_id=secret_id, mount_point=mount
        )
        return
    # 3. A pre-existing token. Only an *explicit* VAULT_TOKEN reaches this: the
    #    client is constructed with `token=""`, so `client.token` is falsy unless
    #    a token was declared (never from `~/.vault-token`).
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

    # `token=""` and NOT the default `None`: with `None`, hvac calls
    # `utils.get_token_from_env()`, which reads `$VAULT_TOKEN` *and*
    # `~/.vault-token`. A stray developer token in the home directory would then
    # let this report a capability REACHABLE on a host that is supposed to be
    # AppRole-only — the runtime half of the trap WI-015 closed in `onboard`.
    client = hvac.Client(url=addr, token=env.get("VAULT_TOKEN") or "")
    _authenticate(client, env, source=_auth_source(env, vault_env))
    return bool(client.is_authenticated())  # token self-lookup; no secret read


def resolve(cap: Capability) -> dict[str, str]:
    """Read the capability's secret field(s) from Vault (KV v2).

    Field selection is **required** (fail-closed): `options.fields` (a list)
    selects specific fields, or `options.field` (singular) reads one. When
    neither is set the call raises — a Vault secret is not curated for injection
    and defaulting to "all fields" risks over-exposing side-channel material
    (rotation notes, audit IDs, tokens stored alongside the password). Explicit
    selection is the safe default.

    Config-shape validation runs *before* the optional `hvac` import so a
    malformed declaration fails fast with a clear `SecretSourceConfigError`
    even when the `[cred]` extra is not installed (round-3 review: the
    `_declared_fields`/`resolve` agreement must be observable without the
    optional dependency).
    """
    fields_opt = cap.options.get("fields")
    if "fields" in cap.options and not isinstance(fields_opt, list):
        # Config-shape error (round-3 review MINOR 4): raise the same type
        # `_declared_fields` raises so the F10 agreement claim holds on type
        # too, not just on the selected set. `SecretSourceConfigError`
        # subclasses RuntimeError, so existing `pytest.raises(RuntimeError)`
        # callers keep matching.
        raise SecretSourceConfigError(
            f"capability {cap.id!r}: options.fields must be a list "
            f"(got {type(fields_opt).__name__})"
        )
    field_opt = cap.options.get("field")
    if field_opt is not None and not isinstance(field_opt, str):
        raise SecretSourceConfigError(
            f"capability {cap.id!r}: options.field must be a string "
            f"(got {type(field_opt).__name__})"
        )
    if isinstance(fields_opt, list):
        want = [str(f) for f in fields_opt]
    elif field_opt is not None:
        want = [field_opt]
    else:
        raise SecretSourceConfigError(
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
        import hvac
    except ImportError as exc:
        raise RuntimeError(
            "cred source 'vault' needs the [cred] extra: "
            "pip install 'agent-capability-broker[cred]'"
        ) from exc

    try:
        # `token=""`, never `None` — see the note in `reachable`.
        client = hvac.Client(url=addr, token=env.get("VAULT_TOKEN") or "")
        _authenticate(client, env, source=_auth_source(env))
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
