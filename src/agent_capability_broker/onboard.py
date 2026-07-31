"""Plan 009 — declared secret onboarding: planner, drift check, and applier.

The manifest entry is the single declaration; every provisioned artifact is
derived from it deterministically (policy name, AppRole name, policy HCL, and
the access-plane ``.env`` path for each declared harness).  The same
``OnboardAction`` objects feed the dry-run plan, ``--check``, ``--apply``, and
provenance, so what is shown is what is done.

Three invariants this module exists to hold:

**Where the plane file lives is not this module's opinion.**  ``plane_targets``
delegates to :func:`providers.vault_env_path` — the *same* function that renders
``ACB_VAULT_ENV`` into a harness shim and that ``doctor`` probes with.  A
capability's ``options.vault_env`` is therefore a bare filename beside the
harness config (``providers._assert_safe_path_component``), never a CWD-relative
or absolute path.  Onboarding cannot "succeed" into a location the runtime does
not read, and a manifest cannot aim a *write* at an arbitrary operator file.

**Never-overwrite is enforced by Vault, not by a pre-flight read.**  The KV
write always carries ``cas=0``.  A metadata probe is advisory only: it can say
"already holds a value" (skip early) or "cannot determine" (a least-privilege
onboarding AppRole cannot read metadata), and "cannot determine" never grants
permission to write — ``cas=0`` does the enforcing, atomically.

**Upstream exception text never reaches output.**  Every failure detail is
built from ``type(exc).__name__`` only.  hvac/requests/Vault error strings can
echo request material, and a value in transit is request material.
"""

from __future__ import annotations

import os
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from .model import Capability
from .providers import adapters, vault_env_path

# Policy/role name components. Deliberately narrower than a Vault path: these
# become `acb-<name>` identifiers quoted into HCL.
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
# One segment of a KV path. No quotes, braces, backslashes, whitespace, glob
# characters, `.` or `..` — the path is interpolated into a quoted HCL string
# and an unvalidated segment is a policy-injection primitive.
_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# The derived AppRole's configuration, in the units Vault reports so a re-read
# compares byte-for-byte against what we asked for (no "1h" vs 3600 drift).
ROLE_CONFIG: dict[str, object] = {
    "token_ttl": 3600,
    "token_max_ttl": 14400,
    "secret_id_ttl": 0,
    "secret_id_num_uses": 0,
}
_ROLE_DRIFT_KEYS = ("token_ttl", "token_max_ttl", "secret_id_ttl", "secret_id_num_uses")

# hvac exception class names that mean "the object is not there" as opposed to
# "we were not allowed to look". Matched on the name so this module keeps its
# lazy-hvac discipline (no module-level import of the optional extra).
_ABSENT_EXC_NAMES = frozenset({"InvalidPath"})
_DENIED_EXC_NAMES = frozenset({"Forbidden", "PermissionError"})
# Transport-level failures: the operator should retry, not re-read the manifest.
_RETRYABLE_EXC_NAMES = frozenset(
    {
        "ConnectionError",
        "ConnectTimeout",
        "ConnectionRefusedError",
        "ReadTimeout",
        "Timeout",
        "SSLError",
        "ProxyError",
        "ChunkedEncodingError",
    }
)
# Substrings Vault uses when a `cas` precondition fails. Inspected privately —
# never emitted, because the surrounding message may carry request material.
_CAS_CONFLICT_MARKERS = (
    "check-and-set",
    "cas parameter",
    "did not match the current version",
)


class OnboardRefusal(RuntimeError):
    """A refusal: the declaration, or its preconditions, forbid onboarding.

    Raised before any mutation. Message is derived from the manifest and local
    paths only — never from an upstream exception string.
    """


class OnboardError(RuntimeError):
    """An operational failure (Vault unreachable, missing extra, …).

    ``retryable`` feeds the CLI error envelope's ``retryable`` field.
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


def _sanitize(exc: BaseException) -> str:
    """The only thing we ever say about an upstream exception: its class.

    ``str(exc)`` from hvac/requests can contain the request body, and on the KV
    write path the request body *is* the secret. See ``TestNoSecretsInOutput``.
    """
    return type(exc).__name__


def _is_retryable(exc: BaseException) -> bool:
    names = {type(exc).__name__} | {c.__name__ for c in type(exc).__mro__}
    return bool(names & _RETRYABLE_EXC_NAMES)


def _is_cas_conflict(exc: BaseException) -> bool:
    """Does this exception mean "the path already holds a value"?

    Inspects ``str(exc)`` but never returns or logs it.
    """
    if type(exc).__name__ not in {"InvalidRequest", "VaultError", "BadRequest"}:
        return False
    message = str(exc).lower()
    return any(marker in message for marker in _CAS_CONFLICT_MARKERS)


# ---------------------------------------------------------------------------
# Derivation (pure: no I/O, no hvac, no secret values)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OnboardAction:
    """One idempotent provisioning step derived from the manifest.

    ``kind`` is a closed set:
      ``create_policy``    — write the least-privilege read policy
      ``create_role``      — create/converge the AppRole bound to that policy
      ``write_plane_env``  — render role_id/secret_id into one harness's plane file
      ``write_kv``         — transit a value into the KV path (never overwrites)
      ``rollback``         — synthesized during ``--apply`` unwind, never planned

    ``harness`` is the declared harness for ``write_plane_env`` and ``""`` for
    the Vault-side steps. ``payload`` carries no secret material.
    """

    capability: str
    kind: str
    target: str
    summary: str
    harness: str = ""
    payload: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class PlaneTarget:
    """Where one harness reads this capability's AppRole from."""

    harness: str
    path: Path


def _cap_name(cap: Capability) -> str:
    name = cap.name
    if not _NAME_RE.fullmatch(name):
        raise OnboardRefusal(
            f"capability {cap.id!r}: name {name!r} is not a valid policy/role "
            f"component (must match {_NAME_RE.pattern})"
        )
    return name


def policy_name(cap: Capability) -> str:
    return f"acb-{_cap_name(cap)}"


def role_name(cap: Capability) -> str:
    return f"acb-{_cap_name(cap)}"


def split_vault_path(path: str) -> tuple[str, str]:
    """``kv/agent-suite/qual/bot`` -> ``("kv", "agent-suite/qual/bot")``.

    Every segment is validated against ``_PATH_SEGMENT_RE``: the result is
    interpolated into a quoted HCL string, so a segment containing ``"``,
    ``{``, ``}``, a newline, or a traversal component would let a manifest
    append policy stanzas of its own choosing.
    """
    segments = path.split("/")
    if len(segments) < 2 or not all(segments):
        raise OnboardRefusal(
            f"vault path {path!r} must be '<mount>/<path>' with non-empty "
            f"segments (e.g. kv/agent-suite/qual/bot)"
        )
    for segment in segments:
        if not _PATH_SEGMENT_RE.fullmatch(segment):
            raise OnboardRefusal(
                f"vault path {path!r}: segment {segment!r} is not a safe path "
                f"component (must match {_PATH_SEGMENT_RE.pattern}) — the path "
                f"is interpolated into policy HCL"
            )
    head, _, tail = path.partition("/")
    return head, tail


def vault_path_of(cap: Capability) -> str:
    raw = cap.options.get("vault")
    if not isinstance(raw, str) or not raw:
        raise OnboardRefusal(f"capability {cap.id!r}: no 'vault' path declared")
    split_vault_path(raw)
    return raw


def policy_hcl(cap: Capability) -> str:
    """Least-privilege read-only policy scoped to exactly the declared KV path."""
    mount, secret_path = split_vault_path(vault_path_of(cap))
    return (
        f'path "{mount}/data/{secret_path}" {{\n'
        f'  capabilities = ["read"]\n'
        f"}}\n"
        f"\n"
        f'path "{mount}/metadata/{secret_path}" {{\n'
        f'  capabilities = ["read"]\n'
        f"}}\n"
    )


def plane_targets(cap: Capability) -> tuple[PlaneTarget, ...]:
    """One plane ``.env`` per declared harness, resolved by the runtime's own rule.

    This calls :func:`providers.vault_env_path` — the function that renders
    ``ACB_VAULT_ENV`` into the harness shim and that ``doctor`` hands to
    ``cred_vault.reachable``.  Using it here is the whole fix for "onboard and
    runtime disagree about where the plane file lives": there is one resolver,
    so agreement is structural rather than asserted.

    Consequences, all deliberate:

    * ``options.vault_env`` must be a **bare filename**; an absolute path or a
      traversal is an ``OnboardRefusal`` (the runtime rejects those too, and a
      write path must not be able to escape the harness directory).
    * Nothing resolves against the process CWD.
    * A capability declared for two harnesses gets two plane files, each with
      its own SecretID, so one harness's credential can be revoked alone.
    """
    known = adapters()
    targets: list[PlaneTarget] = []
    for harness in sorted(cap.harnesses):
        adapter = known.get(harness)
        if adapter is None:  # pragma: no cover — parse_manifest rejects these
            raise OnboardRefusal(
                f"capability {cap.id!r}: unknown harness {harness!r}"
            )
        try:
            path = vault_env_path(cap, adapter)
        except ValueError as exc:
            # providers._assert_safe_path_component: the traversal guard added in
            # 4d6e376. Re-raised as a refusal so `onboard` reports it as a
            # refusal rather than an internal error.
            raise OnboardRefusal(f"capability {cap.id!r}: {exc}") from exc
        targets.append(PlaneTarget(harness=harness, path=path))
    return tuple(targets)


def assert_plane_not_shared(
    cap: Capability, siblings: tuple[Capability, ...] = ()
) -> None:
    """Refuse to write an access plane another capability reads.

    Without ``options.vault_env`` a capability's plane file is the harness-wide
    default (``<harness config>/vault.env``) — one AppRole shared by every cred
    capability on that harness.  Onboarding mints a *capability-scoped*
    least-privilege AppRole, so writing it there would silently repoint every
    other capability on that harness at a role that cannot read their paths.
    The declaration is the fix: a bare ``vault_env`` filename beside the harness
    config gives this capability its own plane, which shim rendering, ``doctor``
    and ``exec`` already resolve the same way.
    """
    if cap.options.get("vault_env"):
        return
    known = adapters()
    for target in plane_targets(cap):
        adapter = known[target.harness]
        for other in siblings:
            if other.id == cap.id or other.provider != "cred":
                continue
            if other.options.get("source", "vault") != "vault":
                continue
            if target.harness not in other.harnesses:
                continue
            if vault_env_path(other, adapter) != target.path:
                continue
            raise OnboardRefusal(
                f"capability {cap.id!r} would provision harness "
                f"{target.harness!r}'s shared access plane {str(target.path)!r}, "
                f"which {other.id!r} also reads — a capability-scoped AppRole "
                f"written there would break it. Declare "
                f'vault_env = "{cap.name}.env" on {cap.id!r} (a bare filename '
                f"beside the harness config) so it gets a dedicated plane"
            )


def declared_fields(cap: Capability) -> list[str]:
    fields_opt = cap.options.get("fields")
    if isinstance(fields_opt, list):
        names = [str(f) for f in fields_opt]
        if not names:
            raise OnboardRefusal(
                f"capability {cap.id!r}: options.fields is empty — field "
                f"selection is required"
            )
        return names
    field_opt = cap.options.get("field")
    if isinstance(field_opt, str) and field_opt:
        return [field_opt]
    raise OnboardRefusal(
        f"capability {cap.id!r}: field selection required — set options.field "
        f"or options.fields"
    )


def validate_for_onboard(
    cap: Capability, siblings: tuple[Capability, ...] = ()
) -> None:
    """Every refusal that needs no I/O, checked before any Vault contact.

    ``siblings`` are the manifest's other capabilities; passing them enables the
    shared-plane refusal (:func:`assert_plane_not_shared`).
    """
    if cap.provider != "cred":
        raise OnboardRefusal(
            f"capability {cap.id!r}: onboarding supports only cred capabilities "
            f"(got provider {cap.provider!r})"
        )
    source = cap.options.get("source", "vault")
    if source != "vault":
        raise OnboardRefusal(
            f"capability {cap.id!r}: onboarding supports only source='vault' "
            f"(got {source!r}) — suite/AKV/Windows sources follow Plan 008"
        )
    if not cap.harnesses:
        raise OnboardRefusal(f"capability {cap.id!r}: declares no harnesses")
    _cap_name(cap)
    vault_path_of(cap)
    declared_fields(cap)
    plane_targets(cap)
    assert_plane_not_shared(cap, siblings)


def plan_onboard(
    cap: Capability, siblings: tuple[Capability, ...] = ()
) -> list[OnboardAction]:
    """Derive the ordered provisioning steps. Pure: no I/O, no hvac, no probes.

    Ordering is the dependency order the applier walks and the order it unwinds
    in reverse: policy, then the role bound to it, then the plane file(s) that
    hold that role's credentials, then the value.
    """
    validate_for_onboard(cap, siblings)

    pname = policy_name(cap)
    rname = role_name(cap)
    hcl = policy_hcl(cap)
    path = vault_path_of(cap)
    fields = declared_fields(cap)

    plan: list[OnboardAction] = [
        OnboardAction(
            capability=cap.id,
            kind="create_policy",
            target=f"sys/policies/acl/{pname}",
            summary=f"read-only policy {pname!r} scoped to exactly {path}",
            payload={"policy_name": pname, "hcl": hcl, "vault_path": path},
        ),
        OnboardAction(
            capability=cap.id,
            kind="create_role",
            target=f"auth/approle/role/{rname}",
            summary=f"AppRole {rname!r} bound to policy {pname!r}",
            payload={"role_name": rname, "policies": [pname], **ROLE_CONFIG},
        ),
    ]
    for target in plane_targets(cap):
        plan.append(
            OnboardAction(
                capability=cap.id,
                kind="write_plane_env",
                target=str(target.path),
                harness=target.harness,
                summary=(
                    f"role_id + a secret_id dedicated to harness "
                    f"{target.harness!r} at {target.path} (mode 0600; an "
                    f"existing file is backed up to .bak and its stale "
                    f"secret_id revoked)"
                ),
                payload={"plane_env": str(target.path), "role_name": rname},
            )
        )
    plan.append(
        OnboardAction(
            capability=cap.id,
            kind="write_kv",
            target=path,
            summary=(
                f"transit value(s) for fields {fields!r} into {path} with cas=0 "
                f"(an existing value is never overwritten)"
            ),
            payload={"vault_path": path, "fields": fields},
        )
    )
    return plan


# ---------------------------------------------------------------------------
# Admin plane (privileged, explicit, and never ambient)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AdminPlane:
    """The privileged plane that creates policies/roles. Never the capability's."""

    path: Path
    addr: str
    env: dict[str, str]


def load_admin_plane(admin_env: str | os.PathLike[str] | None = None) -> AdminPlane | None:
    """Resolve the admin plane, or ``None`` when none was *requested*.

    ``None`` is returned in exactly one case: neither ``--admin-env`` nor
    ``$ACB_VAULT_ADMIN_ENV`` was given, i.e. the caller deliberately asked for
    an offline run.  Every other problem raises — a *broken* admin plane is an
    error, never a silent degrade to offline (that is how ``--check`` used to
    report "clean" with authentication failing).

    ``VAULT_ADDR`` and the auth material come from the file, never from the
    ambient environment.
    """
    source = admin_env if admin_env else os.environ.get("ACB_VAULT_ADMIN_ENV")
    if not source:
        return None
    path = Path(source)
    if not path.is_file():
        raise OnboardRefusal(
            f"admin plane file {str(path)!r} does not exist — onboarding needs "
            f"--admin-env <file> or $ACB_VAULT_ADMIN_ENV"
        )
    from .cred_vault import _parse_env_text

    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise OnboardRefusal(
            f"cannot read admin plane file {str(path)!r}: {exc.strerror or _sanitize(exc)}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise OnboardRefusal(
            f"admin plane file {str(path)!r} is not valid UTF-8 "
            f"(byte offset {exc.start})"
        ) from exc
    env = _parse_env_text(text)
    addr = env.get("VAULT_ADDR")
    if not addr:
        raise OnboardRefusal(
            f"admin plane {str(path)!r} does not set VAULT_ADDR (an ambient "
            f"VAULT_ADDR is never used — the privileged plane is explicit)"
        )
    has_auth = bool(
        env.get("VAULT_TOKEN")
        or (env.get("VAULT_ROLE_ID") and env.get("VAULT_SECRET_ID"))
        or env.get("VAULT_K8S_ROLE")
    )
    if not has_auth:
        raise OnboardRefusal(
            f"admin plane {str(path)!r} declares no auth material (expected "
            f"VAULT_TOKEN, or VAULT_ROLE_ID + VAULT_SECRET_ID, or "
            f"VAULT_K8S_ROLE) — an ambient $VAULT_TOKEN or ~/.vault-token is "
            f"never picked up"
        )
    return AdminPlane(path=path, addr=addr, env=env)


def _admin_client(plane: AdminPlane) -> object:
    """An authenticated hvac client bound to ``plane`` and nothing else.

    ``token=""`` rather than ``None`` is load-bearing: ``hvac.Client.__init__``
    does ``token if token is not None else utils.get_token_from_env()``, which
    reads ``$VAULT_TOKEN`` and then ``~/.vault-token``.  Passing the empty
    string defeats that fallback, so an admin file that declares no token
    cannot borrow whatever token is lying around the operator's shell.  The
    same reasoning pins ``url`` (hvac falls back to ``$VAULT_ADDR``).
    """
    from .cred_vault import _authenticate

    try:
        import hvac
    except ImportError as exc:
        raise OnboardError(
            "onboarding needs the [cred] extra: "
            "pip install 'agent-capability-broker[cred]'"
        ) from exc

    client = hvac.Client(url=plane.addr, token=plane.env.get("VAULT_TOKEN") or "")
    try:
        _authenticate(client, plane.env)
        authenticated = bool(client.is_authenticated())
    except RuntimeError as exc:
        # cred_vault._authenticate's own "no auth available" signal.
        raise OnboardRefusal(
            f"admin plane {str(plane.path)!r}: {exc}"
        ) from exc
    except Exception as exc:
        if _is_retryable(exc):
            raise OnboardError(
                f"cannot reach Vault at {plane.addr} ({_sanitize(exc)})",
                retryable=True,
            ) from exc
        raise OnboardRefusal(
            f"admin plane {str(plane.path)!r} failed to authenticate "
            f"({_sanitize(exc)})"
        ) from exc
    if not authenticated:
        raise OnboardRefusal(
            f"admin plane {str(plane.path)!r} failed to authenticate "
            f"(token self-lookup returned not-authenticated)"
        )
    return client


# ---------------------------------------------------------------------------
# Read-only probes (tristate: present / absent / could-not-determine)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Probe:
    """``present is None`` means "could not determine" — never "safe to write"."""

    present: bool | None
    data: dict[str, object] | None = None
    reason: str = ""


def _classify(exc: BaseException) -> Probe:
    name = _sanitize(exc)
    if name in _ABSENT_EXC_NAMES:
        return Probe(present=False)
    if name in _DENIED_EXC_NAMES:
        return Probe(present=None, reason="permission denied")
    if _is_retryable(exc):
        return Probe(present=None, reason=f"Vault unreachable ({name})")
    return Probe(present=None, reason=f"probe failed ({name})")


def probe_policy(client: object, name: str) -> Probe:
    try:
        resp = client.sys.read_policy(name)  # type: ignore[attr-defined]
    except Exception as exc:
        return _classify(exc)
    if not isinstance(resp, dict):
        return Probe(present=None, reason="unexpected policy read response")
    rules = resp.get("rules") or resp.get("policy") or resp.get("data", {})
    if isinstance(rules, dict):
        rules = rules.get("rules") or rules.get("policy")
    if not isinstance(rules, str):
        return Probe(present=True, data={}, reason="policy present, rules unreadable")
    return Probe(present=True, data={"hcl": rules})


def probe_role(client: object, name: str) -> Probe:
    try:
        resp = client.auth.approle.read_role(name)  # type: ignore[attr-defined]
    except Exception as exc:
        return _classify(exc)
    data = resp.get("data") if isinstance(resp, dict) else None
    if not isinstance(data, dict):
        return Probe(present=True, data={}, reason="role present, config unreadable")
    return Probe(present=True, data=dict(data))


def probe_kv(client: object, vault_path: str) -> Probe:
    """Does the KV path hold a value? Metadata only — never a value read.

    A ``None`` result is expected under the least-privilege onboarding AppRole
    the contract recommends: that credential can write the path but cannot read
    its metadata.  The applier treats ``None`` as "unknown" and relies on
    ``cas=0``; it must never be read as "absent".
    """
    mount, secret_path = split_vault_path(vault_path)
    try:
        client.secrets.kv.v2.read_secret_metadata(  # type: ignore[attr-defined]
            mount_point=mount, path=secret_path
        )
    except Exception as exc:
        return _classify(exc)
    return Probe(present=True)


def _role_drift(desired_policy: str, data: dict[str, object]) -> str:
    """Empty string when the live role matches what we would create."""
    if not data:
        return ""
    raw = data.get("token_policies") or data.get("policies") or []
    policies: list[str]
    if isinstance(raw, str):
        policies = [raw]
    elif isinstance(raw, (list, tuple)):
        policies = [str(p) for p in raw]
    else:
        return "role token_policies has an unexpected shape"
    if sorted(policies) != [desired_policy]:
        return "role is bound to different policies"
    for key in _ROLE_DRIFT_KEYS:
        if key in data and data[key] != ROLE_CONFIG[key]:
            return f"role {key} differs from the derived configuration"
    return ""


# ---------------------------------------------------------------------------
# Plane file I/O
# ---------------------------------------------------------------------------


def _plane_env_text(addr: str, role_id: str, secret_id: str) -> str:
    return (
        f"# Written by `acb onboard --apply`. Mode 0600; do not commit.\n"
        f"VAULT_ADDR={addr}\n"
        f"VAULT_ROLE_ID={role_id}\n"
        f"VAULT_SECRET_ID={secret_id}\n"
    )


def _read_plane_file(path: Path) -> dict[str, str] | None:
    """Parsed ``VAULT_*`` pairs, or ``None`` when the file does not exist.

    An unreadable *existing* file raises: onboarding must not silently replace
    a plane file it could not inspect.
    """
    from .cred_vault import _parse_env_text

    try:
        text = path.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OnboardError(
            f"cannot read existing plane file {str(path)!r}: "
            f"{exc.strerror or _sanitize(exc)}"
        ) from exc
    except UnicodeDecodeError:
        return {}
    return _parse_env_text(text)


def _write_plane_file(path: Path, text: str) -> str | None:
    """Write ``text`` to ``path`` at mode 0600, backing up any existing file.

    Returns the backup path, or ``None`` when nothing was there before.

    * The new file is created with ``O_CREAT|O_EXCL`` and mode ``0o600`` in one
      syscall, so it is never briefly group/world-readable (the chmod-after-write
      race).
    * ``os.replace`` — not ``Path.rename`` — moves the old file aside and the
      new file into place.  ``Path.rename`` onto an existing ``.bak`` raises
      ``FileExistsError`` on Windows, which crashed the second ``--apply``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(path.name + ".acb-new")
    if staged.exists():
        staged.unlink()
    fd = os.open(str(staged), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
    except BaseException:
        staged.unlink(missing_ok=True)
        raise
    backup: str | None = None
    if path.exists():
        backup = str(path) + ".bak"
        os.replace(str(path), backup)
    os.replace(str(staged), str(path))
    if os.name == "posix":
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return backup


def _plane_mode_problem(path: Path) -> str:
    """Non-empty when the plane file is readable by group or other (POSIX)."""
    if os.name != "posix":
        return ""
    try:
        mode = path.stat().st_mode
    except OSError:  # pragma: no cover — caller has already read the file
        return ""
    if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
        return f"plane file mode is {mode & 0o777:04o}, expected 0600"
    return ""


# ---------------------------------------------------------------------------
# --check
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CheckResult:
    """One row of the drift report. ``status`` in ok/missing/drift/unknown."""

    action: OnboardAction
    status: str
    detail: str = ""


@dataclass(frozen=True)
class CheckReport:
    results: list[CheckResult]
    online: bool

    @property
    def problems(self) -> list[CheckResult]:
        """Every row that is not ``ok``.

        ``unknown`` counts. A report that could not verify a thing has not
        verified it, and a drift gate that treats "I could not look" as "clean"
        is the fail-open class this whole verb exists to close.
        """
        return [r for r in self.results if r.status != "ok"]

    @property
    def clean(self) -> bool:
        return not self.problems


def check_onboard(
    cap: Capability,
    admin_env: str | os.PathLike[str] | None = None,
    siblings: tuple[Capability, ...] = (),
) -> CheckReport:
    """Read-only drift report. Never mutates; never reads a secret value.

    Raises ``OnboardRefusal``/``OnboardError`` when the *admin plane itself* is
    unusable (missing file, no ``VAULT_ADDR``, failed authentication, Vault
    unreachable).  Those are errors, not offline mode.  Offline is only the
    deliberate case of no admin plane having been requested at all, and even
    then every unverifiable row is ``unknown`` — so the report is never
    ``clean``.
    """
    plan = plan_onboard(cap, siblings)
    plane = load_admin_plane(admin_env)
    client = _admin_client(plane) if plane is not None else None

    pname = policy_name(cap)
    rname = role_name(cap)
    role_id: str | None = None
    results: list[CheckResult] = []

    for action in plan:
        if action.kind == "create_policy":
            if client is None:
                results.append(
                    CheckResult(action, "unknown", "offline (no admin plane requested)")
                )
                continue
            probe = probe_policy(client, pname)
            if probe.present is None:
                results.append(CheckResult(action, "unknown", probe.reason))
            elif not probe.present:
                results.append(CheckResult(action, "missing", "policy not found"))
            else:
                live = (probe.data or {}).get("hcl")
                if not isinstance(live, str):
                    results.append(
                        CheckResult(action, "unknown", "policy present, rules unreadable")
                    )
                elif live.strip() != policy_hcl(cap).strip():
                    results.append(
                        CheckResult(
                            action, "drift", "policy scope differs from the manifest"
                        )
                    )
                else:
                    results.append(CheckResult(action, "ok", "policy present and scoped"))

        elif action.kind == "create_role":
            if client is None:
                results.append(
                    CheckResult(action, "unknown", "offline (no admin plane requested)")
                )
                continue
            probe = probe_role(client, rname)
            if probe.present is None:
                results.append(CheckResult(action, "unknown", probe.reason))
            elif not probe.present:
                results.append(CheckResult(action, "missing", "AppRole not found"))
            else:
                drift = _role_drift(pname, probe.data or {})
                role_id = _read_role_id(client, rname)
                if drift:
                    results.append(CheckResult(action, "drift", drift))
                else:
                    results.append(CheckResult(action, "ok", "AppRole present and bound"))

        elif action.kind == "write_plane_env":
            results.append(_check_plane(action, role_id, plane))

        elif action.kind == "write_kv":
            if client is None:
                results.append(
                    CheckResult(action, "unknown", "offline (no admin plane requested)")
                )
                continue
            probe = probe_kv(client, str(action.payload["vault_path"]))
            if probe.present is None:
                results.append(
                    CheckResult(
                        action,
                        "unknown",
                        f"cannot determine whether the path holds a value "
                        f"({probe.reason})",
                    )
                )
            elif probe.present:
                results.append(CheckResult(action, "ok", "KV path holds a value"))
            else:
                results.append(CheckResult(action, "missing", "KV path holds no value"))

    return CheckReport(results=results, online=client is not None)


def _read_role_id(client: object, rname: str) -> str | None:
    try:
        resp = client.auth.approle.read_role_id(rname)  # type: ignore[attr-defined]
    except Exception:
        return None
    data = resp.get("data") if isinstance(resp, dict) else None
    if isinstance(data, dict):
        value = data.get("role_id")
        if isinstance(value, str) and value:
            return value
    return None


def _check_plane(
    action: OnboardAction, role_id: str | None, plane: AdminPlane | None
) -> CheckResult:
    """Plane-file row. Locally knowable facts are reported even offline."""
    path = Path(str(action.payload["plane_env"]))
    try:
        existing = _read_plane_file(path)
    except OnboardError as exc:
        return CheckResult(action, "unknown", str(exc))
    if existing is None:
        return CheckResult(action, "missing", "plane file absent")
    if not existing.get("VAULT_ROLE_ID") or not existing.get("VAULT_SECRET_ID"):
        return CheckResult(
            action, "drift", "plane file present but declares no role_id/secret_id"
        )
    mode_problem = _plane_mode_problem(path)
    if mode_problem:
        return CheckResult(action, "drift", mode_problem)
    if plane is not None and existing.get("VAULT_ADDR") != plane.addr:
        return CheckResult(
            action, "drift", "plane file VAULT_ADDR differs from the admin plane"
        )
    if role_id is None:
        return CheckResult(
            action,
            "unknown",
            "plane file present and complete; role_id match needs a reachable "
            "admin plane",
        )
    if existing.get("VAULT_ROLE_ID") != role_id:
        return CheckResult(
            action, "drift", "plane file holds a role_id for a different AppRole"
        )
    return CheckResult(action, "ok", "plane file present and bound to the AppRole")


# ---------------------------------------------------------------------------
# --apply
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ApplyResult:
    """Outcome of one step. ``status`` in
    applied/converged/skipped/failed/aborted/rolled_back/rollback_failed."""

    action: OnboardAction
    status: str
    detail: str = ""
    backup_path: str | None = None


@dataclass(frozen=True)
class ApplyReport:
    results: list[ApplyResult]

    @property
    def failed(self) -> list[ApplyResult]:
        return [r for r in self.results if r.status in ("failed", "rollback_failed")]

    @property
    def succeeded(self) -> list[ApplyResult]:
        return [r for r in self.results if r.status in ("applied", "converged")]

    @property
    def ok(self) -> bool:
        return not self.failed


@dataclass(frozen=True)
class _Undo:
    """One compensating step for something *this run* created."""

    description: str
    action: OnboardAction
    run: Callable[[], object]


def apply_onboard(
    cap: Capability,
    admin_env: str | os.PathLike[str] | None = None,
    values: dict[str, str] | None = None,
    siblings: tuple[Capability, ...] = (),
) -> ApplyReport:
    """Provision idempotently, fail fast, and unwind what this run created.

    Semantics the reviewed branch lacked:

    * **Idempotent.** A re-run mints no SecretID and rewrites no plane file
      when the existing file already names this AppRole; the policy and role
      are compared before being written.
    * **Fail fast.** The first failed step aborts the rest.  A failed
      ``create_policy`` can no longer leave an AppRole bound to a dangling
      policy with a SecretID minted and a value transited.
    * **Unwind.** Objects *this run* created (policy, role, plane files, minted
      SecretIDs) are removed in reverse order on failure; pre-existing objects
      are left alone.  Each undo is reported as a ``rollback`` row, and an undo
      that itself fails is reported as ``rollback_failed`` so nothing is
      silently left behind.
    """
    plan = plan_onboard(cap, siblings)
    plane = load_admin_plane(admin_env)
    if plane is None:
        raise OnboardRefusal(
            "onboarding requires --admin-env <file> or $ACB_VAULT_ADMIN_ENV "
            "(the privileged plane that creates policies/roles); the "
            "capability's own plane is never used to create itself"
        )
    client = _admin_client(plane)

    pname = policy_name(cap)
    rname = role_name(cap)
    hcl = policy_hcl(cap)

    results: list[ApplyResult] = []
    undo: list[_Undo] = []
    role_id: str | None = None
    aborted = False

    try:
        for action in plan:
            if aborted:
                results.append(
                    ApplyResult(action, "aborted", "not attempted (an earlier step failed)")
                )
                continue
            if action.kind == "create_policy":
                outcome = _apply_policy(client, action, pname, hcl, undo)
            elif action.kind == "create_role":
                outcome, role_id = _apply_role(client, action, pname, rname, undo)
            elif action.kind == "write_plane_env":
                outcome = _apply_plane(client, action, rname, role_id, plane, undo)
            else:
                outcome = _apply_kv(client, action, values)
            results.append(outcome)
            if outcome.status == "failed":
                aborted = True
        if aborted:
            results.extend(_unwind(undo))
    finally:
        if values is not None:
            values.clear()
    return ApplyReport(results=results)


def _apply_policy(
    client: object,
    action: OnboardAction,
    pname: str,
    hcl: str,
    undo: list[_Undo],
) -> ApplyResult:
    probe = probe_policy(client, pname)
    if probe.present:
        live = (probe.data or {}).get("hcl")
        if isinstance(live, str) and live.strip() == hcl.strip():
            return ApplyResult(action, "converged", "policy already matches")
    try:
        client.sys.create_or_update_policy(pname, hcl)  # type: ignore[attr-defined]
    except Exception as exc:
        return ApplyResult(action, "failed", f"policy write failed ({_sanitize(exc)})")
    if probe.present is False:
        # Only undo what we know we created. A policy that already existed (or
        # whose existence we could not determine) is operator state.
        def delete_policy() -> object:
            return client.sys.delete_policy(pname)  # type: ignore[attr-defined]

        undo.append(
            _Undo(
                description=f"delete policy {pname!r} created by this run",
                action=action,
                run=delete_policy,
            )
        )
        return ApplyResult(action, "applied", f"policy {pname!r} created")
    return ApplyResult(action, "applied", f"policy {pname!r} converged to manifest scope")


def _apply_role(
    client: object,
    action: OnboardAction,
    pname: str,
    rname: str,
    undo: list[_Undo],
) -> tuple[ApplyResult, str | None]:
    probe = probe_role(client, rname)
    if probe.present and not _role_drift(pname, probe.data or {}):
        status, detail, created = "converged", "AppRole already matches", False
    else:
        try:
            client.auth.approle.create_or_update_approle(  # type: ignore[attr-defined]
                rname, token_policies=[pname], **ROLE_CONFIG
            )
        except Exception as exc:
            return (
                ApplyResult(action, "failed", f"AppRole write failed ({_sanitize(exc)})"),
                None,
            )
        created = probe.present is False
        status = "applied"
        detail = f"AppRole {rname!r} " + ("created" if created else "converged")
    if created:

        def delete_role() -> object:
            return client.auth.approle.delete_role(rname)  # type: ignore[attr-defined]

        undo.append(
            _Undo(
                description=f"delete AppRole {rname!r} created by this run",
                action=action,
                run=delete_role,
            )
        )
    role_id = _read_role_id(client, rname)
    if role_id is None:
        return (
            ApplyResult(
                action, "failed", f"AppRole {rname!r} written but its role_id is unreadable"
            ),
            None,
        )
    return ApplyResult(action, status, detail), role_id


def _apply_plane(
    client: object,
    action: OnboardAction,
    rname: str,
    role_id: str | None,
    plane: AdminPlane,
    undo: list[_Undo],
) -> ApplyResult:
    path = Path(str(action.payload["plane_env"]))
    if role_id is None:  # pragma: no cover — the role step aborts first
        return ApplyResult(action, "failed", "no role_id available")
    try:
        existing = _read_plane_file(path)
    except OnboardError as exc:
        return ApplyResult(action, "failed", str(exc))

    if (
        existing is not None
        and existing.get("VAULT_ROLE_ID") == role_id
        and existing.get("VAULT_SECRET_ID")
        and existing.get("VAULT_ADDR") == plane.addr
        and not _plane_mode_problem(path)
    ):
        # Idempotent: matching content, so no SecretID is minted and the file
        # is not rewritten. Reruns do not accumulate live SecretIDs.
        return ApplyResult(action, "converged", "plane file already matches")

    try:
        resp = client.auth.approle.generate_secret_id(rname)  # type: ignore[attr-defined]
    except Exception as exc:
        return ApplyResult(
            action, "failed", f"secret_id generation failed ({_sanitize(exc)})"
        )
    data = resp.get("data") if isinstance(resp, dict) else None
    secret_id = data.get("secret_id") if isinstance(data, dict) else None
    accessor = data.get("secret_id_accessor") if isinstance(data, dict) else None
    if not isinstance(secret_id, str) or not secret_id:
        return ApplyResult(action, "failed", "Vault returned no secret_id")
    if isinstance(accessor, str) and accessor:
        minted_accessor = accessor

        def destroy_minted() -> object:
            return client.auth.approle.destroy_secret_id_accessor(  # type: ignore[attr-defined]
                rname, minted_accessor
            )

        undo.append(
            _Undo(
                description="destroy the secret_id minted by this run",
                action=action,
                run=destroy_minted,
            )
        )

    try:
        backup = _write_plane_file(path, _plane_env_text(plane.addr, role_id, secret_id))
    except OSError as exc:
        return ApplyResult(
            action,
            "failed",
            f"cannot write plane file {str(path)!r}: {exc.strerror or _sanitize(exc)}",
        )
    finally:
        # Best-effort: drop this process's reference to the minted SecretID as
        # soon as it has reached the 0600 file (same caveat as exec).
        del secret_id
    undo.append(
        _Undo(
            description=f"restore the previous plane file at {path}",
            action=action,
            run=_restore_plane(path, backup),
        )
    )

    detail = f"plane file written for harness {action.harness!r}"
    stale = (existing or {}).get("VAULT_SECRET_ID")
    if stale:
        detail += "; " + _revoke_stale_secret_id(client, rname, stale)
    return ApplyResult(action, "applied", detail, backup_path=backup)


def _restore_plane(path: Path, backup: str | None) -> Callable[[], object]:
    def run() -> object:
        if backup is not None and Path(backup).exists():
            os.replace(backup, str(path))
        else:
            path.unlink(missing_ok=True)
        return None

    return run


def _revoke_stale_secret_id(client: object, rname: str, stale: str) -> str:
    """Best-effort revoke of the SecretID a replaced plane file held.

    Without this, every plane rewrite left a live SecretID behind that nothing
    tracked. The value is never echoed; only the outcome is reported.
    """
    try:
        resp = client.auth.approle.read_secret_id(  # type: ignore[attr-defined]
            role_name=rname, secret_id=stale
        )
        # Vault answers an unknown/destroyed SecretID with 204 No Content, which
        # hvac surfaces as a `requests.Response`, not a dict (verified live). The
        # isinstance guard is what keeps that from raising.
        data = resp.get("data") if isinstance(resp, dict) else None
        accessor = data.get("secret_id_accessor") if isinstance(data, dict) else None
        if not isinstance(accessor, str) or not accessor:
            return "stale secret_id could not be resolved to an accessor (not revoked)"
        client.auth.approle.destroy_secret_id_accessor(  # type: ignore[attr-defined]
            rname, accessor
        )
    except Exception as exc:
        return f"stale secret_id not revoked ({_sanitize(exc)})"
    return "stale secret_id revoked"


def _apply_kv(
    client: object, action: OnboardAction, values: dict[str, str] | None
) -> ApplyResult:
    if values is None:
        return ApplyResult(action, "skipped", "no values supplied (--values-from none)")
    vault_path = str(action.payload["vault_path"])
    mount, secret_path = split_vault_path(vault_path)

    probe = probe_kv(client, vault_path)
    if probe.present:
        return ApplyResult(
            action, "skipped", f"{vault_path} already holds a value — never overwritten"
        )
    # probe.present is False (absent) or None (could not determine, e.g. the
    # least-privilege onboarding AppRole cannot read metadata). Either way the
    # write below carries cas=0, so Vault — not this probe — enforces
    # never-overwrite, atomically and without a check-then-write race.
    try:
        client.secrets.kv.v2.create_or_update_secret(  # type: ignore[attr-defined]
            mount_point=mount, path=secret_path, secret=values, cas=0
        )
    except Exception as exc:
        if _is_cas_conflict(exc):
            return ApplyResult(
                action,
                "skipped",
                f"{vault_path} already holds a value — never overwritten "
                f"(cas=0 rejected by Vault)",
            )
        if _sanitize(exc) in _DENIED_EXC_NAMES:
            # Verified against live Vault: a credential granted only `create` on
            # kv/data/<path> gets Forbidden — not a cas conflict — on the second
            # write, because KV v2 needs `update` to add a version. So this is
            # ambiguous between "the policy is too narrow" and "the path already
            # holds a value and the credential is create-only". Fail closed and
            # name both, rather than reporting a success that may not be one:
            # either way nothing was written, so the guarantee still holds.
            return ApplyResult(
                action,
                "failed",
                f"KV write to {vault_path} denied (Forbidden); no value was "
                f"written, so any existing value is intact. Either the "
                f"onboarding credential lacks create/update on the path, or it "
                f"holds 'create' only and the path already has a version "
                f"(KV v2 requires 'update' to write one). Grant "
                f"[\"create\", \"update\"] so cas=0 can report the difference",
            )
        return ApplyResult(action, "failed", f"KV write failed ({_sanitize(exc)})")
    return ApplyResult(action, "applied", f"value written to {vault_path}")


def _unwind(undo: list[_Undo]) -> list[ApplyResult]:
    """Compensate, in reverse, for everything this run created."""
    out: list[ApplyResult] = []
    for entry in reversed(undo):
        rollback = OnboardAction(
            capability=entry.action.capability,
            kind="rollback",
            target=entry.action.target,
            summary=entry.description,
            harness=entry.action.harness,
        )
        try:
            entry.run()
        except Exception as exc:
            out.append(
                ApplyResult(
                    rollback,
                    "rollback_failed",
                    f"{entry.description} failed ({_sanitize(exc)}) — this object "
                    f"remains and needs manual cleanup",
                )
            )
        else:
            out.append(ApplyResult(rollback, "rolled_back", entry.description))
    return out
