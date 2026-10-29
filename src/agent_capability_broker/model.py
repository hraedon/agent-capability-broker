"""Core data model and manifest parsing. Stdlib-only by charter.

This is the concrete contract described in docs/capability-model.md. Nothing
here performs I/O against a live system, mutates a config, or touches a secret.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from functools import lru_cache
from pathlib import Path

import platformdirs

from .launchers import LAUNCHER_REFUSAL, is_launcher

# Providers the core knows how to dispatch to. The core validates only that a
# capability names a known provider and lists harnesses; provider-specific keys
# (vault, engine, backend, ...) are validated by the provider itself.
KNOWN_PROVIDERS = frozenset({"cred", "e2e"})
KNOWN_HARNESSES = frozenset({"claude", "opencode", "codex", "hermes", "zcode"})

# Manifest v2 (Plan 012 §5). Delivery rungs, declared assurance floors and the
# off-VM decision tiers a capability may name. Values are validated by the core;
# the free-form keys inside ``issuer`` / ``delivery`` are kept but not judged.
DELIVERY_RUNGS = ("helper", "proxy", "remote-op", "env")
ASSURANCE_LEVELS = ("D0", "D1", "H1", "H1+D1")  # weakest -> strongest
DECISIONS = ("auto", "approve", "deny")

# Only a value that never enters the VM can be hidden. Root in the VM is
# accepted (Plan 012 section 1), so a native credential helper (any process in
# the VM can ask it for the token) and an in-VM egress proxy (the token sits in
# VM memory) can at best devalue (D1); ``env`` injects the value outright.
HIDDEN_LEVELS = ("H1", "H1+D1")
HIDING_RUNGS = ("remote-op",)


def hidden_floor_problem(rung: str, floor: str | None) -> str | None:
    """Why ``floor`` cannot be met by ``rung``, or None when it is attainable.

    Pure. Used at manifest parse time and by ``doctor`` so the two cannot
    disagree: an ``H1`` / ``H1+D1`` floor is only meaningful on ``remote-op``.
    """
    if floor in HIDDEN_LEVELS and rung not in HIDING_RUNGS:
        return (
            f"declared floor {floor} is unattainable on the {rung!r} rung: the value "
            f"enters the VM and root in the VM is accepted, so only 'remote-op' "
            f"(the value never enters the VM) can be H1; {rung} is at best D1"
        )
    return None

# Issuer kinds that *mint* a scoped, expiring credential (so what reaches the VM
# is devalued, D1). Anything else -- ``vault-kv`` and any kind not listed here --
# is treated as a static source (D0). Unknown kinds are deliberately conservative:
# an issuer is only credited once the derivation table knows it issues.
ISSUING_KINDS = frozenset(
    {
        "vault-ssh-ca",
        "vault-k8s-token",
        "vault-ldap-library",
        "vault-ldap-static",
        "vault-database",
        "vault-pki",
        "remote-mint",
    }
)
STATIC_KINDS = frozenset({"vault-kv"})

# Keys the core reads off a capability table itself; everything else is left in
# ``Capability.options`` for the provider (v1 behaviour, unchanged).
_V2_KEYS = ("issuer", "delivery", "assurance", "decision")
_DNS_LABEL = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")


class Status(StrEnum):
    """How a capability stands for one harness. See spine §4."""

    PRESENT_OK = "present_ok"          # wired and the resource is reachable
    PRESENT_BROKEN = "present_broken"  # wired but non-functional (the headline signal)
    ABSENT = "absent"                  # listed for this harness but not wired
    NOT_APPLICABLE = "not_applicable"  # not listed for this harness
    UNKNOWN = "unknown"                # provider could not determine


class ManifestError(ValueError):
    """A capabilities.toml that violates the core contract."""


@lru_cache(maxsize=1)
def _user_config_root() -> Path:
    """Platform-idiomatic user-config root (Plan 003 WI-3.1).

    ``~/.config`` on Linux, ``%APPDATA%`` on Windows — replaces the hardcoded
    ``~/.config`` default. Callers honor ``$XDG_CONFIG_HOME`` explicitly ahead
    of this fallback so the suite env precedence stays visible.
    """
    return Path(platformdirs.user_config_dir())


@lru_cache(maxsize=1)
def _user_state_root() -> Path:
    """Platform-idiomatic user-state root (Plan 003 WI-3.1).

    ``~/.local/state`` on Linux, ``%LOCALAPPDATA%`` on Windows — replaces the
    hardcoded ``~/.local/state`` default. Callers honor ``$XDG_STATE_HOME``
    explicitly ahead of this fallback.
    """
    return Path(platformdirs.user_state_dir())


def suite_config_dir() -> Path | None:
    """The suite's shared config directory (blueprint §2.1).

    ``$AGENT_SUITE_CONFIG`` may point at a file (e.g. ``suite.env``) or a
    directory.  If a file, its parent is the config dir.  When unset, the
    default is the platform config root's ``agent-suite/`` subdir
    (``~/.config/agent-suite/`` on Linux, ``%APPDATA%/agent-suite/`` on
    Windows).  Returns ``None`` when the env var is unset *and* the default
    does not exist (so callers don't waste I/O probing a non-existent suite
    location ahead of the acb-private fallback).
    """
    env = os.environ.get("AGENT_SUITE_CONFIG")
    if env:
        p = Path(env)
        return p.parent if p.is_file() else p
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else _user_config_root()
    default = base / "agent-suite"
    return default if default.is_dir() else None


def default_manifest_locations() -> list[Path]:
    """Ordered, CWD-independent manifest search path (see `resolve_manifest`).

    Precedence (Plan 005 WI-1.1): an ``$ACB_MANIFEST`` override, then the
    suite config dir (``$AGENT_SUITE_CONFIG`` → the platform config root's
    ``agent-suite/`` subdir) when present, then the acb-private XDG location,
    then CWD for in-repo dev.
    The suite dir sits ahead of the acb-private default so a suite deployment
    can declare one manifest for the whole estate.
    """
    locs: list[Path] = []
    env = os.environ.get("ACB_MANIFEST")
    if env:
        locs.append(Path(env))
    suite = suite_config_dir()
    if suite is not None:
        locs.append(suite / "capabilities.toml")
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else _user_config_root()
    locs.append(base / "acb" / "capabilities.toml")
    locs.append(Path("capabilities.toml"))  # CWD, for working inside the acb repo
    return locs


def resolve_manifest(explicit: str | os.PathLike[str] | None = None) -> Path:
    """Find the manifest independent of the caller's working directory.

    An `explicit` path (e.g. a `--manifest` flag) always wins. Otherwise the
    `default_manifest_locations` are tried in order and the first that exists is
    returned. If none exist, raise `ManifestError` naming *every* location
    checked — so an agent in another harness is told where to put the file
    instead of guessing (`~/.acb`, the platform config root's `acb/`, …) and
    giving up.
    """
    if explicit is not None:
        return Path(explicit)
    searched = default_manifest_locations()
    for loc in searched:
        if loc.is_file():
            return loc
    locations = ", ".join(str(p) for p in searched)
    raise ManifestError(
        f"no capabilities.toml found (looked in: {locations}). "
        f"Set $ACB_MANIFEST or create capabilities.toml in the platform config "
        f"dir (e.g. ~/.config/acb/ on Linux, %APPDATA%/acb/ on Windows)"
    )


@dataclass(frozen=True)
class Capability:
    """One desired capability from the manifest.

    The v2 fields (Plan 012 §5) are additive: a directly-constructed or
    v1-parsed ``Capability`` carries the lossless upconversion defaults
    (``delivery = {rung = "env"}``, no issuer, no declared floor, so
    ``assurance`` reads ``"D0"``). ``declared_assurance`` keeps whether the
    floor was actually *declared* -- ``doctor`` treats an undeclared ``D0``
    differently from an acknowledged one.
    """

    id: str                       # "provider:name"
    provider: str
    harnesses: tuple[str, ...]    # advisory under v2: the VM, not the harness, is the boundary
    options: dict[str, object] = field(default_factory=dict)  # provider-specific keys
    issuer: dict[str, object] | None = None
    delivery: dict[str, object] = field(default_factory=lambda: {"rung": "env"})
    declared_assurance: str | None = None
    decision: str | None = None

    @property
    def name(self) -> str:
        return self.id.split(":", 1)[1] if ":" in self.id else self.id

    @property
    def rung(self) -> str:
        return str(self.delivery.get("rung", "env"))

    @property
    def issuer_kind(self) -> str | None:
        kind = self.issuer.get("kind") if self.issuer else None
        return kind if isinstance(kind, str) else None

    @property
    def assurance(self) -> str:
        """The declared floor, or ``D0`` for an entry that declares none (v1)."""
        return self.declared_assurance or "D0"

    @property
    def declares_v2(self) -> bool:
        """True when the entry carries any v2 key (i.e. is not a bare v1 entry)."""
        return (
            self.issuer is not None
            or self.declared_assurance is not None
            or self.decision is not None
            or self.delivery != {"rung": "env"}
        )


@dataclass(frozen=True)
class BoundaryConfig:
    """The manifest-level ``[boundary]`` table read by ``doctor --boundary``.

    Both keys are optional. Neither carries a secret: a namespace name and a
    list of host names the operator checks by hand.
    """

    vault_namespace: str | None = None
    ssh_admin_targets: tuple[str, ...] = ()


@dataclass(frozen=True)
class McpServer:
    """A normalized view of one MCP server across harness config formats.

    Adapters translate each harness's native shape into this; providers read it
    without knowing whether it came from Claude's `mcpServers` or opencode's
    `mcp`. Carries no secret material (no headers/tokens) by construction.
    """

    name: str
    kind: str                      # "local" | "remote" | "unknown"
    command: tuple[str, ...]       # argv for local servers; () for remote
    url: str | None = None         # endpoint for remote servers
    enabled: bool = True


@dataclass(frozen=True)
class Verdict:
    """The result of inspecting one capability for one harness (doctor row)."""

    capability: str
    harness: str
    status: Status
    detail: str = ""


@dataclass(frozen=True)
class Action:
    """A declarative, planned change toward `PRESENT_OK`. The same object is
    printed in the dry-run plan and recorded in provenance — so what is shown is
    exactly what is (or would be) done. Payload carries no secret material."""

    capability: str
    harness: str
    kind: str                                      # e.g. "pin_npx_version", "manual"
    target: str                                    # server/config key the action touches
    summary: str                                   # human-readable, secret-free
    payload: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionResult:
    """Outcome of applying (or declining to apply) one Action."""

    action: Action
    status: str                                    # "applied" | "skipped" | "failed"
    detail: str = ""
    backup_path: str | None = None


def parse_manifest(path: Path) -> list[Capability]:
    """Parse and validate capabilities.toml into Capability objects.

    Raises ManifestError on any core-contract violation. Does not read secrets
    or contact any backend.
    """
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc

    table = raw.get("capability", {})
    if not isinstance(table, dict) or not table:
        raise ManifestError("manifest has no [capability.\"...\"] entries")

    caps: list[Capability] = []
    for cap_id, body in table.items():
        if not isinstance(body, dict):
            raise ManifestError(f"capability {cap_id!r} is not a table")
        provider = body.get("provider")
        if provider not in KNOWN_PROVIDERS:
            raise ManifestError(
                f"capability {cap_id!r}: unknown or missing provider {provider!r} "
                f"(known: {sorted(KNOWN_PROVIDERS)})"
            )
        id_prefix = cap_id.split(":", 1)[0] if ":" in cap_id else None
        if id_prefix and id_prefix != provider:
            raise ManifestError(
                f"capability {cap_id!r}: ID prefix {id_prefix!r} does not match "
                f"declared provider {provider!r}"
            )
        if "/" in cap_id or "\\" in cap_id or ".." in cap_id:
            raise ManifestError(
                f"capability {cap_id!r}: id must not contain path separators or "
                f"traversal sequences (it flows into harness shim filenames)"
            )
        harnesses = body.get("harnesses")
        if not isinstance(harnesses, list) or not harnesses:
            raise ManifestError(f"capability {cap_id!r}: 'harnesses' must be a non-empty list")
        unknown = set(harnesses) - KNOWN_HARNESSES
        if unknown:
            raise ManifestError(
                f"capability {cap_id!r}: unknown harness(es) {sorted(unknown)} "
                f"(known: {sorted(KNOWN_HARNESSES)})"
            )
        issuer, delivery, assurance, decision = _parse_v2(cap_id, body)
        _lint_trusted_argv(cap_id, provider, body)
        options = {
            k: v for k, v in body.items() if k not in {"provider", "harnesses", *_V2_KEYS}
        }
        caps.append(
            Capability(
                id=cap_id,
                provider=str(provider),
                harnesses=tuple(harnesses),
                options=options,
                issuer=issuer,
                delivery=delivery,
                declared_assurance=assurance,
                decision=decision,
            )
        )
    return caps


def _lint_trusted_argv(cap_id: str, provider: object, body: dict[str, object]) -> None:
    """Refuse a launcher-first ``trusted_argv`` when the manifest is parsed.

    The same ``launchers.is_launcher`` rule ``acb exec`` and ``doctor`` apply, run
    early so a bad declaration fails before anything can exec. Only a
    well-formed first element is judged here; a missing, empty or malformed
    ``trusted_argv`` is still reported by the provider (it is not a launcher
    problem, and v1 manifests must keep parsing).
    """
    if provider != "cred":
        return
    argv = body.get("trusted_argv")
    if isinstance(argv, list) and argv and isinstance(argv[0], str) and is_launcher(argv[0]):
        raise ManifestError(f"capability {cap_id!r}: options.trusted_argv {LAUNCHER_REFUSAL}")


def _parse_v2(
    cap_id: str, body: dict[str, object]
) -> tuple[dict[str, object] | None, dict[str, object], str | None, str | None]:
    """Validate the v2 keys of one capability table (Plan 012 §5).

    A v1 entry (none of the keys) upconverts to ``delivery = {rung = "env"}``,
    no issuer, no declared floor, no decision -- nothing is dropped or invented.
    Errors are ``ManifestError`` like every other core-contract violation.
    """
    issuer: dict[str, object] | None = None
    if "issuer" in body:
        raw_issuer = body["issuer"]
        if not isinstance(raw_issuer, dict):
            raise ManifestError(f"capability {cap_id!r}: 'issuer' must be a table")
        kind = raw_issuer.get("kind")
        if not isinstance(kind, str) or not kind.strip():
            raise ManifestError(
                f"capability {cap_id!r}: issuer.kind is required and must be a non-empty string"
            )
        issuer = dict(raw_issuer)

    delivery: dict[str, object] = {"rung": "env"}
    if "delivery" in body:
        raw_delivery = body["delivery"]
        if not isinstance(raw_delivery, dict):
            raise ManifestError(f"capability {cap_id!r}: 'delivery' must be a table")
        rung = raw_delivery.get("rung")
        if rung not in DELIVERY_RUNGS:
            raise ManifestError(
                f"capability {cap_id!r}: delivery.rung must be one of "
                f"{list(DELIVERY_RUNGS)} (got {rung!r})"
            )
        delivery = dict(raw_delivery)

    assurance: str | None = None
    if "assurance" in body:
        raw_assurance = body["assurance"]
        if not isinstance(raw_assurance, str) or raw_assurance not in ASSURANCE_LEVELS:
            raise ManifestError(
                f"capability {cap_id!r}: assurance must be one of "
                f"{list(ASSURANCE_LEVELS)} (got {raw_assurance!r})"
            )
        assurance = raw_assurance
        problem = hidden_floor_problem(str(delivery["rung"]), assurance)
        if problem is not None:
            raise ManifestError(f"capability {cap_id!r}: assurance: {problem}")

    decision: str | None = None
    if "decision" in body:
        raw_decision = body["decision"]
        if not isinstance(raw_decision, str) or raw_decision not in DECISIONS:
            raise ManifestError(
                f"capability {cap_id!r}: decision must be one of "
                f"{list(DECISIONS)} (got {raw_decision!r})"
            )
        if delivery["rung"] != "remote-op":
            raise ManifestError(
                f"capability {cap_id!r}: 'decision' is only valid when "
                f"delivery.rung = 'remote-op' (got rung {delivery['rung']!r}); the "
                f"decision is enforced off the VM, so an in-VM rung cannot honour it"
            )
        decision = raw_decision

    return issuer, delivery, assurance, decision


def parse_boundary(path: Path) -> BoundaryConfig:
    """Read the optional manifest-level ``[boundary]`` table.

    Unknown keys are refused: a typo in a safety table (``vault_namespaces``)
    that is silently ignored would turn a check off without anyone noticing.
    Does not contact any backend.
    """
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc

    table = raw.get("boundary")
    if table is None:
        return BoundaryConfig()
    if not isinstance(table, dict):
        raise ManifestError("[boundary] must be a table")
    unknown = set(table) - {"vault_namespace", "ssh_admin_targets"}
    if unknown:
        raise ManifestError(
            f"[boundary]: unknown key(s) {sorted(unknown)} "
            f"(known: ['ssh_admin_targets', 'vault_namespace'])"
        )

    namespace = table.get("vault_namespace")
    if namespace is not None and (
        not isinstance(namespace, str) or not _DNS_LABEL.match(namespace)
    ):
        raise ManifestError(
            "[boundary]: vault_namespace must be a Kubernetes namespace name "
            "(lowercase alphanumerics and '-', at most 63 characters)"
        )

    targets_raw = table.get("ssh_admin_targets", [])
    if not isinstance(targets_raw, list) or not all(
        isinstance(t, str) and t.strip() and not t.startswith("-") for t in targets_raw
    ):
        raise ManifestError(
            "[boundary]: ssh_admin_targets must be a list of non-empty host names"
        )
    return BoundaryConfig(
        vault_namespace=namespace,
        ssh_admin_targets=tuple(str(t) for t in targets_raw),
    )


# --- assurance derivation (Plan 011 §2, Plan 012 §5) -----------------------------


def assurance_rank(level: str) -> int:
    """Total order D0 < D1 < H1 < H1+D1 (a hidden value outranks a devalued one)."""
    return ASSURANCE_LEVELS.index(level)


def derive_assurance(cap: Capability) -> tuple[str, str]:
    """The *effective* assurance a capability's configuration can reach, and why.

    Deterministic and pure: it reads only the parsed manifest entry.

    ====================================  ==========================================
    configuration                         effective level
    ====================================  ==========================================
    ``remote-op`` + issuing issuer        ``H1+D1`` (hidden *and* devalued)
    ``remote-op`` otherwise               ``H1``    (the value never enters the VM)
    ``helper``/``proxy``/``env`` +        ``D1``    (issued, scoped, short-lived)
    issuing ``issuer.kind``
    ``helper``/``proxy``/``env`` with no  ``D0``    (standing secret in the VM)
    issuer, a static one (``vault-kv``)
    or a kind not known to issue
    ====================================  ==========================================

    Returns ``(level, reason)``; the reason never contains a secret or a path.
    """
    kind = cap.issuer_kind
    issues = kind in ISSUING_KINDS
    if cap.rung == "remote-op":
        if issues:
            return "H1+D1", f"remote-op with issuing issuer {kind!r}"
        return "H1", "remote-op: the value never enters the VM"
    if issues:
        return "D1", f"{cap.rung} rung with issuing issuer {kind!r}"
    if kind is None:
        return "D0", f"{cap.rung} rung reading a static source (no issuer declared)"
    if kind in STATIC_KINDS:
        return "D0", f"{cap.rung} rung reading static issuer {kind!r}"
    return "D0", f"{cap.rung} rung with issuer kind {kind!r}, which is not a known issuing kind"
