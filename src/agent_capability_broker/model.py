"""Core data model and manifest parsing. Stdlib-only by charter.

This is the concrete contract described in docs/capability-model.md. Nothing
here performs I/O against a live system, mutates a config, or touches a secret.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

# Providers the core knows how to dispatch to. The core validates only that a
# capability names a known provider and lists harnesses; provider-specific keys
# (vault, engine, backend, ...) are validated by the provider itself.
KNOWN_PROVIDERS = frozenset({"cred", "e2e"})
KNOWN_HARNESSES = frozenset({"claude", "opencode"})


class Status(StrEnum):
    """How a capability stands for one harness. See spine §4."""

    PRESENT_OK = "present_ok"          # wired and the resource is reachable
    PRESENT_BROKEN = "present_broken"  # wired but non-functional (the headline signal)
    ABSENT = "absent"                  # listed for this harness but not wired
    NOT_APPLICABLE = "not_applicable"  # not listed for this harness
    UNKNOWN = "unknown"                # provider could not determine


class ManifestError(ValueError):
    """A capabilities.toml that violates the core contract."""


@dataclass(frozen=True)
class Capability:
    """One desired capability from the manifest."""

    id: str                       # "provider:name"
    provider: str
    harnesses: tuple[str, ...]
    options: dict[str, object] = field(default_factory=dict)  # provider-specific keys

    @property
    def name(self) -> str:
        return self.id.split(":", 1)[1] if ":" in self.id else self.id


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
        harnesses = body.get("harnesses")
        if not isinstance(harnesses, list) or not harnesses:
            raise ManifestError(f"capability {cap_id!r}: 'harnesses' must be a non-empty list")
        unknown = set(harnesses) - KNOWN_HARNESSES
        if unknown:
            raise ManifestError(
                f"capability {cap_id!r}: unknown harness(es) {sorted(unknown)} "
                f"(known: {sorted(KNOWN_HARNESSES)})"
            )
        options = {k: v for k, v in body.items() if k not in {"provider", "harnesses"}}
        caps.append(
            Capability(
                id=cap_id,
                provider=str(provider),
                harnesses=tuple(harnesses),
                options=options,
            )
        )
    return caps
