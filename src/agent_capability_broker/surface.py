"""Rogue / clobbered capability detection (agent-suite WI-001). Stdlib-only.

`doctor`'s per-capability verdicts answer "is what the manifest declares
actually wired?". That question is blind in one direction: a capability that
was added or overwritten **outside** the manifest is invisible, because nothing
ever looks at the installed surface itself. This module closes that gap by
walking the real surface each harness advertises and diffing it against the
manifest:

- **rogue** — a capability-shaped artifact is installed in a harness that the
  manifest does not declare there (an undeclared `cred-*` / `e2e-*` shim, or
  Playwright MCP wiring in a harness no `e2e` capability lists). Reported as a
  **warn**: drift the operator must see, but not by itself proof that anything
  is broken, so it degrades rather than fails a box.
- **clobbered** — a capability the manifest *does* declare has a shim installed
  that no longer brokers it: the file exists under the expected name but does
  not surface `acb exec <capability id>` any more. Something replaced acb's
  discovery artifact, so an agent following that shim is doing something other
  than what the manifest declares. Reported as a **fail**: this is an integrity
  violation, not drift.

Read-only by construction, and it never surfaces shim *contents* — a clobbered
shim may well have had a literal secret pasted into it, so findings carry the
path and the verdict, never the body.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .model import Capability, McpServer
from .providers import shim_name

# Shim names in acb's capability namespace: `<provider>-<name>`, the rendering
# of a `provider:name` capability id. Anything else in a harness's shim dir is
# an ordinary skill/command and none of acb's business.
_MANAGED_SHIM = re.compile(r"^(?:cred|e2e)-[A-Za-z0-9][A-Za-z0-9._-]*$")
_BROKERS = re.compile(r"acb exec\s+((?:cred|e2e):[^\s`'\"]+)")
_MAX_SHIM_BYTES = 256 * 1024


class ShimSurface(Protocol):
    """The read-only slice of a harness adapter the audit needs."""

    name: str

    @property
    def shims_path(self) -> Path: ...
    def available(self) -> bool: ...
    def mcp_servers(self) -> dict[str, McpServer]: ...
    def command_shims(self) -> set[str]: ...


@dataclass(frozen=True)
class SurfaceFinding:
    """One rogue/clobbered observation, in suite-health check vocabulary."""

    name: str                      # check name, e.g. "rogue:claude:cred-x"
    kind: str                      # "rogue" | "clobbered" | "unreadable"
    status: str                    # "warn" | "fail" (never "pass" — suite lexicon)
    harness: str
    detail: str
    capability: str | None = None


def _shim_file(adapter: ShimSurface, name: str) -> Path | None:
    """Locate a shim's body across the two harness layouts, without adapter help.

    Claude/Hermes/Codex render `skills/<name>/SKILL.md`; opencode renders
    `command/<name>.md`. Returns None when neither exists (the name came from
    `command_shims()`, so this should not happen — but a race or a hand-edit
    between the two reads must not raise).
    """
    skill = adapter.shims_path / name / "SKILL.md"
    if skill.is_file():
        return skill
    command = adapter.shims_path / f"{name}.md"
    if command.is_file():
        return command
    return None


def _brokered_ids(path: Path) -> tuple[set[str] | None, str | None]:
    """Capability ids a shim body brokers -> (ids, read-error).

    Only the `acb exec <id>` invocations are extracted; the body itself is never
    returned or logged (it may contain a pasted secret). An oversized or
    unreadable file yields an error string instead of a false verdict.
    """
    try:
        if path.stat().st_size > _MAX_SHIM_BYTES:
            return None, f"shim is larger than {_MAX_SHIM_BYTES} bytes; not inspected"
        body = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, f"cannot read shim ({exc.__class__.__name__})"
    return set(_BROKERS.findall(body)), None


def _looks_like_playwright(server: McpServer) -> bool:
    haystack = (server.name + " " + " ".join(server.command) + " " + (server.url or "")).lower()
    return "playwright" in haystack


def audit_surface(
    caps: list[Capability], harness_adapters: dict[str, ShimSurface]
) -> list[SurfaceFinding]:
    """Diff each available harness's installed capability surface vs the manifest.

    Unavailable harnesses (no config on this host) are skipped entirely: there
    is no surface to audit, and the per-capability verdicts already report that
    as UNKNOWN. Deterministic order (harness, then check name) so the check list
    is stable for callers and CI.
    """
    findings: list[SurfaceFinding] = []
    for harness, adapter in sorted(harness_adapters.items()):
        if not adapter.available():
            continue
        declared = {
            shim_name(cap): cap
            for cap in caps
            if harness in cap.harnesses and cap.provider == "cred"
        }
        declared_ids = {cap.id for cap in caps if harness in cap.harnesses}
        installed = adapter.command_shims()

        # --- rogue: installed in the capability namespace, undeclared here ----
        for name in sorted(installed):
            if name in declared or not _MANAGED_SHIM.fullmatch(name):
                continue
            path = _shim_file(adapter, name)
            brokered: set[str] = set()
            if path is not None:
                ids, error = _brokered_ids(path)
                if ids is not None:
                    brokered = ids - declared_ids
                elif error is not None:
                    findings.append(SurfaceFinding(
                        name=f"rogue:{harness}:{name}",
                        kind="unreadable",
                        status="warn",
                        harness=harness,
                        detail=(
                            f"'{name}' is installed in {harness} but not declared in the "
                            f"manifest, and {error}"
                        ),
                    ))
                    continue
            if brokered:
                detail = (
                    f"'{name}' is installed in {harness} and brokers "
                    f"{sorted(brokered)}, which the manifest does not declare for this "
                    f"harness — a capability added outside the manifest"
                )
                capability: str | None = sorted(brokered)[0]
            else:
                detail = (
                    f"'{name}' occupies the acb capability namespace in {harness} but no "
                    f"manifest capability declares it here — added outside the manifest"
                )
                capability = None
            findings.append(SurfaceFinding(
                name=f"rogue:{harness}:{name}",
                kind="rogue",
                status="warn",
                harness=harness,
                detail=detail,
                capability=capability,
            ))

        # --- rogue MCP wiring: a browser wired where no e2e capability lists it
        if not any(
            cap.provider == "e2e" and harness in cap.harnesses for cap in caps
        ):
            for server_name, server in sorted(adapter.mcp_servers().items()):
                if not _looks_like_playwright(server):
                    continue
                findings.append(SurfaceFinding(
                    name=f"rogue:{harness}:mcp:{server_name}",
                    kind="rogue",
                    status="warn",
                    harness=harness,
                    detail=(
                        f"MCP server '{server_name}' wires a browser into {harness}, but no "
                        f"e2e capability in the manifest declares this harness — browser "
                        f"wiring added outside the manifest"
                    ),
                ))

        # --- clobbered: declared here, but its shim no longer brokers it ------
        for name, cap in sorted(declared.items()):
            if name not in installed:
                continue  # ABSENT is already the provider's verdict, not a clobber
            path = _shim_file(adapter, name)
            if path is None:
                continue
            ids, error = _brokered_ids(path)
            if ids is None:
                findings.append(SurfaceFinding(
                    name=f"clobber:{harness}:{cap.id}",
                    kind="unreadable",
                    status="warn",
                    harness=harness,
                    capability=cap.id,
                    detail=f"declared shim '{name}' could not be verified: {error}",
                ))
                continue
            if cap.id in ids:
                continue
            findings.append(SurfaceFinding(
                name=f"clobber:{harness}:{cap.id}",
                kind="clobbered",
                status="fail",
                harness=harness,
                capability=cap.id,
                detail=(
                    f"'{name}' in {harness} no longer brokers {cap.id} "
                    + (f"(it brokers {sorted(ids)}) " if ids else "(it invokes no `acb exec`) ")
                    + f"— the declared shim at {path} has been replaced or rewritten"
                ),
            ))

    return findings
