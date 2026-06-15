"""Providers. Stdlib-only core (inspect path).

A provider implements the four operations from the design spine; this module
ships the read-only `inspect` for the first two providers. The act-path methods
(`plan_reconcile`/`apply`/`exec`) raise until Plan 002 so the mutating,
secret-handling code lands under its own review.

`inspect` is side-effect-free: it reads adapter wiring + cheap local signals and
never launches a credential use or surfaces a secret.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from .adapters import ClaudeAdapter, OpencodeAdapter
from .model import Capability, McpServer, Status, Verdict

_BROWSER_DIR_PREFIXES = ("chromium", "chromium_headless_shell", "firefox", "webkit")


class HarnessAdapter(Protocol):
    name: str

    def available(self) -> bool: ...
    def mcp_servers(self) -> dict[str, McpServer]: ...


class Provider(Protocol):
    name: str

    def inspect(self, cap: Capability, harness: str, adapter: HarnessAdapter) -> Verdict: ...


def _browser_cache() -> Path:
    """Where Playwright keeps browser binaries (honoring the standard override)."""
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env and env != "0":
        return Path(env)
    return Path.home() / ".cache" / "ms-playwright"


def _browsers_installed() -> tuple[bool, Path]:
    cache = _browser_cache()
    if not cache.is_dir():
        return False, cache
    found = any(
        p.is_dir() and p.name.startswith(_BROWSER_DIR_PREFIXES) for p in cache.iterdir()
    )
    return found, cache


def _floating_npx_tag(command: tuple[str, ...]) -> str | None:
    """If the launcher is an `npx` invocation that re-resolves a package on every
    start (an `@latest`/`@next` dist-tag, or a scoped package with no version),
    return the offending token. Such launchers fail offline even when browsers
    are installed — the exact reason opencode agents hit "no Playwright"."""
    if "npx" not in command:
        return None
    for tok in command:
        if tok.startswith("-"):
            continue
        if tok.endswith(("@latest", "@next")):
            return tok
        # scoped package with no @version pin, e.g. "@playwright/mcp"
        if tok.startswith("@") and "/" in tok and tok.count("@") == 1:
            return f"{tok} (unpinned)"
    return None


def _find_playwright(servers: dict[str, McpServer]) -> McpServer | None:
    for s in servers.values():
        haystack = (" ".join(s.command) + " " + (s.url or "")).lower()
        if "playwright" in haystack:
            return s
    return None


class E2eProvider:
    """Playwright/browser capability. Distinguishes 'present but broken' from
    'absent' — the distinction that makes `doctor` worth more than `cat`."""

    name = "e2e"

    def inspect(self, cap: Capability, harness: str, adapter: HarnessAdapter) -> Verdict:
        server = _find_playwright(adapter.mcp_servers())
        installed, cache = _browsers_installed()

        if server is None:
            if installed:
                detail = (
                    f"no Playwright wiring in {harness}, yet browsers ARE installed at "
                    f"{cache} — the capability exists but this harness can't reach it"
                )
            else:
                detail = f"no Playwright wiring in {harness} and no browser binaries at {cache}"
            return Verdict(cap.id, harness, Status.ABSENT, detail)

        if not server.enabled:
            return Verdict(
                cap.id, harness, Status.PRESENT_BROKEN,
                f"Playwright server '{server.name}' is wired but disabled",
            )

        if not installed:
            return Verdict(
                cap.id, harness, Status.PRESENT_BROKEN,
                f"Playwright server '{server.name}' wired but no browser binaries at {cache}",
            )

        floating = _floating_npx_tag(server.command)
        if floating:
            return Verdict(
                cap.id, harness, Status.PRESENT_BROKEN,
                f"Playwright server '{server.name}' launches via 'npx … {floating}': the "
                f"dist-tag is re-resolved from the registry on every start, so it fails "
                f"without network even though browsers are installed at {cache}. "
                f"Pin a version or point at a provisioned endpoint",
            )

        return Verdict(
            cap.id, harness, Status.PRESENT_OK,
            f"Playwright server '{server.name}' wired; browsers at {cache}",
        )


class CredProvider:
    """Vault-backed AD/service-account creds. Inspect = reachability of the
    broker (token self-lookup), never a secret read. The Vault client is the
    optional [cred] extra; absent it, inspect degrades to UNKNOWN, never crashes.

    The reachability path lands in Plan 001 WI-3 follow-up; for now it reports
    UNKNOWN with the reason so `doctor` is honest about what it didn't check."""

    name = "cred"

    def inspect(self, cap: Capability, harness: str, adapter: HarnessAdapter) -> Verdict:
        return Verdict(
            cap.id, harness, Status.UNKNOWN,
            "cred reachability check not yet wired (needs [cred] extra + Vault auth)",
        )


PROVIDERS: dict[str, Provider] = {
    "e2e": E2eProvider(),
    "cred": CredProvider(),
}


def adapters() -> dict[str, HarnessAdapter]:
    """Fresh adapter instances bound to this host's default config locations."""
    return {"claude": ClaudeAdapter(), "opencode": OpencodeAdapter()}
