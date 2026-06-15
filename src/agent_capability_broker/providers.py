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
from .model import Action, ActionResult, Capability, McpServer, Status, Verdict

_BROWSER_DIR_PREFIXES = ("chromium", "chromium_headless_shell", "firefox", "webkit")


class HarnessAdapter(Protocol):
    name: str

    def available(self) -> bool: ...
    def mcp_servers(self) -> dict[str, McpServer]: ...


class Provider(Protocol):
    name: str

    def inspect(self, cap: Capability, harness: str, adapter: HarnessAdapter) -> Verdict: ...
    def plan_reconcile(
        self, cap: Capability, harness: str, adapter: HarnessAdapter
    ) -> list[Action]: ...
    def apply(self, action: Action, adapter: HarnessAdapter) -> ActionResult: ...


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


def _pin_package(token: str, pin: str) -> str:
    """Set a package token's version to `pin`, preserving an `@scope/name`.

    A version separator is an `@` that is not the leading scope marker.
    "@playwright/mcp@latest" -> "@playwright/mcp@<pin>"; "pkg" -> "pkg@<pin>".
    """
    at = token.rfind("@")
    base = token[:at] if at > 0 else token
    return f"{base}@{pin}"


def _pin_argv(command: tuple[str, ...], pin: str) -> list[str]:
    """Return argv with the (first) playwright package token pinned to `pin`."""
    out: list[str] = []
    pinned = False
    for tok in command:
        if not pinned and not tok.startswith("-") and "playwright" in tok.lower():
            out.append(_pin_package(tok, pin))
            pinned = True
        else:
            out.append(tok)
    return out


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

    def plan_reconcile(
        self, cap: Capability, harness: str, adapter: HarnessAdapter
    ) -> list[Action]:
        verdict = self.inspect(cap, harness, adapter)
        if verdict.status in (Status.PRESENT_OK, Status.NOT_APPLICABLE, Status.UNKNOWN):
            return []

        server = _find_playwright(adapter.mcp_servers())
        # The one case with a safe automatic fix: a wired-but-floating npx launcher.
        if (
            verdict.status is Status.PRESENT_BROKEN
            and server is not None
            and server.enabled
            and _floating_npx_tag(server.command) is not None
        ):
            pin = cap.options.get("pin")
            if isinstance(pin, str) and pin:
                argv = _pin_argv(server.command, pin)
                return [
                    Action(
                        cap.id, harness, "pin_npx_version", server.name,
                        f"pin '{server.name}' launcher to a fixed version "
                        f"(removes the per-start registry resolution)",
                        payload={"argv": argv},
                    )
                ]
            return [
                Action(
                    cap.id, harness, "manual", server.name,
                    "wired via a floating npx tag; set options.pin = \"<version>\" in the "
                    "manifest (or backend = \"remote\") to enable an automatic fix",
                )
            ]

        # No safe automatic fix yet (absent / no browsers / disabled): surface it.
        return [Action(cap.id, harness, "manual", cap.id, verdict.detail)]

    def apply(self, action: Action, adapter: HarnessAdapter) -> ActionResult:
        if action.kind == "manual":
            return ActionResult(action, "skipped", "manual action — no automatic apply")
        if action.kind == "pin_npx_version":
            if not isinstance(adapter, OpencodeAdapter):
                return ActionResult(action, "skipped", "writing is wired for opencode only")
            raw = action.payload.get("argv", [])
            argv = [str(x) for x in raw] if isinstance(raw, list) else []
            res = adapter.write_command(action.target, argv)
            if not res.changed:
                return ActionResult(action, "skipped", "already pinned")
            return ActionResult(
                action, "applied", f"pinned launcher to {' '.join(argv)}",
                backup_path=str(res.backup_path),
            )
        return ActionResult(action, "skipped", f"unsupported action kind {action.kind!r}")


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

    def plan_reconcile(
        self, cap: Capability, harness: str, adapter: HarnessAdapter
    ) -> list[Action]:
        # cred exec/inject is Plan 002 WI-4; nothing to reconcile in configs yet.
        return []

    def apply(self, action: Action, adapter: HarnessAdapter) -> ActionResult:
        return ActionResult(action, "skipped", "cred act path not yet implemented (WI-4)")


PROVIDERS: dict[str, Provider] = {
    "e2e": E2eProvider(),
    "cred": CredProvider(),
}


def adapters() -> dict[str, HarnessAdapter]:
    """Fresh adapter instances bound to this host's default config locations."""
    return {"claude": ClaudeAdapter(), "opencode": OpencodeAdapter()}
