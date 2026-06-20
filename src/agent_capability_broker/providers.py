"""Providers. Stdlib-only core (inspect/reconcile/exec dispatch).

A provider implements the four spine operations: `inspect` (read-only),
`plan_reconcile` + `apply` (the gated config act path), and `exec` (inject a
capability into a child process). The Vault backend used by `cred.exec` is an
optional extra imported lazily from `cred_vault`, so this module stays
stdlib-only.

`inspect` is side-effect-free; `exec` injects a secret into the child's
environment and never returns it to stdout or the model context.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Protocol

from . import provenance
from .adapters import ClaudeAdapter, OpencodeAdapter
from .model import Action, ActionResult, Capability, McpServer, Status, Verdict

_BROWSER_DIR_PREFIXES = ("chromium", "chromium_headless_shell", "firefox", "webkit")


class HarnessAdapter(Protocol):
    name: str

    @property
    def shims_path(self) -> Path: ...
    @property
    def vault_env_path(self) -> Path: ...
    def available(self) -> bool: ...
    def mcp_servers(self) -> dict[str, McpServer]: ...
    def command_shims(self) -> set[str]: ...


class Provider(Protocol):
    name: str

    def inspect(self, cap: Capability, harness: str, adapter: HarnessAdapter) -> Verdict: ...
    def plan_reconcile(
        self, cap: Capability, harness: str, adapter: HarnessAdapter
    ) -> list[Action]: ...
    def apply(self, action: Action, adapter: HarnessAdapter) -> ActionResult: ...
    def exec(self, cap: Capability, argv: list[str]) -> int: ...


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

        # ABSENT: the harness exposes no Playwright at all. If browsers are present
        # and the manifest pins a version, add a pinned wiring; otherwise surface
        # the prerequisite as a manual step.
        if verdict.status is Status.ABSENT:
            installed, _ = _browsers_installed()
            if not installed:
                return [Action(
                    cap.id, harness, "manual", "e2e",
                    "no browser binaries; run `playwright install chromium` first",
                )]
            pin = cap.options.get("pin")
            if not (isinstance(pin, str) and pin):
                return [Action(
                    cap.id, harness, "manual", "e2e",
                    "set options.pin = \"<version>\" in the manifest to add a pinned wiring",
                )]
            command = ["npx", "-y", f"@playwright/mcp@{pin}", "--headless", "--isolated"]
            return [Action(
                cap.id, harness, "add_mcp", "playwright",
                f"add a pinned Playwright MCP server to {harness}",
                payload={"command": command},
            )]

        # No safe automatic fix (e.g. disabled / no browsers while wired): surface it.
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
        if action.kind == "add_mcp":
            if not isinstance(adapter, ClaudeAdapter | OpencodeAdapter):
                return ActionResult(action, "skipped", "writing not supported for this harness")
            if action.target in adapter.mcp_servers():
                return ActionResult(action, "skipped", "already present")
            raw = action.payload.get("command", [])
            command = [str(x) for x in raw] if isinstance(raw, list) else []
            res = adapter.add_mcp_server(action.target, command)
            return ActionResult(
                action, "applied", f"added '{action.target}' -> {' '.join(command)}",
                backup_path=str(res.backup_path) if res.backup_path else None,
            )
        return ActionResult(action, "skipped", f"unsupported action kind {action.kind!r}")

    def exec(self, cap: Capability, argv: list[str]) -> int:
        raise NotImplementedError(
            "e2e exec (running a command against a provisioned browser) is not yet "
            "implemented; use `reconcile` to fix wiring"
        )


def _inject_var(field: str, mapping: object) -> str:
    """Env var name for a resolved field: an explicit mapping wins, else FIELD."""
    if isinstance(mapping, dict):
        override = mapping.get(field)
        if isinstance(override, str) and override:
            return override
    return field.upper()


def _cred_shim_name(cap: Capability) -> str:
    """The command/skill shim that surfaces `acb exec <cap>` to a harness.

    Derived from the capability id (`cred:svc-bot` -> `cred-svc-bot`), overridable
    via `options.shim`. This is the discoverability artifact `doctor` looks for.
    """
    shim = cap.options.get("shim")
    if isinstance(shim, str) and shim:
        return shim
    return cap.id.replace(":", "-")


def _render_cred_shim(cap: Capability, harness: str, shim: str, vault_env: Path) -> str:
    """Markdown for a cred discovery shim. Carries **no secret** — only the
    capability id and the inject-don't-surface invocation pattern. Frontmatter
    matches each harness: Claude `SKILL.md` needs `name:`, opencode does not.

    The command prefixes `ACB_VAULT_ENV` so acb authenticates via this harness's
    AppRole `.env` (per-harness role separation: Claude and opencode hold
    distinct AppRoles with distinct least-privilege policies).
    """
    desc = (
        f"Run a command with the {cap.id} credential injected by acb "
        f"(inject-don't-surface — the secret reaches the child's environment, never "
        f"stdout or your context). Use when a tool needs {cap.id}."
    )
    body = f"""# {shim} — broker {cap.id}

`{cap.id}` is brokered by **agent-capability-broker**; it is not stored in this
harness. To run a tool with it, shell out to `acb exec` — the credential is
injected into the child process's environment and **never** printed or returned
to your context:

```
ACB_VAULT_ENV={vault_env} acb exec {cap.id} -- <command> [args...]
```

`ACB_VAULT_ENV` points acb at this harness's Vault AppRole (distinct per
harness). Do not read or echo the secret. `acb doctor` reports whether this
capability is present and the broker reachable; `acb reconcile` (re)renders this shim.
"""
    if harness == "claude":
        front = f'---\nname: {shim}\ndescription: "{desc}"\n---\n\n'
    else:
        front = f'---\ndescription: "{desc}"\n---\n\n'
    return front + body


class CredProvider:
    """Vault-backed AD/service-account creds.

    Discoverability has two axes (Plan 004): a credential is *discoverable* in a
    harness iff that harness exposes a command/skill shim surfacing `acb exec
    cred:<name>` (the ABSENT axis), and *working* iff the broker is reachable via
    a read-only token self-lookup (the PRESENT_OK vs PRESENT_BROKEN axis). The
    Vault client is the optional [cred] extra; absent it (or absent Vault env),
    reachability degrades to UNKNOWN with a reason — never a crash."""

    name = "cred"

    def _reachability(self, cap: Capability) -> tuple[Status, str]:
        """Read-only broker reachability -> (status, detail). Never reads a secret;
        any failure is mapped to UNKNOWN so `doctor` stays honest and robust."""
        source = str(cap.options.get("source", "vault"))
        if source == "env":
            var = cap.options.get("from_env")
            if isinstance(var, str) and var in os.environ:
                return Status.PRESENT_OK, f"source 'env': ${var} is set"
            return Status.PRESENT_BROKEN, f"source 'env': ${var or '?'} is not set"
        if source != "vault":
            return Status.UNKNOWN, f"unknown cred source {source!r}"
        try:
            from . import cred_vault  # lazy: keeps the [cred] extra optional

            ok = cred_vault.reachable(cap)
        except Exception as exc:  # best-effort: never let a probe break doctor
            return Status.UNKNOWN, f"broker reachability not checked ({exc})"
        if ok:
            return Status.PRESENT_OK, "broker reachable (token self-lookup)"
        return Status.PRESENT_BROKEN, "broker unreachable (token self-lookup failed)"

    def inspect(self, cap: Capability, harness: str, adapter: HarnessAdapter) -> Verdict:
        shim = _cred_shim_name(cap)
        if shim not in adapter.command_shims():
            return Verdict(
                cap.id, harness, Status.ABSENT,
                f"no '{shim}' shim in {harness}: an agent there can't discover "
                f"`acb exec {cap.id}`",
            )
        status, detail = self._reachability(cap)
        return Verdict(cap.id, harness, status, f"'{shim}' shim present; {detail}")

    def plan_reconcile(
        self, cap: Capability, harness: str, adapter: HarnessAdapter
    ) -> list[Action]:
        shim = _cred_shim_name(cap)
        if shim not in adapter.command_shims():
            content = _render_cred_shim(cap, harness, shim, adapter.vault_env_path)
            return [Action(
                cap.id, harness, "add_cred_shim", shim,
                f"add a '{shim}' discovery shim to {harness} (surfaces `acb exec {cap.id}`)",
                payload={"content": content},
            )]
        # Shim present: discoverability is satisfied. An unreachable broker is an
        # infra/auth problem, not something a config write can fix — surface it.
        status, detail = self._reachability(cap)
        if status is Status.PRESENT_BROKEN:
            return [Action(
                cap.id, harness, "manual", shim,
                f"broker unreachable for {cap.id}: {detail} — fix Vault/auth, not a shim",
            )]
        return []

    def apply(self, action: Action, adapter: HarnessAdapter) -> ActionResult:
        if action.kind == "manual":
            return ActionResult(action, "skipped", "manual action — no automatic apply")
        if action.kind != "add_cred_shim":
            return ActionResult(action, "skipped", f"unsupported action kind {action.kind!r}")
        if action.target in adapter.command_shims():
            return ActionResult(action, "skipped", "shim already present")
        content = str(action.payload.get("content", ""))
        if isinstance(adapter, OpencodeAdapter):
            res = adapter.write_command_shim(action.target, content)
        elif isinstance(adapter, ClaudeAdapter):
            res = adapter.write_skill_shim(action.target, content)
        else:
            return ActionResult(action, "skipped", "shim rendering not supported for this harness")
        return ActionResult(
            action, "applied", f"rendered '{action.target}' discovery shim",
            backup_path=str(res.backup_path) if res.backup_path else None,
        )

    def _resolve(self, cap: Capability) -> dict[str, str]:
        """Return the capability's secret field(s). Source-pluggable.

        `vault` (default) brokers via Vault (optional [cred] extra); `env` reads
        an already-present environment variable (lightweight / testing). Either
        way the value is returned only to `exec`, never to the model context.
        """
        source = str(cap.options.get("source", "vault"))
        if source == "env":
            var = cap.options.get("from_env")
            if not isinstance(var, str) or not var:
                raise RuntimeError(f"{cap.id}: source 'env' requires options.from_env")
            if var not in os.environ:
                raise RuntimeError(f"{cap.id}: env var ${var} is not set")
            field = str(cap.options.get("field", "password"))
            return {field: os.environ[var]}
        if source == "vault":
            from . import cred_vault  # lazy: keeps the [cred] extra optional

            return cred_vault.resolve(cap)
        raise RuntimeError(f"{cap.id}: unknown cred source {source!r}")

    def exec(self, cap: Capability, argv: list[str]) -> int:
        """Run `argv` with the resolved secret(s) injected into its environment.

        Inject-don't-surface: the secret is placed only in the child's env (per
        `options.inject`, else the upper-cased field name); it is never written
        to stdout, the provenance event, or the model context. Returns the
        child's exit code.
        """
        if not argv:
            raise ValueError("exec requires a command after '--'")

        fields = self._resolve(cap)
        mapping = cap.options.get("inject")
        child_env = os.environ.copy()
        injected: list[str] = []
        for field, value in fields.items():
            var = _inject_var(field, mapping)
            child_env[var] = value
            injected.append(var)

        result = subprocess.run(argv, env=child_env)  # noqa: S603 (intentional exec)

        # Provenance records the act and which env vars were set — never a value.
        action = Action(
            cap.id, "local", "exec", cap.id,
            f"injected {sorted(injected)} into child '{argv[0]}'",
        )
        provenance.emit(
            ActionResult(action, "applied", f"child exited {result.returncode}")
        )
        return result.returncode


PROVIDERS: dict[str, Provider] = {
    "e2e": E2eProvider(),
    "cred": CredProvider(),
}


def adapters() -> dict[str, HarnessAdapter]:
    """Fresh adapter instances bound to this host's default config locations."""
    return {"claude": ClaudeAdapter(), "opencode": OpencodeAdapter()}
