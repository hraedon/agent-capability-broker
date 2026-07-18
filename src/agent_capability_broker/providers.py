"""Providers. Stdlib-only core (inspect/reconcile/exec dispatch).

A provider implements the four spine operations: `inspect` (read-only),
`plan_reconcile` + `apply` (the gated config act path), and `exec` (inject a
capability into a child process). The Vault backend used by `cred.exec` is an
optional extra imported lazily from `cred_vault`, so this module stays
stdlib-only.

`inspect` is side-effect-free; `exec` never emits a secret through
ACB-controlled output. A suite child inherits stdout/stderr and is constrained
to an exact manifest-qualified command because it remains in the trust boundary.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from . import provenance
from .adapters import ClaudeAdapter, CodexAdapter, HermesAdapter, OpencodeAdapter, WriteResult
from .model import Action, ActionResult, Capability, McpServer, Status, Verdict
from .secret_sources import (
    SecretSourceConfigError,
    SecretSourceError,
    SecretSourceKind,
    SecretSourceUnavailable,
    resolve_suite,
    source_kind,
    suite_spec,
    validate_suite_command,
)

_BROWSER_DIR_PREFIXES = ("chromium", "chromium_headless_shell", "firefox", "webkit")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_RESERVED_INJECT_VARS = frozenset(
    {
        "COMSPEC", "HOME", "PATH", "PATHEXT", "PYTHONHOME", "PYTHONPATH",
        "ACB_CHECKOUT_RECEIPT", "SHELL", "SYSTEMROOT", "TEMP", "TMP", "USERPROFILE",
    }
)
_SUITE_CHILD_ENV_ALLOWLIST = frozenset(
    {"LANG", "LC_ALL", "SYSTEMROOT", "TEMP", "TMP", "TZ", "WINDIR"}
)
_TREE_TERMINATION_GRACE_SECONDS = 2.0


class HarnessAdapter(Protocol):
    name: str

    @property
    def shims_path(self) -> Path: ...
    @property
    def vault_env_path(self) -> Path: ...
    def available(self) -> bool: ...
    def mcp_servers(self) -> dict[str, McpServer]: ...
    def command_shims(self) -> set[str]: ...
    def shim_path(self, name: str) -> Path: ...
    def read_shim(self, name: str) -> str | None: ...
    def remove_shim(self, name: str) -> WriteResult: ...


class Provider(Protocol):
    name: str

    def inspect(self, cap: Capability, harness: str, adapter: HarnessAdapter) -> Verdict: ...
    def plan_reconcile(
        self, cap: Capability, harness: str, adapter: HarnessAdapter
    ) -> list[Action]: ...
    def plan_uninstall(
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

        if isinstance(adapter, CodexAdapter):
            return [Action(
                cap.id,
                harness,
                "manual",
                cap.id,
                "Codex e2e/MCP reconciliation is unsupported; existing wiring is "
                "inspected read-only and never rewritten",
                payload={"unsupported": True},
            )]

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

    def plan_uninstall(
        self, cap: Capability, harness: str, adapter: HarnessAdapter
    ) -> list[Action]:
        """Plan removal of acb-installed e2e MCP wiring. Ownership is proven by
        matching the server command to what acb would add (the server name is
        not checked — ``_find_playwright`` finds any server whose command or
        URL contains 'playwright'). A server that doesn't match (hand-authored,
        modified, or no pin in manifest) is preserved."""
        server = _find_playwright(adapter.mcp_servers())
        if server is None:
            return []
        pin = cap.options.get("pin")
        if not (isinstance(pin, str) and pin):
            return [Action(
                cap.id, harness, "manual", server.name,
                f"manifest has no options.pin for {cap.id}; cannot verify "
                f"ownership of '{server.name}' — remove manually if needed",
            )]
        expected_cmd = ["npx", "-y", f"@playwright/mcp@{pin}", "--headless", "--isolated"]
        if list(server.command) == expected_cmd:
            return [Action(
                cap.id, harness, "remove_mcp", server.name,
                f"remove acb-installed '{server.name}' MCP server from {harness}",
                payload={"expected_command": expected_cmd},
            )]
        return [Action(
            cap.id, harness, "manual", server.name,
            f"'{server.name}' in {harness} does not match acb's expected wiring — "
            f"not removing (hand-authored or modified); remove manually if needed",
        )]

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
            if not isinstance(adapter, ClaudeAdapter | OpencodeAdapter | HermesAdapter):
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
        if action.kind == "remove_mcp":
            if not isinstance(adapter, ClaudeAdapter | OpencodeAdapter | HermesAdapter):
                return ActionResult(action, "skipped", "MCP removal not supported for this harness")
            current = adapter.mcp_servers().get(action.target)
            if current is None:
                return ActionResult(action, "skipped", "already absent")
            expected = action.payload.get("expected_command")
            if not isinstance(expected, list) or list(current.command) != expected:
                return ActionResult(
                    action,
                    "failed",
                    "MCP wiring changed after uninstall planning; preserved",
                )
            res = adapter.remove_mcp_server(action.target)
            if not res.changed:
                return ActionResult(action, "skipped", "already absent")
            return ActionResult(
                action, "applied", f"removed '{action.target}' MCP server",
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


def _injection_plan(
    cap: Capability, fields: list[str], *, mapping: object | None = None
) -> dict[str, str]:
    """Validate field->child-env wiring before any child is launched.

    Existing inherited variables are never silently clobbered. Environment
    names required for process/runtime operation are refused even if absent.
    """
    selected = cap.options.get("inject") if mapping is None else mapping
    plan: dict[str, str] = {}
    inherited = {name.upper() for name in os.environ}
    if "ACB_CHECKOUT_RECEIPT" in inherited:
        raise SecretSourceConfigError(
            f"{cap.id}: inherited ACB_CHECKOUT_RECEIPT is refused; nested checkout "
            "inheritance is not supported"
        )
    used: set[str] = set()
    for field in fields:
        var = _inject_var(field, selected)
        if not _ENV_NAME.fullmatch(var):
            raise SecretSourceConfigError(
                f"{cap.id}: inject target for field {field!r} is not a valid environment name"
            )
        folded = var.upper()
        if folded in _RESERVED_INJECT_VARS:
            raise SecretSourceConfigError(
                f"{cap.id}: inject target {var!r} is reserved for process operation"
            )
        if folded in used:
            raise SecretSourceConfigError(
                f"{cap.id}: duplicate inject target {var!r}"
            )
        if folded in inherited:
            raise SecretSourceConfigError(
                f"{cap.id}: inject target {var!r} already exists in the inherited environment"
            )
        used.add(folded)
        plan[field] = var
    return plan


def _suite_child_env(plan: dict[str, str], fields: list[str]) -> dict[str, str]:
    """Build a minimal environment for the exact suite command.

    The absolute executable path makes PATH unnecessary. Credential field names
    and inject targets are excluded from inherited state before resolved values
    are added by the caller.
    """
    blocked = {name.upper() for name in plan.values()}
    blocked.update(field.upper() for field in fields)
    return {
        name: value
        for name, value in os.environ.items()
        if name.upper() in _SUITE_CHILD_ENV_ALLOWLIST and name.upper() not in blocked
    }


def _checkout_receipt(
    cap: Capability,
    field_env: dict[str, str],
    *,
    invocation_id: str,
    timeout_seconds: float,
) -> str:
    """Return value-free launch correlation metadata for the qualified child."""
    issued = datetime.now(UTC)
    expires = issued + timedelta(seconds=timeout_seconds)
    issued_text = issued.isoformat().replace("+00:00", "Z")
    expires_text = expires.isoformat().replace("+00:00", "Z")
    return json.dumps(
        {
            "schema": "acb.checkout-receipt.v1",
            "invocation_id": invocation_id,
            "issued_at": issued_text,
            "expires_at": expires_text,
            "checkouts": [
                {
                    "capability_id": cap.id,
                    "fields": {field: field_env[field] for field in sorted(field_env)},
                }
            ],
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _windows_taskkill_path() -> str:
    """Return a trusted taskkill path or fail closed before secret resolution."""
    found = shutil.which("taskkill.exe") or shutil.which("taskkill")
    if found:
        return str(Path(found).resolve())
    system_root = os.environ.get("SystemRoot")
    if system_root:
        candidate = Path(system_root) / "System32" / "taskkill.exe"
        if candidate.is_file():
            return str(candidate)
    raise SecretSourceUnavailable(
        "source 'suite' is disabled on Windows because taskkill.exe is unavailable"
    )


def _windows_containment_preflight() -> str:
    if not getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0):
        raise SecretSourceUnavailable(
            "source 'suite' is disabled on Windows because process-group creation "
            "is unavailable"
        )
    return _windows_taskkill_path()


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    *,
    platform_name: str,
    taskkill_path: str | None = None,
    grace_seconds: float = _TREE_TERMINATION_GRACE_SECONDS,
) -> None:
    """Terminate and reap the owned process tree without exposing its env."""
    if platform_name == "nt":
        if taskkill_path is None:
            raise RuntimeError("Windows process-tree containment is unavailable")
        try:
            completed = subprocess.run(  # noqa: S603 (trusted system executable)
                [taskkill_path, "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=grace_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            if process.poll() is None:
                process.kill()
            process.wait(timeout=grace_seconds)
            raise RuntimeError("Windows process-tree termination failed") from None
        if completed.returncode != 0:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=grace_seconds)
            raise RuntimeError("Windows process-tree termination failed")
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)  # type: ignore[attr-defined, unused-ignore]  # POSIX-only
        except ProcessLookupError:
            if process.poll() is None:
                process.wait(timeout=grace_seconds)
            return
        deadline = time.monotonic() + grace_seconds
        while True:
            process.poll()  # reap the direct child as soon as it exits
            try:
                os.killpg(process.pid, 0)  # type: ignore[attr-defined, unused-ignore]  # POSIX-only
            except ProcessLookupError:
                break
            if time.monotonic() >= deadline:
                try:
                    os.killpg(process.pid, signal.SIGKILL)  # type: ignore[attr-defined, unused-ignore]  # POSIX-only
                except ProcessLookupError:
                    pass
                break
            time.sleep(0.05)

    try:
        process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=grace_seconds)


def _run_contained(
    argv: list[str],
    *,
    env: dict[str, str],
    timeout_seconds: float,
    taskkill_path: str | None,
) -> subprocess.CompletedProcess[bytes]:
    """Run an exact command in an owned process group; contain on every interruption."""
    if os.name == "nt":
        creation_flag = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if not creation_flag or taskkill_path is None:
            raise RuntimeError("Windows process-tree containment is unavailable")
        process = subprocess.Popen(  # noqa: S603 (exact trusted argv)
            argv,
            env=env,
            creationflags=creation_flag,
        )
    else:
        process = subprocess.Popen(  # noqa: S603 (exact trusted argv)
            argv,
            env=env,
            start_new_session=True,
        )
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except BaseException:
        _terminate_process_tree(
            process,
            platform_name=os.name,
            taskkill_path=taskkill_path,
        )
        raise
    if os.name != "nt":
        # A qualified child should not leave descendants behind. Kill any
        # process still in the owned session before returning normally.
        try:
            os.killpg(process.pid, 0)  # type: ignore[attr-defined, unused-ignore]  # POSIX-only
        except ProcessLookupError:
            pass
        else:
            _terminate_process_tree(process, platform_name=os.name)
    return subprocess.CompletedProcess(argv, returncode)


def _cred_shim_name(cap: Capability) -> str:
    """The command/skill shim that surfaces `acb exec <cap>` to a harness.

    Derived from the capability id (`cred:svc-bot` -> `cred-svc-bot`), overridable
    via `options.shim`. This is the discoverability artifact `doctor` looks for.
    """
    shim = cap.options.get("shim")
    if isinstance(shim, str) and shim:
        return shim
    return cap.id.replace(":", "-")


_ACB_MANAGED_MARKER = "<!-- acb:managed-shim -->"


def _looks_acb_owned(content: str) -> bool:
    """Loose ownership check: does this content look like an acb-rendered shim?

    Every shim acb renders carries a unique ``<!-- acb:managed-shim -->`` marker
    at the end of the body. A hand-authored shim is extremely unlikely to
    contain this exact comment. Used as a fallback when the exact content hash
    doesn't match (stale shim after acb upgrade or manifest drift).
    """
    return _ACB_MANAGED_MARKER in content


def _vault_env_path(cap: Capability, adapter: HarnessAdapter) -> Path:
    """The `.env` file the shim should point `ACB_VAULT_ENV` at.

    Defaults to the adapter's `vault_env_path` (beside the harness config). A
    capability may override with `options.vault_env` (a bare filename resolved
    against the same dir) to use a different AppRole per access plane — e.g.
    homelab AD creds via `vault.env`, cert-watch test creds via `cert-watch.env`.
    """
    base = adapter.vault_env_path
    override = cap.options.get("vault_env")
    if isinstance(override, str) and override:
        return base.parent / override
    return base


def _render_cred_shim(cap: Capability, harness: str, shim: str, vault_env: Path) -> str:
    """Markdown for a cred discovery shim. Carries **no secret** — only the
    capability id and the inject-don't-surface invocation pattern. Frontmatter
    matches each harness: Claude `SKILL.md` needs `name:`, opencode does not.

    The command prefixes `ACB_VAULT_ENV` so acb authenticates via this harness's
    AppRole `.env` (per-harness role separation: Claude and opencode hold
    distinct AppRoles with distinct least-privilege policies).  Invocation
    patterns are rendered for both Unix and Windows so a cross-platform estate
    can follow the same shim from either OS (Plan 005 WI-3.1).
    """
    desc = (
        f"Run a command with the {cap.id} credential injected by acb "
        f"(ACB never prints the value; the manifest-qualified child is responsible "
        f"for safe output). Use when a tool needs {cap.id}."
    )
    ve = str(vault_env)
    if source_kind(cap) is SecretSourceKind.SUITE:
        unix_command = f"acb exec {cap.id} -- <exact options.trusted_argv>"
        powershell_command = unix_command
        cmd_command = unix_command
        source_note = (
            "The suite resolver selects the configured backend at execution time; "
            "the shim contains only the capability id and no secret reference."
        )
    else:
        unix_command = f"ACB_VAULT_ENV={ve} acb exec {cap.id} -- <command> [args...]"
        powershell_command = (
            f'$env:ACB_VAULT_ENV="{ve}"; acb exec {cap.id} -- <command> [args...]'
        )
        cmd_command = (
            f'set "ACB_VAULT_ENV={ve}"&& acb exec {cap.id} -- <command> [args...]'
        )
        source_note = (
            "`ACB_VAULT_ENV` points acb at this harness's Vault AppRole "
            "(distinct per harness)."
        )
    body = f"""# {shim} — broker {cap.id}

`{cap.id}` is brokered by **agent-capability-broker**; it is not stored in this
harness. To run a tool with it, shell out to `acb exec` — the credential is
injected into the child process's environment. ACB does not print or return it,
but the child inherits stdout/stderr and must be the exact manifest-qualified
command; do not invoke a shell, interpreter, or unreviewed wrapper.

**Linux / macOS:**

```
{unix_command}
```

**Windows (PowerShell):**

```
{powershell_command}
```

**Windows (cmd):**

```
{cmd_command}
```

{source_note} Do not read or echo the secret. `acb doctor` reports whether this
capability is present and the broker reachable; `acb reconcile` (re)renders this shim.
`acb install-harness {harness}` is the bootstrap step that renders all shims for
this harness at once.

<!-- acb:managed-shim -->
"""
    if harness in ("claude", "hermes", "codex"):
        front = f'---\nname: {shim}\ndescription: "{desc}"\n---\n\n'
    else:
        front = f'---\ndescription: "{desc}"\n---\n\n'
    return front + body


class CredProvider:
    """Inject-only AD/service-account credentials from closed source kinds.

    Discoverability has two axes (Plan 004): a credential is *discoverable* in a
    harness iff that harness exposes a command/skill shim surfacing `acb exec
    cred:<name>` (the ABSENT axis), and *working* iff the selected source can be
    validated without reading a value (the PRESENT_OK/PRESENT_BROKEN/UNKNOWN
    axis). Backend clients are optional lazy imports; absence degrades to an
    actionable UNKNOWN, never a crash."""

    name = "cred"

    def _reachability(
        self, cap: Capability, *, vault_env: Path | None = None
    ) -> tuple[Status, str]:
        """Read-only broker reachability -> (status, detail). Never reads a secret;
        any failure is mapped to UNKNOWN so `doctor` stays honest and robust.

        `vault_env` pins the probe to the capability's declared access plane (the
        same `.env` the shim embeds) so multi-plane estates are checked per-plane,
        not all through one shell `ACB_VAULT_ENV` (WI-008)."""
        try:
            source = source_kind(cap)
        except SecretSourceConfigError as exc:
            return Status.PRESENT_BROKEN, str(exc)
        if source is SecretSourceKind.ENV:
            var = cap.options.get("from_env")
            if isinstance(var, str) and var in os.environ:
                return Status.PRESENT_OK, f"source 'env': ${var} is set"
            return Status.PRESENT_BROKEN, f"source 'env': ${var or '?'} is not set"
        if source is SecretSourceKind.SUITE:
            try:
                spec = suite_spec(cap, require_available=True)
            except SecretSourceConfigError as exc:
                return Status.PRESENT_BROKEN, str(exc)
            except SecretSourceUnavailable as exc:
                return Status.UNKNOWN, str(exc)
            providers = sorted(set(spec.providers.values()))
            return (
                Status.UNKNOWN,
                f"suite provider(s) {providers!r} available; values intentionally unproven",
            )
        try:
            from . import cred_vault  # lazy: keeps the [cred] extra optional

            ok = cred_vault.reachable(cap, vault_env=vault_env)
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
        actual = adapter.read_shim(shim)
        try:
            expected = _render_cred_shim(
                cap, harness, shim, _vault_env_path(cap, adapter)
            )
        except Exception:
            expected = None
        if actual is None or expected is None or actual != expected:
            ownership = (
                "ACB-marked but modified"
                if actual and _looks_acb_owned(actual)
                else "not ACB-owned"
            )
            return Verdict(
                cap.id,
                harness,
                Status.PRESENT_BROKEN,
                f"'{shim}' skill name is present but its content is {ownership}; "
                "preserved as a conflict rather than trusted as capability wiring",
            )
        status, detail = self._reachability(cap, vault_env=_vault_env_path(cap, adapter))
        return Verdict(cap.id, harness, status, f"'{shim}' shim present; {detail}")

    def plan_reconcile(
        self, cap: Capability, harness: str, adapter: HarnessAdapter
    ) -> list[Action]:
        shim = _cred_shim_name(cap)
        if shim not in adapter.command_shims():
            content = _render_cred_shim(cap, harness, shim, _vault_env_path(cap, adapter))
            return [Action(
                cap.id, harness, "add_cred_shim", shim,
                f"add a '{shim}' discovery shim to {harness} (surfaces `acb exec {cap.id}`)",
                payload={"content": content},
            )]
        actual = adapter.read_shim(shim)
        try:
            expected = _render_cred_shim(
                cap, harness, shim, _vault_env_path(cap, adapter)
            )
        except Exception:
            expected = None
        if actual is None or expected is None or actual != expected:
            ownership = (
                "ACB-marked but modified"
                if actual and _looks_acb_owned(actual)
                else "hand-authored"
            )
            return [Action(
                cap.id,
                harness,
                "manual",
                shim,
                f"'{shim}' already exists with {ownership} content; preserving it "
                "and refusing to claim capability wiring",
                payload={"conflict": True},
            )]
        # Shim present: discoverability is satisfied. An unreachable broker is an
        # infra/auth problem, not something a config write can fix — surface it.
        status, detail = self._reachability(cap, vault_env=_vault_env_path(cap, adapter))
        if status is Status.PRESENT_BROKEN:
            return [Action(
                cap.id, harness, "manual", shim,
                f"broker unreachable for {cap.id}: {detail} — fix Vault/auth, not a shim",
            )]
        return []

    def plan_uninstall(
        self, cap: Capability, harness: str, adapter: HarnessAdapter
    ) -> list[Action]:
        """Plan removal of acb-owned cred shims. Ownership is proven **only**
        by an exact content match (hash check): the on-disk content must be
        byte-for-byte what acb would render today. A marker-bearing shim whose
        content has changed is **preserved** — the user may have edited it, and
        acb never destroys user modifications. If the expected content cannot be
        rendered (e.g. invalid source config), the shim is also preserved."""
        shim = _cred_shim_name(cap)
        if shim not in adapter.command_shims():
            return []
        actual = adapter.read_shim(shim)
        if actual is None:
            return []
        try:
            expected = _render_cred_shim(
                cap, harness, shim, _vault_env_path(cap, adapter)
            )
        except Exception:
            expected = None
        if expected is not None and actual == expected:
            return [Action(
                cap.id, harness, "remove_cred_shim", shim,
                f"remove acb-owned '{shim}' discovery shim from {harness}",
                payload={
                    "expected_sha256": hashlib.sha256(actual.encode("utf-8")).hexdigest()
                },
            )]
        if _looks_acb_owned(actual):
            # An acb-owned artifact (carries our marker) that we cannot safely
            # remove is a *conflict*: the uninstall did not complete, and the
            # caller must not read it as clean success. Flagged so the CLI fails
            # closed with a non-zero exit.
            return [Action(
                cap.id, harness, "manual", shim,
                f"'{shim}' in {harness} carries the acb marker but content has "
                f"changed — not removing (user-modified); remove manually if needed",
                payload={"conflict": True},
            )]
        # No acb marker and no content match: acb never owned this artifact, so
        # there is nothing of ours to remove. Surfaced as a manual note, but the
        # uninstall of acb-owned state is complete.
        return [Action(
            cap.id, harness, "manual", shim,
            f"'{shim}' in {harness} does not match acb's expected content and "
            f"lacks acb ownership marker — not removing (hand-authored); "
            f"remove manually if needed",
        )]

    def apply(self, action: Action, adapter: HarnessAdapter) -> ActionResult:
        if action.kind == "manual":
            return ActionResult(action, "skipped", "manual action — no automatic apply")
        if action.kind == "remove_cred_shim":
            if action.target not in adapter.command_shims():
                return ActionResult(action, "skipped", "shim already absent")
            actual = adapter.read_shim(action.target)
            expected_sha256 = action.payload.get("expected_sha256")
            if (
                actual is None
                or not isinstance(expected_sha256, str)
                or hashlib.sha256(actual.encode("utf-8")).hexdigest() != expected_sha256
            ):
                return ActionResult(
                    action,
                    "failed",
                    "shim changed after uninstall planning; preserved",
                )
            res = adapter.remove_shim(action.target)
            if not res.changed:
                return ActionResult(action, "skipped", "shim already absent")
            return ActionResult(
                action, "applied", f"removed '{action.target}' discovery shim",
            )
        if action.kind != "add_cred_shim":
            return ActionResult(action, "skipped", f"unsupported action kind {action.kind!r}")
        if action.target in adapter.command_shims():
            return ActionResult(action, "skipped", "shim already present")
        content = str(action.payload.get("content", ""))
        if isinstance(adapter, OpencodeAdapter):
            res = adapter.write_command_shim(action.target, content)
        elif isinstance(adapter, ClaudeAdapter | HermesAdapter | CodexAdapter):
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
        an already-present environment variable (lightweight/testing); and
        `suite` uses the optional public Regista facade. Values return only to
        `exec`; ACB does not place them in model-visible output. The qualified
        suite child remains responsible for its own stdout/stderr.
        """
        source = source_kind(cap)
        if source is SecretSourceKind.ENV:
            var = cap.options.get("from_env")
            if not isinstance(var, str) or not var:
                raise RuntimeError(f"{cap.id}: source 'env' requires options.from_env")
            if var not in os.environ:
                raise RuntimeError(f"{cap.id}: env var ${var} is not set")
            field = str(cap.options.get("field", "password"))
            return {field: os.environ[var]}
        if source is SecretSourceKind.VAULT:
            from . import cred_vault  # lazy: keeps the [cred] extra optional

            return cred_vault.resolve(cap)
        return resolve_suite(cap)

    def exec(self, cap: Capability, argv: list[str]) -> int:
        """Run `argv` with the resolved secret(s) injected into its environment.

        ACB itself never writes a value to argv, output, errors, receipts, or
        provenance. A suite child receives the value and inherits stdout/stderr,
        so it must exactly match the manifest-qualified command and remains part
        of the trust boundary. Returns the child's exit code.
        """
        if not argv:
            raise ValueError("exec requires a command after '--'")

        source = source_kind(cap)
        if source is not SecretSourceKind.SUITE:
            # Legacy Vault/env sources keep their established injection,
            # environment, timeout, and single-provenance behavior.
            legacy_fields = self._resolve(cap)
            mapping = cap.options.get("inject")
            legacy_plan = {
                field: _inject_var(field, mapping) for field in legacy_fields
            }
            legacy_env = os.environ.copy()
            injected: list[str] = []
            for field, value in legacy_fields.items():
                var = legacy_plan[field]
                legacy_env[var] = value
                injected.append(var)
            action = Action(
                cap.id,
                "local",
                "exec",
                cap.id,
                f"injected {sorted(injected)} into child '{argv[0]}'",
            )
            legacy_result = subprocess.run(argv, env=legacy_env)  # noqa: S603
            provenance.emit(
                ActionResult(action, "applied", f"child exited {legacy_result.returncode}")
            )
            return legacy_result.returncode

        # Suite command, manifest, collision, and receipt-name validation all
        # happen before a value is resolved.
        validate_suite_command(cap, argv)
        taskkill_path = _windows_containment_preflight() if os.name == "nt" else None
        suite = suite_spec(cap, require_available=False)
        plan = _injection_plan(cap, list(suite.refs), mapping=suite.inject)
        invocation_id = uuid.uuid4().hex
        action = Action(
            cap.id,
            "local",
            "exec",
            cap.id,
            f"qualified child '{argv[0]}' will receive {sorted(plan.values())} "
            f"(invocation {invocation_id})",
        )
        provenance.emit(
            ActionResult(action, "started", "qualified credential resolution starting")
        )
        terminal = ActionResult(action, "failed", "qualified invocation interrupted")
        fields: dict[str, str] = {}
        child_env: dict[str, str] = {}
        result: subprocess.CompletedProcess[bytes] | None = None
        pending_error: RuntimeError | None = None
        try:
            try:
                fields = resolve_suite(cap, suite)
            except SecretSourceError:
                terminal = ActionResult(
                    action,
                    "failed",
                    "qualified credential resolution failed",
                )
                raise

            child_env = _suite_child_env(plan, list(fields))
            for field, value in fields.items():
                child_env[plan[field]] = value
            child_env["ACB_CHECKOUT_RECEIPT"] = _checkout_receipt(
                cap,
                plan,
                invocation_id=invocation_id,
                timeout_seconds=suite.timeout_seconds,
            )
            try:
                result = _run_contained(
                    argv,
                    env=child_env,
                    timeout_seconds=suite.timeout_seconds,
                    taskkill_path=taskkill_path,
                )
            except subprocess.TimeoutExpired:
                terminal = ActionResult(
                    action,
                    "failed",
                    f"qualified child timed out after {suite.timeout_seconds:g} seconds",
                )
                pending_error = RuntimeError(
                    f"{cap.id}: qualified child timed out after "
                    f"{suite.timeout_seconds:g} seconds"
                )
            except OSError as exc:
                error_kind = type(exc).__name__
                terminal = ActionResult(
                    action,
                    "failed",
                    f"qualified child launch failed ({error_kind})",
                )
                pending_error = RuntimeError(
                    f"{cap.id}: qualified child launch failed ({error_kind})"
                )
            except RuntimeError:
                terminal = ActionResult(
                    action,
                    "failed",
                    "qualified child process-tree containment failed",
                )
                pending_error = RuntimeError(
                    f"{cap.id}: qualified child process-tree containment failed"
                )
            else:
                terminal = ActionResult(
                    action,
                    "applied" if result.returncode == 0 else "failed",
                    f"qualified child exited {result.returncode}",
                )
        finally:
            # Best-effort lifetime reduction. Python strings and process memory
            # cannot be cryptographically erased; this only clears live mappings.
            for field in fields:
                fields[field] = ""
            for var in plan.values():
                child_env[var] = ""
            child_env["ACB_CHECKOUT_RECEIPT"] = ""
            provenance.emit(terminal)

        if pending_error is not None:
            raise pending_error
        assert result is not None
        return result.returncode


PROVIDERS: dict[str, Provider] = {
    "e2e": E2eProvider(),
    "cred": CredProvider(),
}


def adapters() -> dict[str, HarnessAdapter]:
    """Fresh adapter instances bound to this host's default config locations."""
    return {
        "claude": ClaudeAdapter(),
        "opencode": OpencodeAdapter(),
        "hermes": HermesAdapter(),
        "codex": CodexAdapter(),
    }
