---
name: check-capabilities
description: Inspect agent-capability-broker capability availability, missing credential shims, browser provisioning, or harness wiring drift using the acb CLI.
---

Run `acb --version` and `acb doctor --json` in the execution host's shell.
Use `acb shims --json` when comparing skill discovery across harnesses. These
commands inspect configuration and availability; they do not fetch secret values.

The manifest resolves from `ACB_MANIFEST`, the suite configuration directory,
the ACB configuration directory, then the current directory. If resolution
fails, request the manifest's path, not its contents or any credential. Pass
`--manifest "<path>"` to select an operator-provided manifest explicitly.

Report the Codex verdicts and named causes. `UNKNOWN`, a shim existing on disk,
and a reachable backend are distinct observations; none proves a successful
credential checkout or desktop skill discovery. Browser MCP writes for Codex
are currently unsupported. Use the desktop's available browser tools when
appropriate; do not install another browser stack merely to turn doctor green.

For missing credential shims, preview `acb install-harness codex --dry-run --json`.
Dry-run exits 2 by contract. Apply with `acb install-harness codex --json` only
when installing the wiring is within the user's request. It creates shared
skills under `~/.agents/skills` and preserves existing files. Open a new chat
after installation for discovery. The static plugin supplies this workflow;
the installed CLI and host's capability manifest supply the actual capabilities.

On Windows use PowerShell commands on separate lines. A POSIX `acb` shell
wrapper alone is insufficient; use the installed `acb.exe` entry point. Do not
print configuration bodies, environment dumps, Vault files, or secret values
while diagnosing PATH or backend configuration.
