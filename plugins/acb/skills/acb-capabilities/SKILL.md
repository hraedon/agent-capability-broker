---
name: acb-capabilities
description: Inspect Agent Capability Broker health and use an already-declared, pre-qualified capability without exposing credential values. Use when a task needs a capability managed by ACB or when diagnosing ACB capability readiness in Codex.
---

# Agent Capability Broker

Use ACB as an inject-only capability boundary. The plugin contains no
credential identifiers, references, values, or backend configuration.
Capability-specific Codex skills are generated separately by
`acb install-harness codex` from the operator's local manifest.

## Inspect safely

Run `acb doctor --json` for a read-only readiness report. Treat `absent`,
`present_broken`, and `unknown` as named conditions; do not infer that a
credential exists or works merely because this plugin is installed.

Do not print the capability manifest, backend references, environment, Codex
configuration, or provenance files into model context while diagnosing a
credential capability.

## Invoke safely

Use only a capability-specific skill installed by ACB or an invocation the
operator has explicitly supplied. Invoke through:

```
acb exec <declared-capability-id> -- <pre-qualified-command-and-arguments>
```

For suite-backed credentials, the complete command and arguments must exactly
match the manifest-qualified child. Never substitute a shell, interpreter,
generic wrapper, or command assembled by the model. ACB injects values into the
qualified child; it does not return them to Codex, but the child owns its
stdout/stderr and must also be trusted not to disclose them.

Never ask ACB, the backend, or the child to get, print, echo, inspect, copy, or
return a credential value. Never put a value in argv, a skill, Codex config,
hooks, MCP configuration, a temporary script, or a transcript.

## Installation boundary

`acb install-harness codex` is a mutating bootstrap command that applies by
default. Run it only when the operator asks to provision Codex; use
`--dry-run --json` first when a preview is appropriate. Uninstall removes only
exact, ACB-rendered artifacts and preserves hand-authored or modified skills.
