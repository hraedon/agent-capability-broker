---
name: use-capability
description: Launch an authorized tool through acb exec with a named credential or browser capability, keeping injected credentials out of the conversation.
---

Identify the capability ID (`cred:<name>` or `e2e:<name>`) and the intended
operation from the user's task or an installed capability skill. Check its
availability with `acb doctor --json`. Do not infer authorization for a new
operation merely because a capability is available.

Use the installed capability skill for its host-specific broker configuration.
Launch the intended child through `acb exec <capability-id> -- <command> <args>`.
For `source = "suite"`, the complete command must match the manifest's exact
`options.trusted_argv`; use the qualified tool, never replace it with a shell,
interpreter, or wrapper. Request the approved command if it is unavailable.

ACB injects credentials into the child and does not return their values. The
child inherits stdout/stderr and must itself avoid disclosing them. Never run
`env`, `set`, `Get-ChildItem Env:`, echo, or a credential-printing test as the
child. Never retrieve a secret to paste it into another tool or chat.

Browser execution supplies `ACB_E2E_EXECUTABLE` or `ACB_E2E_ENDPOINT` to the
child; ACB does not drive the browser. If the backend is unavailable, report
the named error and stop that operation rather than inventing an endpoint.

Treat exit codes and the tool's safe result as execution evidence. A successful
doctor check alone does not prove the task ran. Keep capability IDs and
value-free receipt/provenance references when available; never log injected
values or entire child environments. Execute on the host where the manifest,
backend, and qualified executable are provisioned. A plugin installed on
Windows does not provision a remote or cloud execution host.
