# agent-capability-broker

**Keep agents at parity across harnesses.** A capability that exists on a
machine — an AD service-account credential, a Playwright browser, a web-search
backend — should be *uniformly discoverable and invocable* by an agent
regardless of which harness it runs in (Claude Code, opencode, cron, …). Today
it isn't: the same box can have working Chromium browsers that opencode can't
reach (because its Playwright MCP dies on an `npx` fetch) while Claude Code never
exposes them at all. That asymmetry — *capability present, access uneven* — is
what this tool closes.

`acb` is a small deterministic CLI driven by **one declarative manifest** of the
capabilities an estate's agents should have. From that single source it does two
things:

- **Reports** (`acb doctor`) — diff every harness against the manifest and say,
  per capability, whether it is present-and-working, present-but-broken, absent,
  or not-applicable. This is discoverability and the parity report. *Read-only.*
- **Reconciles & brokers** (`acb reconcile`, `acb exec`) — render the correct
  per-harness wiring from the manifest so two configs can't drift by hand, and
  inject the capability (credentials, a browser endpoint) into a child process at
  runtime. *Acting; gated, dry-run by default, provenance-emitting.*

## Why it exists

Two real pains, one shape:

1. **Credentials.** Agents increasingly need real creds (AD binds, service
   accounts, a remote VM). The fix so far has been per-secret Vault
   AppRoles delivered as `.env` files — better than plaintext, but still
   hand-placed per harness, and a secret in a transcript is a leaked secret.
2. **E2E tooling.** opencode agents complain "no Playwright" while Claude Code
   never does — not because the browsers are missing (they're installed) but
   because opencode reaches them through a fragile per-session MCP and Claude
   doesn't reach for them at all.

Both are the same problem: *a capability the host can provide, that agents can't
find or use the same way across harnesses.* `acb` makes the desired set explicit
and reconciles reality to it.

## Scope

**In:**
- A declarative **capability manifest** (`capabilities.toml`): the desired set,
  per estate/host, with which harnesses should expose each. It is resolved
  independently of the working directory — `$ACB_MANIFEST`, then
  `~/.config/acb/capabilities.toml` (the canonical install location), then
  `./capabilities.toml` for in-repo dev — so `acb` works the same from any
  harness's shell, not only from its own checkout.
- A **provider** interface; `cred` (Vault-brokered AD/service-account creds) and
  `e2e` (Playwright/browser provisioning, local or remote backend) are the first
  two. Adding a provider is the extension point.
- **Harness adapters** that read and render each harness's wiring (Claude Code
  `settings.json` + skills; opencode `opencode.json` MCP/commands).
- `doctor` (read-only parity report), `reconcile` (generate wiring, dry-run by
  default), `exec` (inject-and-run, never surfacing the secret).
- **Provenance emission** of every acting verb to regista / agent-provenance.

**Out / non-goals:**
- **Not a secret store.** Vault remains the credential backend; `acb`'s `cred`
  provider is a *client*, never a vault. No secrets at rest in `acb`'s own state.
- **Not the browser runtime.** A remote Playwright/browser endpoint (k8s or
  otherwise) is a *backend* the `e2e` provider targets; `acb` does not host it.
- **Not an MCP-first design.** A per-harness MCP is exactly the fragility that
  caused the parity gap. `acb` is a CLI substrate; an MCP front is a possible
  *future option*, not the mechanism (see Design principles).
- **Not pipeline state.** Coordination/durable state is regista's job; `acb`
  emits *to* it and depends on it for nothing in its truth path.

## Design principles

- **One manifest, generated wiring.** Parity is maintained by reconciling each
  harness's config *from* the manifest, not by hand-syncing two files.
- **CLI substrate, thin per-harness shims.** Callable from any harness's shell
  with zero server wiring. (agent-notes already went MCP→CLI+skills and that won
  for cross-harness reuse; the opencode Playwright failure is the same MCP
  fragility, observed again.) An MCP *front* over the same core stays possible
  for harnesses that can't shell out — but it is not the default.
- **Two faces, one boundary.** The **read path** (`doctor`/inspect) is
  deterministic and read-only — no mutation, no secret ever surfaced. The **act
  path** (`reconcile`/`exec`) mutates configs and injects secrets: it is
  **dry-run by default**, backs up before writing, never clobbers an existing
  secret, and emits provenance on every action.
- **Inject, don't surface.** `acb exec cred:svc-bot -- ./script` injects the
  secret into the child process and never returns it to the model's context.
  `get` is an escape hatch, not the default.
- **Deterministic core, no AI in the truth path.** `doctor`'s verdicts are
  computed, not narrated. Any narration layer imports the core, never the reverse
  (enforced by an architecture test).

## Boundary with sibling tools

- **Vault / the self-hosted AppRoles** are the credential *backend*; `acb`'s `cred`
  provider authenticates to them (k8s auth → AppRole `.env` → `VAULT_TOKEN`) and
  brokers access. `acb` replaces the hand-placed `.env` *distribution*, not Vault.
- **regista / agent-provenance** receive `acb`'s provenance events; a brokered
  capability check-out becomes an attestable agent action. `acb` does not store
  state there in its truth path.
- **agent-notes / agent-wake** are siblings in the same agent-infra family
  (CLI + skills, provenance, stdlib core); `acb` follows the same conventions and
  composes with them, but owns a distinct concern — *capability parity*.

## Status

Charter stage (2026-06-15). The manifest schema, provider interface, harness
adapters, and the read-only `doctor` report are the first deliverable — see
`docs/capability-model.md` (design spine) and `plans/001-manifest-and-doctor.md`.
