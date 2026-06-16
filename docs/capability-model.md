# Capability model (design spine)

This document dictates `acb`'s data model and what each verb may do. Everything
else — the CLI, the providers, the adapters — is an implementation of the
contract defined here. Read this before the code.

## 1. The core idea

A **capability** is something an agent can do that depends on environment
provisioning rather than on the agent itself: bind to AD with a service account,
drive a browser for end-to-end testing, reach a web-search backend. A capability
can be *present and working*, *present but broken*, or *absent* in a given
harness on a given host — independently of whether the underlying resource (the
Vault secret, the installed browser) exists at all.

Parity is the property that the **same set** of capabilities is present-and-
working across every harness an estate runs. `acb` maintains it by reconciling
each harness against one declarative manifest.

## 2. Identifiers

A capability is named `provider:name`:

- `cred:svc-bot` — a service-account credential, via the `cred` provider.
- `e2e:chromium` — a Chromium browser for E2E, via the `e2e` provider.

`provider` selects the implementation; `name` is unique within a provider and is
the manifest key. Identifiers are opaque strings — no work-domain meaning is
encoded in committed examples (`cred:svc-bot`, not a real account name).

## 3. The manifest — `capabilities.toml`

The single declarative source of the **desired** capability set for a host or
estate. Stdlib `tomllib` parses it; there is no other source of truth.

```toml
# Example — placeholders only; never commit a real one.
[capability."cred:svc-bot"]
provider  = "cred"
vault     = "kv/example/ad/svc-bot"      # path, not a secret; example value
field     = "password"
harnesses = ["claude", "opencode"]

[capability."e2e:chromium"]
provider  = "e2e"
engine    = "playwright"
browser   = "chromium"
backend   = "local"                       # or "remote" + endpoint
harnesses = ["claude", "opencode"]
```

- `harnesses` lists which harnesses *should* expose this capability. `doctor`
  reports a capability as `NOT_APPLICABLE` for harnesses not listed.
- Provider-specific keys (`vault`, `field`, `engine`, `backend`, …) are validated
  by the provider, not the core. The core only understands `provider` and
  `harnesses`.
- The manifest contains **no secrets** — only references (a Vault path, a browser
  engine). It is safe to commit *as an example with placeholders*; a real estate
  manifest pointing at real Vault paths is treated like a config and gitignored.

## 4. Status

`doctor` and `inspect` classify each capability × harness into exactly one:

| Status | Meaning |
|---|---|
| `PRESENT_OK` | Wired in the harness *and* the underlying resource is reachable/working. |
| `PRESENT_BROKEN` | Wired but non-functional — the Playwright-MCP-that-won't-start case. The most valuable signal: the harness *thinks* it has the capability. |
| `ABSENT` | Listed in the manifest for this harness, but not wired. |
| `NOT_APPLICABLE` | Not listed for this harness. |
| `UNKNOWN` | Provider could not determine status (e.g. resource probe disabled). |

`PRESENT_OK` vs `PRESENT_BROKEN` is the distinction that makes `doctor` worth
more than reading a config file: it requires a *reachability check*, not just a
wiring check. Reachability checks must be **read-only and side-effect-free** (a
browser launch-and-close, a Vault token self-lookup — never an enrollment, never
a credential *use* against a live target). This is the family's "flag, don't
probe" rule applied to the read path.

## 5. Provider interface

A provider is the unit of extension. It implements four operations; the first two
are read-only, the last two act.

```
inspect(cap, harness, adapter)        -> Status        # read-only
plan_reconcile(cap, harness, adapter) -> list[Action]  # read-only (dry-run plan)
apply(action)                         -> ActionResult  # MUTATES; emits provenance
exec(cap, argv)                       -> int           # injects secret; emits provenance
```

- `inspect` combines what the **adapter** reports about wiring with the
  provider's own **reachability** check to produce a `Status`.
- `plan_reconcile` returns the ordered `Action`s that would move a capability
  from its current status toward `PRESENT_OK` — *without performing them*. This is
  what `acb reconcile` prints by default.
- `apply` performs one `Action`. Only reached under `--apply`. Backs up any
  config it writes, is idempotent, never overwrites an existing secret, and emits
  a provenance event.
- `exec` resolves the capability (e.g. fetches a credential, locates a browser
  endpoint), launches `argv` with it injected into the child's environment /a
  short-lived temp file, and **never returns the secret to the caller's stdout or
  the model's context**.

First two providers:

- **`cred`** — Vault-backed AD/service-account credentials. Auth resolves inside
  the provider: in-cluster k8s auth → AppRole `.env` → `VAULT_TOKEN`. `inspect`
  checks the harness can *reach* the broker (token self-lookup), not that a
  specific secret is readable (that would be a use). The HTTP/Vault client is an
  optional extra; the core never imports it.
- **`e2e`** — Playwright/browser capability. `inspect` checks the browser binary
  or remote endpoint is reachable and launchable headless. `plan_reconcile` for
  an `ABSENT`/`PRESENT_BROKEN` Chromium might be: install browser binaries, or
  replace the harness's fragile `npx`-launched MCP block with a wiring that points
  at an already-provisioned browser/endpoint.

## 6. Harness adapters

An adapter encapsulates one harness's config format and capability surface:

```
current_wiring(cap)  -> WiringState | None   # how (if at all) the harness exposes cap today
render_wiring(cap)   -> WiringFragment        # what the manifest says it should be
write_wiring(frag)   -> None                  # MUTATES; backup-first, secret-preserving
exposed_tools()      -> set[str]              # what the harness currently advertises
```

- **claude** — reads `~/.claude/settings.json` (MCP servers, permissions) and the
  global skills directory.
- **opencode** — reads `~/.config/opencode/opencode.json` (`mcp` blocks,
  `command` shims).

Adapters must assume configs are **secret-bearing** (live bearer tokens, Vault
material). They may read freely for diffing; they may write only through the
gated act path, which backs the file up first and refuses to overwrite a secret
value already present.

## 7. The read/act boundary (the safety contract)

| | Read path | Act path |
|---|---|---|
| Verbs | `doctor`, `inspect` | `reconcile --apply`, `exec`, `apply` |
| Mutates config? | Never | Yes (backup-first, idempotent, no secret clobber) |
| Touches secrets? | Never surfaces them; reachability checks only | Injects into child; never to stdout/model context |
| Determinism | Fully deterministic, no model calls | Deterministic actions; provenance-emitting |
| Default | — | **Dry-run** (`--apply` required to mutate) |

This boundary is the project's core safety property. The read path is as safe as
any lens sibling; the act path is where `acb` earns its "not read-only"
asterisk, and every rule on it exists to keep a brokered secret or a generated
config from doing harm or leaking.

## 8. Provenance

Every act-path verb emits an event — `{agent, capability, harness, action, when,
purpose}` — to regista / agent-provenance. A credential check-out or a config
reconcile becomes an *attestable agent action*, which is the workplace's actual
audit gap. Provenance emission is an optional integration: if the sink is
unreachable the act still completes and the event is queued/logged locally; the
core never depends on regista being up.

## 9. Open questions (resolve during plan 001)

- **Reachability probes vs. side effects.** Where exactly is the line for a
  read-only `inspect` of `cred` — token self-lookup only, or a no-op
  capability-check that risks looking like a use? Lean strict: self-lookup only.
- **Remote browser endpoint shape.** WebSocket CDP endpoint vs. a hosted
  `@playwright/mcp`? The endpoint is a backend either way; decide the `e2e`
  provider's target contract.
- **Manifest scope.** One global manifest, or per-estate + host overlays? Start
  with one file; add overlays only if a second estate appears.
