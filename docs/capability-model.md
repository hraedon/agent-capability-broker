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

In a suite deployment (Plan 005), the manifest is the **suite's capability
contract**: one file declares every capability the estate's agents should have,
and `acb install-harness <name>` provisions each harness from it. The manifest
is resolved from the suite config dir (`$AGENT_SUITE_CONFIG` →
`~/.config/agent-suite/`) when present, ahead of the acb-private default
(`~/.config/acb/`). See `docs/capabilities.example.toml` for a committed
placeholder; a real estate manifest (pointing at real Vault paths) is
gitignored — it is a config, not an example.

```toml
# Example — placeholders only; never commit a real one.
[capability."cred:svc-bot"]
provider  = "cred"
source    = "suite"
refs      = { username = "vault:kv/example/ad/svc-bot/username", password = "vault:kv/example/ad/svc-bot/password" }
inject    = { username = "EXAMPLE_USERNAME", password = "EXAMPLE_PASSWORD" }
trusted_argv = ["/opt/example/bin/directory-check", "--validate"]
timeout_seconds = 120
harnesses = ["claude", "opencode"]

[capability."e2e:chromium"]
provider  = "e2e"
engine    = "playwright"
browser   = "chromium"
backend   = "local"                       # or "remote" + endpoint
harnesses = ["claude", "opencode"]

# WI-010: a vault-source capability with a declared naming contract. The
# fields inject as EXAMPLE_CONTROL_USERNAME / EXAMPLE_CONTROL_PASSWORD, so two
# [username, password] capabilities can compose in one checkout without
# colliding and without shadowing reserved names like USERNAME.
[capability."cred:example-control"]
provider   = "cred"
vault      = "kv/example/lab/control"
fields     = ["username", "password"]
env_prefix = "EXAMPLE_CONTROL"            # or inject = { username = "...", ... }
harnesses  = ["claude", "opencode"]
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
  short-lived temp file, and never writes the secret through ACB-controlled
  output. The suite child inherits stdout/stderr and remains a qualified trust
  boundary as described below.

First two providers:

- **`cred`** — AD/service-account credentials from the legacy Vault source or
  provider-neutral `source = "suite"`. Suite refs are explicit `vault:`,
  `azure:`, or `windows:` references resolved through the optional public
  `regista.secrets` facade. Doctor validates wiring and provider availability
  but never resolves a value. Suite execution additionally requires an absolute
  `trusted_argv` whose complete argv must match exactly before resolution. ACB
  supplies a minimal child environment and a bounded timeout. Auth for the legacy Vault source resolves inside
  the provider: in-cluster k8s auth → AppRole `.env` → `VAULT_TOKEN`. Because cred
  has no per-harness config artifact, discoverability has **two axes** (Plan 004):
  a cred is `ABSENT` in a harness until that harness exposes a command/skill shim
  surfacing `acb exec cred:<name>`, and once present, a read-only **broker
  reachability** check (token self-lookup — not a secret read, which would be a
  use) decides `PRESENT_OK` vs `PRESENT_BROKEN`. `plan_reconcile` renders the
  missing shim. The HTTP/Vault client and suite resolver are lazy optional
  extras; the core imports neither at module load.
- **`e2e`** — Playwright/browser capability. `inspect` checks the browser binary
  or remote endpoint is reachable and launchable headless. `plan_reconcile` for
  an `ABSENT`/`PRESENT_BROKEN` Chromium might be: install browser binaries, or
  replace the harness's fragile `npx`-launched MCP block with a wiring that points
  at an already-provisioned browser/endpoint.

## 6. Harness adapters

The closed manifest set recognizes `claude`, `opencode`, `codex`, and the
component-private `hermes` target. The Codex adapter (`CodexAdapter`, Plan 008
WI-3.1) is implemented for the cred provider: `acb install-harness codex`
renders `cred:<id>` discovery skills into `$CODEX_HOME/skills/<name>/SKILL.md`
(Codex's own `SKILL.md` format), create-only and preserving the user's config
and existing skills (including the reserved `.system` tree). The Codex e2e/MCP
write path is honestly `unsupported` (a named skip), not a false green.
`acb install-harness all` still expands only to the currently supported public
adapters, Claude and OpenCode: Codex joins `all` atomically after its live
interop proof (Plan 007 WI-3.1), not merely because its adapter exists. A
supported `--dry-run` exits 2 and keeps the same result schema; the aggregate is
a no-op only when both concrete records are installed no-ops.

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
- **codex** — reads `$CODEX_HOME/config.toml` (`[mcp_servers.*]`, via stdlib
  `tomllib`) and `$CODEX_HOME/skills/<name>/SKILL.md` skills; writes cred
  discovery skills only (create-only), never Codex config, auth, or the
  `.system` skill tree.

The MCP capability layer is read via `mcp_servers()`; `exposed_tools()`'s concrete
realization is `command_shims()` — the command/skill shim surface (opencode
`command/*.md`, Claude `skills/<name>/SKILL.md`) — reported by `acb shims`
(Plan 003). Rendering a *missing* shim into a harness is a future act-path slice.

Adapters must assume configs are **secret-bearing** (live bearer tokens, Vault
material). They may read freely for diffing; they may write only through the
gated act path, which backs the file up first and refuses to overwrite a secret
value already present.

## 7. The read/act boundary (the safety contract)

| | Read path | Act path |
|---|---|---|
| Verbs | `doctor`, `inspect` | `reconcile --apply`, `exec`, `apply` |
| Mutates config? | Never | Yes (backup-first, idempotent, no secret clobber) |
| Touches secrets? | Never surfaces them; reachability checks only | Injects into a qualified child; ACB does not emit values, but the child-output boundary applies |
| Determinism | Fully deterministic, no model calls | Deterministic actions; provenance-emitting |
| Default | — | **Dry-run** (`--apply` required to mutate) |

This boundary is the project's core safety property. The read path is as safe as
any lens sibling; the act path is where `acb` earns its "not read-only"
asterisk, and every rule on it exists to keep a brokered secret or a generated
config from doing harm or leaking.

### Suite child-output and checkout-receipt boundary

`source = "suite"` does not make an arbitrary child safe. ACB never writes the
resolved value to its own stdout/stderr, argv, error, or provenance, but the
qualified child receives it and inherits the operator's stdout/stderr. That
child can print, transform, or exfiltrate the value. Therefore the complete,
absolute `trusted_argv` is a deployment qualification boundary: use a reviewed
purpose-built executable, not a shell, interpreter, or general wrapper. Exact
value capture/redaction would be defense in depth only and cannot stop a
malicious transformation.

The qualified child receives `ACB_CHECKOUT_RECEIPT`, compact JSON with this
value-free shape:

```json
{
  "schema": "acb.checkout-receipt.v1",
  "invocation_id": "uuid",
  "issued_at": "UTC ISO-8601",
  "expires_at": "UTC ISO-8601",
  "checkouts": [
    {
      "capability_id": "cred:svc-bot",
      "fields": {"password": "EXAMPLE_PASSWORD", "username": "EXAMPLE_USERNAME"}
    }
  ]
}
```

This is parent-launch binding and provenance correlation metadata, not a
cryptographic authorization token. Nested receipt inheritance is refused on
every validated path.

### Injection naming and composed checkout (WI-010)

Every cred `exec` child receives an `ACB_CHECKOUT_RECEIPT`, not only the suite
source. How a field becomes a child env name:

1. an explicit `inject = { field = "ENV_NAME" }` entry wins;
2. else `env_prefix = "EXAMPLE_CONTROL"` names the field
   `EXAMPLE_CONTROL_FIELD`;
3. else the bare upper-cased field name (`username` → `USERNAME`).

Declaring `inject` or `env_prefix` opts the capability into the **strict
path**: names are validated, reserved names (`USERNAME`, `USER`, `PATH`,
`HOME`, … — a superset of the evidence-lab boundary's denylist) are refused,
collisions with the inherited environment or with other capabilities in the
same checkout are refused, and an inherited `ACB_CHECKOUT_RECEIPT` is refused —
all before any secret is resolved. Bare capabilities keep the historical
overwrite semantics so existing shims are unaffected; they still receive a
fresh single-capability receipt.

**Composed checkout** runs one command with several capabilities at once:

```
acb exec cred:example-control cred:example-guest -- <command> [args...]
```

All capabilities resolve from the invoking access plane (one `ACB_VAULT_ENV`),
inject under their declared names, and share a single receipt whose
`checkouts` array covers every capability in order. This replaces nested
`acb exec` shells that re-export values by hand — the pattern that moved
secret handling back into ad-hoc shell. Only non-suite cred capabilities
compose; the suite source keeps its dedicated exact-command trust model.
Per-capability access-plane routing at exec time (two planes in one composed
checkout) remains open.

The bounded runner owns a new POSIX session or Windows process group. On timeout
or interruption it terminates and reaps the tree: POSIX `killpg` TERM followed
by bounded KILL, or Windows `taskkill /PID /T /F` with direct-kill fallback.
Windows suite execution is disabled before resolution when `taskkill.exe` or the
process-group creation flag is unavailable. A deliberately detaching or
privilege-escaping child remains outside what stdlib containment can prove and
is another reason the exact child must be qualified.

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
