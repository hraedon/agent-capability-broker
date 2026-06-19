# Plan 004 — `cred` discoverability (shim presence + broker reachability)

**Goal:** give the `cred` provider a real per-harness discoverability/parity story
so `acb doctor` reports it and `acb reconcile` can fix it — closing **WI-007**.

Today `CredProvider.inspect` returns `UNKNOWN` unconditionally and
`plan_reconcile`/`apply` are no-ops. So a credential is usable only because an
agent can shell out to `acb exec cred:<name>` — a harness-agnostic path with **no
discovery surface and no doctor verdict**. `cred` is a second-class capability the
headline parity report can't see.

## The model (decided 2026-06-19)

`cred` has no per-harness *config* artifact (no MCP block to read), so its
per-harness signal is the **command/skill shim surface** built in Plan 003. A
`cred` capability is *discoverable* in a harness iff that harness exposes a shim
that surfaces `acb exec cred:<name>`. Layered with **broker reachability**:

| Condition | Status |
|---|---|
| No shim for the cap in this harness | `ABSENT` (agent can't discover it) |
| Shim present, broker reachable | `PRESENT_OK` |
| Shim present, broker unreachable | `PRESENT_BROKEN` |
| Shim present, reachability not checkable (no `[cred]` extra / no Vault env) | `UNKNOWN` (honest) |

This **extends spine §5** (which described cred `inspect` as reachability-only):
reachability is still the `PRESENT_OK` vs `PRESENT_BROKEN` axis, but shim presence
is the `ABSENT` axis that actually expresses per-harness parity.

Shim name derives from the capability: `cred:svc-bot` → `cred-svc-bot`, overridable
via `options.shim`. The rendered shim contains **no secret** — only the capability
id and the `acb exec` invocation pattern, plus the inject-don't-surface rule.

## Deliverables

### WI-1 — Broker reachability (read-only, optional extra)
- `cred_vault.reachable(cap) -> bool`: **token self-lookup only** (`is_authenticated`),
  never a secret read; raises when no `[cred]` extra / no `VAULT_ADDR` so the
  provider maps it to `UNKNOWN`. Read-only and side-effect-free (spine §4).
- `source = "env"` creds report reachability as "is `from_env` set" (no Vault).

### WI-2 — `CredProvider.inspect`
- Compute shim presence via `adapter.command_shims()` (Plan 003) and reachability
  per the table above. Best-effort: any reachability error → `UNKNOWN`, never a
  crash or a hang that breaks `doctor`.

### WI-3 — `plan_reconcile` + `apply` (render the shim; gated act path)
- `ABSENT` → `add_cred_shim` action carrying the rendered markdown; `apply` writes
  it to the harness's shim dir (opencode `command/<name>.md`, Claude
  `skills/<name>/SKILL.md`). Idempotent (skip if the shim already exists — never
  clobber a hand-edited shim), provenance-emitting, dry-run by default.
- `PRESENT_BROKEN` (broker unreachable) → a `manual` action: it's an infra/auth
  problem, not something a config write fixes.
- Adapters gain `write_command_shim` / `write_skill_shim` (create-only; refuse to
  overwrite an existing file — callers guard for idempotence, mirroring `add_mcp`).

### WI-4 — Tests + guards
- Shim-name derivation (default + `options.shim`), the four inspect verdicts
  (reachability injected/monkeypatched — no live Vault), the render output
  (Claude has `name:`, opencode doesn't; both carry `acb exec cred:<id>`; valid
  YAML frontmatter), reconcile render + idempotent re-apply, provenance carries no
  secret. CLI end-to-end with `source = "env"`: `doctor` ABSENT → exit 1, then
  `reconcile --apply` renders the shim → `doctor` `PRESENT_OK` → exit 0.
- Arch/safety guards stay green (core stdlib-only; render is pure strings; the
  Vault client stays in the lazy `cred_vault` extra).

## Out of scope / noted
- **Re-rendering a stale shim.** `apply` only *creates* a missing shim; updating an
  existing-but-outdated shim's body is deferred (avoids clobbering hand edits).
- **Reachability cost.** A Vault auth per `doctor` row is acceptable for now; cache
  per (addr, auth) if cred capabilities multiply.
- WI-006 (multi-field binds) is orthogonal and still open.

## Definition of done
- CI green on 3.12 + 3.13.
- On this host, after adding a `cred:*` capability listing both harnesses to a
  (gitignored) manifest, `acb doctor` reports `ABSENT` where no shim exists and
  `acb reconcile --apply` renders a working discovery shim into that harness.
