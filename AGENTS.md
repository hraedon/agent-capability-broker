# AGENTS.md

Conventions and quick reference for agents (and humans) working on
agent-capability-broker (`acb`).

## What this is

A deterministic CLI that keeps agents at **capability parity across harnesses**.
It reads one declarative manifest of the capabilities an estate's agents should
have, and (a) **reports** how each harness measures up (`doctor`, read-only) and
(b) **reconciles** reality to the manifest and **brokers** capabilities into
child processes (`reconcile`, `exec` — acting, gated). See `README.md` for the
full charter.

`acb` is **not** purely read-only like the lens siblings — it mutates harness
configs and injects secrets. That makes the read/act boundary the single most
important rule here. Read the Hard rules.

## Orient

1. **Read the design spine.** `docs/capability-model.md` — the capability
   identifier scheme, manifest schema, provider interface, harness-adapter
   contract, the `Status` enum, and the read/act boundary. It dictates the data
   model and what each verb is allowed to do.
2. **Read the model** (once it exists). The dataclasses in
   `src/agent_capability_broker/model.py` are the concrete contract.
3. **Validate against reality.** Tests run `doctor` against synthetic harness
   configs in fixtures; a `samples`-marked path can diff against *copies* of real
   configs (gitignored) — never the live files in place.

## Hard rules

- **Read path is read-only; act path is gated.**
  - `doctor` / `inspect` never mutate a config and never surface a secret. They
    only read and diff. Deterministic, no model calls.
  - `reconcile` / `exec` / any `apply` mutate config or touch secrets. They are
    **dry-run by default** (`--apply` to act), **back up** a config before
    writing it, are **idempotent**, and **never clobber a secret already present**
    in a harness config (the config-no-clobber lesson from a sibling tool). Every
    acting verb **emits a provenance event**.
- **Inject, don't surface.** The default credential verb injects into the child
  process (env / short-lived temp file) and never returns the secret to the
  model's context. Agents log everything; a brokered secret in a transcript is a
  leaked secret. `get` exists as an escape hatch and must be explicit.
- **`acb` is a client, never a store.** No credential, token, or browser session
  is persisted in `acb`'s own state. Vault is the credential backend; a remote
  browser endpoint is the E2E backend. `acb` holds neither at rest.
- **No AI in the deterministic core.** `doctor`'s verdicts are computed with zero
  model calls. Narration is an optional layer that imports the core, never the
  reverse (enforce with an architecture test).
- **No secrets, tokens, or work-domain identifiers in committed files.** Real
  harness configs contain live bearer tokens and Vault paths — they live in a
  gitignored `samples/` and are **never** committed. Manifest examples, fixtures,
  and docs use neutral placeholders (`kv/example/ad/svc-bot`, `EXAMPLE.local`).
- **Fixtures are synthetic.** No real Vault paths, account names, domain names,
  tokens, or endpoints in committed test files.
- **Stdlib-only core.** Truth path uses `tomllib`, `json`, `subprocess`,
  `argparse` — no third-party deps. A Vault/HTTP client for the `cred` provider
  and any narration/web layers are optional extras that the core does not import.

## Build / test / lint (mirrors the sibling projects)

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/pytest -q             # unit + fixture tests (samples tests skip if samples/ absent)
.venv/bin/pytest -q -m samples  # diff against copies of real configs (needs samples/)
.venv/bin/ruff check .
.venv/bin/mypy src
```

## Providers (the extension point)

A provider implements: `inspect` (read-only status for a capability×harness),
`plan_reconcile` (the dry-run action list), `apply` (one mutating action), and
`exec` (inject-and-run). First two:

- **`cred`** — brokers Vault-backed AD/service-account creds. Auth resolution
  *inside* the provider: in-cluster k8s auth → AppRole `.env` → `VAULT_TOKEN`.
  Least-privilege lives in Vault policy, not here.
- **`e2e`** — provisions/locates a Playwright browser (local install or a remote
  endpoint) and exposes it to a harness without a fragile per-session `npx` MCP.

## Harness adapters

Each adapter reads and renders one harness's wiring:

- **claude** — `~/.claude/settings.json` (MCP servers, permissions) + the global
  skills dir.
- **opencode** — `~/.config/opencode/opencode.json` (`mcp` blocks, `command`
  shims).

Adapters must treat existing configs as **secret-bearing**: read for diffing,
write only via the gated act path (backup-first, no secret clobber).

## Boundary with sibling tools

`acb` brokers and reconciles *capabilities*; it does not store secrets (Vault
does), host browsers (a backend does), hold pipeline state (regista does), or
keep memory (agent-notes does). It **emits** provenance to regista /
agent-provenance and follows the family's CLI + skills conventions.

## Status

Charter stage (2026-06-15). First deliverable: manifest schema + provider
interface + harness adapters + read-only `doctor`. See
`plans/001-manifest-and-doctor.md`.
