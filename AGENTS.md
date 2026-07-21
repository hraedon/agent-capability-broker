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
  model's context through ACB-controlled output. Agents log everything; a
  brokered secret in a transcript is a leaked secret. For `source = "suite"`,
  the exact manifest-qualified child inherits stdout/stderr and is itself part
  of the trust boundary; never substitute a shell, interpreter, or unreviewed
  wrapper. `get` exists as an escape hatch and must be explicit.
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

**`SUITE.lock` is a marker only (Plan 019 B2-generalize).** acb records the
released spine (regista) version in `SUITE.lock` `[spine]` so the umbrella
cross-repo lock-agreement check can include it — but acb does **not** install or
develop against regista in CI (regista is the optional, lazily-imported
`suite-secrets` extra, stubbed by a `FakeResolver` in tests). So there is no
`scripts/dev-install.py` here, unlike the faces and cairn. Keep `[spine].version`
in agreement with the umbrella; bump the `suite-secrets` floor in `pyproject.toml`
when the compatible range changes.

## Providers (the extension point)

A provider implements: `inspect` (read-only status for a capability×harness),
`plan_reconcile` (the dry-run action list), `apply` (one mutating action), and
`exec` (inject-and-run). First two:

- **`cred`** — brokers Vault-backed AD/service-account creds. Auth resolution
  *inside* the provider: in-cluster k8s auth → AppRole `.env` → `VAULT_TOKEN`.
  Least-privilege lives in Vault policy, not here. Discoverability (Plan 004): a
  cred is `ABSENT` in a harness until a command/skill shim surfaces `acb exec
  cred:<name>` there; `reconcile` renders it, broker reachability (token
  self-lookup) gives `PRESENT_OK`/`PRESENT_BROKEN`.
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

`codex` is part of the closed suite harness set. `install-harness codex` renders
cred discovery skills into `$CODEX_HOME/skills/<name>/SKILL.md` (Codex's own
skill format), backup-first and create-only — the `CodexAdapter` (Plan 008
WI-3.1). It stays **out of the stable `all` expansion** (Decision 2) until the
live interop proof (Plan 007 WI-3.1) lands; `CODEX_HOME`/`ACB_CODEX_HOME` select
the config root. Codex MCP writes (e2e provider) remain an honest `unsupported`
skip. Hermes remains a component-private explicit target and is not part of the
suite's stable `all` expansion.

Beyond the MCP capability layer, each adapter also reads its **command/skill shim
surface** (`command_shims()`): opencode `command/<name>.md` stems and Claude/Codex
`skills/<name>/SKILL.md` dirs (Codex's reserved `.system` tree is never
enumerated or written). `acb shims` reports that surface's parity across
harnesses (read-only, exits non-zero on a gap) — see `plans/003-shim-surface.md`.

## Boundary with sibling tools

`acb` brokers and reconciles *capabilities*; it does not store secrets (Vault
does), host browsers (a backend does), hold pipeline state (regista does), or
keep memory (agent-notes does). It **emits** provenance to regista /
agent-provenance and follows the family's CLI + skills conventions.

## Status

Charter stage (2026-06-15). Landed through Plan 005: manifest schema, provider
interface, harness adapters, and the verbs `doctor`, `shims`, `reconcile`,
`exec`, and `install-harness`. See `docs/capability-model.md` (design spine)
and `plans/001`–`plans/005`.
