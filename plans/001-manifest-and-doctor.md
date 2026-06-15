# Plan 001 — Manifest, provider interface, and read-only `doctor`

**Goal:** turn the design spine (`docs/capability-model.md`) into a buildable,
CI-green skeleton whose first *useful* output is `acb doctor` — the read-only
parity report across Claude Code and opencode. The act path (`reconcile`,
`exec`) is designed-for but stubbed; it lands in Plan 002 so the safety-critical
mutating code gets its own focused review.

**Why doctor first:** it is the read-only, deterministic, lowest-risk slice that
already delivers the headline value — *"opencode thinks it has Playwright but it's
broken; Claude doesn't expose it at all."* It needs no secret handling and no
config writes, so it de-risks the data model before any mutation lands.

## Deliverables

### WI-1 — Buildable skeleton
- `pyproject.toml` (stdlib-only core, `[dev]` ruff/mypy/pytest, console-script
  `acb`), `src/agent_capability_broker/`, MIT `LICENSE`, `.gitignore`,
  `.github/` CI on 3.12 + 3.13.
- `acb --help` and `acb doctor --help` run after `pip install -e ".[dev]"`.

### WI-2 — Manifest + model (`model.py`)
- `tomllib` parse of `capabilities.toml` into `Capability` dataclasses.
- `Status` enum (§4 of the spine). `WiringState`, `Action`, `ActionResult`,
  `WiringFragment` dataclasses.
- Validation: unknown `provider`, missing `harnesses`, duplicate keys → clear
  errors. The core validates only `provider` + `harnesses`; provider-specific
  keys are validated by the provider.

### WI-3 — Provider interface + two providers (inspect-only for this plan)
- `Provider` protocol with all four methods; `plan_reconcile`/`apply`/`exec`
  may raise `NotImplementedError` this plan (Plan 002 fills them).
- `cred` provider `inspect`: resolve auth (k8s → AppRole `.env` → `VAULT_TOKEN`),
  do a **token self-lookup only** (no secret read) for reachability, combine with
  adapter wiring → `Status`. The Vault client is an optional `[cred]` extra; when
  absent, `inspect` returns `UNKNOWN` with a reason, never crashes.
- `e2e` provider `inspect`: detect the browser binary / remote endpoint and a
  headless launch-and-close reachability check → distinguish `PRESENT_OK` from
  `PRESENT_BROKEN` (e.g. opencode's MCP block present but `npx` launch fails).

### WI-4 — Harness adapters (read side)
- `claude` adapter: parse `~/.claude/settings.json` + skills dir →
  `current_wiring` / `exposed_tools`.
- `opencode` adapter: parse `~/.config/opencode/opencode.json` (`mcp`,
  `command`) → same. Must correctly read the real-world `mcp.playwright` block
  shape (`npx @playwright/mcp@latest`).
- Adapters are **read-only in this plan**; `write_wiring` raises until Plan 002.

### WI-5 — `acb doctor`
- For each capability × listed harness, compute `Status` and print a matrix
  (human table + `--json`). Exit non-zero if any capability is `PRESENT_BROKEN`
  or `ABSENT` (so it's CI/cron-usable as a parity gate).
- No mutation, no secret surfaced — verifiable by the architecture/safety test.

### WI-6 — Tests + guards
- Synthetic fixtures: a `claude/settings.json` and an `opencode/opencode.json`
  (placeholder tokens) exercising each `Status`, incl. the broken-Playwright case.
- **Architecture test:** the core (`model`, providers' inspect path, adapters'
  read path) imports no third-party package and no narration/web layer.
- **Safety test:** `doctor`/`inspect` perform no file writes and emit no secret
  to stdout (assert against a tmp config tree + captured output).
- `samples`-marked test: diff against *copies* of real configs if `samples/`
  present; skipped otherwise.

## Explicitly deferred to Plan 002 (the act path)
- `reconcile` (render + write wiring, dry-run default, `--apply`, backup-first,
  no-secret-clobber), `exec` (inject-and-run), `apply`, provenance emission to
  regista. These mutate state and handle secrets and deserve their own review.

## Definition of done
- CI green on 3.12 + 3.13 (push the branch and watch CI; do not trust local
  green that reads generated artifacts).
- `acb doctor` run against this host's real Claude + opencode configs (copied
  into `samples/`) correctly reports the live Playwright asymmetry.
- `docs/capability-model.md` §9 open questions resolved or carried into Plan 002
  with rationale.

## Validation note
This host is itself the first realistic fixture: opencode's `opencode.json` has a
`mcp.playwright` block (`npx -y @playwright/mcp@latest`) and Claude's config has
no Playwright exposure, while `~/.cache/ms-playwright` holds installed Chromium.
`doctor` should yield `e2e:chromium` = `PRESENT_BROKEN` (opencode) / `ABSENT`
(claude) against `PRESENT_OK`-capable browsers. Use copies under `samples/`,
never the live files.
