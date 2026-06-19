# Plan 003 — The command-shim surface (read side)

**Goal:** complete the documented-but-unbuilt half of the harness-adapter
contract — the **command/skill shim surface** (`exposed_tools` in spine §6) — and
give it a read-only consumer that reports *shim parity* across harnesses.

So far `acb` reasons about the **MCP capability layer** (`cred`, `e2e`) via each
adapter's `mcp_servers()`. But the family's "CLI + skills" tooling — `start`,
`end`, `file-breadcrumb`, … — is surfaced differently per harness: as **Claude
skills** (`~/.claude/skills/<name>/SKILL.md`) and as **opencode commands**
(`~/.config/opencode/command/<name>.md`). That surface drifts by hand, the same
"capability present, access uneven" shape this tool exists to flag — one layer
down from MCP. This plan reads that surface and reports its parity.

**Why read-only and self-contained:** like `doctor`, this is the deterministic,
secret-free, lowest-risk slice. It adds no mutation (rendering/installing a
missing shim is a *later* act-path slice, explicitly deferred below), so it
de-risks the shim data model before any write lands.

## Motivating finding (this host)

Claude exposes **10** shims; opencode exposes **11** — the same 10 **plus
`cert-watch-e2e`**, which has no Claude-skill counterpart. A real, live parity
gap on the tooling layer that the MCP-only `doctor` cannot see.

## Deliverables

### WI-1 — Adapter shim read side
- `HarnessAdapter.command_shims() -> set[str]`: the names of the command/skill
  shims a harness advertises. Read-only; no secret material (shim bodies are not
  read, only their names enumerated).
  - **opencode:** `<config-dir>/command/*.md` → file stems.
  - **claude:** `<settings-dir>/skills/<name>/SKILL.md` → the `<name>` dirs that
    actually contain a `SKILL.md` (a bare dir is not an exposed skill).
- `shims_path` derives from each adapter's existing config path's parent, so a
  test that points an adapter at a tmp config tree gets a tmp shim dir for free —
  no new env var. A missing shim dir yields `set()`, never an error.

### WI-2 — `acb shims` (read-only parity report)
- Enumerate the shim surface for every harness whose shim dir exists; print a
  matrix (`* present / - absent`) and a `--json` form, mirroring `doctor`.
- **Parity gate:** exit non-zero when a participating harness is missing a shim
  another participating harness has (cron/CI-usable). Fewer than two
  participating harnesses → nothing to compare → exit 0.
- Pure parity helper (`_shim_gap`) computes the asymmetric set so the logic is
  unit-testable apart from I/O.

### WI-3 — Tests + guards
- Synthetic shim trees (tmp `command/` and `skills/`) exercise: opencode stems,
  claude `SKILL.md`-gated dirs (bare dir and stray file ignored), empty/missing
  dir, the asymmetric-gap case, and the symmetric (exit 0) case.
- `acb shims` end-to-end via `main()` over env-pointed tmp trees: asserts the gap
  shim is named, the exit code, **and that the tree is unmodified** (read path).
- Existing arch/safety guards stay green (stdlib-only; no write, no secret).

## Explicitly deferred (a later act-path slice)
- **Rendering / installing** a missing shim (e.g. generate the absent Claude
  skill from the opencode command, or vice versa). That mutates a harness's
  tooling tree and belongs on the gated act path (backup-first, idempotent,
  provenance) — same boundary as `reconcile`. `shims` only *reports* for now.
- A unified `exposed_tools()` that unions the MCP and shim surfaces; add it when a
  consumer needs the combined view. `command_shims()` is the concrete realization
  of the spine's shim half today.

## Definition of done
- CI green on 3.12 + 3.13 (push the branch and watch CI; do not trust local green).
- `acb shims` run against this host's real Claude + opencode trees reports the
  live `cert-watch-e2e` asymmetry and exits non-zero.
