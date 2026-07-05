# Plan 005 — Suite cohesion: capability provisioning as a bootstrap step

**Status:** Landed 2026-07-03 (commit 1eca849)
**Author:** Claude (Fable 5), from the 2026-07-02 agent-suite deployment review
**Strategic role:** acb keeps agents at capability + credential parity across
harnesses. In a suite deployment it is bootstrap step 5 (blueprint §2.3): after
the store, faces, and provenance are up, acb is what makes the agents able to
actually *do* the work — reach the AD service credentials, the browser, the search
backend — uniformly, whichever sanctioned harness they run in. This plan makes acb
a clean suite component: config-contract adoption, a doctor that conforms, and a
provisioning step a fresh machine can run. See `/projects/agent-suite-blueprint.md`
(Phase D, Tier 2).

## Ground truth at time of writing

- acb is public (`hraedon/agent-capability-broker`), `main` = origin, CI green on
  3.12/3.13; PRs #1–#11 merged. The credential half is in **live use** — the
  in-harness `cred-*` skills are acb's shims. `acb doctor` (read-only) probes each
  capability's declared access plane (WI-008); the act path is `reconcile`/`exec`.
- Config: `ACB_MANIFEST`, `ACB_VAULT_ENV`, `ACB_STATE_DIR`, `ACB_AGENT`,
  `ACB_CLAUDE_SETTINGS`, `ACB_OPENCODE_CONFIG` — all acb-private, resolved
  `$ACB_MANIFEST` → `~/.config/acb/capabilities.toml` → `./` (the WI-9 CWD fix).
- acb's `exec` is already attested via cairn's harness interception bound to the
  ambient work_item_id (memory) — the provenance composition is proven.
- acb deliberately does **not** merge into dossier/agent-notes (category-distinct);
  it is a capability broker, not a face. That boundary holds.
- Open: the e2e (browser/search) half is asserted-not-proven; the cred half is
  load-bearing.

## Principles this plan must hold

- **Read-only doctor, gated act.** Unchanged. `doctor` never mutates; `reconcile`/
  `exec` are the deliberate act path. Suite adoption adds surface, not new
  authority.
- **Secrets inject, never surface.** The `cred-*` shims inject into the child
  environment, never into stdout or an agent's context — the discipline stays
  exactly as shipped.
- **Adopt the shared facts where they overlap.** acb's config is mostly its own
  (manifest path, harness config paths) and stays `ACB_*`. Where acb needs the
  suite's Vault/secret location or the shared config dir, it reads
  `$AGENT_SUITE_CONFIG` conventions rather than a private path.

---

## Phase 1 — Suite config + doctor adoption

### WI-1.1 — Read the suite config dir; `acb doctor --json` conforms
- Resolve the manifest and Vault-env location honoring the suite convention
  (`$AGENT_SUITE_CONFIG` dir) ahead of the acb-private defaults, without breaking
  the existing precedence. Conform `acb doctor` to the suite health shape (regista
  Plan 025 WI-3.1): `{component:"acb", version, checks:[per-capability plane
  reachable, cred present, shim installed, …]}` — acb has no direct regista
  dependency, so its `regista` block is `{reachable:null}` (honestly absent, not
  faked).
- **AC:** `acb doctor --json` validates against the suite shape; the manifest
  resolves from the suite config dir when present; existing resolution still works;
  no capability over-claims a plane it can't reach (WI-008 behavior preserved).

## Phase 2 — Provisioning as a bootstrap step

### WI-2.1 — `acb install-harness` / `acb provision`
- One idempotent command that installs acb's shims into a named sanctioned harness
  and verifies each declared capability is reachable — the bootstrap step 5 form,
  sharing the `install-harness` idiom with agent-notes Plan 017 and cairn Plan
  008. Re-runnable; `--dry-run`; reports per-capability status.
- **AC:** on a clean profile, `install-harness claude` yields working `cred-*`
  shims and a green `doctor`; re-run is a no-op; a missing credential is a named,
  actionable status, not a silent skip.

### WI-2.2 — The capability manifest as a suite artifact
- Document the `capabilities.toml` as the suite's declarative capability source,
  with a committed **placeholder** example (real one gitignored — the inline-comment
  gotcha that once broke the ignore rule is already fixed; keep it fixed). A work
  deployment edits one manifest to declare the estate's capabilities.
- **AC:** the placeholder example is committed and the real manifest is ignored
  (verified); the identifier gate stays green; docs describe the one-manifest model
  as the suite's capability contract.

## Phase 3 — Cross-platform + secret backends

### WI-3.1 — Windows harness wiring; creds from the suite secret backend
- Ensure `install-harness` and the `cred-*` shims work on **Windows** (the
  harnesses run there too), not only Linux. Route credential sourcing through the
  suite secret backend (Vault/AKV/Windows — Plan 025 WI-1.2) rather than assuming a
  single `ACB_VAULT_ENV` file, so acb draws creds from the same store the rest of
  the suite uses. acb stays public (no publication gate needed).
- **AC:** `install-harness claude` yields working shims on a Windows profile and a
  Linux profile; a credential resolves from each configured backend (gated tests);
  the inject-don't-surface discipline holds on both OSes; existing `ACB_VAULT_ENV`
  still works as a fallback.

## Sequencing & notes

- **Harness note (2026-07-02, revised):** the *work deployment* is Claude-first, but
  the operator runs **both Claude and opencode locally**, so acb's cross-harness
  parity — its founding charter — stays **maintained, not dormant**: WI-2.1/WI-3.1
  support both harnesses and a dual-harness validation confirms the cohesion changes
  don't regress an existing opencode config. Both harnesses are testable locally, so
  this is cheap. Don't build *new* multi-harness features for the first deployment,
  but do keep the opencode paths green (blueprint §4).
- Tier 2 — the suite (Tier 0–1) is useful without acb, but acb is what makes
  multi-harness agents actually capable, so it's the first Tier-2 to land.
- Depends only lightly on regista Plan 025 (the doctor shape + config-dir
  convention); acb has no regista runtime dependency and should not grow one — it
  is deliberately the suite member that is *not* a regista client (a reason not to
  over-couple the suite; see the acb memory note).
- Coordinate `install-harness` with agent-notes 017 and cairn 008 so the suite
  ends with one wiring idiom, not three.
- Proving the e2e half (browser/search) is out of scope here (it's an acb product
  item, not a cohesion item) — flagged so the suite doctor reports the cred half
  as proven and the e2e half as asserted, honestly.
