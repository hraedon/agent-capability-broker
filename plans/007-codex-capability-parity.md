# Plan 007 — Codex capability parity

**Status:** Proposed 2026-07-10.
**Author:** GPT-5.6 Sol, from the suite Codex integration audit.
**Strategic role:** Extend acb's deterministic inspect/plan/apply/exec contract
to local Codex without turning acb into a Codex config manager or secret store.

## Ground truth

- acb currently recognizes Claude, OpenCode, and Hermes. Claude/OpenCode expose
  normalized MCP and command-shim surfaces through adapters.
- Codex uses TOML configuration for MCP and shared
  `.agents/skills/<name>/SKILL.md` skills.
- Python's stdlib can parse TOML but cannot safely round-trip arbitrary TOML
  while preserving comments and formatting.
- The Codex CLI owns supported MCP mutation commands. acb can inspect first,
  back up, invoke the supported command, then verify the normalized result.
- Existing provider semantics remain valid: credentials are injected only into
  `acb exec` children; e2e is a capability, not an assumption that every
  Codex installation has a browser.
- Plugins are a distribution surface, not automatically an acb provider. This
  plan does not conflate plugin inventory with MCP/skill parity.

References:

- https://learn.chatgpt.com/docs/customization/overview
- https://learn.chatgpt.com/docs/config-file/config-reference

## Decisions

1. Add a `CodexAdapter` implementing the existing normalized adapter contract.
2. Read `$CODEX_HOME/config.toml` with `tomllib`; never surface env values,
   headers, tokens, or unrelated config.
3. Prove the supported `codex mcp` CLI's targeted mutation behavior before
   adopting it. If it preserves unrelated bytes/values, use it after backup and
   no-clobber checks. Otherwise append only a new, absent top-level MCP table
   after full parse/duplicate validation. Never serialize the whole TOML
   document.
4. Install capability shims as canonical skills under
   `$HOME/.agents/skills`.
5. Preserve dry-run-by-default, explicit apply, backup-first, idempotency,
   provenance emission, and no-secret-clobber.
6. Treat Codex Browser Use or bundled plugins as separately discoverable
   capabilities only after their stable machine-readable surface is specified.

## Phase 1 — Adapter and model

### WI-1.1 — Recognize Codex

Add `codex` to the closed harness set, adapter dispatch, CLI validation,
manifest schema/examples, and exhaustive tests.

**AC:** manifests accept Codex, reject unknown targets, and every closed dispatch
uses an explicit Codex case.

### WI-1.2 — Read-only Codex adapter

Normalize Codex MCP servers and shared skill shims. Add injectable config,
skills, binary, and command-runner paths for tests.

**AC:**

- `doctor` and `inspect` detect local/remote MCP entries, enabled state, and
  skill names.
- Secret-bearing MCP fields are neither returned nor logged.
- Missing/corrupt config becomes a named status without mutation.
- Read paths produce byte-identical files.

### WI-1.3 — Honest availability

Distinguish binary absent, config absent/fresh profile, config unreadable, and
available.

**AC:** a fresh Codex install can be planned for; an unreadable config fails
closed; absence is not mislabeled as a broken capability.

Also close the existing generic false-success edge: a specifically requested
unavailable harness that verifies as `UNKNOWN` must not return exit zero.

## Phase 2 — Reconciliation

### WI-2.1 — Skill shim install

Render cred/e2e command shims as Codex skills using the same canonical shim
intent and Codex-compatible frontmatter.

**AC:**

- `acb install-harness codex --dry-run` reports exact paths.
- Apply creates only absent owned skills; re-run is a no-op.
- Existing hand-authored same-name skills are preserved and reported as
  conflicts.
- Uninstall/rollback behavior follows an ownership manifest and hash checks.
  **Landed 2026-07-17:** `install-harness --uninstall` removes acb-owned shims
  and MCP wiring via an exact content match (hash check). A marker-bearing shim
  whose content has changed is preserved (user edits are never destroyed).
  Works across all harnesses (claude, opencode, codex, hermes). MCP server
  removals back up config first; emits provenance.

### WI-2.2 — Safe MCP server addition

Implement add for an absent server using the proven surgical method from
Decision 3. Back up config before mutation, refuse existing same-name servers
unless the normalized entry is already equal, and verify after mutation.
Existing floating/pinned entries that cannot be changed surgically become named
manual actions rather than whole-file rewrites.

**AC:**

- Comments, ordering, profiles, hooks, model settings, and unrelated MCP
  entries survive byte-for-byte except for the Codex CLI's own targeted edit.
- Command failure restores the backup when safe and produces no success
  provenance event.
- Verification mismatch is a hard failure.
- Tests use a fake runner and include token-bearing unrelated entries.
- A proof fixture records whether the current Codex CLI is safe for the chosen
  mutation path; the implementation does not assume it.

### WI-2.3 — Brokered execution

Exercise `acb exec` from a Codex skill for cred and e2e providers.

**AC:** the child receives only requested injected values; no secret appears in
doctor JSON, plan output, provenance, or skill text.

## Phase 3 — Parity and proof

### WI-3.1 — Shim parity

Extend `acb shims` to include Codex with an explicit requested-target set so
an uninstalled optional harness does not create a false estate-wide failure.

**AC:** missing/stale Codex skills are named and parity comparisons remain
deterministic.

### WI-3.2 — Local end-to-end proof

From an isolated Codex home, install one synthetic credential capability and
one local-browser capability, invoke both through Codex, and remove the wiring.

**AC:** doctor transitions absent → present_ok → absent, existing config
survives, and cairn captures the `acb exec` call when provenance is enabled.

### WI-3.3 — Documentation

Document config/skill locations, supported MCP operations, backup and conflict
semantics, sandbox/network expectations, and local-vs-cloud scope.

## Out of scope

- General Codex configuration editing.
- Installing arbitrary Codex plugins or changing workspace policy.
- Surfacing credentials to model context.
- Claiming parity for hosted Codex tasks without a proven deployment contract.
- Treating plugins, skills, MCP, or Codex itself as new providers. Providers
  remain `cred` and `e2e`; plugins are distribution bundles.
