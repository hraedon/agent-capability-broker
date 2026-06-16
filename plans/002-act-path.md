# Plan 002 — The act path (reconcile, exec, provenance)

**Goal:** turn `doctor`'s findings into safe, gated *action*. This is where `acb`
stops being read-only, so every work item here is bound by the read/act safety
contract (spine §7): dry-run by default, backup-first, idempotent, never clobber
an existing secret, emit provenance on every act.

The work is ordered by **secret-handling risk**, lowest first, so the riskiest
code (credential injection) lands last with the most surrounding machinery
already proven.

## WI-1 — Action model + local provenance sink (foundation)
- `Action` (declarative: capability, harness, kind, target, summary, payload) and
  `ActionResult` (status: applied | skipped | failed, detail, backup_path).
  Declarative so the dry-run plan and the provenance record are the same object.
- `provenance.emit(event)` — append-only JSONL to a local state dir
  (`$ACB_STATE_DIR` or XDG default). This is the always-available fallback sink;
  the regista/agent-provenance forwarder is WI-5. Events carry
  `{ts, agent, capability, harness, action, target, result}` — **never** a secret
  value or a config token.

## WI-2 — `e2e reconcile` (no secrets; fixes the live finding) ← first slice
- `E2eProvider.plan_reconcile`: for a `PRESENT_BROKEN` Playwright server whose
  launcher is a floating `npx` tag, emit a `pin_npx_version` action that rewrites
  the dist-tag to `options.pin` (or, if `backend = "remote"`, a `point_endpoint`
  action). `PRESENT_OK` → `[]` (idempotent). Cases without a safe automatic fix
  (no browsers, fully `ABSENT`) → a `manual` action that the dry-run prints and
  `--apply` skips with a reason.
- `OpencodeAdapter.write_command(server, argv)`: surgical edit — load, mutate
  only that server's `command`, **back up first**, idempotent no-op when already
  equal, re-serialize preserving every other key (the sibling server's bearer
  token survives untouched). This is the write side's safety proof.
- `acb reconcile [-m manifest] [--apply]`: dry-run prints the plan; `--apply`
  executes, emits provenance per action, prints results. Exit non-zero if any
  planned action remains unapplied.

## WI-3 — `e2e` ABSENT → add wiring; browser provisioning
- `add_mcp` action for an `ABSENT` capability (e.g. expose Playwright to Claude),
  rendered from the manifest, pointing at a pinned package / provisioned browser.
- `install_browsers` action (or a clear manual instruction) when binaries are
  missing. Keep provisioning explicit and idempotent.

## WI-4 — `cred exec` (inject-don't-surface; highest secret risk)
- `CredProvider`: resolve auth inside the provider (k8s → AppRole `.env` →
  `VAULT_TOKEN`); `inspect` does a **token self-lookup only** (no secret read).
- `acb exec cred:<name> -- <cmd…>`: fetch the secret, inject into the child via
  env / a short-lived `0600` temp file, run, scrub. **Never** returns the secret
  to stdout or the model context. `get` is an explicit, warned escape hatch.
- The `[cred]` extra (hvac) gates this; absent it, `exec` errors cleanly.

## WI-5 — Provenance forwarder to regista / agent-provenance — DEFERRED (2026-06-15)
- Forward the local JSONL events to the regista sink when reachable; the local
  log stays the source of truth so an act never blocks on the sink being up.
  Turns a credential check-out / config reconcile into an attestable agent action.
- **Deferred by decision (2026-06-15).** regista's `append_event` is
  *work-item-scoped*: an event must attach to an existing `work_item_id` under a
  workflow, with a DSN. Mapping a cred-checkout / reconcile onto that model is a
  real coupling decision (which workflow? a per-host/session work item?), and is
  really an agent-provenance design question — not a mechanical forward. The
  local append-only JSONL provenance is functional in the meantime.
- **Revisit trigger:** a defined "capability" / agent-action workflow exists in
  regista or agent-provenance to attach these events to. Until then, parked.

## Safety invariants (apply to every WI)
- **Dry-run is the default.** Mutation requires `--apply`.
- **Backup before write.** Timestamped `.bak-<ts>` beside the file; never
  in-place without one.
- **Idempotent.** Re-running a satisfied action is a no-op, not a second edit.
- **No secret clobber.** A write may never replace a non-empty secret-bearing
  value; edits are surgical to the targeted field. Proven by a test that a
  token-bearing sibling config survives a reconcile byte-for-byte in value.
- **No secret surfaced.** Neither stdout, the dry-run plan, nor a provenance
  event ever contains a credential or a config token.

## Definition of done (per slice; push branch + watch CI)
- WI-2 first: `acb reconcile --apply` against a *copy* of this host's
  opencode.json rewrites `@playwright/mcp@latest` → a pinned version, leaving the
  a sibling server's bearer token intact, and a re-run is a no-op. CI green 3.12+3.13.
