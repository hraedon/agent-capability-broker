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
  (`$ACB_STATE_DIR` or XDG default). This is acb's own provenance of internal
  detail; a direct regista forwarder (WI-5) was **superseded** — cairn's harness
  interception already attests `acb exec` to regista (see WI-5 below). Events carry
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

## WI-5 — Provenance forwarder to regista / agent-provenance — SUPERSEDED (2026-06-22)
- Original intent: forward the local JSONL events to a regista sink, turning a
  credential check-out / config reconcile into an attestable agent action.
- **Superseded — a direct acb→regista forwarder is the wrong abstraction.**
  agent-provenance (cairn) Plans 002/004 already intercept *every tool call* in a
  session via PreToolUse/PostToolUse and log it to regista, bound to the session's
  ambient `work_item_id`. An `acb exec cred:X -- <cmd>` invocation **is** a tool
  call: cairn captures "agent ran `acb exec cred:X` against work-item Y at time T"
  for free, and sees only the command line — never the secret (inject-don't-surface
  holds; the secret lives in the child's env, not the argv). So the attestable fact
  already reaches regista without acb being a direct client.
- **Why not build it anyway:** the only way a standalone forwarder works is a
  *work-item-less* event grain in regista, and regista's core invariants all assume
  `work_item_id` (signing envelope requires it; the hash-chain linkage; the
  `work_item_id` pagination cursor; the per-work-item-row concurrency lock).
  Forcing that grain in is high blast-radius core churn for a consumer that should
  not be a direct regista client. Verified 2026-06-22: regista has no such grain
  and no WI tracking one.
- **What remains true:** acb's local append-only JSONL provenance stays — it carries
  acb-*internal* detail a harness hook can't see (which fields were injected, the
  reconcile backup path). It is complementary to cairn's tool-call attestation, not
  a feed into regista.
- **Optional follow-up (nice-to-have, not a blocker):** have cairn recognize the
  `acb exec cred:*` argv shape and emit a structured `capability_checkout` payload
  rather than a generic `tool_call` — a richer attestation, owned by agent-provenance.

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
