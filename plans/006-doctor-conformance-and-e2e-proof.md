# Plan 006 — Doctor conformance + proving the e2e half

**Status:** Proposed 2026-07-07.
**Author:** Claude (Fable 5), from the 2026-07-07 suite v2 gaps review
**Strategic role:** Two truths surfaced in the v2 review. First, acb's `doctor
--json` does not conform to the suite health contract — it emits no top-level
`ok`, so the suite umbrella classifies acb **failed** on a box where every
individual check reports `present_ok` (verified 2026-07-07). Second, the
long-standing open item stands: the e2e (browser/Playwright) half of acb is
asserted, not proven — the cred half is load-bearing daily, the e2e half has
never had a recorded live proof. Small plan, two closures.

## Ground truth (verified 2026-07-07)

- `acb doctor --json` top level: `{component, version, regista:{reachable:
  null}, checks:[…]}` — no `ok`, no `degraded`. The umbrella (per the suite
  contract) classifies from the top-level `ok` bool → acb shows `failed` in
  `agent-suite doctor` while all its checks are green. cairn/dossier/agent-notes
  had the same drift fixed 2026-07-05; acb was missed.
- The umbrella's rendering compounds it: acb's per-check entries carry no
  `name` field either (`name: None` in the aggregate), so even the failure is
  illegible.
- Cred half: in live daily use (the `cred-*` skills are acb's shims), multi-
  plane routing proven. E2e half: `doctor` probes Playwright wiring
  (`present_ok` on both harnesses today) but no end-to-end browser task has
  been driven through both harnesses and recorded.

### WI-1.1 — Conform `doctor --json` to the suite health contract
- Emit top-level `ok` / `degraded` per the contract (classify from checks the
  way the other components do), and give every check a `name`. Keep exit-code
  semantics consistent with the JSON.
- **AC:** `agent-suite doctor` on a healthy box classifies acb `ok`; a broken
  capability yields `degraded`/`failed` with a named check; contract-shape
  asserted in acb's tests so it can't drift again.

### WI-1.2 — Live e2e proof, both harnesses
- Drive one real browser task (navigate + assert content on a local test page)
  through the e2e capability from Claude Code and from opencode, using only
  what `capabilities.toml` provisions. Record the proof as a committed script +
  doc, per the family's live-proof discipline — the negative path (Playwright
  server absent) must fail the doctor probe, proving the probe isn't
  decorative.
- **AC:** proof script passes on the operator box on both harnesses; removing
  the Playwright wiring flips doctor to a named failure.

### WI-1.3 — Composition check with provenance (once cairn is wired)
- After agent-provenance Plan 009 WI-2.1 lands, verify the standing claim that
  `acb exec` invocations attest via cairn's interception bound to the ambient
  work item — as a recorded check, not a memory. No acb code expected; this is
  a validation WI.
- **AC:** an `acb exec` run in a hooked session appears in the attestation
  chain; the finding (works / doesn't) is recorded in this plan's status.
