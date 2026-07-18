# Plan 009 — Declared secret onboarding (`acb onboard`)

**Status:** Proposed 2026-07-18 (WI-011).
**Author:** Claude Fable 5, from the windows-evidence-lab plane-seeding session.
**Strategic role:** Turn "source the admin token and hand-run `vault policy
write` / AppRole setup / `kv put`" into a reviewed, idempotent, provenance-
emitting act — with the manifest remaining the single declaration of what
exists and why.

## Ground truth

- Seeding `kv/homelab/lab/*` for the evidence lab (2026-07-18) meant sourcing
  the Vault admin token by hand and running policy/AppRole/KV commands from a
  session transcript. It worked, but it is unrepeatable operator folklore:
  nothing records which policies, roles, and paths exist because a session
  created them, and every new capability re-derives the dance.
- The manifest already declares everything an onboarding needs to *derive*:
  the KV path (`vault`), the field set (`fields`), the access plane
  (`vault_env`), and the naming contract (`env_prefix`/`inject`, WI-010).
  Today none of that declaration drives provisioning.
- acb's act path already has the right discipline to reuse: dry-run by
  default, backup-first, refuse-to-clobber, provenance on every act
  (`reconcile`, `install-harness`).
- acb is a Vault **client, not a store** (charter). Onboarding must not bend
  that: it may create *structure* (paths, policies, roles, plane files) and
  may transport a value once, but it never persists or prints one.
- WI-011 records the user's explicit ask: a plan to allow this via acb.

## Decisions

1. **The manifest entry drives everything.** `acb onboard cred:<name>`
   derives the KV path, policy name (`acb-<name>`), AppRole name
   (`acb-<name>`), policy scope (exactly the declared KV path, read-only),
   and the plane `.env` location (the capability's `vault_env` beside the
   harness config) deterministically from the manifest. No positional
   arguments duplicating manifest facts; drift is impossible because there is
   nothing to drift.
2. **The privileged plane is explicit and separate.** Onboarding requires
   `--admin-env <file>` (or `$ACB_VAULT_ADMIN_ENV`): a file holding the admin
   token or a dedicated onboarding AppRole. The capability's own plane is
   never used to create itself, and an ambient shell `VAULT_TOKEN` is never
   picked up silently. Missing admin plane = refusal, before any Vault call.
3. **Dry-run by default; `--apply` acts.** The dry-run prints the exact
   intended state: policy name and HCL, role name and configuration, KV path,
   plane file path, and which of these already exist. What is shown is what
   is done — the same Action objects feed the plan output, the apply, and
   provenance (the established reconcile pattern).
4. **Structure converges; values never do.** Policies, roles, and plane files
   are reconciled idempotently (create-if-absent, converge-if-drifted,
   backup-first for files). A KV path that already holds a value is **never
   overwritten** — there is no force flag for values. Rotation is a different
   verb for a different plan.
5. **Values arrive out-of-band, transit once.** `--values-from stdin` (JSON
   on stdin), `--values-from file:<path>` (read once, never copied), or
   `--values-from k8s:<namespace>/<secret>` (the migration path used for the
   donor lab secret). Default is `--values-from none`: onboard structure
   only. acb never echoes a value, never writes one to argv, logs, receipts,
   or provenance, and zeroes its in-process copies after the single KV write
   (best-effort, same caveat as exec).
6. **`onboard --check` is the read half.** A read-only drift report: does the
   derived structure exist and match the manifest-derived expectation
   (policy present and scoped correctly, role present, plane file present
   and parseable, KV path exists — via metadata, never a value read)? This
   is the durable answer to "nothing records which policies/roles/paths
   exist": the manifest is the record, and `--check` audits reality against
   it. `doctor` stays as-is; a broken plane's actionable next step in its
   detail text becomes "run `acb onboard --check cred:<name>`".
7. **Vault first, suite sources later.** The verb ships for
   `source = "vault"` capabilities only. AKV/Windows onboarding follows the
   Plan 008 suite-source contract once that path settles; the CLI surface is
   designed so a second backend is a new planner, not a new verb.

## Phase 0 — Onboarding contract and pure planner

- `docs/onboarding-contract.md`: derivation rules (names, scopes, paths),
  the refusal matrix (no admin plane, value exists, plane file exists with
  different role, policy exists with wider scope), and the value-transit
  guarantee.
- Pure planning module: manifest entry → ordered `Action` list + expected
  policy HCL. No I/O; property-tested (derivations are total, deterministic,
  and collision-free across a manifest).
- Refusals are planning-time wherever the needed fact is local; Vault-state
  refusals are surfaced in the plan as `verify` steps so the dry-run is
  honest about what it could not know offline.

## Phase 1 — `onboard` dry-run and `--check`

- `acb onboard cred:<name>` renders the plan (no Vault mutation; read-only
  existence probes only when the admin plane is provided, clearly marked
  otherwise as `unknown (offline)`).
- `acb onboard --check cred:<name>`: the read-only drift report, exit code
  reflecting drift. Covered in CI with a fake Vault client (the `hvac`
  surface used is small: policy read/write, AppRole read/write, KV metadata,
  one KV write).

## Phase 2 — `--apply` against live Vault

- Idempotent create/converge of policy, role, plane `.env` (backup-first;
  the secret_id lands only in the plane file, mode 0600, never in output).
- Value transit for `stdin`/`file`/`k8s` sources; `none` skips.
- Provenance events for every act (acb JSONL; cairn's harness interception
  attests the `acb onboard --apply` invocation to regista as usual).

## Phase 3 — Evidence-lab re-onboarding rehearsal

- From a scratch plane: onboard `cred:lab-hyperv-control` and
  `cred:lab-guest-bootstrap` end-to-end with zero hand-run `vault` commands;
  prove `doctor` PRESENT_OK, a composed checkout (WI-010) succeeds, and
  `onboard --check` reports clean. Record the rehearsal in
  windows-evidence-lab's evidence conventions.
- Only after the rehearsal: mark WI-011 resolved and document the verb in
  README + capability-model §7.

## Sequencing

Phase 0 and 1 are safe immediately (no privileged action exists until
`--apply`). Phase 2 wants review of the refusal matrix first — it is the
first acb code that *creates* Vault objects. Phase 3 is an afternoon on the
operator box and doubles as welab evidence.

## Explicit non-goals

- Not a secret store, cache, or rotation scheduler (rotation is follow-up
  work with its own refusal semantics).
- No AKV/Windows-native onboarding in this plan.
- No CI execution of `--apply` (CI proves planning and refusals with a fake
  client; live acts happen on the operator box under provenance).
- No management of Vault mounts, auth methods, or admin identities — the
  admin plane is assumed to exist; acb onboards *capabilities*, not Vault
  itself.
