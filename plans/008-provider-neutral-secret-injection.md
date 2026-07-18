# Plan 008 — Provider-neutral suite secret injection

**Status:** In progress 2026-07-17. Public Regista facade, the synthetic,
fail-closed `source = "suite"` injection slice, and the **Codex cred-shim adapter
(WI-3.1 adapter half)** are implemented; live backend conformance (WI-1.3), the
live Codex interop proof, and the Windows evidence-lab proof (WI-3.2) remain open.  
**Author:** GPT-5.6 Sol, from the Windows evidence-lab and Codex readiness audit.  
**Strategic role:** Let ACB inject credentials from the agent-suite secret
backend contract without becoming a secret store, printing a resolved value, or
pulling secret-backend logic into its deterministic read path.

## Ground truth

- `CredProvider` currently implements only `source = "vault"` and the testing /
  escape-hatch `source = "env"`.
- The only credential-backend extra in `pyproject.toml` is `hvac`; Azure Key
  Vault and Windows-native resolution are not implemented in ACB.
- Plan 005 is marked landed and its WI-3.1 says ACB resolves through the suite's
  Vault/AKV/Windows backend. That acceptance criterion is not present in the
  current source. This plan is the corrective work, not a second credential
  architecture.
- Regista implements the suite resolver internally and exposes it as an alias on
  the package, but there is no importable `regista.secrets` module matching the
  public name used by suite documentation. ACB must not depend on
  `regista._secrets`.
- ACB's core safety property remains inject-don't-surface: `exec` resolves only
  on the act path and gives values only to the selected child environment.
- A credential may require more than one field (for example, username and
  password). A one-reference/one-value shortcut is insufficient for Windows
  administration.

## Decisions

1. **Publish the resolver boundary first.** Regista provides a stable public
   `regista.secrets` facade with `resolve`, provider discovery, typed errors,
   and the canonical reference vocabulary. ACB never imports a private module
   or shells to a CLI that prints a secret.
2. **The core stays backend-neutral.** Add a small secret-source protocol. The
   suite adapter imports Regista lazily behind an optional extra and only from
   the credential act/probe edge.
3. **Vault compatibility remains.** Existing `source = "vault"` manifests and
   `ACB_VAULT_ENV` behavior continue to work for at least one release. New suite
   deployments use `source = "suite"` plus provider-neutral references.
4. **Multiple named references are explicit.** A capability maps child fields
   to refs; injection maps fields to environment names. No value appears in the
   manifest.
5. **Doctor does not prove a secret by reading it.** It validates syntax,
   provider availability, identity/backend reachability where a non-secret
   operation exists, and injection wiring. A backend that cannot prove a
   particular ref without resolving it reports `UNKNOWN` until an authorized
   use; it is not mislabeled green.
6. **Codex receives a shim, never a value.** The Codex skill names the
   capability and `acb exec` command only. Codex configuration, hook payloads,
   skills, MCP entries, and provenance never contain the resolved fields.
7. **Secret values are not accepted on argv.** ACB rejects manifest options that
   attempt literal credential values and never uses `regista secrets --ref`,
   PowerShell interpolation, or another stdout bridge.

## Implemented first-slice manifest shape

Placeholder example only:

```toml
[capability."cred:lab-hyperv-control"]
provider = "cred"
harnesses = ["claude", "opencode", "codex"]

source = "suite"
refs = { username = "vault:secret/example/lab/username", password = "vault:secret/example/lab/password" }
inject = { username = "LAB_USERNAME", password = "LAB_PASSWORD" }
trusted_argv = ["/opt/example/bin/lab-control", "--run"]
timeout_seconds = 120
```

The real capability manifest is local and gitignored. The first slice accepts
only explicit `vault:`, `azure:`, and `windows:` suite refs. Bare refs and
`file:`/`env:`/`literal:` suite refs are refused; legacy `source = "env"` and
`source = "vault"` remain separate compatibility paths. This does not claim
live Azure or Windows conformance, which remains WI-1.3 work.

**Qualified-child correction (adversarial review):** Inject-only means ACB does
not emit the resolved value; it does not mean an arbitrary child cannot print or
transform its environment. The first slice therefore requires an exact,
absolute `trusted_argv`, checks it before resolution, uses a minimal child
environment and bounded timeout, and emits started/terminal provenance. The
purpose-built child must still be separately qualified. Capturing/redacting
exact output values would only be defense in depth and would not prevent encoded
or transformed exfiltration.

The child receives a value-free `ACB_CHECKOUT_RECEIPT` using schema
`acb.checkout-receipt.v1`: invocation id, issued/expires UTC timestamps, and an
extensible `checkouts` list containing capability id and logical field names.
Each checkout's `fields` is a semantic-field → injected-environment-name mapping
so the lab can validate the exact authority-to-environment wiring.
It is parent-launch binding/correlation metadata, not a cryptographic
authorization token. This slice emits one checkout. Nested inheritance and
atomic multi-capability checkout/composition are an explicit live blocker/WI.

## Phase 0 — Reconcile the suite contract

### WI-0.1 — Canonical public resolver facade and reference names

Coordinate with Regista and agent-suite to expose the supported public import
and reconcile the currently inconsistent Windows/Azure vocabulary in docs and
source (`wincred`/`akv` versus `windows`/`azure`). Define availability/probe
behavior separately from value resolution.

This is also a custody-semantic decision, not an aliasing exercise. Current
agent-suite Windows guidance describes user-scoped Credential Manager entries;
the Regista `windows:` implementation stores a machine-scoped DPAPI blob in the
reference itself. Either implement and name both backends, or select one and
update the runbooks/threat model. Do not describe machine-scope DPAPI as
user-scope Credential Manager.

**AC:** consumers import only a documented public module; one versioned table
maps every accepted scheme to its backend, required extra, scope, and probe
semantics; stale scheme examples fail the documentation/contract test; the
Windows conformance proof demonstrates which principals can decrypt the value.

### WI-0.2 — Secret-source protocol

Define a closed source kind and an edge protocol for:

- validating a reference without resolving it;
- reporting provider/identity reachability when safe;
- resolving named fields only during `exec`;
- returning typed, redacted failures.

**AC:** the model/core modules do not import Regista, Vault, Azure, or Windows
SDKs; closed dispatch uses exhaustive handling; exception text contains a
capability/field/backend name but never a resolved value.

## Phase 1 — Suite source implementation

### WI-1.1 — Optional Regista resolver adapter

Add a `suite-secrets` optional extra pinned to `regista>=0.5.1,<0.6` and its
public `regista.secrets` `API_VERSION = 1` contract, with lazy adapter import.
Resolve each named ref to bytes, decode only fields declared as
text, construct the child environment, and discard references after the child
returns.

**AC:** missing optional dependencies become an actionable status; no fallback
to plaintext files or environment values occurs; importing/using doctor without
the extra remains supported.

### WI-1.2 — Multi-field injection and collision policy

Validate `refs` and `inject` mappings. Refuse duplicate child variable names,
reserved variables, inherited-variable clobber, empty commands, unknown fields,
and literal/raw values.

**AC:** username/password and token-only fixtures work; a pre-existing child
environment variable is preserved or causes an explicit refusal according to
one documented policy—never silently overwritten.

Implemented slice: suite execution refuses inherited/inject receipt collisions,
requires exact absolute `trusted_argv`, builds a minimal child environment, and
uses a manifest timeout bounded to 900 seconds. Started and terminal provenance
share the receipt invocation id. Qualification of the trusted executable and
multi-capability composition remain open integration work.

Timeout/interruption containment now owns a new POSIX session or Windows process
group. POSIX uses process-group TERM → bounded grace → KILL; Windows uses
`taskkill /PID /T /F` with direct-kill fallback and fails closed before
resolution if `taskkill.exe` or the creation flag is unavailable. A deliberately
detaching/privilege-escaping child remains part of executable qualification.

### WI-1.3 — Backend conformance

Exercise Vault, Azure Key Vault, and Windows-native custody through the public
resolver. Unit tests use synthetic providers; live tests are explicit,
credential-gated jobs and retain no value-bearing artifacts.

**AC:** each backend passes unavailable, unauthorized, missing-ref, valid use,
rotation, and redacted-failure cases on its supported OS.

## Phase 2 — Read/act honesty and provenance

### WI-2.1 — Non-secret doctor probes

Report provider installed, reference syntactically valid, backend identity
available, harness shim present, and last-use status as separate checks. Never
resolve a credential merely to turn doctor green.

**AC:** a Windows DPAPI or similar backend without a safe existence probe
reports the ref as unproven/`UNKNOWN`; doctor remains read-only under syscall and
fake-provider assertions.

### WI-2.2 — Value-free provenance

Emit capability id, requested fields, injected variable *names*, backend kind,
child executable basename, correlation id, timing, and exit status. Do not emit
refs when they disclose estate topology unless local policy explicitly permits
their sanitized form.

**AC:** high-entropy canaries used as username, password, and token are absent
from ACB-controlled stdout/stderr, exceptions, provenance, logs, hook fixtures,
receipts, and serialized results. A separately qualified evidence-lab child
proves its own output remains canary-free; arbitrary-child non-disclosure is not
claimed.

### WI-2.3 — Process and platform adversarial tests

Test Windows and Unix argv/process inspection, inherited environment, child
failure, timeout, interruption, concurrent executions, Unicode, shell wrappers,
and grandchildren. Document the residual fact that Python strings and child
environments cannot be guaranteed cryptographically erased from process memory.

**AC:** ACB invokes the requested executable directly by argv, never through an
implicit shell; cancellation terminates the owned process tree according to the
documented policy; no secret is copied into a temporary file unless a future
explicit file-injection mode defines deletion and ACL guarantees. Landed for
the suite slice with a POSIX grandchild-canary test and Windows branch tests.

## Phase 3 — Codex and evidence-lab composition

### WI-3.1 — Codex capability shim

Complete Plan 007's Codex adapter and install a component-owned skill/plugin
entry that invokes `acb exec cred:<id> -- <command>`. It must not offer a
`get`, print, inspect-value, or copy-to-clipboard workflow to the model.

**AC:** install, rerun, conflict, trust, disable, and uninstall behavior passes
against an isolated `CODEX_HOME` and `ACB_HOME`; user skills/plugins/config are
preserved.

**Landed 2026-07-18 (adapter and component-plugin slice).** `CodexAdapter`
(`src/…/adapters.py`)
renders cred discovery skills into `$HOME/.agents/skills/<name>/SKILL.md` in
Codex's own `SKILL.md` format (verified byte-shape-identical to Codex's bundled
`.system` skills), create-only and backup-first. `install-harness codex` now
flows the normal plan/apply/verify path (the hard-coded `unsupported` block is
gone); the shim carries only the `acb exec cred:<id> -- <cmd>` inject-don't-
surface pattern — no get/print/inspect/clipboard, no secret value (canary test).
`CODEX_HOME`/`ACB_CODEX_HOME` select the root; the reserved `.system` tree is
never enumerated or written. Verified against an isolated `CODEX_HOME` via the
real CLI **and** unit tests (install, dry-run, rerun-no-op, hand-edited-shim
conflict → preserved/fail-closed, user config/skills preserved, `all` excludes
codex). A real `codex debug prompt-input` proof now confirms that a generated
skill under an isolated `$HOME/.agents/skills` is model-visible without a model
call or user authentication. `plugins/acb` owns the static plugin manifest and
a generic value-free broker skill; a real isolated marketplace test proves
plugin add/list/remove. It contains no capability identifiers or secret refs,
so dynamic `cred-*` skills remain generated from the local manifest. Codex
stays out of the stable `all` expansion until WI-3.2's credentialed invocation
proof.

Remaining for WI-3.1: (a) *live credentialed invocation* of the shim is Plan
007 WI-3.1's interop proof, not asserted here; (b) publishing/pinning the
component-owned plugin in the suite **marketplace** remains agent-suite's
composition concern (Plan 007 WI-0.1); (c) *trust*
does not apply to skills (only hooks/MCP need `/hooks` trust) and
*uninstall/disable* is now implemented as a cross-harness `install-harness
--uninstall` surface (exact content match hash check; marker-bearing shims with
changed content are preserved — user edits are never destroyed; MCP removals
backup-first; provenance-emitting).

### WI-3.2 — Windows evidence-lab proof

Run a synthetic evidence-lab command through Codex and ACB using least-privilege
lab credentials. Correlate cairn tool-call provenance, ACB injection provenance,
lab scenario id, and evidence-pack id.

**AC:** the operation succeeds, negative tests fail under the standard-user
capability, and secret canaries are absent from the Codex transcript, process
argv, hook inputs/outputs, cairn/regista events, lab logs, and sanitized evidence
pack.

## Sequencing

WI-0.1 is the prerequisite. WI-0.2 and the Codex read-only adapter can proceed
next. Implement Phase 1 before claiming agent-suite backend parity; implement
Phase 2 before enabling real lab credentials; finish with the correlated live
proof in Phase 3.

## Explicit non-goals

- Storing credentials in ACB.
- Managing Codex or ChatGPT login credentials.
- Returning secret values to an agent for manual use.
- Making doctor perform an authenticated target action to prove a credential.
- Replacing backend-native least privilege, rotation, access logging, or
  approval controls.
