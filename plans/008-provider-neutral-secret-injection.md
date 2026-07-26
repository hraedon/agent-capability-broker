# Plan 008 — Provider-neutral suite secret injection

**Status:** In progress 2026-07-25. Public Regista facade, the synthetic,
fail-closed `source = "suite"` injection slice, and the **Codex cred-shim adapter
(WI-3.1 adapter half)** are implemented; live backend conformance (WI-1.3), the
live Codex interop proof, the Windows authenticated-launch boundary (WI-3.2),
and the Windows evidence-lab proof (WI-3.3) remain open.
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
- A domain-joined Windows host reached through public-key SSH can identify the
  caller as a domain principal without holding a reusable domain credential.
  In that state DC discovery and TCP reachability can succeed while LDAP,
  SYSVOL, AD PowerShell, and Group Policy operations fail. ACB resolving a
  credential on the control host does not by itself repair that second hop.
- Installing an AI harness on the Windows target would not create the missing
  logon token and would add a second model-authentication and privileged-agent
  surface. The target needs ACB plus a deterministic qualified child, not
  Codex, Claude Code, or OpenCode.

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
8. **Resolve on the Windows execution host.** For in-band Windows domain
   validation, `acb exec` runs on the Windows target and injects the selected
   credential into an exact component-owned launcher there. Public-key SSH may
   trigger the value-free command and retrieve sanitized evidence, but it does
   not carry the credential and is not treated as the authenticated AD
   execution context.
9. **The qualified child creates the domain logon.** ACB remains a broker, not
   a remote-execution or Windows impersonation framework. The component-owned
   launcher consumes the injected fields and uses a reviewed Windows logon API
   or equivalently bounded native facility to create a process with reusable
   domain credentials and a loaded profile. Passing a password in `ssh`,
   PowerShell, `schtasks`, or another process argv is forbidden.
10. **Keep the target deterministic.** Routine validation installs ACB, the
    declared secret provider, and the qualified validator/launcher only. An AI
    coding harness on the target is neither required nor part of the proof.
    Interactive agents remain on the control plane; product-specific
    repositories own validation behavior and evidence semantics.

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
against an isolated `CODEX_HOME`; user skills/plugins/config are preserved.

**Landed 2026-07-17 (adapter half).** `CodexAdapter` (`src/…/adapters.py`)
renders cred discovery skills into `$CODEX_HOME/skills/<name>/SKILL.md` in
Codex's own `SKILL.md` format (verified byte-shape-identical to Codex's bundled
`.system` skills), create-only and backup-first. `install-harness codex` now
flows the normal plan/apply/verify path (the hard-coded `unsupported` block is
gone); the shim carries only the `acb exec cred:<id> -- <cmd>` inject-don't-
surface pattern — no get/print/inspect/clipboard, no secret value (canary test).
`CODEX_HOME`/`ACB_CODEX_HOME` select the root; the reserved `.system` tree is
never enumerated or written. Verified against an isolated `CODEX_HOME` via the
real CLI **and** unit tests (install, dry-run, rerun-no-op, hand-edited-shim
conflict → preserved, user config/skills preserved, `all` excludes codex). Codex
stays out of the stable `all` expansion until WI-3.2's live proof.

Remaining for WI-3.1: (a) *live* Codex in-session discovery/invocation of the
shim is Plan 007 WI-3.1's billable interop proof, not asserted here; (b) the
Codex **plugin/marketplace** composition (`.codex-plugin/plugin.json` +
`codex plugin add`) is agent-suite's suite-level distribution concern (Plan 007
WI-0.1), not acb's — acb owns the direct-installer skill surface; (c) *trust*
does not apply to skills (only hooks/MCP need `/hooks` trust) and generic
*uninstall/disable* is a pre-existing cross-harness gap (acb has no uninstall for
claude/opencode either), so it is deferred as a suite-wide WI, not a codex-only
one — recorded rather than faked green.

### WI-3.2 — Windows authenticated-launch boundary

Define and qualify the composition between Windows-local `acb exec` and a
component-owned validation launcher. ACB owns capability resolution, exact
`trusted_argv` matching, minimal environment injection, timeout/process-tree
containment, and value-free provenance. The consuming component (initially
Windows Evidence Lab, with GPO validation as the first live consumer) owns the
launcher, creation of the authenticated Windows process, operation allowlist,
rollback, and evidence reduction.

The intended control flow is:

```text
control-plane agent
    -> public-key SSH (value-free trigger)
    -> Windows-local acb exec
    -> exact qualified launcher with injected fields
    -> authenticated local Windows process
    -> LDAP / SYSVOL / ADWS / GPMC or product operation
    -> sanitized evidence pack
```

The launcher must consume credentials only from its declared injected
environment, construct the authenticated process in memory, and then remove
credential variables from every environment it controls. If it uses a
transient scheduled task or service as the native logon facility, registration
must occur through an API that does not expose the password in argv or generated
script text, the definition must contain no secret value, and cleanup must be
verified on success, failure, timeout, and cancellation. A general shell,
PowerShell interpreter, SSH client, or arbitrary script runner is not a
qualified `trusted_argv`.

Implementation slices:

1. **ACB Windows-host conformance.** Prove manifest discovery, suite-provider
   resolution, Windows absolute-path `trusted_argv` matching, minimal child
   environment, process-tree timeout/cancellation, redacted failures, and
   provenance when `acb exec` itself is invoked from public-key SSH. This slice
   belongs in ACB.
2. **Qualified launcher contract and implementation.** Publish the exact
   request/result schemas and a fake-launcher conformance fixture in ACB. Build
   the real Windows launcher in the consuming component, using native APIs
   directly rather than teaching ACB product operations or accepting arbitrary
   commands.
3. **Live composition proof.** Install released artifacts on a resettable
   synthetic Windows target, invoke the value-free ACB command over SSH, prove
   authenticated and negative operations, collect the sanitized evidence pack,
   and verify cleanup. Keep this credential-gated proof out of default CI.

**AC:**

- Starting from a public-key SSH session with no usable domain TGT, the
  value-free remote invocation causes Windows-local ACB to resolve the declared
  username/password fields and launch only the exact qualified executable.
- The authenticated child proves its execution identity and successfully
  performs allowlisted LDAP, SYSVOL, AD PowerShell, and Group Policy read
  probes against a synthetic domain. The original SSH process continues to
  fail the same probes, demonstrating that the result came from the new logon
  boundary rather than ambient authority.
- Positive and negative identities are separate capabilities. The delegated
  validation identity succeeds only for its declared read or disposable-test
  scope; a standard-user capability fails privileged operations with a typed,
  redacted authorization result.
- Secret/password canaries are absent from local and remote argv, command lines,
  generated scripts, task/service definitions, environment dumps, stdout,
  stderr, exceptions, ACB provenance, SSH transcripts, Windows event text under
  the test's control, and returned evidence. The account identifier may appear
  where Windows security auditing necessarily records the authenticated
  principal; the runbook classifies and redacts that field rather than claiming
  it is absent.
- The launcher has a fixed operation allowlist, bounded input/output,
  deterministic result schema, timeout, cancellation, process-tree cleanup,
  and an explicit refusal when the required Windows logon/containment mechanism
  is unavailable.
- Reruns are idempotent. No transient task, service, profile artifact, staging
  credential, or secret-bearing file remains after any terminal outcome.
- CI covers the contract with synthetic credentials and fake Windows APIs.
  A separately gated Windows test records OS/tool versions, executable and
  input digests, capability id and injected field names, correlation id,
  sanitized probe results, cleanup proof, and evidence hashes—never values.
- The runbook states explicitly that installing Codex, Claude Code, or OpenCode
  on the Windows target is unnecessary; doing so cannot substitute for this
  authenticated-launch proof.

### WI-3.3 — Codex and Windows evidence-lab proof

Run a synthetic evidence-lab command through Codex and ACB using least-privilege
lab credentials through the WI-3.2 Windows-local launch boundary. Correlate
cairn tool-call provenance, control-plane ACB/SSH invocation, Windows-local ACB
injection provenance, lab scenario id, and evidence-pack id.

**AC:** the operation succeeds, negative tests fail under the standard-user
capability, and secret canaries are absent from the Codex transcript, process
argv, hook inputs/outputs, cairn/regista events, lab logs, and sanitized evidence
pack. The Windows target has no AI harness installed and the original SSH
session never acquires or receives the domain credential.

## Sequencing

WI-0.1 is the prerequisite. WI-0.2 and the Codex read-only adapter can proceed
next. Implement Phase 1 before claiming agent-suite backend parity; implement
Phase 2 before enabling real lab credentials. Complete WI-3.2 before any
product plan depends on unattended domain-authenticated Windows validation;
finish with the correlated Codex/evidence-lab proof in WI-3.3.

## Explicit non-goals

- Storing credentials in ACB.
- Managing Codex or ChatGPT login credentials.
- Returning secret values to an agent for manual use.
- Making doctor perform an authenticated target action to prove a credential.
- Replacing backend-native least privilege, rotation, access logging, or
  approval controls.
- Installing, authenticating, or operating an AI coding harness on a Windows
  validation target.
- Implementing product-specific validation operations, rollback semantics, or
  evidence schemas in ACB; those belong to the qualified child.
- Treating public-key SSH identity, PowerShell remoting identity, or an
  impersonation-only token as proof of reusable domain credentials.
