# Plan 012 — Broker and operations service (decision)

**Status:** Accepted design, 2026-10-28. Implementation started (§9).
**Author:** Claude Opus 5.5, at the owner's direction, after reading the
2026-10-19 v2 proposal (GLM), Plan 010 R0 (Kimi K3), Plan 011 R1 (Opus) and an
independent v2 design (Argon).
**Supersedes:** Plan 010 and the v2 proposal as executable plans. Plan 011 R1
is the base; this document records what changes from it and why. Where they
disagree, this document wins.

> Charter carry-forwards: one manifest, read/act boundary, dry-run-by-default
> acts, provenance on every act, client-never-store, no AI in the truth path,
> stdlib-only core. acb is a Vault client, not a secret store.

## 1. What was decided, and from where

| Decision | Source |
|---|---|
| The trust boundary is the **agent VM**, not an OS principal inside it. Root in the VM is accepted. No separate broker principal. | 011 R1 (owner direction). Rejects Argon's separate-principal daemon and GLM's per-user hardening. |
| Every capability must **hide** (value never enters the VM) or **devalue** (issued, scoped, ≤15 min, revocable). Manifest declares an assurance level (`D0`, `D1`, `H1`, `H1+D1`); `doctor` verifies it. | 011 |
| **Blast-radius rule:** the VM holds nothing that administers anything that guards or issues secrets. `acb doctor --boundary` checks it. | 011 |
| **Integration ladder:** native credential helper → in-VM egress proxy → off-VM typed operation → env injection (compatibility only). Ordinary commands (`git push`, `kubectl get`) just work. | 011; GLM's proxy mode; K3's "no CLI composition" goal |
| **New: non-Vault minting happens off the VM.** | This plan, §2 |
| **New: rung 4 is closed now** — every `cred` exec requires an exact `trusted_argv`, whatever its source. | GLM Phase 0 item 5; this plan §5 |
| Broker IPC is `acb.broker.v1`: length-prefixed JSON, one request per connection, size limits, peer credentials from the socket. | K3 |
| Checkouts bind to a session and expiry; `acb checkouts` (read) and `acb revoke` (act). | K3, 011 |
| Off-VM operations take **typed inputs validated against a declared schema**; results are value-free by construction. | Argon (`arg_schema`), 011 (rung 3) |
| Vault hygiene: service tokens (not batch) for anything revocable; `num_uses` bounded; no ambient `VAULT_TOKEN`; no root token on any workstation. | GLM §5 |
| **AOS is optional.** The grant contract keeps an `issuer` field so an AOS mediator can be added; no phase depends on it. | Owner, 2026-10-28 (AOS no longer targets clinical deployment) |
| **Approvals** for `approve`-tier operations are WebAuthn assertions verified by `acb-ops` itself. The operator console only relays them. | This plan, §4 |
| Implementation language: Python, stdlib-only for the broker; `hvac` stays an optional extra used through `cred_vault`. | Charter. Go's memory-hygiene argument doesn't apply when root in the VM is accepted. |

Rejected outright: argv grammars for general-purpose CLIs (011); executable
SHA-256 pinning inside the VM (Argon — meaningless when root is accepted);
SPIRE as a prerequisite (GLM — later, if ever); blocking provenance (K3 Q5 —
stays non-blocking).

## 2. Amendment: minting happens off the VM

011 lets the in-VM broker mint short-lived forge tokens. To mint, the broker
would hold a credential that can create other credentials (an account
password, an admin token, a GitHub App private key). Root in the VM can read
broker memory, so that minting credential is a standing `D0` secret and the
"devalued" tokens it produces are not devalued at all.

Rule: **the VM's identity may obtain issued credentials, never the means to
issue them.** Two kinds of issuer are allowed:

1. **Vault engines** that mint inside Vault: SSH CA, Kubernetes secrets
   engine, LDAP library/static roles, database, PKI. The VM's Vault policy
   grants `creds/` paths only.
2. **`acb-ops` mint endpoints** for issuers Vault cannot drive (forge tokens,
   GitHub App installation tokens, Entra tokens). `acb-ops` holds the minting
   credential; the broker asks it for a scoped, expiring token over mTLS.

Static KV reads remain possible but are `D0` by definition and reported so.

## 3. Components

```text
 agent VM (boundary)                          off-VM (cluster ns the VM cannot administer)
 ┌───────────────────────────────────┐        ┌──────────────────────────────────────┐
 │ harness ─► git / kubectl / ssh    │        │ acb-ops                              │
 │              │ helper protocol    │  mTLS  │  - mint endpoints (forge, GH App)    │
 │              ▼                    │◄──────►│  - typed operations (rung 3)         │
 │ acb-broker (systemd, root ok)     │        │  - policy tiers + rate limits        │
 │  - one VM Vault identity          │        │  - WebAuthn approval verification    │
 │  - acb.broker.v1 on unix socket   │        │  - holds minting/privileged creds    │
 │  - checkout registry (accessors,  │        └───────────────┬──────────────────────┘
 │    never values) + TTL revoke     │                        │ approval relay only
 │  - advisory harness detection     │        ┌───────────────▼──────────────────────┐
 └──────────────┬────────────────────┘        │ operator console (separate project)  │
                │ creds/ paths only           │  inbox: blocked agents + approvals   │
                ▼                             └──────────────────────────────────────┘
              Vault (engines mint)
```

- **acb-broker** — §3.1 of 011 plus K3's IPC and lifecycle. It persists lease
  accessors (never values) so `acb revoke` survives a restart.
- **Helper front-ends** — thin stdlib executables that speak a tool's native
  protocol and forward to the broker: `acb-git-credential` (git credential
  helper protocol), `acb-kube-credential` (client-go `ExecCredential`). Each is
  a client of the socket and holds no policy.
- **acb-ops** — a small HTTP service outside the VM. Authenticates the broker
  by mTLS (short-lived client cert from Vault PKI); everything the VM asserts
  (harness, session) is advisory.

## 4. Approvals and the operator console

011 left the approval channel open (Q5). It must be something the VM cannot
answer. Decision:

- `acb-ops` creates a pending approval with a digest over the exact grant
  (operation, typed inputs, subject, expiry, policy digest).
- The operator approves by producing a **WebAuthn assertion over that digest**
  with an enrolled passkey. `acb-ops` verifies the assertion against its own
  enrolled credential list.
- The operator console (a separate, publicly reachable page behind Authentik)
  lists pending approvals and performs the WebAuthn ceremony, but it is only a
  relay. A compromised console can hide or delay approvals; it cannot forge
  one. Until the console exists, `acb-ops` serves a minimal approval page
  itself, and ntfy carries the "approval pending" notification.

## 5. Manifest v2 (delta over 011 §9)

Per capability, added keys: `issuer` (table, `kind` required), `delivery`
(table, `rung` ∈ `helper | proxy | remote-op | env`), `assurance` (declared
floor), `decision` (`auto | approve | deny`, remote-op only), `harnesses`
(advisory). A v1 entry upconverts losslessly to `delivery = {rung = "env"}`
with `assurance = "D0"` unless its source is an issuing engine.

Rung `env` keeps today's semantics with one change: **`trusted_argv` is
required for every `cred` capability** (not only `source = "suite"`), and the
first element may not be a shell or interpreter (`sh`, `bash`, `zsh`, `dash`,
`pwsh`, `powershell`, `cmd`, `python*`, `node`, `perl`, `ruby`, `env`; list
expanded in §10 (b)). `acb exec cred:x -- env` must fail with a manifest/exec
error before any secret is resolved.

## 6. Vault configuration (summary)

- VM identity: one AppRole now (`secret_id_num_uses` bounded, CIDR-bound,
  rotated by the operator from the workstation); cert or TPM-backed later.
- VM policy: `read` (`update` for dynamic `creds/`) on declared
  `creds/`/`issue/`/`sign/` paths and declared legacy KV paths, plus `update` on
  `auth/token/create` (per-checkout child tokens cannot exceed the parent's
  policies). Revocation relies on the `default` policy's `auth/token/revoke-self`.
  Nothing under `sys/` (in particular no `sys/leases`), no `auth/token/revoke-accessor`,
  nothing else under `auth/` or `identity/`, no policy writes. `doctor --boundary`
  checks the admin paths with a capabilities-self call and warns on the broad
  revoke paths (§10 (c)).
- Dynamic credentials are read with a per-checkout child token (service type,
  TTL ≤ 15 min, bounded `num_uses`, not renewable) and revoked by that token's
  `revoke-self`; the broker's own token never reads them.
- Provisioning (`acb onboard`, policy writes) runs from the workstation with
  an operator OIDC login, never a root token on disk.

## 7. Phases

Each phase stands alone and ends with evidence (`doctor` output plus a probe).

- **P0 — Hygiene.** Code: `doctor --boundary` (read-only), rung-4 hardening
  (§5), assurance reporting for v1 entries. Operator: kubeconfig mode and
  scope, SSH key reach, plane-policy audit, remove any root token file,
  rotate. *Acceptance:* all boundary checks pass; `acb exec cred:x -- env`
  is refused for every capability.
- **P1 — Broker.** `acb-broker`, `acb.broker.v1`, checkout registry,
  `checkouts`/`revoke`, helper front-ends for git and kubectl, issuer
  interface with `vault-kv` (legacy D0), `vault-k8s-token` and `remote-mint`
  kinds. Pilot one capability live. *Acceptance:* `kubectl get pods` (or
  `git push`) works from every harness with no acb invocation; no plane files
  remain for the piloted capability.
- **P2 — acb-ops minimal.** mTLS, forge mint endpoint, approval verification,
  the minimal approval page. Move forge tokens to `remote-mint`.
- **P3 — Privileged operations.** Typed directory and hypervisor operations,
  LDAP library check-out; move privileged capabilities off the VM.
- **P4 — Workstation zone.** As 011 Phase 5.

## 8. Non-goals

As 011 §13, plus: the operator console is not part of acb and never holds a
credential or an approval key.

## 9. Work items started 2026-10-28

| WI | Scope | Files |
|---|---|---|
| WI-012-1 | Rung-4 hardening (§5) | `providers.py` exec paths, shim text, exec tests |
| WI-012-2 | Manifest v2 keys + upconvert, assurance in `doctor`, `doctor --boundary` | `model.py`, `cli.py` (doctor), new `boundary.py`, `docs/capability-model.md` |
| WI-012-3 | Broker core: `acb.broker.v1`, server, checkout registry, issuer interface (fake + `vault-kv`), git and kube helper front-ends | new `broker/` package, `pyproject.toml` scripts |

WI-012-3 reads the v2 keys through its own small parser until WI-012-2 lands;
a follow-up item switches it to the shared model.

## 10. Review amendments (2026-10-28)

From an external review (Argon) of this plan. Where these disagree with
§§1-9, this section wins.

**(a) Assurance: helper and proxy are never `H1`.** Root in the VM is accepted,
so a native credential helper hands the token to any VM process that asks and
an in-VM egress proxy holds it in VM memory. Only `remote-op` (the value never
enters the VM) can be `H1`. The derivation already gives helper/proxy/env at
most `D1` (`D0` for a non-issuing issuer such as `vault-kv`). Now enforced:
declaring `H1` or `H1+D1` on any other rung is a `ManifestError` and a failing
`doctor` check; a `helper`/`proxy` capability that is `D0` is a `warn` that
suggests `remote-op`.

**(b) Launcher denylist.** The §5 list was incomplete. It now also covers `ksh`,
`fish`, `csh`, `tcsh`, `py`, `wscript`, `cscript`, `mshta`, `rundll32`,
`regsvr32`, `busybox`, `toybox`, `nice`, `nohup`, `timeout`, `stdbuf`, `setsid`,
`sudo`, `doas`, `su`, `xargs`, `find`, `awk`/`gawk`/`mawk`, `sed`, `uv`, `uvx`,
`npx`, `bunx`, `bun`, `deno`, `php`, `lua`, `tclsh`, `wish`, `expect`,
`osascript`, `ssh`, `script`, with version suffixes (`python3.13`, `lua5.4`,
`php8.3`, `ruby3.2`, `perl5.38`, `node22`) and `.exe .com .bat .cmd .ps1`
stripped, case-insensitively, on the basename. One list (`launchers.py`),
enforced at manifest parse, in `doctor` and at exec. It is a lint guard against
operator mistakes, not a sandbox: `trusted_argv` is an exact full-argv match
from an operator-reviewed manifest.

**(c) Revocation without `sys/leases/revoke`.** Revoking by lease id needs a
broad lease-revoke grant (it could revoke other identities' leases). Instead,
each checkout from a dynamic engine gets a child token of the broker's own
(`auth/token/create`: non-orphan, `policies` a subset of the parent's, `ttl`
the checkout TTL capped at 15 min, bounded `num_uses`, not renewable, service
type). The creds are read with the child token, which lives only in broker
memory; revoke is `auth/token/revoke-self` called with it, and Vault revokes
every lease it created. The VM policy needs `update` on `auth/token/create`
and the `default` policy's `revoke-self`; **nothing** under `sys/leases` and no
`auth/token/revoke-accessor` (too broad). After a broker restart the token is
gone and the lease dies with the token TTL (≤ 15 min); only the token
accessor and expiry are persisted, for `checkouts` display. Static KV reads
have no lease and are unchanged. `doctor --boundary` warns if either broad
revoke path is granted.

**(d) P4 note: peer credentials.** Broker peer-credential extraction goes behind
a small platform helper: Linux `SO_PEERCRED`, macOS `LOCAL_PEERCRED` /
`getpeereid`, Windows `SIO_AF_UNIX_GETPEERPID` or a 0700 owner-ACL directory.
Not implemented now.

**(e) `acb-ops` WebAuthn verification (§4, made precise).** The challenge is
`base64url(SHA-256(canonical grant JSON))`. `acb-ops` verifies: `rpIdHash`;
the origin against an allowlist (the console origin); the `UP` and `UV` flags;
the signature over `authenticatorData || SHA-256(clientDataJSON)`; and
`signCount` monotonicity. `acb-ops` is not part of the stdlib-only core and
takes a cryptography dependency via an `[ops]` optional extra.
