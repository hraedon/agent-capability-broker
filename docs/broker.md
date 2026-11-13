# acb-broker (in-VM credential broker)

Status: core landed in WI-012-3 (Plan 012, phase P1). Not yet wired into the
`acb` CLI, `install-harness`, or a service unit. See "Follow-ups" below.

## What it is

`acb-broker` is a small stdlib-only daemon that runs inside an agent VM. It
holds **one** Vault identity for the VM, issues short-lived credentials to the
tools agents already run (`git`, `kubectl`) through those tools' own
credential-helper protocols, and revokes them on expiry, session end, explicit
request, or shutdown.

The design rule it implements (Plan 012 §2): **the VM's identity may obtain
issued credentials, never the means to issue them.** The broker reads Vault
`creds/` paths; anything that needs a minting credential (forge tokens, GitHub
App installation tokens) is `remote-mint` and belongs to `acb-ops` off the VM
(P2).

```text
 harness ─► git push / kubectl get
               │ credential-helper / exec-plugin protocol
               ▼
 acb-git-credential / acb-kube-credential   (thin clients, no policy)
               │ acb.broker.v1 over a unix socket
               ▼
 acb-broker ─► Vault engine (creds/)        (one VM identity)
   ├─ values: memory only
   └─ state file: checkout ids + token accessors (never values)
```

## Components (`src/agent_capability_broker/broker/`)

| Module | Role |
|---|---|
| `protocol.py` | `acb.broker.v1` framing, strict request validation, error codes, the value rule |
| `config.py` | Reads the v2 manifest keys (`issuer`, `delivery`, `assurance`, `harnesses`). Own parser until WI-012-2's shared model lands |
| `issuers.py` | Issuer interface and kinds: `vault-k8s-token`, `vault-kv`, `remote-mint` (refuses: P2), `fake` (tests only) |
| `registry.py` | Checkouts: values in memory, value-free state file, reaper, crash recovery |
| `harness.py` | Advisory harness attribution from the peer's process tree |
| `service.py` | Request handling, independent of sockets |
| `server.py` | AF_UNIX server; `acb-broker` entry point |
| `client.py` | Socket client; `list_checkouts` / `revoke_checkouts` / `broker_status` for the CLI follow-up |
| `git_credential.py` | `acb-git-credential` (git credential-helper protocol) |
| `kube_credential.py` | `acb-kube-credential` (client-go `ExecCredential`, `client.authentication.k8s.io/v1`) |

## Manifest keys the broker reads

Only capabilities with an `issuer` table are served; v1 entries are ignored by
the broker and keep today's `acb exec` behaviour.

```toml
# Placeholders only.
[capability."cred:example-k8s"]
provider  = "cred"
issuer    = { kind = "vault-k8s-token", mount = "kubernetes", role = "agent-read",
              namespace = "example", ttl = "10m" }
delivery  = { rung = "helper", tool = "kubectl" }
assurance = "D1"
harnesses = ["claude", "codex"]          # advisory allowlist

[capability."cred:example-forge"]
provider  = "cred"
issuer    = { kind = "vault-kv", path = "kv/example/forge/bot", fields = ["username", "password"] }
delivery  = { rung = "helper", tool = "git", hosts = ["forge.example.test"] }
assurance = "D0"                         # a static read is D0 by definition
```

- `issuer.ttl` is bounded to 15 minutes (Plan 012 §6); default 15m.
- `delivery.hosts` (git) must not overlap between capabilities.
- `delivery.username` supplies the git username when the issued value has none.
- A declared `assurance` above what the issuer can deliver is reported by
  `status` (`meets_floor: false`); enforcing it is `doctor`'s job (WI-012-2).

## Protocol: `acb.broker.v1`

One request per connection; each direction is one frame: a 4-byte big-endian
length, then UTF-8 JSON (an object). Requests are capped at 64 KiB, responses
at 1 MiB. Unknown keys are errors, not ignored.

```json
{"v": "acb.broker.v1", "method": "checkout",
 "params": {"match": {"tool": "git", "host": "forge.example.test"}},
 "front_end": "git", "session": "optional", "harness_hint": "optional"}
```

| Method | Params | Effect |
|---|---|---|
| `checkout` | exactly one of `capability` / `match {tool, host?}`; optional `ttl` (can only shorten) | Issue, or reuse a live checkout for the same capability + session + harness with ≥60s left |
| `revoke` | exactly one of `checkout_id` / `capability` / `match` / `all`; `own_session`, `dry_run` | Revoke at the issuer, drop the value |
| `list` | optional `capability`, `session` | Read-only, value-free checkout metadata |
| `status` | none | Read-only: counts, capabilities, issuer availability, paths |

Responses: `{"v", "ok": true, "result", "carries_secret"}` or
`{"v", "ok": false, "error": {"code", "message"}}`. Error codes are stable:
`bad_frame`, `too_large`, `bad_request`, `unknown_method`, `forbidden_peer`,
`unknown_capability`, `no_match`, `harness_not_allowed`, `delivery_mismatch`,
`not_found`, `not_implemented`, `issuer_error`, `busy`, `timeout`, `internal`.

**Value rule.** Only a successful `checkout` with a `front_end` (`git` or
`kube`) carries a value, under `result.value`, with `carries_secret: true`.
The helper needs it to hand to git or kubectl; that is rung 1 by design.
`protocol.encode_response` is the single exit point for every response and
refuses any other shape, so `list`, `status`, `revoke`, errors and value-less
checkouts cannot carry one. A `front_end` may only check out a capability
whose `delivery` names that helper's tool (`git` → `git`, `kube` → `kubectl`).
That is accident prevention, not access control: any local caller can claim
any `front_end`.

## Socket

- Path: `$ACB_BROKER_SOCKET`, else `$XDG_RUNTIME_DIR/acb/broker.sock`, else
  `/run/acb/broker.sock` (root) or `/tmp/acb-<uid>/broker.sock`.
- The directory is created 0700 and must be owned by the broker's uid; the
  socket is 0600. A stale socket with no listener is replaced; a live one
  makes startup fail; a non-socket at that path is never replaced.
- Peer credentials come from `SO_PEERCRED`. A peer whose uid is neither the
  broker's nor 0 is refused before its request is read. Run the broker as the
  agent user (the socket is 0600, so a root-owned broker is unreachable for a
  non-root agent).
- Each connection has a whole-request deadline (5s); workers are bounded (16);
  excess connections get `busy`.

## State file

`$ACB_BROKER_STATE`, else `<acb state dir>/broker/checkouts.json`. JSON,
`acb.broker-state.v1`, mode 0600, written by temp file + fsync + rename. Each
record: checkout id, capability, harness label, session, issued/expiry,
issuer kind, assurance, revocation handle and token accessor (the accessor of
the checkout's Vault child token; none for `vault-kv`), and a
pending-revocation flag. **Never a value, and never a Vault token.** `list`
shows the accessor and expiry; the child token itself exists only in memory.

On startup the broker revokes every record left in the file (crash cleanup).
A revocation that fails stays recorded as pending and the reaper retries it.

## Lifetime and revocation

A checkout is revoked when it expires (the reaper runs every 5s), when the
harness process it was attributed to exits (session end, guarded against PID
reuse by process start time), on `revoke`, and on SIGTERM/SIGINT. The value is
dropped from memory as soon as revocation starts.

- `vault-k8s-token`: **token-bound revocation.** For each checkout the broker
  creates a child token of its own Vault token (`auth/token/create`: not an
  orphan, `policies` a subset of the parent's, `ttl` the checkout TTL capped at
  15 minutes, `num_uses` bounded (3), not renewable, service type), reads
  `<mount>/creds/<role>` **with the child token**, and holds the child token
  only in memory. Revocation is `auth/token/revoke-self` called with the child
  token, and Vault revokes every lease that token created. It never calls
  `sys/leases/revoke` and never `auth/token/revoke-accessor`, so the VM
  identity cannot revoke other identities' leases or tokens.
  - **Broker restart.** The child token is lost with the process; only its
    accessor and the checkout expiry were persisted. The lease then dies on
    its own when the child token's TTL expires (at most 15 minutes after the
    checkout was issued). `recover()` therefore treats an accessor it does not
    hold as already bound to the TTL: it logs that fact and clears the record.
  - The optional `issuer.token_policies` list narrows the child token to a
    dedicated policy (it must be a subset of the broker token's). Omitted, the
    child inherits the broker's policies. Prefer a dedicated policy holding
    only `read` on `<mount>/creds/<role>`: it also keeps the child from being
    able to mint further tokens.
  - `ttl` of the creds is the checkout's, and the lease cannot outlive the child
    token, so `Issued.ttl` is bounded by the token's remaining life.
- `vault-kv`: a static read. Revocation only forgets the in-memory copy; the
  value stays valid in Vault. That is why it is `D0`.
- `remote-mint`: refuses with `not_implemented` until `acb-ops` exists.

## Vault identity

The Vault issuers use `cred_vault.authenticated_client(allow_token=False)`:
the WI-016 invariants (`token=""`, fail-closed AppRole) plus a refusal of a
bare `VAULT_TOKEN`. The broker authenticates once with the VM's AppRole or
Kubernetes identity and re-authenticates once on an auth error. `hvac` is
imported only when a Vault issuer first runs.

### Vault policy for the VM identity

The policy is the minimum the broker's calls need (placeholders; adapt mounts
and roles):

```hcl
# read the dynamic credentials it hands out
path "kubernetes/creds/agent-read" { capabilities = ["update"] }   # POST creds/<role>
# legacy static reads (D0), only the declared paths
path "kv/data/example/forge/bot"   { capabilities = ["read"] }
# per-checkout child tokens: they can never exceed the parent's policies
path "auth/token/create"           { capabilities = ["update"] }
```

- The `default` policy already grants `auth/token/revoke-self`, which is what the
  child token uses to revoke itself and its leases. Do not remove `default` from
  the VM identity or from `token_policies`.
- **Nothing under `sys/leases`, and not `auth/token/revoke-accessor`.** Either
  would let a compromised VM revoke other identities' leases or tokens. Nothing
  under `sys/`, `auth/` (apart from `auth/token/create`), or `identity/`.
- `acb doctor --boundary` warns (`boundary.vault-revoke-scope`) if the identity
  holds `sys/leases/revoke` or `auth/token/revoke-accessor`, in addition to the
  existing admin-path check.
- Vault caps a child token's TTL at its parent's remaining life, so a checkout
  can be shorter than asked when the broker's own token is near expiry (the
  issued TTL reflects it; the session re-authenticates on an auth error).

## Harness attribution (advisory)

The broker walks from the peer PID up the parent chain to the first known
harness binary (`claude`, `codex`, `opencode`, `zcode`, matched on comm, exe,
argv[0] or argv[1]). Failing that it uses the client's `ACB_HARNESS`, and
failing that `shell`. The label drives provenance attribution, the advisory
`harnesses` allowlist, and session anchoring. **It is not a security
boundary.** Any process in the VM can impersonate any harness. Harnesses
that must be separated need separate VMs.

## Provenance

Every checkout and revoke emits one value-free event through
`provenance.emit` (`action` = `broker_checkout` / `broker_revoke`, `target` =
checkout id, `purpose` = `acb-broker`). A failing sink is logged and never
blocks a request.

## What is and isn't protected

The trust boundary is the VM (Plan 012 §1).

Protected:

- Values never touch disk through the broker: not the state file, not
  provenance, not logs. Tests assert a canary value is absent from all three.
- Other non-root users of the VM cannot use the socket.
- Core dumps are disabled (`RLIMIT_CORE` 0), and the process is marked
  non-dumpable (`PR_SET_DUMPABLE` 0). That keeps same-uid, non-root processes
  from ptracing it or reading `/proc/<pid>/mem`.
- Issued credentials are short-lived (≤ 15 min) and revoked early when their
  session ends. Revoking the VM's Vault identity stops all new issuance.
- A restarted broker cannot revoke the child tokens of the previous run; their
  leases expire with the token TTL (at most 15 minutes).

Not protected:

- **Root in the VM can read the broker's memory**, and with it every live
  value and the VM's Vault token. This is accepted by design: the VM is the
  boundary.
- Any same-uid process can connect to the socket and ask for a checkout, as
  any harness. The allowlist and `front_end` checks only prevent accidents.
- Values returned to helpers are handed to git or kubectl, and those tools
  may cache them (kubectl caches until `expirationTimestamp`).
- Python strings cannot be zeroized. A dropped value stays in freed memory
  until it is reused.
- `vault-kv` values are standing secrets (`D0`). Revoking the checkout does not
  revoke the value.

## Standalone git credential (no daemon)

Since 0.7.0, `acb git-credential <capability-id> get|store|erase [-m MANIFEST]`
serves git directly on Windows and Linux, without a daemon, socket or child
command. The caller selects the capability; acb does not detect the harness.

It reuses the daemon's `vault-kv` issuer (`path`, explicit `fields`) and helper
delivery (`tool = "git"`, `hosts`). The standalone helper requires **exactly
one** bare host in `delivery.hosts`, with no port, path, URL syntax, trailing
dot or wildcard (ASCII DNS names / IPv4 only). This is the required host, using
the existing plural key rather than introducing a competing `host` option.
`delivery.protocol` defaults to `https`; it must match git's protocol exactly.
`username_field` and `password_field` name the two distinct selected KV fields.
Do not also declare the legacy top-level `vault` / `field` / `fields` keys.

```toml
[capability."cred:forge-bot"]
provider = "cred"
source = "vault"
harnesses = ["codex"]               # advisory; caller selects the capability
issuer = {kind = "vault-kv", path = "kv/example/forge/bot", fields = ["login", "token"]}
delivery = {rung = "helper", tool = "git", hosts = ["forge.example"], username_field = "login", password_field = "token"}
assurance = "D0"
```

The declaration also works through `acb-broker` / `acb-git-credential` (whose
existing transport is HTTPS only); the shared delivery parser and daemon apply
the same field mapping. Existing daemon declarations using canonical
`username` / `password` fields or `delivery.username` keep working there.

```sh
git config credential.https://forge.example.helper '!acb git-credential cred:forge-bot'
```

Git appends `get`, `store` or `erase` and passes attributes on stdin. On a
matching `get`, stdout contains only `username=...` and `password=...` lines.
A different or missing host/protocol, or any `port`, `path` or `url` attribute,
produces no output and exits 0, without accessing Vault. Hosts compare without
case; ports (even `:443`) and paths are never stripped or normalized. With
`credential.useHttpPath=true`, git sends a path and this host-only helper
declines the request. Duplicate scalar attributes or malformed requests are
errors. Values containing CR, LF or NUL, missing fields, and empty/non-string
fields are refused before any answer is written. `store` and `erase` consume
stdin and do nothing, even if the manifest is absent. The helper stores no
credential and `erase` does not revoke the standing forge secret.

Every failure emits no answer and one stderr line containing only its exception
class: exit 2 for declaration errors, 1 for operational errors. The identity
needs `read` on `kv/data/example/forge/bot`; `doctor` checks that grant through
`sys/capabilities-self` without reading the value. KV resolution uses the same
auth as `acb exec`, including fail-closed AppRole handling and 0.6.0's best-effort
revocation of logins acb owns, on successful or failed reads. Explicit development
`VAULT_TOKEN` values remain borrowed. The default policy normally supplies
`auth/token/revoke-self`. A value-free provenance event records each attempted
matching read; no request attributes, Vault path or field values are recorded.

There is no child command: `acb exec` refuses this capability, neither
`trusted_argv` nor `unqualified_exec` may be declared (even `false`), and no
discovery shim is needed. This removes the "any command may receive this
credential" exception. It does **not** authenticate the caller as git: any
process with access to the same Vault plane can invoke the helper protocol.
The secret is still static, available in VM memory and handed to git, so its
assurance remains `D0`; `doctor` continues to warn about that static helper.

### Per-harness wrapper and plane selection

Provision a wrapper for each harness and select it in that harness's git
configuration or launch environment. For example, `forge-codex-helper`:

```sh
#!/bin/sh
export ACB_VAULT_ENV=/example/planes/codex-vault.env
exec acb git-credential cred:forge-bot "$@"
```

On Windows a corresponding `C:/example/forge-codex-helper.cmd` can be:

```bat
@echo off
set "ACB_VAULT_ENV=C:\example\planes\codex-vault.env"
acb git-credential cred:forge-bot %*
```

Point git at the provisioned wrapper (for example
`git -c credential.https://forge.example.helper='!/example/bin/forge-codex-helper' fetch`).
An OpenCode wrapper selects its own capability ID and `ACB_VAULT_ENV` plane
instead; declare that capability in the manifest as well. Keep selection in
the caller's wrapper: no process-tree inference or optional harness detector
is part of this verb. Separate capability/plane labels are advisory within
one OS identity; Vault policy and VM boundaries determine actual access.

## Standalone kubectl credential (no daemon)

`acb kube-token <capability-id> [-m MANIFEST]` is a cross-platform (Windows and
Linux) kubectl exec-credential plugin that needs no daemon and no socket. It
authenticates to Vault the way `acb exec` does for a vault-sourced credential
(AppRole from the plane file named by `$ACB_VAULT_ENV`, the `token=""` and
fail-closed invariants), makes one write to `<mount>/creds/<role>`, and prints
one `ExecCredential` JSON line.

```toml
# Placeholders only. No `trusted_argv` / `unqualified_exec`: there is no child.
[capability."cred:example-k8s"]
provider  = "cred"
harnesses = ["claude"]
issuer    = { kind = "vault-k8s-token", mount = "kubernetes", role = "example-role",
              namespace = "example-ns", ttl = "10m" }   # ttl <= 15m; audiences, cluster_role_binding optional
delivery  = { rung = "helper", tool = "kubectl" }
```

```yaml
# kubeconfig
users:
  - name: example-agent
    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        command: acb
        args: ["kube-token", "cred:example-k8s"]
        env:
          - name: ACB_VAULT_ENV
            value: /path/to/vault.env
        interactiveMode: Never
```

The identity needs only `update` on `kubernetes/creds/example-role`;
`acb doctor` checks that grant through `sys/capabilities-self`. Unlike the
daemon path, there is no per-checkout child token and no checkout registry:
the owned Vault login token is revoked afterwards (best effort), and the
expiry reported to kubectl is the lease minus 30 seconds. On failure nothing is
printed to stdout, stderr carries only the exception class name, and the exit
code is 1 (2 for a manifest or usage problem). `acb exec` refuses a helper-rung
capability and points here.

## AppRole SecretID rotation

`acb rotate-secret-id --plane /path/to/one.env --plane /path/to/two.env`
checks one identity's explicitly listed planes; add `--apply` to rotate. The
default is a dry run: it logs in, reports the role, paths, whether rotation is
due, and the `update` grants on the mint/destroy paths, then revokes its login.
It never uses ambient Vault variables, Kubernetes auth or a developer token.
All planes must have the same address, RoleID and AppRole mount (default
`approle`). Inline and `*_FILE` deliveries follow `cred_vault`'s precedence;
relative credential-file paths resolve against the working directory.

The role's policy needs `update` on both
`auth/approle/role/example-agent/secret-id` and
`auth/approle/role/example-agent/secret-id/destroy` (substitute the mount and
role), plus lookup-self, capabilities-self and revoke-self, normally supplied
by Vault's default policy. SecretID lookup is neither needed nor attempted.
Set a finite `secret_id_ttl` and **`secret_id_num_uses=0`** (unlimited logins)
in Vault separately, then schedule this command
more frequently than that TTL. `--min-age` accepts an integer with `s`, `m`,
`h` or `d`; the default is `7d`. A missing/invalid rotation timestamp means due.

Apply mints with `rotated_by=acb` and the hostname as metadata, verifies a fresh
AppRole login, atomically replaces every delivery, destroys the old SecretID
using the new login, then revokes both login tokens in `finally` (best effort).
Other plane lines, quotes, inline comments, BOMs, line endings and file modes
are preserved, including Windows owner/group/DACLs and Linux ownership/access ACLs. A
failure to copy permissions stops the replacement before writing secret bytes.
Linux replacement directories are fsynced before destruction. No credential
backups or recovery secrets are kept: the old
SecretID remains valid until all deliveries have been replaced. Plane files
are intentionally updated only by this explicit rotation verb.

Inline deliveries get a `# acb: secret-id rotated <UTC timestamp>` comment
immediately before the secret. A `VAULT_SECRET_ID_FILE` delivery leaves its
plane unchanged and writes a sibling `<secret-file>.rotated` timestamp plus
SHA-256 digest. Metadata is replaced before the secret; it counts only when
the digest matches the current value, so a failed replacement cannot make an
old SecretID appear fresh. The SecretID file still contains only its value
and original surrounding whitespace. Shared delivery files are written once.

If a write fails, the old SecretID is kept and the single error line lists
which planes hold the new value, the old value, or could not be read. Re-run
with the **same complete plane list** and `--apply`: mixed values are accepted
only if one working login is uniquely newer by rotation timestamp, or only
one can log in and Vault definitively rejects the other (400/403; transport
errors fail closed). Recovery synchronizes to that verified value without minting
again when it has a rotation timestamp, even if `--min-age` has not elapsed,
then destroys the other value. If the sole working value has no timestamp,
it mints and verifies a fresh replacement instead of claiming the old one is new.
Working values tied for newest age are refused. Repeated interrupted recovery
can leave more than two values; the same unique-newest/sole-working rule applies.
No SecretID or token
appears in output or provenance. Exit codes: 0 success/not due, 1 operational
failure, 2 invalid or ambiguous planes. Every apply attempt emits provenance;
sink failure is reported without changing the rotation result.

Overlapping rotations lock the supplied planes and delivery paths with sibling
`.acb-rotation.lock` files. After a process crash, verify no rotation is running
before removing stale locks and retrying. Avoid concurrent manual edits. If
destroy fails after all writes, the new files stay usable and exit is 1; the
old SecretID then remains until its Vault TTL or operator cleanup (its value
is deliberately not retained for a later retry). A mint or verification failure
leaves deliveries unchanged; any unused minted SecretID likewise expires at
its configured TTL.

KV resolution and read probes (`reachable`, `capabilities_self`, `read_granted`,
including doctor) also revoke logins acb obtained by AppRole or Kubernetes auth.
Explicit `VAULT_TOKEN` values and caller-injected clients are borrowed and are
never revoked automatically. Standalone kube-token cleanup does not invalidate
the issued Kubernetes token for a pre-existing ServiceAccount. The in-VM broker
daemon's token lifetime is unchanged.

## Running it (manual, for now)

```bash
acb-broker --manifest /path/to/capabilities.toml   # Linux only; logs to stderr
git -c credential.helper= -c credential.helper=acb-git-credential fetch
```

On non-Linux platforms `acb-broker` exits 2 with an "unsupported platform"
message.

## Follow-ups

- Peer-credential extraction (`SO_PEERCRED` today) moves behind a small platform
  helper for the workstation zone (Plan 012 section 10 (d)). Not implemented.

- Switch `config.py` to the shared manifest-v2 model once WI-012-2 lands.
- CLI verbs: `acb checkouts` (read) and `acb revoke` (act, dry-run by
  default), wired to `client.list_checkouts` / `client.revoke_checkouts`.
- A systemd unit (`User=` the agent user), and `install-harness` rendering of
  the git `credential.helper` stanza and the kubeconfig `exec` block.
- Lease renewal while a tool is still using a credential (today a checkout
  simply expires and the next helper call issues a new one).
- A live pilot of one capability (P1 acceptance).
