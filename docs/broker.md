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
   └─ state file: checkout ids + lease ids (never values)
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
issuer kind, assurance, revocation handle (a Vault lease id, or none for
`vault-kv`), and a pending-revocation flag. **Never a value.**

On startup the broker revokes every record left in the file (crash cleanup).
A revocation that fails stays recorded as pending and the reaper retries it.

## Lifetime and revocation

A checkout is revoked when it expires (the reaper runs every 5s), when the
harness process it was attributed to exits (session end, guarded against PID
reuse by process start time), on `revoke`, and on SIGTERM/SIGINT. The value is
dropped from memory as soon as revocation starts.

- `vault-k8s-token`: writes `<mount>/creds/<role>` with
  `kubernetes_namespace` and `ttl`; revokes with
  `sys/leases/revoke/<lease_id>`. Using the URL form means the VM policy can
  scope revocation to its own engine paths
  (`sys/leases/revoke/<mount>/creds/<role>/*`) instead of granting
  `sys/leases/revoke` broadly.
- `vault-kv`: a static read. Revocation only forgets the in-memory copy; the
  value stays valid in Vault. That is why it is `D0`.
- `remote-mint`: refuses with `not_implemented` until `acb-ops` exists.

## Vault identity

The Vault issuers use `cred_vault.authenticated_client(allow_token=False)`:
the WI-016 invariants (`token=""`, fail-closed AppRole) plus a refusal of a
bare `VAULT_TOKEN`. The broker authenticates once with the VM's AppRole or
Kubernetes identity and re-authenticates once on an auth error. `hvac` is
imported only when a Vault issuer first runs.

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

## Running it (manual, for now)

```bash
acb-broker --manifest /path/to/capabilities.toml   # Linux only; logs to stderr
git -c credential.helper= -c credential.helper=acb-git-credential fetch
```

On non-Linux platforms `acb-broker` exits 2 with an "unsupported platform"
message.

## Follow-ups

- Switch `config.py` to the shared manifest-v2 model once WI-012-2 lands.
- CLI verbs: `acb checkouts` (read) and `acb revoke` (act, dry-run by
  default), wired to `client.list_checkouts` / `client.revoke_checkouts`.
- A systemd unit (`User=` the agent user), and `install-harness` rendering of
  the git `credential.helper` stanza and the kubeconfig `exec` block.
- Lease renewal while a tool is still using a credential (today a checkout
  simply expires and the next helper call issues a new one).
- A live pilot of one capability (P1 acceptance).
