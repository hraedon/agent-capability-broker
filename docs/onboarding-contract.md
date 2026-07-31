# Onboarding contract (Plan 009)

Derivation rules, refusal matrix, and value-transit guarantee for
`acb onboard`.  The manifest entry is the single declaration; every provisioned
artifact is derived from it deterministically, so there is nothing to drift.

`acb onboard cred:<name>` is a dry run.  `--check` audits.  `--apply` acts.

## Derivation rules

Given a `cred` capability with `source = "vault"` (the default):

| Artifact | Derived from | Rule |
|---|---|---|
| Policy name | `cap.name` | `acb-<name>` |
| AppRole name | `cap.name` | `acb-<name>` |
| Policy HCL | `options.vault` | `read` on `<mount>/data/<path>` and `<mount>/metadata/<path>`, nothing else |
| AppRole config | fixed | `token_ttl=3600`, `token_max_ttl=14400`, `secret_id_ttl=0`, `secret_id_num_uses=0` |
| Plane `.env` | `options.vault_env` + declared harnesses | `providers.vault_env_path(cap, adapter)` — one file **per declared harness** |
| KV path | `options.vault` | verbatim, after segment validation |
| Fields | `options.field` / `options.fields` | verbatim |

Policy/role name components must match `^[a-zA-Z0-9][a-zA-Z0-9._-]*$`.  Every
segment of the KV path must match the same pattern: the path is interpolated
into a quoted HCL string, so a segment containing `"`, `{`, `}`, whitespace, a
newline, a glob, or a traversal component would let a manifest append policy
stanzas of its own choosing.

### Where the plane file lives

**One resolver, used by everything.**  `onboard.plane_targets` calls
`providers.vault_env_path` — the same function that renders `ACB_VAULT_ENV`
into a harness shim and that `doctor` hands to `cred_vault.reachable`.  The
consequences are deliberate:

- The default is the adapter's own `vault_env_path`: `<harness config>/vault.env`
  (`~/.claude/vault.env`, `~/.config/opencode/vault.env`, `$CODEX_HOME/vault.env`,
  `~/.hermes/vault.env`).
- `options.vault_env` is a **bare filename** resolved beside that same harness
  config.  An absolute path, a path separator, or a traversal component is a
  refusal — on the write side as well as the read side (the class fixed in
  4d6e376: `providers._assert_safe_path_component`).  Nothing resolves against
  the process working directory.
- A capability declared for *n* harnesses gets *n* plane files, each holding a
  **distinct SecretID** from the one AppRole, so one harness's credential can be
  revoked without disturbing the others.
- Provisioning a capability-scoped AppRole into a harness's *shared*
  `vault.env` is refused when another `source = "vault"` cred capability
  resolves to the same file: that AppRole is least-privilege for one KV path and
  would break every other capability reading that plane.  Declare
  `vault_env = "<name>.env"` to get a dedicated plane.

### Estate note: reference shape

This estate's Vault refs are `vault:<mount>/<path…>/<field>` on mount `kv/` —
the last path segment is the *field*.  The `#field` form that appears in older
runbooks has never resolved.  `options.vault` is therefore the path **without**
the field, and `options.field`/`options.fields` name the fields; the two compose
into the estate's ref shape without transformation.  A component resolves
`vault:` refs only when `hvac` is importable in its own environment.

## Refusal matrix

Planning-time — no I/O, checked before any Vault contact:

| Condition | Outcome |
|---|---|
| Provider is not `cred` | refuse |
| `source` is not `vault` | refuse (suite/AKV/Windows follow Plan 008) |
| No `vault` path, or not `<mount>/<path>` | refuse |
| A `vault` path segment is not a safe path component | refuse (HCL injection) |
| No field selection, or an empty `fields` list | refuse |
| Name contains invalid characters | refuse |
| `vault_env` is not a bare filename | refuse (write-path traversal) |
| The derived plane file is another capability's access plane | refuse |
| `--apply`/`--check` with no admin plane requested | `--apply` refuses; `--check` runs offline and reports `unknown` |
| Admin plane file absent, unreadable, or not UTF-8 | refuse |
| Admin plane declares no `VAULT_ADDR` | refuse (an ambient `VAULT_ADDR` is never used) |
| Admin plane declares no auth material | refuse (an ambient `$VAULT_TOKEN`/`~/.vault-token` is never used) |
| Admin plane fails to authenticate | refuse — **never** a degrade to offline |
| Vault unreachable | operational error, `retryable: true` |

Vault-state, resolved by `--check` and converged by `--apply`:

| Condition | Outcome |
|---|---|
| Policy absent | create |
| Policy exists, same scope | converge (no write) |
| Policy exists, different scope | converge to the manifest-derived scope |
| AppRole absent | create |
| AppRole exists, bound to this policy with the derived config | converge (no write) |
| AppRole exists, different policies or TTLs | converge to the derived config |
| Plane file matching this AppRole, mode 0600 | no-op — **no SecretID is minted** |
| Plane file with a stale role_id | mint, back up to `.bak`, rewrite, revoke the stale SecretID |
| Plane file present but unreadable | abort (never replace what could not be inspected) |
| KV path holds a value | **never overwrite** — `write_kv` is skipped |
| KV metadata unreadable | unknown; the write still carries `cas=0`, so Vault enforces |

## Never overwriting a value

The KV write **always** carries `cas=0`.  Vault, not acb, is the enforcer:
`cas=0` succeeds only when the path has no current version, atomically.

The metadata probe is advisory and tristate — present / absent / *could not
determine* — and "could not determine" never grants permission to write.  This
matters because the least-privilege onboarding AppRole recommended below is
exactly the credential that can write a path but cannot read its metadata; a
guard that scored "permission denied" as "no value here" would overwrite a live
secret.  A `cas` rejection is reported as `skipped — never overwritten`, not as
a failure, so a re-run with values still supplied stays exit 0.

There is no force flag.  Rotation is a different verb for a different plan.

## Idempotency, abort, and rollback

`--apply` is idempotent: a second run mints no SecretID, rewrites no plane file,
and writes neither policy nor role, because each is compared against the derived
expectation first.  Plane files are written via `O_CREAT|O_EXCL` at mode `0600`
(no chmod-after-write window) and moved into place with `os.replace`, which
overwrites an existing `.bak` on every platform.

`--apply` is **fail-fast**: the first failed step aborts the remainder, so a
failed `create_policy` cannot leave an AppRole bound to a dangling policy with a
SecretID minted and a value transited.

On failure, everything **this run created** is unwound in reverse order — the
plane file (restored from `.bak` if there was one), the minted SecretID
(destroyed by accessor), the AppRole, the policy.  Objects that already existed
are operator state and are left alone.  An unwind step that itself fails is
reported as `rollback_failed` and names what remains for manual cleanup.

## Value-transit guarantee

- `--values-from none` (default): structure only, no value touches Vault.
- `--values-from stdin`: JSON on stdin, read once, written once, cleared
  in-process after the write (best-effort, same caveat as `exec`).
- `--values-from file:<path>`: read once, never copied.
- `--values-from k8s:<ns>/<secret>`: reserved; currently a usage error.

Values never appear in argv, logs, provenance, receipts, dry-run output, or
`--check` reports.  Neither do SecretIDs, role_ids beyond the plane file, or
admin tokens.

**Upstream exception text is never printed.**  Every failure detail is built
from `type(exc).__name__` only, because hvac/requests/Vault error strings can
echo the request body — and on the KV write path the request body *is* the
secret.  `_is_cas_conflict` inspects a message to classify it and never returns
or logs it.  A malformed `--values-from` document is reported by line and column,
not by content.

## Privileged plane

Onboarding requires `--admin-env <file>` or `$ACB_VAULT_ADMIN_ENV`: a file
declaring `VAULT_ADDR` plus one of `VAULT_TOKEN`, `VAULT_ROLE_ID` +
`VAULT_SECRET_ID`, or `VAULT_K8S_ROLE`.  The capability's own plane is never used
to create itself.

Both the address and the credential come from that file.  `hvac.Client` is
constructed with `token=""` — not `None` — because `None` triggers hvac's
`get_token_from_env()`, which reads `$VAULT_TOKEN` and then `~/.vault-token`;
the empty string is what defeats that fallback.  The `url` is pinned for the
same reason.

A least-privilege onboarding AppRole is recommended over an admin token.  It
needs:

```hcl
path "sys/policies/acl/acb-*"        { capabilities = ["create", "update", "read", "delete"] }
path "auth/approle/role/acb-*"       { capabilities = ["create", "update", "read", "delete"] }
path "auth/approle/role/acb-*/role-id"   { capabilities = ["read"] }
path "auth/approle/role/acb-*/secret-id" { capabilities = ["create", "update"] }
path "auth/approle/role/acb-*/secret-id/lookup"            { capabilities = ["create", "update"] }
path "auth/approle/role/acb-*/secret-id-accessor/destroy"   { capabilities = ["create", "update"] }
path "<mount>/data/<path>"           { capabilities = ["create"] }
```

Note what is *absent*: no `read` on `<mount>/data/*` and no `<mount>/metadata/*`.
Such a credential cannot read the metadata probe — by design — which is why
never-overwrite rests on `cas=0` rather than on the probe.

## Exit codes

Per suite CLI contract v1 §3, with no overloading:

| Code | Meaning |
|---|---|
| 0 | success — plan rendered, `--check` clean, or `--apply` completed |
| 1 | operational — refusal, drift/unverified state, apply failure, Vault unreachable |
| 2 | usage — invalid capability id, unknown capability, `--check` with `--apply`, unknown `--values-from` |

Under `--json`, exit 0 and a not-clean `--check` emit a report document
(`{"ok": …, "mode": …, …}`); operational and usage errors emit the contract error
envelope.  `--apply` failures carry `partial: {"succeeded": n, "failed": m}`.
