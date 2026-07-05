# Publication / sanitization review

Gate before flipping the repository from **private** to **public**. The standing
rule (portfolio-wide): no work-domain identifiers, secrets, or live-infra detail
in the committed tree **or its history** — a public repo exposes every past
commit, not just `HEAD`.

## Review of 2026-06-16

**Scope:** all git-tracked files at the reviewed commit **and** the full commit
history (`git log -p --all`). Reviewer: Claude (Opus 4.8), with an independent
second opinion from an opencode-hosted agent (different harness + model).

### Method
- Tracked-tree sweep for: Vault host/addr, AppRole/role_id/secret_id *values*,
  bearer-token values, `kv/<real-mount>` paths, real service-account names,
  internal hostnames (`mvmc*`, `ad.hraedon.com`), IP addresses, the work-domain
  name, internal/corporate domains, emails.
- Full-history sweep for the same (squash-merged `main`, PRs #1–#5).
- Independent opencode second opinion over the tracked tree.

### Findings and remediation
History was **clean** — no secret values, no Vault host, no internal hostnames or
IPs in any commit. Seven low-severity leaks in the tracked tree, each a real
identifier that had slipped past the project's own placeholder convention
(`AGENTS.md`: "neutral placeholders only"). The first three were found by the
primary review; the last four by the independent opencode second opinion. All
fixed before publication:

| # | Where | Was | Now | Found by |
|---|---|---|---|---|
| 1 | `docs/capability-model.md` §2 | a real service-account name (redacted) | `cred:svc-bot` | primary |
| 2 | `src/.../cred_vault.py` `_split_mount` docstring | `kv/homelab/ad/...` (mirrors real mount) | `kv/example/ad/...` | primary |
| 3 | `plans/002-act-path.md` | "z.ai server's bearer token" (names a real provider) | "a sibling server's bearer token" | primary |
| 4 | `.gitignore` | `.cw-vault-ci.env` (names a real infra file; redundant with `*-vault*.env`) | removed | opencode |
| 5 | `AGENTS.md` | "the cert-watch web.config-no-clobber lesson" (real project) | "config-no-clobber lesson from a sibling tool" | opencode |
| 6 | `README.md` ×2 | "the cert-watch VM", "the homelab AppRoles" | "a remote VM", "the self-hosted AppRoles" | opencode |
| 7 | `tests/test_reconcile.py` | `"zai"` MCP server name (matches a real vendor) | `"sibling"` | opencode |

No secrets were ever committed: the `cred` provider reads `role_id`/`secret_id`/
`VAULT_TOKEN` from the environment (never hardcoded); test tokens are obviously
synthetic (`super-secret-token-value`, `p@ssw0rd-do-not-leak-*`); real configs
and manifests are gitignored (`samples/`, `capabilities.toml`, `*.env`). The live
Vault validation in the session used a `mktemp` manifest that was never tracked.

### Accepted, not flagged
- `hraedon` as author / in GitHub URLs — the maintainer's public identity, used
  by the already-public sibling repos (`adcs-lens`, `gpo-lens`). Not the
  work domain.
- `kubernetes.io/...serviceaccount/token` in `cred_vault.py` — the standard,
  documented in-cluster token path, not infra-specific.
- Placeholder identifiers (`svc-bot`, `kv/example/...`, `EXAMPLE.local`).

### Independent second opinion (opencode)
An opencode-hosted agent reviewed all 23 tracked files independently and
concurred on the core finding: **no actual secret values, tokens, API keys, IPs,
or live endpoints are committed** — material is read from env vars, paths are
placeholders, and test tokens are obviously synthetic. It surfaced findings #4–#7
above (real project/environment/vendor *names*), all since remediated, and
explicitly cleared the `hraedon` GitHub identity, the standard k8s token path, and
the synthetic test secrets.

## Verdict
**Clear to go public.** Both reviewers concur: history is clean of secrets, and
all real identifiers found in the tree have been replaced with placeholders.
A final post-remediation sweep of the tracked tree returns no real identifiers,
and the full gate set (ruff + mypy-strict + 32 tests) is green.

Re-run this review (tree **and** history) before any future publication that adds
new history.
