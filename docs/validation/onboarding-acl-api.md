# Onboarding ACL policy API validation

Tested source `507b38b2405a591b0e0ba2aec0b4bbc7a622953d`, based on `5f67fef1f0024b867672c8b9db95c12a992299ee`. The only production changes replace the HVAC policy read, write and rollback deletion calls with the ACL policy methods. The committed and working-tree SHA-256 of `onboard.py` is `efa997058059d8624101e1d9ccedfab1c2263e96a480f6b866dbbc42c43ba31c`.

- `uv sync --extra dev --extra cred` created only this worktree's `.venv`; the test used HVAC 2.4.0.
- `.venv/Scripts/pytest.exe -o addopts='' -q tests/test_onboarding.py tests/test_onboarding_acl_transport.py` passed: 136 passed, 3 skipped. The new tests use a synthetic requests adapter through the real HVAC client to verify GET, PUT and DELETE under `/v1/sys/policies/acl/sample-policy`, nested policy response parsing, 404 versus 403 classification, rollback and denied rollback reporting. No HTTP traffic leaves the process.
- `.venv/Scripts/ruff.exe check .` and `.venv/Scripts/mypy.exe src` passed.
- `.venv/Scripts/pytest.exe -q` completed with four failures: `shims-json`, its conformance meta-gate, and two Windows path-string assertions in `test_cred_vault_auth.py`. The other tests completed, with expected skips; the full suite did not pass. All four failures were independently reproduced against a clean `git archive` of baseline `5f67fef` using the same isolated interpreter. The conformance fixture uses HOME isolation while Windows resolves user-profile paths separately; the two credential tests compare raw Windows paths against strings that escape backslashes. No unrelated baseline files were changed. The full run occurred before the final added denied-rollback transport test; the focused run above includes that test.
- `git diff --check` passed.

The synthetic adapter tests verify HVAC request construction and response handling, not a live Vault server, the operator's token, policy grant, or installed package. No real Vault call, credential read or installed-environment mutation was performed. Independent review and the native work-item gate remain pending.

## Accepted source and local runtime qualification

Actual independent Google security/general review and the native gate accepted `118718e3bd31b62dc447535d407c2cc41794d522`; see [review summary](../reviews/onboarding-acl-api/independent-review.md). OpenAI implementation was isolated and claimed before edits. No emergency path or same-lineage waiver was used; provenance is native work state, source/module hashes and private execution receipts, with no extra suite adapter claim.

After acceptance, the operator's installed onboarding module was repaired to exact reviewed SHA-256 `efa997058059d8624101e1d9ccedfab1c2263e96a480f6b866dbbc42c43ba31c`, with code/RECORD backups and only its RECORD row updated. All other installed Python sources and both replaced-file ACLs were verified unchanged. Existing adapter behavior was preserved by avoiding a whole-package reinstall. The installed real HVAC client then passed synthetic GET/PUT/DELETE and rollback route checks with zero network calls; a second repair Plan reported already repaired. The CLI and existing capability's read-only local Plan still passed.

This is a local runtime repair, not a published package release or authenticated Vault qualification. A later whole-package reinstall must include this source correction while preserving the separately maintained adapter behavior. The full-suite baseline failures remain open; they were not hidden by the targeted repair.
