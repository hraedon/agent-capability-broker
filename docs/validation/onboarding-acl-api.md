# Onboarding ACL policy API validation

Tested source `507b38b2405a591b0e0ba2aec0b4bbc7a622953d`, based on `5f67fef1f0024b867672c8b9db95c12a992299ee`. The only production changes replace the HVAC policy read, write and rollback deletion calls with the ACL policy methods. The committed and working-tree SHA-256 of `onboard.py` is `efa997058059d8624101e1d9ccedfab1c2263e96a480f6b866dbbc42c43ba31c`.

- `uv sync --extra dev --extra cred` created only this worktree's `.venv`; the test used HVAC 2.4.0.
- `.venv/Scripts/pytest.exe -o addopts='' -q tests/test_onboarding.py tests/test_onboarding_acl_transport.py` passed: 136 passed, 3 skipped. The new tests use a synthetic requests adapter through the real HVAC client to verify GET, PUT and DELETE under `/v1/sys/policies/acl/sample-policy`, nested policy response parsing, 404 versus 403 classification, rollback and denied rollback reporting. No HTTP traffic leaves the process.
- `.venv/Scripts/ruff.exe check .` and `.venv/Scripts/mypy.exe src` passed.
- `.venv/Scripts/pytest.exe -q` completed with four failures: `shims-json`, its conformance meta-gate, and two Windows path-string assertions in `test_cred_vault_auth.py`. The other tests completed, with expected skips; the full suite did not pass. All four failures were independently reproduced against a clean `git archive` of baseline `5f67fef` using the same isolated interpreter. The conformance fixture uses HOME isolation while Windows resolves user-profile paths separately; the two credential tests compare raw Windows paths against strings that escape backslashes. No unrelated baseline files were changed. The full run occurred before the final added denied-rollback transport test; the focused run above includes that test.
- `git diff --check` passed.

The synthetic adapter tests verify HVAC request construction and response handling, not a live Vault server, the operator's token, policy grant, or installed package. No real Vault call, credential read or installed-environment mutation was performed. Independent review and the native work-item gate remain pending.
