---
model: qwen3.8-max-preview
datetime: 2026-07-26T12:30Z
project: agent-capability-broker (acb)
---

# Session Reflection — 2026-07-26

**Work summary:** Implemented Plan 008's remaining ACB-owned work items: WI-1.3 backend conformance (synthetic vault/azure/windows provider tests covering unavailable, unauthorized, missing-ref, valid, rotation, redacted-failure), WI-3.2 Slice 1 Windows-host conformance (trusted_argv matching, minimal child env, process-tree containment, redacted failures, provenance — all synthetic), and WI-3.2 Slice 2 qualified launcher contract (request/result schemas + fake-launcher conformance fixture). Two rounds of adversarial review drove hardening: taskkill PATH trust removed, fake launcher credential leak fixed, exception notes cleared, close_fds made explicit, expected_capability_id added to LauncherRequest. Validated Windows-specific paths on mvmcitest01 (real Windows host).

---

## On the project

acb's inject-don't-surface property is genuinely well-enforced at this point. The suite exec path is the most hardened: exact trusted_argv, minimal child env, process-group containment, value-free provenance, checkout receipts. The launcher contract module formalizes what a consuming component must accept and produce, which is the right boundary — acb stays a broker, not an operator.

The tension I see: the bare/strict exec paths (non-suite) are materially less contained than the suite path. No process group, no timeout, no close_fds explicit. This is tracked as WI-012 but it's the kind of asymmetry that will bite — an operator who uses `source = "vault"` with `inject` declared gets the strict path's naming validation but not the suite path's containment. The plan correctly scopes containment to suite-only for now, but the design doc's language ("The bounded runner owns a new POSIX session") reads as universal.

## On the work done

Confident in: the backend conformance tests are thorough — six cases × three backends, all through the public resolver interface, all canary-checked. The launcher contract is clean and self-consistent; the fake launcher genuinely conforms (clears creds before output, validates receipt, fails closed on missing fields). The Windows validation on mvmcitest01 proved the real taskkill/process-group mechanics work.

Less confident: the `_terminate_process_tree` POSIX path has a theoretical PID-reuse race that both reviewers flagged. It's pre-existing and the window is tiny, but it's the kind of thing that only matters in production under load. Also, the launcher contract's `from_environ` defaulting to `os.environ` is a footgun for test authors — a reviewer flagged it and I assessed it as acceptable (the child IS reading its own env), but requiring an explicit parameter would be safer.

## On what remains

**Needed before Plan 008 can claim completion:**
- WI-1.3 live backend conformance (credential-gated CI jobs for real Vault/Azure/Windows)
- WI-3.2 Slice 3: live composition proof on a resettable Windows target
- WI-3.3: correlated Codex/evidence-lab proof
- Live Codex interop proof (Plan 007 WI-3.1)

**Nice to have / tracked elsewhere:**
- WI-012: containment on bare/strict exec paths
- Resolution timeout for the suite resolver (no timeout on `resolver.resolve()` — a hung backend blocks exec indefinitely)
- Executable existence check in `_trusted_argv` before resolution (currently only validates the path is absolute)
- `_suite_child_env` allowlist is Windows-oriented; on POSIX the child gets no PATH (fine for absolute trusted_argv, but worth documenting)

## Gaps to flag

- **No resolution timeout** (`secret_sources.py:242`): `resolver.resolve(ref)` has no timeout. A hung regista backend blocks `acb exec` indefinitely. The child timeout doesn't help because resolution happens before launch.
- **`_trusted_argv` doesn't check file existence** (`secret_sources.py:134`): A typo'd manifest path passes validation, secrets resolve, then exec fails. Fail-closed would check `Path(executable).is_file()` at validation time.
- **`_suite_child_env` allowlist is Windows-centric** (`providers.py:100-102`): `SYSTEMROOT`, `WINDIR` are in the allowlist but `PATH`, `HOME`, `USER` are not. On POSIX, a suite child gets an empty PATH. The absolute trusted_argv makes this work, but a launcher that spawns helpers will fail.
- **PID-reuse race in POSIX `_terminate_process_tree`** (`providers.py:884-903`): After the direct child exits, the PGID can be recycled. The loop may signal an unrelated group. Pre-existing, documented limitation, but worth a cgroup-based fix for production.
- **`OperationResult.status` is open-ended** (`launcher_contract.py`): `LauncherResult.status` is validated against a closed set but operation statuses accept any string. A consuming component can't rely on a fixed vocabulary.
