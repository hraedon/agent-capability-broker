# Live proof — the e2e half of acb

**Plan 006 WI-1.2.** The `cred` half of acb is load-bearing daily (the `cred-*`
skills *are* acb shims). The `e2e` half was asserted, never proven: `doctor`
reported Playwright wiring `present_ok`, but no browser task had ever been
driven through the capability and recorded. This is the recorded proof.

## What it proves

`scripts/e2e_live_proof.py` runs three phases and exits non-zero if any fails:

| Phase | Claim under test |
| --- | --- |
| 1 | `acb exec e2e:chromium -- …` brokers the provisioned browser into a child, and the child navigates a locally served page and asserts its rendered content. |
| 2 | With Playwright wiring present, `doctor`'s check `e2e:chromium@opencode` is `ok`; **removing the wiring flips it to a named failing check** (`fail`, top-level `ok: false`, non-zero exit). Verified, not asserted — a decorative probe fails this phase. |
| 3 | With no browser binaries reachable, `acb exec` fails with the contract-v1 error envelope (`E2E_UNAVAILABLE`, exit 2), launches nothing, and prints no traceback. |

The child (`scripts/e2e_browser_task.py`) reads **only** what acb injected —
`ACB_E2E_BACKEND`, `ACB_E2E_EXECUTABLE` — and does no capability discovery of
its own. That is the point: if the capability is not brokered, the task cannot
run.

## What it does not touch

The script is hermetic. It serves its own page on loopback, writes its own
temporary manifest, temporary harness configs and temporary provenance state,
and **never reads or writes** the operator's real `capabilities.toml`,
`~/.claude/settings.json`, or `~/.config/opencode/opencode.json`. Phase 2's
"remove the wiring" edits a temp file, never a live harness config.

## Running it

```bash
uv venv && uv pip install -e ".[dev]"
.venv/bin/python scripts/e2e_live_proof.py        # --keep to retain the workspace
```

Prerequisite: Playwright browser binaries (`playwright install chromium`, or an
existing `~/.cache/ms-playwright`). With none installed the script exits **3**
and says the proof was *not run* — an honest "unproven", never a pass.

## Recorded result

**2026-07-24, operator Linux box — PROOF PASSED** (all three phases), against
`chromium-1228` in `~/.cache/ms-playwright`:

```
[PASS] 1 exec drives a real browser task: exit=0 stdout="PASS: rendered
       http://127.0.0.1:<port>/page.html and found 'ACB-E2E-PROOF-MARKER' in the DOM"
[PASS] 2a doctor sees the wired capability: check e2e:chromium@opencode = ok
[PASS] 2b removing the wiring flips doctor to a NAMED failing check:
       check e2e:chromium@opencode = fail, ok=False, exit=1
[PASS] 3 unprovisioned exec fails with the contract-v1 envelope: exit=2 code='E2E_UNAVAILABLE'
```

### Host caveat, recorded honestly

This box (Ubuntu 23.10+ AppArmor policy) restricts unprivileged user
namespaces, so Chromium aborts with `No usable sandbox!` unless the renderer
sandbox is dropped. The task therefore takes an **opt-in** `--allow-no-sandbox`
flag: by default it refuses and explains, and with the flag it retries once and
prints a `note:` saying the sandbox was disabled. The proof passes that flag
(the page under test is loopback-only). Dropping the sandbox is never silent.

### Scope actually covered

Plan 006 WI-1.2 asks for the proof "through Claude Code and opencode". What is
proven here is the capability itself — brokering and driving a real browser
through `acb exec` — plus the doctor negative path per harness config. The
per-harness *invocation* half (an agent inside each harness invoking the shim)
is not scripted; the e2e capability renders MCP wiring rather than a `cred-*`
style discovery shim, so there is no harness-side artifact for a script to
invoke non-interactively. That remains open.
