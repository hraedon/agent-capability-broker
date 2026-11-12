# Desktop Codex

The desktop plugin supplies `check-capabilities` and `use-capability` workflows.
The Python CLI, capability manifest, provider dependencies, and credentials
remain host prerequisites. Installing the plugin does not copy credentials,
provision a browser, or grant a new operation.

Install the CLI in your Python environment (`uv tool install
"agent-capability-broker-hraedon[cred]"` for the published Vault client).
For a source checkout, use `uv pip install --python <venv-python> -e ".[cred]"`.
On Windows confirm `Get-Command acb.exe` succeeds: a POSIX `acb` shell wrapper
is not a PowerShell executable. Restart the desktop app after changing PATH.

From this repository, register its local marketplace and install the plugin:

```text
codex plugin marketplace add .
codex plugin add agent-capability-broker@agent-capability-broker-local
```

Alternatively select the local marketplace in the desktop Plugins directory.
The catalog points only at `plugins/agent-capability-broker`, keeping virtual
environments, Git history, and machine configuration outside the plugin cache.
Open a new chat and select `check-capabilities` or ask to check ACB availability.
Use the skill name shown by the client; plugin skills may be namespaced.

For host-specific credential discovery, ensure the operator's manifest lists
`codex` for the intended capabilities. Preview and then install the wiring:

```text
acb install-harness codex --dry-run --json
acb install-harness codex --json
acb doctor --json
```

Dry-run exits 2 by contract. Credential skills are create-only under
`$HOME/.agents/skills`. `ACB_CODEX_SKILLS` overrides that directory for isolated
testing; `ACB_CODEX_HOME`, then `CODEX_HOME`, select the independent config root.
Vault plane files remain under the config root (or the capability's configured
override). No credentials are embedded in the plugin or generated skills.
Existing skills are preserved, so inspect any named conflicts or clobbered
surface findings. Earlier versions wrote skills under `$CODEX_HOME/skills`;
they are left intact. Compare them before manually removing duplicates.

Codex MCP configuration remains read-only. Browser MCP additions return
`unsupported`; a static plugin is not a substitute for backend qualification.
Codex remains outside stable `install-harness all` until the suite's live
interop proof is complete. A successful synthetic test does not promote it.

Keep Codex-specific actor/producer settings in its process environment rather
than changing a shared ZCode profile. A local Windows install and a remote
Linux execution host each need their own CLI, manifest and backend access.

Remove the workflow plugin with
`codex plugin remove agent-capability-broker@agent-capability-broker-local`.
This does not remove separately installed capability shims or provider files.
ACB has no ownership-tracked shim uninstall; compare generated files before
removing them manually.

Packaging follows the [official plugin documentation](https://developers.openai.com/plugins/build/plugins).

## Verification on Windows (2026-10-15)

The focused adapter, plugin, installer, surface-audit and shim tests passed
55 tests. Changed Python files passed Ruff; source passed mypy. Both plugin
skills passed frontmatter validation. An isolated `CODEX_HOME` accepted actual
CLI marketplace registration, install/list, removal and reinstallation; all
three cached files matched the source (4,523 bytes).

The broader suite had seven failures in unchanged tests: two Vault refusal
messages use repr-escaped Windows paths where assertions expect raw paths,
and five identifier-gate tests require symlink privileges unavailable in this
session. The two path failures were reproduced on the original checkout.
No credential checkout, browser execution or live desktop skill selection was
claimed from these tests. The everyday desktop profile was not changed.

After the owner authorized local installation, the plugin was installed and
enabled in the Windows Codex profile, with the source-built CLI and optional
Vault client installed as a native `acb.exe`. Cached plugin bytes matched the
source. Live `acb doctor --json` exited zero. The existing workstation manifest
declares its nine credential capabilities for ZCode; Codex checks remain
not-applicable. Installation did not expand those grants or copy Vault material.

### Real read-only capability check (2026-10-15)

After the owner authorized a real capability test, the live Codex check for
`cred:gitea-readonly` reported its shim present and broker reachable. Executing
native curl through `acb exec` then checked out the Vault-backed credential
and made an authenticated HTTPS `GET /api/v1/user`: HTTP 200, process exit 0.
The unauthenticated control returned HTTP 403. Curl imported the injected
token through its environment-variable expansion; the command line contained
only the variable placeholder. No token or account response body was printed,
and the response body was discarded. No service settings or repository data
were changed. This proves one credential checkout and authenticated read on
this workstation; it does not qualify other capabilities or automatic hooks.
