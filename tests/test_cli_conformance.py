"""acb's CLI run through the CLI contract v1 conformance kit (Plan 018 WI-2).

The kit is the centrally versioned package ``agent_suite.conformance``, consumed
pinned as ``agent-suite-conformance==1.1.0`` from PyPI (Plan 019 B1) via the
``[dev]`` extra — never copied, never imported by runtime code. These are acb's
component-side fixtures against its own CLI.

Scope note (acb WI-014, the safe first pass): acb is more delicate than the B3
audit's "cleanest target" framing — its act-path verbs (``exec`` /
``install-harness`` / ``reconcile`` / ``register``) return exit 2 on operational
errors too, and that 2 is load-bearing (``install-harness --dry-run`` = 2 is a
deliberate "would-install" signal ``_cmd_install_harness_all`` consumes; ``exec``
is the live ``cred-*`` skill path). So this pass conforms only the **read-only**
``doctor`` operational-error path (the hermetic, non-load-bearing one) plus the
framework-level §1/§2/§4 guarantees, and adds a top-level envelope/no-traceback
boundary. Act-path exit-code reclassification is deferred to a follow-up with
live cred-skill validation, so no ErrorCase is asserted over those verbs here.
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

# Installed by the [dev] extra as a pinned PyPI dep (fails loudly in CI, never a
# silent skip); importorskip keeps a kit-less local checkout from erroring.
conformance = pytest.importorskip("agent_suite.conformance")

BrokenPipeCase = conformance.BrokenPipeCase
ErrorCase = conformance.ErrorCase
SuccessCase = conformance.SuccessCase
UsageCase = conformance.UsageCase
assert_cases_declared = conformance.assert_cases_declared
run_broken_pipe_case = conformance.run_broken_pipe_case
run_error_case = conformance.run_error_case
run_success_case = conformance.run_success_case
run_usage_case = conformance.run_usage_case

_CLI = (sys.executable, "-m", "agent_capability_broker")

# An isolated, empty HOME so `shims` finds no harness shim surface (surfaces
# empty -> no parity gap -> exit 0), and the ACB config-path overrides + XDG root
# are stripped so a populated operator/dev environment can't leak in and make the
# read non-hermetic.
_EMPTY_HOME = tempfile.mkdtemp(prefix="acb-conformance-home-")
_HERMETIC_UNSET = (
    "ACB_MANIFEST",
    "ACB_CLAUDE_SETTINGS",
    "ACB_OPENCODE_CONFIG",
    "ACB_HERMES_CONFIG",
    "ACB_STATE_DIR",
    "ACB_CODEX_HOME",
    "CODEX_HOME",
    "XDG_CONFIG_HOME",
)

# A manifest path that cannot resolve, forcing the documented operational error.
_MISSING_MANIFEST = "/nonexistent/acb-conformance/capabilities.toml"

# Plan 009 `onboard` fixtures (acb WI-015 M8: the verb shipped with zero
# conformance cases and an exit 2 that meant three different things).
#
# `onboard`'s dry-run is hermetic by construction: without --admin-env it makes
# no Vault call and no filesystem write, so it is a legitimate SuccessCase. The
# manifest declares `vault_env` so the derived plane path is a dedicated file
# beside the (empty, nonexistent) harness config rather than a shared one.
_ONBOARD_DIR = tempfile.mkdtemp(prefix="acb-conformance-onboard-")
_ONBOARD_MANIFEST = os.path.join(_ONBOARD_DIR, "capabilities.toml")
with open(_ONBOARD_MANIFEST, "w", encoding="utf-8") as _fh:
    _fh.write(
        '[capability."cred:conformance-bot"]\n'
        'provider = "cred"\n'
        'harnesses = ["claude"]\n'
        'vault = "kv/agent-suite/qual/conformance-bot"\n'
        'fields = ["username", "password"]\n'
        'vault_env = "conformance-bot.env"\n'
        "\n"
        # A suite-source capability: the documented planning-time refusal, and
        # the hermetic operational-error path for this verb.
        '[capability."cred:conformance-suite"]\n'
        'provider = "cred"\n'
        'harnesses = ["claude"]\n'
        'source = "suite"\n'
        'vault = "kv/agent-suite/qual/conformance-suite"\n'
        'fields = ["username"]\n'
    )

# An admin-plane path that cannot exist: `onboard --check` must treat it as an
# error rather than degrading to an offline "clean" report.
_MISSING_ADMIN_ENV = os.path.join(_ONBOARD_DIR, "no-such-admin.env")

# An admin plane that declares an address but no auth material. This is the M5
# case: `hvac.Client(url, token=None)` would fall back to $VAULT_TOKEN and then
# ~/.vault-token, so the ambient sentinel the ErrorCase injects is genuinely in
# scope here. acb must refuse *and* must not echo the sentinel.
_ADDR_ONLY_ADMIN_ENV = os.path.join(_ONBOARD_DIR, "addr-only-admin.env")
with open(_ADDR_ONLY_ADMIN_ENV, "w", encoding="utf-8") as _fh:
    _fh.write("VAULT_ADDR=http://127.0.0.1:8200\n")


SUCCESS_CASES = [
    # `shims --json` is a pure filesystem read: no store, no manifest, JSON out.
    SuccessCase(
        name="shims-json",
        argv=(*_CLI, "shims", "--json"),
        env={"HOME": _EMPTY_HOME},
        unset_env=_HERMETIC_UNSET,
    ),
    # `onboard` dry-run: derives the plan, contacts nothing, exit 0. Pins the
    # taxonomy fix — this path used to exit 2 ("dry-run success"), colliding
    # with both refusal and usage.
    SuccessCase(
        name="onboard-dry-run-json",
        argv=(
            *_CLI, "onboard", "cred:conformance-bot",
            "--manifest", _ONBOARD_MANIFEST, "--json",
        ),
        env={"HOME": _EMPTY_HOME},
        unset_env=(*_HERMETIC_UNSET, "ACB_VAULT_ADMIN_ENV", "ACB_VAULT_ENV"),
    ),
]

ERROR_CASES = [
    # A missing manifest is an operational failure: doctor emits the contract
    # envelope on stdout with exit 1 (not the old exit 2), code MANIFEST_ERROR.
    ErrorCase(
        name="doctor-missing-manifest",
        argv=(*_CLI, "doctor", "--manifest", _MISSING_MANIFEST, "--json"),
        expect_code="MANIFEST_ERROR",
        unset_env=_HERMETIC_UNSET,
    ),
    # A planning-time refusal is operational (1), not usage (2).
    ErrorCase(
        name="onboard-refused-non-vault-source",
        argv=(
            *_CLI, "onboard", "cred:conformance-suite",
            "--manifest", _ONBOARD_MANIFEST, "--json",
        ),
        expect_code="ONBOARD_REFUSED",
        env={"HOME": _EMPTY_HOME},
        unset_env=(*_HERMETIC_UNSET, "ACB_VAULT_ADMIN_ENV"),
    ),
    # `--check` with an unusable admin plane must be an error, never a clean
    # report (M1: the drift gate that went green with authentication broken).
    ErrorCase(
        name="onboard-check-broken-admin-plane",
        argv=(
            *_CLI, "onboard", "cred:conformance-bot",
            "--manifest", _ONBOARD_MANIFEST, "--check",
            "--admin-env", _MISSING_ADMIN_ENV, "--json",
        ),
        expect_code="ONBOARD_REFUSED",
        env={"HOME": _EMPTY_HOME},
        unset_env=_HERMETIC_UNSET,
    ),
    # `--check` offline verified nothing, so it must not report success.
    ErrorCase(
        name="onboard-check-offline-is-not-clean",
        argv=(
            *_CLI, "onboard", "cred:conformance-bot",
            "--manifest", _ONBOARD_MANIFEST, "--check",
        ),
        expect_code=None,
        json_mode=False,
        env={"HOME": _EMPTY_HOME},
        unset_env=(*_HERMETIC_UNSET, "ACB_VAULT_ADMIN_ENV"),
    ),
    # `--apply` against an admin plane that declares no auth material: refuse,
    # rather than borrowing the ambient VAULT_TOKEN, and do not echo it. The kit
    # sets both names to its sentinel and fails the case if either surfaces.
    ErrorCase(
        name="onboard-apply-refuses-without-leaking-ambient-token",
        argv=(
            *_CLI, "onboard", "cred:conformance-bot",
            "--manifest", _ONBOARD_MANIFEST, "--apply",
            "--admin-env", _ADDR_ONLY_ADMIN_ENV, "--json",
        ),
        expect_code="ONBOARD_REFUSED",
        env={"HOME": _EMPTY_HOME},
        unset_env=_HERMETIC_UNSET,
        secret_env_names=("VAULT_TOKEN", "VAULT_SECRET_ID"),
    ),
]

USAGE_CASES = [
    UsageCase(name="unknown-verb", argv=(*_CLI, "bogusverb")),
    # Exit 2 is now *only* usage for this verb.
    UsageCase(name="onboard-invalid-capability-id", argv=(*_CLI, "onboard", "bogus")),
    UsageCase(
        name="onboard-mutually-exclusive-modes",
        argv=(
            *_CLI, "onboard", "cred:conformance-bot",
            "--manifest", _ONBOARD_MANIFEST, "--check", "--apply",
        ),
    ),
    UsageCase(
        name="onboard-unknown-values-source",
        argv=(
            *_CLI, "onboard", "cred:conformance-bot",
            "--manifest", _ONBOARD_MANIFEST, "--apply",
            "--values-from", "bogus-source",
        ),
    ),
    UsageCase(name="onboard-missing-capability-argument", argv=(*_CLI, "onboard")),
]

BROKEN_PIPE_CASES = [
    BrokenPipeCase(
        name="shims-broken-pipe",
        argv=(*_CLI, "shims", "--json"),
        env={"HOME": _EMPTY_HOME},
    ),
]

# WI-026 meta-guard: fail collection loudly if any contract dimension empties.
# A zero-case dimension enforces nothing and — because this module is the
# kit-importing surface — would be indistinguishable from a pass in green CI.
# (The whole-module-skip class is covered by test_conformance_meta_guard.py.)
assert_cases_declared(
    minimum=1,
    success=SUCCESS_CASES,
    error=ERROR_CASES,
    usage=USAGE_CASES,
    broken_pipe=BROKEN_PIPE_CASES,
)


@pytest.mark.parametrize("case", SUCCESS_CASES, ids=lambda c: c.name)
def test_success_conformance(case: SuccessCase) -> None:
    assert run_success_case(case) == []


@pytest.mark.parametrize("case", ERROR_CASES, ids=lambda c: c.name)
def test_error_conformance(case: ErrorCase) -> None:
    assert run_error_case(case) == []


@pytest.mark.parametrize("case", USAGE_CASES, ids=lambda c: c.name)
def test_usage_conformance(case: UsageCase) -> None:
    assert run_usage_case(case) == []


@pytest.mark.parametrize("case", BROKEN_PIPE_CASES, ids=lambda c: c.name)
def test_broken_pipe_conformance(case: BrokenPipeCase) -> None:
    assert run_broken_pipe_case(case) == []
