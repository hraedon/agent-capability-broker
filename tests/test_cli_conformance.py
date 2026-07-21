"""acb's CLI run through the CLI contract v1 conformance kit (Plan 018 WI-2).

The kit is the centrally versioned package ``agent_suite.conformance``, consumed
pinned as ``agent-suite-conformance==1.0.0`` from PyPI (Plan 019 B1) via the
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


SUCCESS_CASES = [
    # `shims --json` is a pure filesystem read: no store, no manifest, JSON out.
    SuccessCase(
        name="shims-json",
        argv=(*_CLI, "shims", "--json"),
        env={"HOME": _EMPTY_HOME},
        unset_env=_HERMETIC_UNSET,
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
]

USAGE_CASES = [
    UsageCase(name="unknown-verb", argv=(*_CLI, "bogusverb")),
]

BROKEN_PIPE_CASES = [
    BrokenPipeCase(
        name="shims-broken-pipe",
        argv=(*_CLI, "shims", "--json"),
        env={"HOME": _EMPTY_HOME},
    ),
]


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
