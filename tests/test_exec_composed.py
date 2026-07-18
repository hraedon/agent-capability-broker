"""WI-010: per-capability env naming and composed checkout.

Two capabilities whose fields are both [username, password] must be able to
check out together under distinct declared names (`env_prefix` / `inject`),
with one `acb.checkout-receipt.v1` covering the whole checkout — replacing
nested `acb exec` shells that re-export values by hand. Values never reach
acb's stdout/stderr/provenance; validation happens before any resolution.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_capability_broker import cred_vault, providers
from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability
from agent_capability_broker.providers import CredProvider, exec_composed
from agent_capability_broker.secret_sources import SecretSourceConfigError

USER_A = "svc-hyperv-canary"
PASS_A = "hyperv-p@ss-canary-1f9c"
USER_B = "svc-guest-canary"
PASS_B = "guest-p@ss-canary-8e2d"


def _vault_cap(name: str, prefix: str | None = None, **extra: object) -> Capability:
    options: dict[str, object] = {
        "vault": f"kv/example/lab/{name}",
        "fields": ["username", "password"],
        **extra,
    }
    if prefix is not None:
        options["env_prefix"] = prefix
    return Capability(f"cred:{name}", "cred", ("opencode",), options)


def _fake_resolve(monkeypatch: pytest.MonkeyPatch, secrets: dict[str, dict[str, str]]) -> None:
    monkeypatch.setattr(cred_vault, "resolve", lambda cap: dict(secrets[cap.id]))


def _dump_env_argv(out: Path, names: list[str]) -> list[str]:
    entries = ",".join(f"{n!r}:os.environ.get({n!r},'MISSING')" for n in names)
    code = f"import json,os,pathlib;pathlib.Path(r'{out}').write_text(json.dumps({{{entries}}}))"
    return [sys.executable, "-c", code]


def test_env_prefix_names_child_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    _fake_resolve(
        monkeypatch,
        {"cred:hyperv-control": {"username": USER_A, "password": PASS_A}},
    )
    cap = _vault_cap("hyperv-control", "HYPERV_CONTROL")
    out = tmp_path / "seen.json"

    rc = CredProvider().exec(
        cap,
        _dump_env_argv(
            out,
            ["HYPERV_CONTROL_USERNAME", "HYPERV_CONTROL_PASSWORD", "ACB_CHECKOUT_RECEIPT"],
        ),
    )

    assert rc == 0
    seen = json.loads(out.read_text())
    assert seen["HYPERV_CONTROL_USERNAME"] == USER_A
    assert seen["HYPERV_CONTROL_PASSWORD"] == PASS_A
    receipt = json.loads(seen["ACB_CHECKOUT_RECEIPT"])
    assert receipt["schema"] == "acb.checkout-receipt.v1"
    assert receipt["checkouts"] == [
        {
            "capability_id": "cred:hyperv-control",
            "fields": {
                "password": "HYPERV_CONTROL_PASSWORD",
                "username": "HYPERV_CONTROL_USERNAME",
            },
        }
    ]
    captured = capsys.readouterr()
    for canary in (USER_A, PASS_A):
        assert canary not in captured.out and canary not in captured.err


def test_inject_mapping_wins_over_env_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    _fake_resolve(
        monkeypatch,
        {"cred:hyperv-control": {"username": USER_A, "password": PASS_A}},
    )
    cap = _vault_cap(
        "hyperv-control", "HYPERV_CONTROL", inject={"username": "HV_ADMIN_NAME"}
    )
    out = tmp_path / "seen.json"

    rc = CredProvider().exec(
        cap, _dump_env_argv(out, ["HV_ADMIN_NAME", "HYPERV_CONTROL_PASSWORD"])
    )

    assert rc == 0
    seen = json.loads(out.read_text())
    assert seen["HV_ADMIN_NAME"] == USER_A                    # explicit map wins
    assert seen["HYPERV_CONTROL_PASSWORD"] == PASS_A          # prefix fills the rest


def test_composed_checkout_injects_all_and_emits_one_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    _fake_resolve(
        monkeypatch,
        {
            "cred:hyperv-control": {"username": USER_A, "password": PASS_A},
            "cred:guest-bootstrap": {"username": USER_B, "password": PASS_B},
        },
    )
    caps = [
        _vault_cap("hyperv-control", "HYPERV_CONTROL"),
        _vault_cap("guest-bootstrap", "GUEST_BOOTSTRAP"),
    ]
    out = tmp_path / "seen.json"

    rc = exec_composed(
        caps,
        _dump_env_argv(
            out,
            [
                "HYPERV_CONTROL_USERNAME",
                "HYPERV_CONTROL_PASSWORD",
                "GUEST_BOOTSTRAP_USERNAME",
                "GUEST_BOOTSTRAP_PASSWORD",
                "ACB_CHECKOUT_RECEIPT",
            ],
        ),
    )

    assert rc == 0
    seen = json.loads(out.read_text())
    assert seen["HYPERV_CONTROL_USERNAME"] == USER_A
    assert seen["HYPERV_CONTROL_PASSWORD"] == PASS_A
    assert seen["GUEST_BOOTSTRAP_USERNAME"] == USER_B
    assert seen["GUEST_BOOTSTRAP_PASSWORD"] == PASS_B

    receipt = json.loads(seen["ACB_CHECKOUT_RECEIPT"])
    assert [c["capability_id"] for c in receipt["checkouts"]] == [
        "cred:hyperv-control",
        "cred:guest-bootstrap",
    ]

    captured = capsys.readouterr()
    provenance_log = (state / "provenance.jsonl").read_text()
    for canary in (USER_A, PASS_A, USER_B, PASS_B):
        assert canary not in captured.out and canary not in captured.err
        assert canary not in provenance_log
    assert "HYPERV_CONTROL_PASSWORD" in provenance_log
    assert "GUEST_BOOTSTRAP_PASSWORD" in provenance_log


def test_composed_bare_names_collide_and_refuse_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _never(cap: Capability) -> dict[str, str]:
        raise AssertionError("resolution must not run when the plan is invalid")

    monkeypatch.setattr(cred_vault, "resolve", _never)
    caps = [_vault_cap("hyperv-control"), _vault_cap("guest-bootstrap")]

    with pytest.raises(SecretSourceConfigError):
        exec_composed(caps, [sys.executable, "-c", "pass"])


def test_reserved_username_target_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bare `username` maps to USERNAME, which shadows the Windows logon
    variable — the evidence lab refuses it, and so does the strict path."""

    def _never(cap: Capability) -> dict[str, str]:
        raise AssertionError("resolution must not run when the plan is invalid")

    monkeypatch.setattr(cred_vault, "resolve", _never)
    cap = _vault_cap(
        "hyperv-control", inject={"username": "USERNAME", "password": "HV_PASSWORD"}
    )

    with pytest.raises(SecretSourceConfigError, match="reserved"):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])


def test_inherited_target_collision_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HYPERV_CONTROL_PASSWORD", "already-here")

    def _never(cap: Capability) -> dict[str, str]:
        raise AssertionError("resolution must not run when the plan is invalid")

    monkeypatch.setattr(cred_vault, "resolve", _never)
    cap = _vault_cap("hyperv-control", "HYPERV_CONTROL")

    with pytest.raises(SecretSourceConfigError, match="already exists"):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])


def test_strict_path_refuses_inherited_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACB_CHECKOUT_RECEIPT", "parent-receipt")

    def _never(cap: Capability) -> dict[str, str]:
        raise AssertionError("resolution must not run when the plan is invalid")

    monkeypatch.setattr(cred_vault, "resolve", _never)
    cap = _vault_cap("hyperv-control", "HYPERV_CONTROL")

    with pytest.raises(SecretSourceConfigError, match="nested checkout"):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])


def test_bare_path_gets_fresh_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bare capability keeps its historical overwrite semantics: the child
    receives a fresh single-capability receipt, not the parent's."""
    monkeypatch.setenv("SRC", PASS_A)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ACB_CHECKOUT_RECEIPT", "parent-receipt")
    cap = Capability(
        "cred:test", "cred", ("opencode",),
        {"source": "env", "from_env": "SRC", "field": "password"},
    )
    out = tmp_path / "seen.json"

    rc = CredProvider().exec(cap, _dump_env_argv(out, ["PASSWORD", "ACB_CHECKOUT_RECEIPT"]))

    assert rc == 0
    seen = json.loads(out.read_text())
    assert seen["PASSWORD"] == PASS_A                       # bare name preserved
    receipt = json.loads(seen["ACB_CHECKOUT_RECEIPT"])      # fresh, not "parent-receipt"
    assert receipt["checkouts"] == [
        {"capability_id": "cred:test", "fields": {"password": "PASSWORD"}}
    ]


def test_composed_refuses_suite_source() -> None:
    suite_cap = Capability(
        "cred:lab-control", "cred", ("opencode",),
        {
            "source": "suite",
            "refs": {"password": "vault:kv/example/lab/password"},
            "inject": {"password": "LAB_PASSWORD"},
            "trusted_argv": [sys.executable, "-c", "pass"],
        },
    )
    with pytest.raises(SecretSourceConfigError, match="composed checkout"):
        exec_composed(
            [_vault_cap("hyperv-control", "HYPERV_CONTROL"), suite_cap],
            [sys.executable, "-c", "pass"],
        )


def test_composed_refuses_repeated_capability() -> None:
    cap = _vault_cap("hyperv-control", "HYPERV_CONTROL")
    with pytest.raises(RuntimeError, match="repeated"):
        exec_composed([cap, cap], [sys.executable, "-c", "pass"])


def test_resolved_fields_must_match_declared_selection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(
        cred_vault,
        "resolve",
        lambda cap: {"username": USER_A, "password": PASS_A, "rotation_note": "x"},
    )
    cap = _vault_cap("hyperv-control", "HYPERV_CONTROL")

    with pytest.raises(RuntimeError, match="declared selection"):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])


def test_cli_composed_exec_two_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SRC_A", PASS_A)
    monkeypatch.setenv("SRC_B", PASS_B)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:control"]\nprovider="cred"\nsource="env"\n'
        'from_env="SRC_A"\nfield="password"\nenv_prefix="HYPERV_CONTROL"\n'
        'harnesses=["opencode"]\n'
        '[capability."cred:guest"]\nprovider="cred"\nsource="env"\n'
        'from_env="SRC_B"\nfield="password"\nenv_prefix="GUEST_BOOTSTRAP"\n'
        'harnesses=["opencode"]\n',
        encoding="utf-8",
    )
    out = tmp_path / "seen.json"
    child = _dump_env_argv(
        out, ["HYPERV_CONTROL_PASSWORD", "GUEST_BOOTSTRAP_PASSWORD", "ACB_CHECKOUT_RECEIPT"]
    )

    rc = main(["exec", "cred:control", "cred:guest", "-m", str(manifest), "--", *child])

    assert rc == 0
    seen = json.loads(out.read_text())
    assert seen["HYPERV_CONTROL_PASSWORD"] == PASS_A
    assert seen["GUEST_BOOTSTRAP_PASSWORD"] == PASS_B
    receipt = json.loads(seen["ACB_CHECKOUT_RECEIPT"])
    assert [c["capability_id"] for c in receipt["checkouts"]] == [
        "cred:control",
        "cred:guest",
    ]


def test_cli_unknown_second_capability_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SRC_A", PASS_A)
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:control"]\nprovider="cred"\nsource="env"\n'
        'from_env="SRC_A"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )

    rc = main(
        ["exec", "cred:control", "cred:nope", "-m", str(manifest), "--",
         sys.executable, "-c", "pass"]
    )

    assert rc == 2
    assert "cred:nope" in capsys.readouterr().err


def test_composed_receipt_parses_with_evidence_lab_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The composed receipt must satisfy the evidence lab's own parser — the
    consumer that made composed checkout a live-execution prerequisite."""
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    _fake_resolve(
        monkeypatch,
        {
            "cred:lab-hyperv-control": {"username": USER_A, "password": PASS_A},
            "cred:lab-guest-bootstrap": {"username": USER_B, "password": PASS_B},
        },
    )
    caps = [
        _vault_cap("lab-hyperv-control", "HYPERV_CONTROL"),
        _vault_cap("lab-guest-bootstrap", "GUEST_BOOTSTRAP"),
    ]
    out = tmp_path / "seen.json"
    rc = exec_composed(caps, _dump_env_argv(out, ["ACB_CHECKOUT_RECEIPT"]))
    assert rc == 0
    raw = json.loads(out.read_text())["ACB_CHECKOUT_RECEIPT"]

    lab_src = Path(__file__).resolve().parents[2] / "windows-evidence-lab" / "src"
    if not lab_src.is_dir():
        pytest.skip("composed windows-evidence-lab checkout is not present")
    sys.path.insert(0, str(lab_src))
    try:
        from windows_evidence_lab.capabilities import parse_checkout_receipt

        parsed = parse_checkout_receipt(raw)
    finally:
        sys.path.remove(str(lab_src))
        sys.modules.pop("windows_evidence_lab.capabilities", None)
        sys.modules.pop("windows_evidence_lab", None)

    parsed.validate_exact(
        ["cred:lab-hyperv-control", "cred:lab-guest-bootstrap"],
        {
            "cred:lab-hyperv-control": {
                "username": "HYPERV_CONTROL_USERNAME",
                "password": "HYPERV_CONTROL_PASSWORD",
            },
            "cred:lab-guest-bootstrap": {
                "username": "GUEST_BOOTSTRAP_USERNAME",
                "password": "GUEST_BOOTSTRAP_PASSWORD",
            },
        },
    )


def test_env_prefix_alone_prevents_bare_collision_across_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression guard for the original WP-1 wiring failure: two [username,
    password] capabilities compose without any hand re-export."""
    assert "HYPERV_CONTROL_USERNAME" not in os.environ
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    _fake_resolve(
        monkeypatch,
        {
            "cred:hyperv-control": {"username": USER_A, "password": PASS_A},
            "cred:guest-bootstrap": {"username": USER_B, "password": PASS_B},
        },
    )
    caps = [
        _vault_cap("hyperv-control", "HYPERV_CONTROL"),
        _vault_cap("guest-bootstrap", "GUEST_BOOTSTRAP"),
    ]
    rc = exec_composed(caps, [sys.executable, "-c", "pass"])
    assert rc == 0


# --- Regressions from the PR #14 adversarial review ---


def test_child_command_tokens_are_never_treated_as_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F1: a child argument shaped like `cred:x` must stay in the child argv,
    not become a checkout request (argparse eats the first `--`, so the old
    tokenwise scan ran over the whole child command)."""
    monkeypatch.setenv("SRC", PASS_A)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:test"]\nprovider="cred"\nsource="env"\n'
        'from_env="SRC"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    out = tmp_path / "argv.json"
    code = f"import json,sys,pathlib;pathlib.Path(r'{out}').write_text(json.dumps(sys.argv[1:]))"

    rc = main(
        ["exec", "-m", str(manifest), "cred:test", "--",
         sys.executable, "-c", code, "cred:zzz", "hello", "-m", "marker"]
    )

    assert rc == 0
    assert json.loads(out.read_text()) == ["cred:zzz", "hello", "-m", "marker"]


def test_historical_single_capability_form_without_separator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SRC", PASS_A)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:test"]\nprovider="cred"\nsource="env"\n'
        'from_env="SRC"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )

    rc = main(
        ["exec", "-m", str(manifest), "cred:test",
         sys.executable, "-c", "raise SystemExit(3)"]
    )

    assert rc == 3


def test_non_capability_token_before_separator_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["exec", "cred:test", "bogus-token", "--", sys.executable, "-c", "pass"])
    assert rc == 2
    assert "bogus-token" in capsys.readouterr().err


def test_lowercase_env_prefix_refused_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F2: names the evidence-lab boundary rejects must be refused by acb
    before a secret is resolved, not injected and then rejected downstream."""

    def _never(cap: Capability) -> dict[str, str]:
        raise AssertionError("resolution must not run when the plan is invalid")

    monkeypatch.setattr(cred_vault, "resolve", _never)
    cap = _vault_cap("hyperv-control", "hyperv_control")

    with pytest.raises(SecretSourceConfigError, match="not a valid environment name"):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])


def test_nonconformant_capability_id_refused_on_strict_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _never(cap: Capability) -> dict[str, str]:
        raise AssertionError("resolution must not run when the plan is invalid")

    monkeypatch.setattr(cred_vault, "resolve", _never)
    cap = Capability(
        "cred:Lab_Control", "cred", ("opencode",),
        {"vault": "kv/example/lab/x", "fields": ["username", "password"],
         "env_prefix": "LAB_CONTROL"},
    )

    with pytest.raises(SecretSourceConfigError, match="receipt-conformant"):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])


def test_launch_failure_emits_provenance_and_contained_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F4: a child that cannot launch must leave started+failed provenance
    (value-free) and raise a contained RuntimeError, not a raw OSError."""
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    _fake_resolve(
        monkeypatch,
        {"cred:hyperv-control": {"username": USER_A, "password": PASS_A}},
    )
    cap = _vault_cap("hyperv-control", "HYPERV_CONTROL")

    with pytest.raises(RuntimeError, match="child launch failed"):
        CredProvider().exec(cap, [str(tmp_path / "no-such-binary")])

    log = (state / "provenance.jsonl").read_text()
    assert '"started"' in log and "child launch failed" in log
    assert USER_A not in log and PASS_A not in log


def test_receipt_module_constants_align_with_evidence_lab() -> None:
    """acb must refuse at least every name the evidence-lab boundary refuses,
    or acb would issue receipts the consumer rejects."""
    lab_src = Path(__file__).resolve().parents[2] / "windows-evidence-lab" / "src"
    if not lab_src.is_dir():
        pytest.skip("composed windows-evidence-lab checkout is not present")
    sys.path.insert(0, str(lab_src))
    try:
        from windows_evidence_lab import capabilities as lab_capabilities

        lab_reserved = set(lab_capabilities._RESERVED_ENVIRONMENT_FIELDS)
    finally:
        sys.path.remove(str(lab_src))
        sys.modules.pop("windows_evidence_lab.capabilities", None)
        sys.modules.pop("windows_evidence_lab", None)
    assert lab_reserved <= set(providers._RESERVED_INJECT_VARS)


# --- Round-2 adversarial review follow-ups (F9/F10/F11) ---


def test_bare_path_launch_failure_emits_provenance_and_contains_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F9: the bare (no inject/env_prefix) path must apply the same launch-
    failure discipline as the strict (F4) and suite paths — emit started +
    failed provenance, raise a contained RuntimeError (not a raw OSError),
    and leave no resolved value in provenance."""
    state = tmp_path / "state"
    monkeypatch.setenv("SRC", PASS_A)
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    cap = Capability(
        "cred:bare-test", "cred", ("opencode",),
        {"source": "env", "from_env": "SRC", "field": "password"},
    )

    with pytest.raises(RuntimeError, match="child launch failed"):
        CredProvider().exec(cap, [str(tmp_path / "no-such-binary")])

    log = (state / "provenance.jsonl").read_text()
    events = [json.loads(line) for line in log.splitlines() if line.strip()]
    assert len(events) >= 2
    assert events[0]["result"] == "started"
    terminal = events[-1]
    assert terminal["result"] == "failed"
    assert "child launch failed" in terminal["detail"]
    assert "PASSWORD" in terminal["summary"]
    assert PASS_A not in log


def test_bare_path_successful_exec_emits_started_and_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F9: the bare path on a successful launch now emits a started event
    followed by an applied terminal event (the historical single-event
    behavior is gone — every cred exec path emits the started+terminal pair)."""
    state = tmp_path / "state"
    monkeypatch.setenv("SRC", PASS_A)
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    cap = Capability(
        "cred:bare-test", "cred", ("opencode",),
        {"source": "env", "from_env": "SRC", "field": "password"},
    )

    rc = CredProvider().exec(cap, [sys.executable, "-c", "pass"])
    assert rc == 0

    log = (state / "provenance.jsonl").read_text()
    events = [json.loads(line) for line in log.splitlines() if line.strip()]
    assert [e["result"] for e in events] == ["started", "applied"]
    assert PASS_A not in log


def test_declared_fields_accepts_empty_fields_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F10: `_declared_fields` must agree with `cred_vault.resolve` on every
    input. An empty `fields = []` selects nothing — `_declared_fields` returns
    `[]`, matching the resolver's behavior (not a config error)."""
    cap = Capability(
        "cred:empty", "cred", ("opencode",),
        {"vault": "kv/example/empty", "fields": []},
    )
    assert providers._declared_fields(cap) == []


def test_declared_fields_rejects_non_list_fields() -> None:
    """F10: `fields = "password"` (a string, not a list) must raise at plan
    validation, matching `cred_vault.resolve`'s refusal — not fall through to
    the singular `field` check."""
    cap = Capability(
        "cred:bad", "cred", ("opencode",),
        {"vault": "kv/example/bad", "fields": "password"},
    )
    with pytest.raises(SecretSourceConfigError, match="options.fields must be a list"):
        providers._declared_fields(cap)


def test_declared_fields_rejects_non_string_field() -> None:
    """F10: `field = 42` (not a string) must raise at plan validation,
    matching `cred_vault.resolve`'s refusal."""
    cap = Capability(
        "cred:bad", "cred", ("opencode",),
        {"vault": "kv/example/bad", "field": 42},
    )
    with pytest.raises(SecretSourceConfigError, match="options.field must be a string"):
        providers._declared_fields(cap)


def test_cli_unknown_option_after_capability_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """F11: in the composed form (with '--'), an unknown option-shaped token
    after the first capability id must be reported as 'unknown option', not
    misreported as 'not a capability id'."""
    monkeypatch.setenv("SRC", PASS_A)
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:test"]\nprovider="cred"\nsource="env"\n'
        'from_env="SRC"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )

    rc = main(
        ["exec", "cred:test", "-x", "--", sys.executable, "-c", "pass", "-m", str(manifest)]
    )

    assert rc == 2
    err = capsys.readouterr().err
    assert "unknown option '-x'" in err


def test_cli_historical_form_passes_flag_like_child_args(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F11 regression guard: the historical no-'--' form still lets the first
    capability eat the rest of the line as the child command, including
    flag-shaped child arguments."""
    monkeypatch.setenv("SRC", PASS_A)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:test"]\nprovider="cred"\nsource="env"\n'
        'from_env="SRC"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    out = tmp_path / "argv.json"
    code = f"import json,sys,pathlib;pathlib.Path(r'{out}').write_text(json.dumps(sys.argv[1:]))"

    rc = main(
        ["exec", "-m", str(manifest), "cred:test",
         sys.executable, "-c", code, "-x", "--flag", "positional"]
    )

    assert rc == 0
    assert json.loads(out.read_text()) == ["-x", "--flag", "positional"]


# --- Round-3 adversarial review follow-ups (MAJOR 1 / MINOR 3..6) ---


def test_declares_naming_rejects_non_string_env_prefix() -> None:
    """MAJOR 1: a present-but-malformed `env_prefix` (wrong type) must fail
    closed, not silently downgrade to the bare (overwrite, no-validation) path.
    A user who wrote `env_prefix = 123` intended the strict path; routing them
    to bare semantics would shadow inherited vars without any receipt-level
    validation."""
    cap = Capability(
        "cred:bad", "cred", ("opencode",),
        {"vault": "kv/example/bad", "fields": ["password"], "env_prefix": 123},
    )
    with pytest.raises(SecretSourceConfigError, match="options.env_prefix must be a string"):
        providers._declares_naming(cap)


def test_declares_naming_rejects_non_mapping_inject() -> None:
    """MAJOR 1: `inject = "PGPASSWORD"` (a string, not a mapping) must fail
    closed rather than downgrade to the bare path."""
    cap = Capability(
        "cred:bad", "cred", ("opencode",),
        {"vault": "kv/example/bad", "fields": ["password"], "inject": "PGPASSWORD"},
    )
    with pytest.raises(SecretSourceConfigError, match="options.inject must be a mapping"):
        providers._declares_naming(cap)


@pytest.mark.parametrize("opts", [{"env_prefix": ""}, {"inject": {}}])
def test_declares_naming_treats_empty_declaration_as_bare(opts: dict[str, object]) -> None:
    """MAJOR 1 boundary: an explicitly *empty* declaration (``env_prefix = ""``
    or ``inject = {}``) is not malformed — it is "no names declared", so the
    capability stays on the bare path (only a wrong TYPE is a refusal)."""
    cap = Capability(
        "cred:empty", "cred", ("opencode",),
        {"vault": "kv/example/empty", "fields": ["password"], **opts},
    )
    assert providers._declares_naming(cap) is False


def test_declared_fields_converts_non_string_list_elements() -> None:
    """F10 edge: `fields = [42, "password"]` — both `_declared_fields` and
    `cred_vault.resolve` coerce elements with `str()`, so the selected set
    agrees (`["42", "password"]`). Guards against a future change that breaks
    the post-resolution `set(fields) == set(plan)` invariant."""
    cap = Capability(
        "cred:bad", "cred", ("opencode",),
        {"vault": "kv/example/bad", "fields": [42, "password"]},
    )
    assert providers._declared_fields(cap) == ["42", "password"]


def test_declared_fields_prefers_fields_over_field() -> None:
    """F10 edge: when both `field` and `fields` are set, `fields` wins. Both
    `_declared_fields` and `cred_vault.resolve` honor this precedence — pin
    it so the agreement claim holds under the combined declaration."""
    cap = Capability(
        "cred:both", "cred", ("opencode",),
        {"vault": "kv/example/both", "field": "password", "fields": ["username"]},
    )
    assert providers._declared_fields(cap) == ["username"]


def test_cred_vault_resolve_raises_secret_source_config_error_for_bad_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MINOR 4: `cred_vault.resolve` now raises `SecretSourceConfigError`
    (a `RuntimeError` subclass) for config-shape errors, matching the type
    `_declared_fields` raises — so the F10 agreement holds on type too."""
    cap = Capability(
        "cred:bad", "cred", ("opencode",),
        {"vault": "kv/example/bad", "fields": "password"},
    )
    with pytest.raises(SecretSourceConfigError, match="options.fields must be a list"):
        cred_vault.resolve(cap)


def test_bare_path_resolution_failure_emits_started_and_failed_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MINOR 5: the bare path's resolution-failure branch must still emit a
    started event followed by a failed terminal event, with no secret in the
    log. Pins the F9 'every exit path emits started+terminal' claim against
    the resolution-failure branch (OSError and success are already covered)."""
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    # `from_env` points at an unset variable → resolution fails before any
    # child is launched, without needing Vault.
    cap = Capability(
        "cred:bare-test", "cred", ("opencode",),
        {"source": "env", "from_env": "ACB_NEVER_SET_VAR", "field": "password"},
    )

    with pytest.raises(RuntimeError, match="ACB_NEVER_SET_VAR"):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])

    log = (state / "provenance.jsonl").read_text()
    events = [json.loads(line) for line in log.splitlines() if line.strip()]
    assert [e["result"] for e in events] == ["started", "failed"]
    assert "resolution failed" in events[-1]["detail"]
    assert "ACB_NEVER_SET_VAR" not in log  # the var name is not itself secret, but refuse it anyway


def test_strict_path_started_summary_does_not_claim_injection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NIT 7 / provenance honesty: the strict path's `started` event must
    describe the *attempt* (resolution starting), not claim injection already
    happened. A `failed` record whose summary says 'injected ...' would be a
    lie when resolution never completed."""
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    cap = _vault_cap("strict-fail", prefix="STRICT_FAIL")
    # Force resolution to fail by pointing cred_vault.resolve at a bomb.
    def _boom(_cap: Capability) -> dict[str, str]:
        raise RuntimeError("boom from vault")

    monkeypatch.setattr(cred_vault, "resolve", _boom)

    with pytest.raises(RuntimeError, match="boom"):
        exec_composed([cap], [sys.executable, "-c", "pass"])

    events = [
        json.loads(line)
        for line in (state / "provenance.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert events[0]["result"] == "started"
    assert "injected" not in events[0]["summary"]
    assert "starting" in events[0]["summary"]
    terminal = events[-1]
    assert terminal["result"] == "failed"


def test_strict_path_terminal_summary_records_injected_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """NIT 7 complement: on a successful strict checkout the terminal event
    DOES record the injected var names (the started event deliberately does
    not). Both events remain secret-free."""
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    cap = _vault_cap("strict-ok", prefix="STRICT_OK")
    _fake_resolve(monkeypatch, {cap.id: {"username": USER_A, "password": PASS_A}})

    rc = exec_composed([cap], [sys.executable, "-c", "pass"])
    assert rc == 0

    events = [
        json.loads(line)
        for line in (state / "provenance.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert [e["result"] for e in events] == ["started", "applied"]
    assert "injected" not in events[0]["summary"]
    assert "STRICT_OK_USERNAME" in events[-1]["summary"]
    assert "STRICT_OK_PASSWORD" in events[-1]["summary"]
    assert USER_A not in (state / "provenance.jsonl").read_text()
    assert PASS_A not in (state / "provenance.jsonl").read_text()


def test_bare_path_refuses_oversized_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MINOR 3: a bare capability whose receipt would exceed the 16 KiB
    contract limit is refused (consistency with the strict path's plan-time
    byte guard), with a failed terminal event and no secret leak."""
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    # A bare (no env_prefix/inject) vault-source capability whose resolved
    # field set is large enough that the receipt JSON trips the 16 KiB limit.
    many_fields = {f"field{i:04d}": "v" for i in range(9000)}
    cap = Capability(
        "cred:bare-huge", "cred", ("opencode",),
        {"vault": "kv/example/huge", "fields": list(many_fields)},
    )
    monkeypatch.setattr(cred_vault, "resolve", lambda _cap: dict(many_fields))

    with pytest.raises(SecretSourceConfigError, match="exceeds the 16 KiB contract limit"):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])

    events = [
        json.loads(line)
        for line in (state / "provenance.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert events[-1]["result"] == "failed"
    assert "exceeds the 16 KiB contract limit" in events[-1]["detail"]


# --- Round-2 adversarial review follow-ups (MAJOR 1 / MAJOR 2 / MINOR 4) ---


def test_composed_rejects_malformed_inject_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round-2 MAJOR 1: a composed capability with a malformed `inject`
    (string, not a mapping) must fail closed at plan time — NOT silently
    downgrade to bare naming inside `_injection_plan`. `_declares_naming`'s
    fail-closed must apply to the composed path, not only the single path."""
    def _never(cap: Capability) -> dict[str, str]:
        raise AssertionError("resolution must not run when the declaration is malformed")

    monkeypatch.setattr(cred_vault, "resolve", _never)
    good = _vault_cap("hyperv-control", prefix="HYPERV_CONTROL")
    bad = Capability(
        "cred:guest-bootstrap", "cred", ("opencode",),
        {"vault": "kv/example/lab/guest-bootstrap", "fields": ["password"],
         "inject": "GUEST_PASSWORD"},
    )

    with pytest.raises(SecretSourceConfigError, match="options.inject must be a mapping"):
        exec_composed([good, bad], [sys.executable, "-c", "pass"])


def test_composed_rejects_malformed_env_prefix_before_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Round-2 MAJOR 1: a composed capability with a non-string `env_prefix`
    must fail closed at plan time, not silently downgrade."""
    def _never(cap: Capability) -> dict[str, str]:
        raise AssertionError("resolution must not run when the declaration is malformed")

    monkeypatch.setattr(cred_vault, "resolve", _never)
    bad = Capability(
        "cred:bad-prefix", "cred", ("opencode",),
        {"vault": "kv/example/bad", "fields": ["password"], "env_prefix": 42},
    )

    with pytest.raises(SecretSourceConfigError, match="options.env_prefix must be a string"):
        exec_composed([bad], [sys.executable, "-c", "pass"])


def test_strict_path_emits_terminal_provenance_on_keyboard_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-2 MAJOR 2: a KeyboardInterrupt (or any BaseException) during the
    child run must still emit a terminal provenance event via the `finally` —
    the safety property that does NOT depend on redesigning containment. The
    OS delivers SIGINT to the whole foreground process group, so the child is
    not orphaned in the normal terminal case; the guaranteed behavior acb owns
    is that terminal provenance is never skipped."""
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    cap = _vault_cap("interrupt", prefix="INT")
    _fake_resolve(monkeypatch, {cap.id: {"username": USER_A, "password": PASS_A}})

    def _raise_kbi(_argv: list[str], **_kw: object) -> subprocess.CompletedProcess[bytes]:
        raise KeyboardInterrupt

    monkeypatch.setattr(providers.subprocess, "run", _raise_kbi)

    with pytest.raises(KeyboardInterrupt):
        exec_composed([cap], [sys.executable, "-c", "pass"])

    log = (state / "provenance.jsonl").read_text()
    events = [json.loads(line) for line in log.splitlines() if line.strip()]
    assert [e["result"] for e in events] == ["started", "failed"]
    assert USER_A not in log and PASS_A not in log


def test_bare_path_emits_terminal_provenance_on_keyboard_interrupt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-2 MAJOR 2 (bare path): same guarantee — terminal provenance is
    emitted even when the child run is interrupted by BaseException."""
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    monkeypatch.setenv("SRC", PASS_A)
    cap = Capability(
        "cred:bare-int", "cred", ("opencode",),
        {"source": "env", "from_env": "SRC", "field": "password"},
    )

    def _raise_kbi(_argv: list[str], **_kw: object) -> subprocess.CompletedProcess[bytes]:
        raise KeyboardInterrupt

    monkeypatch.setattr(providers.subprocess, "run", _raise_kbi)

    with pytest.raises(KeyboardInterrupt):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])

    log = (state / "provenance.jsonl").read_text()
    events = [json.loads(line) for line in log.splitlines() if line.strip()]
    assert [e["result"] for e in events] == ["started", "failed"]
    assert PASS_A not in log


def test_strict_path_started_and_terminal_events_are_ordered_and_correlated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-2 MINOR 4: the strict path now emits two events. Pin the
    invariants downstream consumers rely on: the started event strictly
    precedes the terminal event (monotonic `ts`), and both share the same
    correlation keys (`capability` + `target`)."""
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    cap = _vault_cap("ordered", prefix="ORD")
    _fake_resolve(monkeypatch, {cap.id: {"username": USER_A, "password": PASS_A}})

    rc = exec_composed([cap], [sys.executable, "-c", "pass"])
    assert rc == 0

    events = [
        json.loads(line)
        for line in (state / "provenance.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert len(events) == 2
    started, terminal = events
    assert started["result"] == "started" and terminal["result"] == "applied"
    # Monotonic timestamps (isoformat UTC sorts lexicographically).
    assert started["ts"] <= terminal["ts"]
    # Shared correlation: same capability + target.
    assert started["capability"] == terminal["capability"] == cap.id
    assert started["target"] == terminal["target"] == cap.id
    assert USER_A not in (state / "provenance.jsonl").read_text()
    assert PASS_A not in (state / "provenance.jsonl").read_text()
