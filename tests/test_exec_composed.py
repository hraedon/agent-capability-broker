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
