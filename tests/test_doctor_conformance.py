"""Plan 006 WI-1.1: `acb doctor --json` conforms to the suite health contract.

The suite-doctor umbrella (agent-suite ``doctor.py``) classifies a component
from the top-level ``ok``/``degraded`` booleans; without them it defaults
``ok``→false and reports a healthy box as failed. These tests pin the contract
shape so it can't drift again:

- top-level ``ok``/``degraded`` exist and are correctly classified from checks,
- every check carries a non-None ``name`` (the capability@harness cell),
- per-check ``status`` uses the sibling vocabulary (ok/warn/fail/skip),
- the exit code is consistent with the JSON ``ok`` verdict.

Classification mirrors cairn's ``run_doctor`` (cairn/_doctor.py): a hard fail
(present_broken / absent) is unhealthy; a soft unknown (cannot determine) only
degrades; not_applicable is a skip.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.cli import _classify_health, _doctor_checks, main
from agent_capability_broker.model import Status, Verdict

_VOCAB = {"ok", "warn", "fail", "skip"}


def _v(status: Status, *, capability: str = "cred:svc-bot", harness: str = "opencode") -> Verdict:
    return Verdict(capability, harness, status, "detail")


# --- classification (pure, no I/O) -------------------------------------------


def test_classify_all_present_ok_is_healthy() -> None:
    checks = _doctor_checks([_v(Status.PRESENT_OK), _v(Status.PRESENT_OK, harness="claude")])
    ok, degraded = _classify_health(checks)
    assert ok is True
    assert degraded is False


def test_classify_present_broken_fails() -> None:
    checks = _doctor_checks([_v(Status.PRESENT_OK), _v(Status.PRESENT_BROKEN)])
    ok, degraded = _classify_health(checks)
    assert ok is False
    assert degraded is False


def test_classify_absent_fails() -> None:
    checks = _doctor_checks([_v(Status.ABSENT)])
    ok, degraded = _classify_health(checks)
    assert ok is False
    assert degraded is False


def test_classify_unknown_degrades_without_failing() -> None:
    checks = _doctor_checks([_v(Status.PRESENT_OK), _v(Status.UNKNOWN)])
    ok, degraded = _classify_health(checks)
    assert ok is True
    assert degraded is True


def test_classify_only_not_applicable_is_healthy() -> None:
    checks = _doctor_checks([_v(Status.NOT_APPLICABLE, harness="claude")])
    ok, degraded = _classify_health(checks)
    assert ok is True
    assert degraded is False


def test_classify_fail_dominates_warn() -> None:
    # A hard fail present alongside a warn -> unhealthy, not degraded.
    checks = _doctor_checks([_v(Status.PRESENT_BROKEN), _v(Status.UNKNOWN)])
    ok, degraded = _classify_health(checks)
    assert ok is False
    assert degraded is False


# --- check shape (name + vocabulary) ----------------------------------------


def test_check_name_is_capability_at_harness() -> None:
    checks = _doctor_checks([_v(Status.PRESENT_OK, capability="cred:bot", harness="opencode")])
    assert checks[0]["name"] == "cred:bot@opencode"
    assert all(c["name"] == f"{c['capability']}@{c['harness']}" for c in checks)


def test_check_names_are_never_none() -> None:
    checks = _doctor_checks([_v(s) for s in Status])
    assert all(c["name"] is not None and c["name"] != "" for c in checks)


def test_check_status_uses_sibling_vocabulary() -> None:
    checks = _doctor_checks([_v(s) for s in Status])
    assert all(c["status"] in _VOCAB for c in checks)
    # Spot-check the mapping matches the plan's intent.
    by_status = {v.status: v for v in [
        _v(Status.PRESENT_OK), _v(Status.PRESENT_BROKEN), _v(Status.ABSENT),
        _v(Status.UNKNOWN), _v(Status.NOT_APPLICABLE),
    ]}
    assert _doctor_checks([by_status[Status.PRESENT_OK]])[0]["status"] == "ok"
    assert _doctor_checks([by_status[Status.PRESENT_BROKEN]])[0]["status"] == "fail"
    assert _doctor_checks([by_status[Status.ABSENT]])[0]["status"] == "fail"
    assert _doctor_checks([by_status[Status.UNKNOWN]])[0]["status"] == "warn"
    assert _doctor_checks([by_status[Status.NOT_APPLICABLE]])[0]["status"] == "skip"


def test_every_status_maps() -> None:
    # A closed enum: every member must have a check-status mapping (no KeyError).
    for s in Status:
        assert _doctor_checks([_v(s)])[0]["status"] in _VOCAB


# --- end-to-end via the CLI --------------------------------------------------


def _env_manifest(tmp_path: Path) -> Path:
    """A cred cap backed by an env source (no live Vault needed)."""
    m = tmp_path / "capabilities.toml"
    m.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_T"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    return m


def _harness_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, opencode_present: bool
) -> Path:
    root = tmp_path / "oc"
    root.mkdir()
    if opencode_present:
        (root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_HERMES_CONFIG", str(tmp_path / "no-hermes.yaml"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    return root


def _run_doctor_json(manifest: Path) -> tuple[dict, int]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest), "--json"])
    return json.loads(buf.getvalue()), rc


def test_doctor_json_healthy_classifies_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _harness_env(tmp_path, monkeypatch, opencode_present=True)
    (root / "command").mkdir()
    (root / "command" / "cred-svc-bot.md").write_text("# shim\n", encoding="utf-8")
    monkeypatch.setenv("ACB_T", "set")
    manifest = _env_manifest(tmp_path)

    payload, rc = _run_doctor_json(manifest)

    assert payload["component"] == "acb"
    assert "version" in payload
    assert payload["ok"] is True
    assert payload["degraded"] is False
    assert payload["regista"] == {"reachable": None}
    assert rc == 0
    # Contract: every check has a non-None name and a vocabulary status.
    assert len(payload["checks"]) >= 1
    assert all(c["name"] for c in payload["checks"])
    assert all(c["status"] in _VOCAB for c in payload["checks"])
    # The probed cell is present_ok -> "ok".
    oc = next(c for c in payload["checks"] if c["harness"] == "opencode")
    assert oc["status"] == "ok"
    assert oc["name"] == "cred:svc-bot@opencode"


def test_doctor_json_failed_when_capability_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # opencode config present (adapter available) but no discovery shim -> ABSENT.
    _harness_env(tmp_path, monkeypatch, opencode_present=True)
    manifest = _env_manifest(tmp_path)

    payload, rc = _run_doctor_json(manifest)

    assert payload["ok"] is False
    assert payload["degraded"] is False
    assert rc == 1
    oc = next(c for c in payload["checks"] if c["harness"] == "opencode")
    assert oc["status"] == "fail"
    assert oc["name"] == "cred:svc-bot@opencode"


def test_doctor_json_degraded_when_harness_unconfigured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # No opencode config at all -> adapter unavailable -> UNKNOWN (soft warn).
    # Nothing failed, but the capability's state can't be confirmed -> degraded.
    _harness_env(tmp_path, monkeypatch, opencode_present=False)
    manifest = _env_manifest(tmp_path)

    payload, rc = _run_doctor_json(manifest)

    assert payload["ok"] is True
    assert payload["degraded"] is True
    assert rc == 0
    oc = next(c for c in payload["checks"] if c["harness"] == "opencode")
    assert oc["status"] == "warn"


def test_doctor_json_top_level_keys_present_regardless_of_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The drift guard: ok/degraded must always be present (the umbrella reads them).
    _harness_env(tmp_path, monkeypatch, opencode_present=True)
    manifest = _env_manifest(tmp_path)

    payload, _ = _run_doctor_json(manifest)

    assert "ok" in payload and isinstance(payload["ok"], bool)
    assert "degraded" in payload and isinstance(payload["degraded"], bool)
    assert "checks" in payload and isinstance(payload["checks"], list)
