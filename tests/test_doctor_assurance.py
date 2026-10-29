"""`doctor` assurance reporting (Plan 012 §5): effective level vs declared floor.

fail: effective < declared floor.  warn: D0 with no declared floor (reported
honestly, not passed).  ok otherwise.  Derivation itself is tested in
test_manifest_v2.py; this covers the verdicts and their place in the report.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.cli import _assurance_checks, _classify_health, main
from agent_capability_broker.model import parse_manifest

_VOCAB = {"ok", "warn", "fail", "skip"}


def _manifest(tmp_path: Path, *entries: str) -> Path:
    p = tmp_path / "capabilities.toml"
    p.write_text("\n".join(entries), encoding="utf-8")
    return p


def _cred(name: str, body: str = "") -> str:
    return f'[capability."cred:{name}"]\nprovider = "cred"\nharnesses = ["claude"]\n{body}\n'


def _check(tmp_path: Path, entry: str) -> dict[str, object]:
    (check,) = _assurance_checks(parse_manifest(_manifest(tmp_path, entry)))
    return check


def test_v1_cred_entry_warns_it_is_d0_with_no_floor(tmp_path: Path) -> None:
    check = _check(tmp_path, _cred("a", 'source = "env"\nfrom_env = "ACB_X"'))
    assert check["status"] == "warn"
    assert check["effective"] == "D0" and check["declared"] is None
    assert "no assurance floor declared" in str(check["detail"])
    assert check["name"] == "cred:a@assurance"
    assert check["kind"] == "assurance"


def test_declared_d0_floor_is_an_acknowledged_ok(tmp_path: Path) -> None:
    check = _check(tmp_path, _cred("a", 'assurance = "D0"'))
    assert check["status"] == "ok"
    assert "acknowledged" in str(check["detail"])


def test_static_issuer_with_d1_floor_fails(tmp_path: Path) -> None:
    body = 'issuer = { kind = "vault-kv" }\ndelivery = { rung = "helper" }\nassurance = "D1"'
    check = _check(tmp_path, _cred("a", body))
    assert check["status"] == "fail"
    assert "below the declared floor D1" in str(check["detail"])
    assert check["effective"] == "D0" and check["declared"] == "D1"


def test_env_rung_with_floor_above_d0_fails(tmp_path: Path) -> None:
    assert _check(tmp_path, _cred("a", 'assurance = "H1"'))["status"] == "fail"


def test_issuing_helper_meets_d1(tmp_path: Path) -> None:
    body = 'issuer = { kind = "vault-ssh-ca" }\ndelivery = { rung = "helper" }\nassurance = "D1"'
    check = _check(tmp_path, _cred("a", body))
    assert check["status"] == "ok" and check["effective"] == "D1"


def test_d1_does_not_meet_an_h1_floor(tmp_path: Path) -> None:
    body = 'issuer = { kind = "vault-pki" }\ndelivery = { rung = "proxy" }\nassurance = "H1"'
    assert _check(tmp_path, _cred("a", body))["status"] == "fail"


def test_remote_op_meets_h1_but_not_h1_d1_without_an_issuing_issuer(tmp_path: Path) -> None:
    op = 'delivery = { rung = "remote-op" }\n'
    assert _check(tmp_path, _cred("a", op + 'assurance = "H1"'))["status"] == "ok"
    assert _check(tmp_path, _cred("a", op + 'assurance = "H1+D1"'))["status"] == "fail"


def test_remote_op_with_issuing_issuer_meets_h1_d1(tmp_path: Path) -> None:
    body = (
        'issuer = { kind = "vault-ldap-library" }\ndelivery = { rung = "remote-op" }\n'
        'decision = "approve"\nassurance = "H1+D1"'
    )
    check = _check(tmp_path, _cred("a", body))
    assert check["status"] == "ok" and check["effective"] == "H1+D1"


def test_stronger_than_floor_is_ok(tmp_path: Path) -> None:
    body = 'issuer = { kind = "remote-mint" }\ndelivery = { rung = "helper" }\nassurance = "D0"'
    assert _check(tmp_path, _cred("a", body))["status"] == "ok"


def test_issuing_without_a_floor_is_ok_not_a_warning(tmp_path: Path) -> None:
    body = 'issuer = { kind = "vault-database" }\ndelivery = { rung = "env" }'
    check = _check(tmp_path, _cred("a", body))
    assert check["status"] == "ok" and check["effective"] == "D1"


def test_v1_e2e_entry_holds_no_credential_and_is_not_judged(tmp_path: Path) -> None:
    entry = '[capability."e2e:chromium"]\nprovider = "e2e"\nharnesses = ["claude"]\n'
    assert _assurance_checks(parse_manifest(_manifest(tmp_path, entry))) == []


def test_e2e_entry_declaring_a_floor_is_judged(tmp_path: Path) -> None:
    entry = (
        '[capability."e2e:chromium"]\nprovider = "e2e"\nharnesses = ["claude"]\n'
        'assurance = "D1"\n'
    )
    assert _check(tmp_path, entry)["status"] == "fail"


def test_checks_use_the_suite_vocabulary_and_classify(tmp_path: Path) -> None:
    caps = parse_manifest(
        _manifest(
            tmp_path,
            _cred("warned"),
            _cred("failed", 'assurance = "D1"'),
            _cred("passed", 'assurance = "D0"'),
        )
    )
    checks = _assurance_checks(caps)
    assert [c["status"] for c in checks] == ["warn", "fail", "ok"]
    assert all(c["status"] in _VOCAB for c in checks)
    assert _classify_health(checks[:1]) == (True, True)   # warn degrades, never fails
    assert _classify_health(checks[:2]) == (False, False)  # fail dominates


# --- end to end through the CLI --------------------------------------------------


def _isolate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for var, name in {
        "ACB_OPENCODE_CONFIG": "oc.json",
        "ACB_CLAUDE_SETTINGS": "claude.json",
        "ACB_HERMES_CONFIG": "hermes.yaml",
        "ACB_ZCODE_CONFIG": "zcode.json",
    }.items():
        monkeypatch.setenv(var, str(tmp_path / "none" / name))
    monkeypatch.setenv("ACB_CODEX_HOME", str(tmp_path / "none" / "codex"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))


def _doctor_json(manifest: Path) -> tuple[dict[str, object], int]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest), "--json"])
    return json.loads(buf.getvalue()), rc


def test_doctor_json_degrades_on_an_undeclared_d0(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate(tmp_path, monkeypatch)
    payload, rc = _doctor_json(_manifest(tmp_path, _cred("a", 'source = "env"\nfrom_env = "X"')))
    assert rc == 0
    assert payload["ok"] is True and payload["degraded"] is True
    (check,) = [c for c in payload["checks"] if c.get("kind") == "assurance"]  # type: ignore[attr-defined]
    assert check["status"] == "warn" and check["name"] == "cred:a@assurance"


def test_doctor_json_fails_below_the_floor_and_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate(tmp_path, monkeypatch)
    payload, rc = _doctor_json(_manifest(tmp_path, _cred("a", 'assurance = "D1"')))
    assert rc == 1
    assert payload["ok"] is False
    check = next(c for c in payload["checks"] if c.get("kind") == "assurance")  # type: ignore[attr-defined]
    assert check["status"] == "fail"


def test_doctor_text_output_lists_assurance_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate(tmp_path, monkeypatch)
    manifest = _manifest(tmp_path, _cred("a", 'assurance = "D0"'))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest)])
    assert rc == 0
    assert "cred:a@assurance" in buf.getvalue()


def test_doctor_reports_a_v2_manifest_error_as_the_manifest_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _isolate(tmp_path, monkeypatch)
    manifest = _manifest(tmp_path, _cred("a", 'assurance = "D9"'))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest), "--json"])
    payload = json.loads(buf.getvalue())
    assert rc == 1
    assert payload["ok"] is False and payload["error"]["code"] == "MANIFEST_ERROR"
