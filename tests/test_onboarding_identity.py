"""Identity model: each harness has one Vault identity made outside acb.
`acb onboard` then creates nothing in Vault's auth or policy; it verifies the
grant with the harness's own plane and can transit the value."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_capability_broker import cred_vault, onboard
from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability

CAP = Capability(
    id="cred:svc-bot", provider="cred", harnesses=("claude", "opencode"),
    options={"vault": "kv/example/ad/svc-bot", "fields": ["username", "password"]},
)
SIBLING = Capability(
    id="cred:other-bot", provider="cred", harnesses=("claude",),
    options={"vault": "kv/example/ad/other-bot", "fields": ["token"]},
)


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Harness config roots under tmp, each with a plane file."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    for target in onboard.plane_targets(CAP):
        target.path.parent.mkdir(parents=True, exist_ok=True)
        target.path.write_text(
            "VAULT_ADDR=https://vault.example.invalid\nVAULT_ROLE_ID=r\nVAULT_SECRET_ID=s\n",
            encoding="utf-8",
        )
    return tmp_path


def _grants(monkeypatch: pytest.MonkeyPatch, answer: object) -> list[str]:
    asked: list[str] = []

    def fake(cap: Capability, *, vault_env: object = None) -> object:
        asked.append(str(vault_env))
        return answer(str(vault_env)) if callable(answer) else answer

    monkeypatch.setattr(cred_vault, "read_granted", fake)
    return asked


def test_plan_creates_nothing_in_vault_auth_or_policy(home: Path) -> None:
    plan = onboard.plan_onboard(CAP, model=onboard.MODEL_IDENTITY)
    assert [a.kind for a in plan] == ["write_kv", "require_grant", "require_grant"]
    assert {a.harness for a in plan if a.kind == "require_grant"} == {"claude", "opencode"}
    assert all("secret_id" not in json.dumps(a.payload) for a in plan)


def test_a_shared_plane_is_allowed_only_in_the_identity_model(home: Path) -> None:
    onboard.plan_onboard(CAP, (SIBLING,), model=onboard.MODEL_IDENTITY)
    with pytest.raises(onboard.OnboardRefusal):
        onboard.plan_onboard(CAP, (SIBLING,), model=onboard.MODEL_APPROLE)


def test_an_unknown_model_is_refused(home: Path) -> None:
    with pytest.raises(onboard.OnboardRefusal):
        onboard.plan_onboard(CAP, model="surprise")


@pytest.mark.parametrize(
    ("answer", "status"), [(True, "ok"), (False, "missing"), (None, "unknown")]
)
def test_check_reports_each_harness_grant_with_its_own_plane(
    home: Path, monkeypatch: pytest.MonkeyPatch, answer: object, status: str
) -> None:
    asked = _grants(monkeypatch, answer)
    report = onboard.check_onboard(CAP, model=onboard.MODEL_IDENTITY)
    rows = [r for r in report.results if r.action.kind == "require_grant"]
    assert [r.status for r in rows] == [status, status]
    assert asked == [r.action.target for r in rows]
    # The value's presence cannot be verified without a privileged plane.
    assert [r.status for r in report.results if r.action.kind == "write_kv"] == ["unknown"]
    assert not report.clean


def test_check_says_enroll_when_the_harness_has_no_plane(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    asked = _grants(monkeypatch, True)
    for target in onboard.plane_targets(CAP):
        target.path.unlink()
    report = onboard.check_onboard(CAP, model=onboard.MODEL_IDENTITY)
    rows = [r for r in report.results if r.action.kind == "require_grant"]
    assert all(r.status == "unknown" and "enroll" in r.detail for r in rows)
    assert asked == []


def test_apply_without_a_privileged_plane_verifies_and_writes_nothing(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _grants(monkeypatch, True)
    before = {t.path: t.path.read_text(encoding="utf-8") for t in onboard.plane_targets(CAP)}
    report = onboard.apply_onboard(CAP, model=onboard.MODEL_IDENTITY)
    assert [(r.action.kind, r.status) for r in report.results] == [
        ("write_kv", "skipped"), ("require_grant", "converged"), ("require_grant", "converged"),
    ]
    assert report.ok
    after = {t.path: t.path.read_text(encoding="utf-8") for t in onboard.plane_targets(CAP)}
    assert after == before


def test_apply_fails_on_a_missing_grant_but_still_reports_every_harness(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _grants(monkeypatch, lambda plane: "opencode" in plane)
    report = onboard.apply_onboard(CAP, model=onboard.MODEL_IDENTITY)
    by_harness = {r.action.harness: r for r in report.results if r.action.kind == "require_grant"}
    assert by_harness["claude"].status == "failed" and "NOT granted" in by_harness["claude"].detail
    assert by_harness["opencode"].status == "converged"
    assert not report.ok


def test_apply_clears_the_values_it_was_handed(home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _grants(monkeypatch, True)
    values = {"username": "u", "password": "p"}
    onboard.apply_onboard(CAP, values=values, model=onboard.MODEL_IDENTITY)
    assert values == {}


def test_cli_defaults_to_the_identity_model(
    home: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _grants(monkeypatch, True)
    manifest = home / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider = "cred"\nharnesses = ["claude", "opencode"]\n'
        'vault = "kv/example/ad/svc-bot"\nfields = ["username", "password"]\n',
        encoding="utf-8",
    )
    assert main(["onboard", "cred:svc-bot", "-m", str(manifest), "--json"]) == 0
    plan = json.loads(capsys.readouterr().out)["plan"]
    assert [row["kind"] for row in plan] == ["write_kv", "require_grant", "require_grant"]
    assert [row["state"] for row in plan if row["kind"] == "require_grant"] == ["ok", "ok"]

    assert main(
        ["onboard", "cred:svc-bot", "-m", str(manifest), "--json", "--per-capability-approle"]
    ) == 0
    legacy = json.loads(capsys.readouterr().out)["plan"]
    assert legacy[0]["kind"] == "create_policy"
