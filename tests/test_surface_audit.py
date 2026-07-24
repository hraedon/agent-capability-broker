"""Rogue / clobbered capability detection (WI-C, agent-suite WI-001).

`doctor`'s per-capability verdicts can only see what the manifest declares. The
surface audit looks the other way — at what is actually installed — so a
capability added or overwritten *outside* the manifest is named rather than
invisible. These tests pin both the detection and the suite health-contract
shape it must emit (top-level `ok` bool; per-check status ok/warn/fail/skip,
never "pass").
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.adapters import ClaudeAdapter, OpencodeAdapter
from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability
from agent_capability_broker.surface import ShimSurface, audit_surface

_VOCAB = {"ok", "warn", "fail", "skip"}

CAP = Capability("cred:svc-bot", "cred", ("opencode",), {"source": "env", "from_env": "ACB_T"})

_GOOD_SHIM = """\
---
description: "broker cred:svc-bot"
---

Run: `ACB_VAULT_ENV=/x/vault.env acb exec cred:svc-bot -- <command>`
"""
_CLOBBERED_SHIM = """\
---
description: "broker cred:svc-bot"
---

Run: `psql "postgres://bot:REDACTED@db.example.invalid/app"`
"""


def _opencode(tmp_path: Path, shims: dict[str, str], mcp: dict[str, object] | None = None):
    root = tmp_path / "oc"
    (root / "command").mkdir(parents=True)
    (root / "opencode.json").write_text(json.dumps({"mcp": mcp or {}}), encoding="utf-8")
    for name, body in shims.items():
        (root / "command" / f"{name}.md").write_text(body, encoding="utf-8")
    return OpencodeAdapter(config_path=root / "opencode.json")


def _claude(tmp_path: Path, shims: dict[str, str], servers: dict[str, object] | None = None):
    root = tmp_path / "cl"
    root.mkdir(parents=True)
    (root / "settings.json").write_text(
        json.dumps({"mcpServers": servers or {}}), encoding="utf-8"
    )
    for name, body in shims.items():
        (root / "skills" / name).mkdir(parents=True)
        (root / "skills" / name / "SKILL.md").write_text(body, encoding="utf-8")
    return ClaudeAdapter(settings_path=root / "settings.json")


def _audit(caps: list[Capability], **adapters: ShimSurface):
    return audit_surface(caps, dict(adapters))


# --- clean box ---------------------------------------------------------------


def test_clean_surface_yields_no_findings(tmp_path: Path) -> None:
    adapter = _opencode(tmp_path, {"cred-svc-bot": _GOOD_SHIM, "reflect": "# unrelated\n"})
    assert _audit([CAP], opencode=adapter) == []


def test_unavailable_harness_is_not_audited(tmp_path: Path) -> None:
    # No opencode.json at all -> nothing installed to audit (the per-capability
    # verdict already reports UNKNOWN); the audit must not invent a finding.
    adapter = OpencodeAdapter(config_path=tmp_path / "absent" / "opencode.json")
    assert _audit([CAP], opencode=adapter) == []


# --- rogue -------------------------------------------------------------------


def test_rogue_shim_is_named(tmp_path: Path) -> None:
    adapter = _opencode(
        tmp_path,
        {
            "cred-svc-bot": _GOOD_SHIM,
            "cred-rogue-admin": "Run: `acb exec cred:rogue-admin -- <command>`\n",
        },
    )
    findings = _audit([CAP], opencode=adapter)
    assert [f.name for f in findings] == ["rogue:opencode:cred-rogue-admin"]
    assert findings[0].kind == "rogue"
    assert findings[0].status == "warn"
    assert findings[0].capability == "cred:rogue-admin"
    assert "does not declare" in findings[0].detail


def test_rogue_shim_that_brokers_nothing_is_still_named(tmp_path: Path) -> None:
    adapter = _opencode(tmp_path, {"cred-svc-bot": _GOOD_SHIM, "cred-handrolled": "# mine\n"})
    findings = _audit([CAP], opencode=adapter)
    assert [f.name for f in findings] == ["rogue:opencode:cred-handrolled"]
    assert findings[0].capability is None


def test_non_capability_shims_are_ignored(tmp_path: Path) -> None:
    adapter = _opencode(
        tmp_path, {"cred-svc-bot": _GOOD_SHIM, "start": "# skill\n", "credentials": "# no\n"}
    )
    assert _audit([CAP], opencode=adapter) == []


def test_capability_declared_for_another_harness_is_rogue_here(tmp_path: Path) -> None:
    # cred:svc-bot is declared for opencode only; its shim showing up in Claude
    # is a capability wired outside the manifest for that harness.
    claude = _claude(tmp_path, {"cred-svc-bot": _GOOD_SHIM})
    findings = _audit([CAP], claude=claude)
    assert [f.name for f in findings] == ["rogue:claude:cred-svc-bot"]
    assert findings[0].status == "warn"


def test_undeclared_browser_wiring_is_rogue(tmp_path: Path) -> None:
    adapter = _opencode(
        tmp_path,
        {"cred-svc-bot": _GOOD_SHIM},
        mcp={"playwright": {"type": "local", "command": ["npx", "-y", "@playwright/mcp@1.43.0"]}},
    )
    findings = _audit([CAP], opencode=adapter)
    assert [f.name for f in findings] == ["rogue:opencode:mcp:playwright"]
    assert findings[0].status == "warn"


def test_declared_browser_wiring_is_not_rogue(tmp_path: Path) -> None:
    e2e = Capability("e2e:chromium", "e2e", ("opencode",), {})
    adapter = _opencode(
        tmp_path,
        {"cred-svc-bot": _GOOD_SHIM},
        mcp={"playwright": {"type": "local", "command": ["npx", "-y", "@playwright/mcp@1.43.0"]}},
    )
    assert _audit([CAP, e2e], opencode=adapter) == []


# --- clobbered ---------------------------------------------------------------


def test_clobbered_shim_is_a_named_failure(tmp_path: Path) -> None:
    adapter = _opencode(tmp_path, {"cred-svc-bot": _CLOBBERED_SHIM})
    findings = _audit([CAP], opencode=adapter)
    assert [f.name for f in findings] == ["clobber:opencode:cred:svc-bot"]
    assert findings[0].kind == "clobbered"
    assert findings[0].status == "fail"
    assert findings[0].capability == "cred:svc-bot"


def test_clobber_finding_never_surfaces_the_shim_body(tmp_path: Path) -> None:
    # A clobbered shim may hold pasted secret material; the finding carries the
    # path and the verdict, never the contents.
    adapter = _opencode(tmp_path, {"cred-svc-bot": _CLOBBERED_SHIM})
    detail = _audit([CAP], opencode=adapter)[0].detail
    assert "REDACTED" not in detail and "postgres://" not in detail


def test_shim_replaced_by_another_capability_is_clobbered(tmp_path: Path) -> None:
    adapter = _opencode(
        tmp_path, {"cred-svc-bot": "Run: `acb exec cred:someone-else -- <command>`\n"}
    )
    findings = _audit([CAP], opencode=adapter)
    assert [f.name for f in findings] == ["clobber:opencode:cred:svc-bot"]
    assert "cred:someone-else" in findings[0].detail


def test_absent_shim_is_not_a_clobber(tmp_path: Path) -> None:
    # Declared but never installed is the provider's ABSENT verdict, not a clobber.
    adapter = _opencode(tmp_path, {})
    assert _audit([CAP], opencode=adapter) == []


# --- the doctor surface (contract shape) -------------------------------------


def _doctor_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "oc"
    (root / "command").mkdir(parents=True)
    (root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_HERMES_CONFIG", str(tmp_path / "no-hermes.yaml"))
    monkeypatch.setenv("ACB_CODEX_HOME", str(tmp_path / "no-codex"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ACB_T", "set")
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_T"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    (root / "command" / "cred-svc-bot.md").write_text(_GOOD_SHIM, encoding="utf-8")
    return manifest


def _doctor_json(manifest: Path) -> tuple[dict, int]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest), "--json"])
    return json.loads(buf.getvalue()), rc


def test_doctor_clean_box_stays_ok(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = _doctor_env(tmp_path, monkeypatch)
    payload, rc = _doctor_json(manifest)
    assert payload["ok"] is True
    assert rc == 0
    assert not [c for c in payload["checks"] if c["name"].startswith(("rogue:", "clobber:"))]


def test_doctor_reports_a_rogue_capability_as_a_named_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _doctor_env(tmp_path, monkeypatch)
    (tmp_path / "oc" / "command" / "cred-rogue-admin.md").write_text(
        "Run: `acb exec cred:rogue-admin -- <command>`\n", encoding="utf-8"
    )

    payload, rc = _doctor_json(manifest)

    check = next(c for c in payload["checks"] if c["name"] == "rogue:opencode:cred-rogue-admin")
    assert check["status"] == "warn"
    assert check["kind"] == "rogue"
    assert all(c["status"] in _VOCAB for c in payload["checks"])
    # Drift degrades the box; it does not fail it.
    assert payload["ok"] is True and payload["degraded"] is True
    assert rc == 0


def test_doctor_reports_a_clobbered_capability_as_a_named_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _doctor_env(tmp_path, monkeypatch)
    (tmp_path / "oc" / "command" / "cred-svc-bot.md").write_text(
        _CLOBBERED_SHIM, encoding="utf-8"
    )

    payload, rc = _doctor_json(manifest)

    check = next(c for c in payload["checks"] if c["name"] == "clobber:opencode:cred:svc-bot")
    assert check["status"] == "fail"
    assert check["kind"] == "clobbered"
    assert payload["ok"] is False
    assert rc == 1
    assert isinstance(payload["ok"], bool)  # the umbrella classifies from this


def test_doctor_table_names_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _doctor_env(tmp_path, monkeypatch)
    (tmp_path / "oc" / "command" / "cred-rogue-admin.md").write_text("# mine\n", encoding="utf-8")
    main(["doctor", "-m", str(manifest)])
    out = capsys.readouterr().out
    assert "rogue:opencode:cred-rogue-admin" in out
