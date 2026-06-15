"""WI-3: ABSENT -> add wiring. reconcile can bring a harness with no Playwright
to parity by adding a pinned MCP server, backup-first and idempotently, without
disturbing existing servers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_capability_broker.adapters import ClaudeAdapter
from agent_capability_broker.model import Capability, Status
from agent_capability_broker.providers import E2eProvider

CAP = Capability(
    id="e2e:chromium", provider="e2e", harnesses=("claude",), options={"pin": "1.43.0"}
)


@pytest.fixture
def browsers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "ms-playwright"
    (cache / "chromium-1223").mkdir(parents=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))


def test_absent_with_pin_plans_add_mcp(tmp_path: Path, browsers: None) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    adapter = ClaudeAdapter(settings_path=settings)

    plan = E2eProvider().plan_reconcile(CAP, "claude", adapter)
    assert [a.kind for a in plan] == ["add_mcp"]
    assert plan[0].payload["command"] == [
        "npx", "-y", "@playwright/mcp@1.43.0", "--headless", "--isolated",
    ]


def test_absent_without_pin_is_manual(tmp_path: Path, browsers: None) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    cap = Capability("e2e:chromium", "e2e", ("claude",))  # no pin
    plan = E2eProvider().plan_reconcile(cap, "claude", ClaudeAdapter(settings_path=settings))
    assert plan[0].kind == "manual"
    assert "options.pin" in plan[0].summary


def test_absent_without_browsers_is_manual(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty"))
    settings = tmp_path / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    plan = E2eProvider().plan_reconcile(CAP, "claude", ClaudeAdapter(settings_path=settings))
    assert plan[0].kind == "manual"
    assert "playwright install" in plan[0].summary


def test_apply_adds_and_preserves_existing(tmp_path: Path, browsers: None) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps({"mcpServers": {"keep-me": {"command": "node", "args": ["x.js"]}}}),
        encoding="utf-8",
    )
    adapter = ClaudeAdapter(settings_path=settings)
    plan = E2eProvider().plan_reconcile(CAP, "claude", adapter)

    res = E2eProvider().apply(plan[0], adapter)
    assert res.status == "applied" and res.backup_path

    after = json.loads(settings.read_text())
    assert after["mcpServers"]["playwright"]["args"][1] == "@playwright/mcp@1.43.0"
    assert after["mcpServers"]["keep-me"]["command"] == "node"  # untouched


def test_apply_creates_file_when_absent(tmp_path: Path, browsers: None) -> None:
    settings = tmp_path / "nested" / "settings.json"  # does not exist yet
    adapter = ClaudeAdapter(settings_path=settings)
    plan = E2eProvider().plan_reconcile(CAP, "claude", adapter)

    res = E2eProvider().apply(plan[0], adapter)
    assert res.status == "applied" and res.backup_path is None  # nothing to back up
    assert "playwright" in json.loads(settings.read_text())["mcpServers"]


def test_apply_is_idempotent(tmp_path: Path, browsers: None) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    adapter = ClaudeAdapter(settings_path=settings)

    plan = E2eProvider().plan_reconcile(CAP, "claude", adapter)
    E2eProvider().apply(plan[0], adapter)
    # Now wired + browsers present -> PRESENT_OK -> empty plan.
    assert E2eProvider().inspect(CAP, "claude", adapter).status is Status.PRESENT_OK
    assert E2eProvider().plan_reconcile(CAP, "claude", adapter) == []
    # A stray re-apply is a skipped no-op.
    assert E2eProvider().apply(plan[0], adapter).status == "skipped"
