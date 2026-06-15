"""e2e provider inspect: the four verdicts, against synthetic harness configs.

Reproduces the live asymmetry this project exists to catch — opencode wires
Playwright via `npx @playwright/mcp@latest` (re-resolved every start => broken
offline) while Claude doesn't wire it at all, even though browsers are installed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_capability_broker.adapters import ClaudeAdapter, OpencodeAdapter
from agent_capability_broker.model import Capability, Status
from agent_capability_broker.providers import E2eProvider

CAP = Capability(id="e2e:chromium", provider="e2e", harnesses=("claude", "opencode"))


@pytest.fixture
def installed_browsers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cache = tmp_path / "ms-playwright"
    (cache / "chromium-1223").mkdir(parents=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))
    return cache


def _opencode(tmp_path: Path, mcp: dict[str, object]) -> OpencodeAdapter:
    p = tmp_path / "opencode.json"
    p.write_text(json.dumps({"mcp": mcp}), encoding="utf-8")
    return OpencodeAdapter(config_path=p)


def _claude(tmp_path: Path, servers: dict[str, object]) -> ClaudeAdapter:
    p = tmp_path / "settings.json"
    p.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return ClaudeAdapter(settings_path=p)


def test_opencode_npx_latest_is_broken(tmp_path: Path, installed_browsers: Path) -> None:
    adapter = _opencode(
        tmp_path,
        {
            "playwright": {
                "type": "local",
                "enabled": True,
                "command": ["npx", "-y", "@playwright/mcp@latest", "--headless"],
            }
        },
    )
    v = E2eProvider().inspect(CAP, "opencode", adapter)
    assert v.status is Status.PRESENT_BROKEN
    assert "@latest" in v.detail  # explains the offline failure mode


def test_claude_unwired_is_absent_despite_browsers(
    tmp_path: Path, installed_browsers: Path
) -> None:
    adapter = _claude(tmp_path, {"some-other": {"command": "node", "args": ["x.js"]}})
    v = E2eProvider().inspect(CAP, "claude", adapter)
    assert v.status is Status.ABSENT
    assert "browsers ARE installed" in v.detail


def test_pinned_version_with_browsers_is_ok(tmp_path: Path, installed_browsers: Path) -> None:
    adapter = _opencode(
        tmp_path,
        {"playwright": {"command": ["npx", "-y", "@playwright/mcp@1.43.0"]}},
    )
    v = E2eProvider().inspect(CAP, "opencode", adapter)
    assert v.status is Status.PRESENT_OK


def test_wired_but_no_browsers_is_broken(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path / "empty-cache"))
    adapter = _opencode(
        tmp_path, {"playwright": {"command": ["npx", "-y", "@playwright/mcp@1.43.0"]}}
    )
    v = E2eProvider().inspect(CAP, "opencode", adapter)
    assert v.status is Status.PRESENT_BROKEN
    assert "no browser binaries" in v.detail


def test_disabled_server_is_broken(tmp_path: Path, installed_browsers: Path) -> None:
    adapter = _opencode(
        tmp_path,
        {"playwright": {"enabled": False, "command": ["npx", "-y", "@playwright/mcp@1.43.0"]}},
    )
    v = E2eProvider().inspect(CAP, "opencode", adapter)
    assert v.status is Status.PRESENT_BROKEN
    assert "disabled" in v.detail
