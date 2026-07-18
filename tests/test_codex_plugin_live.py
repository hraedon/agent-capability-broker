"""Isolated real-CLI proof for ACB's component-owned Codex plugin."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("codex") is None,
    reason="codex CLI not installed — live plugin proof is skipped",
)

ROOT = Path(__file__).parents[1]
MARKETPLACE = "acb-fixture"


def _run(*argv: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=60)


def test_real_codex_installs_and_removes_component_plugin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()
    monkeypatch.setenv("CODEX_HOME", str(codex_home))

    marketplace = tmp_path / "marketplace"
    plugins = marketplace / "plugins"
    plugins.mkdir(parents=True)
    shutil.copytree(ROOT / "plugins" / "acb", plugins / "acb")
    catalog = marketplace / ".agents" / "plugins" / "marketplace.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_text(
        json.dumps(
            {
                "name": MARKETPLACE,
                "interface": {"displayName": "ACB fixture"},
                "plugins": [
                    {
                        "name": "acb",
                        "source": {"source": "local", "path": "./plugins/acb"},
                        "policy": {
                            "installation": "AVAILABLE",
                            "authentication": "ON_USE",
                        },
                        "category": "Developer Tools",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    added_marketplace = _run(
        "codex", "plugin", "marketplace", "add", str(marketplace), "--json"
    )
    assert added_marketplace.returncode == 0, added_marketplace.stderr

    installed = _run("codex", "plugin", "add", f"acb@{MARKETPLACE}", "--json")
    assert installed.returncode == 0, installed.stderr
    listed = _run("codex", "plugin", "list", "--json")
    assert listed.returncode == 0, listed.stderr
    entries = json.loads(listed.stdout)["installed"]
    acb = next(entry for entry in entries if entry["pluginId"] == f"acb@{MARKETPLACE}")
    assert acb["version"] == "0.1.0"
    assert acb["enabled"] is True

    removed = _run("codex", "plugin", "remove", f"acb@{MARKETPLACE}", "--json")
    assert removed.returncode == 0, removed.stderr
    listed_after = _run("codex", "plugin", "list", "--json")
    assert listed_after.returncode == 0, listed_after.stderr
    assert all(
        entry["pluginId"] != f"acb@{MARKETPLACE}"
        for entry in json.loads(listed_after.stdout)["installed"]
    )
