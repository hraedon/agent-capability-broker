"""The marketplace stages a bounded plugin, never the Python checkout."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_marketplace_resolves_only_the_distributable_plugin() -> None:
    catalog = json.loads((ROOT / ".agents/plugins/marketplace.json").read_text())
    (entry,) = catalog["plugins"]
    plugin = (ROOT / entry["source"]["path"]).resolve()
    assert plugin.is_relative_to(ROOT / "plugins")
    manifest = json.loads((plugin / ".codex-plugin/plugin.json").read_text())
    assert manifest["name"] == entry["name"] == "agent-capability-broker"
    assert not {"apps", "mcpServers", "hooks"} & manifest.keys()
    skills = plugin / manifest["skills"]
    assert sorted(p.parent.name for p in skills.glob("*/SKILL.md")) == [
        "check-capabilities",
        "use-capability",
    ]
    files = [p for p in plugin.rglob("*") if p.is_file()]
    assert sum(p.stat().st_size for p in files) < 100_000
    assert not any({".git", ".venv"} & set(p.parts) for p in files)
