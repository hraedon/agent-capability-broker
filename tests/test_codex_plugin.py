"""Static conformance for ACB's component-owned Codex plugin."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
PLUGIN = ROOT / "plugins" / "acb"


def test_codex_plugin_identity_and_skill_are_value_free() -> None:
    manifest = json.loads(
        (PLUGIN / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    skill = (PLUGIN / "skills" / "acb-capabilities" / "SKILL.md").read_text(
        encoding="utf-8"
    )

    assert manifest["name"] == "acb"
    assert manifest["version"] == "0.1.0"
    assert manifest["skills"] == "./skills/"
    assert "acb exec <declared-capability-id>" in skill
    assert "acb install-harness codex" in skill

    rendered = json.dumps(manifest, sort_keys=True) + skill
    for forbidden in (
        "cred:svc-bot",
        "kv/example",
        "vault:",
        "azure:",
        "windows:",
        "VAULT_TOKEN",
        "auth.json",
    ):
        assert forbidden not in rendered


def test_codex_plugin_does_not_duplicate_generated_capability_skills() -> None:
    skill_dirs = sorted(path.name for path in (PLUGIN / "skills").iterdir() if path.is_dir())
    assert skill_dirs == ["acb-capabilities"]
