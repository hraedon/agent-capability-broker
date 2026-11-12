"""Codex's shared skills root is independent of its configuration root."""

from pathlib import Path

import pytest

from agent_capability_broker.adapters import CodexAdapter


def test_default_skills_use_user_home_not_custom_codex_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "user")
    monkeypatch.delenv("ACB_CODEX_SKILLS", raising=False)
    adapter = CodexAdapter(codex_home=tmp_path / "config elsewhere")
    assert adapter.shims_path == tmp_path / "user" / ".agents" / "skills"
    assert adapter.config_path == tmp_path / "config elsewhere" / "config.toml"
    assert adapter.vault_env_path == tmp_path / "config elsewhere" / "vault.env"


def test_shared_root_override_is_create_only_and_excludes_reserved_skills(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "codex"
    config.mkdir()
    before = b'# user comment\nmodel = "example-model"\n'
    (config / "config.toml").write_bytes(before)
    shared = tmp_path / "shared skills"
    monkeypatch.setenv("ACB_CODEX_SKILLS", str(shared))
    adapter = CodexAdapter(codex_home=config)
    adapter.write_skill_shim("cred-example", "original")
    # _create_file refuses changed content; it never silently overwrites it.
    with pytest.raises(FileExistsError):
        adapter.write_skill_shim("cred-example", "replacement")
    reserved = shared / ".system" / "reserved"
    reserved.mkdir(parents=True)
    (reserved / "SKILL.md").write_text("reserved", encoding="utf-8")
    assert adapter.command_shims() == {"cred-example"}
    assert (shared / "cred-example" / "SKILL.md").read_text() == "original"
    assert (config / "config.toml").read_bytes() == before
    assert not (config / "skills").exists()
