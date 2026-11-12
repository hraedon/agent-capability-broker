"""Act-path safety for harness config writes.

Harness configs are secret-bearing. These tests pin three properties of the
write path: an unparseable existing config is never rewritten (the read path
degrades to empty for ``doctor``; the write path must refuse), a backup is never
more permissive than the config it copies, and shim creation is exclusive.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from agent_capability_broker.adapters import (
    ClaudeAdapter,
    HermesAdapter,
    OpencodeAdapter,
    UnsafeConfigError,
    ZcodeAdapter,
    _backup,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


@pytest.mark.parametrize(
    "content",
    [
        '{\n  // opencode accepts JSONC comments\n  "mcp": {"keep": {"command": ["x"]}}\n}\n',
        '{"mcpServers": {"keep": {"command": "x",}}}',  # trailing comma
        '["not", "an", "object"]',
    ],
)
def test_add_mcp_server_refuses_to_rewrite_unparseable_config(
    tmp_path: Path, content: str
) -> None:
    config = tmp_path / "settings.json"
    config.write_text(content, encoding="utf-8")
    adapter = ClaudeAdapter(settings_path=config)

    with pytest.raises(UnsafeConfigError, match="refusing to rewrite"):
        adapter.add_mcp_server("playwright", ["npx", "x"])

    assert config.read_text(encoding="utf-8") == content  # byte-for-byte untouched
    assert not list(tmp_path.glob("settings.json.bak-*"))  # refused before backing up


def test_opencode_and_zcode_refuse_to_rewrite_corrupt_config(tmp_path: Path) -> None:
    oc = tmp_path / "opencode.json"
    oc.write_text('{"mcp": {"s": {"command": ["a"]}', encoding="utf-8")
    with pytest.raises(UnsafeConfigError):
        OpencodeAdapter(config_path=oc).add_mcp_server("p", ["npx"])
    with pytest.raises(UnsafeConfigError):
        OpencodeAdapter(config_path=oc).write_command("s", ["b"])
    assert oc.read_text(encoding="utf-8") == '{"mcp": {"s": {"command": ["a"]}'

    zc = tmp_path / "cli" / "config.json"
    zc.parent.mkdir()
    zc.write_text("not json", encoding="utf-8")
    with pytest.raises(UnsafeConfigError):
        ZcodeAdapter(config_path=zc).add_mcp_server("p", ["npx"])
    assert zc.read_text(encoding="utf-8") == "not json"


def test_blank_config_is_treated_as_empty_for_writes(tmp_path: Path) -> None:
    config = tmp_path / "settings.json"
    config.write_text("  \n", encoding="utf-8")
    adapter = ClaudeAdapter(settings_path=config)
    assert adapter.add_mcp_server("s", ["mcp"]).changed is True
    assert "s" in adapter.mcp_servers()


def test_hermes_refuses_to_rewrite_unparseable_yaml(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    config = tmp_path / "config.yaml"
    content = "mcp_servers: [unclosed\n  : : bad\n"
    config.write_text(content, encoding="utf-8")
    with pytest.raises(UnsafeConfigError, match="refusing to rewrite"):
        HermesAdapter(config_path=config).add_mcp_server("p", ["npx"])
    assert config.read_text(encoding="utf-8") == content

    config.write_text("- a\n- list\n", encoding="utf-8")
    with pytest.raises(UnsafeConfigError):
        HermesAdapter(config_path=config).add_mcp_server("p", ["npx"])


def test_hermes_empty_yaml_is_an_empty_config(tmp_path: Path) -> None:
    pytest.importorskip("yaml")
    config = tmp_path / "config.yaml"
    config.write_text("# only a comment\n", encoding="utf-8")
    adapter = HermesAdapter(config_path=config)
    assert adapter.add_mcp_server("p", ["npx"]).changed is True
    assert "p" in adapter.mcp_servers()


@posix_only
def test_backup_is_not_more_permissive_than_the_config(tmp_path: Path) -> None:
    config = tmp_path / "settings.json"
    config.write_text('{"mcpServers": {}}\n', encoding="utf-8")
    config.chmod(0o600)
    old_umask = os.umask(0o022)  # a typical umask would make a naive copy 0644
    try:
        backup = _backup(config)
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    assert backup.read_bytes() == config.read_bytes()


@posix_only
def test_backup_never_widens_group_or_world_bits(tmp_path: Path) -> None:
    config = tmp_path / "settings.json"
    config.write_text("{}", encoding="utf-8")
    config.chmod(0o664)
    backup = _backup(config)
    assert stat.S_IMODE(backup.stat().st_mode) & 0o077 == 0


def test_backup_collision_gets_a_distinct_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "settings.json"
    config.write_text("{}", encoding="utf-8")
    first = _backup(config)
    second = _backup(config)
    assert first != second
    assert first.read_bytes() == second.read_bytes() == b"{}"


def test_write_skill_shim_is_exclusive(tmp_path: Path) -> None:
    adapter = ClaudeAdapter(settings_path=tmp_path / "settings.json")
    adapter.write_skill_shim("cred-x", "one\n")
    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        adapter.write_skill_shim("cred-x", "two\n")
    assert (tmp_path / "skills" / "cred-x" / "SKILL.md").read_text(encoding="utf-8") == "one\n"
