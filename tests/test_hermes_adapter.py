"""HermesAdapter coverage (feat/hermes-harness).

Mirrors the sibling-adapter tests (`test_shims`, `test_add_wiring`) so the YAML
harness gets the same direct coverage the JSON harnesses already had: shim
enumeration, the backup/no-clobber act-path contract, the YAML round-trip, the
corrupt-config degradation path, and the ``vault.env`` secret-placement rule.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_capability_broker.adapters import HermesAdapter, _load_yaml

# Skip the suite when pyyaml (the [hermes] extra) isn't installed — the read path
# degrades gracefully, but these tests exercise the YAML round-trip which needs it.
pytest.importorskip("yaml")


def _hermes_tree(root: Path, skills: list[str], *, bare: list[str] | None = None) -> HermesAdapter:
    """Build a synthetic Hermes config root with named skill shims.

    Mirrors ``_claude_tree`` in test_shims: a bare dir (no SKILL.md) is not an
    exposed skill.
    """
    root.mkdir(parents=True, exist_ok=True)
    skills_dir = root / "skills"
    skills_dir.mkdir(exist_ok=True)
    for name in skills:
        (skills_dir / name).mkdir(exist_ok=True)
        (skills_dir / name / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    for name in bare or []:
        (skills_dir / name).mkdir(exist_ok=True)
    return HermesAdapter(config_path=root / "config.yaml")


# --- command_shims() -------------------------------------------------------

def test_command_shims_lists_skill_md_dirs(tmp_path: Path) -> None:
    adapter = _hermes_tree(tmp_path, ["start", "end", "cert-watch-e2e"])
    assert adapter.command_shims() == {"start", "end", "cert-watch-e2e"}


def test_command_shims_excludes_bare_dirs(tmp_path: Path) -> None:
    # A dir without SKILL.md is not an exposed skill (same rule as Claude).
    adapter = _hermes_tree(tmp_path, ["start", "end"], bare=["half-built"])
    assert adapter.command_shims() == {"start", "end"}


def test_command_shims_missing_dir_is_empty_not_error(tmp_path: Path) -> None:
    assert HermesAdapter(config_path=tmp_path / "config.yaml").command_shims() == set()


# --- add_mcp_server: backup / no-clobber / round-trip -----------------------

def test_add_mcp_server_round_trip(tmp_path: Path) -> None:
    """Write a server, read it back via mcp_servers(), verify the normalized shape."""
    config = tmp_path / "config.yaml"
    config.write_text("mcp_servers: {}\n", encoding="utf-8")
    adapter = HermesAdapter(config_path=config)

    res = adapter.add_mcp_server("playwright", ["npx", "@playwright/mcp@1.43.0"])
    assert res.changed is True
    assert res.backup_path is not None and res.backup_path.is_file()  # backed up existing

    servers = adapter.mcp_servers()
    pw = servers["playwright"]
    assert pw.kind == "local"
    assert pw.command == ("npx", "@playwright/mcp@1.43.0")
    assert pw.enabled is True


def test_add_mcp_server_creates_file_when_absent(tmp_path: Path) -> None:
    """No existing config -> created (nested parents), nothing to back up."""
    config = tmp_path / "nested" / "config.yaml"  # does not exist yet
    adapter = HermesAdapter(config_path=config)

    res = adapter.add_mcp_server("playwright", ["npx", "@playwright/mcp@1.43.0"])
    assert res.changed is True
    assert res.backup_path is None
    assert config.is_file()
    assert "playwright" in adapter.mcp_servers()


def test_add_mcp_server_preserves_existing_servers(tmp_path: Path) -> None:
    """Adding a new server must not disturb an existing (secret-bearing) entry."""
    config = tmp_path / "config.yaml"
    config.write_text(
        "mcp_servers:\n"
        "  keep-me:\n"
        "    command: [node, x.js]\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    adapter = HermesAdapter(config_path=config)

    adapter.add_mcp_server("playwright", ["npx", "@playwright/mcp@1.43.0"])

    servers = adapter.mcp_servers()
    assert "keep-me" in servers and "playwright" in servers
    assert servers["keep-me"].command == ("node", "x.js")  # untouched byte-for-byte
    assert servers["playwright"].command == ("npx", "@playwright/mcp@1.43.0")


def test_add_mcp_server_refuses_to_clobber_existing(tmp_path: Path) -> None:
    """Re-adding a server that already exists raises (no secret clobber)."""
    config = tmp_path / "config.yaml"
    config.write_text(
        "mcp_servers:\n"
        "  playwright:\n"
        "    command: [node, legacy.js]\n"
        "    enabled: true\n",
        encoding="utf-8",
    )
    adapter = HermesAdapter(config_path=config)

    with pytest.raises(KeyError, match="already present"):
        adapter.add_mcp_server("playwright", ["npx", "@playwright/mcp@1.43.0"])

    # The existing entry survived unchanged.
    assert adapter.mcp_servers()["playwright"].command == ("node", "legacy.js")


def test_add_mcp_server_backup_is_distinct(tmp_path: Path) -> None:
    """The backup is a separate .bak-* file, leaving the live config writable."""
    config = tmp_path / "config.yaml"
    config.write_text("mcp_servers: {}\n", encoding="utf-8")
    adapter = HermesAdapter(config_path=config)

    res = adapter.add_mcp_server("playwright", ["npx", "@playwright/mcp@1.43.0"])
    assert res.backup_path is not None
    assert res.backup_path != config
    assert res.backup_path.name.startswith("config.yaml.bak-")
    # Original content preserved in the backup.
    assert "mcp_servers" in res.backup_path.read_text(encoding="utf-8")


# --- _load_yaml: degradation paths ------------------------------------------

def test_load_yaml_missing_file_returns_empty(tmp_path: Path) -> None:
    """A missing config file yields {} silently (no warning, no yaml needed)."""
    assert _load_yaml(tmp_path / "absent.yaml") == {}


def test_load_yaml_corrupt_returns_empty_and_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Malformed YAML -> empty dict + a stderr warning; never crashes."""
    config = tmp_path / "config.yaml"
    config.write_text("mcp_servers: [unclosed\n  : : bad\n", encoding="utf-8")

    assert _load_yaml(config) == {}
    err = capsys.readouterr().err
    assert "corrupted YAML" in err
    assert str(config) in err


def test_load_yaml_non_mapping_top_returns_empty(tmp_path: Path) -> None:
    """A YAML scalar/list at the top level is not a valid config mapping -> {}."""
    config = tmp_path / "config.yaml"
    config.write_text("- just\n- a\n- list\n", encoding="utf-8")

    assert _load_yaml(config) == {}


# --- vault_env_path: the secret-placement rule ------------------------------

def test_vault_env_path_is_vault_env_not_dotenv(tmp_path: Path) -> None:
    """Vault AppRole env must land in `vault.env` (not `.env`), matching the
    sibling adapters and the cred_vault defaults. `.env` is auto-sourced by
    direnv/docker/python-dotenv and would leak the secret into other tools' env
    (violates the 'Inject, don't surface' hard rule in AGENTS.md)."""
    adapter = HermesAdapter(config_path=tmp_path / "config.yaml")
    assert adapter.vault_env_path == tmp_path / "vault.env"
    assert adapter.vault_env_path.name == "vault.env"


def test_vault_env_path_matches_sibling_adapters(tmp_path: Path) -> None:
    """All three harness adapters must agree on the vault.env filename."""
    from agent_capability_broker.adapters import ClaudeAdapter, OpencodeAdapter

    hermes = HermesAdapter(config_path=tmp_path / "hermes" / "config.yaml")
    claude = ClaudeAdapter(settings_path=tmp_path / "claude" / "settings.json")
    opencode = OpencodeAdapter(config_path=tmp_path / "oc" / "opencode.json")

    assert hermes.vault_env_path.name == claude.vault_env_path.name == opencode.vault_env_path.name
