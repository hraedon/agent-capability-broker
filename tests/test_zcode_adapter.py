"""ZCode harness adapter (`ZcodeAdapter`) and its registry wiring.

ZCode reads MCP servers from `~/.zcode/cli/config.json` under a *nested*
`mcp.servers` key (command-string + `args` per entry) and discovers skills as
`~/.zcode/skills/<name>/SKILL.md` — the same SKILL.md shape as Claude Code but
under the config root, not beside the config file. These tests pin that shape
through the adapter contract (mcp_servers / command_shims / add_mcp_server /
write_skill_shim / available / paths) and the provider dispatch that makes
`install-harness zcode`, cred shims, and e2e MCP writes work.
"""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.adapters import ZcodeAdapter
from agent_capability_broker.cli import main
from agent_capability_broker.model import KNOWN_HARNESSES, parse_manifest
from agent_capability_broker.providers import PROVIDERS, adapters


def _zcode_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated `~/.zcode` (created, so `available()` is True) with ACB_ZCODE_CONFIG
    pointing at its `cli/config.json`; sibling harness roots are pinned to
    non-existent paths so tests never touch the operator's real configs."""
    home = tmp_path / "zcode-home"
    (home / "cli").mkdir(parents=True)
    monkeypatch.setenv("ACB_ZCODE_CONFIG", str(home / "cli" / "config.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(tmp_path / "no-oc.json"))
    monkeypatch.setenv("ACB_HERMES_CONFIG", str(tmp_path / "no-hermes.yaml"))
    monkeypatch.setenv("ACB_CODEX_HOME", str(tmp_path / "no-codex"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    return home


def _write_config(home: Path, data: dict[str, object]) -> Path:
    config = home / "cli" / "config.json"
    config.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return config


def _skill(home: Path, name: str) -> None:
    d = home / "skills" / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\n---\n# {name}\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Paths and availability
# ---------------------------------------------------------------------------


def test_default_config_path_is_zcode_cli_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACB_ZCODE_CONFIG", raising=False)
    monkeypatch.setenv("HOME", os.sep + "fake-home")
    monkeypatch.setenv("USERPROFILE", os.sep + "fake-home")
    adapter = ZcodeAdapter()
    assert adapter.config_path == Path(os.sep + "fake-home") / ".zcode" / "cli" / "config.json"
    assert adapter.shims_path == Path(os.sep + "fake-home") / ".zcode" / "skills"
    assert adapter.vault_env_path == Path(os.sep + "fake-home") / ".zcode" / "cli" / "vault.env"


def test_env_override_selects_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "alt" / "config.json"
    monkeypatch.setenv("ACB_ZCODE_CONFIG", str(config))
    adapter = ZcodeAdapter()
    assert adapter.config_path == config
    # The config root (skills/, availability) is the config's parent's parent.
    assert adapter.zcode_home == tmp_path
    assert adapter.shims_path == tmp_path / "skills"
    assert adapter.vault_env_path == tmp_path / "alt" / "vault.env"


def test_explicit_path_wins_over_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACB_ZCODE_CONFIG", str(tmp_path / "from-env.json"))
    adapter = ZcodeAdapter(config_path=tmp_path / "explicit.json")
    assert adapter.config_path == tmp_path / "explicit.json"


def test_available_is_config_root_dir_not_config_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _zcode_home(tmp_path, monkeypatch)
    adapter = ZcodeAdapter()
    # `~/.zcode` exists but config.json does not (fresh client state): the
    # harness is initialised, so it is provisionable.
    assert not adapter.config_path.is_file()
    assert adapter.available() is True

    (home / "cli").rmdir()  # gut the tree entirely: root still exists
    assert adapter.available() is True

    gone = ZcodeAdapter(config_path=tmp_path / "never" / "cli" / "config.json")
    assert gone.available() is False


# ---------------------------------------------------------------------------
# MCP read path (nested mcp.servers)
# ---------------------------------------------------------------------------


def test_mcp_servers_reads_nested_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _zcode_home(tmp_path, monkeypatch)
    _write_config(home, {
        "plugins": {"enabledPlugins": {"demo@market": True}},
        "mcp": {"servers": {
            "stdio-one": {
                "type": "stdio", "command": "npx",
                "args": ["-y", "@example/mcp"],
                "env": {"TOKEN": "not-a-real-secret"},
            },
            "remote-one": {"type": "http", "url": "https://mcp.example.test/sse"},
            "off-one": {"type": "stdio", "command": "mcp", "enabled": False},
            "legacy-off": {"type": "stdio", "command": "mcp", "enable": False},
        }},
    })
    servers = ZcodeAdapter().mcp_servers()

    assert set(servers) == {"stdio-one", "remote-one", "off-one", "legacy-off"}
    assert servers["stdio-one"].kind == "local"
    assert servers["stdio-one"].command == ("npx", "-y", "@example/mcp")
    assert servers["stdio-one"].enabled is True
    # The adapter surfaces only wiring fields, never env/header values.
    assert "TOKEN" not in json.dumps(servers["stdio-one"].__dict__)

    assert servers["remote-one"].kind == "remote"
    assert servers["remote-one"].url == "https://mcp.example.test/sse"
    # ZCode's `enabled: false` and its legacy `enable: false` spelling both
    # disable the server.
    assert servers["off-one"].enabled is False
    assert servers["legacy-off"].enabled is False


def test_mcp_servers_missing_and_corrupt_config_degrade_to_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _zcode_home(tmp_path, monkeypatch)
    adapter = ZcodeAdapter()
    assert adapter.mcp_servers() == {}  # no config file yet

    adapter.config_path.write_text("{ not json", encoding="utf-8")
    assert adapter.mcp_servers() == {}
    assert "corrupted JSON" in capsys.readouterr().err

    # A non-dict `mcp` value (hand-mangled) is empty, not a crash.
    _write_config(adapter.zcode_home, {"mcp": ["nope"]})
    assert adapter.mcp_servers() == {}


# ---------------------------------------------------------------------------
# Skill shim surface
# ---------------------------------------------------------------------------


def test_command_shims_enumerates_skill_dirs_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _zcode_home(tmp_path, monkeypatch)
    _skill(home, "cred-svc-bot")
    _skill(home, "another")
    (home / "skills" / "bare-dir").mkdir()  # no SKILL.md: not a skill
    _skill(home, ".system")  # dot-dir: never enumerated or written

    assert ZcodeAdapter().command_shims() == {"cred-svc-bot", "another"}


def test_command_shims_missing_dir_is_empty_not_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _zcode_home(tmp_path, monkeypatch)
    assert ZcodeAdapter().command_shims() == set()


def test_write_skill_shim_is_create_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _zcode_home(tmp_path, monkeypatch)
    adapter = ZcodeAdapter()
    res = adapter.write_skill_shim("cred-svc-bot", "# body\n")
    assert res.changed is True and res.backup_path is None
    assert (home / "skills" / "cred-svc-bot" / "SKILL.md").read_text(encoding="utf-8") == "# body\n"

    with pytest.raises(FileExistsError):
        adapter.write_skill_shim("cred-svc-bot", "# clobbered\n")


# ---------------------------------------------------------------------------
# MCP write path (nested container, backup-first, no clobber)
# ---------------------------------------------------------------------------


def test_add_mcp_server_creates_nested_container_and_preserves_siblings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _zcode_home(tmp_path, monkeypatch)
    config = _write_config(home, {"plugins": {"enabledPlugins": {"demo@market": True}}})
    adapter = ZcodeAdapter()

    res = adapter.add_mcp_server("playwright", ["npx", "-y", "@playwright/mcp@1.50.0"])
    assert res.changed is True
    assert res.backup_path is not None  # the pre-existing config was backed up

    data = json.loads(config.read_text(encoding="utf-8"))
    assert data["plugins"] == {"enabledPlugins": {"demo@market": True}}  # untouched
    entry = data["mcp"]["servers"]["playwright"]
    # ZCode schema: `command` is a string; the argv tail is `args`.
    assert entry["command"] == "npx"
    assert entry["args"] == ["-y", "@playwright/mcp@1.50.0"]
    assert entry["type"] == "stdio"


def test_add_mcp_server_into_fresh_file_has_no_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _zcode_home(tmp_path, monkeypatch)  # config.json does not exist yet
    adapter = ZcodeAdapter()
    res = adapter.add_mcp_server("s", ["mcp-server"])
    assert res.changed is True and res.backup_path is None
    assert "s" in adapter.mcp_servers()


def test_add_mcp_server_refuses_clobber(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _zcode_home(tmp_path, monkeypatch)
    _write_config(home, {"mcp": {"servers": {"s": {"type": "stdio", "command": "x"}}}})
    with pytest.raises(KeyError, match="already present in mcp.servers"):
        ZcodeAdapter().add_mcp_server("s", ["y"])


# ---------------------------------------------------------------------------
# Registry + provider dispatch
# ---------------------------------------------------------------------------


def test_zcode_is_a_known_harness_and_registered_adapter() -> None:
    assert "zcode" in KNOWN_HARNESSES
    registry = adapters()
    assert registry["zcode"].name == "zcode"
    assert isinstance(registry["zcode"], ZcodeAdapter)


def test_manifest_accepts_zcode_harness_list(tmp_path: Path) -> None:
    m = tmp_path / "capabilities.toml"
    m.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["zcode"]\n',
        encoding="utf-8",
    )
    caps = parse_manifest(m)
    assert caps[0].harnesses == ("zcode",)


def test_cred_shim_frontmatter_carries_name_field(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ZCode SKILL.md needs the `name:` frontmatter field (Claude shape), unlike
    opencode's bare description."""
    from agent_capability_broker.model import Capability
    from agent_capability_broker.providers import _render_cred_shim

    home = _zcode_home(tmp_path, monkeypatch)
    cap = Capability(
        id="cred:svc-bot", provider="cred", harnesses=("zcode",),
        options={"source": "env", "from_env": "ACB_TEST_SECRET"},
    )
    content = _render_cred_shim(cap, "zcode", "cred-svc-bot", home / "cli" / "vault.env")
    assert content.startswith("---\nname: cred-svc-bot\ndescription: ")
    assert "acb exec cred:svc-bot" in content
    assert str(home / "cli" / "vault.env") in content  # ACB_VAULT_ENV points at the plane file


def test_cred_provider_apply_renders_skill_shim_for_zcode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _zcode_home(tmp_path, monkeypatch)
    adapter = ZcodeAdapter()
    cred = PROVIDERS["cred"]
    from agent_capability_broker.model import Action

    action = Action(
        "cred:svc-bot", "zcode", "add_cred_shim", "cred-svc-bot",
        "add shim", payload={"content": "---\nname: cred-svc-bot\n---\n# body\n"},
    )
    result = cred.apply(action, adapter)
    assert result.status == "applied"
    assert (home / "skills" / "cred-svc-bot" / "SKILL.md").is_file()

    # Idempotence at the provider layer: an already-present shim is a skip.
    again = cred.apply(action, adapter)
    assert again.status == "skipped"


def test_e2e_add_mcp_applies_to_zcode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _zcode_home(tmp_path, monkeypatch)
    adapter = ZcodeAdapter()
    e2e = PROVIDERS["e2e"]
    from agent_capability_broker.model import Action

    action = Action(
        "e2e:chromium", "zcode", "add_mcp", "playwright",
        "add server", payload={"command": ["npx", "-y", "@playwright/mcp@1.50.0"]},
    )
    result = e2e.apply(action, adapter)
    assert result.status == "applied"
    servers = adapter.mcp_servers()
    assert servers["playwright"].command == ("npx", "-y", "@playwright/mcp@1.50.0")


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


def _zcode_manifest(tmp_path: Path) -> Path:
    m = tmp_path / "capabilities.toml"
    m.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["zcode"]\n',
        encoding="utf-8",
    )
    return m


def test_doctor_reports_zcode_unknown_when_harness_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACB_ZCODE_CONFIG", str(tmp_path / "never" / "cli" / "config.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(_zcode_manifest(tmp_path))])
    # UNKNOWN (harness not installed here) is a warn, not a fail — exit 0.
    assert rc == 0
    assert "zcode     unknown" in buf.getvalue()


def test_install_harness_zcode_end_to_end_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _zcode_home(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _zcode_manifest(tmp_path)
    shim = home / "skills" / "cred-svc-bot" / "SKILL.md"

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "zcode", "-m", str(manifest)])
    assert rc == 0
    assert shim.is_file()
    assert "present_ok" in buf.getvalue().lower()

    buf2 = io.StringIO()
    with redirect_stdout(buf2):
        rc2 = main(["install-harness", "zcode", "-m", str(manifest)])
    assert rc2 == 0
    assert "present_ok" in buf2.getvalue().lower()


def test_install_harness_zcode_dry_run_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _zcode_home(tmp_path, monkeypatch)
    manifest = _zcode_manifest(tmp_path)

    with redirect_stdout(io.StringIO()) as buf:
        rc = main(["install-harness", "zcode", "-m", str(manifest), "--dry-run"])
    assert rc == 2
    assert "would apply" in buf.getvalue().lower()
    assert not (tmp_path / "zcode-home" / "skills").exists()


def test_install_harness_all_expands_to_zcode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`all` includes zcode since its live interop proof (2026-10-09: a fresh
    ZCode session's skill discovery surfaced every rendered shim, descriptions
    matching the on-disk SKILL.md exactly). Codex stays out until its own
    proof, per Decision 2."""
    _zcode_home(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["claude","opencode","zcode"]\n',
        encoding="utf-8",
    )

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "all", "-m", str(manifest), "--dry-run", "--json"])
    payload = json.loads(buf.getvalue())
    assert rc == 2  # dry-run exit contract
    expanded = [record["harness"] for record in payload["results"]]
    assert expanded == ["claude", "opencode", "zcode"]


def test_cred_shim_quotes_plane_path_in_every_shell_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Windows plane path (spaces, backslashes) must survive every invocation
    block — the POSIX assignment too, not just PowerShell/cmd."""
    from agent_capability_broker.model import Capability
    from agent_capability_broker.providers import _render_cred_shim

    _zcode_home(tmp_path, monkeypatch)
    cap = Capability(
        id="cred:svc-bot", provider="cred", harnesses=("zcode",),
        options={"source": "env", "from_env": "ACB_TEST_SECRET"},
    )
    content = _render_cred_shim(
        cap, "zcode", "cred-svc-bot",
        Path("C:/Users/some user/.zcode/cli/vault.env"),
    )
    quoted = 'ACB_VAULT_ENV="C:\\Users\\some user\\.zcode\\cli\\vault.env"'
    assert quoted in content  # POSIX block
    assert '$env:ACB_VAULT_ENV=' in content  # PowerShell block already quoted
    assert 'set "ACB_VAULT_ENV=' in content  # cmd block already quoted
