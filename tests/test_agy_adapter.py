"""agy (Antigravity CLI) adapter: credential discovery skills under the config
directory's ``skills/``; MCP is read, never written."""
from __future__ import annotations

from pathlib import Path

import pytest

from agent_capability_broker import cred_vault
from agent_capability_broker.adapters import AgyAdapter
from agent_capability_broker.cli import main
from agent_capability_broker.model import KNOWN_HARNESSES, Capability, Status
from agent_capability_broker.providers import CredProvider, _render_cred_shim, adapters

CAP = Capability(
    id="cred:svc-bot", provider="cred", harnesses=("agy",),
    options={"vault": "kv/example/ad/svc-bot", "fields": ["username"]},
)


@pytest.fixture
def config_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "gemini" / "config"
    root.mkdir(parents=True)
    monkeypatch.setenv("ACB_AGY_CONFIG_DIR", str(root))
    return root


def test_agy_is_a_known_harness_with_a_registered_adapter(config_dir: Path) -> None:
    assert "agy" in KNOWN_HARNESSES
    adapter = adapters()["agy"]
    assert isinstance(adapter, AgyAdapter) and adapter.name == "agy"
    assert adapter.shims_path == config_dir / "skills"
    assert adapter.vault_env_path == config_dir / "vault.env"


def test_default_location_is_the_gemini_config_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ACB_AGY_CONFIG_DIR", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    adapter = AgyAdapter()
    assert adapter.config_dir == tmp_path / ".gemini" / "config"
    assert adapter.available() is False


def test_skills_are_enumerated_by_name_and_dot_directories_skipped(config_dir: Path) -> None:
    adapter = AgyAdapter()
    assert adapter.command_shims() == set()
    for name in ("cred-svc-bot", ".hidden", "no-skill-file"):
        (config_dir / "skills" / name).mkdir(parents=True)
    (config_dir / "skills" / "cred-svc-bot" / "SKILL.md").write_text("x", encoding="utf-8")
    (config_dir / "skills" / ".hidden" / "SKILL.md").write_text("x", encoding="utf-8")
    assert adapter.command_shims() == {"cred-svc-bot"}


def test_mcp_servers_are_read_and_an_empty_config_is_no_servers(config_dir: Path) -> None:
    adapter = AgyAdapter()
    (config_dir / "mcp_config.json").write_text("", encoding="utf-8")
    assert adapter.mcp_servers() == {}
    (config_dir / "mcp_config.json").write_text(
        '{"mcpServers": {"playwright": {"command": "npx", "args": ["x"]}}}', encoding="utf-8"
    )
    assert set(adapter.mcp_servers()) == {"playwright"}
    assert not hasattr(adapter, "add_mcp_server")


def test_shim_is_a_named_skill_and_is_create_only(config_dir: Path) -> None:
    adapter = AgyAdapter()
    content = _render_cred_shim(CAP, "agy", "cred-svc-bot", adapter.vault_env_path)
    assert content.startswith("---\nname: cred-svc-bot\n")
    adapter.write_skill_shim("cred-svc-bot", content)
    with pytest.raises(FileExistsError):
        adapter.write_skill_shim("cred-svc-bot", "something else")


def test_reconcile_then_doctor(config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cred_vault, "reachable", lambda cap, **_: True)
    provider, adapter = CredProvider(), AgyAdapter()
    assert provider.inspect(CAP, "agy", adapter).status is Status.ABSENT
    for action in provider.plan_reconcile(CAP, "agy", adapter):
        assert provider.apply(action, adapter).status == "applied"
    assert provider.inspect(CAP, "agy", adapter).status is Status.PRESENT_OK


def test_install_harness_accepts_agy(config_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACB_TEST_SECRET", "not-leaked")
    manifest = config_dir.parent / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["agy"]\n',
        encoding="utf-8",
    )
    assert main(["install-harness", "agy", "-m", str(manifest)]) == 0
    assert (config_dir / "skills" / "cred-svc-bot" / "SKILL.md").is_file()
