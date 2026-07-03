"""Plan 005 WI-1.1: suite config dir resolution + doctor JSON suite shape.

acb adopts the suite's $AGENT_SUITE_CONFIG convention: the manifest and
vault.env resolve from the suite config dir when present, ahead of the
acb-private defaults. doctor --json conforms to the suite health shape.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker import cred_vault
from agent_capability_broker.cli import main
from agent_capability_broker.model import resolve_manifest, suite_config_dir

# --- suite_config_dir() resolution -------------------------------------------


def test_suite_config_dir_from_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """$AGENT_SUITE_CONFIG can point at a file (suite.env) — its parent is the dir."""
    suite_file = tmp_path / "suite.env"
    suite_file.write_text("# suite config\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_file))
    assert suite_config_dir() == tmp_path


def test_suite_config_dir_from_env_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """$AGENT_SUITE_CONFIG can point at a directory directly."""
    suite_dir = tmp_path / "agent-suite"
    suite_dir.mkdir()
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_dir))
    assert suite_config_dir() == suite_dir


def test_suite_config_dir_default_when_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When unset, default to ~/.config/agent-suite/ if it exists."""
    monkeypatch.delenv("AGENT_SUITE_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    default = tmp_path / "agent-suite"
    default.mkdir()
    assert suite_config_dir() == default


def test_suite_config_dir_none_when_unset_and_default_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("AGENT_SUITE_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert suite_config_dir() is None


# --- manifest resolution from suite config dir -------------------------------


def test_manifest_resolves_from_suite_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite_dir = tmp_path / "agent-suite"
    suite_dir.mkdir()
    (suite_dir / "capabilities.toml").write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_dir))
    monkeypatch.delenv("ACB_MANIFEST", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.chdir(tmp_path)

    assert resolve_manifest() == suite_dir / "capabilities.toml"


def test_acb_manifest_env_wins_over_suite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite_dir = tmp_path / "agent-suite"
    suite_dir.mkdir()
    (suite_dir / "capabilities.toml").write_text("# suite\n", encoding="utf-8")
    acb_manifest = tmp_path / "explicit.toml"
    acb_manifest.write_text(
        '[capability."cred:a"]\nprovider="cred"\nharnesses=["claude"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_dir))
    monkeypatch.setenv("ACB_MANIFEST", str(acb_manifest))

    assert resolve_manifest() == acb_manifest


def test_manifest_falls_back_to_acb_private_when_suite_has_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite_dir = tmp_path / "agent-suite"
    suite_dir.mkdir()
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_dir))
    monkeypatch.delenv("ACB_MANIFEST", raising=False)

    xdg = tmp_path / "xdg"
    acb_manifest = xdg / "acb" / "capabilities.toml"
    acb_manifest.parent.mkdir(parents=True)
    acb_manifest.write_text(
        '[capability."cred:a"]\nprovider="cred"\nharnesses=["claude"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    monkeypatch.chdir(tmp_path)

    assert resolve_manifest() == acb_manifest


# --- vault env resolution from suite config dir ------------------------------


def test_vault_env_from_suite_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    suite_dir = tmp_path / "agent-suite"
    suite_dir.mkdir()
    (suite_dir / "vault.env").write_text(
        "VAULT_ADDR=https://suite-vault\nVAULT_TOKEN=suite-tok\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_dir))
    monkeypatch.delenv("ACB_VAULT_ENV", raising=False)
    for k in ("VAULT_ADDR", "VAULT_TOKEN"):
        monkeypatch.delenv(k, raising=False)

    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://suite-vault"
    assert env["VAULT_TOKEN"] == "suite-tok"


def test_suite_env_provides_vault_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """suite.env in the suite config dir can carry VAULT_* vars (WI-3.1)."""
    suite_dir = tmp_path / "agent-suite"
    suite_dir.mkdir()
    (suite_dir / "suite.env").write_text(
        "REGISTA_DSN=postgres://suite\n"
        "VAULT_ADDR=https://from-suite-env\n"
        "VAULT_TOKEN=suite-env-tok\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_dir))
    monkeypatch.delenv("ACB_VAULT_ENV", raising=False)
    for k in ("VAULT_ADDR", "VAULT_TOKEN"):
        monkeypatch.delenv(k, raising=False)

    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://from-suite-env"
    assert env["VAULT_TOKEN"] == "suite-env-tok"
    assert "REGISTA_DSN" not in env  # only VAULT_* keys are extracted


def test_vault_env_takes_precedence_over_suite_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """vault.env (dedicated) is checked before suite.env (shared)."""
    suite_dir = tmp_path / "agent-suite"
    suite_dir.mkdir()
    (suite_dir / "vault.env").write_text("VAULT_ADDR=https://dedicated\n", encoding="utf-8")
    (suite_dir / "suite.env").write_text("VAULT_ADDR=https://shared\n", encoding="utf-8")
    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_dir))
    monkeypatch.delenv("ACB_VAULT_ENV", raising=False)
    monkeypatch.delenv("VAULT_ADDR", raising=False)

    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://dedicated"


def test_acb_vault_env_wins_over_suite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """$ACB_VAULT_ENV (explicit shell override) wins over the suite dir."""
    suite_dir = tmp_path / "agent-suite"
    suite_dir.mkdir()
    (suite_dir / "vault.env").write_text("VAULT_ADDR=https://suite\n", encoding="utf-8")
    shell_env = tmp_path / "shell.env"
    shell_env.write_text("VAULT_ADDR=https://shell\n", encoding="utf-8")

    monkeypatch.setenv("AGENT_SUITE_CONFIG", str(suite_dir))
    monkeypatch.setenv("ACB_VAULT_ENV", str(shell_env))
    monkeypatch.delenv("VAULT_ADDR", raising=False)

    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://shell"


def test_vault_env_fallback_respects_xdg_config_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MEDIUM-2 fix: the acb-private vault.env fallback respects XDG_CONFIG_HOME,
    consistent with the manifest resolution."""
    monkeypatch.delenv("AGENT_SUITE_CONFIG", raising=False)
    monkeypatch.delenv("ACB_VAULT_ENV", raising=False)
    xdg = tmp_path / "xdg"
    acb_vault = xdg / "acb" / "vault.env"
    acb_vault.parent.mkdir(parents=True)
    acb_vault.write_text("VAULT_ADDR=https://from-xdg\n", encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    for k in ("VAULT_ADDR", "VAULT_TOKEN"):
        monkeypatch.delenv(k, raising=False)

    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://from-xdg"


# --- doctor --json suite shape -----------------------------------------------


def test_doctor_json_suite_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="NOT_SET"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    (oc_root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["doctor", "-m", str(manifest), "--json"])

    payload = json.loads(buf.getvalue())
    assert payload["component"] == "acb"
    assert "version" in payload
    assert isinstance(payload["checks"], list)
    assert len(payload["checks"]) >= 1
    check = payload["checks"][0]
    assert {"capability", "harness", "status", "detail"} <= set(check)
    assert payload["regista"] == {"reachable": None}


def test_doctor_json_no_secret_leaked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The suite-shape JSON must not surface a secret (read-path safety)."""
    secret = "p@ss-do-not-leak-7f3a"
    monkeypatch.setenv("ACB_SECRET", secret)
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_SECRET"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    (oc_root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    (oc_root / "command").mkdir()
    (oc_root / "command" / "cred-svc-bot.md").write_text("# shim\n", encoding="utf-8")
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["doctor", "-m", str(manifest), "--json"])

    assert secret not in buf.getvalue()
