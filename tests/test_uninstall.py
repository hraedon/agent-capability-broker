"""Ownership-based uninstall surface (Plan 007 WI-2.1 AC: hash checks).

``install-harness --uninstall`` is the inverse of ``install-harness``: it
removes only acb-owned shims and MCP wiring, proven by a content hash check.
Hand-authored or modified artifacts are preserved and reported as manual
actions. Dry-run by default; emits provenance on every removal.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.adapters import CodexAdapter
from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability
from agent_capability_broker.providers import CredProvider

# ---- opencode cred shim uninstall ----


def _setup_oc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, shims: list[str] | None = None
) -> Path:
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    (oc_root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    if shims:
        cmd_dir = oc_root / "command"
        cmd_dir.mkdir()
        for name in shims:
            (cmd_dir / f"{name}.md").write_text("# hand-authored\n", encoding="utf-8")
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    return oc_root


def _cred_manifest(tmp_path: Path) -> Path:
    m = tmp_path / "capabilities.toml"
    m.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    return m


def test_uninstall_removes_acb_owned_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Install then uninstall: the shim is gone and doctor reports ABSENT."""
    oc_root = _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])
    assert (oc_root / "command" / "cred-svc-bot.md").is_file()

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    assert not (oc_root / "command" / "cred-svc-bot.md").exists()
    assert "absent" in buf.getvalue().lower()


def test_uninstall_dry_run_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oc_root = _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])
    shim = oc_root / "command" / "cred-svc-bot.md"
    assert shim.is_file()
    before = shim.read_text(encoding="utf-8")

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall", "--dry-run"])

    assert rc == 2
    assert "would remove" in buf.getvalue().lower()
    assert shim.read_text(encoding="utf-8") == before


def test_uninstall_rerun_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Uninstalling when nothing is installed is a no-op (exit 0, not 2)."""
    _setup_oc(tmp_path, monkeypatch)
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    assert not (tmp_path / "oc" / "command" / "cred-svc-bot.md").exists()


def test_uninstall_preserves_hand_authored_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A shim whose content doesn't match acb's rendering and lacks acb markers
    is preserved."""
    _setup_oc(tmp_path, monkeypatch, shims=["cred-svc-bot"])
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _cred_manifest(tmp_path)
    shim = tmp_path / "oc" / "command" / "cred-svc-bot.md"
    before = shim.read_text(encoding="utf-8")

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    assert shim.read_text(encoding="utf-8") == before
    assert "manual" in buf.getvalue().lower()
    assert "skipped" in buf.getvalue().lower()


def test_uninstall_preserves_modified_acb_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A shim that carries the acb managed marker but whose content has been
    modified by the user is preserved — acb never destroys user edits — but this
    is an *incomplete* uninstall (an acb-owned artifact remains), so it is a
    conflict with a non-zero exit, not a false clean success."""
    oc_root = _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])

    shim = oc_root / "command" / "cred-svc-bot.md"
    content = shim.read_text(encoding="utf-8")
    content = content + "\n<!-- user edit -->\n"
    shim.write_text(content, encoding="utf-8")
    before = shim.read_text(encoding="utf-8")

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])

    assert rc == 1  # fail closed: the shim remains, so uninstall did not complete
    assert shim.read_text(encoding="utf-8") == before
    out = buf.getvalue().lower()
    assert "manual" in out
    assert "skipped" in out
    assert "incomplete" in out


def test_uninstall_modified_acb_shim_json_is_failed_with_conflict_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Conflicts use the closed status vocabulary while retaining metadata."""
    oc_root = _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])

    shim = oc_root / "command" / "cred-svc-bot.md"
    shim.write_text(shim.read_text(encoding="utf-8") + "\n<!-- user edit -->\n", encoding="utf-8")

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall", "--json"])

    assert rc == 1
    payload = json.loads(buf.getvalue())
    assert payload["status"] == "failed"
    assert payload["conflict"] is True
    assert payload["actions"][0]["conflict"] is True
    assert "changed" in payload["actions"][0]["detail"]
    # the capability is still PRESENT (shim remains) — never reported absent
    assert payload["checks"][0]["status"] != "absent"


def test_uninstall_modified_acb_shim_dry_run_is_failed_with_conflict_detail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oc_root = _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])
    shim = oc_root / "command" / "cred-svc-bot.md"
    shim.write_text(shim.read_text(encoding="utf-8") + "\n<!-- user edit -->\n")

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(
            [
                "install-harness",
                "opencode",
                "-m",
                str(manifest),
                "--uninstall",
                "--dry-run",
                "--json",
            ]
        )

    assert rc == 2
    payload = json.loads(buf.getvalue())
    assert payload["status"] == "failed"
    assert payload["conflict"] is True
    assert payload["actions"][0]["conflict"] is True
    assert "changed" in payload["actions"][0]["detail"]
    assert payload["no_op"] is False
    assert shim.is_file()


def test_uninstall_json_reports_uninstalled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall", "--json"])

    assert rc == 0
    payload = json.loads(buf.getvalue())
    assert payload["status"] == "uninstalled"
    assert payload["harness"] == "opencode"
    assert payload["actions"][0]["kind"] == "remove_cred_shim"
    assert payload["checks"][0]["status"] == "absent"


def test_uninstall_emits_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)
    state = tmp_path / "state"

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])
    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])

    log = (state / "provenance.jsonl").read_text()
    events = [json.loads(line) for line in log.strip().splitlines()]
    uninstall_events = [e for e in events if e["action"] == "remove_cred_shim"]
    assert len(uninstall_events) >= 1
    assert uninstall_events[-1]["result"] == "applied"
    assert "p@ss-not-leaked" not in log


def test_uninstall_multiple_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET_A", "secret-a")
    monkeypatch.setenv("ACB_TEST_SECRET_B", "secret-b")

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:cred-a"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET_A"\nharnesses=["opencode"]\n'
        '[capability."cred:cred-b"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET_B"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    assert not (tmp_path / "oc" / "command" / "cred-cred-a.md").exists()
    assert not (tmp_path / "oc" / "command" / "cred-cred-b.md").exists()


# ---- codex uninstall ----


def _setup_codex(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    user_skills: list[str] | None = None,
) -> Path:
    """Isolated ``CODEX_HOME`` and ``ACB_HOME``.

    Both are pointed at ``codex_home`` for isolation; user-scoped skills therefore
    resolve to ``codex_home/.agents/skills``.
    """
    codex_home = tmp_path / "codex-home"
    skills_home = codex_home / ".agents" / "skills"
    skills_home.mkdir(parents=True)
    (codex_home / "config.toml").write_text(
        'model = "gpt-5.6"\n\n[mcp_servers.hindsight]\nurl = "https://example/mcp"\n',
        encoding="utf-8",
    )
    sysskill = skills_home / ".system" / "imagegen"
    sysskill.mkdir(parents=True)
    (sysskill / "SKILL.md").write_text("---\nname: imagegen\n---\n", encoding="utf-8")
    for name in user_skills or []:
        d = skills_home / name
        d.mkdir()
        (d / "SKILL.md").write_text(f"---\nname: {name}\n---\n# user's own\n", encoding="utf-8")
    monkeypatch.setenv("ACB_CODEX_HOME", str(codex_home))
    monkeypatch.setenv("ACB_HOME", str(codex_home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(tmp_path / "no-oc.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    return codex_home


def _codex_cred_manifest(tmp_path: Path) -> Path:
    m = tmp_path / "capabilities.toml"
    m.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["codex"]\n',
        encoding="utf-8",
    )
    return m


def test_uninstall_codex_removes_skill_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _setup_codex(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "codex", "-m", str(manifest)])
    assert (home / ".agents" / "skills" / "cred-svc-bot" / "SKILL.md").is_file()

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "codex", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    assert not (home / ".agents" / "skills" / "cred-svc-bot").exists()


def test_uninstall_codex_preserves_user_skills(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _setup_codex(tmp_path, monkeypatch, user_skills=["my-notes"])
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "codex", "-m", str(manifest)])
    with redirect_stdout(io.StringIO()):
        main(["install-harness", "codex", "-m", str(manifest), "--uninstall"])

    assert (home / ".agents" / "skills" / "my-notes" / "SKILL.md").is_file()
    assert (home / ".agents" / "skills" / ".system" / "imagegen" / "SKILL.md").is_file()


def test_uninstall_codex_preserves_hand_authored_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _setup_codex(tmp_path, monkeypatch, user_skills=["cred-svc-bot"])
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)
    shim = home / ".agents" / "skills" / "cred-svc-bot" / "SKILL.md"
    before = shim.read_text(encoding="utf-8")

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "codex", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    assert shim.read_text(encoding="utf-8") == before


def test_uninstall_codex_rechecks_hash_before_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A shim changed after planning is preserved (TOCTOU ownership guard)."""
    home = _setup_codex(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        assert main(["install-harness", "codex", "-m", str(manifest)]) == 0

    cap = Capability(
        "cred:svc-bot",
        "cred",
        ("codex",),
        {"source": "env", "from_env": "ACB_TEST_SECRET"},
    )
    adapter = CodexAdapter()
    action = CredProvider().plan_uninstall(cap, "codex", adapter)[0]
    shim = home / ".agents" / "skills" / "cred-svc-bot" / "SKILL.md"
    shim.write_text(
        shim.read_text(encoding="utf-8") + "\n<!-- concurrent edit -->\n",
        encoding="utf-8",
    )

    result = CredProvider().apply(action, adapter)

    assert result.status == "failed"
    assert "changed after uninstall planning" in result.detail
    assert shim.is_file()


# ---- e2e MCP uninstall ----


def test_uninstall_e2e_removes_acb_installed_mcp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Install a Playwright MCP server via reconcile, then uninstall it."""
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    (oc_root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

    cache = tmp_path / "ms-playwright"
    (cache / "chromium-1223").mkdir(parents=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:chromium"]\nprovider="e2e"\npin="1.43.0"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])
    cfg = json.loads((oc_root / "opencode.json").read_text())
    assert "playwright" in cfg["mcp"]

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    cfg_after = json.loads((oc_root / "opencode.json").read_text())
    assert "playwright" not in cfg_after.get("mcp", {})


def test_uninstall_e2e_preserves_non_acb_mcp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Playwright server that doesn't match acb's expected command is preserved."""
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    cfg = {
        "mcp": {
            "playwright": {
                "type": "local", "enabled": True,
                "command": ["npx", "-y", "@playwright/mcp@0.9.0", "--debug"],
            },
        }
    }
    (oc_root / "opencode.json").write_text(json.dumps(cfg), encoding="utf-8")
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))

    cache = tmp_path / "ms-playwright"
    (cache / "chromium-1223").mkdir(parents=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:chromium"]\nprovider="e2e"\npin="1.43.0"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    cfg_after = json.loads((oc_root / "opencode.json").read_text())
    assert "playwright" in cfg_after["mcp"]
    assert "manual" in buf.getvalue().lower()


# ---- uninstall all ----


def test_uninstall_all_excludes_codex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``all --uninstall`` expands to the stable set, never codex."""
    home = _setup_codex(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "codex", "-m", str(manifest)])
    assert (home / ".agents" / "skills" / "cred-svc-bot" / "SKILL.md").is_file()

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["install-harness", "all", "-m", str(manifest), "--uninstall", "--json"])

    payload = json.loads(buf.getvalue())
    targeted = {r["harness"] for r in payload["results"]}
    assert "codex" not in targeted
    assert (home / ".agents" / "skills" / "cred-svc-bot" / "SKILL.md").is_file()


def test_uninstall_all_json_dry_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main([
            "install-harness", "all", "-m", str(manifest),
            "--uninstall", "--dry-run", "--json",
        ])

    assert rc == 2
    payload = json.loads(buf.getvalue())
    assert payload["status"] == "uninstalled"
    assert [r["harness"] for r in payload["results"]] == ["claude", "opencode"]


# ---- full round-trip: install → uninstall → install ----


def test_full_round_trip_install_uninstall_reinstall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Install, uninstall, and reinstall: the second install is not a no-op."""
    oc_root = _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])
    assert (oc_root / "command" / "cred-svc-bot.md").is_file()

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])
    assert not (oc_root / "command" / "cred-svc-bot.md").exists()

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])
    assert rc == 0
    assert (oc_root / "command" / "cred-svc-bot.md").is_file()


# ---- Claude uninstall ----


def _setup_claude(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    claude_root = tmp_path / "claude"
    claude_root.mkdir()
    (claude_root / "settings.json").write_text('{"mcpServers": {}}', encoding="utf-8")
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(claude_root / "settings.json"))
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(tmp_path / "no-oc.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    return claude_root


def test_uninstall_claude_removes_skill_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claude_root = _setup_claude(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["claude"]\n',
        encoding="utf-8",
    )

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "claude", "-m", str(manifest)])
    assert (claude_root / "skills" / "cred-svc-bot" / "SKILL.md").is_file()

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "claude", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    assert not (claude_root / "skills" / "cred-svc-bot").exists()


def test_uninstall_claude_removes_mcp_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E2e MCP server installed by acb is removed from Claude's settings.json."""
    claude_root = _setup_claude(tmp_path, monkeypatch)
    cache = tmp_path / "ms-playwright"
    (cache / "chromium-1223").mkdir(parents=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:chromium"]\nprovider="e2e"\npin="1.43.0"\nharnesses=["claude"]\n',
        encoding="utf-8",
    )

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "claude", "-m", str(manifest)])
    cfg = json.loads((claude_root / "settings.json").read_text())
    assert "playwright" in cfg["mcpServers"]

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "claude", "-m", str(manifest), "--uninstall"])

    assert rc == 0
    cfg_after = json.loads((claude_root / "settings.json").read_text())
    assert "playwright" not in cfg_after.get("mcpServers", {})


# ---- error handling ----


def test_uninstall_corrupted_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A corrupted manifest produces a clean error, not a traceback."""
    _setup_oc(tmp_path, monkeypatch)
    manifest = tmp_path / "bad.toml"
    manifest.write_text("not valid toml {{{", encoding="utf-8")

    rc = main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])
    assert rc == 2
    assert "error:" in capsys.readouterr().err.lower()


def test_uninstall_e2e_emits_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provenance is emitted for e2e MCP removal."""
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    (oc_root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))

    cache = tmp_path / "ms-playwright"
    (cache / "chromium-1223").mkdir(parents=True)
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(cache))

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:chromium"]\nprovider="e2e"\npin="1.43.0"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )

    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest)])
    with redirect_stdout(io.StringIO()):
        main(["install-harness", "opencode", "-m", str(manifest), "--uninstall"])

    log = (state / "provenance.jsonl").read_text()
    events = [json.loads(line) for line in log.strip().splitlines()]
    remove_events = [e for e in events if e["action"] == "remove_mcp"]
    assert len(remove_events) >= 1
    assert remove_events[-1]["result"] == "applied"
