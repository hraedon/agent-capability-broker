"""Plan 005 WI-2.1: install-harness command.

One idempotent command that installs acb's shims into a named harness and
verifies each declared capability is reachable. Re-runnable; --dry-run;
reports per-capability status; a missing credential is a named, actionable
status, not a silent skip.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.cli import main


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
            (cmd_dir / f"{name}.md").write_text("# shim\n", encoding="utf-8")
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


def test_install_harness_creates_shims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])

    out = buf.getvalue()
    assert rc == 0
    assert (tmp_path / "oc" / "command" / "cred-svc-bot.md").is_file()
    assert "present_ok" in out.lower()


def test_install_harness_dry_run_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--dry-run"])

    out = buf.getvalue()
    assert rc == 2
    assert "would apply" in out.lower()
    assert not (tmp_path / "oc" / "command" / "cred-svc-bot.md").exists()


def test_install_harness_rerun_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        rc1 = main(["install-harness", "opencode", "-m", str(manifest)])
    assert rc1 == 0

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc2 = main(["install-harness", "opencode", "-m", str(manifest)])

    assert rc2 == 0
    assert "present_ok" in buf.getvalue().lower()


def test_install_harness_unknown_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _cred_manifest(tmp_path)

    rc = main(["install-harness", "zsh", "-m", str(manifest)])
    assert rc == 2
    assert "unknown harness" in capsys.readouterr().err.lower()


def _setup_codex(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    user_skills: list[str] | None = None,
) -> Path:
    """Isolated CODEX_HOME with an initialised ``config.toml`` (so the adapter is
    ``available()``) plus optional pre-existing user skills and a reserved
    ``.system`` skill acb must neither enumerate nor touch."""
    home = tmp_path / "codex-home"
    (home / "skills").mkdir(parents=True)
    (home / "config.toml").write_text(
        'model = "gpt-5.6"\n\n[mcp_servers.hindsight]\nurl = "https://example/mcp"\n',
        encoding="utf-8",
    )
    # Codex's own bundled skills live under .system — acb must ignore this tree.
    sysskill = home / "skills" / ".system" / "imagegen"
    sysskill.mkdir(parents=True)
    (sysskill / "SKILL.md").write_text("---\nname: imagegen\n---\n", encoding="utf-8")
    for name in user_skills or []:
        d = home / "skills" / name
        d.mkdir()
        (d / "SKILL.md").write_text(f"---\nname: {name}\n---\n# user's own\n", encoding="utf-8")
    monkeypatch.setenv("ACB_CODEX_HOME", str(home))
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(tmp_path / "no-oc.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    return home


def _codex_cred_manifest(tmp_path: Path) -> Path:
    m = tmp_path / "capabilities.toml"
    m.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["codex"]\n',
        encoding="utf-8",
    )
    return m


def test_install_harness_codex_creates_skill_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _setup_codex(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _codex_cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "codex", "-m", str(manifest), "--json"])

    assert rc == 0
    payload = json.loads(buf.getvalue())
    assert payload["harness"] == "codex"
    assert payload["status"] == "installed"

    shim = home / "skills" / "cred-svc-bot" / "SKILL.md"
    assert shim.is_file()
    body = shim.read_text(encoding="utf-8")
    # Codex skills need a `name:` in frontmatter, same as Claude Code.
    assert "name: cred-svc-bot" in body
    # Inject-don't-surface: the shim teaches `acb exec`, never a get/print/value.
    assert "acb exec cred:svc-bot" in body
    assert "p@ss-not-leaked" not in body
    for banned in ("acb get", "print the", "inspect-value", "clipboard"):
        assert banned not in body.lower()


def test_install_harness_codex_dry_run_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _setup_codex(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "codex", "-m", str(manifest), "--dry-run"])

    assert rc == 2
    assert not (home / "skills" / "cred-svc-bot" / "SKILL.md").exists()


def test_install_harness_codex_rerun_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_codex(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        rc1 = main(["install-harness", "codex", "-m", str(manifest)])
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc2 = main(["install-harness", "codex", "-m", str(manifest), "--json"])

    assert rc1 == 0 and rc2 == 0
    payload = json.loads(buf.getvalue())
    assert payload["no_op"] is True


def test_install_harness_codex_preserves_user_skills_and_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = _setup_codex(tmp_path, monkeypatch, user_skills=["my-notes"])
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)
    config_before = (home / "config.toml").read_text(encoding="utf-8")
    user_before = (home / "skills" / "my-notes" / "SKILL.md").read_text(encoding="utf-8")
    sys_before = (home / "skills" / ".system" / "imagegen" / "SKILL.md").read_text(encoding="utf-8")

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "codex", "-m", str(manifest)])

    assert rc == 0
    # acb never touches Codex config, the user's own skill, or the .system tree.
    assert (home / "config.toml").read_text(encoding="utf-8") == config_before
    assert (home / "skills" / "my-notes" / "SKILL.md").read_text(encoding="utf-8") == user_before
    assert (
        home / "skills" / ".system" / "imagegen" / "SKILL.md"
    ).read_text(encoding="utf-8") == sys_before


def test_install_harness_codex_refuses_to_clobber_hand_edited_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A pre-existing shim of the same name is the operator's; acb must not
    # overwrite it — it reports the capability present and re-run is a no-op.
    home = _setup_codex(tmp_path, monkeypatch, user_skills=["cred-svc-bot"])
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)
    before = (home / "skills" / "cred-svc-bot" / "SKILL.md").read_text(encoding="utf-8")

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "codex", "-m", str(manifest), "--json"])

    assert rc == 0
    assert (home / "skills" / "cred-svc-bot" / "SKILL.md").read_text(encoding="utf-8") == before
    assert json.loads(buf.getvalue())["no_op"] is True


def test_install_harness_all_excludes_codex(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Plan 007 Decision 2: `all` stays the stable set (claude, opencode) until
    # Codex conformance is proven; it never silently expands to codex.
    home = _setup_codex(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "x")
    manifest = _codex_cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["install-harness", "all", "-m", str(manifest), "--json"])

    payload = json.loads(buf.getvalue())
    targeted = {r["harness"] for r in payload["results"]}
    assert "codex" not in targeted
    assert not (home / "skills" / "cred-svc-bot").exists()


def test_install_harness_json_reports_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(
            ["install-harness", "opencode", "-m", str(manifest), "--json"]
        )

    assert rc == 0
    payload = json.loads(buf.getvalue())
    assert payload["status"] == "installed"
    assert payload["harness"] == "opencode"
    assert payload["checks"][0]["status"] == "present_ok"


def test_install_harness_supported_json_dry_run_uses_contract_exit_two(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(
            [
                "install-harness",
                "opencode",
                "-m",
                str(manifest),
                "--dry-run",
                "--json",
            ]
        )

    assert rc == 2
    payload = json.loads(buf.getvalue())
    assert payload["tool"] == "acb"
    assert payload["harness"] == "opencode"
    assert payload["status"] == "installed"
    assert payload["no_op"] is False
    assert payload["actions"]


def test_requested_unavailable_adapter_unknown_is_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "missing.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["claude"]\n',
        encoding="utf-8",
    )

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "claude", "-m", str(manifest), "--json"])

    assert rc == 1
    payload = json.loads(buf.getvalue())
    assert payload["status"] == "failed"
    assert payload["checks"][0]["status"] == "unknown"


def test_install_harness_missing_credential_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A missing credential is a named, actionable status, not a silent skip."""
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.delenv("ACB_TEST_SECRET", raising=False)
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])

    out = buf.getvalue()
    assert "applied" in out.lower()          # shim was installed
    assert "present_broken" in out.lower()    # broker unreachable (env not set)
    assert rc == 1


def test_install_harness_reports_per_capability_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["install-harness", "opencode", "-m", str(manifest)])

    out = buf.getvalue()
    assert "cred:svc-bot" in out
    assert "opencode" in out
    assert "present_ok" in out.lower()
    assert "capability status" in out.lower()


def test_install_harness_only_provisions_named_harness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    oc_root = tmp_path / "oc"
    oc_root.mkdir()
    (oc_root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    claude_root = tmp_path / "claude"
    claude_root.mkdir()
    (claude_root / "settings.json").write_text('{}', encoding="utf-8")

    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(claude_root / "settings.json"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:svc-bot"]\nprovider="cred"\nsource="env"\n'
        'from_env="ACB_TEST_SECRET"\nharnesses=["claude", "opencode"]\n',
        encoding="utf-8",
    )

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])
    assert rc == 0

    assert (oc_root / "command" / "cred-svc-bot.md").is_file()
    assert not (claude_root / "skills").exists()


def test_install_harness_provisioned_harness_dry_run_is_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """--dry-run on a fully-provisioned harness reports nothing to install."""
    _setup_oc(tmp_path, monkeypatch, shims=["cred-svc-bot"])
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest), "--dry-run"])

    assert rc == 2
    assert "nothing to install" in buf.getvalue().lower()


def test_install_harness_all_expands_stable_targets_with_contract_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(
            [
                "install-harness",
                "all",
                "-m",
                str(manifest),
                "--dry-run",
                "--json",
            ]
        )

    assert rc == 2
    payload = json.loads(buf.getvalue())
    assert payload["tool"] == "acb"
    assert payload["harness"] == "all"
    assert payload["status"] == "installed"
    assert payload["no_op"] is False
    assert [record["harness"] for record in payload["results"]] == [
        "claude",
        "opencode",
    ]
    assert all(record["tool"] == "acb" for record in payload["results"])
    assert all(record["status"] == "installed" for record in payload["results"])


def test_install_harness_all_is_noop_only_when_both_records_are_noop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)
    with redirect_stdout(io.StringIO()):
        assert main(["install-harness", "opencode", "-m", str(manifest)]) == 0

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(
            [
                "install-harness",
                "all",
                "-m",
                str(manifest),
                "--dry-run",
                "--json",
            ]
        )

    assert rc == 2
    payload = json.loads(buf.getvalue())
    assert payload["no_op"] is True
    assert all(record["no_op"] is True for record in payload["results"])


def test_install_harness_emits_provenance_for_manual_actions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MEDIUM-3 fix: manual actions emit provenance (matching reconcile)."""
    # Shim already present but broker unreachable → manual action in the plan.
    _setup_oc(tmp_path, monkeypatch, shims=["cred-svc-bot"])
    monkeypatch.delenv("ACB_TEST_SECRET", raising=False)
    manifest = _cred_manifest(tmp_path)

    with redirect_stdout(io.StringIO()):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])

    assert rc == 1  # PRESENT_BROKEN
    log = (tmp_path / "state" / "provenance.jsonl").read_text()
    event = json.loads(log.strip())
    assert event["action"] == "manual"
    assert event["result"] == "skipped"


def test_install_harness_multiple_capabilities(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Multiple capabilities are all provisioned in one run."""
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

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["install-harness", "opencode", "-m", str(manifest)])

    out = buf.getvalue()
    assert rc == 0
    assert (tmp_path / "oc" / "command" / "cred-cred-a.md").is_file()
    assert (tmp_path / "oc" / "command" / "cred-cred-b.md").is_file()
    assert "cred:cred-a" in out
    assert "cred:cred-b" in out


def test_install_harness_apply_error_is_handled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If provider.apply() raises, install-harness reports a failure instead of
    crashing with an unhandled traceback."""
    _setup_oc(tmp_path, monkeypatch)
    monkeypatch.setenv("ACB_TEST_SECRET", "p@ss-not-leaked")
    manifest = _cred_manifest(tmp_path)

    from agent_capability_broker.providers import CredProvider

    original_apply = CredProvider.apply

    def raising_apply(self: CredProvider, action: object, adapter: object) -> object:
        raise FileExistsError("simulated race condition")

    monkeypatch.setattr(CredProvider, "apply", raising_apply)

    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["install-harness", "opencode", "-m", str(manifest)])

        out = buf.getvalue()
        assert "FAILED" in out.upper() or "failed" in out
        assert rc != 0
    finally:
        monkeypatch.setattr(CredProvider, "apply", original_apply)
