"""Plan 003: the command/skill shim surface (read side) and `acb shims`.

Reproduces the live drift this slice exists to catch — a tooling shim exposed in
one harness (opencode command) with no counterpart in another (Claude skill) —
one layer below the MCP capabilities that `doctor` reasons about.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.adapters import ClaudeAdapter, OpencodeAdapter
from agent_capability_broker.cli import _shim_gap, main


def _opencode_tree(root: Path, commands: list[str]) -> OpencodeAdapter:
    (root / "command").mkdir(parents=True)
    for name in commands:
        (root / "command" / f"{name}.md").write_text("# shim\n", encoding="utf-8")
    return OpencodeAdapter(config_path=root / "opencode.json")


def _claude_tree(root: Path, skills: list[str], *, bare: list[str] | None = None) -> ClaudeAdapter:
    skills_dir = root / "skills"
    skills_dir.mkdir(parents=True)
    for name in skills:
        (skills_dir / name).mkdir()
        (skills_dir / name / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    for name in bare or []:  # dir without SKILL.md => not an exposed skill
        (skills_dir / name).mkdir()
    return ClaudeAdapter(settings_path=root / "settings.json")


def test_opencode_shims_are_md_stems(tmp_path: Path) -> None:
    adapter = _opencode_tree(tmp_path, ["start", "end", "cert-watch-e2e"])
    # A stray non-md file is ignored.
    (tmp_path / "command" / "notes.txt").write_text("x", encoding="utf-8")
    assert adapter.command_shims() == {"start", "end", "cert-watch-e2e"}


def test_claude_shims_require_skill_md(tmp_path: Path) -> None:
    adapter = _claude_tree(tmp_path, ["start", "end"], bare=["half-built"])
    assert adapter.command_shims() == {"start", "end"}  # bare dir excluded


def test_missing_shim_dir_is_empty_not_error(tmp_path: Path) -> None:
    assert OpencodeAdapter(config_path=tmp_path / "opencode.json").command_shims() == set()
    assert ClaudeAdapter(settings_path=tmp_path / "settings.json").command_shims() == set()


def test_shim_gap_flags_asymmetry() -> None:
    surfaces = {"claude": {"start", "end"}, "opencode": {"start", "end", "cert-watch-e2e"}}
    assert _shim_gap(surfaces) == {"cert-watch-e2e"}


def test_shim_gap_symmetric_is_clean() -> None:
    surfaces = {"claude": {"start", "end"}, "opencode": {"start", "end"}}
    assert _shim_gap(surfaces) == set()


def test_shim_gap_single_harness_has_nothing_to_compare() -> None:
    assert _shim_gap({"opencode": {"start", "end"}}) == set()


def _point_env(monkeypatch: pytest.MonkeyPatch, claude_root: Path, oc_root: Path) -> None:
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(claude_root / "settings.json"))
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(oc_root / "opencode.json"))


def test_cli_shims_reports_gap_and_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claude_root, oc_root = tmp_path / "claude", tmp_path / "oc"
    _claude_tree(claude_root, ["start", "end"])
    _opencode_tree(oc_root, ["start", "end", "cert-watch-e2e"])
    _point_env(monkeypatch, claude_root, oc_root)

    before = sorted(p.name for p in tmp_path.rglob("*"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["shims"])

    out = buf.getvalue()
    assert rc == 1
    assert "cert-watch-e2e" in out and "parity gap" in out
    # Read path mutates nothing on disk.
    assert sorted(p.name for p in tmp_path.rglob("*")) == before


def test_cli_shims_symmetric_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claude_root, oc_root = tmp_path / "claude", tmp_path / "oc"
    _claude_tree(claude_root, ["start", "end"])
    _opencode_tree(oc_root, ["start", "end"])
    _point_env(monkeypatch, claude_root, oc_root)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["shims"])
    assert rc == 0
    assert "parity gap" not in buf.getvalue()


def test_cli_shims_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    claude_root, oc_root = tmp_path / "claude", tmp_path / "oc"
    _claude_tree(claude_root, ["start"])
    _opencode_tree(oc_root, ["start", "cert-watch-e2e"])
    _point_env(monkeypatch, claude_root, oc_root)

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["shims", "--json"])
    payload = json.loads(buf.getvalue())
    assert rc == 1
    assert payload["gap"] == ["cert-watch-e2e"]
    assert payload["surfaces"]["claude"] == ["start"]
