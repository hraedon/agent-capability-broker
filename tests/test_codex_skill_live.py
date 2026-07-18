"""Real-CLI discovery proof for an ACB-generated shared Codex skill."""

from __future__ import annotations

import io
import os
import shutil
import subprocess
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.cli import main

pytestmark = pytest.mark.skipif(
    shutil.which("codex") is None,
    reason="codex CLI not installed — live skill discovery proof is skipped",
)


def test_real_codex_discovers_generated_shared_skill(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No model call or user auth: ``debug prompt-input`` renders discovery."""
    home = tmp_path / "home"
    codex_home = home / ".codex"
    codex_home.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("ACB_HOME", str(home))
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    monkeypatch.setenv("ACB_CODEX_HOME", str(codex_home))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("ACB_SYNTHETIC_SECRET", "not-a-real-credential")

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:synthetic-proof"]\n'
        'provider="cred"\nsource="env"\n'
        'from_env="ACB_SYNTHETIC_SECRET"\n'
        'harnesses=["codex"]\n',
        encoding="utf-8",
    )
    with redirect_stdout(io.StringIO()):
        assert main(["install-harness", "codex", "-m", str(manifest)]) == 0

    proc = subprocess.run(
        ("codex", "debug", "prompt-input", "Use the synthetic proof capability."),
        cwd=tmp_path,
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert proc.returncode == 0, proc.stderr
    assert "cred-synthetic-proof" in proc.stdout
    assert "cred:synthetic-proof" in proc.stdout
    assert "not-a-real-credential" not in proc.stdout
