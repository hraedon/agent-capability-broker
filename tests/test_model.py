"""Manifest parsing + validation. No backend, no secrets, no mutation."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_capability_broker.model import ManifestError, parse_manifest

EXAMPLE = Path(__file__).resolve().parents[1] / "docs" / "capabilities.example.toml"


def _write(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "capabilities.toml"
    p.write_text(body, encoding="utf-8")
    return p


def test_example_manifest_parses() -> None:
    caps = parse_manifest(EXAMPLE)
    ids = {c.id for c in caps}
    assert ids == {"cred:svc-bot", "e2e:chromium"}
    e2e = next(c for c in caps if c.id == "e2e:chromium")
    assert e2e.provider == "e2e"
    assert e2e.harnesses == ("claude", "opencode")
    # provider-specific keys land in options, not the core fields
    assert e2e.options["browser"] == "chromium"
    assert "provider" not in e2e.options


def test_unknown_provider_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, '[capability."x:y"]\nprovider = "nope"\nharnesses = ["claude"]\n')
    with pytest.raises(ManifestError, match="unknown or missing provider"):
        parse_manifest(p)


def test_unknown_harness_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, '[capability."cred:a"]\nprovider = "cred"\nharnesses = ["zsh"]\n')
    with pytest.raises(ManifestError, match="unknown harness"):
        parse_manifest(p)


def test_empty_manifest_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, "# nothing here\n")
    with pytest.raises(ManifestError, match="no .* entries"):
        parse_manifest(p)
