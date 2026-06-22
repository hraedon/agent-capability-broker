"""Manifest parsing + validation. No backend, no secrets, no mutation."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_capability_broker.model import ManifestError, parse_manifest, resolve_manifest

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


def test_id_prefix_mismatch_rejected(tmp_path: Path) -> None:
    p = _write(tmp_path, '[capability."cred:svc-bot"]\nprovider = "e2e"\nharnesses = ["claude"]\n')
    with pytest.raises(ManifestError, match="ID prefix .* does not match"):
        parse_manifest(p)


# --- manifest discovery (CWD-independent) -----------------------------------
# Regression for the cross-harness failure: acb resolved `capabilities.toml`
# against CWD only, so from any directory but its own repo it could not find the
# manifest. Discovery now mirrors the rest of acb ($ACB_* -> XDG -> CWD).

def test_explicit_path_always_wins(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACB_MANIFEST", str(tmp_path / "from-env.toml"))
    explicit = tmp_path / "explicit.toml"
    assert resolve_manifest(explicit) == explicit  # never consults the search path


def test_env_override_resolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = tmp_path / "estate.toml"
    target.write_text('[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\n')
    monkeypatch.setenv("ACB_MANIFEST", str(target))
    assert resolve_manifest() == target


def test_xdg_location_found_without_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ACB_MANIFEST", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)  # no ./capabilities.toml here
    canonical = tmp_path / "acb" / "capabilities.toml"
    canonical.parent.mkdir(parents=True)
    canonical.write_text('[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\n')
    assert resolve_manifest() == canonical


def test_missing_manifest_names_every_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ACB_MANIFEST", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ManifestError, match=r"looked in:.*acb/capabilities\.toml"):
        resolve_manifest()
