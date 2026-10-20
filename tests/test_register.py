"""`acb register`: the manifest-append verb.

Register writes operator-controlled strings into the manifest, which later
drives shim filenames and credential injection. It must escape what it writes
and validate the *resulting* manifest before touching the file: a bad write
here can brick every later `acb` command.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_capability_broker.cli import _toml_basic_string, main
from agent_capability_broker.model import parse_manifest

BASE = (
    '[capability."cred:existing"]\nprovider = "cred"\nsource = "env"\n'
    'from_env = "ACB_TEST_SECRET"\nharnesses = ["claude"]\n'
)


@pytest.fixture
def manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    for var, name in (
        ("ACB_CLAUDE_SETTINGS", "no-claude.json"),
        ("ACB_OPENCODE_CONFIG", "no-oc.json"),
        ("ACB_HERMES_CONFIG", "no-hermes.yaml"),
        ("ACB_ZCODE_CONFIG", "no-zcode/cli/config.json"),
        ("ACB_CODEX_HOME", "no-codex"),
    ):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    path = tmp_path / "capabilities.toml"
    path.write_text(BASE, encoding="utf-8")
    monkeypatch.setenv("ACB_MANIFEST", str(path))
    return path


def _register(manifest: Path, cap_id: str, *extra: str) -> int:
    return main(
        ["register", cap_id, "--vault", "kv/example/app/token", "--fields", "token",
         *extra]
    )


def test_register_appends_a_parseable_entry(manifest: Path) -> None:
    assert _register(manifest, "cred:new-token", "--env-prefix", "NEW", "--apply") == 0
    caps = {c.id: c for c in parse_manifest(manifest)}
    new = caps["cred:new-token"]
    assert new.options["vault"] == "kv/example/app/token"
    assert new.options["field"] == "token"
    assert new.options["env_prefix"] == "NEW"
    assert new.harnesses == ("claude", "opencode", "zcode")
    assert "cred:existing" in caps  # the existing entry survives


def test_register_dry_run_writes_nothing(
    manifest: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _register(manifest, "cred:new-token") == 2
    assert manifest.read_text(encoding="utf-8") == BASE
    assert "would append" in capsys.readouterr().out


@pytest.mark.parametrize(
    "cap_id",
    [
        "cred:../escape",       # traversal: parse_manifest rejects it after the fact
        "cred:a/b",
        "cred:a" + chr(92) + "b",
        'cred:a"b',             # not a shim-safe name (and hostile to TOML headers)
        "cred:a b",
        "cred:-x",
        "cred:x\n",             # `$` used to match before a trailing newline
        "e2e:chromium",         # not a cred capability
    ],
)
def test_register_rejects_ids_that_would_corrupt_the_manifest(
    manifest: Path, cap_id: str
) -> None:
    assert _register(manifest, cap_id, "--apply") == 2
    assert manifest.read_text(encoding="utf-8") == BASE  # untouched
    parse_manifest(manifest)  # and still loads


def test_register_rejects_vault_env_with_path_separators(manifest: Path) -> None:
    assert _register(manifest, "cred:new", "--vault-env", "../../evil.env", "--apply") == 2
    assert manifest.read_text(encoding="utf-8") == BASE


def test_register_cannot_inject_extra_keys_through_a_value(manifest: Path) -> None:
    hostile = 'X"\nsource = "env"\nfrom_env = "ACB_TEST_SECRET'
    assert _register(manifest, "cred:new", "--env-prefix", hostile, "--apply") == 0
    new = {c.id: c for c in parse_manifest(manifest)}["cred:new"]
    assert new.options["env_prefix"] == hostile  # kept literal, not interpreted
    assert "source" not in new.options and "from_env" not in new.options


def test_register_values_with_backslashes_round_trip(manifest: Path) -> None:
    # A Windows-style path in a value used to produce invalid TOML escapes.
    assert _register(manifest, "cred:new", "--env-prefix", r"C:\tmp\new", "--apply") == 0
    new = {c.id: c for c in parse_manifest(manifest)}["cred:new"]
    assert new.options["env_prefix"] == r"C:\tmp\new"


def test_register_is_idempotent(manifest: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _register(manifest, "cred:existing", "--apply") == 0
    assert manifest.read_text(encoding="utf-8") == BASE
    assert "already registered" in capsys.readouterr().out


@pytest.mark.parametrize("raw", ['a"b', "a\b", "a\nb", "a\x7fb", "\u00e9\u4e2d", "\x00"])
def test_toml_basic_string_round_trips(raw: str) -> None:
    import tomllib

    assert tomllib.loads(f"v = {_toml_basic_string(raw)}")["v"] == raw
