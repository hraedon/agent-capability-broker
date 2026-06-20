"""cred exec: inject-don't-surface. The secret reaches the child's environment
and nowhere else — not stdout, not stderr, not the provenance event.

These use the `env` cred source so the safety property is provable in CI without
a live Vault; the Vault source shares the same injection path.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability
from agent_capability_broker.providers import CredProvider

SECRET = "p@ssw0rd-do-not-leak-7f3a"


def _writer_argv(out: Path, var: str) -> list[str]:
    """A child that records what it received for `var` (proves injection)."""
    code = (
        f"import os, pathlib; "
        f"pathlib.Path(r'{out}').write_text(os.environ.get({var!r}, 'MISSING'))"
    )
    return [sys.executable, "-c", code]


def test_child_receives_secret_provider_stays_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("SRC", SECRET)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    out = tmp_path / "seen.txt"
    cap = Capability(
        "cred:test", "cred", ("opencode",),
        {"source": "env", "from_env": "SRC", "field": "password"},
    )

    rc = CredProvider().exec(cap, _writer_argv(out, "PASSWORD"))

    assert rc == 0
    assert out.read_text() == SECRET            # child got the real secret
    captured = capsys.readouterr()
    assert SECRET not in captured.out and SECRET not in captured.err  # acb stayed silent


def test_inject_mapping_renames_env_var(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SRC", SECRET)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    out = tmp_path / "seen.txt"
    cap = Capability(
        "cred:db", "cred", ("opencode",),
        {"source": "env", "from_env": "SRC", "field": "password",
         "inject": {"password": "PGPASSWORD"}},
    )

    CredProvider().exec(cap, _writer_argv(out, "PGPASSWORD"))
    assert out.read_text() == SECRET


def test_provenance_has_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SRC", SECRET)
    state = tmp_path / "state"
    monkeypatch.setenv("ACB_STATE_DIR", str(state))
    cap = Capability(
        "cred:test", "cred", ("opencode",),
        {"source": "env", "from_env": "SRC"},
    )

    CredProvider().exec(cap, [sys.executable, "-c", "pass"])
    log = (state / "provenance.jsonl").read_text()
    event = json.loads(log.strip())
    assert event["action"] == "exec"
    assert "PASSWORD" in event["summary"]        # records the var name...
    assert SECRET not in log                      # ...never the value


def test_missing_env_source_errors(tmp_path: Path) -> None:
    cap = Capability("cred:x", "cred", ("opencode",), {"source": "env", "from_env": "NOPE"})
    with pytest.raises(RuntimeError, match=r"NOPE"):
        CredProvider().exec(cap, [sys.executable, "-c", "pass"])


def test_multi_field_exec_injects_each_and_stays_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Multi-field resolve (WI-006): the vault source returns username+password,
    and exec injects BOTH into the child's env — without leaking either to
    stdout/stderr/provenance. Proves the injection machinery handles a dict of
    fields, not just the single-field env source."""
    from agent_capability_broker import cred_vault

    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    cap = Capability(
        "cred:ad", "cred", ("opencode",),
        {"vault": "kv/x/y", "fields": ["username", "password"]},
    )
    secrets = {"username": "svc-bot", "password": SECRET}
    monkeypatch.setattr(cred_vault, "resolve", lambda c: secrets)

    out = tmp_path / "seen.txt"
    # Child records both vars it received.
    code = (
        f"import os, pathlib; "
        f"pathlib.Path(r'{out}').write_text("
        f"os.environ.get('USERNAME','?') + '|' + os.environ.get('PASSWORD','?'))"
    )
    rc = CredProvider().exec(cap, [sys.executable, "-c", code])

    assert rc == 0
    received = out.read_text()
    assert received == f"svc-bot|{SECRET}"  # both fields injected
    captured = capsys.readouterr()
    assert SECRET not in captured.out and SECRET not in captured.err  # broker silent

    log = (tmp_path / "state" / "provenance.jsonl").read_text()
    assert SECRET not in log and "svc-bot" not in log  # provenance carries no value
    assert "PASSWORD" in log and "USERNAME" in log       # ...only the var names


def test_cli_exec_passes_child_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SRC", SECRET)
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:test"]\nprovider="cred"\nsource="env"\n'
        'from_env="SRC"\nharnesses=["opencode"]\n',
        encoding="utf-8",
    )
    child = [sys.executable, "-c", "raise SystemExit(7)"]
    rc = main(["exec", "-m", str(manifest), "cred:test", "--", *child])
    assert rc == 7
