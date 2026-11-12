"""Per-capability opt-out from the exact-command rule: explicit, reported, and
never silent."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability, parse_manifest
from agent_capability_broker.secret_sources import (
    SecretSourceConfigError,
    unqualified_exec,
    validate_cred_trusted_argv,
    validate_exec_command,
)

TOOL = "C:\\tools\\example.exe" if __import__("os").name == "nt" else "/opt/tools/example"


def _cap(**options: object) -> Capability:
    return Capability("cred:svc-bot", "cred", ("claude",), {"vault": "kv/example/x", **options})


def test_neither_declaration_is_still_an_error_and_names_the_opt_out() -> None:
    with pytest.raises(SecretSourceConfigError, match="unqualified_exec"):
        validate_cred_trusted_argv(_cap())
    with pytest.raises(SecretSourceConfigError):
        validate_exec_command(_cap(), [TOOL])


def test_the_opt_out_allows_any_command() -> None:
    cap = _cap(unqualified_exec=True)
    assert unqualified_exec(cap) is True
    assert validate_cred_trusted_argv(cap) == ()
    validate_exec_command(cap, ["anything", "at", "all"])


def test_an_exact_command_is_still_exact() -> None:
    cap = _cap(trusted_argv=[TOOL, "--validate"])
    assert unqualified_exec(cap) is False
    validate_exec_command(cap, [TOOL, "--validate"])
    with pytest.raises(SecretSourceConfigError, match="does not match"):
        validate_exec_command(cap, [TOOL])


@pytest.mark.parametrize(
    "options",
    [
        {"unqualified_exec": True, "trusted_argv": [TOOL]},
        {"unqualified_exec": "yes"},
        {"unqualified_exec": True, "source": "suite"},
    ],
)
def test_ambiguous_or_malformed_declarations_are_refused(options: dict[str, object]) -> None:
    with pytest.raises(SecretSourceConfigError):
        validate_cred_trusted_argv(_cap(**options))


def test_false_is_the_same_as_absent() -> None:
    assert unqualified_exec(_cap(unqualified_exec=False, trusted_argv=[TOOL])) is False


def test_doctor_warns_for_each_unqualified_capability(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACB_T", "set")
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:loose"]\nprovider="cred"\nsource="env"\nfrom_env="ACB_T"\n'
        'unqualified_exec=true\nharnesses=["opencode"]\n\n'
        '[capability."cred:tight"]\nprovider="cred"\nsource="env"\nfrom_env="ACB_T"\n'
        f"trusted_argv=[{json.dumps(TOOL)}]\nharnesses=[\"opencode\"]\n",
        encoding="utf-8",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["doctor", "-m", str(manifest), "--json"])
    checks = json.loads(buf.getvalue())["checks"]
    warned = [c for c in checks if c.get("kind") == "unqualified_exec"]
    assert [(c["capability"], c["status"]) for c in warned] == [("cred:loose", "warn")]


def test_register_writes_the_opt_out_and_requires_a_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:x"]\nprovider = "e2e"\nengine = "playwright"\n'
        'browser = "chromium"\nbackend = "local"\nharnesses = ["claude"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_MANIFEST", str(manifest))
    base = ["register", "cred:newbot", "--vault", "kv/example/lab/newbot", "--fields", "token",
            "--harnesses", "claude"]
    assert main([*base, "--apply"]) == 2
    assert main([*base, "--apply", "--unqualified-exec"]) == 0
    caps = {c.id: c for c in parse_manifest(manifest)}
    assert caps["cred:newbot"].options["unqualified_exec"] is True
    assert "trusted_argv" not in caps["cred:newbot"].options
