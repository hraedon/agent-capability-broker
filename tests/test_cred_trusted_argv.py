"""Plan 012 section 5 / WI-012-1: every ``cred`` capability runs only its exact
manifest ``trusted_argv`` and that command may not be a shell or interpreter.

The point of these tests is the *ordering*: a refused command must never cause
a secret to be resolved, so every refusal test runs against a Vault source whose
resolver (and reachability probe) fail the test if they are ever called.
"""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path

import pytest
from _childpy import CHILD_PY, EXAMPLE_TOOL, trusted_toml

from agent_capability_broker import cred_vault, providers
from agent_capability_broker.adapters import OpencodeAdapter
from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability, Status, parse_manifest
from agent_capability_broker.providers import (
    CredProvider,
    _render_cred_shim,
    exec_composed,
)
from agent_capability_broker.secret_sources import (
    SecretSourceConfigError,
    validate_cred_trusted_argv,
    validate_exec_command,
)

SECRET = "vault-secret-canary-31c9"


def _abs(path: str) -> str:
    """``path`` made absolute on *this* platform.

    A POSIX-style ``/usr/bin/x`` is not absolute on Windows (no drive), so the
    absolute-path rule would fire before the shell/interpreter rule these tests
    exercise. ``os.path.abspath`` adds the current drive there and is the
    identity on POSIX. Windows-style paths are returned untouched.
    """
    return os.path.abspath(path) if path.startswith("/") else path


# argv a prompt-injected agent would try against a vault cred.
REFUSED_COMMANDS = [
    ["env"],
    ["/usr/bin/env"],
    ["sh", "-c", "echo $PASSWORD"],
    ["/bin/bash", "-c", "env"],
    ["python3", "-c", "import os; print(os.environ)"],
    ["powershell", "-Command", "Get-ChildItem Env:"],
    ["cmd", "/c", "set"],
    [EXAMPLE_TOOL, "--extra-arg"],  # right program, wrong arguments
]


@pytest.fixture
def no_secret_touched(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> list[str]:
    """Make any attempt to resolve a value, probe Vault, or spawn a child fail.

    Returns the (empty) list of calls so a test can also assert on it.
    """
    calls: list[str] = []

    def _boom(name: str):  # type: ignore[no-untyped-def]
        def inner(*args: object, **kwargs: object) -> object:
            calls.append(name)
            raise AssertionError(f"{name} must not run for a refused command")

        return inner

    monkeypatch.setattr(cred_vault, "resolve", _boom("cred_vault.resolve"))
    monkeypatch.setattr(cred_vault, "reachable", _boom("cred_vault.reachable"))
    monkeypatch.setattr(providers.subprocess, "run", _boom("subprocess.run"))
    monkeypatch.setattr(providers.subprocess, "Popen", _boom("subprocess.Popen"))
    # And an unreachable Vault, in case anything bypasses the stubs above.
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:9")
    monkeypatch.setenv("VAULT_TOKEN", "unused-test-token")
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    return calls


def _vault_cap(**extra: object) -> Capability:
    options: dict[str, object] = {
        "vault": "kv/example/lab/svc",
        "fields": ["username", "password"],
        **extra,
    }
    return Capability("cred:svc", "cred", ("opencode",), options)


def _manifest(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "capabilities.toml"
    path.write_text(
        '[capability."cred:svc"]\nprovider = "cred"\nvault = "kv/example/lab/svc"\n'
        'fields = ["username", "password"]\nharnesses = ["opencode"]\n' + body,
        encoding="utf-8",
    )
    return path


# --- refusal happens before any secret is resolved ---------------------------


@pytest.mark.parametrize("command", REFUSED_COMMANDS, ids=lambda c: " ".join(c)[:40])
def test_provider_refuses_other_commands_before_resolving(
    command: list[str], no_secret_touched: list[str]
) -> None:
    cap = _vault_cap(trusted_argv=[EXAMPLE_TOOL])

    with pytest.raises(SecretSourceConfigError, match="options.trusted_argv"):
        CredProvider().exec(cap, command)

    assert no_secret_touched == []


@pytest.mark.parametrize("command", REFUSED_COMMANDS, ids=lambda c: " ".join(c)[:40])
def test_cli_exec_refuses_other_commands_before_resolving(
    command: list[str],
    no_secret_touched: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = _manifest(tmp_path, trusted_toml([EXAMPLE_TOOL]))

    rc = main(["exec", "-m", str(manifest), "cred:svc", "--", *command])

    assert rc == 2
    assert "does not match options.trusted_argv" in capsys.readouterr().err
    assert no_secret_touched == []
    # Nothing started, so no checkout provenance either.
    assert not (tmp_path / "state" / "provenance.jsonl").exists()


def test_cli_exec_refusal_uses_the_exec_error_envelope(
    no_secret_touched: list[str],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest = _manifest(tmp_path, trusted_toml([EXAMPLE_TOOL]))

    rc = main(["exec", "-m", str(manifest), "--json", "cred:svc", "--", "env"])

    assert rc == 2
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["ok"] is False
    assert envelope["error"]["code"] == "EXEC_ERROR"
    assert "trusted_argv" in envelope["error"]["message"]
    assert no_secret_touched == []


def test_historical_form_without_separator_is_refused_too(
    no_secret_touched: list[str], tmp_path: Path
) -> None:
    manifest = _manifest(tmp_path, trusted_toml([EXAMPLE_TOOL]))

    rc = main(["exec", "-m", str(manifest), "cred:svc", "env"])

    assert rc == 2
    assert no_secret_touched == []


@pytest.mark.parametrize("source_options", [
    {"source": "env", "from_env": "ACB_UNUSED_SRC"},
    {"source": "vault", "vault": "kv/example/lab/svc", "fields": ["password"]},
])
def test_every_non_suite_source_requires_the_exact_command(
    source_options: dict[str, object],
    no_secret_touched: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ACB_UNUSED_SRC", SECRET)
    cap = Capability(
        "cred:svc", "cred", ("opencode",), {**source_options, "trusted_argv": [EXAMPLE_TOOL]}
    )

    with pytest.raises(SecretSourceConfigError, match="does not match"):
        CredProvider().exec(cap, ["env"])

    assert no_secret_touched == []


def test_missing_trusted_argv_refuses_exec_before_resolving(
    no_secret_touched: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = _manifest(tmp_path, "")

    rc = main(["exec", "-m", str(manifest), "cred:svc", "--", "env"])

    assert rc == 2
    assert "options.trusted_argv is required" in capsys.readouterr().err
    assert no_secret_touched == []


# --- composed checkout obeys the same rule -----------------------------------


def _composed_caps(argv_a: list[str], argv_b: list[str]) -> list[Capability]:
    return [
        Capability(
            "cred:a", "cred", ("opencode",),
            {"vault": "kv/example/lab/a", "fields": ["password"], "env_prefix": "A",
             "trusted_argv": argv_a},
        ),
        Capability(
            "cred:b", "cred", ("opencode",),
            {"vault": "kv/example/lab/b", "fields": ["password"], "env_prefix": "B",
             "trusted_argv": argv_b},
        ),
    ]


def test_composed_refuses_arbitrary_command_before_resolving(
    no_secret_touched: list[str],
) -> None:
    caps = _composed_caps([EXAMPLE_TOOL], [EXAMPLE_TOOL])

    with pytest.raises(SecretSourceConfigError, match="does not match"):
        exec_composed(caps, ["env"])

    assert no_secret_touched == []


def test_composed_requires_every_capability_to_qualify_the_command(
    no_secret_touched: list[str],
) -> None:
    # `cred:b` never qualified this program, so `cred:a`'s value must not reach it.
    caps = _composed_caps([EXAMPLE_TOOL], [str(Path(EXAMPLE_TOOL).with_name("other-tool"))])

    with pytest.raises(SecretSourceConfigError, match=r"cred:b.*does not match"):
        exec_composed(caps, [EXAMPLE_TOOL])

    assert no_secret_touched == []


def test_composed_refuses_capability_without_trusted_argv(
    no_secret_touched: list[str],
) -> None:
    caps = _composed_caps([EXAMPLE_TOOL], [EXAMPLE_TOOL])
    caps[1] = Capability("cred:b", "cred", ("opencode",), {"vault": "kv/example/lab/b"})

    with pytest.raises(SecretSourceConfigError, match="trusted_argv is required"):
        exec_composed(caps, [EXAMPLE_TOOL])

    assert no_secret_touched == []


def test_composed_runs_when_all_capabilities_qualify_the_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(
        cred_vault, "resolve", lambda cap: {"password": f"{SECRET}-{cap.name}"}
    )
    out = tmp_path / "seen.json"
    code = (
        f"import json,os,pathlib;pathlib.Path(r'{out}').write_text(json.dumps("
        "[os.environ.get('A_PASSWORD'), os.environ.get('B_PASSWORD')]))"
    )
    child = [CHILD_PY, "-c", code]
    caps = _composed_caps(child, child)

    assert exec_composed(caps, child) == 0
    assert json.loads(out.read_text()) == [f"{SECRET}-a", f"{SECRET}-b"]


# --- the exact trusted command still runs ------------------------------------


def test_exact_trusted_argv_runs_with_the_secret_injected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    resolved: list[str] = []

    def fake_resolve(cap: Capability) -> dict[str, str]:
        resolved.append(cap.id)
        return {"username": "svc-bot", "password": SECRET}

    monkeypatch.setattr(cred_vault, "resolve", fake_resolve)
    out = tmp_path / "seen.txt"
    code = f"import os,pathlib;pathlib.Path(r'{out}').write_text(os.environ['PASSWORD'])"
    child = [CHILD_PY, "-c", code]
    manifest = _manifest(tmp_path, trusted_toml(child))

    rc = main(["exec", "-m", str(manifest), "cred:svc", "--", *child])

    assert rc == 0
    assert resolved == ["cred:svc"]
    assert out.read_text() == SECRET
    captured = capsys.readouterr()
    assert SECRET not in captured.out and SECRET not in captured.err


# --- manifest validation: missing / interpreter-first trusted_argv -----------


def test_missing_trusted_argv_is_a_manifest_error() -> None:
    with pytest.raises(SecretSourceConfigError, match="trusted_argv is required"):
        validate_cred_trusted_argv(_vault_cap())
    with pytest.raises(SecretSourceConfigError, match="trusted_argv is required"):
        validate_cred_trusted_argv(_vault_cap(trusted_argv=[]))
    with pytest.raises(SecretSourceConfigError, match="non-empty strings"):
        validate_cred_trusted_argv(_vault_cap(trusted_argv=[EXAMPLE_TOOL, ""]))


def test_relative_trusted_argv_is_a_manifest_error() -> None:
    with pytest.raises(SecretSourceConfigError, match="absolute"):
        validate_cred_trusted_argv(_vault_cap(trusted_argv=["directory-check"]))


@pytest.mark.parametrize(
    "executable",
    [
        "/bin/sh", "/bin/bash", "/usr/bin/zsh", "/bin/dash", "/usr/bin/pwsh",
        "/usr/bin/powershell", "/usr/bin/env", "/usr/bin/node", "/usr/bin/perl",
        "/usr/bin/ruby", "/usr/bin/python", "/usr/bin/python3", "/usr/bin/python3.14",
        "/usr/bin/python3.14t", "/usr/local/bin/pythonw",
        "/BIN/BASH", "/usr/bin/Python3",
        r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\CMD.EXE",
        r"C:\Program Files\Git\usr\bin\bash.exe", r"C:\Program Files\Git\bin\sh.exe",
        r"C:\Python312\PYTHON.EXE", r"C:\Python312\python3.12.exe",
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Python314\python.exe", r"C:\Program Files\nodejs\node.exe",
        "C:/Windows/System32/cmd.exe",
    ],
)
def test_interpreter_first_trusted_argv_is_a_manifest_error(executable: str) -> None:
    executable = _abs(executable)
    cap = _vault_cap(trusted_argv=[executable, "-c", "anything"])

    with pytest.raises(SecretSourceConfigError, match="shell or interpreter"):
        validate_cred_trusted_argv(cap)
    with pytest.raises(SecretSourceConfigError, match="shell or interpreter"):
        validate_exec_command(cap, [executable, "-c", "anything"])


@pytest.mark.parametrize(
    "executable",
    [
        "/opt/example/bin/directory-check",
        "/usr/bin/envsubst",          # basename match, not a prefix match: not `env`
        "/usr/bin/shred",
        "/usr/local/bin/cmdline-tool",
        r"C:\Program Files\Example\directory-check.exe",
    ],
)
def test_purpose_built_executables_are_accepted(executable: str) -> None:
    executable = _abs(executable)
    cap = _vault_cap(trusted_argv=[executable, "--validate"])

    assert validate_cred_trusted_argv(cap) == (executable, "--validate")
    validate_exec_command(cap, [executable, "--validate"])


def test_interpreter_check_only_looks_at_the_first_element() -> None:
    # An interpreter-named *argument* of a purpose-built tool is fine.
    cap = _vault_cap(trusted_argv=[_abs("/opt/example/bin/runner"), "--shell", "bash"])

    validate_cred_trusted_argv(cap)


def test_parse_manifest_keeps_trusted_argv_for_every_source(tmp_path: Path) -> None:
    caps = parse_manifest(_manifest(tmp_path, trusted_toml([EXAMPLE_TOOL])))

    assert caps[0].options["trusted_argv"] == [EXAMPLE_TOOL]


# --- doctor / reconcile surface the problem instead of crashing --------------


def _doctor_checks_for(manifest: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict:
    root = tmp_path / "oc"
    (root / "command").mkdir(parents=True)
    (root / "opencode.json").write_text('{"mcp": {}}', encoding="utf-8")
    # A shim is present, so only the manifest problem can fail the check.
    (root / "command" / "cred-svc.md").write_text(
        "# shim\n\n```\nacb exec cred:svc -- <exact options.trusted_argv>\n```\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_OPENCODE_CONFIG", str(root / "opencode.json"))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(tmp_path / "no-claude.json"))
    monkeypatch.setenv("ACB_HERMES_CONFIG", str(tmp_path / "no-hermes.yaml"))
    monkeypatch.setenv("ACB_ZCODE_CONFIG", str(tmp_path / "no-zcode.json"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "no-codex"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest), "--json"])
    payload = json.loads(buf.getvalue())
    payload["_rc"] = rc
    return payload


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("", "trusted_argv is required"),
        (trusted_toml([_abs("/bin/sh"), "-c", "true"]), "shell or interpreter"),
        (trusted_toml(["relative-tool"]), "absolute"),
    ],
)
def test_doctor_fails_a_cred_with_a_bad_trusted_argv(
    body: str,
    message: str,
    no_secret_touched: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path, body)

    payload = _doctor_checks_for(manifest, monkeypatch, tmp_path)

    check = next(c for c in payload["checks"] if c["name"] == "cred:svc@opencode")
    assert check["status"] == "fail"
    assert message in check["detail"]
    assert payload["ok"] is False
    assert payload["_rc"] == 1
    assert no_secret_touched == []  # and Vault was never probed


def test_doctor_passes_a_cred_with_a_valid_trusted_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(cred_vault, "reachable", lambda cap, *, vault_env=None: True)
    manifest = _manifest(tmp_path, trusted_toml([EXAMPLE_TOOL]))

    payload = _doctor_checks_for(manifest, monkeypatch, tmp_path)

    check = next(c for c in payload["checks"] if c["name"] == "cred:svc@opencode")
    assert check["status"] == "ok"


def test_inspect_and_reconcile_report_a_bad_trusted_argv(
    tmp_path: Path, no_secret_touched: list[str]
) -> None:
    adapter = OpencodeAdapter(config_path=tmp_path / "opencode.json")
    cap = _vault_cap(trusted_argv=[_abs("/bin/sh")])

    verdict = CredProvider().inspect(cap, "opencode", adapter)
    plan = CredProvider().plan_reconcile(cap, "opencode", adapter)

    assert verdict.status is Status.PRESENT_BROKEN
    assert "shell or interpreter" in verdict.detail
    # reconcile does not render a shim for a capability that can never exec
    assert [a.kind for a in plan] == ["manual"]
    assert no_secret_touched == []


# --- the rendered shim no longer implies arbitrary commands ------------------


@pytest.mark.parametrize("harness", ["claude", "opencode"])
def test_vault_shim_demands_the_exact_trusted_argv(harness: str) -> None:
    text = _render_cred_shim(
        _vault_cap(trusted_argv=[EXAMPLE_TOOL]), harness, "cred-svc", Path("/tmp/vault.env")
    )

    assert "<command>" not in text
    assert "[args...]" not in text
    assert text.count("<exact options.trusted_argv>") == 3  # unix, PowerShell, cmd
    assert "refuses anything else" in text
    assert "acb exec cred:svc" in text  # still discoverable by the surface audit


# --- register writes a qualifying entry --------------------------------------


def test_register_requires_and_writes_trusted_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:x"]\nprovider = "e2e"\nengine = "playwright"\n'
        'browser = "chromium"\nbackend = "local"\nharnesses = ["claude"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_MANIFEST", str(manifest))

    rc = main([
        "register", "cred:newbot", "--vault", "kv/example/lab/newbot", "--fields", "token",
        "--harnesses", "claude", "--apply", "--trusted-argv", EXAMPLE_TOOL, "--validate",
    ])
    capsys.readouterr()

    assert rc == 0
    caps = {c.id: c for c in parse_manifest(manifest)}
    assert caps["cred:newbot"].options["trusted_argv"] == [EXAMPLE_TOOL, "--validate"]
    validate_cred_trusted_argv(caps["cred:newbot"])


def test_register_refuses_an_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    manifest = tmp_path / "capabilities.toml"
    monkeypatch.setenv("ACB_MANIFEST", str(manifest))

    rc = main([
        "register", "cred:newbot", "--vault", "kv/example/lab/newbot", "--fields", "token",
        "--harnesses", "claude", "--apply", "--trusted-argv", _abs("/bin/bash"), "-c", "x",
    ])

    assert rc == 2
    assert "shell or interpreter" in capsys.readouterr().err
    assert not manifest.exists()
