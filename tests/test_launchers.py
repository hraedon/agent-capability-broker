"""The shell / interpreter / launcher denylist for ``trusted_argv`` (Plan 012 section 10 (b)).

One matcher (``launchers.is_launcher``), three enforcement points: manifest
parsing, ``doctor`` (the provider's ``inspect``) and ``acb exec`` (the exact-argv
guard). It is a lint guard against operator mistakes, not a sandbox.
"""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path

import pytest
from _childpy import EXAMPLE_TOOL, trusted_toml

from agent_capability_broker import secret_sources
from agent_capability_broker.cli import main
from agent_capability_broker.launchers import LAUNCHER_NAMES, is_launcher, launcher_basename
from agent_capability_broker.model import Capability, ManifestError, parse_manifest
from agent_capability_broker.secret_sources import (
    SecretSourceConfigError,
    validate_cred_trusted_argv,
    validate_exec_command,
)

# What the 2026-10-28 external review asked to add, on top of the original list.
ADDED = [
    "ksh", "fish", "csh", "tcsh", "py", "wscript", "cscript", "mshta", "rundll32",
    "regsvr32", "busybox", "toybox", "nice", "nohup", "timeout", "stdbuf", "setsid",
    "sudo", "doas", "su", "xargs", "find", "awk", "gawk", "mawk", "sed", "uv", "uvx",
    "npx", "bunx", "bun", "deno", "php", "lua", "tclsh", "wish", "expect", "osascript",
    "ssh", "script",
]
ORIGINAL = [
    "sh", "bash", "zsh", "dash", "pwsh", "powershell", "cmd", "python", "node", "perl",
    "ruby", "env",
]


def _abs(path: str) -> str:
    return os.path.abspath(path) if path.startswith("/") else path


def _cap(argv: list[str]) -> Capability:
    return Capability(
        id="cred:svc", provider="cred", harnesses=("opencode",),
        options={"source": "vault", "trusted_argv": argv},
    )


@pytest.mark.parametrize("name", ADDED + ORIGINAL)
def test_every_listed_name_is_a_launcher(name: str) -> None:
    assert name in LAUNCHER_NAMES or name == "python"
    assert is_launcher(name)
    assert is_launcher(f"/usr/bin/{name}")
    assert is_launcher(f"/usr/bin/{name.upper()}")


@pytest.mark.parametrize("name", ADDED + ORIGINAL)
@pytest.mark.parametrize("ext", [".exe", ".com", ".bat", ".cmd", ".ps1", ".EXE", ".Ps1"])
def test_windows_style_names_and_extensions(name: str, ext: str) -> None:
    assert is_launcher(f"C:\\Windows\\System32\\{name}{ext}")
    assert is_launcher(f"C:/Tools/{name}{ext}")


@pytest.mark.parametrize(
    "executable",
    [
        r"C:\Windows\System32\CMD.EXE",
        r"C:\Windows\py.exe",
        r"C:\Windows\System32\wscript.exe",
        r"C:\Windows\System32\mshta.EXE",
        r"C:\Windows\System32\rundll32.exe",
        r"C:\Windows\System32\regsvr32.exe",
        r"C:\Windows\System32\OpenSSH\ssh.exe",
        r"C:\Windows\System32\timeout.exe",
        r"C:\Windows\System32\find.exe",
        r"C:\Program Files\Git\usr\bin\xargs.exe",
        r"C:\Program Files\Git\usr\bin\awk.exe",
        r"C:\Users\x\.cargo\bin\uv.exe",
        r"C:\Program Files\nodejs\npx.cmd",
        r"C:\Program Files\PowerShell\7\pwsh.ps1",
        "C:\\Windows\\System32\\cmd.exe ",     # Windows ignores trailing spaces / dots
        "C:\\Windows\\System32\\cmd.exe.",
        r"C:\Windows\System32\cmd.bat.exe",
    ],
)
def test_windows_style_paths(executable: str) -> None:
    assert is_launcher(executable)


@pytest.mark.parametrize(
    "executable",
    [
        # version suffixes across the interpreter families
        "/usr/bin/python3.13", "/usr/bin/python3.14t", "/usr/bin/python2", "/usr/bin/pythonw",
        "/usr/bin/pypy3", "/usr/bin/pypy3.10",
        "/usr/bin/lua5.4", "/usr/bin/lua5.1", "/usr/bin/luajit",
        "/usr/bin/php8.3", "/usr/bin/php7", "/usr/bin/php-8.3",
        "/usr/bin/ruby3.2", "/usr/bin/ruby3",
        "/usr/bin/perl5.38", "/usr/bin/perl5.38.2",
        "/usr/bin/node22", "/usr/bin/node18.19", "/usr/bin/nodejs",
        "/usr/bin/tclsh8.6", "/usr/bin/wish8.6",
        r"C:\Program Files\PHP\php8.3.exe",
        r"C:\Python313\python3.13.exe",
        r"C:\Program Files\nodejs\node22.exe",
    ],
)
def test_versioned_interpreter_families(executable: str) -> None:
    assert is_launcher(executable)


@pytest.mark.parametrize(
    "executable",
    [
        "/opt/example/bin/directory-check",
        "/usr/bin/envsubst",             # not `env`
        "/usr/bin/shred", "/usr/bin/shasum", "/usr/bin/nodeinfo", "/usr/bin/rubric",
        "/usr/bin/lualatex", "/usr/bin/phpize", "/usr/bin/perlbrew",
        "/usr/local/bin/cmdline-tool", "/usr/bin/sshd", "/usr/bin/scripts", "/usr/bin/suid-tool",
        "/usr/bin/pyright",  # `py` is exact, not a prefix
        "/usr/bin/uvicorn", "/usr/bin/bunyan", "/usr/bin/denoise", "/usr/bin/timeout-watcher",
        r"C:\Program Files\Example\directory-check.exe",
        r"C:\Program Files\Example\directory-check.cmd",
        "",
    ],
)
def test_purpose_built_names_are_not_launchers(executable: str) -> None:
    assert not is_launcher(executable)


def test_basename_normalisation() -> None:
    assert launcher_basename(r"C:\Windows\System32\CMD.EXE") == "cmd"
    assert launcher_basename("/usr/bin/Python3.13") == "python3.13"
    assert launcher_basename("C:/x/run.cmd") == "run"
    assert launcher_basename("/opt/example/bin/tool") == "tool"


# --- enforced at exec time ---------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["ssh", "xargs", "sudo", "py", "timeout", "awk", "uvx", "python3.13"]
)
def test_exec_guard_refuses_added_launchers(name: str) -> None:
    exe = _abs(f"/usr/bin/{name}")
    cap = _cap([exe, "--help"])
    with pytest.raises(SecretSourceConfigError, match="shell or interpreter"):
        validate_cred_trusted_argv(cap)
    with pytest.raises(SecretSourceConfigError, match="shell or interpreter"):
        validate_exec_command(cap, [exe, "--help"])


def test_exec_guard_refuses_windows_style_launcher() -> None:
    cap = _cap([r"C:\Windows\System32\mshta.exe", "x"])
    with pytest.raises(SecretSourceConfigError, match="shell or interpreter"):
        validate_cred_trusted_argv(cap)


def test_only_one_list_exists() -> None:
    # secret_sources must not keep a private copy that could drift from the shared list.
    for name in ("_INTERPRETER_NAMES", "_INTERPRETER_PREFIXES", "_is_interpreter"):
        assert not hasattr(secret_sources, name)


# --- enforced when the manifest is parsed --------------------------------------------


def _manifest(tmp_path: Path, argv: list[str], provider: str = "cred") -> Path:
    p = tmp_path / "capabilities.toml"
    p.write_text(
        f'[capability."{provider}:svc"]\nprovider = "{provider}"\nharnesses = ["opencode"]\n'
        + trusted_toml(argv),
        encoding="utf-8",
    )
    return p


@pytest.mark.parametrize(
    "executable",
    ["/usr/bin/ssh", "/usr/bin/xargs", "/usr/bin/lua5.4", "/usr/bin/php8.3", "/usr/bin/node22",
     r"C:\Windows\System32\mshta.exe", r"C:\Windows\py.exe", "C:/Tools/stdbuf.exe", "/bin/sh"],
)
def test_parse_manifest_rejects_a_launcher_first_trusted_argv(
    tmp_path: Path, executable: str
) -> None:
    with pytest.raises(ManifestError, match=r"cred:svc.*shell or interpreter"):
        parse_manifest(_manifest(tmp_path, [executable, "-c", "x"]))


def test_parse_manifest_accepts_a_purpose_built_executable(tmp_path: Path) -> None:
    (cap,) = parse_manifest(_manifest(tmp_path, [EXAMPLE_TOOL, "--validate"]))
    assert cap.options["trusted_argv"] == [EXAMPLE_TOOL, "--validate"]


def test_parse_manifest_only_judges_the_first_element(tmp_path: Path) -> None:
    parse_manifest(_manifest(tmp_path, [EXAMPLE_TOOL, "ssh", "sudo", "bash"]))


def test_parse_manifest_leaves_missing_or_malformed_trusted_argv_to_the_provider(
    tmp_path: Path,
) -> None:
    # v1 manifests without trusted_argv must keep parsing; exec/doctor report them.
    p = tmp_path / "capabilities.toml"
    p.write_text(
        '[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\n'
        '[capability."cred:b"]\nprovider = "cred"\nharnesses = ["claude"]\ntrusted_argv = []\n'
        '[capability."cred:c"]\nprovider = "cred"\nharnesses = ["claude"]\ntrusted_argv = [3]\n',
        encoding="utf-8",
    )
    assert len(parse_manifest(p)) == 3


# --- caught by doctor before any exec ------------------------------------------------


def test_doctor_reports_a_launcher_first_trusted_argv_without_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(_manifest(tmp_path, ["/usr/bin/ssh", "host"])), "--json"])
    assert rc == 1
    payload = json.loads(buf.getvalue())
    assert payload["error"]["code"] == "MANIFEST_ERROR"
    assert "shell or interpreter" in payload["error"]["message"]
    assert "cred:svc" in payload["error"]["message"]
