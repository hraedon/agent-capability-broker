"""The shell / interpreter / launcher denylist for ``trusted_argv`` (Plan 012 section 5).

One list, one matcher, three enforcement points: manifest parsing
(``model.parse_manifest``), ``doctor`` (via the provider's ``inspect``) and
``acb exec`` (``secret_sources.validate_exec_command``).

**This is a lint guard against operator mistakes, not a sandbox.**
``trusted_argv`` is an exact, full-argv match against an operator-reviewed
manifest: the thing that actually constrains what runs is that the whole
command line must equal what the operator wrote. The denylist only catches the
foreseeable slip of naming a general-purpose launcher (a shell, an
interpreter, or a wrapper such as ``nice`` / ``sudo`` / ``xargs`` that execs
whatever follows) as the first element, where a later edit to the arguments
would silently turn the capability into "run anything with this secret in its
environment". It cannot, and does not try to, stop a purpose-built binary
that is itself a launcher under another name.

Stdlib-only; imports nothing from the package.
"""

from __future__ import annotations

import re
from pathlib import PureWindowsPath

# Names matched exactly (after the basename / extension normalisation below).
LAUNCHER_NAMES = frozenset({
    # POSIX and Windows shells
    "sh", "bash", "zsh", "dash", "ash", "ksh", "csh", "tcsh", "fish",
    "pwsh", "powershell", "cmd",
    # multi-call binaries
    "busybox", "toybox",
    # script interpreters and their launchers
    "node", "nodejs", "perl", "ruby", "php", "lua", "luajit", "tclsh", "wish",
    "expect", "deno", "bun", "bunx", "npx", "uv", "uvx", "py", "pyw",
    "osascript", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
    # stream editors / text tools that can execute commands
    "awk", "gawk", "mawk", "nawk", "sed",
    # wrappers that exec whatever follows
    "env", "nice", "nohup", "timeout", "stdbuf", "setsid", "sudo", "doas", "su",
    "xargs", "find", "script",
    # remote shell
    "ssh",
})

# Families whose binaries carry a version suffix (python3.13, lua5.4, php8.3,
# ruby3.2, perl5.38, node22, tclsh8.6). ``python`` / ``pypy`` also match by
# prefix (pythonw, python3.14t, python3-config): historically every python*.
_PREFIX_FAMILIES = ("python", "pypy")
_VERSIONED = re.compile(
    r"^(?:node|nodejs|perl|ruby|php|lua|luajit|tclsh|wish|expect|deno|bun)"
    r"[-_]?[0-9][0-9._-]*[a-z]?$"
)

# Windows resolves ``cmd`` to cmd.exe / cmd.com / cmd.bat ..., and ignores
# trailing dots and spaces in a file name.
_STRIPPED_EXTENSIONS = (".exe", ".com", ".bat", ".cmd", ".ps1")


def launcher_basename(executable: str) -> str:
    r"""Normalised basename: lower-case, POSIX or Windows path, extensions stripped.

    ``C:\Windows\System32\CMD.EXE`` -> ``cmd``; ``/usr/bin/Python3.13`` ->
    ``python3.13``. ``PureWindowsPath`` splits on both ``/`` and ``\``.
    """
    base = PureWindowsPath(executable).name.lower().rstrip(" .")
    stripped = True
    while stripped:
        stripped = False
        for ext in _STRIPPED_EXTENSIONS:
            if base.endswith(ext) and len(base) > len(ext):
                base = base[: -len(ext)].rstrip(" .")
                stripped = True
    return base


def is_launcher(executable: str) -> bool:
    """True when ``executable`` is a shell, interpreter or exec-wrapper by name."""
    base = launcher_basename(executable)
    if not base:
        return False
    return (
        base in LAUNCHER_NAMES
        or base.startswith(_PREFIX_FAMILIES)
        or _VERSIONED.match(base) is not None
    )


LAUNCHER_REFUSAL = (
    "must not start with a shell or interpreter or other launcher (an exec "
    "wrapper such as sudo or xargs); name a reviewed purpose-built executable"
)

__all__ = ["LAUNCHER_NAMES", "LAUNCHER_REFUSAL", "is_launcher", "launcher_basename"]
