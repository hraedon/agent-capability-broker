"""Test helpers for cred ``exec`` tests (Plan 012 section 5).

Every cred capability must now declare an exact ``trusted_argv`` whose first
element is an absolute path and not a shell or interpreter, so tests can no
longer use ``sys.executable`` as the child. ``CHILD_PY`` is a tiny launcher
that forwards its arguments to the running interpreter: ``[*CHILD_PY, "-c",
code]`` behaves exactly like ``[sys.executable, "-c", code]`` but is a
qualifiable, purpose-named executable.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import stat
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

from agent_capability_broker.model import Capability


def _make_launcher() -> str:
    root = Path(tempfile.mkdtemp(prefix="acb-test-child-"))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    if os.name == "nt":
        launcher = root / "acbtestchild.cmd"
        launcher.write_text(f'@"{sys.executable}" %*\r\n', encoding="utf-8")
    else:
        launcher = root / "acbtestchild"
        launcher.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(launcher)


CHILD_PY: str = _make_launcher()


# A platform-absolute stand-in for a qualified tool, for manifests that are only
# parsed/diagnosed (doctor, reconcile) and never exec'd.
EXAMPLE_TOOL: str = str(Path(tempfile.gettempdir()) / "acb-example-tool")
# TOML line declaring it; append to a ``provider = "cred"`` table body.
TRUSTED_TOML: str = "trusted_argv = " + json.dumps([EXAMPLE_TOOL]) + "\n"


def trusting(cap: Capability, argv: list[str]) -> Capability:
    """``cap`` with ``argv`` declared as its exact manifest ``trusted_argv``."""
    return replace(cap, options={**cap.options, "trusted_argv": list(argv)})


def trusting_all(caps: list[Capability], argv: list[str]) -> list[Capability]:
    """Every capability in ``caps`` declaring ``argv`` as its trusted_argv."""
    return [trusting(cap, argv) for cap in caps]


def trusted_toml(argv: list[str]) -> str:
    """A ``trusted_argv = [...]`` TOML line declaring exactly ``argv``."""
    return "trusted_argv = " + json.dumps(list(argv)) + "\n"
