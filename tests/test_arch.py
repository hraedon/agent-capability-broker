"""Architecture + safety guards (spine §7).

- The deterministic core imports no third-party package and no optional layer.
- The read path (`doctor`) performs no file writes and surfaces no secret.
"""

from __future__ import annotations

import ast
import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_capability_broker"

# Modules that form the stdlib-only truth path. As provider backends land, their
# optional-import modules are added to ALLOWED_EXTRA, not here.
CORE_MODULES = [
    "model.py", "cli.py", "adapters.py", "providers.py", "provenance.py",
    "secret_sources.py",
]
STDLIB_OK = {
    "__future__", "argparse", "ast", "dataclasses", "enum", "functools", "importlib", "json",
    "pathlib", "sys", "tomllib", "io", "contextlib", "os", "typing", "datetime",
    "subprocess", "re", "shutil", "signal", "time", "uuid",
    # platformdirs: config-dir portability (not the truth/verdict path) — sole permitted runtime dep
    "platformdirs",
}
# Relative imports of these core modules are allowed (e.g. `from .model import ...`).
CORE_INTERNAL = {"model", "cli", "adapters", "providers", "provenance", "secret_sources"}
# Optional-extra modules that must NEVER be imported at module level by the core.
FORBIDDEN_IN_CORE = {"cred_vault", "hvac"}


def _imports(module: Path) -> set[str]:
    """Module-level imported module names, including relative imports.

    MEDIUM-4: previously `node.level == 0` filtered out relative imports, and
    `node.module is None` (``from . import cred_vault``) was never captured.
    Now we check only ``tree.body`` (module-level statements) and handle both
    ``from .cred_vault import ...`` (node.module='cred_vault') and
    ``from . import cred_vault`` (node.module=None, alias='cred_vault').
    """
    tree = ast.parse(module.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module.split(".")[0])
            else:
                # from . import foo, bar — capture alias names
                names.update(a.name for a in node.names)
    return names


@pytest.mark.parametrize("mod", CORE_MODULES)
def test_core_is_stdlib_only(mod: str) -> None:
    external = _imports(SRC / mod) - STDLIB_OK - {"agent_capability_broker"} - CORE_INTERNAL
    assert not external, f"{mod} imports non-stdlib/non-core packages: {external}"


@pytest.mark.parametrize("mod", CORE_MODULES)
def test_core_no_forbidden_relative_imports(mod: str) -> None:
    """MEDIUM-4: relative imports of optional-extra modules at module level are
    forbidden — the core must import them lazily inside function bodies."""
    assert not (_imports(SRC / mod) & FORBIDDEN_IN_CORE), \
        f"{mod} imports a forbidden optional-extra module at module level"


def test_doctor_does_not_write_or_leak(tmp_path: Path) -> None:
    from agent_capability_broker.cli import main

    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."e2e:chromium"]\nprovider = "e2e"\nharnesses = ["opencode"]\n',
        encoding="utf-8",
    )
    before = {p.name for p in tmp_path.iterdir()}

    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["doctor", "-m", str(manifest)])

    # Read path mutates nothing on disk...
    assert {p.name for p in tmp_path.iterdir()} == before
    # ...and the charter-stage doctor surfaces no credential material.
    out = buf.getvalue().lower()
    assert "password" not in out and "secret" not in out
