"""Suite-wide test isolation."""
from __future__ import annotations

import pytest

from agent_capability_broker import cred_vault


@pytest.fixture(autouse=True)
def _no_live_grant_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    """The grant check behind `doctor` logs in to Vault. Tests that stub
    `reachable` must not fall through to a real login with whatever access
    plane the developer's machine has, so by default the check answers "could
    not be asked". Tests of the check itself call the function they imported,
    or patch it again."""
    monkeypatch.setattr(cred_vault, "read_granted", lambda cap, **_: None)


@pytest.fixture(autouse=True)
def _no_real_agy_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Keep the agy adapter off the developer's real ``~/.gemini/config``."""
    monkeypatch.setenv("ACB_AGY_CONFIG_DIR", str(tmp_path_factory.mktemp("agy") / "absent"))
