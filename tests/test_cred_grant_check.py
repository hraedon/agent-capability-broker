"""`doctor` must not report a credential capability PRESENT_OK when its plane
logs in but the identity's policy does not grant the declared path."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import hvac
import pytest

from agent_capability_broker import cred_vault
from agent_capability_broker.cred_vault import _capabilities_in
from agent_capability_broker.cred_vault import read_granted as real_read_granted
from agent_capability_broker.model import Capability, Status
from agent_capability_broker.providers import CredProvider

CAP = Capability(
    id="cred:svc-bot", provider="cred", harnesses=("opencode",),
    options={
        "vault": "kv/example/ad/svc-bot", "fields": ["username"], "unqualified_exec": True,
    },
)
API_PATH = "kv/data/example/ad/svc-bot"


class _Client:
    reply: Any = None
    posts: list[tuple[str, Any]] = []

    def __init__(self, url: str | None = None, token: str | None = None, **_: Any) -> None:
        self.token = token
        self.auth = MagicMock()
        self.adapter = MagicMock()
        self.adapter.post.side_effect = self._post
        self.secrets = MagicMock()

    def _post(self, url: str, json: Any = None) -> Any:
        _Client.posts.append((url, json))
        if isinstance(_Client.reply, Exception):
            raise _Client.reply
        return _Client.reply


@pytest.fixture
def plane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    _Client.posts = []
    monkeypatch.setattr(hvac, "Client", _Client)
    f = tmp_path / "plane.env"
    f.write_text(
        "VAULT_ADDR=https://vault.example.invalid\nVAULT_ROLE_ID=r\nVAULT_SECRET_ID=s\n",
        encoding="utf-8",
    )
    return str(f)


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ({"data": {"capabilities": ["read"], API_PATH: ["read"]}}, True),
        ({"capabilities": ["read", "list"]}, True),
        ({"data": {API_PATH: ["root"]}}, True),
        ({"data": {"capabilities": ["deny"], API_PATH: ["deny"]}}, False),
        ({"data": {API_PATH: ["list"]}}, False),
        ({"data": {}}, None),
        ("not a dict", None),
        (RuntimeError("403"), None),
    ],
)
def test_read_granted_reports_vaults_answer(plane: str, reply: Any, expected: bool | None) -> None:
    _Client.reply = reply
    assert real_read_granted(CAP, vault_env=plane) is expected


def test_read_granted_asks_about_the_data_path_and_never_reads_the_secret(plane: str) -> None:
    _Client.reply = {"data": {API_PATH: ["read"]}}
    assert real_read_granted(CAP, vault_env=plane) is True
    assert _Client.posts == [("/v1/sys/capabilities-self", {"paths": [API_PATH]})]


def test_read_granted_is_unknown_without_a_declared_path(plane: str) -> None:
    cap = Capability(id="cred:x", provider="cred", harnesses=("opencode",), options={})
    assert real_read_granted(cap, vault_env=plane) is None
    assert _Client.posts == []


def test_capabilities_in_refuses_a_malformed_list() -> None:
    assert _capabilities_in({"data": {API_PATH: ["read", 1]}}, API_PATH) is None


@pytest.mark.parametrize(
    ("granted", "status", "needle"),
    [
        (True, Status.PRESENT_OK, "declared path granted"),
        (False, Status.PRESENT_BROKEN, "not granted read"),
        (None, Status.PRESENT_OK, "broker reachable (token self-lookup)"),
    ],
)
def test_doctor_verdict_follows_the_grant(
    monkeypatch: pytest.MonkeyPatch, granted: bool | None, status: Status, needle: str
) -> None:
    monkeypatch.setattr(cred_vault, "reachable", lambda cap, **_: True)
    monkeypatch.setattr(cred_vault, "read_granted", lambda cap, **_: granted)
    got, detail = CredProvider()._reachability(CAP)
    assert got is status and needle in detail


def test_an_unreachable_broker_is_not_asked_about_grants(monkeypatch: pytest.MonkeyPatch) -> None:
    asked: list[str] = []
    monkeypatch.setattr(cred_vault, "reachable", lambda cap, **_: False)
    monkeypatch.setattr(cred_vault, "read_granted", lambda cap, **_: asked.append(cap.id))
    got, _ = CredProvider()._reachability(CAP)
    assert got is Status.PRESENT_BROKEN and asked == []
