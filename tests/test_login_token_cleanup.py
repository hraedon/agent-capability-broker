"""Only owned AppRole/Kubernetes logins are revoked, even on failed use."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_capability_broker import cred_vault, kube_token
from agent_capability_broker.cred_vault import read_granted
from agent_capability_broker.model import Capability

CAP = Capability("cred:example", "cred", ("claude",),
                 {"vault": "kv/example/bot", "field": "password"})


@pytest.mark.parametrize("auth", ["approle", "kubernetes", "token"])
@pytest.mark.parametrize("operation", ["resolve", "reachable", "capabilities", "grant", "kube"])
@pytest.mark.parametrize("failed", [False, True])
def test_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any,
    auth: str, operation: str, failed: bool,
) -> None:
    events: list[str] = []
    client = MagicMock()
    client.token = ""
    client.auth.approle.login.side_effect = lambda **_: events.append("login")
    client.auth.kubernetes.login.side_effect = lambda **_: events.append("login")

    def revoke() -> None:
        events.append("revoke")
        raise RuntimeError("canary-secret-in-revoke-error")

    client.auth.token.revoke_self.side_effect = revoke

    def request(*args: Any, **kwargs: Any) -> Any:
        events.append("request")
        if failed:
            raise ValueError("canary-secret-in-request-error")
        return {
            "data": {"data": {"password": "synthetic-value"}, "service_account_token": "sa"},
            "capabilities": ["read"], "some/path": ["read"],
        }

    client.secrets.kv.v2.read_secret_version.side_effect = request
    client.is_authenticated.side_effect = request
    client.sys.get_capabilities.side_effect = request
    client.adapter.post.side_effect = request
    client.write_data.side_effect = request

    def factory(**kwargs: Any) -> Any:
        assert kwargs["token"] == ("explicit-dev-token" if auth == "token" else "")
        client.token = kwargs["token"]
        return client

    monkeypatch.setitem(sys.modules, "hvac", SimpleNamespace(Client=factory))
    jwt = tmp_path / "jwt"
    monkeypatch.setattr(cred_vault, "_K8S_TOKEN", jwt)
    env = {"VAULT_ADDR": "https://vault.example.invalid"}
    if auth == "approle":
        env.update(VAULT_ROLE_ID="example-role", VAULT_SECRET_ID="example-secret")
    elif auth == "kubernetes":
        env["VAULT_K8S_ROLE"] = "example-role"
        jwt.write_text("example-jwt")
    else:
        env["VAULT_TOKEN"] = "explicit-dev-token"
    monkeypatch.setattr(cred_vault, "_vault_env", lambda *args: env)
    monkeypatch.setattr(cred_vault, "_auth_source", lambda *args: None)
    if operation == "kube" and auth == "token":
        with pytest.raises(RuntimeError):
            kube_token.mint({"role": "example-role", "namespace": "example",
                             "_ttl_declared": False})
        assert events == []
        return
    try:
        if operation == "resolve":
            assert cred_vault.resolve(CAP) == {"password": "synthetic-value"}
        elif operation == "reachable":
            assert cred_vault.reachable(CAP)
        elif operation == "capabilities":
            assert cred_vault.capabilities_self(["some/path"]) == {"some/path": ["read"]}
        elif operation == "grant":
            assert read_granted(CAP) is (None if failed else True)
        else:
            doc = kube_token.mint({"role": "example-role", "namespace": "example",
                                   "_ttl_declared": False})
            assert doc["status"]["token"] == "sa"
    except (RuntimeError, ValueError):
        assert failed
    assert events == (["request"] if auth == "token" else ["login", "request", "revoke"])
    output = capsys.readouterr()
    assert output.out == output.err == ""


@pytest.mark.parametrize("revoke", [False, True])
def test_injected_client_is_borrowed(revoke: bool) -> None:
    client = MagicMock()
    # Even a client previously obtained through acb is borrowed when injected.
    client._acb_login_owned = True
    client.write_data.return_value = {"data": {"service_account_token": "synthetic-sa"}}
    params = {"role": "example-role", "namespace": "example", "_ttl_declared": False}
    kube_token.mint(params, client=client, revoke=revoke)
    assert client.auth.token.revoke_self.call_count == int(revoke)
    client.reset_mock()
    client.sys.get_capabilities.return_value = {"example/path": ["read"]}
    cred_vault.capabilities_self(["example/path"], client=client)
    client.auth.token.revoke_self.assert_not_called()


def test_cleanup_opt_in_does_not_revoke_ambient_dev_token(monkeypatch: pytest.MonkeyPatch) -> None:
    client = MagicMock()
    client._acb_login_owned = False
    monkeypatch.setattr(cred_vault, "authenticated_client", lambda *args, **kwargs: client)
    with cred_vault.client_session(revoke=True):
        pass
    client.auth.token.revoke_self.assert_not_called()
