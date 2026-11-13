"""Standalone git helper: synthetic manifests and fake Vault only."""

from __future__ import annotations

import io
import json
import sys
import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_capability_broker import cred_vault, git_credential
from agent_capability_broker.broker.config import load_broker_config
from agent_capability_broker.cli import main
from agent_capability_broker.cred_vault import read_granted as real_read_granted
from agent_capability_broker.model import ManifestError, Status, derive_assurance, parse_manifest
from agent_capability_broker.providers import CredProvider

CAP_ID = "cred:forge-bot"
USER = "synthetic-user"
PASSWORD = "synthetic-secret-canary"
TEXT = ('''[capability."cred:forge-bot"]
provider = "cred"
source = "vault"
harnesses = ["opencode"]
issuer = {kind = "vault-kv", path = "kv/example/forge/bot", fields = ["login", "token"]}
delivery = {rung = "helper", tool = "git", hosts = ["forge.example"], '''
'''username_field = "login", password_field = "token"}
assurance = "D0"
''')


@pytest.fixture
def manifest(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.toml"
    path.write_text(TEXT, encoding="utf-8")
    return path


@pytest.fixture
def vault(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, list[str]]:
    """Exercise real auth/resolve/cleanup through a fake hvac and a fake plane."""
    events: list[str] = []
    client = MagicMock()
    client.auth.approle.login.side_effect = lambda **_: events.append("login")
    client.auth.token.revoke_self.side_effect = lambda: events.append("revoke")

    def read(**kwargs: Any) -> Any:
        assert kwargs == {
            "mount_point": "kv", "path": "example/forge/bot", "raise_on_deleted_version": True,
        }
        events.append("read")
        return {"data": {"data": {"login": USER, "token": PASSWORD, "extra": "never-return"}}}

    client.secrets.kv.v2.read_secret_version.side_effect = read

    def factory(**kwargs: Any) -> Any:
        assert kwargs == {"url": "https://vault.example", "token": ""}
        return client

    monkeypatch.setitem(sys.modules, "hvac", SimpleNamespace(Client=factory))
    monkeypatch.setattr(cred_vault, "_vault_env", lambda *_: {
        "VAULT_ADDR": "https://vault.example", "VAULT_ROLE_ID": "fake-role",
        "VAULT_SECRET_ID": "fake-secret-id",
    })
    monkeypatch.setattr(cred_vault, "_auth_source", lambda *_: None)
    monkeypatch.setattr(cred_vault, "_K8S_TOKEN", Path("no-such-synthetic-jwt"))
    return client, events


def invoke(manifest: Path, monkeypatch: pytest.MonkeyPatch, attrs: str, op: str = "get") -> int:
    monkeypatch.setattr(sys, "stdin", io.StringIO(attrs))
    return main(["git-credential", CAP_ID, "-m", str(manifest), op])


def test_get_and_login_cleanup(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, vault: Any,
) -> None:
    assert invoke(manifest, monkeypatch, "protocol=https\nhost=FORGE.EXAMPLE\n\n") == 0
    out = capsys.readouterr()
    assert out.out == f"username={USER}\npassword={PASSWORD}\n" and out.err == ""
    assert vault[1] == ["login", "read", "revoke"]
    from agent_capability_broker.provenance import state_dir

    event = (state_dir() / "provenance.jsonl").read_text()
    assert PASSWORD not in event and USER not in event and "kv/example" not in event
    assert json.loads(event)["result"] == "applied"


@pytest.mark.parametrize("attrs", [
    "protocol=https\nhost=other.example\n", "protocol=http\nhost=forge.example\n",
    "protocol=HTTPS\nhost=forge.example\n", "host=forge.example\n", "protocol=https\n",
    "protocol=https\nhost=forge.example:443\n", "protocol=https\nhost=forge.example/repo\n",
    "protocol=https\nhost=forge.example\npath=repo.git\n",
    "protocol=https\nhost=forge.example\npath=\n",
    "protocol=https\nhost=forge.example\nport=443\n",
    "protocol=https\nhost=forge.example\nurl=https://other.example\n",
    "protocol=https\nhost=forge.example.\n", "protocol=https\nhost=user@forge.example\n",
    "protocol=https\nhost=forge.example\\repo\n", "protocol=https\nhost=forge.example%3a443\n",
])
def test_fallthrough_without_vault(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, vault: Any, attrs: str,
) -> None:
    assert invoke(manifest, monkeypatch, attrs) == 0
    assert capsys.readouterr() == ("", "") and vault[1] == []


@pytest.mark.parametrize("op", ["store", "erase"])
def test_noops_need_no_manifest_or_vault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, op: str,
) -> None:
    stream = io.StringIO(f"host=forge.example\npassword={PASSWORD}\n\n")
    monkeypatch.setattr(sys, "stdin", stream)
    assert main(["git-credential", CAP_ID, op, "-m", str(tmp_path / "absent")]) == 0
    assert stream.read() == "" and capsys.readouterr() == ("", "")


@pytest.mark.parametrize("old,new", [
    ('source = "vault"', 'source = "env"'),
    ('kind = "vault-kv"', 'kind = "remote-mint"'),
    ('rung = "helper"', 'rung = "env"'),
    ('hosts = ["forge.example"]', 'hosts = []'),
    ('hosts = ["forge.example"]', 'hosts = ["forge.example", "other.example"]'),
    ('hosts = ["forge.example"]', 'hosts = ["forge.example:443"]'),
    ('hosts = ["forge.example"]', 'hosts = ["forge.example/repo"]'),
    ('hosts = ["forge.example"]', 'hosts = ["https://forge.example"]'),
    ('hosts = ["forge.example"]', 'hosts = ["forge.example." ]'),
    ('username_field = "login", ', ''),
    ('password_field = "token"', 'password_field = "missing"'),
    ('password_field = "token"', 'password_field = "login"'),
    ('fields = ["login", "token"]', 'fields = ["login", "token", "extra"]'),
    ('fields = ["login", "token"]', 'fields = []'),
    ('fields = ["login", "token"]', 'field = "token"'),
    ('path = "kv/example/forge/bot"', 'path = "kv"'),
    ('tool = "git"', 'tool = "git", protocol = "https://"'),
])
def test_invalid_declarations(
    manifest: Path, old: str, new: str, monkeypatch: pytest.MonkeyPatch, capsys: Any, vault: Any,
) -> None:
    manifest.write_text(TEXT.replace(old, new), encoding="utf-8")
    assert invoke(manifest, monkeypatch, "protocol=https\nhost=forge.example\n") == 2
    out = capsys.readouterr()
    assert out.out == "" and len(out.err.strip().splitlines()) == 1
    assert PASSWORD not in out.err and USER not in out.err and vault[1] == []


@pytest.mark.parametrize("declaration", [
    'trusted_argv = ["/opt/example/bin/git"]', 'unqualified_exec = true',
    'unqualified_exec = false',
])
def test_forbidden_options_are_manifest_errors(manifest: Path, declaration: str) -> None:
    manifest.write_text(TEXT + declaration + "\n", encoding="utf-8")
    with pytest.raises(ManifestError):
        parse_manifest(manifest)


def test_explicit_protocol(manifest: Path, monkeypatch: pytest.MonkeyPatch, vault: Any) -> None:
    manifest.write_text(TEXT.replace('tool = "git"', 'tool = "git", protocol = "http"'))
    assert invoke(manifest, monkeypatch, "protocol=https\nhost=forge.example\n") == 0
    assert vault[1] == []
    assert invoke(manifest, monkeypatch, "protocol=http\nhost=forge.example\n") == 0
    assert vault[1] == ["login", "read", "revoke"]


@pytest.mark.parametrize("bad", ["", "bad\nline", "bad\rline", "bad\0value", 42, None])
@pytest.mark.parametrize("field", ["login", "token"])
def test_bad_values_emit_nothing(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, vault: Any,
    bad: object, field: str,
) -> None:
    client, events = vault
    data = {"login": USER, "token": PASSWORD}
    data[field] = bad
    client.secrets.kv.v2.read_secret_version.side_effect = lambda **_: {"data": {"data": data}}
    assert invoke(manifest, monkeypatch, "protocol=https\nhost=forge.example\n") == 1
    out = capsys.readouterr()
    assert out.out == "" and out.err.strip() in {"RuntimeError", "ValueError"}
    assert events == ["login", "revoke"]


def test_failed_read_revokes_and_redacts(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, vault: Any,
) -> None:
    client, events = vault
    client.secrets.kv.v2.read_secret_version.side_effect = ValueError(PASSWORD)
    client.auth.token.revoke_self.side_effect = RuntimeError(PASSWORD)
    assert invoke(manifest, monkeypatch, "protocol=https\nhost=forge.example\n") == 1
    assert capsys.readouterr() == ("", "RuntimeError\n")
    client.auth.token.revoke_self.assert_called_once()
    assert events == ["login"]


@pytest.mark.parametrize("attrs", [
    "protocol=https\nhost=other.example\nhost=forge.example\n",
    "protocol=http\nprotocol=https\nhost=forge.example\n", "bad-input\n",
])
def test_ambiguous_input_is_redacted(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, vault: Any, attrs: str,
) -> None:
    assert invoke(manifest, monkeypatch, attrs) == 1
    assert capsys.readouterr() == ("", "ValueError\n") and vault[1] == []


def test_exec_refuses_before_read(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, vault: Any,
) -> None:
    for suffix in (["--", "git", "fetch"], ["git"]):
        assert main(["exec", "-m", str(manifest), CAP_ID, *suffix]) == 2
        assert "acb git-credential" in capsys.readouterr().err
    assert vault[1] == []


@pytest.mark.parametrize("granted", [True, False, None])
def test_doctor_without_shim_and_static_assurance(
    manifest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, granted: Any,
) -> None:
    from agent_capability_broker.adapters import OpencodeAdapter

    cap, = parse_manifest(manifest)
    monkeypatch.setattr(cred_vault, "reachable", lambda *_, **__: True)
    monkeypatch.setattr(cred_vault, "read_granted", lambda *_, **__: granted)
    adapter = OpencodeAdapter(config_path=tmp_path / "opencode.json")
    verdict = CredProvider().inspect(cap, "opencode", adapter)
    expected = Status.PRESENT_BROKEN if granted is False else Status.PRESENT_OK
    assert verdict.status is expected and "acb git-credential" in verdict.detail
    assert "update" not in verdict.detail
    assert derive_assurance(cap)[0] == "D0"
    actions = CredProvider().plan_reconcile(cap, "opencode", adapter)
    assert all(action.kind == "manual" for action in actions)
    main(["doctor", "-m", str(manifest), "--json"])
    out = capsys.readouterr().out
    assert "D0" in out and "static" in out and "unqualified" not in out


@pytest.mark.parametrize("grant,expected", [("read", True), ("root", True), ("update", False)])
def test_grant_checks_kv_read_without_reading(
    manifest: Path, vault: Any, grant: str, expected: bool,
) -> None:
    cap, = parse_manifest(manifest)
    client, events = vault
    api = "kv/data/example/forge/bot"
    client.adapter.post.return_value = {"data": {api: [grant]}}
    assert real_read_granted(cap) is expected
    client.adapter.post.assert_called_once_with("/v1/sys/capabilities-self", json={"paths": [api]})
    assert events == ["login", "revoke"]


def test_declaration_is_shared_with_daemon(manifest: Path) -> None:
    cap, = parse_manifest(manifest)
    resolver, delivery = git_credential.validate(cap)
    broker = load_broker_config(manifest).capabilities[CAP_ID]
    assert delivery == broker.delivery
    assert resolver.options == {"vault": broker.issuer.params["path"],
                                "fields": broker.issuer.params["fields"]}
    assert tomllib.loads(TEXT)["capability"][CAP_ID]["issuer"]["kind"] == "vault-kv"


def test_git_extensions_are_ignored(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, vault: Any,
) -> None:
    attrs = ("protocol=https\nhost=forge.example\ncapability[]=authtype\n"
             "wwwauth[]=Basic realm=example\nwwwauth[]=Bearer realm=example\n\n")
    assert invoke(manifest, monkeypatch, attrs) == 0
    assert capsys.readouterr() == (f"username={USER}\npassword={PASSWORD}\n", "")


def test_legacy_daemon_entry_does_not_block_selected_helper(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, vault: Any,
) -> None:
    legacy = '''
[capability."cred:legacy"]
provider = "cred"
harnesses = ["opencode"]
issuer = {kind = "vault-kv", path = "kv/example/other", fields = ["token"]}
delivery = {rung = "helper", tool = "git", hosts = ["other.example"], username = "bot"}
'''
    manifest.write_text(TEXT + legacy)
    assert len(parse_manifest(manifest)) == 2
    assert len(load_broker_config(manifest).capabilities) == 2
    assert invoke(manifest, monkeypatch, "protocol=https\nhost=forge.example\n") == 0


@pytest.mark.parametrize("mapping", [
    ("login", "token"), ("password", "username"),
])
def test_daemon_serves_the_same_field_mapping(
    manifest: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mapping: tuple[str, str],
) -> None:
    from agent_capability_broker.broker import git_credential as daemon
    from agent_capability_broker.broker.harness import Attribution
    from agent_capability_broker.broker.issuers import FakeIssuer
    from agent_capability_broker.broker.protocol import make_request
    from agent_capability_broker.broker.registry import Registry
    from agent_capability_broker.broker.service import Broker, Peer

    username_field, password_field = mapping
    text = TEXT.replace('"login"', f'"{username_field}"').replace('"token"', f'"{password_field}"')
    manifest.write_text(text)
    config = load_broker_config(manifest)
    issuer = FakeIssuer(lambda *_: {username_field: USER, password_field: PASSWORD})
    registry = Registry(tmp_path / "checkouts.json", {"vault-kv": issuer},
                        events=lambda *_: None)
    broker = Broker(config, registry, {"vault-kv": issuer},
                    attribute_fn=lambda *_: Attribution("opencode", "hint", None, None))
    reply = broker.handle(make_request("checkout", {"match": {"tool": "git", "host":
                          "forge.example"}}, front_end="git"), Peer(1, 1, 1))
    assert reply["ok"] is True
    monkeypatch.setattr(daemon, "call", lambda *_, **__: (reply["result"], True))
    stdout = io.StringIO()
    assert daemon.main(["get"], stdin=io.StringIO("protocol=https\nhost=forge.example\n"),
                       stdout=stdout) == 0
    assert stdout.getvalue().startswith(f"username={USER}\npassword={PASSWORD}\n")


@pytest.mark.parametrize("args", [
    [], [CAP_ID], [CAP_ID, PASSWORD], [CAP_ID, "get", "--unknown", PASSWORD],
    [CAP_ID, "get", "-m"], [CAP_ID, "get", "--json", PASSWORD],
])
def test_cli_usage_errors_are_redacted(args: list[str], capsys: Any) -> None:
    assert main(["git-credential", *args]) == 2
    assert capsys.readouterr() == ("", "GitCredentialConfigError\n")


def test_cli_help_is_available(capsys: Any) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["git-credential", "--help"])
    assert caught.value.code == 0
    out = capsys.readouterr()
    assert "get,store,erase" in out.out and out.err == ""


@pytest.mark.parametrize("extra", [
    'vault = "kv/example/other"', 'fields = ["other"]', 'field = "other"',
])
def test_competing_vault_options_are_refused(
    manifest: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, vault: Any, extra: str,
) -> None:
    manifest.write_text(TEXT + extra + "\n")
    assert invoke(manifest, monkeypatch, "protocol=https\nhost=forge.example\n") == 2
    assert capsys.readouterr() == ("", "GitCredentialConfigError\n") and vault[1] == []
