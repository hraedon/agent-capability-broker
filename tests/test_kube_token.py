"""`acb kube-token`: the standalone kubectl exec-credential helper (no daemon).

Fixtures are synthetic (`EXAMPLE.local`, `kubernetes`, `example-role`); the fake
hvac client records every call so the tests can assert the exact Vault path and
body, that no child token is created, and that nothing is revoked.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_capability_broker import cred_vault, kube_token
from agent_capability_broker.cli import main
from agent_capability_broker.cred_vault import read_granted as real_read_granted
from agent_capability_broker.model import Capability, Status
from agent_capability_broker.providers import CredProvider
from agent_capability_broker.secret_sources import (
    SecretSourceConfigError,
    validate_cred_trusted_argv,
)

TOKEN = "canary-sa-token-do-not-print"
NOW = 1_800_000_000.0  # 2027-01-15T08:00:00Z
CAP_ID = "cred:example-k8s"

GOOD = """
[capability."cred:example-k8s"]
provider = "cred"
harnesses = ["claude"]

[capability."cred:example-k8s".issuer]
kind = "vault-k8s-token"
mount = "kubernetes"
role = "example-role"
namespace = "example-ns"
ttl = "10m"
audiences = ["https://kube.EXAMPLE.local", "aud-two"]
cluster_role_binding = false

[capability."cred:example-k8s".delivery]
rung = "helper"
tool = "kubectl"
"""


def _manifest(tmp_path: Path, text: str = GOOD) -> str:
    p = tmp_path / "capabilities.toml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def _variant(old: str, new: str) -> str:
    assert old in GOOD
    return GOOD.replace(old, new)


class FakeClient:
    """Records Vault calls; any call other than a creds write fails the test."""

    def __init__(self, reply: Any = None, raises: Exception | None = None) -> None:
        self.reply = reply if reply is not None else {
            "lease_duration": 600,
            "data": {"service_account_token": TOKEN},
        }
        self.raises = raises
        self.writes: list[tuple[str, dict[str, Any]]] = []

    def write_data(self, path: str, data: dict[str, Any] | None = None) -> Any:
        self.writes.append((path, dict(data or {})))
        if self.raises is not None:
            raise self.raises
        return self.reply

    def __getattr__(self, name: str) -> Any:  # revoke/create/etc. must never be reached
        raise AssertionError(f"unexpected Vault client use: {name}")


def _run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], *, text: str = GOOD,
    client: FakeClient | None = None, clock: Any = lambda: NOW, cap_id: str = CAP_ID,
) -> tuple[int, str, str]:
    code = kube_token.run(cap_id, _manifest(tmp_path, text), client=client, clock=clock)
    out = capsys.readouterr()
    return code, out.out, out.err


# ---------------------------------------------------------------- success


def test_happy_path_shape_call_and_expiry(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client = FakeClient()
    code, out, err = _run(tmp_path, capsys, client=client)
    assert code == 0 and err == ""
    assert out.count("\n") == 1 and out.endswith("\n")
    doc = json.loads(out)
    # 2027-01-15T08:00:00Z + 600 s lease - 30 s margin
    assert doc == {
        "apiVersion": "client.authentication.k8s.io/v1",
        "kind": "ExecCredential",
        "status": {"token": TOKEN, "expirationTimestamp": "2027-01-15T08:09:30Z"},
    }
    assert " " not in out  # compact: exactly one JSON line
    assert client.writes == [
        (
            "kubernetes/creds/example-role",
            {
                "kubernetes_namespace": "example-ns",
                "ttl": "600s",
                "audiences": "https://kube.EXAMPLE.local,aud-two",
                "cluster_role_binding": False,
            },
        )
    ]


def test_minimal_declaration_sends_only_the_namespace(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    text = (
        GOOD.replace('mount = "kubernetes"\n', "")
        .replace('ttl = "10m"\n', "")
        .replace('audiences = ["https://kube.EXAMPLE.local", "aud-two"]\n', "")
        .replace("cluster_role_binding = false\n", "")
    )
    client = FakeClient(reply={"data": {"service_account_token": TOKEN}})  # no lease
    code, out, _ = _run(tmp_path, capsys, text=text, client=client)
    assert code == 0
    assert client.writes == [
        ("kubernetes/creds/example-role", {"kubernetes_namespace": "example-ns"})
    ]
    # no lease from Vault and no ttl declared -> 900 s, minus the margin
    assert json.loads(out)["status"]["expirationTimestamp"] == "2027-01-15T08:14:30Z"


def test_lease_falls_back_to_the_requested_ttl(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client = FakeClient(reply={"lease_duration": 0, "data": {"service_account_token": TOKEN}})
    _, out, _ = _run(tmp_path, capsys, client=client)  # ttl = 10m declared
    assert json.loads(out)["status"]["expirationTimestamp"] == "2027-01-15T08:09:30Z"


def test_expiry_is_never_in_the_past() -> None:
    doc = kube_token.exec_credential("t", NOW, 5)  # lease shorter than the margin
    assert doc["status"]["expirationTimestamp"] == "2027-01-15T08:00:00Z"
    doc = kube_token.exec_credential("t", NOW + 0.9, 30)
    assert doc["status"]["expirationTimestamp"] == "2027-01-15T08:00:00Z"


def test_the_mount_is_honoured(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    client = FakeClient()
    code, _, _ = _run(
        tmp_path, capsys, text=_variant('mount = "kubernetes"', 'mount = "k8s-eng"'),
        client=client,
    )
    assert code == 0 and client.writes[0][0] == "k8s-eng/creds/example-role"


def test_no_child_token_and_nothing_is_revoked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client = FakeClient()
    _run(tmp_path, capsys, client=client)
    # FakeClient raises on any attribute other than write_data, and every
    # write is the creds path: no auth/token/create, no revoke-self.
    assert [p for p, _ in client.writes] == ["kubernetes/creds/example-role"]


# ---------------------------------------------------------------- config errors


@pytest.mark.parametrize(
    ("text", "needle"),
    [
        (_variant('ttl = "10m"', 'ttl = "16m"'), "ttl"),
        (_variant('ttl = "10m"', "ttl = 901"), "ttl"),
        (_variant('role = "example-role"\n', ""), "role"),
        (_variant('namespace = "example-ns"\n', ""), "namespace"),
        (_variant('cluster_role_binding = false', 'cluster_role_binding = "no"'), "boolean"),
        (_variant('audiences = ["https://kube.EXAMPLE.local", "aud-two"]', "audiences = 3"),
         "audiences"),
        (_variant('provider = "cred"', 'provider = "e2e"'), "provider"),
        (_variant('kind = "vault-k8s-token"', 'kind = "vault-kv"'), "vault-k8s-token"),
        (_variant('rung = "helper"', 'rung = "env"'), "helper"),
        (_variant('tool = "kubectl"', 'tool = "git"'), "kubectl"),
        (_variant('tool = "kubectl"', 'tool = "kubectl"\nhosts = []'), "ok"),
    ],
)
def test_config_errors_exit_2_with_one_stderr_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], text: str, needle: str
) -> None:
    if needle == "ok":  # sanity: the harmless variant is accepted
        code, _, _ = _run(tmp_path, capsys, text=text, client=FakeClient())
        assert code == 0
        return
    client = FakeClient()
    cap_id = "e2e:example-k8s" if 'provider = "e2e"' in text else CAP_ID
    if cap_id.startswith("e2e:"):
        text = text.replace('"cred:example-k8s"', '"e2e:example-k8s"')
    code, out, err = _run(tmp_path, capsys, text=text, client=client, cap_id=cap_id)
    assert code == 2 and out == ""
    assert len(err.strip().splitlines()) == 1 and needle in err
    assert client.writes == []


def test_unknown_capability_and_missing_issuer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = _run(tmp_path, capsys, cap_id="cred:nope")
    assert (code, out) == (2, "") and "not in manifest" in err
    bare = (
        '[capability."cred:example-k8s"]\nprovider = "cred"\nharnesses = ["claude"]\n'
        'vault = "kv/example/x"\nfield = "password"\ntrusted_argv = ["/usr/bin/example-tool"]\n'
    )
    code, out, err = _run(tmp_path, capsys, text=bare)
    assert (code, out) == (2, "") and "vault-k8s-token" in err


# ---------------------------------------------------------------- Vault failure


@pytest.mark.parametrize(
    "reply",
    [
        RuntimeError(f"boom with body {TOKEN} at https://vault.EXAMPLE.local"),
        {"data": {}},
        {"lease_duration": 60},
        "not a dict",
    ],
)
def test_vault_failure_is_class_name_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], reply: Any
) -> None:
    client = (
        FakeClient(raises=reply) if isinstance(reply, Exception) else FakeClient(reply=reply)
    )
    code, out, err = _run(tmp_path, capsys, client=client)
    assert code == 1 and out == ""
    assert TOKEN not in err and "EXAMPLE" not in err and "boom" not in err
    assert len(err.strip().splitlines()) == 1
    assert err.startswith("error: kube-token failed (")


# ---------------------------------------------------------------- real auth path


class _AuthClient:
    """hvac stand-in used through `cred_vault.authenticated_client`."""

    instances: list[_AuthClient] = []

    def __init__(self, url: str | None = None, token: str | None = None, **_: Any) -> None:
        self.url, self.token = url, token
        self.auth = MagicMock()
        self.writes: list[tuple[str, dict[str, Any]]] = []
        _AuthClient.instances.append(self)

    def write_data(self, path: str, data: dict[str, Any] | None = None) -> Any:
        self.writes.append((path, dict(data or {})))
        return {"lease_duration": 600, "data": {"service_account_token": TOKEN}}


@pytest.fixture
def vault_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    hvac = pytest.importorskip("hvac", reason="needs the [cred] extra")
    for key in list(os.environ):
        if key.startswith(("VAULT", "ACB_VAULT_ENV", "AGENT_SUITE_CONFIG")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cred_vault, "_K8S_TOKEN", tmp_path / "no-such-k8s-token")
    _AuthClient.instances = []
    monkeypatch.setattr(hvac, "Client", _AuthClient)
    return tmp_path / "plane.env"


def test_authenticates_like_exec_then_makes_one_write(
    tmp_path: Path, vault_env: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault_env.write_text(
        "VAULT_ADDR=https://vault.EXAMPLE.local\nVAULT_ROLE_ID=r\nVAULT_SECRET_ID=s\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_VAULT_ENV", str(vault_env))
    monkeypatch.setenv("VAULT_TOKEN", "ambient-token-must-not-be-used-with-approle")
    code = main(["kube-token", CAP_ID, "-m", _manifest(tmp_path)])
    out = capsys.readouterr()
    assert code == 0 and out.err == ""
    assert json.loads(out.out)["status"]["token"] == TOKEN
    (c,) = _AuthClient.instances
    assert c.url == "https://vault.EXAMPLE.local"
    c.auth.approle.login.assert_called_once_with(
        role_id="r", secret_id="s", mount_point="approle"
    )
    assert [p for p, _ in c.writes] == ["kubernetes/creds/example-role"]


def test_token_empty_invariant_without_vault_token(
    tmp_path: Path, vault_env: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No declared token -> client built with token="" and the run fails closed."""
    vault_env.write_text("VAULT_ADDR=https://vault.EXAMPLE.local\n", encoding="utf-8")
    monkeypatch.setenv("ACB_VAULT_ENV", str(vault_env))
    code = main(["kube-token", CAP_ID, "-m", _manifest(tmp_path)])
    out = capsys.readouterr()
    assert code == 1 and out.out == "" and "RuntimeError" in out.err
    assert [c.token for c in _AuthClient.instances] == [""]


def test_incomplete_approle_fails_closed(
    tmp_path: Path, vault_env: Path, monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vault_env.write_text(
        "VAULT_ADDR=https://vault.EXAMPLE.local\nVAULT_ROLE_ID=r\n", encoding="utf-8"
    )
    monkeypatch.setenv("ACB_VAULT_ENV", str(vault_env))
    monkeypatch.setenv("VAULT_TOKEN", "ambient")
    code = main(["kube-token", CAP_ID, "-m", _manifest(tmp_path)])
    out = capsys.readouterr()
    assert code == 1 and out.out == ""
    assert all(not c.writes for c in _AuthClient.instances)


# ---------------------------------------------------------------- acb exec refuses


def test_exec_refuses_a_helper_capability_before_resolving(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise AssertionError("must refuse before resolving anything")

    monkeypatch.setattr(cred_vault, "authenticated_client", boom)
    monkeypatch.setattr(cred_vault, "resolve", boom)
    code = main(["exec", "-m", _manifest(tmp_path), CAP_ID, "--", "kubectl", "get", "pods"])
    err = capsys.readouterr().err
    assert code == 2
    assert f"use the helper: acb kube-token {CAP_ID}" in err
    # the historical no-"--" form is refused too
    code = main(["exec", "-m", _manifest(tmp_path), CAP_ID, "kubectl"])
    assert code == 2 and "acb kube-token" in capsys.readouterr().err


# ---------------------------------------------------------------- exact-command rule


def _helper_cap(**options: object) -> Capability:
    return Capability(
        CAP_ID, "cred", ("claude",), dict(options),
        issuer={"kind": "vault-k8s-token", "role": "example-role", "namespace": "n"},
        delivery={"rung": "helper", "tool": "kubectl"},
    )


def test_helper_issuer_needs_neither_trusted_argv_nor_unqualified() -> None:
    assert validate_cred_trusted_argv(_helper_cap()) == ()


@pytest.mark.parametrize(
    "options",
    [
        {"trusted_argv": ["/usr/bin/kubectl"]},
        {"unqualified_exec": True},
        {"unqualified_exec": False},
    ],
)
def test_declaring_either_on_a_helper_issuer_is_an_error(options: dict[str, object]) -> None:
    with pytest.raises(SecretSourceConfigError, match="helper-rung"):
        validate_cred_trusted_argv(_helper_cap(**options))


def test_every_other_cred_capability_keeps_the_rule() -> None:
    plain = Capability("cred:x", "cred", ("claude",), {"vault": "kv/example/x"})
    with pytest.raises(SecretSourceConfigError, match="trusted_argv is required"):
        validate_cred_trusted_argv(plain)
    env_rung = Capability(
        "cred:x", "cred", ("claude",), {},
        issuer={"kind": "vault-k8s-token", "role": "r", "namespace": "n"},
    )
    with pytest.raises(SecretSourceConfigError, match="trusted_argv is required"):
        validate_cred_trusted_argv(env_rung)
    assert validate_cred_trusted_argv(
        Capability("cred:x", "cred", ("claude",), {"unqualified_exec": True})
    ) == ()


# ---------------------------------------------------------------- doctor


API = "kubernetes/creds/example-role"


class _GrantClient:
    reply: Any = None
    posts: list[tuple[str, Any]] = []

    def __init__(self, url: str | None = None, token: str | None = None, **_: Any) -> None:
        self.token = token
        self.auth = MagicMock()
        self.adapter = MagicMock()
        self.adapter.post.side_effect = self._post

    def _post(self, url: str, json: Any = None) -> Any:
        _GrantClient.posts.append((url, json))
        if isinstance(_GrantClient.reply, Exception):
            raise _GrantClient.reply
        return _GrantClient.reply


@pytest.fixture
def plane(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    hvac = pytest.importorskip("hvac", reason="needs the [cred] extra")
    _GrantClient.posts = []
    monkeypatch.setattr(hvac, "Client", _GrantClient)
    f = tmp_path / "plane.env"
    f.write_text(
        "VAULT_ADDR=https://vault.EXAMPLE.local\nVAULT_ROLE_ID=r\nVAULT_SECRET_ID=s\n",
        encoding="utf-8",
    )
    return str(f)


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ({"data": {API: ["update"]}}, True),
        ({"data": {API: ["create"]}}, True),
        ({"data": {API: ["root"]}}, True),
        ({"capabilities": ["update"]}, True),
        ({"data": {API: ["read", "list"]}}, False),
        ({"data": {API: ["deny"]}}, False),
        ({"data": {}}, None),
        ("not a dict", None),
        (RuntimeError("403"), None),
    ],
)
def test_doctor_grant_check_asks_about_the_creds_path(
    plane: str, reply: Any, expected: bool | None
) -> None:
    _GrantClient.reply = reply
    assert real_read_granted(_helper_cap(), vault_env=plane) is expected
    assert _GrantClient.posts == [("/v1/sys/capabilities-self", {"paths": [API]})]


def test_grant_check_uses_the_declared_mount_and_is_unknown_without_a_role(plane: str) -> None:
    _GrantClient.reply = {"data": {"k8s-eng/creds/r": ["update"]}}
    cap = Capability(
        CAP_ID, "cred", ("claude",), {},
        issuer={"kind": "vault-k8s-token", "mount": "k8s-eng", "role": "r", "namespace": "n"},
        delivery={"rung": "helper", "tool": "kubectl"},
    )
    assert real_read_granted(cap, vault_env=plane) is True
    broken = Capability(
        CAP_ID, "cred", ("claude",), {},
        issuer={"kind": "vault-k8s-token", "namespace": "n"},
        delivery={"rung": "helper", "tool": "kubectl"},
    )
    _GrantClient.posts = []
    assert real_read_granted(broken, vault_env=plane) is None
    assert _GrantClient.posts == []


@pytest.mark.parametrize(
    ("granted", "status", "needle"),
    [
        (True, Status.PRESENT_OK, "update on the declared creds path granted"),
        (False, Status.PRESENT_BROKEN, "not granted update on the declared creds path"),
        (None, Status.PRESENT_OK, "broker reachable (token self-lookup)"),
    ],
)
def test_doctor_verdict_for_a_helper_capability(
    monkeypatch: pytest.MonkeyPatch, granted: bool | None, status: Status, needle: str
) -> None:
    monkeypatch.setattr(cred_vault, "reachable", lambda cap, **_: True)
    monkeypatch.setattr(cred_vault, "read_granted", lambda cap, **_: granted)
    got, detail = CredProvider()._reachability(_helper_cap())
    assert got is status and needle in detail


def test_helper_capability_needs_no_discovery_shim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agent_capability_broker.adapters import OpencodeAdapter

    adapter = OpencodeAdapter(config_path=tmp_path / "opencode.json")
    assert CAP_ID.replace(":", "-") not in adapter.command_shims()
    monkeypatch.setattr(cred_vault, "reachable", lambda cap, **_: True)
    monkeypatch.setattr(cred_vault, "read_granted", lambda cap, **_: True)
    provider = CredProvider()
    verdict = provider.inspect(_helper_cap(), "opencode", adapter)
    assert verdict.status is Status.PRESENT_OK and "acb kube-token" in verdict.detail
    assert provider.plan_reconcile(_helper_cap(), "opencode", adapter) == []
    monkeypatch.setattr(cred_vault, "read_granted", lambda cap, **_: False)
    assert provider.inspect(_helper_cap(), "opencode", adapter).status is Status.PRESENT_BROKEN
    (action,) = provider.plan_reconcile(_helper_cap(), "opencode", adapter)
    assert action.kind == "manual"
    monkeypatch.setattr(cred_vault, "reachable", lambda cap, **_: False)
    assert provider.inspect(_helper_cap(), "opencode", adapter).status is Status.PRESENT_BROKEN


def test_declaring_trusted_argv_on_a_helper_capability_breaks_doctor(
    tmp_path: Path,
) -> None:
    from agent_capability_broker.adapters import OpencodeAdapter

    adapter = OpencodeAdapter(config_path=tmp_path / "opencode.json")
    cap = _helper_cap(trusted_argv=["/usr/bin/kubectl"])
    v = CredProvider().inspect(cap, "opencode", adapter)
    assert v.status is Status.PRESENT_BROKEN and "helper-rung" in v.detail


def test_json_is_a_single_line_and_matches_the_kubectl_shape() -> None:
    doc = kube_token.exec_credential("t", NOW, 600)
    line = json.dumps(doc, separators=(",", ":"))
    assert re.fullmatch(
        r'\{"apiVersion":"client\.authentication\.k8s\.io/v1","kind":"ExecCredential",'
        r'"status":\{"token":"t","expirationTimestamp":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"\}\}',
        line,
    )
