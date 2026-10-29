"""acb-broker core without sockets: config, issuers, registry, attribution, service.

The canary is the issued value. It must reach the helper-bound checkout
response and nothing else: not the state file, not provenance, not logs, not
list/status/revoke responses.
"""

from __future__ import annotations

import json
import logging
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from agent_capability_broker.broker import protocol as P
from agent_capability_broker.broker.config import (
    BrokerCapability,
    BrokerConfigError,
    load_broker_config,
    parse_broker_config,
    parse_ttl,
)
from agent_capability_broker.broker.harness import Attribution, attribute, pid_alive
from agent_capability_broker.broker.issuers import (
    FakeIssuer,
    IssueContext,
    IssuerError,
    RemoteMintIssuer,
    VaultK8sTokenIssuer,
    VaultKvIssuer,
    VaultSession,
    default_issuers,
)
from agent_capability_broker.broker.registry import Registry, read_state
from agent_capability_broker.broker.service import Broker, Peer, provenance_events

# Skip at import time, not with a mark: module-level code below calls POSIX-only
# APIs (os.getuid), which would raise at collection on Windows.
if not sys.platform.startswith("linux"):
    pytest.skip("acb-broker is Linux-only", allow_module_level=True)

CANARY = "canary-v4lue-9d1e-must-not-persist"
FORGE = "forge.example.test"


def manifest() -> dict[str, Any]:
    return {
        "capability": {
            "cred:forge": {
                "provider": "cred",
                "issuer": {"kind": "fake", "ttl": "10m"},
                "delivery": {
                    "rung": "helper", "tool": "git", "hosts": [FORGE], "username": "agent-bot",
                },
                "assurance": "D1",
                "harnesses": ["claude", "codex", "shell"],
            },
            "cred:k8s": {
                "provider": "cred",
                "issuer": {"kind": "fake", "ttl": 600},
                "delivery": {"rung": "helper", "tool": "kubectl"},
                "assurance": "D1",
            },
            "cred:claude-only": {
                "provider": "cred",
                "issuer": {"kind": "fake"},
                "delivery": {"rung": "env"},
                "harnesses": ["claude"],
            },
            "cred:legacy-v1": {"provider": "cred", "source": "vault", "harnesses": ["claude"]},
        }
    }


def canary_values(cap: BrokerCapability, n: int) -> dict[str, str]:
    return {"password": f"{CANARY}-{n}", "token": f"{CANARY}-{n}"}


class Clock:
    def __init__(self) -> None:
        self.t = 1_800_000_000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "prov"))
    clock = Clock()
    fake = FakeIssuer(canary_values)
    issuers = {"fake": fake}
    reg = Registry(
        tmp_path / "state" / "checkouts.json",
        issuers,
        clock=clock,
        events=provenance_events,
        alive=lambda pid, start: True,
    )
    cfg = parse_broker_config(manifest())
    hint_only = Path(tmp_path / "no-proc")  # empty /proc: attribution falls to the hint
    broker = Broker(
        cfg, reg, issuers, clock=clock,
        attribute_fn=lambda pid, hint: attribute(pid, hint, proc_root=hint_only),
    )
    return {"broker": broker, "reg": reg, "fake": fake, "clock": clock, "tmp": tmp_path}


PEER = Peer(pid=4242, uid=os.getuid(), gid=os.getgid())


def req(method: str, params: dict[str, Any] | None = None, **top: Any) -> dict[str, Any]:
    return P.make_request(method, params, **top)


def assert_no_canary(tmp: Path, *extra: str) -> None:
    for path in tmp.rglob("*"):
        if path.is_file():
            assert CANARY not in path.read_text(encoding="utf-8", errors="replace"), path
    for blob in extra:
        assert CANARY not in blob


# ---------------------------------------------------------------- config


class TestConfig:
    def test_only_issuer_bearing_capabilities_are_served(self) -> None:
        cfg = parse_broker_config(manifest())
        assert set(cfg.capabilities) == {"cred:forge", "cred:k8s", "cred:claude-only"}
        forge = cfg.capabilities["cred:forge"]
        assert forge.issuer.ttl == 600
        assert forge.delivery.hosts == (FORGE,)
        assert cfg.match("git", FORGE.upper()) is forge
        assert cfg.match("git", "other.example.test") is None
        assert cfg.match("kubectl", None) is cfg.capabilities["cred:k8s"]

    @pytest.mark.parametrize(
        ("raw", "secs"), [(60, 60), ("90s", 90), ("15m", 900), ("10", 10)]
    )
    def test_ttl(self, raw: object, secs: int) -> None:
        assert parse_ttl(raw, where="t") == secs

    @pytest.mark.parametrize("raw", ["16m", "1h", 0, True, "soon", 901])
    def test_ttl_bounded_to_15m(self, raw: object) -> None:
        with pytest.raises(BrokerConfigError):
            parse_ttl(raw, where="t")

    @pytest.mark.parametrize(
        "issuer",
        [
            {"kind": "nope"},
            {"kind": "vault-kv", "path": "kv/x"},                       # no field selection
            {"kind": "vault-kv", "path": "nomount", "fields": ["a"]},
            {"kind": "vault-kv", "path": "kv/../sys", "fields": ["a"]},
            {"kind": "vault-k8s-token", "role": "r"},                   # no namespace
            {"kind": "vault-k8s-token", "role": "r", "namespace": "n", "mount": "/abs"},
        ],
    )
    def test_bad_issuer(self, issuer: dict[str, Any]) -> None:
        with pytest.raises(BrokerConfigError):
            parse_broker_config({"capability": {"cred:x": {"provider": "cred", "issuer": issuer}}})

    def test_bad_delivery_and_assurance(self) -> None:
        base = {"provider": "cred", "issuer": {"kind": "fake"}}
        for extra in (
            {"delivery": {"rung": "teleport"}},
            {"delivery": {"rung": "helper"}},            # helper needs a tool
            {"assurance": "D9"},
            {"harnesses": "claude"},
        ):
            with pytest.raises(BrokerConfigError):
                parse_broker_config({"capability": {"cred:x": {**base, **extra}}})

    def test_one_capability_per_git_host(self) -> None:
        d = {"rung": "helper", "tool": "git", "hosts": [FORGE]}
        caps = {
            f"cred:{n}": {"provider": "cred", "issuer": {"kind": "fake"}, "delivery": d}
            for n in ("a", "b")
        }
        with pytest.raises(BrokerConfigError, match="already served"):
            parse_broker_config({"capability": caps})

    def test_vault_kv_is_d0_whatever_is_declared(self) -> None:
        cfg = parse_broker_config({"capability": {"cred:kv": {
            "provider": "cred", "assurance": "D1",
            "issuer": {"kind": "vault-kv", "path": "kv/example/x", "field": "password"},
        }}})
        cap = cfg.capabilities["cred:kv"]
        assert cap.effective_assurance == "D0" and not cap.meets_floor
        assert cap.issuer.params["fields"] == ["password"]

    def test_load_uses_manifest_resolution(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        m = tmp_path / "capabilities.toml"
        m.write_text(
            '[capability."cred:k"]\nprovider = "cred"\n'
            'issuer = { kind = "vault-k8s-token", role = "r", namespace = "ns", ttl = "5m" }\n'
            'delivery = { rung = "helper", tool = "kubectl" }\n',
            encoding="utf-8",
        )
        monkeypatch.setenv("ACB_MANIFEST", str(m))
        cfg = load_broker_config()
        assert cfg.source == m
        assert cfg.capabilities["cred:k"].issuer.params["mount"] == "kubernetes"


# ---------------------------------------------------------------- service + registry


class TestCheckoutRevokeList:
    def test_helper_checkout_carries_value_and_is_marked(self, env: dict[str, Any]) -> None:
        b: Broker = env["broker"]
        resp = b.handle(
            req("checkout", {"match": {"tool": "git", "host": FORGE}}, front_end="git",
                harness_hint="codex"),
            PEER,
        )
        assert resp["ok"] and resp["carries_secret"] is True
        r = resp["result"]
        assert r["value"]["password"].startswith(CANARY)
        assert r["username"] == "agent-bot"
        assert r["harness"] == "codex" and r["harness_source"] == "hint"
        assert r["expires_at"] - r["issued_at"] == 600
        P.check_response_shape("checkout", "git", resp)

    def test_non_helper_checkout_is_value_free(self, env: dict[str, Any]) -> None:
        resp = env["broker"].handle(req("checkout", {"capability": "cred:k8s"}), PEER)
        assert resp["ok"] and resp["carries_secret"] is False
        assert CANARY not in json.dumps(resp)

    def test_reuse_within_session(self, env: dict[str, Any]) -> None:
        b, fake = env["broker"], env["fake"]
        r1 = b.handle(req("checkout", {"capability": "cred:k8s"}, front_end="kube"), PEER)
        r2 = b.handle(req("checkout", {"capability": "cred:k8s"}, front_end="kube"), PEER)
        assert r1["result"]["id"] == r2["result"]["id"] and r2["result"]["reused"]
        assert r1["result"]["value"] == r2["result"]["value"]
        assert len(fake.issued) == 1
        other = b.handle(
            req("checkout", {"capability": "cred:k8s"}, front_end="kube", session="s2"), PEER
        )
        assert other["result"]["id"] != r1["result"]["id"]

    def test_ttl_request_only_shortens(self, env: dict[str, Any]) -> None:
        r = env["broker"].handle(req("checkout", {"capability": "cred:k8s", "ttl": 30}), PEER)
        assert r["result"]["expires_at"] - r["result"]["issued_at"] == 30

    def test_refusals(self, env: dict[str, Any]) -> None:
        b = env["broker"]
        cases = [
            (req("checkout", {"capability": "cred:nope"}), P.ErrorCode.UNKNOWN_CAPABILITY),
            (req("checkout", {"capability": "cred:legacy-v1"}), P.ErrorCode.UNKNOWN_CAPABILITY),
            (
                req("checkout", {"match": {"tool": "git", "host": "x.test"}}, front_end="git"),
                P.ErrorCode.NO_MATCH,
            ),
            (  # the git helper cannot pull a kubectl credential
                req("checkout", {"capability": "cred:k8s"}, front_end="git"),
                P.ErrorCode.DELIVERY_MISMATCH,
            ),
            (  # advisory allowlist: accident prevention, not security
                req("checkout", {"capability": "cred:claude-only"}, harness_hint="codex"),
                P.ErrorCode.HARNESS_NOT_ALLOWED,
            ),
            (req("revoke", {"checkout_id": "co_missing"}), P.ErrorCode.NOT_FOUND),
        ]
        for request, code in cases:
            resp = b.handle(request, PEER)
            assert not resp["ok"] and resp["error"]["code"] == code, (request, resp)

    def test_list_status_revoke_are_value_free(self, env: dict[str, Any]) -> None:
        b, fake = env["broker"], env["fake"]
        co = b.handle(req("checkout", {"capability": "cred:k8s"}, front_end="kube"), PEER)
        cid = co["result"]["id"]
        listed = b.handle(req("list"), PEER)
        status = b.handle(req("status"), PEER)
        dry = b.handle(req("revoke", {"checkout_id": cid, "dry_run": True}), PEER)
        assert [c["id"] for c in listed["result"]["checkouts"]] == [cid]
        assert "revocation_handle" not in listed["result"]["checkouts"][0]
        assert status["result"]["live_checkouts"] == 1
        assert dry["result"]["would_revoke"][0]["id"] == cid and not fake.revoked
        done = b.handle(req("revoke", {"checkout_id": cid}), PEER)
        assert done["result"]["revoked"] == [cid]
        assert fake.revoked == fake.issued
        assert b.handle(req("list"), PEER)["result"]["checkouts"] == []
        for resp, method in ((listed, "list"), (status, "status"), (dry, "revoke"),
                             (done, "revoke")):
            assert resp["carries_secret"] is False
            assert CANARY not in json.dumps(resp)
            P.check_response_shape(method, None, resp)

    def test_revoke_own_session_by_match(self, env: dict[str, Any]) -> None:
        b = env["broker"]
        sel = {"match": {"tool": "git", "host": FORGE}}
        mine = b.handle(req("checkout", sel, front_end="git", session="mine"), PEER)
        theirs = b.handle(req("checkout", sel, front_end="git", session="theirs"), PEER)
        out = b.handle(req("revoke", {**sel, "own_session": True}, front_end="git",
                           session="mine"), PEER)
        assert out["result"]["revoked"] == [mine["result"]["id"]]
        left = b.handle(req("list"), PEER)["result"]["checkouts"]
        assert [c["id"] for c in left] == [theirs["result"]["id"]]

    def test_revoke_all(self, env: dict[str, Any]) -> None:
        b = env["broker"]
        for s in ("a", "b", "c"):
            b.handle(req("checkout", {"capability": "cred:k8s"}, session=s), PEER)
        out = b.handle(req("revoke", {"all": True}), PEER)
        assert len(out["result"]["revoked"]) == 3

    def test_respond_encodes_and_survives_garbage(self, env: dict[str, Any]) -> None:
        b: Broker = env["broker"]
        frame = b.respond(b"not json", PEER)
        body = json.loads(frame[4:])
        assert body["error"]["code"] == P.ErrorCode.BAD_FRAME
        frame = b.respond(json.dumps(req("status")).encode(), PEER)
        assert json.loads(frame[4:])["ok"] is True

    def test_remote_mint_is_not_implemented(self, env: dict[str, Any]) -> None:
        cfg = parse_broker_config({"capability": {"cred:rm": {
            "provider": "cred", "issuer": {"kind": "remote-mint"},
        }}})
        b = Broker(cfg, env["reg"], {"remote-mint": RemoteMintIssuer()})
        resp = b.handle(req("checkout", {"capability": "cred:rm"}), PEER)
        assert resp["error"]["code"] == P.ErrorCode.NOT_IMPLEMENTED

    def test_fake_kind_absent_from_production_table(self, env: dict[str, Any]) -> None:
        assert "fake" not in default_issuers(VaultSession(lambda: object()))
        b = Broker(env["broker"].config, env["reg"], default_issuers(VaultSession(object)))
        resp = b.handle(req("checkout", {"capability": "cred:k8s"}), PEER)
        assert resp["error"]["code"] == P.ErrorCode.ISSUER_ERROR


class TestLifecycle:
    def test_reaper_revokes_on_expiry(self, env: dict[str, Any]) -> None:
        b, reg, fake, clock = env["broker"], env["reg"], env["fake"], env["clock"]
        cid = b.handle(req("checkout", {"capability": "cred:k8s", "ttl": 60}), PEER)["result"]["id"]
        clock.t += 59
        assert reg.reap() == []
        clock.t += 1
        assert reg.reap() == [cid]
        assert fake.revoked == fake.issued
        assert read_state(reg.state_path) == []

    def test_reaper_revokes_on_session_end(self, env: dict[str, Any], tmp_path: Path) -> None:
        fake = FakeIssuer(canary_values)
        alive = {"value": True}
        reg = Registry(
            tmp_path / "s2.json", {"fake": fake}, alive=lambda pid, start: alive["value"]
        )
        b = Broker(
            env["broker"].config, reg, {"fake": fake},
            attribute_fn=lambda pid, hint: Attribution("claude", "process", 777, 12345),
        )
        r = b.handle(req("checkout", {"capability": "cred:k8s"}), PEER)["result"]
        assert r["session"] == "claude-777-12345" and r["anchor_pid"] == 777
        assert reg.reap() == []
        alive["value"] = False  # the harness process exited
        assert reg.reap() == [r["id"]]

    def test_restart_revokes_stale_state(self, env: dict[str, Any], tmp_path: Path) -> None:
        b, reg, fake = env["broker"], env["reg"], env["fake"]
        b.handle(req("checkout", {"capability": "cred:k8s"}), PEER)
        b.handle(req("checkout", {"capability": "cred:forge"}, session="x"), PEER)
        assert len(read_state(reg.state_path)) == 2
        # Crash: the process dies without revoking. A new process starts.
        fresh = FakeIssuer()
        reg2 = Registry(reg.state_path, {"fake": fresh})
        revoked = reg2.recover()
        assert len(revoked) == 2
        assert sorted(fresh.revoked) == sorted(fake.issued)
        assert read_state(reg.state_path) == []

    def test_failed_revoke_stays_pending_and_is_retried(
        self, env: dict[str, Any], tmp_path: Path
    ) -> None:
        b, reg = env["broker"], env["reg"]
        b.handle(req("checkout", {"capability": "cred:k8s"}), PEER)
        flaky = FakeIssuer(fail_revoke=True)
        reg2 = Registry(reg.state_path, {"fake": flaky})
        assert reg2.recover() == []
        rows = read_state(reg.state_path)
        assert len(rows) == 1 and rows[0].revoke_pending
        assert reg2.counts() == (0, 1)
        flaky.fail_revoke = False
        assert len(reg2.reap()) == 1
        assert read_state(reg.state_path) == []

    def test_corrupt_state_is_set_aside(self, tmp_path: Path) -> None:
        p = tmp_path / "checkouts.json"
        p.write_text("{not json", encoding="utf-8")
        assert Registry(p, {}).recover() == []
        assert list(tmp_path.glob("checkouts.json.corrupt-*"))

    def test_state_file_mode_and_value_free(
        self, env: dict[str, Any], caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG, logger="acb.broker")
        b, reg, tmp = env["broker"], env["reg"], env["tmp"]
        resp = b.handle(req("checkout", {"capability": "cred:k8s"}, front_end="kube"), PEER)
        assert resp["result"]["value"]["token"].startswith(CANARY)  # the value did exist
        b.handle(req("checkout", {"match": {"tool": "git", "host": FORGE}}, front_end="git"),
                 PEER)
        state = reg.state_path
        assert stat.S_IMODE(state.stat().st_mode) == 0o600
        assert stat.S_IMODE(state.parent.stat().st_mode) == 0o700
        rec = json.loads(state.read_text(encoding="utf-8"))["checkouts"][0]
        assert rec["revocation_handle"].startswith("fake/creds/")
        assert "value" not in rec
        listing = repr(reg.select())
        reg.revoke_all(reason="shutdown")
        prov = tmp / "prov" / "provenance.jsonl"
        events = [json.loads(line) for line in prov.read_text(encoding="utf-8").splitlines()]
        assert {e["action"] for e in events} == {"broker_checkout", "broker_revoke"}
        assert all(e["purpose"] == "acb-broker" for e in events)
        # The canary is nowhere on disk (state, provenance) and nowhere in the logs.
        assert_no_canary(tmp, caplog.text, listing)

    def test_provenance_failure_does_not_block(
        self, env: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        blocker = env["tmp"] / "blocker"
        blocker.write_text("", encoding="utf-8")
        monkeypatch.setenv("ACB_STATE_DIR", str(blocker / "sub"))  # mkdir will fail
        resp = env["broker"].handle(req("checkout", {"capability": "cred:k8s"}), PEER)
        assert resp["ok"]


# ---------------------------------------------------------------- attribution


def _proc(root: Path, pid: int, ppid: int, comm: str, start: int, argv: list[str]) -> None:
    d = root / str(pid)
    d.mkdir(parents=True)
    rest = ["S", str(ppid)] + ["0"] * 17 + [str(start), "0", "0"]
    (d / "stat").write_text(f"{pid} ({comm}) " + " ".join(rest) + "\n", encoding="utf-8")
    (d / "comm").write_text(comm + "\n", encoding="utf-8")
    (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")


class TestAttribution:
    def test_walks_to_first_known_harness(self, tmp_path: Path) -> None:
        _proc(tmp_path, 300, 200, "acb-git-creden", 30, ["/usr/bin/acb-git-credential", "get"])
        _proc(tmp_path, 200, 100, "git", 20, ["git", "push"])
        _proc(tmp_path, 100, 50, "node", 10, ["node", "/opt/x/bin/codex.js"])
        _proc(tmp_path, 50, 1, "claude", 5, ["claude"])
        a = attribute(300, "zcode", proc_root=tmp_path)
        assert a == Attribution("codex", "process", 100, 10)  # nearest wins, hint ignored

    def test_comm_with_spaces_and_parens(self, tmp_path: Path) -> None:
        _proc(tmp_path, 9, 1, "odd) (name", 3, ["opencode"])
        assert attribute(9, None, proc_root=tmp_path).harness == "opencode"

    def test_hint_then_shell(self, tmp_path: Path) -> None:
        _proc(tmp_path, 9, 1, "bash", 3, ["bash"])
        assert attribute(9, "codex", proc_root=tmp_path) == Attribution("codex", "hint")
        assert attribute(9, "Bad Hint!", proc_root=tmp_path) == Attribution("shell", "default")
        assert attribute(None, None, proc_root=tmp_path).harness == "shell"

    def test_pid_alive_detects_reuse(self, tmp_path: Path) -> None:
        _proc(tmp_path, 9, 1, "claude", 3, ["claude"])
        assert pid_alive(9, 3, tmp_path)
        assert not pid_alive(9, 4, tmp_path)  # same pid, different process
        assert not pid_alive(10, None, tmp_path)

    def test_real_proc_does_not_crash(self) -> None:
        a = attribute(os.getpid(), None)
        assert a.harness  # whatever ran pytest; never raises


# ---------------------------------------------------------------- Vault issuers


class Forbidden(Exception):
    """Stands in for hvac.exceptions.Forbidden (matched by name)."""


class FakeVault:
    def __init__(self, *, fail_first: bool = False) -> None:
        self.writes: list[tuple[str, dict[str, Any] | None]] = []
        self.fail_first = fail_first
        self.store: dict[str, dict[str, Any]] = {}
        # client.secrets.kv.v2.read_secret_version(...) resolves back to self.
        self.secrets = self.kv = self.v2 = self

    def write_data(
        self, path: str, *, data: dict[str, Any] | None = None, wrap_ttl: str | None = None
    ) -> Any:
        if self.fail_first:
            self.fail_first = False
            raise Forbidden("permission denied")
        self.writes.append((path, data))
        if "/creds/" in path:
            n = len(self.writes)
            return {
                "lease_id": f"{path}/lease{n}",
                "lease_duration": 300,
                "renewable": False,
                "data": {
                    "service_account_name": "vault-sa",
                    "service_account_namespace": "agents",
                    "service_account_token": f"{CANARY}-k8s-{n}",
                },
            }
        return None

    def read_secret_version(
        self, *, mount_point: str, path: str, raise_on_deleted_version: bool
    ) -> dict[str, Any]:
        return {"data": {"data": self.store[f"{mount_point}/{path}"]}}


def _cap(issuer: dict[str, Any]) -> BrokerCapability:
    cfg = parse_broker_config({"capability": {"cred:v": {"provider": "cred", "issuer": issuer}}})
    return cfg.capabilities["cred:v"]


CTX = IssueContext(capability_id="cred:v", harness="claude", session="s", ttl=600)


class TestVaultIssuers:
    def test_k8s_token_issue_and_revoke(self) -> None:
        vault = FakeVault()
        issuer = VaultK8sTokenIssuer(VaultSession(lambda: vault))
        cap = _cap({"kind": "vault-k8s-token", "mount": "k8s", "role": "agent-read",
                    "namespace": "agents", "ttl": "10m", "audiences": ["a", "b"]})
        issued = issuer.issue(cap, CTX)
        assert vault.writes[0] == (
            "k8s/creds/agent-read",
            {"kubernetes_namespace": "agents", "ttl": "600s", "audiences": "a,b"},
        )
        assert issued.value_fields == {"token": f"{CANARY}-k8s-1"}
        assert issued.ttl == 300  # Vault's lease_duration wins when shorter
        assert issued.revocation_handle == "k8s/creds/agent-read/lease1"
        assert CANARY not in repr(issued)
        issuer.revoke(issued.revocation_handle)
        assert vault.writes[1] == ("sys/leases/revoke/k8s/creds/agent-read/lease1", None)

    def test_k8s_token_refuses_path_injection_in_handle(self) -> None:
        issuer = VaultK8sTokenIssuer(VaultSession(FakeVault))
        for bad in ("../../sys/seal", "/abs", "a/../b", "x?y=1"):
            with pytest.raises(IssuerError):
                issuer.revoke(bad)

    def test_k8s_token_bad_response_shape(self) -> None:
        class Empty(FakeVault):
            def write_data(self, path: str, *, data: Any = None, wrap_ttl: Any = None) -> Any:
                return {"data": {}}

        issuer = VaultK8sTokenIssuer(VaultSession(Empty))
        cap = _cap({"kind": "vault-k8s-token", "role": "r", "namespace": "n"})
        with pytest.raises(IssuerError, match="unexpected response shape"):
            issuer.issue(cap, CTX)

    def test_session_reauths_once_on_auth_error(self) -> None:
        clients = [FakeVault(fail_first=True), FakeVault()]
        made: list[FakeVault] = []

        def factory() -> FakeVault:
            made.append(clients[len(made)])
            return made[-1]

        issuer = VaultK8sTokenIssuer(VaultSession(factory))
        cap = _cap({"kind": "vault-k8s-token", "role": "r", "namespace": "n"})
        issuer.issue(cap, CTX)
        assert len(made) == 2 and clients[1].writes

    def test_other_errors_are_value_free_issuer_errors(self) -> None:
        class Boom(FakeVault):
            def write_data(self, path: str, *, data: Any = None, wrap_ttl: Any = None) -> Any:
                raise ValueError(f"server said {CANARY}")

        issuer = VaultK8sTokenIssuer(VaultSession(Boom))
        cap = _cap({"kind": "vault-k8s-token", "role": "r", "namespace": "n"})
        with pytest.raises(IssuerError) as ei:
            issuer.issue(cap, CTX)
        assert CANARY not in ei.value.message and "ValueError" in ei.value.message

    def test_auth_refusal_surfaces_as_issuer_error(self) -> None:
        def factory() -> Any:
            raise RuntimeError("VAULT_ADDR is not set")

        issuer = VaultK8sTokenIssuer(VaultSession(factory))
        cap = _cap({"kind": "vault-k8s-token", "role": "r", "namespace": "n"})
        with pytest.raises(IssuerError, match="VAULT_ADDR"):
            issuer.issue(cap, CTX)

    def test_kv_is_a_d0_read_with_noop_revoke(self) -> None:
        vault = FakeVault()
        vault.store["kv/example/forge"] = {"username": "bot", "password": CANARY, "note": "x"}
        issuer = VaultKvIssuer(VaultSession(lambda: vault))
        cap = _cap({"kind": "vault-kv", "path": "kv/example/forge",
                    "fields": ["username", "password"]})
        issued = issuer.issue(cap, CTX)
        assert issued.value_fields == {"username": "bot", "password": CANARY}
        assert issued.revocation_handle is None and cap.effective_assurance == "D0"
        issuer.revoke(None)
        assert vault.writes == []
        missing = _cap({"kind": "vault-kv", "path": "kv/example/forge", "field": "token"})
        with pytest.raises(IssuerError, match="not found"):
            issuer.issue(missing, CTX)

    def test_cred_vault_client_refuses_bare_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pytest.importorskip("hvac", reason="needs the [cred] extra")
        from agent_capability_broker import cred_vault

        for var in list(os.environ):
            if var.startswith("VAULT"):
                monkeypatch.delenv(var)
        monkeypatch.setenv("ACB_VAULT_ENV", str(tmp_path / "absent.env"))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
        monkeypatch.setenv("AGENT_SUITE_CONFIG", str(tmp_path / "suite"))
        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.test:8200")
        monkeypatch.setenv("VAULT_TOKEN", CANARY)
        monkeypatch.setattr(cred_vault, "_K8S_TOKEN", tmp_path / "no-k8s-token")
        with pytest.raises(RuntimeError, match="VAULT_TOKEN is not accepted") as ei:
            cred_vault.authenticated_client(allow_token=False)
        assert CANARY not in str(ei.value)
        # Declared-but-incomplete AppRole still fails closed (WI-016), no token fallback.
        monkeypatch.setenv("VAULT_ROLE_ID", "role")
        with pytest.raises(RuntimeError, match="no SecretID"):
            cred_vault.authenticated_client(allow_token=False)
