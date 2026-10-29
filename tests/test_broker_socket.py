"""acb-broker over a real AF_UNIX socket in a tmpdir, and the helper front-ends.

Everything runs against the fake issuer: no Vault, no git config, no
kubeconfig is touched. The real-git test passes the helper with ``-c`` and an
isolated HOME/global config.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agent_capability_broker.broker import git_credential, kube_credential
from agent_capability_broker.broker import protocol as P
from agent_capability_broker.broker.client import (
    BrokerError,
    BrokerUnavailable,
    broker_status,
    call,
    list_checkouts,
    revoke_checkouts,
)
from agent_capability_broker.broker.config import parse_broker_config
from agent_capability_broker.broker.harness import attribute
from agent_capability_broker.broker.issuers import FakeIssuer
from agent_capability_broker.broker.registry import Registry, read_state
from agent_capability_broker.broker.server import BrokerServer
from agent_capability_broker.broker.service import Broker, Peer, provenance_events

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="acb-broker is Linux-only"
)

CANARY = "canary-s0cket-41b7-must-not-leak"
FORGE = "forge.example.test"
SRC = Path(__file__).resolve().parents[1] / "src"

MANIFEST: dict[str, Any] = {
    "capability": {
        "cred:forge": {
            "provider": "cred",
            "issuer": {"kind": "fake", "ttl": "10m"},
            "delivery": {"rung": "helper", "tool": "git", "hosts": [FORGE],
                         "username": "agent-bot"},
        },
        "cred:k8s": {
            "provider": "cred",
            "issuer": {"kind": "fake", "ttl": "5m"},
            "delivery": {"rung": "helper", "tool": "kubectl"},
        },
    }
}


class Running:
    def __init__(self, root: Path, peer: Peer | None = None) -> None:
        self.root = root
        self.sock = root / "run" / "broker.sock"
        self.fake = FakeIssuer(lambda cap, n: {"password": f"{CANARY}-{n}",
                                               "token": f"{CANARY}-{n}"})
        self.issuers = {"fake": self.fake}
        self.reg = Registry(root / "state" / "checkouts.json", self.issuers,
                            events=provenance_events)
        no_proc = root / "no-proc"
        self.broker = Broker(
            parse_broker_config(MANIFEST), self.reg, self.issuers, socket_path=self.sock,
            attribute_fn=lambda pid, hint: attribute(pid, hint, proc_root=no_proc),
        )
        kwargs: dict[str, Any] = {"reap_interval": 0.05, "conn_timeout": 1.0}
        if peer is not None:
            kwargs["peer_cred"] = lambda conn: peer
        self.server = BrokerServer(self.broker, self.sock, **kwargs)
        self.server.bind()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> list[str]:
        self.server.stop()
        self.thread.join(3)
        return self.server.close()


@pytest.fixture
def short_dir(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    # AF_UNIX paths are limited to ~107 bytes; pytest's tmp_path can exceed that.
    d = Path(tempfile.mkdtemp(prefix="acbt-"))
    monkeypatch.setenv("ACB_STATE_DIR", str(d / "prov"))
    monkeypatch.delenv("ACB_SESSION_ID", raising=False)
    monkeypatch.setenv("ACB_HARNESS", "codex")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def running(short_dir: Path) -> Iterator[Running]:
    r = Running(short_dir)
    try:
        yield r
    finally:
        r.close()


def _raw(sock_path: Path, payload: bytes) -> dict[str, Any]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(str(sock_path))
    s.sendall(payload)
    s.shutdown(socket.SHUT_WR)
    try:
        return P.read_frame(s, limit=P.MAX_RESPONSE_BYTES)
    finally:
        s.close()


def _git(op: str, attrs: str, sock: Path) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    rc = git_credential.main([op], stdin=io.StringIO(attrs), stdout=out, stderr=err,
                             socket_path=sock)
    return rc, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------- server


class TestServer:
    def test_socket_and_dir_modes(self, running: Running) -> None:
        assert stat.S_ISSOCK(os.lstat(running.sock).st_mode)
        assert stat.S_IMODE(os.lstat(running.sock).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(running.sock.parent).st_mode) == 0o700

    def test_status_and_list_round_trip(self, running: Running) -> None:
        st = broker_status(socket_path=running.sock)
        assert st["protocol"] == P.PROTOCOL and st["live_checkouts"] == 0
        assert {c["id"] for c in st["capabilities"]} == {"cred:forge", "cred:k8s"}
        assert list_checkouts(socket_path=running.sock) == []

    def test_malformed_frames_get_error_envelopes(self, running: Running) -> None:
        r = _raw(running.sock, struct.pack(">I", 8) + b"notjson!")
        assert r["error"]["code"] == P.ErrorCode.BAD_FRAME
        r = _raw(running.sock, struct.pack(">I", P.MAX_REQUEST_BYTES + 1))
        assert r["error"]["code"] == P.ErrorCode.TOO_LARGE
        r = _raw(running.sock, P.encode_frame({"v": P.PROTOCOL, "method": "nope"}, limit=999))
        assert r["error"]["code"] == P.ErrorCode.UNKNOWN_METHOD
        # The server is still healthy afterwards.
        assert broker_status(socket_path=running.sock)["live_checkouts"] == 0

    def test_slow_client_times_out(self, running: Running) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(str(running.sock))
        s.sendall(b"\x00\x00")  # half a header, then silence
        resp = P.read_frame(s, limit=P.MAX_RESPONSE_BYTES)
        s.close()
        assert resp["error"]["code"] == P.ErrorCode.TIMEOUT

    def test_foreign_uid_is_refused(self, short_dir: Path) -> None:
        r = Running(short_dir, peer=Peer(pid=1, uid=os.geteuid() + 4242, gid=0))
        try:
            with pytest.raises(BrokerError) as ei:
                call("status", socket_path=r.sock)
            assert ei.value.code == P.ErrorCode.FORBIDDEN_PEER
            assert r.fake.issued == []
        finally:
            r.close()

    def test_root_peer_is_allowed(self, short_dir: Path) -> None:
        r = Running(short_dir, peer=Peer(pid=1, uid=0, gid=0))
        try:
            assert call("status", socket_path=r.sock)[0]["protocol"] == P.PROTOCOL
        finally:
            r.close()

    def test_refuses_to_replace_a_live_socket(self, running: Running) -> None:
        from agent_capability_broker.broker.server import BrokerStartupError

        twin = BrokerServer(running.broker, running.sock)
        with pytest.raises(BrokerStartupError, match="already listening"):
            twin.bind()

    def test_refuses_foreign_or_non_socket_paths(self, short_dir: Path) -> None:
        from agent_capability_broker.broker.server import BrokerStartupError

        r = Running(short_dir)
        r.close()
        (short_dir / "run" / "broker.sock").write_text("x", encoding="utf-8")
        with pytest.raises(BrokerStartupError, match="not a socket"):
            BrokerServer(r.broker, r.sock).bind()

    def test_shutdown_revokes_live_checkouts(self, short_dir: Path) -> None:
        r = Running(short_dir)
        call("checkout", {"capability": "cred:k8s"}, socket_path=r.sock)
        call("checkout", {"capability": "cred:forge"}, socket_path=r.sock)
        revoked = r.close()
        assert len(revoked) == 2 and sorted(r.fake.revoked) == sorted(r.fake.issued)
        assert read_state(r.reg.state_path) == []
        assert not r.sock.exists()

    def test_reaper_thread_revokes_expired(self, running: Running) -> None:
        call("checkout", {"capability": "cred:k8s", "ttl": 1}, socket_path=running.sock)
        deadline = time.monotonic() + 5
        while running.fake.revoked == [] and time.monotonic() < deadline:
            threading.Event().wait(0.05)
        assert running.fake.revoked == running.fake.issued

    def test_revoke_verbs_are_dry_run_by_default(self, running: Running) -> None:
        call("checkout", {"capability": "cred:k8s"}, socket_path=running.sock)
        dry = revoke_checkouts(capability="cred:k8s", socket_path=running.sock)
        assert dry["dry_run"] and len(dry["would_revoke"]) == 1 and not running.fake.revoked
        done = revoke_checkouts(capability="cred:k8s", dry_run=False, socket_path=running.sock)
        assert len(done["revoked"]) == 1 and running.fake.revoked

    def test_canary_never_on_disk_or_in_value_free_responses(self, running: Running) -> None:
        rc, out, _ = _git("get", f"protocol=https\nhost={FORGE}\n\n", running.sock)
        assert rc == 0 and CANARY in out  # the helper did get the value...
        seen = [
            json.dumps(broker_status(socket_path=running.sock)),
            json.dumps(list_checkouts(socket_path=running.sock)),
            json.dumps(revoke_checkouts(all_checkouts=True, socket_path=running.sock)),
        ]
        for blob in seen:
            assert CANARY not in blob
        # ...and nothing persisted carries it (state file + provenance).
        for path in running.root.rglob("*"):
            if path.is_file():
                assert CANARY not in path.read_text(encoding="utf-8", errors="replace"), path


# ---------------------------------------------------------------- helpers


class TestGitHelper:
    def test_get_prints_credentials(self, running: Running) -> None:
        rc, out, err = _git("get", f"protocol=https\nhost={FORGE}\npath=x.git\n\n", running.sock)
        assert rc == 0 and err == ""
        lines = dict(line.split("=", 1) for line in out.strip().splitlines())
        assert lines["username"] == "agent-bot"
        assert lines["password"] == f"{CANARY}-1"
        assert int(lines["password_expiry_utc"]) > 0
        assert list_checkouts(socket_path=running.sock)[0]["harness"] == "codex"

    def test_unknown_host_is_silent(self, running: Running) -> None:
        assert _git("get", "protocol=https\nhost=other.example.test\n\n", running.sock) == (
            0, "", ""
        )
        assert running.fake.issued == []

    def test_http_is_refused(self, running: Running) -> None:
        rc, out, err = _git("get", f"protocol=http\nhost={FORGE}\n\n", running.sock)
        assert rc == 1 and out == "" and "https only" in err
        assert running.fake.issued == []

    def test_store_is_noop_and_erase_revokes(self, running: Running) -> None:
        _git("get", f"protocol=https\nhost={FORGE}\n\n", running.sock)
        assert _git("store", f"protocol=https\nhost={FORGE}\nusername=u\npassword=p\n\n",
                    running.sock) == (0, "", "")
        assert len(list_checkouts(socket_path=running.sock)) == 1
        assert _git("erase", f"protocol=https\nhost={FORGE}\n\n", running.sock) == (0, "", "")
        assert list_checkouts(socket_path=running.sock) == []
        assert running.fake.revoked == running.fake.issued

    def test_unknown_operation_is_ignored(self, running: Running) -> None:
        assert _git("capability", "", running.sock) == (0, "", "")

    def test_broker_down_fails_closed(self, short_dir: Path) -> None:
        rc, out, err = _git("get", f"protocol=https\nhost={FORGE}\n\n",
                            short_dir / "nothing.sock")
        assert rc != 0 and out == ""
        assert err.count("\n") == 1 and "not reachable" in err

    def test_real_git_credential_fill(self, running: Running, short_dir: Path) -> None:
        git = shutil.which("git")
        if git is None:
            pytest.skip("git not installed")
        home = short_dir / "home"
        home.mkdir()
        helper = (
            f"!{sys.executable} -c 'import sys; "
            f"from agent_capability_broker.broker.git_credential import main; "
            f"sys.exit(main())'"
        )
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "ACB_BROKER_SOCKET": str(running.sock),
            "ACB_HARNESS": "claude",
            "PYTHONPATH": str(SRC),
        }
        proc = subprocess.run(
            [git, "-c", "credential.helper=", "-c", f"credential.helper={helper}",
             "credential", "fill"],
            input=f"protocol=https\nhost={FORGE}\n\n",
            capture_output=True, text=True, env=env, timeout=30, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "username=agent-bot" in proc.stdout
        assert f"password={CANARY}-1" in proc.stdout


class TestKubeHelper:
    def test_exec_credential(self, running: Running) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = kube_credential.main(["cred:k8s"], stdout=out, stderr=err, socket_path=running.sock)
        assert rc == 0 and err.getvalue() == ""
        cred = json.loads(out.getvalue())
        assert cred["apiVersion"] == "client.authentication.k8s.io/v1"
        assert cred["kind"] == "ExecCredential"
        assert cred["status"]["token"] == f"{CANARY}-1"
        assert cred["status"]["expirationTimestamp"].endswith("Z")

    def test_wrong_tool_is_refused(self, running: Running) -> None:
        out, err = io.StringIO(), io.StringIO()
        rc = kube_credential.main(["cred:forge"], stdout=out, stderr=err,
                                  socket_path=running.sock)
        assert rc == 1 and out.getvalue() == "" and "delivery_mismatch" in err.getvalue()

    def test_usage(self) -> None:
        err = io.StringIO()
        assert kube_credential.main([], stdout=io.StringIO(), stderr=err) == 2

    def test_broker_down_fails_closed_in_a_subprocess(self, short_dir: Path) -> None:
        env = dict(os.environ)
        env["ACB_BROKER_SOCKET"] = str(short_dir / "nothing.sock")
        env["PYTHONPATH"] = str(SRC)
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys; from agent_capability_broker.broker.kube_credential import main; "
             "sys.exit(main())", "cred:k8s"],
            capture_output=True, text=True, env=env, timeout=30, check=False,
        )
        assert proc.returncode != 0 and proc.stdout == ""
        assert proc.stderr.count("\n") == 1 and "acb-kube-credential" in proc.stderr

    def test_client_reports_unavailable(self, short_dir: Path) -> None:
        with pytest.raises(BrokerUnavailable):
            call("status", socket_path=short_dir / "nothing.sock")


def test_broker_import_does_not_load_hvac() -> None:
    code = (
        "import sys\n"
        "import agent_capability_broker.broker.server, agent_capability_broker.broker.issuers\n"
        "import agent_capability_broker.broker.git_credential\n"
        "import agent_capability_broker.broker.kube_credential\n"
        "assert 'hvac' not in sys.modules, 'hvac imported at module import time'\n"
        "assert 'agent_capability_broker.cred_vault' not in sys.modules\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr


def test_harden_process_disables_core_dumps() -> None:
    code = (
        "import ctypes, ctypes.util, resource\n"
        "from agent_capability_broker.broker.server import harden_process\n"
        "assert harden_process() == []\n"
        "assert resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)\n"
        "libc = ctypes.CDLL(ctypes.util.find_library(\"c\"))\n"
        "assert libc.prctl(3, 0, 0, 0, 0) == 0  # PR_GET_DUMPABLE\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=30, check=False)
    assert proc.returncode == 0, proc.stderr


def test_entry_point_refuses_non_linux(monkeypatch: pytest.MonkeyPatch,
                                       capsys: pytest.CaptureFixture[str]) -> None:
    from agent_capability_broker.broker import server

    monkeypatch.setattr(server.sys, "platform", "darwin")
    assert server.main([]) == 2
    assert "unsupported platform" in capsys.readouterr().err
