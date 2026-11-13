"""Synthetic rotation estate; all Vault traffic uses fake hvac clients."""

from __future__ import annotations

import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent_capability_broker import rotate_secret_id as rotation
from agent_capability_broker.cli import main

OLD = "canary-old-secret"
NEW = "canary-new-secret"
NOW = datetime(2026, 11, 12, tzinfo=UTC)


class InvalidRequest(Exception):
    """Synthetic hvac 400: definitive login rejection."""


class Vault:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.valid = {OLD}
        self.fail = ""
        self.granted = True
        self.logins: list[dict[str, str]] = []
        self.destroyed: list[str] = []
        self.uses = 0
        self.role = "example-agent"

    def client(self, *, url: str, token: str) -> Any:
        assert url == "https://vault.example.invalid" and token == ""
        estate = self

        class Client:
            def __init__(self) -> None:
                self.secret = ""
                self.auth = SimpleNamespace(
                    approle=SimpleNamespace(login=self.login),
                    token=SimpleNamespace(lookup_self=self.lookup, revoke_self=self.revoke),
                )
                self.sys = SimpleNamespace(get_capabilities=self.capabilities)

            def login(self, **kwargs: str) -> None:
                estate.logins.append(kwargs)
                self.secret = kwargs["secret_id"]
                estate.events.append("verify" if self.secret == NEW else "login")
                if self.secret not in estate.valid or (
                    self.secret == NEW and estate.fail == "verify"
                ):
                    raise InvalidRequest(NEW)
                if self.secret == NEW and estate.fail == "timeout":
                    raise TimeoutError(NEW)

            def lookup(self) -> dict[str, Any]:
                estate.events.append("lookup")
                if estate.fail == "lookup":
                    raise RuntimeError(NEW)
                return {"data": {"meta": {"role_name": estate.role}}}

            def revoke(self) -> None:
                estate.events.append("revoke-new" if self.secret == NEW else "revoke-old")
                if estate.fail == "revoke":
                    raise RuntimeError(NEW)

            def capabilities(self, paths: list[str]) -> dict[str, Any]:
                estate.events.append("capabilities")
                return {"data": {p: ["update"] if estate.granted else ["deny"] for p in paths}}

            def write_data(self, path: str, *, data: dict[str, Any]) -> dict[str, Any]:
                assert path.startswith(f"auth/approle/role/{estate.role}/secret-id")
                if path.endswith("/destroy"):
                    estate.events.append("destroy")
                    assert self.secret == NEW
                    if estate.fail == "destroy":
                        raise RuntimeError(OLD)
                    estate.destroyed.append(data["secret_id"])
                    estate.valid.discard(data["secret_id"])
                    return {}
                estate.events.append("mint")
                assert isinstance(data["metadata"], str)
                metadata = json.loads(data["metadata"])
                assert metadata["rotated_by"] == "acb"
                assert metadata["host"]
                if estate.fail == "mint":
                    raise RuntimeError(OLD)
                estate.valid.add(NEW)
                return {"data": {"secret_id": NEW, "secret_id_accessor": "example-accessor",
                                 "secret_id_num_uses": estate.uses}}

        return Client()


@pytest.fixture
def vault(monkeypatch: pytest.MonkeyPatch) -> Vault:
    estate = Vault()
    monkeypatch.setitem(sys.modules, "hvac", SimpleNamespace(
        Client=estate.client,
        exceptions=SimpleNamespace(InvalidRequest=InvalidRequest, Forbidden=InvalidRequest),
    ))
    # These must never override explicitly supplied planes or activate k8s auth.
    monkeypatch.setenv("VAULT_TOKEN", "canary-ambient-token")
    monkeypatch.setenv("VAULT_ADDR", "https://wrong.example.invalid")
    monkeypatch.setenv("VAULT_K8S_ROLE", "wrong-role")
    return estate


def plane(tmp_path: Path, name: str = "one", *, file: bool = False,
          secret: str = OLD, stamp: datetime | None = None) -> Path:
    path = tmp_path / f"{name}.env"
    delivery = f"VAULT_SECRET_ID='{secret}'  # keep this\r\n"
    if file:
        target = tmp_path / f"{name}.secret"
        target.write_bytes((secret + "\r\n").encode())
        target.chmod(0o600)
        delivery = f'VAULT_SECRET_ID_FILE="{target}"\r\n'
        if stamp:
            Path(str(target) + ".rotated").write_bytes(
                rotation._MARKER + stamp.strftime("%Y-%m-%dT%H:%M:%SZ").encode()
                + b" " + rotation._digest(secret) + b"\n"
            )
    elif stamp:
        delivery = (rotation._MARKER.decode() + stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
                    + "\r\n" + delivery)
    path.write_bytes(("# preserve\r\nVAULT_ADDR=https://vault.example.invalid\r\n"
                      "export VAULT_ROLE_ID=example-role-id\r\n" + delivery
                      + "OTHER=unchanged\r\n").encode())
    path.chmod(0o600)
    return path


def call(paths: list[Path], *, apply: bool = False, age: str = "7d") -> int:
    args = ["rotate-secret-id", "--min-age", age]
    for path in paths:
        args.extend(["--plane", str(path)])
    return main(args + (["--apply"] if apply else []))


def test_dry_run(vault: Vault, tmp_path: Path, capsys: Any) -> None:
    paths = [plane(tmp_path), plane(tmp_path, "two", file=True)]
    before = {p: p.read_bytes() for p in tmp_path.iterdir()}
    assert call(paths) == 0
    out = capsys.readouterr().out
    assert "due" in out and "role=example-agent" in out and "mint=true,destroy=true" in out
    assert "mint" not in vault.events and "destroy" not in vault.events
    assert vault.events[-1] == "revoke-old"
    assert before == {p: p.read_bytes() for p in tmp_path.iterdir()}
    assert OLD not in out and NEW not in out


@pytest.mark.parametrize("file", [False, True])
@pytest.mark.parametrize("apply", [False, True])
def test_not_due(vault: Vault, tmp_path: Path, capsys: Any, file: bool, apply: bool) -> None:
    p = plane(tmp_path, file=file, stamp=datetime.now(UTC))
    before = p.read_bytes()
    assert call([p], apply=apply) == 0
    assert "not due" in capsys.readouterr().out
    assert "mint" not in vault.events and p.read_bytes() == before
    assert vault.events[-1] == "revoke-old"


@pytest.mark.parametrize("file", [False, True])
def test_happy_order_and_preservation(
    vault: Vault, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, file: bool,
) -> None:
    paths = [plane(tmp_path, file=file), plane(tmp_path, "two")]
    original = paths[0].read_bytes()
    mode = stat.S_IMODE(paths[0].stat().st_mode)
    write = rotation._atomic_write

    def record(path: Path, content: bytes, mode: int) -> None:
        vault.events.append("write")
        write(path, content, mode)

    monkeypatch.setattr(rotation, "_atomic_write", record)
    assert call(paths, apply=True) == 0
    assert "rotated" in capsys.readouterr().out
    assert vault.events.index("mint") < vault.events.index("verify") < vault.events.index("write")
    last_write = max(i for i, e in enumerate(vault.events) if e == "write")
    assert last_write < vault.events.index("destroy")
    assert vault.events[-2:] == ["revoke-old", "revoke-new"]
    assert vault.destroyed == [OLD]
    for p in rotation._planes(paths):
        assert p.secret == NEW and p.stamp is not None
        assert stat.S_IMODE(p.target.stat().st_mode) == mode
        assert b"\r\n" in p.content and b"\n" not in p.content.replace(b"\r\n", b"")
    if file:
        assert paths[0].read_bytes() == original
    else:
        filtered = b"".join(line for line in paths[0].read_bytes().splitlines(keepends=True)
                            if not line.startswith(rotation._MARKER))
        assert filtered == original.replace(OLD.encode(), NEW.encode())
    log = Path(os.environ["ACB_STATE_DIR"]) / "provenance.jsonl"
    event = json.loads(log.read_text().splitlines()[-1])
    assert event["action"] == "rotate_secret_id" and event["result"] == "applied"
    assert OLD not in log.read_text() and NEW not in log.read_text()


@pytest.mark.parametrize("failure", ["mint", "verify", "lookup", "destroy", "revoke"])
def test_failures(vault: Vault, tmp_path: Path, capsys: Any, failure: str) -> None:
    p = plane(tmp_path)
    before = p.read_bytes()
    vault.fail = failure
    assert call([p], apply=True) == (0 if failure == "revoke" else 1)
    output = capsys.readouterr()
    assert NEW not in output.out + output.err and OLD not in output.out + output.err
    if failure in {"mint", "verify", "lookup"}:
        assert p.read_bytes() == before and vault.destroyed == []
    if failure in {"destroy", "revoke"}:
        assert rotation._planes([p])[0].secret == NEW
        assert vault.events[-2:] == ["revoke-old", "revoke-new"]


@pytest.mark.parametrize("key", ["VAULT_ADDR", "VAULT_ROLE_ID", "VAULT_APPROLE_MOUNT_POINT"])
def test_identity_mismatch(vault: Vault, tmp_path: Path, capsys: Any, key: str) -> None:
    one, two = plane(tmp_path), plane(tmp_path, "two")
    raw = two.read_bytes()
    old = {"VAULT_ADDR": b"https://vault.example.invalid",
           "VAULT_ROLE_ID": b"example-role-id"}.get(key)
    two.write_bytes(raw.replace(old, b"different") if old else (
        raw + f"{key}=different\r\n".encode()
    ))
    assert call([one, two], apply=True) == 2
    output = capsys.readouterr().err
    assert str(two) in output or repr(str(two)) in output
    assert vault.events == []


def test_unexplained_secret_mismatch(vault: Vault, tmp_path: Path, capsys: Any) -> None:
    vault.valid.add(NEW)
    paths = [plane(tmp_path), plane(tmp_path, "two", secret=NEW)]
    assert call(paths, apply=True) == 2
    assert "mismatch" in capsys.readouterr().err
    assert "mint" not in vault.events and "destroy" not in vault.events
    assert vault.events[-2:] == ["revoke-old", "revoke-new"]


@pytest.mark.parametrize("file", [False, True])
@pytest.mark.parametrize("old_works", [False, True])
def test_partial_failure_and_recovery(
    vault: Vault, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any,
    file: bool, old_works: bool,
) -> None:
    paths = [plane(tmp_path, file=file), plane(tmp_path, "two", file=file)]
    last_target = rotation._planes(paths)[1].target
    write = rotation._atomic_write

    def fail_second(path: Path, content: bytes, mode: int) -> None:
        if path == last_target:
            raise OSError(NEW)
        write(path, content, mode)

    monkeypatch.setattr(rotation, "_atomic_write", fail_second)
    assert call(paths, apply=True) == 1
    err = capsys.readouterr().err
    assert "new=[" in err and "old=[" in err
    assert repr(str(paths[0])) in err and repr(str(paths[1])) in err
    assert NEW not in err and OLD not in err
    assert "destroy" not in vault.events
    assert [p.secret for p in rotation._planes(paths)] == [NEW, OLD]
    assert rotation._planes(paths)[1].stamp is None  # staged metadata is not a rotation
    if not old_works:
        vault.valid.discard(OLD)
    vault.events.clear()
    monkeypatch.setattr(rotation, "_atomic_write", write)
    assert call(list(reversed(paths)), apply=True) == 0
    assert "recovered" in capsys.readouterr().out
    assert "mint" not in vault.events
    assert [p.secret for p in rotation._planes(paths)] == [NEW, NEW]
    assert vault.destroyed == [OLD]


def test_grants_and_age_boundary(vault: Vault, tmp_path: Path) -> None:
    p = plane(tmp_path, stamp=NOW - timedelta(days=7))
    vault.granted = False
    code, _ = rotation._rotate(rotation._planes([p]), True, timedelta(days=7), NOW)
    assert code == 1 and "mint" not in vault.events
    vault.granted = True
    code, _ = rotation._rotate(rotation._planes([p]), True, timedelta(days=7), NOW)
    assert code == 0 and "mint" in vault.events


@pytest.mark.parametrize("value", ["-1d", "x", "7", "1.5d", "9" * 100 + "d"])
def test_bad_duration(tmp_path: Path, value: str) -> None:
    assert call([plane(tmp_path)], age=value) == 2


def test_shared_file_and_no_final_newline(vault: Vault, tmp_path: Path) -> None:
    p = plane(tmp_path, file=True)
    two = tmp_path / "two.env"
    two.write_bytes(p.read_bytes())
    assert call([p, two], apply=True) == 0
    assert vault.events.count("mint") == 1
    assert all(p.secret == NEW for p in rotation._planes([p, two]))


def test_inline_bom_and_missing_final_newline(vault: Vault, tmp_path: Path) -> None:
    p = plane(tmp_path)
    raw = b"\xef\xbb\xbf" + p.read_bytes().replace(b"\r\n", b"\n").rstrip(b"\n")
    p.write_bytes(raw)
    assert call([p], apply=True) == 0
    filtered = b"".join(line for line in p.read_bytes().splitlines(keepends=True)
                        if not line.startswith(rotation._MARKER))
    assert filtered == raw.replace(OLD.encode(), NEW.encode())


def test_bom_on_first_secret_line_has_recoverable_timestamp(vault: Vault, tmp_path: Path) -> None:
    p = plane(tmp_path)
    lines = p.read_bytes().splitlines(keepends=True)
    raw = b"\xef\xbb\xbf" + lines[3] + b"".join(lines[:3] + lines[4:])
    p.write_bytes(raw)
    assert call([p], apply=True) == 0
    state = rotation._planes([p])[0]
    assert state.stamp is not None and state.secret == NEW
    assert p.read_bytes().startswith(b"\xef\xbb\xbf" + rotation._MARKER)


def test_unsupported_inline_syntax_refused_before_login(vault: Vault, tmp_path: Path) -> None:
    p = plane(tmp_path)
    p.write_bytes(p.read_bytes().replace(b"VAULT_SECRET_ID=", "\u00a0VAULT_SECRET_ID=".encode()))
    before = p.read_bytes()
    assert call([p], apply=True) == 2
    assert p.read_bytes() == before and vault.events == []


def test_readback_required_before_destroy(
    vault: Vault, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = plane(tmp_path)
    monkeypatch.setattr(rotation, "_write_planes", lambda *args: None)
    assert call([p], apply=True) == 1
    assert "destroy" not in vault.events


def test_permission_copy_failure_never_writes_secret(
    vault: Vault, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    p = plane(tmp_path)
    before = p.read_bytes()

    def fail(source: Path, target: Path, mode: int) -> None:
        assert target.read_bytes() == b""
        raise OSError(NEW)

    monkeypatch.setattr(rotation, "_copy_permissions", fail)
    assert call([p], apply=True) == 1
    assert p.read_bytes() == before and "destroy" not in vault.events
    assert not list(tmp_path.glob(".acb-rotation-*"))


def test_recovery_transport_error_is_not_invalid_credential(vault: Vault, tmp_path: Path) -> None:
    paths = [plane(tmp_path), plane(tmp_path, "two", secret=NEW, stamp=NOW)]
    vault.valid.add(NEW)
    vault.fail = "timeout"
    before = [p.read_bytes() for p in paths]
    assert call(paths, apply=True) == 1
    assert [p.read_bytes() for p in paths] == before
    assert "mint" not in vault.events and "destroy" not in vault.events


@pytest.mark.parametrize("uses", [1, 2, None, True])
def test_finite_or_unknown_use_secretid_refused(
    vault: Vault, tmp_path: Path, uses: Any,
) -> None:
    p = plane(tmp_path)
    vault.uses = uses
    before = p.read_bytes()
    assert call([p], apply=True) == 1
    assert p.read_bytes() == before and "verify" not in vault.events
    assert "destroy" not in vault.events


def test_dotted_role_name(vault: Vault, tmp_path: Path) -> None:
    vault.role = "example.agent"
    assert call([plane(tmp_path)], apply=True) == 0


def test_lock_conflict(vault: Vault, tmp_path: Path) -> None:
    p = plane(tmp_path)
    lock = Path(str(p) + ".acb-rotation.lock")
    lock.write_bytes(b"")
    assert call([p], apply=True) == 1
    assert vault.events == [] and lock.exists()


def test_unexpected_delivery_value_reported_unknown(vault: Vault, tmp_path: Path) -> None:
    p = plane(tmp_path)
    states = rotation._planes([p])
    p.write_bytes(p.read_bytes().replace(OLD.encode(), b"unexpected-synthetic-value"))
    assert rotation._locations(states, NEW) == (
        f"new=[] old=[] unknown=[{repr(str(p))}]"
    )


def test_undated_sole_working_recovery_mints_instead_of_claiming_fresh_age(
    vault: Vault, tmp_path: Path,
) -> None:
    paths = [plane(tmp_path), plane(tmp_path, "two", secret="canary-invalid")]
    assert call(paths, apply=True) == 0
    assert "mint" in vault.events
    assert all(p.secret == NEW and p.stamp is not None for p in rotation._planes(paths))
    assert set(vault.destroyed) == {OLD, "canary-invalid"}


def test_interrupted_undated_recovery_handles_three_values(
    vault: Vault, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # First interruption leaves two values without usable timestamps.
    paths = [plane(tmp_path), plane(tmp_path, "two"),
             plane(tmp_path, "three", secret="canary-invalid")]
    write = rotation._atomic_write

    def second_interruption(path: Path, content: bytes, mode: int) -> None:
        if path == paths[1]:
            raise OSError(NEW)
        write(path, content, mode)

    monkeypatch.setattr(rotation, "_atomic_write", second_interruption)
    assert call(paths, apply=True) == 1
    assert [p.secret for p in rotation._planes(paths)] == [NEW, OLD, "canary-invalid"]
    assert vault.destroyed == []
    vault.events.clear()
    monkeypatch.setattr(rotation, "_atomic_write", write)
    assert call(list(reversed(paths)), apply=True) == 0
    assert "mint" not in vault.events
    assert all(p.secret == NEW for p in rotation._planes(paths))
    assert set(vault.destroyed) == {OLD, "canary-invalid"}


def test_recovery_requires_unique_newest_of_many_live_values(vault: Vault, tmp_path: Path) -> None:
    vault.valid.update({NEW, "canary-middle"})
    paths = [plane(tmp_path, secret=OLD, stamp=NOW - timedelta(days=2)),
             plane(tmp_path, "two", secret="canary-middle", stamp=NOW - timedelta(days=1)),
             plane(tmp_path, "three", secret=NEW, stamp=NOW)]
    assert call(paths, apply=True) == 0
    assert "mint" not in vault.events
    assert all(p.secret == NEW for p in rotation._planes(paths))
    assert set(vault.destroyed) == {OLD, "canary-middle"}


@pytest.mark.skipif(sys.platform != "win32", reason="Windows security descriptor contract")
def test_windows_replacement_preserves_protected_dacl(vault: Vault, tmp_path: Path) -> None:
    import ctypes
    from ctypes import wintypes

    api = ctypes.WinDLL("advapi32", use_last_error=True)
    convert = api.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID),
                        ctypes.POINTER(wintypes.DWORD)]
    convert.restype = wintypes.BOOL
    set_security = api.SetFileSecurityW
    set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID]
    set_security.restype = wintypes.BOOL
    get = api.GetFileSecurityW
    get.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID,
                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    get.restype = wintypes.BOOL
    p = plane(tmp_path)
    descriptor = wintypes.LPVOID()
    # Protected owner-only DACL differs from the temp directory's inherited ACL.
    assert convert("D:P(A;;FA;;;OW)", 1, ctypes.byref(descriptor), None)
    try:
        assert set_security(str(p), 4 | 0x80000000, descriptor)
    finally:
        free = ctypes.WinDLL("kernel32").LocalFree
        free.argtypes = [wintypes.LPVOID]
        free.restype = wintypes.LPVOID
        free(descriptor)

    def permissions() -> bytes:
        size = wintypes.DWORD()
        get(str(p), 4, None, 0, ctypes.byref(size))
        result = ctypes.create_string_buffer(size.value)
        assert get(str(p), 4, result, size, ctypes.byref(size))
        return result.raw

    before = permissions()
    assert call([p], apply=True) == 0
    assert permissions() == before


@pytest.mark.skipif(sys.platform != "linux", reason="Linux POSIX access ACL contract")
def test_linux_replacement_preserves_access_acl(vault: Vault, tmp_path: Path) -> None:
    import struct

    p = plane(tmp_path)
    # Linux POSIX ACL xattr v2: user_obj, named user, group_obj, mask, other.
    entries = [
        (1, 6, 0xFFFFFFFF), (2, 4, 12345), (4, 0, 0xFFFFFFFF),
        (16, 4, 0xFFFFFFFF), (32, 0, 0xFFFFFFFF),
    ]
    acl = struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, perm, uid) for tag, perm, uid in entries
    )
    try:
        os.setxattr(p, "system.posix_acl_access", acl)
    except OSError as exc:
        if exc.errno in {95, 38}:  # filesystem/kernel does not implement ACLs
            pytest.skip("test filesystem does not support POSIX access ACLs")
        raise
    before = p.stat()
    assert call([p], apply=True) == 0
    assert os.getxattr(p, "system.posix_acl_access") == acl
    after = p.stat()
    assert (after.st_mode, after.st_uid, after.st_gid) == (
        before.st_mode, before.st_uid, before.st_gid
    )


def test_stale_lock_is_removed(vault: Vault, tmp_path: Path) -> None:
    """A lock left by a killed run must not block the schedule for ever."""
    p = plane(tmp_path)
    lock = Path(str(p) + ".acb-rotation.lock")
    lock.write_bytes(b"")
    old = datetime.now(UTC).timestamp() - rotation._STALE_LOCK_SECONDS - 60
    os.utime(lock, (old, old))
    assert rotation.run([p], apply=True) == 0
    assert vault.destroyed == [OLD] and not lock.exists()
