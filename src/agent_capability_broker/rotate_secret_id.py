"""Self-service AppRole SecretID rotation. No ambient credentials or secret state.

Inline planes carry a timestamp comment. File deliveries carry a sibling
``.rotated`` timestamp bound to the SecretID's SHA-256 digest. Writing that
metadata *before* the secret makes every interrupted replacement recoverable.
Only the explicitly supplied planes and their declared credential files are read.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import sys
import tempfile
import time
from collections.abc import Iterable, Iterator
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from . import provenance
from .model import Action, ActionResult

_MARKER = b"# acb: secret-id rotated "
_ASSIGN = re.compile(rb"^(?:\xef\xbb\xbf)?[ \t]*(?:export[ \t]+)?(VAULT\w+)[ \t]*=[ \t]*")
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+")
_ROLE_SEGMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
_STALE_LOCK_SECONDS = 3600


class RotationRefusal(Exception):
    """Unusable or ambiguous plane set (exit 2). Messages contain paths only."""


@dataclass(repr=False)
class Plane:
    path: Path
    raw: bytes
    env: dict[str, str] = field(repr=False)
    role_id: str = field(repr=False)
    secret: str = field(repr=False)
    mount: str
    target: Path
    content: bytes = field(repr=False)
    stamp: datetime | None


def duration(value: str) -> timedelta:
    """A non-negative integer followed by s, m, h or d."""
    match = re.fullmatch(r"(\d+)([smhd])", value)
    if match is None:
        raise RotationRefusal("--min-age requires an integer followed by s, m, h or d")
    try:
        return timedelta(seconds=int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[
            match[2]
        ])
    except OverflowError as exc:
        raise RotationRefusal("--min-age is too large") from exc


def _read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise RotationRefusal(f"expected a regular, non-symlink file: {str(path)!r}")
    return path.read_bytes()


def _stamp(raw: bytes, secret: str, *, bound: bool) -> datetime | None:
    stamps = []
    for line in raw.removeprefix(b"\xef\xbb\xbf").splitlines():
        if not line.startswith(_MARKER):
            continue
        parts = line[len(_MARKER):].split()
        if bound and (len(parts) != 2 or parts[1] != _digest(secret)):
            continue
        try:
            stamps.append(datetime.strptime(parts[0].decode("ascii"), "%Y-%m-%dT%H:%M:%SZ")
                          .replace(tzinfo=UTC))
        except (ValueError, IndexError, UnicodeError):
            continue
    return min(stamps) if stamps else None


def _digest(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest().encode("ascii")


def _planes(paths: list[Path]) -> list[Plane]:
    from . import cred_vault

    planes = []
    for path in dict.fromkeys(p.absolute() for p in paths):
        try:
            raw = _read(path)
            env = cred_vault._parse_env_text(raw.decode("utf-8-sig"))
            keys = [m[1] for line in raw.splitlines() if (m := _ASSIGN.match(line))]
            if len(keys) != len(set(keys)):
                raise RotationRefusal(f"duplicate Vault assignment in {str(path)!r}")
            # Resolve *_FILE exactly as cred_vault does (relative to cwd).
            material = cred_vault._approle_material(env)
            if not env.get("VAULT_ADDR") or material is None:
                raise RotationRefusal(f"missing AppRole configuration in {str(path)!r}")
            role_id, secret, mount = material
            if not all(_ROLE_SEGMENT.fullmatch(part) for part in mount.split("/")):
                raise RotationRefusal(f"invalid AppRole mount in {str(path)!r}")
            target = Path(env["VAULT_SECRET_ID_FILE"]).absolute() if env.get(
                "VAULT_SECRET_ID_FILE"
            ) else path
            content = _read(target) if target != path else raw
            metadata = Path(str(target) + ".rotated")
            stamp_raw = _read(metadata) if target != path and metadata.exists() else raw
            planes.append(Plane(path, raw, env, role_id, secret, mount, target, content,
                                _stamp(stamp_raw, secret, bound=target != path)))
            if target == path:
                # The reader deliberately accepts more dotenv syntax than our
                # byte-preserving writer. Refuse anything we cannot round-trip
                # BEFORE a mint or file change (e.g. Unicode whitespace).
                probe = _inline(raw, "acb-format-probe", datetime.now(UTC))
                if cred_vault._parse_env_text(probe.decode("utf-8-sig")).get(
                    "VAULT_SECRET_ID"
                ) != "acb-format-probe":
                    raise RotationRefusal(f"unsupported SecretID syntax in {str(path)!r}")
        except RotationRefusal:
            raise
        except Exception as exc:
            raise RotationRefusal(
                f"cannot read plane {str(path)!r} ({type(exc).__name__})"
            ) from exc
    first = planes[0]
    if any((p.env["VAULT_ADDR"], p.role_id, p.mount) != (
        first.env["VAULT_ADDR"], first.role_id, first.mount
    ) for p in planes):
        raise RotationRefusal("identity mismatch: " + _paths(p.path for p in planes))
    # Never overwrite another plane, role-id delivery or metadata with a secret.
    plane_paths = {p.path for p in planes}
    role_paths = {Path(p.env["VAULT_ROLE_ID_FILE"]).absolute() for p in planes
                  if p.env.get("VAULT_ROLE_ID_FILE")}
    targets = {p.target for p in planes}
    metadata_paths = {Path(str(p.target) + ".rotated") for p in planes if p.target != p.path}
    if any(p.target in plane_paths for p in planes if p.target != p.path) or (
        role_paths & (targets | plane_paths | metadata_paths)
        or metadata_paths & (targets | plane_paths)
    ):
        raise RotationRefusal("overlapping credential paths: " + _paths(plane_paths))
    return planes


def _paths(paths: Iterable[Path]) -> str:
    # repr keeps a scheduled-task summary on one physical line, even for odd paths.
    return ",".join(repr(str(p)) for p in paths)


@contextmanager
def _locks(planes: list[Plane]) -> Iterator[None]:
    """Cooperating rotations serialize.

    A lock older than ``_STALE_LOCK_SECONDS`` belongs to a run that was killed:
    a rotation takes seconds. It is removed, because an unattended schedule
    that refused forever would let the SecretID expire.
    """
    with ExitStack() as stack:
        for path in sorted({p.path for p in planes} | {p.target for p in planes}):
            lock = Path(str(path) + ".acb-rotation.lock")
            try:
                if time.time() - lock.stat().st_mtime > _STALE_LOCK_SECONDS:
                    lock.unlink()
            except FileNotFoundError:
                pass
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            stack.callback(lock.unlink)
        yield


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    """Same-directory replacement; mode is set before writing any secret bytes."""
    fd, name = tempfile.mkstemp(prefix=".acb-rotation-", dir=path.parent)
    temp = Path(name)
    try:
        _copy_permissions(path, temp, mode)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        if sys.platform != "win32":
            # Persist .rotated BEFORE its SecretID rename, including power loss.
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if fd != -1:
            os.close(fd)
        if temp.exists():
            # Windows readonly files cannot be unlinked without resetting mode.
            os.chmod(temp, stat.S_IWRITE | stat.S_IREAD)
            temp.unlink()


def _windows_dacl(source: Path, target: Path) -> None:
    """Copy Windows owner/group/DACL, including inheritance protection."""
    if sys.platform != "win32":
        raise RuntimeError("Windows permissions requested on another platform")
    import ctypes
    from ctypes import wintypes

    api = ctypes.WinDLL("advapi32", use_last_error=True)
    get = api.GetFileSecurityW
    get.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID,
                    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    get.restype = wintypes.BOOL
    set_security = api.SetFileSecurityW
    set_security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID]
    set_security.restype = wintypes.BOOL
    control = api.GetSecurityDescriptorControl
    control.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.WORD),
                        ctypes.POINTER(wintypes.DWORD)]
    control.restype = wintypes.BOOL
    size = wintypes.DWORD()
    information = 7  # OWNER | GROUP | DACL_SECURITY_INFORMATION
    get(str(source), information, None, 0, ctypes.byref(size))
    if not size.value:
        raise ctypes.WinError(ctypes.get_last_error())
    descriptor = ctypes.create_string_buffer(size.value)
    if not get(str(source), information, descriptor, size, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    flags, revision = wintypes.WORD(), wintypes.DWORD()
    if not control(descriptor, ctypes.byref(flags), ctypes.byref(revision)):
        raise ctypes.WinError(ctypes.get_last_error())
    # SE_DACL_PROTECTED; preserve either protected or inherited permissions.
    protection = 0x80000000 if flags.value & 0x1000 else 0x20000000
    if not set_security(str(target), information | protection, descriptor):
        raise ctypes.WinError(ctypes.get_last_error())


def _copy_permissions(source: Path, target: Path, mode: int) -> None:
    """Fail closed if an existing delivery's permissions cannot be preserved."""
    if source.exists():
        if sys.platform == "win32":
            _windows_dacl(source, target)
        else:
            info = source.stat()
            os.chown(target, info.st_uid, info.st_gid)
    os.chmod(target, mode)
    if sys.platform == "linux" and source.exists():
        # Linux POSIX access ACLs are extended attributes. Remove an inherited
        # temp-file ACL if the source has none; otherwise copy it exactly.
        acl = "system.posix_acl_access"
        if acl in os.listxattr(source):
            os.setxattr(target, acl, os.getxattr(source, acl))
        elif acl in os.listxattr(target):
            os.removexattr(target, acl)


def _inline(raw: bytes, secret: str, stamp: datetime) -> bytes:
    bom = b"\xef\xbb\xbf" if raw.startswith(b"\xef\xbb\xbf") else b""
    raw = raw[len(bom):]
    lines = raw.splitlines(keepends=True)
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    out = []
    for line in lines:
        if line.startswith(_MARKER):
            continue
        match = _ASSIGN.match(line)
        if match is not None and match[1] == b"VAULT_SECRET_ID":
            value = line[match.end():]
            # Preserve quoting, trailing whitespace, inline comments and EOLs.
            if value[:1] in (b"'", b'"'):
                end = value.find(value[:1], 1)
                if end < 0:
                    raise RotationRefusal("unterminated SecretID quote")
                replacement = value[:1] + secret.encode() + value[end:]
            else:
                old = re.match(rb"[^\r\n]*?(?=[ \t]+#|\r?\n|$)", value)
                assert old is not None
                length = len(old[0].rstrip(b" \t"))
                replacement = secret.encode() + value[length:]
            out.append(_MARKER + stamp.strftime("%Y-%m-%dT%H:%M:%SZ").encode() + newline)
            out.append(line[:match.end()] + replacement)
        else:
            out.append(line)
    return bom + b"".join(out)


def _write_planes(planes: list[Plane], secret: str, stamp: datetime) -> None:
    written: set[Path] = set()
    for p in planes:
        if p.target in written:
            continue
        if _read(p.path) != p.raw or _read(p.target) != p.content:
            raise RuntimeError("file changed during rotation")
        mode = stat.S_IMODE(p.target.stat().st_mode)
        if p.target == p.path:
            content = _inline(p.raw, secret, stamp)
        else:
            # A digest makes metadata harmless if replacement stops between the
            # two atomic writes: an old value cannot inherit the new timestamp.
            metadata = Path(str(p.target) + ".rotated")
            if metadata.is_symlink():
                raise RuntimeError("symlink metadata")
            _atomic_write(metadata, _MARKER + stamp.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ).encode() + b" " + _digest(secret) + b"\n", mode)
            # Preserve the delivery's whitespace/BOM, replacing only its value.
            text = p.content.decode("utf-8-sig")
            start = len(text) - len(text.lstrip())
            end = len(text.rstrip())
            bom = b"\xef\xbb\xbf" if p.content.startswith(b"\xef\xbb\xbf") else b""
            content = bom + (text[:start] + secret + text[end:]).encode("utf-8")
        _atomic_write(p.target, content, mode)
        written.add(p.target)


def _login(p: Plane, secret: str) -> Any:
    from . import cred_vault

    return cred_vault.approle_client({
        "VAULT_ADDR": p.env["VAULT_ADDR"], "VAULT_ROLE_ID": p.role_id,
        "VAULT_SECRET_ID": secret, "VAULT_APPROLE_MOUNT_POINT": p.mount,
    })


def _role(client: Any) -> str:
    role = client.auth.token.lookup_self()["data"]["meta"]["role_name"]
    if not isinstance(role, str) or not _ROLE_SEGMENT.fullmatch(role):
        raise ValueError("invalid role name in token metadata")
    return role


def _select(planes: list[Plane], clients: list[Any]) -> tuple[str, Any, str, datetime | None]:
    """Only accept mixed values with a unique working/newer candidate."""
    from .cred_vault import AppRoleLoginRejected

    secrets = list(dict.fromkeys(p.secret for p in planes))
    candidates = []
    for secret in secrets:
        try:
            client = _login(planes[0], secret)
        except AppRoleLoginRejected:
            if len(secrets) == 1:
                raise
            continue
        clients.append(client)
        role = _role(client)
        stamps = [p.stamp for p in planes if p.secret == secret]
        stamp = min(s for s in stamps if s is not None) if all(stamps) else None
        candidates.append((secret, client, role, stamp))
    if not candidates:
        raise RuntimeError("no working AppRole login")
    if len({c[2] for c in candidates}) != 1:
        raise RotationRefusal("role mismatch: " + _paths(p.path for p in planes))
    if len(candidates) > 1:
        candidates.sort(key=lambda c: c[3] or datetime.min.replace(tzinfo=UTC))
        if candidates[-1][3] is None or candidates[-2][3] == candidates[-1][3]:
            raise RotationRefusal("ambiguous SecretID mismatch: " + _paths(p.path for p in planes))
    return candidates[-1]


def _locations(planes: list[Plane], secret: str) -> str:
    from . import cred_vault

    new: list[Path] = []
    old: list[Path] = []
    unknown: list[Path] = []
    for p in planes:
        try:
            if p.target == p.path:
                value = cred_vault._parse_env_text(_read(p.path).decode("utf-8-sig")).get(
                    "VAULT_SECRET_ID"
                )
            else:
                value = _read(p.target).decode("utf-8-sig").strip()
            if value == secret:
                new.append(p.path)
            elif value == p.secret:
                old.append(p.path)
            else:
                unknown.append(p.path)
        except Exception:
            unknown.append(p.path)
    return f"new=[{_paths(new)}] old=[{_paths(old)}] unknown=[{_paths(unknown)}]"


def _rotate(planes: list[Plane], apply: bool, min_age: timedelta, now: datetime) -> tuple[int, str]:
    from . import cred_vault

    clients: list[Any] = []
    replacement = ""
    try:
        selected, client, role, stamp = _select(planes, clients)
        recovery = len({p.secret for p in planes}) > 1
        due = recovery or stamp is None or now - stamp >= min_age
        prefix = f"role={role} planes=[{_paths(p.path for p in planes)}]"
        if not due and apply:
            return 0, f"{prefix} not due"
        paths = [f"auth/{planes[0].mount}/role/{role}/secret-id"]
        paths.append(paths[0] + "/destroy")
        caps = cred_vault.capabilities_self(paths, client=client)
        grants = ["update" in caps[path] or "root" in caps[path] for path in paths]
        permissions = f"update:mint={str(grants[0]).lower()},destroy={str(grants[1]).lower()}"
        if not due or not apply:
            return 0, f"{prefix} {'due' if due else 'not due'} {permissions} dry-run={not apply}"
        if not all(grants):
            raise PermissionError("rotation grants missing")
        old_secrets = {p.secret for p in planes}
        if recovery:
            replacement = selected
        if not recovery or stamp is None:
            # A sole working value without metadata is old enough, even during
            # recovery. Never give it a fresh timestamp without minting anew.
            reply = client.write_data(paths[0], data={
                "metadata": json.dumps({"rotated_by": "acb", "host": socket.gethostname()}),
            })
            uses = reply["data"].get("secret_id_num_uses")
            if type(uses) is not int or uses != 0:
                raise ValueError("rotation requires unlimited-use SecretIDs")
            selected = reply["data"]["secret_id"]
            if not isinstance(selected, str) or not _SEGMENT.fullmatch(selected):
                raise ValueError("invalid SecretID response")
            if selected in old_secrets:
                raise ValueError("mint did not return a new SecretID")
            replacement = selected
            client = _login(planes[0], selected)
            clients.append(client)
            if _role(client) != role:
                raise ValueError("verification role mismatch")
            stamp = now
        try:
            _write_planes(planes, selected, stamp or now)
            if any(p.secret != selected for p in _planes([p.path for p in planes])):
                raise RuntimeError("delivery readback did not match replacement")
        except RotationRefusal as exc:
            raise RuntimeError("delivery update failed") from exc
        for old in old_secrets - {selected}:
            client.write_data(paths[1], data={"secret_id": old})
        return 0, f"{prefix} {'recovered' if recovery else 'rotated'}"
    except RotationRefusal as exc:
        return 2, str(exc)
    except Exception as exc:
        locations = _locations(planes, replacement) if replacement else (
            f"planes=[{_paths(p.path for p in planes)}] unchanged"
        )
        return 1, f"rotation failed ({type(exc).__name__}) {locations}"
    finally:
        for client in clients:
            cred_vault.revoke_self(client)


def run(paths: list[Path], *, min_age: str = "7d", apply: bool = False) -> int:
    """One secret-free scheduled-task summary. Dry runs never write files."""
    try:
        age = duration(min_age)
        planes = _planes(paths)
        with _locks(planes) if apply else nullcontext():
            # Read again under the locks; never act on a stale snapshot.
            current = _planes(paths) if apply else planes
            if {p.target for p in current} != {p.target for p in planes}:
                raise RotationRefusal("plane delivery changed while acquiring locks")
            code, summary = _rotate(current, apply, age, datetime.now(UTC).replace(microsecond=0))
    except RotationRefusal as exc:
        code, summary = 2, str(exc)
    except Exception as exc:
        code, summary = 1, f"rotation failed ({type(exc).__name__}) planes=[{_paths(paths)}]"
    if apply:
        action = Action("", "", "rotate_secret_id", _paths(paths), "rotate AppRole SecretID")
        try:
            provenance.emit(ActionResult(action, "applied" if code == 0 else "failed", summary),
                            purpose="rotate-secret-id")
        except Exception as exc:
            summary += f" provenance unavailable ({type(exc).__name__})"
    print(summary, file=sys.stderr if code else sys.stdout)
    return code
