"""WI-006: multi-field resolve + AppRole `.env` fallback (cred_vault backend).

AD binds need username+password from one secret; the resolve path must return
exactly the requested fields so `exec` injects the pair. The `.env` fallback
lets each harness authenticate via its own AppRole file (per-harness role
separation) without putting role_id/secret_id in the shell env.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

pytest.importorskip("hvac", reason="needs the [cred] extra")

import hvac  # noqa: E402 (gated by importorskip above)

from agent_capability_broker import cred_vault  # noqa: E402
from agent_capability_broker.model import Capability  # noqa: E402

AD_CAP = Capability(
    "cred:svc-da", "cred", ("opencode",),
    {"vault": "kv/homelab/ad/svc-da", "fields": ["username", "upn", "password"]},
)
LDAP_CAP = Capability(
    "cred:ldap-bind", "cred", ("opencode",),
    {"vault": "kv/cert-watch/ldap/bind", "fields": ["bind_dn", "password"]},
)
SINGLE_CAP = Capability(
    "cred:single", "cred", ("opencode",),
    {"vault": "kv/x/y", "field": "password"},
)
NO_FIELD_CAP = Capability(
    "cred:no-fields", "cred", ("opencode",),
    {"vault": "kv/x/y"},
)


def _mock_client(data: dict[str, str]) -> MagicMock:
    """A fake hvac client whose KV v2 read returns `data`."""
    client = MagicMock()
    client.is_authenticated.return_value = True
    client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": data}}
    return client


def _patch_vault(monkeypatch: pytest.MonkeyPatch, client: MagicMock) -> None:
    monkeypatch.setattr(cred_vault, "_vault_env", lambda: {"VAULT_ADDR": "https://v"})
    monkeypatch.setattr(hvac, "Client", lambda **kw: client)


# --- field selection (fail-closed) -----------------------------------------

def test_resolve_explicit_fields_list(monkeypatch: pytest.MonkeyPatch) -> None:
    data = {"bind_dn": "CN=bind,DC=lab", "password": "hunter2", "extra": "x"}
    client = _mock_client(data)
    _patch_vault(monkeypatch, client)

    out = cred_vault.resolve(LDAP_CAP)
    assert set(out.keys()) == {"bind_dn", "password"}
    assert out["bind_dn"] == "CN=bind,DC=lab"


def test_resolve_single_field(monkeypatch: pytest.MonkeyPatch) -> None:
    data = {"password": "hunter2", "username": "u"}
    client = _mock_client(data)
    _patch_vault(monkeypatch, client)

    out = cred_vault.resolve(SINGLE_CAP)
    assert out == {"password": "hunter2"}


def test_resolve_multi_field(monkeypatch: pytest.MonkeyPatch) -> None:
    data = {"username": "svc-da", "upn": "svc-da@lab", "password": "hunter2"}
    client = _mock_client(data)
    _patch_vault(monkeypatch, client)

    out = cred_vault.resolve(AD_CAP)
    assert out == {"username": "svc-da", "upn": "svc-da@lab", "password": "hunter2"}


def test_resolve_requires_field_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail-closed: no field/fields => RuntimeError, never silent all-fields."""
    client = _mock_client({"password": "p", "username": "u"})
    _patch_vault(monkeypatch, client)
    with pytest.raises(RuntimeError, match="field selection required"):
        cred_vault.resolve(NO_FIELD_CAP)


def test_resolve_rejects_non_list_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _mock_client({"password": "p"})
    _patch_vault(monkeypatch, client)
    cap = Capability("cred:x", "cred", ("opencode",),
                     {"vault": "kv/x/y", "fields": "password"})
    with pytest.raises(RuntimeError, match="options.fields must be a list"):
        cred_vault.resolve(cap)


def test_resolve_missing_field_raises_without_leaking_other_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The missing-fields error must not list the secret's other field names."""
    data = {"username": "u", "password": "p", "admin_token": "tok-xyz"}
    client = _mock_client(data)
    _patch_vault(monkeypatch, client)
    cap = Capability("cred:x", "cred", ("opencode",),
                     {"vault": "kv/x/y", "fields": ["username", "missing"]})
    with pytest.raises(RuntimeError) as exc_info:
        cred_vault.resolve(cap)
    msg = str(exc_info.value)
    assert "missing" in msg
    assert "admin_token" not in msg  # never advertise the secret's other fields
    assert "available" not in msg.lower()


def test_resolve_rejects_non_string_field_values(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _mock_client({"port": 5432, "password": "p"})  # port is an int in Vault
    _patch_vault(monkeypatch, client)
    cap = Capability("cred:x", "cred", ("opencode",),
                     {"vault": "kv/x/y", "fields": ["port", "password"]})
    with pytest.raises(RuntimeError, match="field 'port'.*not str"):
        cred_vault.resolve(cap)


def test_resolve_wraps_hvac_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    """An hvac failure surfaces as a RuntimeError (caught by the CLI), not a raw
    hvac exception that bypasses the handler and prints a traceback."""
    client = MagicMock()
    client.secrets.kv.v2.read_secret_version.side_effect = hvac.exceptions.Forbidden("denied")
    _patch_vault(monkeypatch, client)
    with pytest.raises(RuntimeError, match="vault read failed"):
        cred_vault.resolve(AD_CAP)


def test_resolve_error_does_not_leak_secret_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No error path — missing fields, type errors, hvac failures — may echo a
    resolved secret value."""
    secret_val = "super-secret-do-not-leak-9f3a"
    client = _mock_client({"password": secret_val, "username": "u"})
    _patch_vault(monkeypatch, client)
    cap = Capability("cred:x", "cred", ("opencode",),
                     {"vault": "kv/x/y", "fields": ["missing"]})
    with pytest.raises(RuntimeError) as exc_info:
        cred_vault.resolve(cap)
    assert secret_val not in str(exc_info.value)


# --- AppRole .env fallback -------------------------------------------------

def test_env_file_loaded_as_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "vault.env"
    env_file.write_text(
        'VAULT_ADDR="https://vault.example"\n'
        "VAULT_ROLE_ID=role-123\n"
        "VAULT_SECRET_ID='secret-456'\n"
        "# a comment\n"
        "\n"
        "IGNORED=1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_VAULT_ENV", str(env_file))
    for k in ("VAULT_ADDR", "VAULT_ROLE_ID", "VAULT_SECRET_ID"):
        monkeypatch.delenv(k, raising=False)

    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://vault.example"
    assert env["VAULT_ROLE_ID"] == "role-123"
    assert env["VAULT_SECRET_ID"] == "secret-456"
    assert "IGNORED" not in env


def test_env_file_handles_export_prefix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "vault.env"
    env_file.write_text(
        "export VAULT_ROLE_ID=role-999\n"
        "export VAULT_SECRET_ID=secret-888\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_VAULT_ENV", str(env_file))
    for k in ("VAULT_ROLE_ID", "VAULT_SECRET_ID"):
        monkeypatch.delenv(k, raising=False)
    env = cred_vault._vault_env()
    assert env["VAULT_ROLE_ID"] == "role-999"
    assert env["VAULT_SECRET_ID"] == "secret-888"


def test_env_file_strips_inline_comments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LOW-3: inline comments after values must be stripped."""
    env_file = tmp_path / "vault.env"
    env_file.write_text(
        "VAULT_ADDR=https://vault.example # production vault\n"
        "VAULT_TOKEN=tok-123 # rotated weekly\n"
        "VAULT_ROLE_ID=role-456\t# tab-separated comment\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_VAULT_ENV", str(env_file))
    for k in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_ROLE_ID"):
        monkeypatch.delenv(k, raising=False)
    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://vault.example"
    assert env["VAULT_TOKEN"] == "tok-123"
    assert env["VAULT_ROLE_ID"] == "role-456"


def test_env_file_preserves_hash_in_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A # inside a value (not preceded by whitespace) is preserved."""
    env_file = tmp_path / "vault.env"
    env_file.write_text(
        'VAULT_ADDR="https://vault.example/path#fragment"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_VAULT_ENV", str(env_file))
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://vault.example/path#fragment"


def test_env_file_strips_comment_after_quoted_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Inline comments after a quoted value are stripped, but the # inside the
    quoted value is preserved (HIGH-2 from adversarial review)."""
    env_file = tmp_path / "vault.env"
    env_file.write_text(
        'VAULT_TOKEN="abc # def" # real comment\n'
        'VAULT_ADDR="https://vault.example" # prod\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_VAULT_ENV", str(env_file))
    for k in ("VAULT_TOKEN", "VAULT_ADDR"):
        monkeypatch.delenv(k, raising=False)
    env = cred_vault._vault_env()
    assert env["VAULT_TOKEN"] == "abc # def"  # # inside quotes preserved
    assert env["VAULT_ADDR"] == "https://vault.example"  # comment stripped


def test_env_file_handles_bom(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "vault.env"
    env_file.write_bytes("\ufeffVAULT_ADDR=https://from-bom\n".encode("utf-8"))
    monkeypatch.setenv("ACB_VAULT_ENV", str(env_file))
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    assert cred_vault._vault_env()["VAULT_ADDR"] == "https://from-bom"


def test_process_env_overrides_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / "vault.env"
    env_file.write_text("VAULT_ADDR=https://from-file\nVAULT_TOKEN=file-tok\n", encoding="utf-8")
    monkeypatch.setenv("ACB_VAULT_ENV", str(env_file))
    monkeypatch.setenv("VAULT_ADDR", "https://from-process")
    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://from-process"
    assert env["VAULT_TOKEN"] == "file-tok"


def test_no_env_file_is_empty_not_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ACB_VAULT_ENV", "/nonexistent/path.env")
    for k in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_ROLE_ID", "VAULT_SECRET_ID"):
        monkeypatch.delenv(k, raising=False)
    assert cred_vault._vault_env() == {}


def test_env_file_non_utf8_raises_with_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / "vault.env"
    env_file.write_bytes(b"VAULT_ADDR=\xff\xfe garbage")
    monkeypatch.setenv("ACB_VAULT_ENV", str(env_file))
    with pytest.raises(RuntimeError, match="not valid UTF-8"):
        cred_vault._load_env_file()


# --- per-plane probing: file is authoritative when env_path is explicit --------
# MEDIUM-1 fix (adversarial review): when _vault_env is called with an explicit
# env_path (per-plane probing, WI-008), the file must be authoritative — process
# env must NOT override it, or all planes probe through one shell credential set.


def test_vault_env_explicit_path_not_overridden_by_process_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When env_path is explicit, the file is authoritative — process env wins
    only for keys NOT in the file."""
    plane_env = tmp_path / "cert-watch.env"
    plane_env.write_text("VAULT_ADDR=https://per-plane\n", encoding="utf-8")
    monkeypatch.setenv("VAULT_ADDR", "https://from-shell")

    env = cred_vault._vault_env(plane_env)
    assert env["VAULT_ADDR"] == "https://per-plane"  # file wins, not shell


def test_vault_env_no_env_path_still_merges_process_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without env_path (the resolve/exec path), process env still overrides."""
    env_file = tmp_path / "vault.env"
    env_file.write_text("VAULT_ADDR=https://from-file\n", encoding="utf-8")
    monkeypatch.setenv("ACB_VAULT_ENV", str(env_file))
    monkeypatch.setenv("VAULT_ADDR", "https://from-process")

    env = cred_vault._vault_env()
    assert env["VAULT_ADDR"] == "https://from-process"  # process wins
