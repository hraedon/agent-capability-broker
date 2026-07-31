"""WI-016: the cred runtime never authenticates with a credential nobody named.

Two properties, and one upstream behaviour they exist to guard against:

* **No ambient credential.** `hvac.Client(url=...)` defaults to `token=None`,
  which makes hvac call `utils.get_token_from_env()` — and that reads
  `$VAULT_TOKEN` *and* `~/.vault-token`. On a host that is supposed to be
  AppRole-only, `reachable()` would then report a capability PRESENT_OK off a
  stray developer token lying in a home directory. WI-015 closed this on the
  admin plane (`onboard._admin_client`); this is the runtime half.
* **Partial AppRole material fails closed.** A RoleID with a missing or
  unreadable SecretID must refuse, not quietly downgrade to whatever token it
  can find. `regista._secrets` (WI-228) refuses identically, so one host cannot
  have two components disagreeing about its posture.

`TestUpstreamHvacBehaviourIsPinned` pins the hvac behaviour itself, so a
dependency bump that changes it turns this guard redundant rather than silently
reopening the trap.

Fixtures never touch the real `$HOME`: the ambient-token tests write
`~/.vault-token` into a *temp* home.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("hvac", reason="needs the [cred] extra")

import hvac  # noqa: E402 (gated by importorskip above)

from agent_capability_broker import cred_vault  # noqa: E402
from agent_capability_broker.model import Capability  # noqa: E402

ADDR = "http://vault.invalid:8200"
CAP = Capability(
    "cred:svc-bot", "cred", ("opencode",),
    {"vault": "kv/example/ad/svc-bot", "field": "password"},
)

# Canaries: if any of these reaches Vault or an error message, a test fails.
DOTFILE_TOKEN = "canary-dotfile-token"
ENV_TOKEN = "canary-env-token"
ROLE_ID = "canary-role-id"
SECRET_ID = "canary-secret-id"


@pytest.fixture(autouse=True)
def isolated_vault_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No `VAULT_*`/config-root leakage from the operator's shell into a test.

    Also pins the k8s token path at a non-existent file so a test host that
    happens to have one cannot silently take the k8s branch.
    """
    for key in list(os.environ):
        if key.startswith(("VAULT", "ACB_VAULT_ENV", "AGENT_SUITE_CONFIG")):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(cred_vault, "_K8S_TOKEN", tmp_path / "no-such-k8s-token")


def _plane(tmp_path: Path, body: str, name: str = "vault.env") -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    p.chmod(0o600)
    return p


def _temp_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A temp `$HOME` holding a `~/.vault-token`. Never the real one."""
    home = tmp_path / "home"
    home.mkdir()
    (home / ".vault-token").write_text(DOTFILE_TOKEN + "\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # expanduser on Windows
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    return home


class _Recorder:
    """A stand-in hvac client that records what it was constructed with.

    Mirrors hvac in the one way that matters here: `self.token` is exactly the
    `token` kwarg, so `_authenticate`'s token branch sees what hvac would see.
    """

    instances: list[_Recorder] = []

    def __init__(self, url: str | None = None, token: str | None = None, **kw: Any) -> None:
        self.url = url
        self.token = token
        self.auth = MagicMock()
        self.logins: list[dict[str, Any]] = []
        self.auth.approle.login.side_effect = lambda **kwargs: self.logins.append(
            {"method": "approle", **kwargs}
        )
        self.auth.kubernetes.login.side_effect = lambda **kwargs: self.logins.append(
            {"method": "kubernetes", **kwargs}
        )
        _Recorder.instances.append(self)

    def is_authenticated(self) -> bool:
        return True


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> type[_Recorder]:
    _Recorder.instances = []
    monkeypatch.setattr(hvac, "Client", _Recorder)
    return _Recorder


# ---------------------------------------------------------------------------
# The defect: an ambient ~/.vault-token must not make a capability reachable
# ---------------------------------------------------------------------------


class TestNoAmbientCredential:
    def test_a_dotfile_token_does_not_make_a_capability_reachable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """THE WI-016 defect, against real hvac. Fails before the fix.

        A plane that declares only `VAULT_ADDR` configures no auth at all. With
        `token=None` hvac would load `~/.vault-token` and `_authenticate` would
        return on `if client.token` — so `reachable()` answered True off a
        credential no operator configured for this capability. `is_authenticated`
        is stubbed True to stand in for the Vault that would have accepted that
        token: the point is that we must never get that far.
        """
        _temp_home(tmp_path, monkeypatch)
        monkeypatch.setattr(hvac.Client, "is_authenticated", lambda self: True)
        plane = _plane(tmp_path, f"VAULT_ADDR={ADDR}\n")

        with pytest.raises(RuntimeError, match="no Vault auth available"):
            cred_vault.reachable(CAP, vault_env=str(plane))

    def test_reachable_constructs_the_client_with_an_empty_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: type[_Recorder]
    ) -> None:
        """`token=""` — not `None` (hvac's env fallback), not a borrowed value."""
        _temp_home(tmp_path, monkeypatch)
        plane = _plane(tmp_path, f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\n"
                                 f"VAULT_SECRET_ID={SECRET_ID}\n")

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        assert recorder.instances[0].token == ""
        assert recorder.instances[0].url == ADDR

    def test_resolve_constructs_the_client_with_an_empty_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: type[_Recorder]
    ) -> None:
        """The read path gets the same treatment as the reachability probe."""
        _temp_home(tmp_path, monkeypatch)
        monkeypatch.setenv("ACB_VAULT_ENV", str(_plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\nVAULT_SECRET_ID={SECRET_ID}\n",
        )))

        def _read(**kw: Any) -> dict[str, Any]:
            return {"data": {"data": {"password": "value-not-asserted"}}}

        _Recorder.instances = []
        client_holder: list[_Recorder] = []

        class _ReadingRecorder(_Recorder):
            def __init__(self, **kw: Any) -> None:
                super().__init__(**kw)
                self.secrets = MagicMock()
                self.secrets.kv.v2.read_secret_version.side_effect = _read
                client_holder.append(self)

        monkeypatch.setattr(hvac, "Client", _ReadingRecorder)
        cred_vault.resolve(CAP)
        assert client_holder[0].token == ""

    def test_an_explicit_vault_token_still_works(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: type[_Recorder]
    ) -> None:
        """Fail-closed is about *ambient* credentials, not declared ones.

        A dev Vault configured with `VAULT_TOKEN` (the documented dev-only path,
        same as regista's) keeps working, and no AppRole login is attempted.
        """
        plane = _plane(tmp_path, f"VAULT_ADDR={ADDR}\nVAULT_TOKEN={ENV_TOKEN}\n")

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        assert recorder.instances[0].token == ENV_TOKEN
        assert recorder.instances[0].logins == []


class TestUpstreamHvacBehaviourIsPinned:
    """Pin what hvac actually does, so the guard cannot become folklore.

    Mirrors `regista/tests/test_wi228_vault_approle.py::TestNoAmbientCredential`.
    If a future hvac stops reading ambient credentials, this test fails and says
    the guard is now redundant rather than wrong.
    """

    def test_token_none_reads_env_and_dotfile_but_empty_string_does_not(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("VAULT_TOKEN", ENV_TOKEN)
        assert hvac.Client(url=ADDR).token == ENV_TOKEN
        assert hvac.Client(url=ADDR, token="").token == ""

        monkeypatch.delenv("VAULT_TOKEN")
        _temp_home(tmp_path, monkeypatch)
        assert hvac.Client(url=ADDR).token == DOTFILE_TOKEN, (
            "hvac no longer reads ~/.vault-token; the token='' guard is now redundant"
        )
        assert hvac.Client(url=ADDR, token="").token == ""


# ---------------------------------------------------------------------------
# Partial AppRole material fails closed
# ---------------------------------------------------------------------------


class TestPartialAppRoleFailsClosed:
    def test_role_id_without_secret_id_refuses(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: type[_Recorder]
    ) -> None:
        """The headline case: a delivered RoleID, an undelivered SecretID.

        A `~/.vault-token` *and* a `$VAULT_TOKEN` are both present, which is
        exactly the situation in which the old fall-through was invisible.
        """
        _temp_home(tmp_path, monkeypatch)
        monkeypatch.setenv("VAULT_TOKEN", ENV_TOKEN)
        plane = _plane(tmp_path, f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\n")

        with pytest.raises(RuntimeError) as exc:
            cred_vault.reachable(CAP, vault_env=str(plane))
        msg = str(exc.value)
        assert "no SecretID" in msg
        assert "VAULT_SECRET_ID_FILE" in msg
        assert "Refusing to fall back to VAULT_TOKEN" in msg
        assert str(plane) in msg, "the refusal must name the file to edit"
        assert recorder.instances[0].logins == [], "no login may be attempted"

    def test_partial_material_does_not_downgrade_to_an_ambient_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Both halves of WI-016 in one shot, against real hvac. Fails before the fix.

        A host provisioned for AppRole whose SecretID never arrived, with a
        developer's `~/.vault-token` lying in the home directory: `if role_id and
        secret_id` failed, `if client.token` succeeded, and `reachable()` reported
        the capability healthy off a credential belonging to no plane. This is the
        "appears correctly provisioned" case the work item describes.
        """
        _temp_home(tmp_path, monkeypatch)
        monkeypatch.setattr(hvac.Client, "is_authenticated", lambda self: True)
        plane = _plane(tmp_path, f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\n")

        with pytest.raises(RuntimeError, match="no SecretID"):
            cred_vault.reachable(CAP, vault_env=str(plane))

    def test_partial_material_refuses_on_the_merged_env_path_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: type[_Recorder]
    ) -> None:
        """`resolve`/`exec` merge `$VAULT_*` over the plane file; still fail closed.

        Here the token is *declared* (`$VAULT_TOKEN`) rather than ambient, and the
        refusal still stands: the operator asked this host for AppRole.
        """
        monkeypatch.setenv("ACB_VAULT_ENV", str(
            _plane(tmp_path, f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\n")
        ))
        monkeypatch.setenv("VAULT_TOKEN", ENV_TOKEN)

        with pytest.raises(RuntimeError, match="no SecretID"):
            cred_vault.reachable(CAP)
        with pytest.raises(RuntimeError, match="no SecretID"):
            cred_vault.resolve(CAP)
        assert all(r.logins == [] for r in recorder.instances)

    def test_secret_id_without_role_id_refuses(
        self, tmp_path: Path, recorder: type[_Recorder]
    ) -> None:
        plane = _plane(tmp_path, f"VAULT_ADDR={ADDR}\nVAULT_SECRET_ID={SECRET_ID}\n")

        with pytest.raises(RuntimeError) as exc:
            cred_vault.reachable(CAP, vault_env=str(plane))
        assert "no RoleID" in str(exc.value)
        assert "VAULT_ROLE_ID" in str(exc.value)

    def test_a_secret_id_file_that_was_never_delivered_refuses(
        self, tmp_path: Path, recorder: type[_Recorder]
    ) -> None:
        missing = tmp_path / "delivery" / "secret-id"
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\n"
            f"VAULT_SECRET_ID_FILE={missing}\n",
        )

        with pytest.raises(RuntimeError) as exc:
            cred_vault.reachable(CAP, vault_env=str(plane))
        assert "VAULT_SECRET_ID_FILE" in str(exc.value)
        assert str(missing) in str(exc.value)
        assert "does not exist" in str(exc.value)

    def test_an_unreadable_secret_id_file_refuses(
        self, tmp_path: Path, recorder: type[_Recorder]
    ) -> None:
        blocked = tmp_path / "secret-id"
        blocked.write_text(SECRET_ID, encoding="utf-8")
        blocked.chmod(0o000)
        if os.access(blocked, os.R_OK):  # root, or a filesystem without POSIX modes
            pytest.skip("mode 000 is not a barrier for this user/filesystem")
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\nVAULT_SECRET_ID_FILE={blocked}\n",
        )

        with pytest.raises(RuntimeError) as exc:
            cred_vault.reachable(CAP, vault_env=str(plane))
        assert "cannot read VAULT_SECRET_ID_FILE" in str(exc.value)
        assert str(blocked) in str(exc.value)

    def test_an_empty_secret_id_file_refuses(
        self, tmp_path: Path, recorder: type[_Recorder]
    ) -> None:
        """A silently failed delivery leaves a zero-byte file, not no file."""
        empty = tmp_path / "secret-id"
        empty.write_text("", encoding="utf-8")
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\nVAULT_SECRET_ID_FILE={empty}\n",
        )

        with pytest.raises(RuntimeError, match="is empty"):
            cred_vault.reachable(CAP, vault_env=str(plane))

    def test_response_wrapped_delivery_is_a_named_refusal(
        self, tmp_path: Path, recorder: type[_Recorder]
    ) -> None:
        """regista unwraps; acb does not. Say which, don't relay a Vault 400."""
        wrapped = tmp_path / "wrapped"
        wrapped.write_text("hvs.canary-wrapping-token", encoding="utf-8")
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\n"
            f"VAULT_SECRET_ID_FILE={wrapped}\nVAULT_SECRET_ID_RESPONSE_WRAPPED=1\n",
        )

        with pytest.raises(RuntimeError, match="does not unwrap"):
            cred_vault.reachable(CAP, vault_env=str(plane))
        assert recorder.instances[0].logins == []

    def test_no_refusal_ever_names_a_value(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: type[_Recorder]
    ) -> None:
        """Paths and variable names are diagnostics; values are not."""
        _temp_home(tmp_path, monkeypatch)
        monkeypatch.setenv("VAULT_TOKEN", ENV_TOKEN)
        secret_file = tmp_path / "secret-id"
        secret_file.write_text(SECRET_ID, encoding="utf-8")
        cases = [
            f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\n",
            f"VAULT_ADDR={ADDR}\nVAULT_SECRET_ID={SECRET_ID}\n",
            f"VAULT_ADDR={ADDR}\nVAULT_SECRET_ID_FILE={secret_file}\n",
        ]
        for i, body in enumerate(cases):
            plane = _plane(tmp_path, body, name=f"case{i}.env")
            with pytest.raises(RuntimeError) as exc:
                cred_vault.reachable(CAP, vault_env=str(plane))
            msg = str(exc.value)
            for canary in (SECRET_ID, DOTFILE_TOKEN, ENV_TOKEN):
                assert canary not in msg, f"{canary!r} leaked into {msg!r}"


# ---------------------------------------------------------------------------
# Positive controls: complete material still authenticates
# ---------------------------------------------------------------------------


class TestCompleteAppRoleStillAuthenticates:
    def test_inline_material_logs_in(
        self, tmp_path: Path, recorder: type[_Recorder]
    ) -> None:
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\nVAULT_SECRET_ID={SECRET_ID}\n",
        )

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        assert recorder.instances[0].logins == [
            {
                "method": "approle",
                "role_id": ROLE_ID,
                "secret_id": SECRET_ID,
                "mount_point": "approle",
            }
        ]

    def test_file_material_logs_in_and_the_file_wins_over_inline(
        self, tmp_path: Path, recorder: type[_Recorder]
    ) -> None:
        """The `*_FILE` forms regista prefers: one 0600 file serves both."""
        role_file = tmp_path / "role-id"
        role_file.write_text(ROLE_ID + "\n", encoding="utf-8")
        secret_file = tmp_path / "secret-id"
        secret_file.write_text(SECRET_ID + "\n", encoding="utf-8")
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\n"
            f"VAULT_ROLE_ID=ignored-inline-role\nVAULT_ROLE_ID_FILE={role_file}\n"
            f"VAULT_SECRET_ID=ignored-inline-secret\nVAULT_SECRET_ID_FILE={secret_file}\n",
        )

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        login = recorder.instances[0].logins[0]
        assert login["role_id"] == ROLE_ID
        assert login["secret_id"] == SECRET_ID

    def test_a_non_default_approle_mount_is_honoured(
        self, tmp_path: Path, recorder: type[_Recorder]
    ) -> None:
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\nVAULT_SECRET_ID={SECRET_ID}\n"
            f"VAULT_APPROLE_MOUNT_POINT=approle-qual\n",
        )

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        assert recorder.instances[0].logins[0]["mount_point"] == "approle-qual"

    def test_approle_precedes_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: type[_Recorder]
    ) -> None:
        """Precedence must match regista's: AppRole before token, always."""
        _temp_home(tmp_path, monkeypatch)
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_TOKEN={ENV_TOKEN}\n"
            f"VAULT_ROLE_ID={ROLE_ID}\nVAULT_SECRET_ID={SECRET_ID}\n",
        )

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        assert recorder.instances[0].logins[0]["method"] == "approle"


class TestKubernetesPathUnaffected:
    """A k8s-authenticated host has neither AppRole material nor a token.

    The fail-closed rule must not reach it: the k8s branch is decided and
    returned before AppRole is inspected.
    """

    def _k8s(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        jwt = tmp_path / "sa-token"
        jwt.write_text("canary-service-account-jwt\n", encoding="utf-8")
        monkeypatch.setattr(cred_vault, "_K8S_TOKEN", jwt)

    def test_in_cluster_auth_needs_no_approle_and_no_token(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: type[_Recorder]
    ) -> None:
        self._k8s(tmp_path, monkeypatch)
        plane = _plane(tmp_path, f"VAULT_ADDR={ADDR}\nVAULT_K8S_ROLE=acb-qual\n")

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        login = recorder.instances[0].logins[0]
        assert login["method"] == "kubernetes"
        assert login["role"] == "acb-qual"

    def test_in_cluster_auth_wins_over_partial_approle_material(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recorder: type[_Recorder]
    ) -> None:
        """Stray AppRole material must not turn a working k8s host into a refusal."""
        self._k8s(tmp_path, monkeypatch)
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_K8S_ROLE=acb-qual\nVAULT_ROLE_ID={ROLE_ID}\n",
        )

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        assert recorder.instances[0].logins[0]["method"] == "kubernetes"

    def test_a_k8s_token_without_a_role_still_falls_through(
        self, tmp_path: Path, recorder: type[_Recorder], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Unchanged: no `VAULT_K8S_ROLE` means the k8s branch is not taken."""
        self._k8s(tmp_path, monkeypatch)
        plane = _plane(
            tmp_path,
            f"VAULT_ADDR={ADDR}\nVAULT_ROLE_ID={ROLE_ID}\nVAULT_SECRET_ID={SECRET_ID}\n",
        )

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        assert recorder.instances[0].logins[0]["method"] == "approle"


class TestRegistaVocabularyAgreement:
    """One plane file, two components (regista WI-228 adopted these names).

    regista reads `VAULT_ADDR`, `VAULT_ROLE_ID`/`VAULT_ROLE_ID_FILE`,
    `VAULT_SECRET_ID`/`VAULT_SECRET_ID_FILE`, `VAULT_APPROLE_MOUNT_POINT` and
    (dev-only) `VAULT_TOKEN` from a mode-0600 env-style plane file — the shape
    `acb onboard` writes. This asserts acb reads the same vocabulary out of the
    same file, so the agreement is a test rather than a comment.
    """

    def test_the_shared_plane_file_shape_authenticates(
        self, tmp_path: Path, recorder: type[_Recorder]
    ) -> None:
        secret_file = tmp_path / "secret-id"
        secret_file.write_text(SECRET_ID, encoding="utf-8")
        plane = _plane(
            tmp_path,
            "# written by acb onboard; read by acb and regista\n"
            f"VAULT_ADDR={ADDR}\n"
            f"VAULT_ROLE_ID={ROLE_ID}\n"
            f"VAULT_SECRET_ID_FILE={secret_file}\n"
            "VAULT_APPROLE_MOUNT_POINT=approle\n",
        )

        assert cred_vault.reachable(CAP, vault_env=str(plane)) is True
        assert recorder.instances[0].logins[0]["method"] == "approle"

    def test_the_names_acb_treats_as_approle_material(self) -> None:
        assert cred_vault._APPROLE_VARS == (
            "VAULT_ROLE_ID",
            "VAULT_ROLE_ID_FILE",
            "VAULT_SECRET_ID",
            "VAULT_SECRET_ID_FILE",
        )
        assert cred_vault._APPROLE_DEFAULT_MOUNT == "approle"
