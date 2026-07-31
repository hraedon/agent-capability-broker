"""Plan 009 declared secret onboarding (WI-015 rewrite).

Every class below is named for the major it pins.  The branch this replaces had
tests that could not fail — a disjunction that was always true, an assertion
after `assert code == 2`, a canary never injected into the code under test — so
the discipline here is: assert on *calls made* and *bytes on disk*, not on
substrings of prose, and inject the canary into the paths that could leak it.

No live Vault. ``FakeVault`` implements the exact surface ``onboard`` uses, with
MagicMock wrappers so a test can assert both resulting state and the calls made
(notably ``cas=0``).  ``hvac`` is an optional extra and is NOT in ``[dev]``, so
this module must not import it at module level; the local exception stand-ins
are pinned against real hvac in ``TestExceptionNamesArePinned``.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent_capability_broker import onboard, providers
from agent_capability_broker.cli import main
from agent_capability_broker.model import Capability, parse_manifest

# A value that must never reach stdout, stderr, JSON, provenance, or a plan.
CANARY = "canary-c7b1f2-never-in-output"

VAULT_ADDR = "http://127.0.0.1:8200"


# ---------------------------------------------------------------------------
# hvac stand-ins. `onboard` classifies exceptions by `type(exc).__name__` so it
# never imports the optional extra; these carry the same names.
# ---------------------------------------------------------------------------


class InvalidPath(Exception):
    """hvac.exceptions.InvalidPath — 404: the object is not there."""


class Forbidden(Exception):
    """hvac.exceptions.Forbidden — 403: we were not allowed to look."""


class InvalidRequest(Exception):
    """hvac.exceptions.InvalidRequest — 400, e.g. a cas precondition failure."""


CAS_CONFLICT = InvalidRequest(
    "check-and-set parameter did not match the current version"
)


# ---------------------------------------------------------------------------
# Capabilities and manifests
# ---------------------------------------------------------------------------


def cap(
    cap_id: str = "cred:qual-bot",
    *,
    harnesses: tuple[str, ...] = ("claude",),
    vault: str = "kv/agent-suite/qual/bot",
    fields: object = ("username", "password"),
    **options: object,
) -> Capability:
    opts: dict[str, object] = {"vault": vault, "fields": list(fields)}  # type: ignore[call-overload]
    opts.update(options)
    return Capability(
        id=cap_id, provider="cred", harnesses=harnesses, options=opts
    )


CAP = cap()


def write_manifest(
    tmp_path: Path,
    *,
    cap_id: str = "cred:qual-bot",
    harnesses: str = '["claude"]',
    vault: str = "kv/agent-suite/qual/bot",
    fields: str = '["username", "password"]',
    extra: str = "",
) -> Path:
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        f'[capability."{cap_id}"]\n'
        f'provider = "cred"\n'
        f"harnesses = {harnesses}\n"
        f'vault = "{vault}"\n'
        f"fields = {fields}\n"
        f"{extra}",
        encoding="utf-8",
    )
    return manifest


def write_admin_env(
    tmp_path: Path,
    *,
    addr: str | None = VAULT_ADDR,
    token: str | None = "admin-token",
    role_id: str | None = None,
    secret_id: str | None = None,
    name: str = "admin.env",
) -> Path:
    lines = []
    if addr is not None:
        lines.append(f"VAULT_ADDR={addr}")
    if token is not None:
        lines.append(f"VAULT_TOKEN={token}")
    if role_id is not None:
        lines.append(f"VAULT_ROLE_ID={role_id}")
    if secret_id is not None:
        lines.append(f"VAULT_SECRET_ID={secret_id}")
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def isolated_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pin every harness/config/state root into tmp_path.

    Without this, `plane_targets` resolves against the *operator's* real
    ~/.claude and an --apply test would write a live plane file there.
    """
    home = tmp_path / "home"
    for sub in (".claude", ".config/opencode", ".hermes", ".codex"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("ACB_CLAUDE_SETTINGS", str(home / ".claude" / "settings.json"))
    monkeypatch.setenv(
        "ACB_OPENCODE_CONFIG", str(home / ".config" / "opencode" / "opencode.json")
    )
    monkeypatch.setenv("ACB_HERMES_CONFIG", str(home / ".hermes" / "config.yaml"))
    monkeypatch.setenv("ACB_CODEX_HOME", str(home / ".codex"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("ACB_VAULT_ADMIN_ENV", raising=False)
    monkeypatch.delenv("ACB_VAULT_ENV", raising=False)
    monkeypatch.delenv("AGENT_SUITE_CONFIG", raising=False)
    monkeypatch.delenv("ACB_MANIFEST", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)
    monkeypatch.delenv("VAULT_ADDR", raising=False)


# ---------------------------------------------------------------------------
# FakeVault
# ---------------------------------------------------------------------------


class FakeVault:
    """The Vault surface `onboard` uses, in memory, with call recording.

    ``policies``/``roles``/``kv`` are the pre-existing state.  ``*_error``
    knobs make one call raise so a test can drive a specific failure path.
    """

    def __init__(
        self,
        *,
        policies: dict[str, str] | None = None,
        roles: dict[str, dict[str, Any]] | None = None,
        kv: set[str] | None = None,
        metadata_error: BaseException | None = None,
        policy_read_error: BaseException | None = None,
        policy_write_error: BaseException | None = None,
        role_write_error: BaseException | None = None,
        secret_id_error: BaseException | None = None,
        kv_write_error: BaseException | None = None,
        secret_id_value: str = "minted-secret-id",
        role_id_value: str = "role-id-abc",
        delete_policy_error: BaseException | None = None,
    ) -> None:
        self.policies = dict(policies or {})
        self.roles = dict(roles or {})
        self.kv = set(kv or set())
        self.secret_id_value = secret_id_value
        self.role_id_value = role_id_value
        self.destroyed_accessors: list[str] = []
        # A copy of every KV payload written. `apply_onboard` clears the caller's
        # dict after the write, and MagicMock.call_args holds the *same* object,
        # so an after-the-fact assertion on call_args would see {} and pass
        # vacuously. Copying at call time keeps the assertion real.
        self.written_secrets: list[dict[str, str]] = []
        self.written_cas: list[int] = []
        self._minted = 0

        self.sys = MagicMock()
        self.auth = MagicMock()
        self.secrets = MagicMock()

        def read_policy(name: str) -> dict[str, str]:
            if policy_read_error is not None:
                raise policy_read_error
            if name not in self.policies:
                raise InvalidPath(f"policy {name} not found")
            return {"name": name, "rules": self.policies[name]}

        def create_or_update_policy(name: str, hcl: str) -> None:
            if policy_write_error is not None:
                raise policy_write_error
            self.policies[name] = hcl

        def delete_policy(name: str) -> None:
            if delete_policy_error is not None:
                raise delete_policy_error
            self.policies.pop(name, None)

        def read_role(name: str) -> dict[str, Any]:
            if name not in self.roles:
                raise InvalidPath(f"role {name} not found")
            return {"data": dict(self.roles[name])}

        def create_or_update_approle(name: str, **kw: Any) -> None:
            if role_write_error is not None:
                raise role_write_error
            self.roles[name] = {
                "token_policies": list(kw.get("token_policies", [])),
                "token_ttl": kw.get("token_ttl"),
                "token_max_ttl": kw.get("token_max_ttl"),
                "secret_id_ttl": kw.get("secret_id_ttl"),
                "secret_id_num_uses": kw.get("secret_id_num_uses"),
            }

        def delete_role(name: str) -> None:
            self.roles.pop(name, None)

        def read_role_id(name: str) -> dict[str, Any]:
            if name not in self.roles:
                raise InvalidPath(f"role {name} not found")
            return {"data": {"role_id": self.role_id_value}}

        def generate_secret_id(name: str, **kw: Any) -> dict[str, Any]:
            if secret_id_error is not None:
                raise secret_id_error
            self._minted += 1
            return {
                "data": {
                    "secret_id": self.secret_id_value,
                    "secret_id_accessor": f"accessor-{self._minted}",
                }
            }

        def read_secret_id(role_name: str, secret_id: str) -> dict[str, Any]:
            return {"data": {"secret_id_accessor": f"accessor-for-{secret_id[:4]}"}}

        def destroy_secret_id_accessor(role_name: str, accessor: str) -> None:
            self.destroyed_accessors.append(accessor)

        def read_secret_metadata(
            *, mount_point: str, path: str
        ) -> dict[str, Any]:
            if metadata_error is not None:
                raise metadata_error
            if f"{mount_point}/{path}" not in self.kv:
                raise InvalidPath("path not found")
            return {"data": {"versions": {}}}

        def create_or_update_secret(
            *, mount_point: str, path: str, secret: dict[str, str], cas: int
        ) -> dict[str, Any]:
            self.written_cas.append(cas)
            if kv_write_error is not None:
                raise kv_write_error
            full = f"{mount_point}/{path}"
            self.written_secrets.append(dict(secret))
            if cas == 0 and full in self.kv:
                raise CAS_CONFLICT
            self.kv.add(full)
            return {"data": {"version": 1}}

        self.sys.read_policy.side_effect = read_policy
        self.sys.create_or_update_policy.side_effect = create_or_update_policy
        self.sys.delete_policy.side_effect = delete_policy
        self.auth.approle.read_role.side_effect = read_role
        self.auth.approle.create_or_update_approle.side_effect = create_or_update_approle
        self.auth.approle.delete_role.side_effect = delete_role
        self.auth.approle.read_role_id.side_effect = read_role_id
        self.auth.approle.generate_secret_id.side_effect = generate_secret_id
        self.auth.approle.read_secret_id.side_effect = read_secret_id
        self.auth.approle.destroy_secret_id_accessor.side_effect = (
            destroy_secret_id_accessor
        )
        self.secrets.kv.v2.read_secret_metadata.side_effect = read_secret_metadata
        self.secrets.kv.v2.create_or_update_secret.side_effect = create_or_update_secret

    def is_authenticated(self) -> bool:
        return True

    # Convenience accessors for assertions.
    @property
    def kv_write(self) -> MagicMock:
        return self.secrets.kv.v2.create_or_update_secret

    @property
    def mint(self) -> MagicMock:
        return self.auth.approle.generate_secret_id

    @property
    def policy_write(self) -> MagicMock:
        return self.sys.create_or_update_policy

    @property
    def role_write(self) -> MagicMock:
        return self.auth.approle.create_or_update_approle


def converged_vault(target: Capability = CAP, **kw: Any) -> FakeVault:
    """A FakeVault that already holds exactly the derived structure."""
    return FakeVault(
        policies={onboard.policy_name(target): onboard.policy_hcl(target)},
        roles={
            onboard.role_name(target): {
                "token_policies": [onboard.policy_name(target)],
                **onboard.ROLE_CONFIG,
            }
        },
        **kw,
    )


def run_cli(argv: list[str], vault: FakeVault | None = None) -> int:
    """Run `acb`, patching the admin client to `vault` when one is supplied."""
    if vault is None:
        return main(argv)
    with patch.object(onboard, "_admin_client", return_value=vault):
        return main(argv)


# ===========================================================================
# Derivation (pure planner)
# ===========================================================================


class TestDerivation:
    def test_policy_and_role_names(self) -> None:
        assert onboard.policy_name(CAP) == "acb-qual-bot"
        assert onboard.role_name(CAP) == "acb-qual-bot"

    def test_policy_hcl_is_read_only_and_exactly_scoped(self) -> None:
        hcl = onboard.policy_hcl(CAP)
        assert 'path "kv/data/agent-suite/qual/bot"' in hcl
        assert 'path "kv/metadata/agent-suite/qual/bot"' in hcl
        assert hcl.count("capabilities") == 2
        for forbidden in ("create", "update", "write", "delete", "sudo", "list", "patch"):
            assert forbidden not in hcl

    def test_plan_is_deterministic(self) -> None:
        assert onboard.plan_onboard(CAP) == onboard.plan_onboard(CAP)

    def test_plan_order_and_one_plane_row_per_harness(self) -> None:
        plan = onboard.plan_onboard(
            cap(harnesses=("opencode", "claude"), vault_env="qual-bot.env")
        )
        assert [a.kind for a in plan] == [
            "create_policy",
            "create_role",
            "write_plane_env",
            "write_plane_env",
            "write_kv",
        ]
        assert [a.harness for a in plan if a.kind == "write_plane_env"] == [
            "claude",
            "opencode",
        ]

    def test_single_field_declaration(self) -> None:
        entry = Capability(
            id="cred:solo",
            provider="cred",
            harnesses=("claude",),
            options={"vault": "kv/agent-suite/qual/solo", "field": "token"},
        )
        kv = next(a for a in onboard.plan_onboard(entry) if a.kind == "write_kv")
        assert kv.payload["fields"] == ["token"]

    def test_plan_payloads_carry_no_secret_material(self) -> None:
        """The canary is injected where a leak could plausibly originate."""
        entry = cap(vault_env="qual-bot.env")
        text = json.dumps(
            [
                {"kind": a.kind, "target": a.target, "summary": a.summary,
                 "payload": a.payload, "harness": a.harness}
                for a in onboard.plan_onboard(entry)
            ]
        )
        assert CANARY not in text
        # Positive control: the assertion above is only meaningful because the
        # plan text is non-trivial and does contain the declared field names.
        assert "username" in text and "kv/agent-suite/qual/bot" in text


class TestRefusals:
    @pytest.mark.parametrize(
        ("entry", "match"),
        [
            (
                Capability(id="e2e:chromium", provider="e2e", harnesses=("claude",),
                           options={}),
                "only cred",
            ),
            (cap(source="suite"), "source='vault'"),
            (
                Capability(id="cred:x", provider="cred", harnesses=("claude",),
                           options={"fields": ["a"]}),
                "no 'vault' path",
            ),
            (
                Capability(id="cred:x", provider="cred", harnesses=("claude",),
                           options={"vault": "nomount", "fields": ["a"]}),
                "must be '<mount>/<path>'",
            ),
            (
                Capability(id="cred:x", provider="cred", harnesses=("claude",),
                           options={"vault": "kv/a/b"}),
                "field selection required",
            ),
            (cap(fields=()), "options.fields is empty"),
        ],
    )
    def test_planning_time_refusals(self, entry: Capability, match: str) -> None:
        with pytest.raises(onboard.OnboardRefusal, match=match):
            onboard.validate_for_onboard(entry)

    @pytest.mark.parametrize(
        "path",
        [
            'kv/x" }\npath "*" { capabilities = ["sudo"',   # HCL stanza injection
            "kv/../etc",                                     # traversal segment
            "kv/a//b",                                       # empty segment
            "kv/a b",                                        # whitespace
            "kv/a*",                                         # glob
            "kv/{a}",                                        # HCL braces
        ],
    )
    def test_vault_path_that_could_inject_hcl_is_refused(self, path: str) -> None:
        with pytest.raises(onboard.OnboardRefusal):
            onboard.policy_hcl(cap(vault=path))

    def test_refused_path_never_reaches_generated_hcl(self) -> None:
        """The refusal is the point: no partially-escaped HCL is ever built."""
        hostile = 'kv/x" }\npath "sys/*" { capabilities = ["sudo"] }\n#'
        with pytest.raises(onboard.OnboardRefusal):
            onboard.plan_onboard(cap(vault=hostile))


# ===========================================================================
# M2 — path traversal on the WRITE path
# ===========================================================================


class TestM2PlaneWritePathCannotEscape:
    """`options.vault_env` must not aim a *write* at an arbitrary file.

    The reviewed branch used `options.vault_env` verbatim, and apply renames any
    pre-existing file at that path to `<path>.bak` and replaces it — so a
    manifest could clobber ~/.bashrc and plant live VAULT_SECRET_ID material
    anywhere the operator can write. `plane_targets` now goes through
    `providers.vault_env_path`, which applies the bare-filename guard added in
    4d6e376.
    """

    @pytest.mark.parametrize(
        "vault_env",
        [
            "/home/itadmin/.bashrc",
            "../../other/vault.env",
            "../vault.env",
            "sub/vault.env",
            "..",
            ".",
            "a\\b.env",
        ],
    )
    def test_non_bare_vault_env_is_refused_at_planning_time(
        self, vault_env: str
    ) -> None:
        with pytest.raises(onboard.OnboardRefusal, match="bare filename"):
            onboard.plan_onboard(cap(vault_env=vault_env))

    def test_absolute_vault_env_does_not_touch_the_targeted_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        decoy = tmp_path / "precious.rc"
        decoy.write_text("export PATH=/usr/bin\n", encoding="utf-8")
        before = decoy.read_bytes()
        manifest = write_manifest(
            tmp_path, extra=f'vault_env = "{decoy}"\n'
        )
        admin = write_admin_env(tmp_path)
        vault = FakeVault()

        code = run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin)],
            vault,
        )

        assert code == 1
        assert decoy.read_bytes() == before
        assert not (tmp_path / "precious.rc.bak").exists()
        assert not (tmp_path / "precious.rc.acb-new").exists()
        vault.mint.assert_not_called()
        vault.policy_write.assert_not_called()
        assert "bare filename" in capsys.readouterr().err

    def test_traversal_vault_env_creates_nothing_outside_the_harness_dir(
        self, tmp_path: Path
    ) -> None:
        escape = tmp_path / "escape"
        escape.mkdir()
        manifest = write_manifest(
            tmp_path, extra='vault_env = "../../escape/vault.env"\n'
        )
        admin = write_admin_env(tmp_path)

        code = run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin)],
            FakeVault(),
        )

        assert code == 1
        assert list(escape.iterdir()) == []

    def test_refusal_precedes_any_vault_contact(self, tmp_path: Path) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "/etc/passwd"\n')
        admin = write_admin_env(tmp_path)
        with patch.object(onboard, "_admin_client") as admin_client:
            code = main(
                ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
                 "--admin-env", str(admin)]
            )
        assert code == 1
        admin_client.assert_not_called()

    def test_the_guard_is_the_repos_existing_one(self) -> None:
        """Same function, same message — not a parallel reimplementation."""
        with pytest.raises(ValueError, match="bare filename"):
            providers._assert_safe_path_component("../x", "options.vault_env")


# ===========================================================================
# M3 — onboard and runtime agree on where the plane file lives
# ===========================================================================


class TestM3PlaneLocationAgreesWithRuntime:
    def test_plane_targets_match_the_path_embedded_in_the_shim(self) -> None:
        """The shim tells the agent which file to point ACB_VAULT_ENV at.

        If onboard writes anywhere else, onboarding "succeeds" and every
        `acb exec` through that shim authenticates against a file that does not
        exist. Compare the two derivations directly.
        """
        entry = cap(harnesses=("claude", "opencode", "codex", "hermes"),
                    vault_env="qual-bot.env")
        known = providers.adapters()
        for target in onboard.plane_targets(entry):
            shim = providers._render_cred_shim(
                entry,
                target.harness,
                providers.shim_name(entry),
                providers.vault_env_path(entry, known[target.harness]),
            )
            assert f"ACB_VAULT_ENV={target.path} acb exec" in shim

    def test_plane_targets_delegate_to_the_single_resolver(self) -> None:
        """Guards against a future copy of the resolution rule drifting."""
        with patch.object(
            onboard, "vault_env_path", wraps=providers.vault_env_path
        ) as resolver:
            onboard.plane_targets(cap(harnesses=("claude", "opencode")))
        assert resolver.call_count == 2

    def test_default_target_is_the_file_the_adapter_declares(self) -> None:
        adapter = providers.adapters()["claude"]
        targets = onboard.plane_targets(cap(harnesses=("claude",)))
        assert targets[0].path == adapter.vault_env_path
        assert targets[0].path.name == "vault.env"

    def test_bare_name_resolves_beside_the_harness_config_not_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A bare `vault_env` valid for exec used to resolve against CWD."""
        elsewhere = tmp_path / "somewhere-else"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        target = onboard.plane_targets(cap(vault_env="qual-bot.env"))[0]
        adapter = providers.adapters()["claude"]
        assert target.path == adapter.vault_env_path.parent / "qual-bot.env"
        assert elsewhere not in target.path.parents

    def test_apply_writes_exactly_where_check_and_doctor_look(
        self, tmp_path: Path
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        admin = write_admin_env(tmp_path)
        entry = parse_manifest(manifest)[0]
        expected = onboard.plane_targets(entry)[0].path

        assert run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin)],
            converged_vault(entry),
        ) == 0

        assert expected.is_file()
        env = dict(
            line.split("=", 1)
            for line in expected.read_text(encoding="utf-8").splitlines()
            if "=" in line and not line.startswith("#")
        )
        assert env["VAULT_ROLE_ID"] == "role-id-abc"
        assert env["VAULT_ADDR"] == VAULT_ADDR

    def test_shared_harness_plane_is_refused(self, tmp_path: Path) -> None:
        """Two capabilities defaulting to one harness's vault.env collide.

        Provisioning a capability-scoped least-privilege AppRole into the
        harness-shared plane would repoint the other capability at a role that
        cannot read its path.
        """
        manifest = tmp_path / "capabilities.toml"
        manifest.write_text(
            '[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\n'
            'vault = "kv/agent-suite/qual/a"\nfield = "token"\n\n'
            '[capability."cred:b"]\nprovider = "cred"\nharnesses = ["claude"]\n'
            'vault = "kv/agent-suite/qual/b"\nfield = "token"\n',
            encoding="utf-8",
        )
        caps = parse_manifest(manifest)
        with pytest.raises(onboard.OnboardRefusal, match="shared access plane"):
            onboard.validate_for_onboard(caps[0], tuple(caps[1:]))

    def test_dedicated_plane_declaration_resolves_the_collision(
        self, tmp_path: Path
    ) -> None:
        manifest = tmp_path / "capabilities.toml"
        manifest.write_text(
            '[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\n'
            'vault = "kv/agent-suite/qual/a"\nfield = "token"\n'
            'vault_env = "a.env"\n\n'
            '[capability."cred:b"]\nprovider = "cred"\nharnesses = ["claude"]\n'
            'vault = "kv/agent-suite/qual/b"\nfield = "token"\n',
            encoding="utf-8",
        )
        caps = parse_manifest(manifest)
        onboard.validate_for_onboard(caps[0], tuple(caps[1:]))
        onboard.validate_for_onboard(caps[1], tuple(caps[:1]))
        assert onboard.plane_targets(caps[0])[0].path.name == "a.env"
        assert onboard.plane_targets(caps[1])[0].path.name == "vault.env"


# ===========================================================================
# M1 — `--check` must not report clean having verified nothing
# ===========================================================================


class TestM1CheckVerifiesSomething:
    def test_unknown_rows_count_as_problems(self) -> None:
        action = onboard.plan_onboard(CAP)[0]
        report = onboard.CheckReport(
            results=[
                onboard.CheckResult(action, "ok"),
                onboard.CheckResult(action, "unknown", "offline"),
            ],
            online=False,
        )
        assert not report.clean
        assert len(report.problems) == 1

    def test_failed_admin_authentication_is_an_error_not_offline_mode(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The headline major: exit 0 / "clean" with authentication broken."""
        manifest = write_manifest(tmp_path)
        admin = write_admin_env(tmp_path)
        with patch.object(
            onboard,
            "_admin_client",
            side_effect=onboard.OnboardRefusal("admin plane failed to authenticate"),
        ):
            code = main(
                ["onboard", "cred:qual-bot", "-m", str(manifest), "--check",
                 "--admin-env", str(admin)]
            )
        captured = capsys.readouterr()
        assert code == 1
        assert "clean" not in (captured.out + captured.err).lower()
        assert "authenticate" in captured.err

    def test_failed_admin_authentication_json_envelope(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path)
        admin = write_admin_env(tmp_path)
        with patch.object(
            onboard,
            "_admin_client",
            side_effect=onboard.OnboardRefusal("admin plane failed to authenticate"),
        ):
            code = main(
                ["onboard", "cred:qual-bot", "-m", str(manifest), "--check",
                 "--admin-env", str(admin), "--json"]
            )
        payload = json.loads(capsys.readouterr().out)
        assert code == 1
        assert payload["ok"] is False
        assert payload["error"]["code"] == "ONBOARD_REFUSED"

    def test_missing_vault_addr_in_admin_file_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """VAULT_ADDR comes from the admin file, never from the shell."""
        monkeypatch.setenv("VAULT_ADDR", "http://ambient.invalid:8200")
        admin = write_admin_env(tmp_path, addr=None)
        with pytest.raises(onboard.OnboardRefusal, match="does not set VAULT_ADDR"):
            onboard.load_admin_plane(str(admin))

    def test_nonexistent_admin_file_is_refused_not_downgraded(
        self, tmp_path: Path
    ) -> None:
        with pytest.raises(onboard.OnboardRefusal, match="does not exist"):
            onboard.load_admin_plane(str(tmp_path / "absent.env"))

    def test_offline_check_reports_unknown_and_is_not_clean(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path)
        code = main(["onboard", "cred:qual-bot", "-m", str(manifest), "--check"])
        out = capsys.readouterr().out
        assert code == 1
        assert "NOT CLEAN" in out
        assert "no admin plane was supplied" in out

    def test_offline_check_still_reports_locally_knowable_plane_facts(
        self, tmp_path: Path
    ) -> None:
        """Offline is honest, not blind: the plane file is on this host."""
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        plane = onboard.plane_targets(entry)[0].path

        absent = onboard.check_onboard(entry)
        plane_row = next(
            r for r in absent.results if r.action.kind == "write_plane_env"
        )
        assert plane_row.status == "missing"

        plane.parent.mkdir(parents=True, exist_ok=True)
        plane.write_text(
            f"VAULT_ADDR={VAULT_ADDR}\nVAULT_ROLE_ID=r\nVAULT_SECRET_ID=s\n",
            encoding="utf-8",
        )
        plane.chmod(stat.S_IRUSR | stat.S_IWUSR)
        present = onboard.check_onboard(entry)
        plane_row = next(
            r for r in present.results if r.action.kind == "write_plane_env"
        )
        assert plane_row.status == "unknown"
        assert "needs a reachable admin plane" in plane_row.detail
        # Present-but-unverified is still not clean.
        assert not present.clean

    def test_offline_check_flags_an_incomplete_plane_file_as_drift(
        self, tmp_path: Path
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        plane = onboard.plane_targets(entry)[0].path
        plane.parent.mkdir(parents=True, exist_ok=True)
        plane.write_text(f"VAULT_ADDR={VAULT_ADDR}\n", encoding="utf-8")
        row = next(
            r
            for r in onboard.check_onboard(entry).results
            if r.action.kind == "write_plane_env"
        )
        assert row.status == "drift"

    def test_world_readable_plane_file_is_drift(self, tmp_path: Path) -> None:
        if os.name != "posix":  # pragma: no cover — POSIX mode bits only
            pytest.skip("POSIX mode bits")
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        plane = onboard.plane_targets(entry)[0].path
        plane.parent.mkdir(parents=True, exist_ok=True)
        plane.write_text("VAULT_ROLE_ID=r\nVAULT_SECRET_ID=s\n", encoding="utf-8")
        plane.chmod(0o644)
        row = next(
            r
            for r in onboard.check_onboard(entry).results
            if r.action.kind == "write_plane_env"
        )
        assert row.status == "drift"
        assert "0644" in row.detail

    def test_denied_kv_metadata_is_unknown_never_ok(self, tmp_path: Path) -> None:
        """A probe that could not look must not be scored as verified."""
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        vault = converged_vault(entry, metadata_error=Forbidden("permission denied"))
        with patch.object(onboard, "_admin_client", return_value=vault):
            report = onboard.check_onboard(entry, admin_env=str(admin))
        kv_row = next(r for r in report.results if r.action.kind == "write_kv")
        assert kv_row.status == "unknown"
        assert not report.clean

    def test_fully_provisioned_state_is_clean(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The positive control: `clean` and exit 0 are reachable."""
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        plane = onboard.plane_targets(entry)[0].path
        plane.parent.mkdir(parents=True, exist_ok=True)
        plane.write_text(
            f"VAULT_ADDR={VAULT_ADDR}\nVAULT_ROLE_ID=role-id-abc\n"
            f"VAULT_SECRET_ID=s\n",
            encoding="utf-8",
        )
        plane.chmod(stat.S_IRUSR | stat.S_IWUSR)
        vault = converged_vault(entry, kv={"kv/agent-suite/qual/bot"})

        code = run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--check",
             "--admin-env", str(admin)],
            vault,
        )
        assert code == 0
        assert "onboarding state: clean" in capsys.readouterr().out

    def test_policy_scope_drift_is_reported(self, tmp_path: Path) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        vault = FakeVault(
            policies={onboard.policy_name(entry): 'path "kv/*" { capabilities = ["read"] }'}
        )
        with patch.object(onboard, "_admin_client", return_value=vault):
            report = onboard.check_onboard(entry, admin_env=str(admin))
        row = next(r for r in report.results if r.action.kind == "create_policy")
        assert row.status == "drift"

    def test_check_never_reads_a_secret_value(self, tmp_path: Path) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        vault = converged_vault(entry, kv={"kv/agent-suite/qual/bot"})
        with patch.object(onboard, "_admin_client", return_value=vault):
            onboard.check_onboard(entry, admin_env=str(admin))
        vault.secrets.kv.v2.read_secret_version.assert_not_called()
        vault.kv_write.assert_not_called()
        vault.policy_write.assert_not_called()
        vault.role_write.assert_not_called()
        vault.mint.assert_not_called()


# ===========================================================================
# M4 — never-overwrite is enforced under a least-privilege credential
# ===========================================================================


class TestM4NeverOverwrite:
    def _apply(
        self, tmp_path: Path, vault: FakeVault, values: dict[str, str] | None = None
    ) -> onboard.ApplyReport:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        with patch.object(onboard, "_admin_client", return_value=vault):
            return onboard.apply_onboard(
                entry,
                admin_env=str(admin),
                values={"username": "u", "password": CANARY}
                if values is None
                else values,
            )

    def test_denied_metadata_probe_is_unknown_not_absent(self) -> None:
        """The exact inversion of the reviewed bug (`except: return False`)."""
        vault = FakeVault(metadata_error=Forbidden("permission denied"))
        probe = onboard.probe_kv(vault, "kv/agent-suite/qual/bot")
        assert probe.present is None
        assert probe.reason == "permission denied"

    def test_absent_path_is_absent(self) -> None:
        assert onboard.probe_kv(FakeVault(), "kv/agent-suite/qual/bot").present is False

    def test_write_always_carries_cas_zero(self, tmp_path: Path) -> None:
        vault = FakeVault()
        report = self._apply(tmp_path, vault)
        assert [r.status for r in report.results if r.action.kind == "write_kv"] == [
            "applied"
        ]
        vault.kv_write.assert_called_once()
        assert vault.written_cas == [0]

    def test_least_privilege_credential_cannot_silently_overwrite(
        self, tmp_path: Path
    ) -> None:
        """Metadata unreadable *and* a value already present.

        This is the documented least-privilege onboarding AppRole: it can write
        the path but cannot read its metadata. The reviewed branch scored that
        as "no value present" and overwrote. `cas=0` makes Vault the enforcer.
        """
        vault = FakeVault(
            metadata_error=Forbidden("permission denied"),
            kv={"kv/agent-suite/qual/bot"},
        )
        report = self._apply(tmp_path, vault)
        kv_row = next(r for r in report.results if r.action.kind == "write_kv")
        assert kv_row.status == "skipped"
        assert "never overwritten" in kv_row.detail
        # The write was attempted (metadata was unknowable) but rejected by
        # Vault, and the stored value is untouched.
        assert vault.kv_write.call_count == 1
        assert vault.written_cas == [0]
        assert report.ok

    def test_known_existing_value_is_not_even_attempted(self, tmp_path: Path) -> None:
        vault = FakeVault(kv={"kv/agent-suite/qual/bot"})
        report = self._apply(tmp_path, vault)
        kv_row = next(r for r in report.results if r.action.kind == "write_kv")
        assert kv_row.status == "skipped"
        vault.kv_write.assert_not_called()

    def test_unknown_metadata_does_not_block_a_legitimate_first_write(
        self, tmp_path: Path
    ) -> None:
        vault = FakeVault(metadata_error=Forbidden("permission denied"))
        report = self._apply(tmp_path, vault)
        kv_row = next(r for r in report.results if r.action.kind == "write_kv")
        assert kv_row.status == "applied"
        assert "kv/agent-suite/qual/bot" in vault.kv

    def test_create_only_credential_fails_closed_not_open(
        self, tmp_path: Path
    ) -> None:
        """Live-verified: a `create`-only credential gets Forbidden, not a CAS
        conflict, on the second write — KV v2 needs `update` to add a version, so
        Vault denies at the ACL layer before evaluating cas.

        That is ambiguous between "path already has a value" and "policy too
        narrow", so it must fail closed and name both. What it must never do is
        report success, and nothing may be written either way.
        """
        vault = FakeVault(
            metadata_error=Forbidden("permission denied"),
            kv_write_error=Forbidden("permission denied"),
        )
        report = self._apply(tmp_path, vault)
        kv_row = next(r for r in report.results if r.action.kind == "write_kv")
        assert kv_row.status == "failed"
        assert "no value was written" in kv_row.detail
        assert '["create", "update"]' in kv_row.detail
        assert not report.ok
        assert vault.written_secrets == []

    def test_values_from_none_writes_nothing(self, tmp_path: Path) -> None:
        vault = FakeVault()
        report = self._apply(tmp_path, vault, values={})
        # An empty dict is still "values supplied"; None is the `none` source.
        vault.kv_write.assert_called_once()
        assert report.ok

    def test_no_force_flag_exists(self) -> None:
        from agent_capability_broker.cli import build_parser

        help_text = build_parser().format_help()
        assert "--force" not in help_text

    def test_values_are_cleared_after_the_write(self, tmp_path: Path) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        values = {"username": "u", "password": CANARY}
        with patch.object(onboard, "_admin_client", return_value=FakeVault()):
            onboard.apply_onboard(entry, admin_env=str(admin), values=values)
        assert values == {}

    def test_values_are_cleared_even_when_the_write_fails(
        self, tmp_path: Path
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        values = {"password": CANARY}
        vault = FakeVault(kv_write_error=InvalidRequest("upstream said no"))
        with patch.object(onboard, "_admin_client", return_value=vault):
            onboard.apply_onboard(entry, admin_env=str(admin), values=values)
        assert values == {}


# ===========================================================================
# M5 — an ambient VAULT_TOKEN is never picked up
# ===========================================================================


class TestM5NoAmbientCredentials:
    def test_admin_file_without_auth_material_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """hvac.Client(url, token=None) reads $VAULT_TOKEN then ~/.vault-token."""
        monkeypatch.setenv("VAULT_TOKEN", CANARY)
        admin = write_admin_env(tmp_path, token=None)
        with pytest.raises(onboard.OnboardRefusal, match="never picked up"):
            onboard.load_admin_plane(str(admin))

    def test_ambient_token_does_not_reach_the_client(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AppRole admin plane: the token kwarg must be "" — not None, not $VAULT_TOKEN.

        `None` is the value that triggers hvac's `get_token_from_env()`; the
        empty string is what defeats it.
        """
        pytest.importorskip("hvac")
        monkeypatch.setenv("VAULT_TOKEN", CANARY)
        admin = write_admin_env(
            tmp_path, token=None, role_id="admin-role", secret_id="admin-secret"
        )
        plane = onboard.load_admin_plane(str(admin))
        assert plane is not None

        constructed = MagicMock()
        constructed.is_authenticated.return_value = True
        with patch("hvac.Client", return_value=constructed) as client_cls:
            onboard._admin_client(plane)
        assert client_cls.call_args.kwargs["token"] == ""
        assert client_cls.call_args.kwargs["url"] == VAULT_ADDR

    def test_vault_addr_is_pinned_to_the_admin_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """hvac also falls back to $VAULT_ADDR when url is falsy."""
        pytest.importorskip("hvac")
        monkeypatch.setenv("VAULT_ADDR", "http://ambient.invalid:8200")
        admin = write_admin_env(tmp_path, addr="http://declared.invalid:8200")
        plane = onboard.load_admin_plane(str(admin))
        assert plane is not None
        constructed = MagicMock()
        constructed.is_authenticated.return_value = True
        with patch("hvac.Client", return_value=constructed) as client_cls:
            onboard._admin_client(plane)
        assert client_cls.call_args.kwargs["url"] == "http://declared.invalid:8200"

    def test_no_admin_plane_means_apply_is_refused(self, tmp_path: Path) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        with pytest.raises(onboard.OnboardRefusal, match="requires --admin-env"):
            onboard.apply_onboard(entry)

    def test_ambient_token_never_appears_in_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("VAULT_TOKEN", CANARY)
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        admin = write_admin_env(tmp_path, token=None)
        code = main(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin), "--json"]
        )
        captured = capsys.readouterr()
        assert code == 1
        assert CANARY not in captured.out + captured.err

    def test_admin_token_from_the_file_is_never_printed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        admin = write_admin_env(tmp_path, token=CANARY)
        code = run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin)],
            FakeVault(),
        )
        captured = capsys.readouterr()
        assert code == 0
        assert CANARY not in captured.out + captured.err


# ===========================================================================
# M6 — apply is idempotent
# ===========================================================================


class TestM6Idempotency:
    def _setup(self, tmp_path: Path) -> tuple[Capability, Path, Path]:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        return entry, admin, onboard.plane_targets(entry)[0].path

    def test_rerun_mints_no_secret_id_and_rewrites_nothing(
        self, tmp_path: Path
    ) -> None:
        entry, admin, plane = self._setup(tmp_path)
        vault = FakeVault()
        with patch.object(onboard, "_admin_client", return_value=vault):
            first = onboard.apply_onboard(entry, admin_env=str(admin))
            after_first = plane.read_bytes()
            second = onboard.apply_onboard(entry, admin_env=str(admin))

        assert first.ok and second.ok
        assert vault.mint.call_count == 1, "a rerun minted a second SecretID"
        assert plane.read_bytes() == after_first
        assert not Path(str(plane) + ".bak").exists()
        assert {r.action.kind: r.status for r in second.results} == {
            "create_policy": "converged",
            "create_role": "converged",
            "write_plane_env": "converged",
            "write_kv": "skipped",
        }

    def test_rerun_does_not_rewrite_policy_or_role(self, tmp_path: Path) -> None:
        entry, admin, _ = self._setup(tmp_path)
        vault = FakeVault()
        with patch.object(onboard, "_admin_client", return_value=vault):
            onboard.apply_onboard(entry, admin_env=str(admin))
            vault.policy_write.reset_mock()
            vault.role_write.reset_mock()
            onboard.apply_onboard(entry, admin_env=str(admin))
        vault.policy_write.assert_not_called()
        vault.role_write.assert_not_called()

    def test_stale_role_id_triggers_rewrite_and_revokes_the_old_secret_id(
        self, tmp_path: Path
    ) -> None:
        entry, admin, plane = self._setup(tmp_path)
        plane.parent.mkdir(parents=True, exist_ok=True)
        plane.write_text(
            f"VAULT_ADDR={VAULT_ADDR}\nVAULT_ROLE_ID=stale-role\n"
            f"VAULT_SECRET_ID=stale-secret\n",
            encoding="utf-8",
        )
        plane.chmod(stat.S_IRUSR | stat.S_IWUSR)
        vault = FakeVault()
        with patch.object(onboard, "_admin_client", return_value=vault):
            report = onboard.apply_onboard(entry, admin_env=str(admin))

        row = next(r for r in report.results if r.action.kind == "write_plane_env")
        assert row.status == "applied"
        assert row.backup_path == str(plane) + ".bak"
        assert "stale secret_id revoked" in row.detail
        assert "role-id-abc" in plane.read_text(encoding="utf-8")
        assert vault.destroyed_accessors == ["accessor-for-stal"]

    def test_second_apply_over_an_existing_bak_does_not_crash(
        self, tmp_path: Path
    ) -> None:
        """`Path.rename` onto an existing .bak raises FileExistsError on Windows."""
        entry, admin, plane = self._setup(tmp_path)
        plane.parent.mkdir(parents=True, exist_ok=True)
        Path(str(plane) + ".bak").write_text("older backup\n", encoding="utf-8")
        plane.write_text("VAULT_ROLE_ID=stale\nVAULT_SECRET_ID=stale\n", encoding="utf-8")
        plane.chmod(stat.S_IRUSR | stat.S_IWUSR)
        vault = FakeVault()
        with patch.object(onboard, "_admin_client", return_value=vault):
            report = onboard.apply_onboard(entry, admin_env=str(admin))
        assert report.ok
        assert Path(str(plane) + ".bak").read_text(encoding="utf-8").startswith(
            "VAULT_ROLE_ID=stale"
        )

    def test_plane_write_never_uses_path_rename(self, tmp_path: Path) -> None:
        """Platform-independence guard: `Path.rename` is the Windows crash.

        Patching it to raise simulates the Windows semantics that broke a second
        `--apply`; `os.replace` must be what the writer actually calls.
        """
        entry, admin, plane = self._setup(tmp_path)
        plane.parent.mkdir(parents=True, exist_ok=True)
        plane.write_text("VAULT_ROLE_ID=stale\nVAULT_SECRET_ID=stale\n", encoding="utf-8")
        plane.chmod(stat.S_IRUSR | stat.S_IWUSR)
        vault = FakeVault()

        def windows_rename(self: Path, target: object) -> Path:
            raise FileExistsError(f"cannot rename onto existing {target}")

        with patch.object(Path, "rename", windows_rename), patch.object(
            onboard, "_admin_client", return_value=vault
        ):
            report = onboard.apply_onboard(entry, admin_env=str(admin))
        assert report.ok, [r.detail for r in report.results if not r.detail == ""]

    def test_plane_file_is_created_at_mode_0600(self, tmp_path: Path) -> None:
        if os.name != "posix":  # pragma: no cover — POSIX mode bits only
            pytest.skip("POSIX mode bits")
        entry, admin, plane = self._setup(tmp_path)
        with patch.object(onboard, "_admin_client", return_value=FakeVault()):
            onboard.apply_onboard(entry, admin_env=str(admin))
        assert plane.stat().st_mode & 0o777 == 0o600

    def test_plane_file_is_never_briefly_group_readable(
        self, tmp_path: Path
    ) -> None:
        """The chmod-after-write race: observe the mode at creation time."""
        if os.name != "posix":  # pragma: no cover — POSIX mode bits only
            pytest.skip("POSIX mode bits")
        entry, admin, plane = self._setup(tmp_path)
        observed: list[int] = []
        real_open = os.open

        def watched_open(path: object, flags: int, *args: int) -> int:
            fd = real_open(path, flags, *args)  # type: ignore[arg-type]
            if str(path).endswith(".acb-new"):
                observed.append(os.fstat(fd).st_mode & 0o777)
            return fd

        with patch.object(os, "open", watched_open), patch.object(
            onboard, "_admin_client", return_value=FakeVault()
        ):
            onboard.apply_onboard(entry, admin_env=str(admin))
        assert observed == [0o600]
        assert plane.stat().st_mode & 0o777 == 0o600

    def test_no_staging_file_is_left_behind(self, tmp_path: Path) -> None:
        entry, admin, plane = self._setup(tmp_path)
        with patch.object(onboard, "_admin_client", return_value=FakeVault()):
            onboard.apply_onboard(entry, admin_env=str(admin))
        assert not Path(str(plane) + ".acb-new").exists()

    def test_multi_harness_apply_mints_one_secret_id_per_plane(
        self, tmp_path: Path
    ) -> None:
        manifest = write_manifest(
            tmp_path,
            harnesses='["claude", "opencode"]',
            extra='vault_env = "qual-bot.env"\n',
        )
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        vault = FakeVault()
        with patch.object(onboard, "_admin_client", return_value=vault):
            report = onboard.apply_onboard(entry, admin_env=str(admin))
        assert report.ok
        assert vault.mint.call_count == 2
        for target in onboard.plane_targets(entry):
            assert target.path.is_file()


# ===========================================================================
# M7 — exception classes, abort, and rollback
# ===========================================================================


class TestM7ErrorsAndRollback:
    def _setup(self, tmp_path: Path) -> tuple[Capability, Path, Path]:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        return entry, admin, onboard.plane_targets(entry)[0].path

    def test_failed_policy_write_aborts_before_any_secret_exists(
        self, tmp_path: Path
    ) -> None:
        """The reviewed branch carried on: role bound to a dangling policy,
        SecretID minted, plane file written, value transited — exit 1 with
        secrets deposited under a broken structure."""
        entry, admin, plane = self._setup(tmp_path)
        vault = FakeVault(policy_write_error=Forbidden("no permission"))
        with patch.object(onboard, "_admin_client", return_value=vault):
            report = onboard.apply_onboard(
                entry, admin_env=str(admin), values={"password": CANARY}
            )

        assert not report.ok
        statuses = {r.action.kind: r.status for r in report.results}
        assert statuses["create_policy"] == "failed"
        assert statuses["create_role"] == "aborted"
        assert statuses["write_plane_env"] == "aborted"
        assert statuses["write_kv"] == "aborted"
        vault.role_write.assert_not_called()
        vault.mint.assert_not_called()
        vault.kv_write.assert_not_called()
        assert not plane.exists()

    def test_failed_kv_write_unwinds_everything_this_run_created(
        self, tmp_path: Path
    ) -> None:
        entry, admin, plane = self._setup(tmp_path)
        vault = FakeVault(kv_write_error=Forbidden("no permission"))
        with patch.object(onboard, "_admin_client", return_value=vault):
            report = onboard.apply_onboard(
                entry, admin_env=str(admin), values={"password": CANARY}
            )

        assert not report.ok
        assert vault.policies == {}, "policy created by this run was not removed"
        assert vault.roles == {}, "AppRole created by this run was not removed"
        assert not plane.exists(), "plane file created by this run was not removed"
        assert vault.destroyed_accessors == ["accessor-1"], (
            "the SecretID minted by this run was left live"
        )
        # Reverse order: the plane file, then the minted SecretID, then the
        # AppRole, then the policy.
        rolled_back = [r for r in report.results if r.status == "rolled_back"]
        assert [r.detail for r in rolled_back] == [
            f"restore the previous plane file at {plane}",
            "destroy the secret_id minted by this run",
            "delete AppRole 'acb-qual-bot' created by this run",
            "delete policy 'acb-qual-bot' created by this run",
        ]

    def test_unwind_restores_a_pre_existing_plane_file(self, tmp_path: Path) -> None:
        entry, admin, plane = self._setup(tmp_path)
        plane.parent.mkdir(parents=True, exist_ok=True)
        plane.write_text("VAULT_ROLE_ID=old\nVAULT_SECRET_ID=old\n", encoding="utf-8")
        plane.chmod(stat.S_IRUSR | stat.S_IWUSR)
        vault = FakeVault(kv_write_error=Forbidden("no permission"))
        with patch.object(onboard, "_admin_client", return_value=vault):
            onboard.apply_onboard(
                entry, admin_env=str(admin), values={"password": CANARY}
            )
        assert plane.read_text(encoding="utf-8") == (
            "VAULT_ROLE_ID=old\nVAULT_SECRET_ID=old\n"
        )

    def test_unwind_leaves_pre_existing_vault_objects_alone(
        self, tmp_path: Path
    ) -> None:
        """Compensation removes what *this run* created — not operator state."""
        entry, admin, _ = self._setup(tmp_path)
        vault = converged_vault(entry, kv_write_error=Forbidden("no permission"))
        with patch.object(onboard, "_admin_client", return_value=vault):
            report = onboard.apply_onboard(
                entry, admin_env=str(admin), values={"password": CANARY}
            )
        assert not report.ok
        assert onboard.policy_name(entry) in vault.policies
        assert onboard.role_name(entry) in vault.roles
        vault.sys.delete_policy.assert_not_called()
        vault.auth.approle.delete_role.assert_not_called()

    def test_failed_rollback_is_reported_not_swallowed(self, tmp_path: Path) -> None:
        entry, admin, _ = self._setup(tmp_path)
        vault = FakeVault(
            kv_write_error=Forbidden("no permission"),
            delete_policy_error=Forbidden("cannot delete"),
        )
        with patch.object(onboard, "_admin_client", return_value=vault):
            report = onboard.apply_onboard(
                entry, admin_env=str(admin), values={"password": CANARY}
            )
        failures = [r for r in report.results if r.status == "rollback_failed"]
        assert len(failures) == 1
        assert "manual cleanup" in failures[0].detail

    @pytest.mark.parametrize(
        "exc",
        [
            InvalidRequest("bad request"),
            Forbidden("denied"),
            ConnectionRefusedError("connection refused"),
            OSError("disk on fire"),
            RuntimeError("unexpected"),
        ],
    )
    def test_no_exception_class_escapes_as_a_traceback(
        self, tmp_path: Path, exc: BaseException,
        capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        admin = write_admin_env(tmp_path)
        code = run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin), "--json"],
            FakeVault(policy_write_error=exc),
        )
        captured = capsys.readouterr()
        assert code == 1
        assert "Traceback" not in captured.out + captured.err
        assert json.loads(captured.out)["error"]["code"] == "ONBOARD_FAILED"

    def test_vault_unreachable_is_a_retryable_error_not_a_traceback(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Vault being down is the *common* failure and used to be a traceback."""
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        admin = write_admin_env(tmp_path)
        with patch.object(
            onboard,
            "_admin_client",
            side_effect=onboard.OnboardError(
                "cannot reach Vault at http://127.0.0.1:8200 (ConnectionError)",
                retryable=True,
            ),
        ):
            code = main(
                ["onboard", "cred:qual-bot", "-m", str(manifest), "--check",
                 "--admin-env", str(admin), "--json"]
            )
        payload = json.loads(capsys.readouterr().out)
        assert code == 1
        assert payload["error"]["code"] == "ONBOARD_ERROR"
        assert payload["error"]["retryable"] is True

    def test_connection_failure_during_auth_is_classified_retryable(
        self, tmp_path: Path
    ) -> None:
        pytest.importorskip("hvac")
        admin = write_admin_env(tmp_path)
        plane = onboard.load_admin_plane(str(admin))
        assert plane is not None
        broken = MagicMock()
        broken.is_authenticated.side_effect = ConnectionRefusedError("refused")
        with patch("hvac.Client", return_value=broken):
            with pytest.raises(onboard.OnboardError) as excinfo:
                onboard._admin_client(plane)
        assert excinfo.value.retryable is True

    def test_unreadable_existing_plane_file_aborts_rather_than_replacing(
        self, tmp_path: Path
    ) -> None:
        entry, admin, plane = self._setup(tmp_path)
        plane.parent.mkdir(parents=True, exist_ok=True)
        plane.write_text("VAULT_ROLE_ID=x\n", encoding="utf-8")
        vault = FakeVault()

        real_read = Path.read_text

        def deny(self: Path, *a: object, **kw: object) -> str:
            if self == plane:
                raise PermissionError(13, "Permission denied")
            return real_read(self, *a, **kw)  # type: ignore[arg-type]

        with patch.object(Path, "read_text", deny), patch.object(
            onboard, "_admin_client", return_value=vault
        ):
            report = onboard.apply_onboard(entry, admin_env=str(admin))
        row = next(r for r in report.results if r.action.kind == "write_plane_env")
        assert row.status == "failed"
        assert "cannot read existing plane file" in row.detail
        vault.mint.assert_not_called()

    def test_probe_classification(self) -> None:
        assert onboard._classify(InvalidPath("nope")).present is False
        assert onboard._classify(Forbidden("nope")).present is None
        assert onboard._classify(ConnectionRefusedError()).present is None
        assert "unreachable" in onboard._classify(ConnectionRefusedError()).reason


class TestExceptionNamesArePinned:
    """The stand-ins above must keep matching real hvac, or the guards are dead.

    `onboard` classifies by `type(exc).__name__` so it never imports the
    optional extra; that only works while these names are real.
    """

    def test_hvac_exception_names_exist(self) -> None:
        exceptions = pytest.importorskip("hvac.exceptions")
        assert exceptions.InvalidPath.__name__ in onboard._ABSENT_EXC_NAMES
        assert exceptions.Forbidden.__name__ in onboard._DENIED_EXC_NAMES
        assert exceptions.InvalidRequest.__name__ == InvalidRequest.__name__

    def test_requests_connection_error_is_classified_retryable(self) -> None:
        requests_exceptions = pytest.importorskip("requests.exceptions")
        assert onboard._is_retryable(requests_exceptions.ConnectionError())

    def test_real_cas_conflict_message_is_recognised(self) -> None:
        exceptions = pytest.importorskip("hvac.exceptions")
        real = exceptions.InvalidRequest(
            "check-and-set parameter did not match the current version"
        )
        assert onboard._is_cas_conflict(real)


# ===========================================================================
# Dry run performs no I/O
# ===========================================================================


class TestDryRunPerformsNoIO:
    def test_dry_run_contacts_no_vault_and_writes_no_file(
        self, tmp_path: Path
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        before = {p for p in tmp_path.rglob("*")}
        with patch.object(onboard, "_admin_client") as admin_client:
            code = main(["onboard", "cred:qual-bot", "-m", str(manifest)])
        assert code == 0
        admin_client.assert_not_called()
        assert {p for p in tmp_path.rglob("*")} == before

    def test_dry_run_survives_a_read_only_filesystem(self, tmp_path: Path) -> None:
        """No write primitive is reachable from the dry-run path at all."""
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')

        def forbidden(*a: object, **kw: object) -> object:
            raise AssertionError("dry run attempted a write")

        with patch.object(Path, "write_text", forbidden), patch.object(
            Path, "write_bytes", forbidden
        ), patch.object(Path, "chmod", forbidden), patch.object(
            os, "replace", forbidden
        ), patch.object(os, "open", forbidden):
            assert main(["onboard", "cred:qual-bot", "-m", str(manifest)]) == 0

    def test_dry_run_annotates_state_when_an_admin_plane_is_supplied(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        entry = parse_manifest(manifest)[0]
        admin = write_admin_env(tmp_path)
        code = run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--admin-env",
             str(admin), "--json"],
            converged_vault(entry),
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 0
        assert payload["annotated"] is True
        assert payload["plan"][0]["state"] == "ok"

    def test_dry_run_makes_no_probe_without_an_admin_plane(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        main(["onboard", "cred:qual-bot", "-m", str(manifest), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["annotated"] is False
        assert all(step["state"] == "unknown" for step in payload["plan"])


# ===========================================================================
# The no-secrets property, with teeth
# ===========================================================================


class TestNoSecretsInOutput:
    """`f"KV write failed: {exc}"` printed raw upstream exception text.

    hvac/requests can echo the request body, and on the KV write path the
    request body *is* the secret. These cases raise exceptions that DO carry
    secret-looking text and assert it never surfaces.
    """

    def _manifest(self, tmp_path: Path) -> tuple[Path, Path]:
        return (
            write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n'),
            write_admin_env(tmp_path),
        )

    @pytest.mark.parametrize(
        "knob",
        [
            "policy_write_error",
            "role_write_error",
            "secret_id_error",
            "kv_write_error",
            "policy_read_error",
            "metadata_error",
        ],
    )
    @pytest.mark.parametrize("json_mode", [True, False])
    def test_secret_bearing_exception_text_never_surfaces(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
        knob: str,
        json_mode: bool,
    ) -> None:
        manifest, admin = self._manifest(tmp_path)
        leaky = InvalidRequest(
            f'failed to write: {{"username":"admin","password":"{CANARY}"}}'
        )
        assert CANARY in str(leaky), "the fixture must actually carry the secret"
        argv = [
            "onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
            "--admin-env", str(admin), "--values-from", "stdin",
        ]
        if json_mode:
            argv.append("--json")
        with patch("sys.stdin.read", return_value=json.dumps({"password": CANARY})):
            run_cli(argv, FakeVault(**{knob: leaky}))
        captured = capsys.readouterr()
        assert CANARY not in captured.out + captured.err

    def test_minted_secret_id_reaches_the_plane_file_and_nothing_else(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest, admin = self._manifest(tmp_path)
        entry = parse_manifest(manifest)[0]
        plane = onboard.plane_targets(entry)[0].path
        code = run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin), "--json"],
            FakeVault(secret_id_value=CANARY),
        )
        captured = capsys.readouterr()
        assert code == 0
        assert CANARY in plane.read_text(encoding="utf-8")  # it must land there
        assert CANARY not in captured.out + captured.err   # and nowhere else

    def test_transited_value_never_surfaces_on_success(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest, admin = self._manifest(tmp_path)
        values_file = tmp_path / "values.json"
        values_file.write_text(
            json.dumps({"username": "admin", "password": CANARY}), encoding="utf-8"
        )
        vault = FakeVault()
        code = run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin), "--values-from", f"file:{values_file}",
             "--json"],
            vault,
        )
        captured = capsys.readouterr()
        assert code == 0
        # The value did reach Vault (so the absence above is not vacuous)...
        assert vault.written_secrets == [{"username": "admin", "password": CANARY}]
        # ...and did not reach output or provenance.
        assert CANARY not in captured.out + captured.err
        log = tmp_path / "state" / "provenance.jsonl"
        assert log.is_file()
        assert CANARY not in log.read_text(encoding="utf-8")

    def test_malformed_values_json_does_not_echo_the_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest, admin = self._manifest(tmp_path)
        values_file = tmp_path / "values.json"
        values_file.write_text(f'{{"password": "{CANARY}"', encoding="utf-8")
        code = main(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin), "--values-from", f"file:{values_file}"]
        )
        captured = capsys.readouterr()
        assert code == 2
        assert CANARY not in captured.out + captured.err

    def test_sanitize_returns_only_a_class_name(self) -> None:
        assert onboard._sanitize(InvalidRequest(f"password={CANARY}")) == (
            "InvalidRequest"
        )

    def test_cas_conflict_detection_does_not_leak_the_inspected_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest, admin = self._manifest(tmp_path)
        conflict = InvalidRequest(
            f'check-and-set parameter did not match the current version; '
            f'body={{"password":"{CANARY}"}}'
        )
        assert onboard._is_cas_conflict(conflict)
        with patch("sys.stdin.read", return_value=json.dumps({"password": CANARY})):
            exit_code = run_cli(
                ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
                 "--admin-env", str(admin), "--values-from", "stdin", "--json"],
                FakeVault(kv_write_error=conflict),
            )
        captured = capsys.readouterr()
        assert exit_code == 0  # never-overwrite held; structure is fine
        assert CANARY not in captured.out + captured.err


# ===========================================================================
# M8 — exit-code taxonomy
# ===========================================================================


class TestM8ExitCodes:
    """0 success / 1 operational / 2 usage. Exit 2 no longer means three things."""

    def test_dry_run_succeeds_with_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        assert main(["onboard", "cred:qual-bot", "-m", str(manifest)]) == 0
        assert "dry run" in capsys.readouterr().out

    def test_dry_run_json_is_a_single_document(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        main(["onboard", "cred:qual-bot", "-m", str(manifest), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["mode"] == "dry_run"
        assert payload["ok"] is True

    @pytest.mark.parametrize(
        ("argv_tail", "code"),
        [
            (["--check", "--apply"], 2),
            (["--values-from", "bogus", "--apply"], 2),
            (["--values-from", "k8s:ns/secret", "--apply"], 2),
        ],
    )
    def test_usage_errors_exit_two(
        self, tmp_path: Path, argv_tail: list[str], code: int
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        admin = write_admin_env(tmp_path)
        assert main(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--admin-env",
             str(admin), *argv_tail]
        ) == code

    def test_invalid_capability_id_is_usage(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["onboard", "not-a-cap-id"]) == 2
        assert "invalid capability ID" in capsys.readouterr().err

    def test_capability_not_in_manifest_is_usage(self, tmp_path: Path) -> None:
        manifest = write_manifest(tmp_path)
        assert main(["onboard", "cred:absent", "-m", str(manifest)]) == 2

    def test_missing_manifest_is_operational(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        code = main(
            ["onboard", "cred:qual-bot", "-m", str(tmp_path / "nope.toml"), "--json"]
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 1
        assert payload["error"]["code"] == "MANIFEST_ERROR"

    def test_refusal_is_operational_not_usage(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path, extra='source = "suite"\n')
        code = main(["onboard", "cred:qual-bot", "-m", str(manifest), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert code == 1
        assert payload["error"]["code"] == "ONBOARD_REFUSED"

    def test_check_clean_zero_not_clean_one(self, tmp_path: Path) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        assert main(["onboard", "cred:qual-bot", "-m", str(manifest), "--check"]) == 1

    def test_apply_failure_envelope_carries_partial_counts(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        admin = write_admin_env(tmp_path)
        values_file = tmp_path / "values.json"
        values_file.write_text(json.dumps({"password": "x"}), encoding="utf-8")
        code = run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin), "--values-from", f"file:{values_file}",
             "--json"],
            FakeVault(kv_write_error=Forbidden("denied")),
        )
        payload = json.loads(capsys.readouterr().out)
        assert code == 1
        assert payload["error"]["code"] == "ONBOARD_FAILED"
        assert payload["error"]["partial"]["failed"] >= 1
        assert payload["error"]["partial"]["succeeded"] >= 0

    def test_every_error_envelope_satisfies_the_contract(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Validated by the conformance kit's own envelope checker."""
        conformance = pytest.importorskip("agent_suite.conformance")
        manifest = write_manifest(tmp_path, extra='source = "suite"\n')
        admin = write_admin_env(tmp_path)
        cases: list[list[str]] = [
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--json"],
            ["onboard", "cred:absent", "-m", str(manifest), "--json"],
            ["onboard", "bogus", "--json"],
            ["onboard", "cred:qual-bot", "-m", str(tmp_path / "no.toml"), "--json"],
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--check", "--apply",
             "--json"],
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin), "--values-from", "bogus", "--json"],
        ]
        for argv in cases:
            capsys.readouterr()
            code = main(argv)
            document = json.loads(capsys.readouterr().out)
            assert code != 0, argv
            assert conformance.validate_envelope(document) == [], argv


class TestProvenance:
    def test_apply_emits_one_event_per_step(self, tmp_path: Path) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        admin = write_admin_env(tmp_path)
        assert run_cli(
            ["onboard", "cred:qual-bot", "-m", str(manifest), "--apply",
             "--admin-env", str(admin)],
            FakeVault(),
        ) == 0
        log = tmp_path / "state" / "provenance.jsonl"
        events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        assert [e["action"] for e in events] == [
            "create_policy", "create_role", "write_plane_env", "write_kv"
        ]
        assert all(e["purpose"] == "onboard" for e in events)

    def test_dry_run_and_check_emit_nothing(self, tmp_path: Path) -> None:
        manifest = write_manifest(tmp_path, extra='vault_env = "qual-bot.env"\n')
        main(["onboard", "cred:qual-bot", "-m", str(manifest)])
        main(["onboard", "cred:qual-bot", "-m", str(manifest), "--check"])
        assert not (tmp_path / "state" / "provenance.jsonl").exists()
