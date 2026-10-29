"""`acb doctor --boundary` (Plan 011 §3 / Plan 012 §6): read-only blast-radius checks.

kubectl is faked two ways: a script on a private PATH (covers real subprocess
behaviour: no shell, literal argv, minimal env) and an injected runner (covers
timeout and platform-independent logic). Vault is faked with a stand-in client;
the WI-016 client-construction invariants are pinned against a recording hvac.
"""

from __future__ import annotations

import io
import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_capability_broker import boundary as boundary_mod
from agent_capability_broker.boundary import (
    VAULT_ADMIN_PATHS,
    BoundaryCheck,
    kubeconfig_files,
    run_boundary_checks,
)
from agent_capability_broker.cli import main
from agent_capability_broker.model import BoundaryConfig

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="fake kubectl is a sh script")

CANARY = "CANARY-TOKEN-DO-NOT-PRINT"  # a stand-in secret planted where output must never reach
NS = "example-vault"

CLUSTER_ADMIN = "auth can-i * * --all-namespaces"
VAULT_SECRETS = f"auth can-i get secrets -n {NS}"
VAULT_EXEC = f"auth can-i create pods/exec -n {NS}"


def _by_name(checks: Sequence[BoundaryCheck]) -> dict[str, BoundaryCheck]:
    return {c.name: c for c in checks}


# --- a fake kubectl on a private PATH ----------------------------------------------


class FakeKubectl:
    def __init__(self, root: Path, answers: Mapping[str, str], *, stderr: str = "") -> None:
        self.bin = root / "bin"
        self.bin.mkdir()
        self.log = root / "kubectl.log"
        self.kubeconfig = root / "kubeconfig"
        # The kubeconfig holds a canary "credential": no check may ever echo it.
        self.kubeconfig.write_text(f"users:\n- user:\n    token: {CANARY}\n", encoding="utf-8")
        self.kubeconfig.chmod(0o600)
        self.home = root / "home"
        self.home.mkdir()
        cases = "\n".join(f'  "{k}") echo "{v}" ;;' for k, v in answers.items())
        script = (
            "#!/bin/sh\n"
            f'echo "$*" >> "{self.log}"\n'
            f'echo "{stderr}" >&2\n'
            'case "$*" in\n'
            f"{cases}\n"
            '  *) echo "error: unexpected query" ;;\n'
            "esac\n"
        )
        exe = self.bin / "kubectl"
        exe.write_text(script, encoding="utf-8")
        exe.chmod(exe.stat().st_mode | stat.S_IXUSR)

    def environ(self, **extra: str) -> dict[str, str]:
        return {
            "PATH": str(self.bin),
            "HOME": str(self.home),
            "KUBECONFIG": str(self.kubeconfig),
            **extra,
        }

    def queries(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


def _no_vault() -> object:
    class _Sys:
        def get_capabilities(self, paths: list[str]) -> dict[str, object]:
            return {p: ["deny"] for p in paths}

    class _Client:
        sys = _Sys()

    return _Client()


@posix_only
def test_all_no_is_ok_and_asks_the_documented_questions(tmp_path: Path) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "no", VAULT_SECRETS: "no", VAULT_EXEC: "no"})
    cfg = BoundaryConfig(vault_namespace=NS)
    checks = _by_name(run_boundary_checks(cfg, environ=fake.environ(), vault_client=_no_vault()))
    assert checks["boundary.kubeconfig.cluster-admin"].verdict == "ok"
    assert checks["boundary.kubeconfig.vault-secrets"].verdict == "ok"
    assert checks["boundary.kubeconfig.vault-exec"].verdict == "ok"
    assert checks["boundary.kubeconfig.mode"].verdict == "ok"
    # Exactly the three questions, with the wildcards passed literally (no shell glob).
    assert fake.queries() == [CLUSTER_ADMIN, VAULT_SECRETS, VAULT_EXEC]


@posix_only
@pytest.mark.parametrize(
    ("yes_query", "check"),
    [
        (CLUSTER_ADMIN, "boundary.kubeconfig.cluster-admin"),
        (VAULT_SECRETS, "boundary.kubeconfig.vault-secrets"),
        (VAULT_EXEC, "boundary.kubeconfig.vault-exec"),
    ],
)
def test_any_yes_fails_only_that_check(tmp_path: Path, yes_query: str, check: str) -> None:
    answers = {CLUSTER_ADMIN: "no", VAULT_SECRETS: "no", VAULT_EXEC: "no", yes_query: "yes"}
    fake = FakeKubectl(tmp_path, answers)
    checks = _by_name(
        run_boundary_checks(
            BoundaryConfig(vault_namespace=NS), environ=fake.environ(), vault_client=_no_vault()
        )
    )
    assert checks[check].verdict == "fail"
    assert checks[check].detail.startswith("yes")
    others = [c for n, c in checks.items() if n.startswith("boundary.kubeconfig.") and n != check]
    assert all(c.verdict == "ok" for c in others)


@posix_only
def test_without_a_vault_namespace_only_the_cluster_wide_question_is_asked(tmp_path: Path) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "no"})
    checks = _by_name(
        run_boundary_checks(BoundaryConfig(), environ=fake.environ(), vault_client=_no_vault())
    )
    kube = [
        n for n in checks
        if n.startswith("boundary.kubeconfig.") and n != "boundary.kubeconfig.mode"
    ]
    assert kube == ["boundary.kubeconfig.cluster-admin"]
    assert fake.queries() == [CLUSTER_ADMIN]


@posix_only
def test_kubectl_missing_is_unknown_with_a_reason_not_a_crash(tmp_path: Path) -> None:
    fake = FakeKubectl(tmp_path, {})
    (fake.bin / "kubectl").unlink()
    checks = run_boundary_checks(
        BoundaryConfig(vault_namespace=NS), environ=fake.environ(), vault_client=_no_vault()
    )
    kube = [c for c in checks if c.name.startswith("boundary.kubeconfig.")]
    assert len(kube) == 3
    assert all(c.verdict == "unknown" and "kubectl not found" in c.detail for c in kube)


@posix_only
def test_no_kubeconfig_is_unknown_with_a_reason(tmp_path: Path) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "yes"})
    fake.kubeconfig.unlink()
    checks = _by_name(
        run_boundary_checks(BoundaryConfig(), environ=fake.environ(), vault_client=_no_vault())
    )
    check = checks["boundary.kubeconfig.cluster-admin"]
    assert check.verdict == "unknown" and "no kubeconfig" in check.detail
    assert fake.queries() == []  # never asked: nothing to ask about


@posix_only
def test_unparseable_answer_is_unknown_and_stderr_is_never_surfaced(tmp_path: Path) -> None:
    fake = FakeKubectl(tmp_path, {}, stderr="dial tcp 203.0.113.9:6443: connection refused")
    checks = _by_name(
        run_boundary_checks(BoundaryConfig(), environ=fake.environ(), vault_client=_no_vault())
    )
    check = checks["boundary.kubeconfig.cluster-admin"]
    assert check.verdict == "unknown"
    assert "203.0.113.9" not in check.detail and "refused" not in check.detail


@posix_only
def test_kubeconfig_mode_wider_than_0600_warns(tmp_path: Path) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "no"})
    fake.kubeconfig.chmod(0o664)
    checks = _by_name(
        run_boundary_checks(BoundaryConfig(), environ=fake.environ(), vault_client=_no_vault())
    )
    mode = checks["boundary.kubeconfig.mode"]
    assert mode.verdict == "warn"
    assert "0664" in mode.detail and "0600" in mode.detail
    # The authority question still runs and is independent of the mode.
    assert checks["boundary.kubeconfig.cluster-admin"].verdict == "ok"


@posix_only
@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_kubeconfig_mode_0600_or_narrower_is_ok(tmp_path: Path, mode: int) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "no"})
    fake.kubeconfig.chmod(mode)
    checks = _by_name(
        run_boundary_checks(BoundaryConfig(), environ=fake.environ(), vault_client=_no_vault())
    )
    assert checks["boundary.kubeconfig.mode"].verdict == "ok"


@posix_only
def test_nothing_sensitive_reaches_the_output(tmp_path: Path) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "yes", VAULT_SECRETS: "no", VAULT_EXEC: "no"})
    checks = run_boundary_checks(
        BoundaryConfig(vault_namespace=NS, ssh_admin_targets=("hv.example.invalid",)),
        environ=fake.environ(VAULT_TOKEN=CANARY),
        vault_client=_no_vault(),
    )
    rendered = json.dumps([c.as_check() for c in checks])
    assert CANARY not in rendered


# --- the injected runner: env, timeout, no shell ----------------------------------


def _kube_env(tmp_path: Path) -> dict[str, str]:
    (tmp_path / "bin").mkdir()
    exe = tmp_path / "bin" / ("kubectl.exe" if sys.platform == "win32" else "kubectl")
    exe.write_text("", encoding="utf-8")
    exe.chmod(0o755)
    cfg = tmp_path / "kubeconfig"
    cfg.write_text("{}", encoding="utf-8")
    cfg.chmod(0o600)
    return {"PATH": str(tmp_path / "bin"), "HOME": str(tmp_path), "KUBECONFIG": str(cfg)}


def test_runner_gets_a_minimal_environment(tmp_path: Path) -> None:
    seen: list[Mapping[str, str]] = []

    def runner(argv: Sequence[str], timeout: float, env: Mapping[str, str]) -> tuple[int, str]:
        seen.append(env)
        assert timeout > 0
        return 1, "no\n"

    environ = _kube_env(tmp_path) | {
        "VAULT_TOKEN": CANARY,
        "AWS_SECRET_ACCESS_KEY": CANARY,
        "HTTPS_PROXY": "http://proxy.example.invalid",
    }
    run_boundary_checks(BoundaryConfig(), environ=environ, runner=runner, vault_client=_no_vault())
    assert seen, "the runner must have been used"
    for env in seen:
        assert CANARY not in "".join(env.values())
        assert set(env) <= {"PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "KUBECONFIG",
                            "TMPDIR", "TEMP", "LC_ALL"}


def test_runner_timeout_is_unknown(tmp_path: Path) -> None:
    def runner(argv: Sequence[str], timeout: float, env: Mapping[str, str]) -> tuple[int, str]:
        raise TimeoutError("hung")

    checks = _by_name(
        run_boundary_checks(
            BoundaryConfig(), environ=_kube_env(tmp_path), runner=runner, vault_client=_no_vault()
        )
    )
    check = checks["boundary.kubeconfig.cluster-admin"]
    assert check.verdict == "unknown" and "timed out" in check.detail


def test_runner_oserror_is_unknown(tmp_path: Path) -> None:
    def runner(argv: Sequence[str], timeout: float, env: Mapping[str, str]) -> tuple[int, str]:
        raise PermissionError("not executable")

    checks = _by_name(
        run_boundary_checks(
            BoundaryConfig(), environ=_kube_env(tmp_path), runner=runner, vault_client=_no_vault()
        )
    )
    assert checks["boundary.kubeconfig.cluster-admin"].verdict == "unknown"


def test_default_runner_is_bounded_and_shell_free(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs, argv=argv)
        return subprocess.CompletedProcess(argv, 1, stdout="no\n", stderr="")

    monkeypatch.setattr(boundary_mod.subprocess, "run", fake_run)
    rc, out = boundary_mod._run(["kubectl", "auth", "can-i", "*", "*"], 7.0, {"PATH": "/x"})
    assert (rc, out) == (1, "no\n")
    assert captured["shell"] is False
    assert captured["timeout"] == 7.0
    assert captured["env"] == {"PATH": "/x"}
    assert captured["stdin"] == subprocess.DEVNULL


def test_default_runner_converts_a_subprocess_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(argv, 1.0)

    monkeypatch.setattr(boundary_mod.subprocess, "run", fake_run)
    with pytest.raises(TimeoutError):
        boundary_mod._run(["kubectl"], 1.0, {})


def test_kubeconfig_files_prefers_the_env_list_then_the_default(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.write_text("x", encoding="utf-8")
    env = {"KUBECONFIG": os.pathsep.join([str(a), str(b), ""]), "HOME": str(tmp_path)}
    assert kubeconfig_files(env) == [a]  # only the ones that exist
    default = tmp_path / ".kube" / "config"
    default.parent.mkdir()
    default.write_text("x", encoding="utf-8")
    assert kubeconfig_files({"HOME": str(tmp_path)}) == [default]


# --- the VM's Vault identity -------------------------------------------------------


class _Sys:
    def __init__(self, reply: object) -> None:
        self.reply = reply
        self.asked: list[list[str]] = []

    def get_capabilities(self, paths: list[str]) -> object:
        self.asked.append(list(paths))
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply


class _Client:
    def __init__(self, reply: object) -> None:
        self.sys = _Sys(reply)


def _vault(reply: object) -> tuple[BoundaryCheck, _Client]:
    client = _Client(reply)
    checks = _by_name(
        run_boundary_checks(
            BoundaryConfig(), environ={"PATH": "", "HOME": "/nonexistent"}, vault_client=client
        )
    )
    return checks["boundary.vault-identity"], client


def _all(caps: list[str]) -> dict[str, list[str]]:
    return {p: list(caps) for p in VAULT_ADMIN_PATHS}


def test_vault_all_deny_is_ok_and_asks_the_four_admin_paths() -> None:
    check, client = _vault(_all(["deny"]))
    assert check.verdict == "ok"
    assert client.sys.asked == [list(VAULT_ADMIN_PATHS)]
    assert set(VAULT_ADMIN_PATHS) == {"sys/policies/acl/x", "auth/x", "identity/x", "sys/mounts"}


@pytest.mark.parametrize("granted", [["read"], ["list"], ["create", "update"], ["sudo"], ["root"],
                                     ["deny", "read"]])
def test_vault_any_capability_beyond_deny_fails(granted: list[str]) -> None:
    reply = _all(["deny"]) | {"identity/x": granted}
    check, _ = _vault(reply)
    assert check.verdict == "fail"
    assert "identity/x" in check.detail
    assert "sys/mounts" not in check.detail  # only the offending path is named


def test_vault_reply_nested_under_data_is_understood() -> None:
    check, _ = _vault({"data": _all(["deny"])})
    assert check.verdict == "ok"
    check, _ = _vault({"data": _all(["deny"]) | {"sys/mounts": ["read"]}})
    assert check.verdict == "fail"


def test_vault_reply_missing_a_path_is_unknown() -> None:
    reply = _all(["deny"])
    del reply["auth/x"]
    check, _ = _vault(reply)
    assert check.verdict == "unknown" and "auth/x" in check.detail


def test_vault_transport_error_is_unknown_and_does_not_leak_its_message() -> None:
    check, _ = _vault(ConnectionError(f"https://vault.example.invalid failed {CANARY}"))
    assert check.verdict == "unknown"
    assert "ConnectionError" in check.detail
    assert CANARY not in check.detail and "vault.example.invalid" not in check.detail


@pytest.fixture
def clean_vault_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """No ambient Vault configuration, and a decoy developer token in $HOME."""
    for key in list(os.environ):
        if key.startswith("VAULT") or key.startswith("ACB_VAULT"):
            monkeypatch.delenv(key)
    monkeypatch.delenv("AGENT_SUITE_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(exist_ok=True)
    (tmp_path / "home" / ".vault-token").write_text(CANARY, encoding="utf-8")
    return tmp_path


def test_no_vault_addr_is_unknown(clean_vault_env: Path) -> None:
    checks = _by_name(
        run_boundary_checks(BoundaryConfig(), environ={"PATH": "", "HOME": "/nonexistent"})
    )
    check = checks["boundary.vault-identity"]
    assert check.verdict == "unknown" and "VAULT_ADDR" in check.detail


def test_hvac_absent_is_unknown_with_the_install_hint(
    clean_vault_env: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(sys.modules, "hvac", None)  # `import hvac` now raises ImportError
    checks = _by_name(
        run_boundary_checks(BoundaryConfig(), environ={"PATH": "", "HOME": "/nonexistent"})
    )
    check = checks["boundary.vault-identity"]
    assert check.verdict == "unknown" and "[cred]" in check.detail


class TestVaultClientInvariants:
    """The boundary probe goes through cred_vault's client builder (WI-016)."""

    @pytest.fixture(autouse=True)
    def _hvac(self) -> None:
        pytest.importorskip("hvac", reason="needs the [cred] extra")

    def _recorder(self, monkeypatch: pytest.MonkeyPatch, reply: object) -> list[dict[str, object]]:
        import hvac

        built: list[dict[str, object]] = []

        class _Auth:
            class approle:  # noqa: N801
                @staticmethod
                def login(**kwargs: object) -> None:
                    built.append({"approle_login": True})

        class _Recorder:
            def __init__(self, url: str | None = None, token: str | None = None, **kw: object):
                built.append({"url": url, "token": token})
                self.token = token
                self.auth = _Auth()
                self.sys = _Sys(reply)

        monkeypatch.setattr(hvac, "Client", _Recorder)
        return built

    def test_token_is_the_empty_string_never_ambient(
        self, clean_vault_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = self._recorder(monkeypatch, _all(["deny"]))
        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.invalid")
        monkeypatch.setenv("VAULT_ROLE_ID", "role")
        monkeypatch.setenv("VAULT_SECRET_ID", "secret")
        checks = _by_name(
            run_boundary_checks(BoundaryConfig(), environ={"PATH": "", "HOME": "/nonexistent"})
        )
        assert checks["boundary.vault-identity"].verdict == "ok"
        assert built[0]["token"] == ""  # not None (hvac would read ~/.vault-token)
        assert {"approle_login": True} in built

    def test_incomplete_approle_fails_closed_to_unknown_not_a_token(
        self, clean_vault_env: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        built = self._recorder(monkeypatch, _all(["root"]))
        monkeypatch.setenv("VAULT_ADDR", "https://vault.example.invalid")
        monkeypatch.setenv("VAULT_ROLE_ID", "role")  # a SecretID is declared nowhere
        monkeypatch.setenv("VAULT_TOKEN", CANARY)  # an explicit token must not rescue it
        checks = _by_name(
            run_boundary_checks(BoundaryConfig(), environ={"PATH": "", "HOME": "/nonexistent"})
        )
        check = checks["boundary.vault-identity"]
        assert check.verdict == "unknown" and "SecretID" in check.detail
        assert CANARY not in check.detail
        assert all("approle_login" not in b for b in built)


# --- declared admin SSH targets ------------------------------------------------------


def test_declared_ssh_targets_are_reported_unknown_checked_by_hand() -> None:
    cfg = BoundaryConfig(ssh_admin_targets=("hv-01.example.invalid", "node-02.example.invalid"))
    checks = _by_name(
        run_boundary_checks(
            cfg, environ={"PATH": "", "HOME": "/nonexistent"}, vault_client=_no_vault()
        )
    )
    for host in cfg.ssh_admin_targets:
        check = checks[f"boundary.ssh-admin:{host}"]
        assert check.verdict == "unknown"
        assert "checked by hand" in check.detail


def test_no_ssh_targets_means_no_ssh_checks() -> None:
    checks = run_boundary_checks(
        BoundaryConfig(), environ={"PATH": "", "HOME": "/nonexistent"}, vault_client=_no_vault()
    )
    assert not [c for c in checks if c.name.startswith("boundary.ssh-admin")]


def test_ssh_is_never_attempted(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*a: object, **k: object) -> None:
        raise AssertionError("subprocess used with no kubectl to run")

    monkeypatch.setattr(boundary_mod.subprocess, "run", forbidden)
    run_boundary_checks(
        BoundaryConfig(ssh_admin_targets=("hv-01.example.invalid",)),
        environ={"PATH": "", "HOME": "/nonexistent"},
        vault_client=_no_vault(),
    )


# --- the check dict -------------------------------------------------------------------


def test_unknown_renders_as_the_suite_warn() -> None:
    d = BoundaryCheck("boundary.x", "unknown", "why").as_check()
    assert d["status"] == "warn" and d["verdict"] == "unknown" and d["kind"] == "boundary"
    assert {c: BoundaryCheck("n", c, "").as_check()["status"] for c in ("ok", "warn", "fail")} == {
        "ok": "ok", "warn": "warn", "fail": "fail"
    }


# --- through the CLI ------------------------------------------------------------------


def _cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fake: FakeKubectl) -> Path:
    for var, name in {
        "ACB_OPENCODE_CONFIG": "oc.json",
        "ACB_CLAUDE_SETTINGS": "claude.json",
        "ACB_HERMES_CONFIG": "hermes.yaml",
        "ACB_ZCODE_CONFIG": "zcode.json",
    }.items():
        monkeypatch.setenv(var, str(tmp_path / "none" / name))
    monkeypatch.setenv("ACB_CODEX_HOME", str(tmp_path / "none" / "codex"))
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("PATH", str(fake.bin))
    monkeypatch.setenv("HOME", str(fake.home))
    monkeypatch.setenv("KUBECONFIG", str(fake.kubeconfig))
    for key in list(os.environ):
        if key.startswith("VAULT") or key.startswith("ACB_VAULT"):
            monkeypatch.delenv(key)
    monkeypatch.delenv("AGENT_SUITE_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\nassurance = "D0"\n\n'
        f'[boundary]\nvault_namespace = "{NS}"\nssh_admin_targets = ["hv-01.example.invalid"]\n',
        encoding="utf-8",
    )
    return manifest


def _doctor(manifest: Path, *flags: str) -> tuple[dict[str, object], int]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest), "--json", *flags])
    return json.loads(buf.getvalue()), rc


@posix_only
def test_cli_boundary_pass_degrades_on_unknowns_but_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "no", VAULT_SECRETS: "no", VAULT_EXEC: "no"})
    manifest = _cli_env(tmp_path, monkeypatch, fake)
    payload, rc = _doctor(manifest, "--boundary")
    boundary = [c for c in payload["checks"] if c.get("kind") == "boundary"]  # type: ignore[attr-defined]
    by_name = {c["name"]: c for c in boundary}
    assert by_name["boundary.kubeconfig.cluster-admin"]["status"] == "ok"
    assert by_name["boundary.vault-identity"]["verdict"] == "unknown"  # no VAULT_ADDR
    assert by_name["boundary.ssh-admin:hv-01.example.invalid"]["verdict"] == "unknown"
    assert all(c["status"] in {"ok", "warn", "fail"} and c["name"] for c in boundary)
    assert payload["ok"] is True and payload["degraded"] is True
    assert rc == 0
    assert CANARY not in json.dumps(payload)


@posix_only
def test_cli_boundary_yes_fails_and_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "yes", VAULT_SECRETS: "no", VAULT_EXEC: "no"})
    manifest = _cli_env(tmp_path, monkeypatch, fake)
    payload, rc = _doctor(manifest, "--boundary")
    assert payload["ok"] is False
    assert rc == 1


@posix_only
def test_cli_without_the_flag_runs_no_boundary_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "yes"})
    manifest = _cli_env(tmp_path, monkeypatch, fake)
    payload, rc = _doctor(manifest)
    assert not [c for c in payload["checks"] if c.get("kind") == "boundary"]  # type: ignore[attr-defined]
    assert fake.queries() == []
    assert rc == 0


@posix_only
def test_cli_boundary_text_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeKubectl(tmp_path, {CLUSTER_ADMIN: "yes", VAULT_SECRETS: "no", VAULT_EXEC: "no"})
    manifest = _cli_env(tmp_path, monkeypatch, fake)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["doctor", "-m", str(manifest), "--boundary"])
    assert rc == 1
    out = buf.getvalue()
    assert "FAIL" in out and "boundary.kubeconfig.cluster-admin" in out
    assert CANARY not in out


def test_cli_bad_boundary_table_is_the_manifest_error_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = tmp_path / "capabilities.toml"
    manifest.write_text(
        '[capability."cred:a"]\nprovider = "cred"\nharnesses = ["claude"]\n\n'
        '[boundary]\nvault_namespaces = "typo"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("ACB_STATE_DIR", str(tmp_path / "state"))
    payload, rc = _doctor(manifest, "--boundary")
    assert rc == 1 and payload["error"]["code"] == "MANIFEST_ERROR"  # type: ignore[index]
