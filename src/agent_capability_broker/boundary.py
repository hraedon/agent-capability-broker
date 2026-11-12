"""`acb doctor --boundary`: the blast-radius rule, checked read-only.

Plan 011 §3 / Plan 012 §6. The rule: **the agent VM holds no credential that
administers anything that guards or issues secrets.** This module checks what
can be checked from inside the VM without acting:

* the kubeconfig's own authority (``kubectl auth can-i``, plus its file mode),
* the VM's Vault identity (``sys/capabilities-self`` on the admin paths, and a
  warning if it holds ``sys/leases/revoke`` or ``auth/token/revoke-accessor``),
* the operator's declared admin SSH targets, which cannot be derived and are
  reported as "checked by hand".

Read-only by construction: every probe is a policy *question* (``can-i``,
``capabilities-self``) and none reads or uses a secret. Subprocesses are run
without a shell, with a timeout and a minimal environment. Output never carries
a token, certificate or kubeconfig content -- only verdicts, capability names,
file modes and paths. Verdicts reuse the doctor vocabulary: ``ok`` / ``warn`` /
``fail`` / ``unknown``, where ``unknown`` (the check could not run) renders as
the suite ``warn`` exactly as ``Status.UNKNOWN`` does for a capability cell.

Stdlib-only. The Vault client (the optional ``[cred]`` extra) is imported
lazily inside the one function that needs it.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .model import BoundaryConfig

# Seconds. kubectl talks to a cluster API; a hung one must not hang doctor.
KUBECTL_TIMEOUT = 20.0

# Verdict -> suite check status. ``unknown`` maps to ``warn`` like Status.UNKNOWN.
_CHECK_STATUS = {"ok": "ok", "warn": "warn", "fail": "fail", "unknown": "warn"}

# Admin paths on which the VM's Vault identity must hold only ``deny``.
VAULT_ADMIN_PATHS = ("sys/policies/acl/x", "auth/x", "identity/x", "sys/mounts")

# Broad revocation capabilities the VM must NOT hold (Plan 012 section 10): the
# broker revokes with per-checkout child tokens (``auth/token/revoke-self``), so
# it needs neither of these. Holding them lets a compromised VM revoke other
# identities' leases / any token whose accessor it can learn. A warning, not a
# failure: it widens blast radius for availability, it does not expose a secret.
VAULT_BROAD_REVOKE_PATHS = ("sys/leases/revoke/x", "auth/token/revoke-accessor")

# The environment kubectl is given: enough to find its kubeconfig and the binary,
# nothing else (no VAULT_*, no tokens, no proxies inherited by accident).
_ENV_KEEP = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "KUBECONFIG", "TMPDIR", "TEMP")

# (argv, timeout seconds, env) -> (returncode, stdout). Raises OSError (binary
# missing/unrunnable) or TimeoutError. Injectable so tests need no real kubectl.
Runner = Callable[[Sequence[str], float, Mapping[str, str]], tuple[int, str]]


@dataclass(frozen=True)
class BoundaryCheck:
    """One boundary finding, shaped like a doctor check."""

    name: str
    verdict: str   # "ok" | "warn" | "fail" | "unknown"
    detail: str

    def as_check(self) -> dict[str, object]:
        """The suite-contract check dict (``kind`` discriminates it from cell checks)."""
        return {
            "name": self.name,
            "capability": None,
            "harness": None,
            "status": _CHECK_STATUS[self.verdict],
            "verdict": self.verdict,
            "detail": self.detail,
            "kind": "boundary",
        }


def _run(argv: Sequence[str], timeout: float, env: Mapping[str, str]) -> tuple[int, str]:
    """Run `argv` (no shell, stdin closed, bounded) and return (rc, stdout)."""
    try:
        proc = subprocess.run(  # noqa: S603 -- fixed argv, no shell
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=dict(env),
            stdin=subprocess.DEVNULL,
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(f"timed out after {timeout:g}s") from exc
    return proc.returncode, proc.stdout


def _minimal_env(environ: Mapping[str, str]) -> dict[str, str]:
    env = {k: environ[k] for k in _ENV_KEEP if k in environ}
    env["LC_ALL"] = "C"
    return env


def kubeconfig_files(environ: Mapping[str, str]) -> list[Path]:
    """The kubeconfig file(s) kubectl would load that exist on disk.

    ``$KUBECONFIG`` (a path list) wins, else ``~/.kube/config``. Existence only --
    the content is never read.
    """
    declared = environ.get("KUBECONFIG")
    if declared:
        candidates = [Path(p) for p in declared.split(os.pathsep) if p]
    else:
        home = environ.get("HOME") or environ.get("USERPROFILE")
        candidates = [Path(home) / ".kube" / "config"] if home else []
    return [p for p in candidates if p.is_file()]


def _kubeconfig_mode_check(files: Sequence[Path]) -> BoundaryCheck | None:
    """Warn when a kubeconfig is group/world accessible (POSIX only)."""
    if os.name != "posix" or not files:
        return None
    wide: list[str] = []
    for path in files:
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            continue
        if mode & 0o177:  # anything beyond rw for the owner
            wide.append(f"{path} is {mode:04o}")
    if wide:
        return BoundaryCheck(
            "boundary.kubeconfig.mode",
            "warn",
            "kubeconfig mode wider than 0600: " + "; ".join(wide),
        )
    return BoundaryCheck(
        "boundary.kubeconfig.mode", "ok", "kubeconfig mode is 0600 or narrower"
    )


def _can_i(
    runner: Runner, kubectl: str, env: Mapping[str, str], args: Sequence[str]
) -> tuple[bool | None, str]:
    """Ask ``kubectl auth can-i``. Returns (answer, reason); answer None = unknown.

    Only the first word of stdout is read (``yes`` / ``no``). stderr is never
    surfaced: kubectl error text can embed server addresses.
    """
    argv = [kubectl, "auth", "can-i", *args]
    try:
        _rc, out = runner(argv, KUBECTL_TIMEOUT, env)
    except TimeoutError:
        return None, f"kubectl timed out after {KUBECTL_TIMEOUT:g}s"
    except OSError as exc:
        return None, f"kubectl could not run ({type(exc).__name__})"
    words = out.strip().lower().split()
    if words and words[0] == "yes":
        return True, ""
    if words and words[0] == "no":
        return False, ""
    return None, "kubectl gave no yes/no answer (cluster unreachable or credentials rejected)"


def _kubectl_checks(
    cfg: BoundaryConfig, environ: Mapping[str, str], runner: Runner
) -> list[BoundaryCheck]:
    queries: list[tuple[str, Sequence[str], str]] = [
        (
            "boundary.kubeconfig.cluster-admin",
            ("*", "*", "--all-namespaces"),
            "the kubeconfig can do everything in every namespace (cluster-admin)",
        )
    ]
    ns = cfg.vault_namespace
    if ns:
        queries.append(
            (
                "boundary.kubeconfig.vault-secrets",
                ("get", "secrets", "-n", ns),
                f"the kubeconfig can read secrets in the Vault namespace {ns!r}",
            )
        )
        queries.append(
            (
                "boundary.kubeconfig.vault-exec",
                ("create", "pods/exec", "-n", ns),
                f"the kubeconfig can exec into pods in the Vault namespace {ns!r}",
            )
        )

    files = kubeconfig_files(environ)
    kubectl = shutil.which("kubectl", path=environ.get("PATH"))
    if kubectl is None:
        return [BoundaryCheck(n, "unknown", "kubectl not found on PATH") for n, _a, _d in queries]
    if not files:
        reason = "no kubeconfig found ($KUBECONFIG unset or missing, no ~/.kube/config)"
        return [BoundaryCheck(n, "unknown", reason) for n, _a, _d in queries]

    out: list[BoundaryCheck] = []
    mode = _kubeconfig_mode_check(files)
    if mode is not None:
        out.append(mode)
    env = _minimal_env(environ)
    for name, args, meaning in queries:
        answer, reason = _can_i(runner, kubectl, env, args)
        if answer is None:
            out.append(BoundaryCheck(name, "unknown", reason))
        elif answer:
            out.append(BoundaryCheck(name, "fail", f"yes: {meaning}"))
        else:
            out.append(BoundaryCheck(name, "ok", "no"))
    return out


def _vault_identity_check(vault_client: object | None) -> BoundaryCheck:
    name = "boundary.vault-identity"
    try:
        from . import cred_vault  # lazy: the optional [cred] extra, never core

        caps = cred_vault.capabilities_self(list(VAULT_ADMIN_PATHS), client=vault_client)
    except RuntimeError as exc:
        return BoundaryCheck(name, "unknown", str(exc))
    except Exception as exc:  # defensive: a probe must never crash doctor
        return BoundaryCheck(name, "unknown", f"Vault probe failed ({type(exc).__name__})")
    offenders = {
        path: sorted(c for c in granted if c != "deny")
        for path, granted in caps.items()
        if any(c != "deny" for c in granted)
    }
    if offenders:
        listing = "; ".join(f"{p} [{', '.join(c)}]" for p, c in offenders.items())
        return BoundaryCheck(
            name,
            "fail",
            f"the VM's Vault identity holds more than deny on admin paths: {listing}",
        )
    return BoundaryCheck(
        name, "ok", f"deny only on {len(VAULT_ADMIN_PATHS)} admin paths (sys/auth/identity)"
    )


def _vault_revoke_scope_check(vault_client: object | None) -> BoundaryCheck:
    name = "boundary.vault-revoke-scope"
    try:
        from . import cred_vault  # lazy: the optional [cred] extra, never core

        caps = cred_vault.capabilities_self(list(VAULT_BROAD_REVOKE_PATHS), client=vault_client)
    except RuntimeError as exc:
        return BoundaryCheck(name, "unknown", str(exc))
    except Exception as exc:  # defensive: a probe must never crash doctor
        return BoundaryCheck(name, "unknown", f"Vault probe failed ({type(exc).__name__})")
    offenders = {
        path: sorted(c for c in granted if c != "deny")
        for path, granted in caps.items()
        if any(c != "deny" for c in granted)
    }
    if offenders:
        listing = "; ".join(f"{p} [{', '.join(c)}]" for p, c in offenders.items())
        return BoundaryCheck(
            name,
            "warn",
            f"the VM's Vault identity can revoke beyond its own tokens: {listing}; the broker "
            f"revokes with per-checkout child tokens (auth/token/revoke-self) and needs "
            f"neither sys/leases/revoke nor auth/token/revoke-accessor",
        )
    return BoundaryCheck(
        name, "ok", "no sys/leases/revoke or auth/token/revoke-accessor (token-bound revocation)"
    )


def run_boundary_checks(
    cfg: BoundaryConfig,
    *,
    environ: Mapping[str, str] | None = None,
    runner: Runner | None = None,
    vault_client: object | None = None,
) -> list[BoundaryCheck]:
    """Run every boundary check. Pure of side effects; never raises on a probe failure.

    `environ`, `runner` and `vault_client` are injection points for tests; in
    production they are the process environment, a bounded no-shell subprocess
    runner, and a client built by ``cred_vault.authenticated_client`` (WI-016
    invariants: ``token=""``, fail closed, never an ambient token).
    """
    env = os.environ if environ is None else environ
    checks = _kubectl_checks(cfg, env, runner or _run)
    checks.append(_vault_identity_check(vault_client))
    checks.append(_vault_revoke_scope_check(vault_client))
    for host in cfg.ssh_admin_targets:
        checks.append(
            BoundaryCheck(
                f"boundary.ssh-admin:{host}",
                "unknown",
                "declared admin SSH target: no VM key may open an admin login there; "
                "checked by hand (acb does not attempt SSH)",
            )
        )
    return checks
