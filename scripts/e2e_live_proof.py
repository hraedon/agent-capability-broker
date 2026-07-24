#!/usr/bin/env python3
"""Live proof of the e2e half of acb (Plan 006 WI-1.2).

The cred half of acb is load-bearing daily; the e2e half was asserted, never
proven. This script is the proof, and it is deliberately *hermetic*: it serves
its own page on loopback, uses its own temporary manifest and temporary harness
configs, and never reads or writes the operator's real `capabilities.toml`,
`~/.claude/settings.json`, or `~/.config/opencode/opencode.json`.

Three phases, each of which must hold:

1. **Positive, exec.** A real browser task — navigate to a locally served page
   and assert its content — is driven through `acb exec e2e:chromium`, with the
   child (`e2e_browser_task.py`) receiving *only* what acb brokered.
2. **Negative, doctor.** With Playwright wiring present, the capability's check
   is `ok`. Remove the wiring and `acb doctor` must flip to a **named failing
   check** (`e2e:chromium@opencode` → `fail`) and a non-zero exit. This is
   verified, not asserted: if the probe were decorative, this phase fails.
3. **Negative, exec.** With no browser binaries reachable, `acb exec` must fail
   with the contract-v1 error envelope (`E2E_UNAVAILABLE`) and launch nothing —
   not raise, not hang, not silently succeed.

Usage:  python3 scripts/e2e_live_proof.py [--keep]
Exit 0 = proof passed; 1 = a phase failed; 3 = prerequisites absent (no browser
binaries on this host — an honest "not run", not a pass).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TASK = REPO / "scripts" / "e2e_browser_task.py"
MARKER = "ACB-E2E-PROOF-MARKER"
ACB = (sys.executable, "-m", "agent_capability_broker")

_MANIFEST = """\
[capability."e2e:chromium"]
provider  = "e2e"
engine    = "playwright"
browser   = "chromium"
backend   = "local"
pin       = "1.43.0"
harnesses = ["opencode"]
"""
_PAGE = f"""\
<!doctype html>
<html><head><title>acb e2e proof</title></head>
<body><h1 id="marker">{MARKER}</h1></body></html>
"""
_WIRED = {
    "mcp": {
        "playwright": {
            "type": "local",
            "enabled": True,
            "command": ["npx", "-y", "@playwright/mcp@1.43.0", "--headless"],
        }
    }
}
_UNWIRED: dict[str, object] = {"mcp": {}}


class _QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


def _serve(root: Path) -> tuple[ThreadingHTTPServer, str]:
    handler = partial(_QuietHandler, directory=str(root))
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/page.html"


def _isolated_env(work: Path, **extra: str) -> dict[str, str]:
    """A child env pinned to this proof's temporary harness/state locations."""
    env = dict(os.environ)
    env.update(
        ACB_CLAUDE_SETTINGS=str(work / "absent-claude.json"),
        ACB_OPENCODE_CONFIG=str(work / "opencode.json"),
        ACB_HERMES_CONFIG=str(work / "absent-hermes.yaml"),
        ACB_CODEX_HOME=str(work / "absent-codex"),
        ACB_STATE_DIR=str(work / "state"),
        PYTHONPATH=str(REPO / "src") + os.pathsep + env.get("PYTHONPATH", ""),
    )
    env.pop("ACB_MANIFEST", None)
    env.update(extra)
    return env


def _run(argv: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=180, check=False)


def _report(phase: str, ok: bool, detail: str) -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {phase}: {detail}")
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="e2e_live_proof")
    parser.add_argument("--keep", action="store_true", help="keep the temp workspace")
    args = parser.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="acb-e2e-proof-"))
    manifest = work / "capabilities.toml"
    manifest.write_text(_MANIFEST, encoding="utf-8")
    (work / "page.html").write_text(_PAGE, encoding="utf-8")
    (work / "opencode.json").write_text(json.dumps(_WIRED), encoding="utf-8")
    (work / "empty-browsers").mkdir()
    server, url = _serve(work)
    print(f"workspace: {work}\nserving:   {url}\n")

    results: list[bool] = []
    try:
        # --- phase 1: a real browser task through `acb exec` ------------------
        proc = _run(
            [
                *ACB, "exec", "-m", str(manifest), "e2e:chromium", "--",
                sys.executable, str(TASK), "--url", url, "--expect", MARKER,
                # This host (and most Ubuntu 23.10+ boxes) restricts unprivileged
                # user namespaces via AppArmor, so the brokered browser cannot use
                # its renderer sandbox. The task says so out loud and retries once
                # rather than pretending; the page under test is loopback-only.
                "--allow-no-sandbox",
            ],
            _isolated_env(work),
        )
        if proc.returncode == 2 and "E2E_UNAVAILABLE" in (proc.stdout + proc.stderr):
            print(
                "PREREQUISITE ABSENT: no Playwright browser binaries on this host.\n"
                f"  {proc.stderr.strip()}\n"
                "  Install with `playwright install chromium`, then re-run. "
                "The proof is NOT run (this is not a pass)."
            )
            return 3
        results.append(_report(
            "1 exec drives a real browser task",
            proc.returncode == 0 and MARKER in proc.stdout,
            f"exit={proc.returncode} stdout={proc.stdout.strip()!r}"
            + (f" stderr={proc.stderr.strip()!r}" if proc.returncode else ""),
        ))

        # --- phase 2: doctor, wiring present then removed ---------------------
        wired = _run([*ACB, "doctor", "-m", str(manifest), "--json"], _isolated_env(work))
        wired_payload = json.loads(wired.stdout)
        wired_check = next(
            c for c in wired_payload["checks"] if c["name"] == "e2e:chromium@opencode"
        )
        results.append(_report(
            "2a doctor sees the wired capability",
            wired_check["status"] == "ok",
            f"check {wired_check['name']} = {wired_check['status']}",
        ))

        (work / "opencode.json").write_text(json.dumps(_UNWIRED), encoding="utf-8")
        unwired = _run([*ACB, "doctor", "-m", str(manifest), "--json"], _isolated_env(work))
        unwired_payload = json.loads(unwired.stdout)
        unwired_check = next(
            c for c in unwired_payload["checks"] if c["name"] == "e2e:chromium@opencode"
        )
        results.append(_report(
            "2b removing the wiring flips doctor to a NAMED failing check",
            unwired_check["status"] == "fail"
            and unwired_payload["ok"] is False
            and unwired.returncode != 0,
            f"check {unwired_check['name']} = {unwired_check['status']}, "
            f"ok={unwired_payload['ok']}, exit={unwired.returncode}",
        ))
        (work / "opencode.json").write_text(json.dumps(_WIRED), encoding="utf-8")

        # --- phase 3: exec without a provisioned browser ----------------------
        broken = _run(
            [
                *ACB, "exec", "-m", str(manifest), "--json", "e2e:chromium", "--",
                sys.executable, str(TASK), "--url", url, "--expect", MARKER,
            ],
            _isolated_env(work, PLAYWRIGHT_BROWSERS_PATH=str(work / "empty-browsers")),
        )
        try:
            envelope = json.loads(broken.stdout)
        except json.JSONDecodeError:
            envelope = {}
        results.append(_report(
            "3 unprovisioned exec fails with the contract-v1 envelope",
            broken.returncode == 2
            and envelope.get("error", {}).get("code") == "E2E_UNAVAILABLE"
            and "Traceback" not in broken.stderr,
            f"exit={broken.returncode} code={envelope.get('error', {}).get('code')!r}",
        ))
    finally:
        server.shutdown()
        if args.keep:
            print(f"\nworkspace kept at {work}")
        else:
            shutil.rmtree(work, ignore_errors=True)

    print("\nPROOF " + ("PASSED" if all(results) else "FAILED"))
    return 0 if all(results) else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
