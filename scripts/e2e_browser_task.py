#!/usr/bin/env python3
"""One real browser task, driven entirely by what `acb exec` brokered.

This is the *qualified child* of an e2e checkout: it is launched as

    acb exec e2e:chromium -- python3 scripts/e2e_browser_task.py --url … --expect …

and reads nothing but the environment acb injected (``ACB_E2E_BACKEND``,
``ACB_E2E_EXECUTABLE``). It performs no capability discovery of its own — no
Playwright install lookup, no MCP wiring, no manifest read — which is the whole
point of the proof: if the capability is not brokered, the task cannot run.

The task navigates the provisioned browser to ``--url`` and asserts ``--expect``
appears in the rendered DOM (Chromium's ``--dump-dom`` renders the page and
prints the resulting DOM, so this is a real navigation + render, not a fetch).

Exit codes: 0 assertion held, 1 assertion failed, 2 usage/env error,
3 the brokered backend cannot be driven by this task.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

_CHROMIUM_FLAGS = ("--headless", "--disable-gpu", "--dump-dom")
# Chromium aborts with this when it can neither use unprivileged user namespaces
# (AppArmor-restricted on Ubuntu 23.10+) nor a setuid sandbox helper.
_NO_SANDBOX_ABORT = "No usable sandbox!"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="e2e_browser_task")
    parser.add_argument("--url", required=True, help="page to navigate to")
    parser.add_argument("--expect", required=True, help="text that must appear in the DOM")
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds")
    parser.add_argument(
        "--allow-no-sandbox",
        action="store_true",
        help=(
            "if the browser aborts because the host has no usable sandbox, retry once "
            "with --no-sandbox and say so. Off by default: dropping the renderer "
            "sandbox is a real security decision, so the task never does it silently."
        ),
    )
    args = parser.parse_args(argv)

    backend = os.environ.get("ACB_E2E_BACKEND")
    if backend is None:
        print(
            "error: no e2e capability brokered (ACB_E2E_BACKEND unset) — run me "
            "via `acb exec e2e:<capability> -- …`",
            file=sys.stderr,
        )
        return 2
    if backend != "local":
        print(
            f"error: brokered backend {backend!r} is not drivable by this task "
            f"(it drives a local browser executable only)",
            file=sys.stderr,
        )
        return 3

    executable = os.environ.get("ACB_E2E_EXECUTABLE")
    if not executable:
        print("error: backend 'local' but ACB_E2E_EXECUTABLE is unset", file=sys.stderr)
        return 2

    def navigate(extra: tuple[str, ...] = ()) -> subprocess.CompletedProcess[str] | int:
        command = [executable, *_CHROMIUM_FLAGS, *extra, args.url]
        try:
            return subprocess.run(  # noqa: S603 (executable comes from acb, not the model)
                command,
                capture_output=True,
                text=True,
                timeout=args.timeout,
                check=False,
            )
        except OSError as exc:
            print(
                f"error: cannot launch brokered browser ({type(exc).__name__})", file=sys.stderr
            )
            return 3
        except subprocess.TimeoutExpired:
            print(f"error: browser task timed out after {args.timeout:g}s", file=sys.stderr)
            return 1

    outcome = navigate()
    if isinstance(outcome, int):
        return outcome
    completed = outcome

    if completed.returncode != 0 and _NO_SANDBOX_ABORT in completed.stderr:
        if not args.allow_no_sandbox:
            print(
                "error: the brokered browser has no usable sandbox on this host "
                "(AppArmor restricts unprivileged user namespaces, and no setuid "
                "sandbox helper is installed). Re-run with --allow-no-sandbox to "
                "proceed without the renderer sandbox, or fix the host policy.",
                file=sys.stderr,
            )
            return 3
        print(
            "note: host has no usable browser sandbox; retrying with --no-sandbox "
            "(renderer sandbox disabled for this task)",
            file=sys.stderr,
        )
        outcome = navigate(("--no-sandbox",))
        if isinstance(outcome, int):
            return outcome
        completed = outcome

    if completed.returncode != 0:
        print(
            f"error: browser exited {completed.returncode}; "
            f"stderr tail: {completed.stderr.strip().splitlines()[-1:]}",
            file=sys.stderr,
        )
        return 1

    if args.expect not in completed.stdout:
        print(
            f"FAIL: {args.expect!r} not in the rendered DOM of {args.url} "
            f"({len(completed.stdout)} bytes rendered)",
            file=sys.stderr,
        )
        return 1

    print(f"PASS: rendered {args.url} and found {args.expect!r} in the DOM")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
