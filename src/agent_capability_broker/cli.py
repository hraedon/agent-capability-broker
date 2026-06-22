"""`acb` command-line entry point.

Charter-stage: `doctor` parses a manifest and prints the parity matrix. Real
per-provider inspection and the act-path verbs (reconcile/exec) land in the
plans; until a provider reports, statuses are UNKNOWN. The read path here never
mutates a config and never surfaces a secret.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import provenance
from .model import (
    KNOWN_HARNESSES,
    Action,
    ManifestError,
    Status,
    Verdict,
    parse_manifest,
    resolve_manifest,
)
from .providers import PROVIDERS, adapters


def _inspect_all(manifest_path: Path) -> list[Verdict]:
    """Compute a verdict per capability x harness by dispatching to providers.

    For each capability, harnesses it lists are inspected by the capability's
    provider (read-only); harnesses it does not list are NOT_APPLICABLE; a listed
    harness whose config is absent is UNKNOWN. Matrix shape and exit semantics
    are stable for callers/CI.
    """
    caps = parse_manifest(manifest_path)
    harness_adapters = adapters()
    verdicts: list[Verdict] = []
    for cap in caps:
        provider = PROVIDERS.get(cap.provider)
        for harness in sorted(KNOWN_HARNESSES):
            if harness not in cap.harnesses:
                verdicts.append(Verdict(cap.id, harness, Status.NOT_APPLICABLE))
                continue
            adapter = harness_adapters.get(harness)
            if provider is None:
                verdicts.append(
                    Verdict(cap.id, harness, Status.UNKNOWN, f"no provider {cap.provider!r}")
                )
            elif adapter is None or not adapter.available():
                verdicts.append(
                    Verdict(cap.id, harness, Status.UNKNOWN, f"no {harness} config found")
                )
            else:
                verdicts.append(provider.inspect(cap, harness, adapter))
    return verdicts


def _print_table(verdicts: list[Verdict]) -> None:
    width = max((len(v.capability) for v in verdicts), default=10)
    for v in verdicts:
        line = f"{v.capability:<{width}}  {v.harness:<8}  {v.status.value}"
        if v.detail:
            line += f"  ({v.detail})"
        print(line)


def _cmd_doctor(args: argparse.Namespace) -> int:
    try:
        verdicts = _inspect_all(resolve_manifest(args.manifest))
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([v.__dict__ | {"status": v.status.value} for v in verdicts], indent=2))
    else:
        _print_table(verdicts)

    # Parity gate: non-zero if anything is broken or absent (cron/CI-usable).
    bad = {Status.PRESENT_BROKEN, Status.ABSENT}
    return 1 if any(v.status in bad for v in verdicts) else 0


def _shim_gap(surfaces: dict[str, set[str]]) -> set[str]:
    """Shims missing from at least one *participating* harness.

    A shim is a parity gap when some harness in `surfaces` exposes it and another
    does not. With fewer than two participating harnesses there is nothing to
    compare, so the gap set is empty. Pure — no I/O.
    """
    if len(surfaces) < 2:
        return set()
    union: set[str] = set().union(*surfaces.values())
    return {shim for shim in union if any(shim not in s for s in surfaces.values())}


def _shim_surfaces() -> dict[str, set[str]]:
    """Each harness whose shim dir exists, mapped to the shims it advertises."""
    return {
        name: adapter.command_shims()
        for name, adapter in adapters().items()
        if adapter.shims_path.is_dir()
    }


def _cmd_shims(args: argparse.Namespace) -> int:
    surfaces = _shim_surfaces()
    gap = _shim_gap(surfaces)

    if args.json:
        print(json.dumps(
            {
                "surfaces": {h: sorted(s) for h, s in surfaces.items()},
                "gap": sorted(gap),
            },
            indent=2,
        ))
    elif not surfaces:
        print("no command-shim surface found for any harness")
    else:
        harnesses = sorted(surfaces)
        all_shims = sorted(set().union(*surfaces.values())) if surfaces else []
        width = max((len(s) for s in all_shims), default=4)
        header = f"{'shim':<{width}}  " + "  ".join(f"{h:<8}" for h in harnesses)
        print(header)
        for shim in all_shims:
            marks = "  ".join(f"{'*' if shim in surfaces[h] else '-':<8}" for h in harnesses)
            line = f"{shim:<{width}}  {marks}"
            if shim in gap:
                line += "  <- parity gap"
            print(line)

    # Parity gate: non-zero when a participating harness lacks a shim another has.
    return 1 if gap else 0


def _plan_all(manifest_path: Path) -> list[Action]:
    """Collect reconcile actions across every capability x listed harness."""
    caps = parse_manifest(manifest_path)
    harness_adapters = adapters()
    plan: list[Action] = []
    for cap in caps:
        provider = PROVIDERS.get(cap.provider)
        if provider is None:
            continue
        for harness in sorted(cap.harnesses):
            adapter = harness_adapters.get(harness)
            if adapter is None or not adapter.available():
                continue
            plan.extend(provider.plan_reconcile(cap, harness, adapter))
    return plan


def _cmd_reconcile(args: argparse.Namespace) -> int:
    try:
        plan = _plan_all(resolve_manifest(args.manifest))
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not plan:
        print("nothing to reconcile — all capabilities present and working")
        return 0

    harness_adapters = adapters()
    auto = [a for a in plan if a.kind != "manual"]
    unapplied = 0

    for action in plan:
        if not args.apply:
            verb = "would apply" if action.kind != "manual" else "manual"
            print(f"[{verb}] {action.capability} / {action.harness}: {action.summary}")
            if action.kind != "manual":
                unapplied += 1
            continue

        adapter = harness_adapters.get(action.harness)
        if adapter is None or not adapter.available():
            print(f"[SKIP] {action.capability} / {action.harness}: adapter unavailable")
            unapplied += 1
            continue
        provider_name = action.capability.split(":", 1)[0]
        provider = PROVIDERS.get(provider_name)
        if provider is None:
            print(f"[SKIP] {action.capability} / {action.harness}: no provider {provider_name!r}")
            unapplied += 1
            continue
        result = provider.apply(action, adapter)
        provenance.emit(result)
        tag = result.status.upper()
        line = f"[{tag}] {action.capability} / {action.harness}: {result.detail or action.summary}"
        if result.backup_path:
            line += f"  (backup: {result.backup_path})"
        print(line)
        if result.status != "applied" and action.kind != "manual":
            unapplied += 1

    if not args.apply and auto:
        print(f"\n{len(auto)} action(s) planned. Re-run with --apply to perform them.")
    # Non-zero while automatically-fixable actions remain unapplied.
    return 1 if unapplied else 0


def _cmd_exec(args: argparse.Namespace) -> int:
    try:
        caps = parse_manifest(resolve_manifest(args.manifest))
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    cap = next((c for c in caps if c.id == args.capability), None)
    if cap is None:
        print(f"error: capability {args.capability!r} not in manifest", file=sys.stderr)
        return 2
    provider = PROVIDERS.get(cap.provider)
    if provider is None:
        print(f"error: no provider {cap.provider!r}", file=sys.stderr)
        return 2

    argv = list(args.argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("error: no command (usage: acb exec <cap> -- <cmd…>)", file=sys.stderr)
        return 2

    try:
        return provider.exec(cap, argv)
    except (RuntimeError, NotImplementedError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acb", description=__doc__)
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    doctor = sub.add_parser("doctor", help="read-only parity report across harnesses")
    doctor.add_argument(
        "-m", "--manifest", default=None,
        help="manifest path (default: $ACB_MANIFEST, ~/.config/acb/capabilities.toml, then ./)",
    )
    doctor.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    doctor.set_defaults(func=_cmd_doctor)

    shims = sub.add_parser(
        "shims", help="read-only parity report of the command/skill shim surface"
    )
    shims.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    shims.set_defaults(func=_cmd_shims)

    rec = sub.add_parser(
        "reconcile", help="bring harnesses to the manifest (dry-run unless --apply)"
    )
    rec.add_argument(
        "-m", "--manifest", default=None,
        help="manifest path (default: $ACB_MANIFEST, ~/.config/acb/capabilities.toml, then ./)",
    )
    rec.add_argument(
        "--apply", action="store_true", help="perform the changes (default: dry-run)"
    )
    rec.set_defaults(func=_cmd_reconcile)

    ex = sub.add_parser(
        "exec", help="run a command with a capability injected (never surfaced)"
    )
    ex.add_argument(
        "-m", "--manifest", default=None,
        help="manifest path (default: $ACB_MANIFEST, ~/.config/acb/capabilities.toml, then ./)",
    )
    ex.add_argument("capability", help="capability id, e.g. cred:svc-bot")
    ex.add_argument("argv", nargs=argparse.REMAINDER, help="-- command and args to run")
    ex.set_defaults(func=_cmd_exec)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        from . import __version__

        print(__version__)
        return 0
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
