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

from .model import KNOWN_HARNESSES, ManifestError, Status, Verdict, parse_manifest
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
        verdicts = _inspect_all(Path(args.manifest))
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acb", description=__doc__)
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    doctor = sub.add_parser("doctor", help="read-only parity report across harnesses")
    doctor.add_argument(
        "-m", "--manifest", default="capabilities.toml", help="path to capabilities.toml"
    )
    doctor.add_argument("--json", action="store_true", help="emit JSON instead of a table")
    doctor.set_defaults(func=_cmd_doctor)

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
