"""`acb` command-line entry point.

The read path (`doctor`, `shims`) is deterministic and never mutates a config
or surfaces a secret. The act path (`reconcile`, `exec`, `install-harness`)
mutates configs and injects secrets: it is dry-run by default, backs up before
writing, is idempotent, never clobbers an existing secret, and emits
provenance on every act.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

from . import provenance
from .model import (
    KNOWN_HARNESSES,
    Action,
    ActionResult,
    ManifestError,
    Status,
    Verdict,
    parse_manifest,
    resolve_manifest,
)
from .providers import PROVIDERS, adapters

_STABLE_INSTALL_HARNESSES = ("claude", "opencode")


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


# Suite-health per-check vocabulary (Plan 006 WI-1.1). Mirrors the
# ok/warn/fail/skip lexicon cairn emits (cairn/_doctor.py): a hard fail
# (present_broken / absent) makes the component unhealthy; a soft unknown
# (cannot determine — e.g. the harness config is absent on this box) is a
# warning that degrades without failing; not_applicable is a skip.
_CHECK_STATUS: dict[Status, str] = {
    Status.PRESENT_OK: "ok",
    Status.PRESENT_BROKEN: "fail",
    Status.ABSENT: "fail",
    Status.UNKNOWN: "warn",
    Status.NOT_APPLICABLE: "skip",
}


def _doctor_checks(verdicts: list[Verdict]) -> list[dict[str, object]]:
    """Render verdicts as suite-contract check dicts.

    Each check carries a ``name`` (the capability@harness cell it probes), the
    normalized ``status`` (ok/warn/fail/skip — the sibling vocabulary), a
    human-readable ``detail``, and the acb-specific ``capability``/``harness``
    pair for matrix context.
    """
    return [
        {
            "name": f"{v.capability}@{v.harness}",
            "capability": v.capability,
            "harness": v.harness,
            "status": _CHECK_STATUS[v.status],
            "detail": v.detail,
        }
        for v in verdicts
    ]


def _classify_health(checks: list[dict[str, object]]) -> tuple[bool, bool]:
    """Classify component health from checks the way the siblings do.

    Mirrors cairn's ``run_doctor`` (cairn/_doctor.py): ``ok`` is false when any
    check failed; ``degraded`` is true only when nothing failed but a warning
    is present. ``failed`` is the implicit third state (``ok`` false). The
    suite-doctor umbrella reads these two booleans (bootstrap-contract §3).
    """
    has_fail = any(str(c["status"]) == "fail" for c in checks)
    has_warn = any(str(c["status"]) == "warn" for c in checks)
    ok = not has_fail
    degraded = ok and has_warn
    return ok, degraded


def _cmd_doctor(args: argparse.Namespace) -> int:
    try:
        verdicts = _inspect_all(resolve_manifest(args.manifest))
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    checks = _doctor_checks(verdicts)
    ok, degraded = _classify_health(checks)

    if args.json:
        from . import __version__

        payload = {
            "component": "acb",
            "version": __version__,
            # The suite-doctor umbrella classifies a component from the
            # top-level ok/degraded booleans (bootstrap-contract §3); without
            # them it defaults ok→false and reports a healthy box as failed.
            "ok": ok,
            "degraded": degraded,
            "checks": checks,
            # acb has no direct regista runtime dependency (by design); report
            # the honestly-absent state rather than faking a reachable verdict.
            "regista": {"reachable": None},
        }
        print(json.dumps(payload, indent=2))
    else:
        _print_table(verdicts)

    # Exit-code consistent with the JSON verdict (sibling convention: exit 0
    # for ok and degraded, non-zero on a hard fail). Same parity gate as before
    # — present_broken/absent fail; unknown/not_applicable do not.
    return 0 if ok else 1


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


def _plan_for_harness(manifest_path: Path, harness: str) -> list[Action]:
    """Collect reconcile actions for one harness only (install-harness)."""
    caps = parse_manifest(manifest_path)
    harness_adapters = adapters()
    plan: list[Action] = []
    adapter = harness_adapters.get(harness)
    for cap in caps:
        if harness not in cap.harnesses:
            continue
        provider = PROVIDERS.get(cap.provider)
        if provider is None:
            continue
        if adapter is None or not adapter.available():
            continue
        plan.extend(provider.plan_reconcile(cap, harness, adapter))
    return plan


def _inspect_for_harness(manifest_path: Path, harness: str) -> list[Verdict]:
    """Post-install verification: inspect each capability × the named harness."""
    caps = parse_manifest(manifest_path)
    harness_adapters = adapters()
    adapter = harness_adapters.get(harness)
    verdicts: list[Verdict] = []
    for cap in caps:
        if harness not in cap.harnesses:
            continue
        provider = PROVIDERS.get(cap.provider)
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


def _uninstall_plan_for_harness(manifest_path: Path, harness: str) -> list[Action]:
    """Collect uninstall actions for one harness."""
    caps = parse_manifest(manifest_path)
    harness_adapters = adapters()
    plan: list[Action] = []
    adapter = harness_adapters.get(harness)
    for cap in caps:
        if harness not in cap.harnesses:
            continue
        provider = PROVIDERS.get(cap.provider)
        if provider is None:
            continue
        if adapter is None or not adapter.available():
            continue
        plan.extend(provider.plan_uninstall(cap, harness, adapter))
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
        try:
            result = provider.apply(action, adapter)
        except (OSError, KeyError) as exc:
            result = ActionResult(action, "failed", f"apply error: {exc}")
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
    argv = list(args.argv)
    manifest = args.manifest

    # argparse.REMAINDER captures everything after the capability positional,
    # including -m/--manifest flags that should have been parsed as options.
    # Extract them so `acb exec <cap> -m manifest.toml -- cmd` works (not just
    # `acb exec -m manifest.toml <cap> -- cmd`).
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in ("-m", "--manifest") and i + 1 < len(argv):
            manifest = argv[i + 1]
            del argv[i:i + 2]
            continue
        if tok.startswith("--manifest="):
            manifest = tok.split("=", 1)[1]
            del argv[i]
            continue
        if tok == "--":
            del argv[i]
            break
        i += 1

    if not argv:
        print("error: no command (usage: acb exec <cap> -- <cmd…>)", file=sys.stderr)
        return 2

    try:
        caps = parse_manifest(resolve_manifest(manifest))
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

    try:
        return provider.exec(cap, argv)
    except (RuntimeError, NotImplementedError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _cmd_uninstall_harness_all(args: argparse.Namespace) -> int:
    """Expand the public stable set and aggregate contract-shaped records
    for uninstall."""

    try:
        manifest_path = resolve_manifest(args.manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    records: list[dict[str, object]] = []
    child_codes: list[int] = []
    for harness in _STABLE_INSTALL_HARNESSES:
        child_args = argparse.Namespace(
            **{
                **vars(args),
                "harness": harness,
                "manifest": str(manifest_path),
                "json": True,
            }
        )
        output = io.StringIO()
        with redirect_stdout(output):
            child_code = _cmd_uninstall_harness(child_args)
        child_codes.append(child_code)
        try:
            child_payload = json.loads(output.getvalue())
        except json.JSONDecodeError:
            child_payload = None
        if not isinstance(child_payload, dict):
            child_payload = {
                "tool": "acb",
                "harness": harness,
                "user": None,
                "status": "failed",
                "actions": [],
                "no_op": False,
            }
        records.append(child_payload)

    expected_code = 2 if args.dry_run else 0
    uninstalled = all(
        code == expected_code and record.get("status") == "uninstalled"
        for code, record in zip(child_codes, records, strict=True)
    )
    no_op = uninstalled and all(record.get("no_op") is True for record in records)
    actions: list[dict[str, object]] = []
    for record in records:
        record_actions = record.get("actions")
        if isinstance(record_actions, list):
            actions.extend(
                action for action in record_actions if isinstance(action, dict)
            )
    payload = {
        "tool": "acb",
        "harness": "all",
        "user": None,
        "status": "uninstalled" if uninstalled else "failed",
        "actions": actions,
        "no_op": no_op,
        "results": records,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for record in records:
            print(
                f"{record['harness']}: {record['status']}"
                + (" (no-op)" if record.get("no_op") is True else "")
            )

    if not uninstalled:
        return 1
    return 2 if args.dry_run else 0


def _cmd_uninstall_harness(args: argparse.Namespace) -> int:
    """Remove acb's owned shims and MCP wiring from one harness.

    The inverse of ``install-harness``: re-renders each expected shim/MCP entry
    and removes only those whose on-disk content matches (ownership hash check)
    or carries the acb managed marker (stale but acb-owned). Hand-authored or
    modified artifacts are preserved and reported as manual actions. ``--dry-run``
    is opt-in (matching ``install-harness``); emits provenance on every removal.
    After removal, re-inspects to confirm capabilities are now ABSENT.
    """
    if args.harness == "all":
        return _cmd_uninstall_harness_all(args)

    if args.harness not in KNOWN_HARNESSES:
        print(
            f"error: unknown harness {args.harness!r} "
            f"(known: {sorted(KNOWN_HARNESSES | {'all'})})",
            file=sys.stderr,
        )
        return 2

    try:
        manifest_path = resolve_manifest(args.manifest)
        plan = _uninstall_plan_for_harness(manifest_path, args.harness)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        adapter = adapters().get(args.harness)
        verdicts = _inspect_for_harness(manifest_path, args.harness)
        unavailable = bool(verdicts) and (adapter is None or not adapter.available())
        conflict = any(bool(action.payload.get("conflict")) for action in plan)
        status = "failed" if (unavailable or conflict) else "uninstalled"
        payload = {
            "tool": "acb",
            "harness": args.harness,
            "user": None,
            "status": status,
            "actions": [
                {
                    "kind": action.kind,
                    "path": action.target,
                    "detail": action.summary,
                    "conflict": bool(action.payload.get("conflict")),
                }
                for action in plan
            ],
            "conflict": conflict,
            "no_op": not plan and not unavailable,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
            return 2
        if not plan:
            print(f"{args.harness}: nothing to uninstall — no acb-owned artifacts found")
            return 2
        for action in plan:
            verb = "would remove" if action.kind != "manual" else "manual"
            print(f"[{verb}] {action.capability} / {action.harness}: {action.summary}")
        auto = [a for a in plan if a.kind != "manual"]
        if auto:
            print(f"\n{len(auto)} action(s) planned. Re-run without --dry-run to perform them.")
        return 2

    harness_adapters = adapters()
    adapter = harness_adapters.get(args.harness)
    applied = 0
    skipped = 0
    action_results: list[ActionResult] = []
    for action in plan:
        if adapter is None or not adapter.available():
            print(f"[SKIP] {action.capability}: adapter unavailable")
            skipped += 1
            continue
        provider_name = action.capability.split(":", 1)[0]
        provider = PROVIDERS.get(provider_name)
        if provider is None:
            print(f"[SKIP] {action.capability}: no provider {provider_name!r}")
            skipped += 1
            continue
        try:
            result = provider.apply(action, adapter)
        except (OSError, KeyError, RuntimeError) as exc:
            result = ActionResult(action, "failed", f"apply error: {exc}")
        provenance.emit(result)
        action_results.append(result)
        tag = result.status.upper()
        line = f"[{tag}] {action.capability}: {result.detail or action.summary}"
        if result.backup_path:
            line += f"  (backup: {result.backup_path})"
        if not args.json:
            print(line)
        if result.status == "applied":
            applied += 1
        else:
            skipped += 1

    verdicts = _inspect_for_harness(manifest_path, args.harness)
    if not args.json:
        print(f"\n— {args.harness} capability status —")
        _print_table(verdicts)

    failed = any(r.status == "failed" for r in action_results)
    # An acb-owned artifact that was preserved (user-edited marker shim) is a
    # conflict: the uninstall did not complete and must not report clean success.
    conflict = any(
        r.action.kind == "manual" and bool(r.action.payload.get("conflict"))
        for r in action_results
    )
    if conflict and not args.json:
        print(
            f"\n{args.harness}: uninstall incomplete — acb-owned artifact(s) "
            f"preserved because they were modified; remove manually to complete."
        )
    status = "failed" if (failed or conflict) else "uninstalled"
    if args.json:
        payload = {
            "tool": "acb",
            "harness": args.harness,
            "user": None,
            "status": status,
            "actions": [
                {
                    "kind": result.action.kind,
                    "path": result.action.target,
                    "detail": (
                        result.action.summary
                        if result.action.payload.get("conflict")
                        else result.detail or result.action.summary
                    ),
                    "status": result.status,
                    "conflict": bool(result.action.payload.get("conflict")),
                }
                for result in action_results
            ],
            "conflict": conflict,
            "checks": [
                {
                    "capability": verdict.capability,
                    "harness": verdict.harness,
                    "status": verdict.status.value,
                    "detail": verdict.detail,
                }
                for verdict in verdicts
            ],
            "no_op": not plan,
        }
        print(json.dumps(payload, indent=2))
    return 1 if (failed or conflict) else 0


def _cmd_install_harness_all(args: argparse.Namespace) -> int:
    """Expand the public stable set and aggregate contract-shaped records."""

    try:
        manifest_path = resolve_manifest(args.manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    records: list[dict[str, object]] = []
    child_codes: list[int] = []
    for harness in _STABLE_INSTALL_HARNESSES:
        child_args = argparse.Namespace(
            **{
                **vars(args),
                "harness": harness,
                "manifest": str(manifest_path),
                "json": True,
            }
        )
        output = io.StringIO()
        with redirect_stdout(output):
            child_code = _cmd_install_harness(child_args)
        child_codes.append(child_code)
        try:
            child_payload = json.loads(output.getvalue())
        except json.JSONDecodeError:
            child_payload = None
        if not isinstance(child_payload, dict):
            child_payload = {
                "tool": "acb",
                "harness": harness,
                "user": None,
                "status": "failed",
                "actions": [],
                "no_op": False,
            }
        records.append(child_payload)

    expected_code = 2 if args.dry_run else 0
    installed = all(
        code == expected_code and record.get("status") == "installed"
        for code, record in zip(child_codes, records, strict=True)
    )
    no_op = installed and all(record.get("no_op") is True for record in records)
    actions: list[dict[str, object]] = []
    for record in records:
        record_actions = record.get("actions")
        if isinstance(record_actions, list):
            actions.extend(
                action for action in record_actions if isinstance(action, dict)
            )
    payload = {
        "tool": "acb",
        "harness": "all",
        "user": None,
        "status": "installed" if installed else "failed",
        "actions": actions,
        "no_op": no_op,
        "results": records,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for record in records:
            print(
                f"{record['harness']}: {record['status']}"
                + (" (no-op)" if record.get("no_op") is True else "")
            )

    if not installed:
        return 1
    return 2 if args.dry_run else 0


def _cmd_install_harness(args: argparse.Namespace) -> int:
    """Install acb's shims into one harness and verify each capability.

    Bootstrap step 5 (Plan 005): one idempotent command that renders the
    discovery shims and MCP wiring a harness needs from the manifest, then
    runs a focused doctor to report per-capability status.  Re-runnable: a
    fully-provisioned harness yields a no-op plan and all-PRESENT_OK verdicts.

    With ``--uninstall``: removes acb-owned shims and MCP wiring instead.
    """
    if getattr(args, "uninstall", False):
        return _cmd_uninstall_harness(args)

    if args.harness == "all":
        return _cmd_install_harness_all(args)

    if args.harness not in KNOWN_HARNESSES:
        print(
            f"error: unknown harness {args.harness!r} "
            f"(known: {sorted(KNOWN_HARNESSES | {'all'})})",
            file=sys.stderr,
        )
        return 2

    try:
        manifest_path = resolve_manifest(args.manifest)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    plan = _plan_for_harness(manifest_path, args.harness)

    if args.dry_run:
        adapter = adapters().get(args.harness)
        verdicts = _inspect_for_harness(manifest_path, args.harness)
        unavailable = bool(verdicts) and (adapter is None or not adapter.available())
        blocking = unavailable or any(
            action.kind == "manual"
            and bool(
                action.payload.get("conflict")
                or action.payload.get("unsupported")
            )
            for action in plan
        )
        verdicts = verdicts if unavailable else []
        payload = {
            "tool": "acb",
            "harness": args.harness,
            "user": None,
            "status": "failed" if blocking else "installed",
            "actions": [
                {
                    "kind": action.kind,
                    "path": action.target,
                    "detail": action.summary,
                }
                for action in plan
            ],
            "checks": [
                {
                    "capability": verdict.capability,
                    "harness": verdict.harness,
                    "status": verdict.status.value,
                    "detail": verdict.detail,
                }
                for verdict in verdicts
            ],
            "no_op": not plan and not unavailable,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
            return 2
        if not plan:
            print(f"{args.harness}: nothing to install — all capabilities present")
            return 2
        for action in plan:
            verb = "would apply" if action.kind != "manual" else "manual"
            print(f"[{verb}] {action.capability} / {action.harness}: {action.summary}")
        auto = [a for a in plan if a.kind != "manual"]
        if auto:
            print(f"\n{len(auto)} action(s) planned. Re-run without --dry-run to perform them.")
        return 2

    # Apply phase: render shims / wire MCP for this harness.
    harness_adapters = adapters()
    adapter = harness_adapters.get(args.harness)
    applied = 0
    skipped = 0
    action_results: list[ActionResult] = []
    for action in plan:
        if adapter is None or not adapter.available():
            print(f"[SKIP] {action.capability}: adapter unavailable")
            skipped += 1
            continue
        provider_name = action.capability.split(":", 1)[0]
        provider = PROVIDERS.get(provider_name)
        if provider is None:
            print(f"[SKIP] {action.capability}: no provider {provider_name!r}")
            skipped += 1
            continue
        try:
            result = provider.apply(action, adapter)
        except (OSError, KeyError, RuntimeError) as exc:
            result = ActionResult(action, "failed", f"apply error: {exc}")
        provenance.emit(result)
        action_results.append(result)
        tag = result.status.upper()
        line = f"[{tag}] {action.capability}: {result.detail or action.summary}"
        if result.backup_path:
            line += f"  (backup: {result.backup_path})"
        if not args.json:
            print(line)
        if result.status == "applied":
            applied += 1
        else:
            skipped += 1

    # Verify phase: re-inspect each capability for this harness.
    verdicts = _inspect_for_harness(manifest_path, args.harness)
    if not args.json:
        print(f"\n— {args.harness} capability status —")
        _print_table(verdicts)

    bad = {Status.PRESENT_BROKEN, Status.ABSENT, Status.UNKNOWN}
    failed = any(v.status in bad for v in verdicts) or any(
        result.status == "failed" for result in action_results
    )
    if args.json:
        payload = {
            "tool": "acb",
            "harness": args.harness,
            "user": None,
            "status": "failed" if failed else "installed",
            "actions": [
                {
                    "kind": result.action.kind,
                    "path": result.action.target,
                    "detail": result.detail or result.action.summary,
                    "status": result.status,
                }
                for result in action_results
            ],
            "checks": [
                {
                    "capability": verdict.capability,
                    "harness": verdict.harness,
                    "status": verdict.status.value,
                    "detail": verdict.detail,
                }
                for verdict in verdicts
            ],
            "no_op": not plan,
        }
        print(json.dumps(payload, indent=2))
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acb", description=__doc__)
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="command")

    doctor = sub.add_parser("doctor", help="read-only parity report across harnesses")
    doctor.add_argument(
        "-m", "--manifest", default=None,
        help="manifest path (default: $ACB_MANIFEST, suite config, platform config dir, then ./)",
    )
    doctor.add_argument("--json", action="store_true", help="emit JSON (suite health shape)")
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
        help="manifest path (default: $ACB_MANIFEST, suite config, platform config dir, then ./)",
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
        help="manifest path (default: $ACB_MANIFEST, suite config, platform config dir, then ./)",
    )
    ex.add_argument("capability", help="capability id, e.g. cred:svc-bot")
    ex.add_argument("argv", nargs=argparse.REMAINDER, help="-- command and args to run")
    ex.set_defaults(func=_cmd_exec)

    ih = sub.add_parser(
        "install-harness",
        help="install (or --uninstall) shims into one harness and verify capabilities",
    )
    ih.add_argument(
        "harness", help="harness to provision (claude, opencode, codex, or all)"
    )
    ih.add_argument(
        "-m", "--manifest", default=None,
        help="manifest path (default: $ACB_MANIFEST, suite config, platform config dir, then ./)",
    )
    ih.add_argument(
        "--dry-run", action="store_true",
        help="show what would be installed/uninstalled without applying"
    )
    ih.add_argument(
        "--uninstall", action="store_true",
        help="remove acb-owned shims and MCP wiring (ownership hash check, preserves hand-authored)"
    )
    ih.add_argument("--json", action="store_true", help="emit contract-shaped JSON")
    ih.set_defaults(func=_cmd_install_harness)

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
