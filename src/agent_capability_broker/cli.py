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
import os
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

from . import provenance
from .model import (
    KNOWN_HARNESSES,
    Action,
    ActionResult,
    Capability,
    ManifestError,
    Status,
    Verdict,
    parse_manifest,
    resolve_manifest,
)
from .providers import PROVIDERS, adapters, exec_composed

_STABLE_INSTALL_HARNESSES = ("claude", "opencode")
_CAPABILITY_ID = re.compile(r"^(?:cred|e2e):\S+$")


def emit_error(
    code: str,
    message: str,
    *,
    use_json: bool,
    detail: str | None = None,
    retryable: bool = False,
    exit_code: int = 1,
) -> int:
    """Report an operational error per suite CLI contract v1 §3 and return the code.

    Under ``--json`` the common error envelope is the single stdout document;
    otherwise the human ``error:`` message goes to *stderr* (acb's existing
    convention). No path prints an error and exits 0. ``exit_code`` defaults to
    1 — the operational-error slot in the taxonomy (0 success, 2 usage). The
    envelope shape is validated by ``agent_suite.conformance`` in the tests; it
    is reproduced here so runtime code never depends on the dev-only kit.
    """
    if use_json:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": code,
                        "message": message,
                        "detail": detail,
                        "retryable": retryable,
                        "partial": None,
                    },
                },
                indent=2,
            )
        )
    else:
        print(f"error: {message}", file=sys.stderr)
        if detail:
            print(f"  {detail}", file=sys.stderr)
    return exit_code


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
        # A missing or malformed manifest is an *operational* failure, not a
        # usage error: emit the contract-v1 envelope (§3) and exit 1, not 2.
        # (The act-path verbs still return 2 here pending live-validated
        # reclassification — acb WI-014 defers that; this read-only path is safe.)
        return emit_error("MANIFEST_ERROR", str(exc), use_json=args.json)

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


_EXEC_USAGE = "usage: acb exec [-m MANIFEST] <cap> [<cap>…] -- <cmd…>"


def _cmd_exec_raw(raw: list[str]) -> int:
    """Parse and run `acb exec` from the raw tokens after the subcommand.

    Deliberately not argparse: argparse consumes the first `--` itself before
    REMAINDER capture, which made any tokenwise capability/command split
    downstream unsound (adversarial review of PR #14, F1 — a child argument
    shaped like `cred:x` could trigger an unrequested checkout). Here the
    first literal `--` is the authoritative boundary: `-m` and capability ids
    may only appear before it; everything after it is the child command,
    never inspected. Without `--`, the historical single-capability form
    `acb exec <cap> <cmd…>` is preserved verbatim; composing requires `--`.
    """
    if "--" in raw:
        sep = raw.index("--")
        head, command = raw[:sep], raw[sep + 1 :]
    else:
        head, command = raw, []

    if any(tok in ("-h", "--help") for tok in head):
        print(_EXEC_USAGE)
        return 0

    manifest: str | None = None
    cap_ids: list[str] = []
    i = 0
    error: str | None = None
    while i < len(head):
        tok = head[i]
        if tok in ("-m", "--manifest"):
            if i + 1 >= len(head):
                error = f"{tok} requires a value"
                break
            manifest = head[i + 1]
            i += 2
            continue
        if tok.startswith("--manifest="):
            manifest = tok.split("=", 1)[1]
            i += 1
            continue
        if (
            "--" in raw
            and tok.startswith("-")
            and tok not in ("-m", "--manifest")
            and not tok.startswith("--manifest=")
        ):
            # In the composed form (with '--'), any head token starting with
            # '-' that is not a manifest option is unknown — refuse it
            # explicitly rather than misreporting as a non-capability id
            # (review F11). The historical no-'--' form still lets the first
            # capability eat the rest of the line as the child command.
            error = f"unknown option {tok!r}"
            break
        if tok.startswith("-") and not cap_ids:
            # No '--' and no capability yet: an unknown option-shaped token
            # is still unknown (the historical form requires the capability
            # to be the first token).
            error = f"unknown option {tok!r}"
            break
        if "--" not in raw and cap_ids:
            # Historical form: first non-flag token is the capability, the
            # rest is the child command, uninspected.
            command = head[i:]
            break
        if "--" in raw and not _CAPABILITY_ID.fullmatch(tok):
            error = (
                f"{tok!r} before '--' is not a capability id "
                f"(expected provider:name, e.g. cred:svc-bot)"
            )
            break
        cap_ids.append(tok)
        i += 1

    if error is not None:
        print(f"error: {error}\n{_EXEC_USAGE}", file=sys.stderr)
        return 2
    if not cap_ids:
        print(f"error: no capability id\n{_EXEC_USAGE}", file=sys.stderr)
        return 2
    if not command:
        print(f"error: no command\n{_EXEC_USAGE}", file=sys.stderr)
        return 2
    if len(cap_ids) != len(set(cap_ids)):
        print(f"error: repeated capability id\n{_EXEC_USAGE}", file=sys.stderr)
        return 2

    try:
        caps = parse_manifest(resolve_manifest(manifest))
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    wanted: list[Capability] = []
    for cap_id in cap_ids:
        cap = next((c for c in caps if c.id == cap_id), None)
        if cap is None:
            print(f"error: capability {cap_id!r} not in manifest", file=sys.stderr)
            return 2
        wanted.append(cap)

    if len(wanted) > 1:
        try:
            return exec_composed(wanted, command)
        except (RuntimeError, NotImplementedError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    provider = PROVIDERS.get(wanted[0].provider)
    if provider is None:
        print(f"error: no provider {wanted[0].provider!r}", file=sys.stderr)
        return 2

    try:
        return provider.exec(wanted[0], command)
    except (RuntimeError, NotImplementedError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


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
    """
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
        payload = {
            "tool": "acb",
            "harness": args.harness,
            "user": None,
            "status": "installed",
            "actions": [
                {
                    "kind": action.kind,
                    "path": action.target,
                    "detail": action.summary,
                }
                for action in plan
            ],
            "no_op": not plan,
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
        except (OSError, KeyError) as exc:
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


def _serialize_toml_value(value: str | list[str]) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(f'"{v}"' for v in value) + "]"
    return f'"{value}"'


def _serialize_capability_toml(cap_id: str, options: dict[str, str | list[str]]) -> str:
    lines = [f'[capability."{cap_id}"]']
    lines.append(f'provider   = {_serialize_toml_value("cred")}')
    for key, value in options.items():
        lines.append(f'{key:<10} = {_serialize_toml_value(value)}')
    return "\n".join(lines) + "\n"


def _cmd_register(args: argparse.Namespace) -> int:
    cap_id: str = args.capability_id
    if not _CAPABILITY_ID.match(cap_id):
        print(
            f"error: invalid capability ID {cap_id!r} "
            "(must match cred:<name> or e2e:<name>)",
            file=sys.stderr,
        )
        return 2
    if not cap_id.startswith("cred:"):
        print("error: register currently supports only cred: capabilities", file=sys.stderr)
        return 2

    for harness in args.harnesses:
        if harness not in KNOWN_HARNESSES:
            print(
                f"error: unknown harness {harness!r} "
                f"(known: {', '.join(sorted(KNOWN_HARNESSES))})",
                file=sys.stderr,
            )
            return 2

    manifest_path = resolve_manifest(getattr(args, "manifest", None))

    existing: list[Capability] = []
    if manifest_path.is_file():
        try:
            existing = parse_manifest(manifest_path)
        except ManifestError as exc:
            print(f"error: cannot parse existing manifest: {exc}", file=sys.stderr)
            return 2

    if any(c.id == cap_id for c in existing):
        if args.json:
            print(json.dumps(
                {"capability": cap_id, "status": "already_registered",
                 "path": str(manifest_path)},
                indent=2,
            ))
        else:
            print(f"{cap_id}: already registered in {manifest_path}")
        return 0

    options: dict[str, str | list[str]] = {"vault": args.vault}
    if len(args.fields) == 1:
        options["field"] = args.fields[0]
    else:
        options["fields"] = args.fields
    if args.env_prefix:
        options["env_prefix"] = args.env_prefix
    if args.vault_env:
        options["vault_env"] = args.vault_env
    options["harnesses"] = args.harnesses

    entry = _serialize_capability_toml(cap_id, options)

    if not args.apply:
        if args.json:
            print(json.dumps(
                {"capability": cap_id, "status": "dry_run", "entry": entry,
                 "path": str(manifest_path)},
                indent=2,
            ))
        else:
            print(f"would append to {manifest_path}:\n")
            print(entry)
            print("Re-run with --apply to write.")
        return 2

    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("a", encoding="utf-8") as f:
        f.write("\n" + entry)

    if args.json:
        print(json.dumps(
            {"capability": cap_id, "status": "registered", "path": str(manifest_path)},
            indent=2,
        ))
    else:
        print(f"registered {cap_id} in {manifest_path}")

    for harness in args.harnesses:
        adapter = adapters().get(harness)
        if adapter is None or not adapter.available():
            continue
        caps = parse_manifest(manifest_path)
        cap = next((c for c in caps if c.id == cap_id), None)
        if cap is None:
            continue
        provider = PROVIDERS.get(cap.provider)
        if provider is None:
            continue
        plan = provider.plan_reconcile(cap, harness, adapter)
        for action in plan:
            try:
                result = provider.apply(action, adapter)
                provenance.emit(result)
                if not args.json:
                    print(
                        f"  [{result.status.upper()}] {harness}: "
                        f"{result.detail or action.summary}"
                    )
            except (OSError, KeyError) as exc:
                if not args.json:
                    print(f"  [FAILED] {harness}: {exc}")

    return 0


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

    # `exec` is registered for `acb --help` discovery only. `main()` routes it
    # to `_cmd_exec_raw` before argparse runs, because argparse consumes the
    # first `--` — the token this command's grammar depends on (PR #14 F1).
    ex = sub.add_parser(
        "exec", help="run a command with one or more capabilities injected (never surfaced)"
    )
    ex.add_argument("tokens", nargs=argparse.REMAINDER, help=_EXEC_USAGE)

    ih = sub.add_parser(
        "install-harness",
        help="install shims into one harness and verify capabilities (bootstrap)",
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
        help="show what would be installed without applying"
    )
    ih.add_argument("--json", action="store_true", help="emit contract-shaped JSON")
    ih.set_defaults(func=_cmd_install_harness)

    reg = sub.add_parser(
        "register",
        help="add a credential capability to the manifest and render shims (idempotent)",
    )
    reg.add_argument("capability_id", help="capability ID (e.g. cred:pypi)")
    reg.add_argument("--vault", required=True, help="Vault KV v2 path (e.g. kv/homelab/pypi/token)")
    reg.add_argument(
        "--fields", nargs="+", required=True,
        help="secret fields to expose (e.g. token, or username password)",
    )
    reg.add_argument("--env-prefix", help="env var prefix for injection (e.g. PYPI → PYPI_TOKEN)")
    reg.add_argument(
        "--vault-env", help="per-plane AppRole .env file (for non-default access planes)"
    )
    reg.add_argument(
        "--harnesses", nargs="+", default=list(_STABLE_INSTALL_HARNESSES),
        help="harnesses to expose (default: claude opencode)",
    )
    reg.add_argument(
        "--apply", action="store_true",
        help="write the manifest entry and render shims (default: dry-run)",
    )
    reg.add_argument("--json", action="store_true", help="emit the result as JSON")
    reg.set_defaults(func=_cmd_register)

    return parser


def _dispatch(raw: list[str], argv: list[str] | None) -> int:
    if raw and raw[0] == "exec":
        return _cmd_exec_raw(raw[1:])
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


def main(argv: list[str] | None = None) -> int:
    """Top-level entry point and last-resort error boundary (CLI contract §3/§4).

    argparse's usage errors raise ``SystemExit`` (exit 2) straight through — a
    ``BaseException``, not caught here, so the usage taxonomy is preserved. Any
    other uncaught exception becomes a contract envelope instead of a traceback:
    a ``ManifestError`` that escaped an act-path verb keeps its ``MANIFEST_ERROR``
    code; anything else is reported as ``INTERNAL_ERROR``. A closed downstream
    pipe is swallowed the CPython way so the interpreter's final flush can't
    re-raise.
    """
    raw = list(sys.argv[1:] if argv is None else argv)
    json_mode = "--json" in raw
    try:
        return _dispatch(raw, argv)
    except BrokenPipeError:
        # A downstream reader closed the pipe (e.g. `acb ... | head`). Redirect
        # stdout to devnull so the final flush at interpreter exit can't raise,
        # and exit without a traceback (§4).
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 1
    except ManifestError as exc:
        return emit_error("MANIFEST_ERROR", str(exc), use_json=json_mode)
    except Exception as exc:  # last-resort boundary: never surface a traceback
        return emit_error(
            "INTERNAL_ERROR",
            f"unexpected {exc.__class__.__name__}: {exc}",
            use_json=json_mode,
        )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
