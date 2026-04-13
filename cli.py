"""
AtomicLoop — CLI for offline atomic test execution and detection validation.

Usage:
    python cli.py --list
    python cli.py --technique T1059.001
    python cli.py --technique T1059.001 --test 1 --dry-run
    python cli.py --technique T1059.001 --test 1 --confirm
    python cli.py --technique T1059.001 --test 1 --confirm --validate --sigma rule.yml
    python cli.py --results
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Ensure core package is importable when running from repo root
sys.path.insert(0, os.path.dirname(__file__))

import yaml
from app import load_config, _DEFAULTS
from core.engine  import AtomicEngine
from core.atomics import get_all_techniques, get_technique, list_techniques_by_tactic


def main() -> None:
    args = parse_args()

    config_path = args.config
    config      = load_config(config_path)
    engine      = AtomicEngine(config)

    if args.list:
        cmd_list(args)
    elif args.technique and not args.test:
        cmd_technique(args)
    elif args.technique and args.test:
        cmd_run(args, engine)
    elif args.results:
        cmd_results(args, engine)
    elif args.result_id:
        cmd_result(args, engine)
    else:
        print("AtomicLoop CLI — use --help for usage.")


# ── Subcommands ───────────────────────────────────────────────────────────────

def cmd_list(args: argparse.Namespace) -> None:
    """List all available techniques."""
    techniques = get_all_techniques()
    by_tactic  = list_techniques_by_tactic()

    print("\nAtomicLoop — Embedded Test Library")
    print("=" * 60)
    for tactic, tids in sorted(by_tactic.items()):
        print(f"\n  {tactic}")
        for tid in tids:
            t = next(x for x in techniques if x["technique_id"] == tid)
            print(f"    {tid:<14}  {t['test_count']} test(s)  {t['technique_name']}")
    print(f"\nTotal: {len(techniques)} techniques\n")


def cmd_technique(args: argparse.Namespace) -> None:
    """Show tests for a technique."""
    tech = get_technique(args.technique)
    if tech is None:
        print(f"[!] Technique {args.technique!r} not found.")
        sys.exit(1)

    print(f"\n{tech['technique_id']} — {tech['technique_name']}")
    print(f"Tactic: {tech['tactic']}")
    print(f"URL:    {tech['mitre_url']}")
    print(f"\n{tech.get('description', '')}\n")
    print(f"{'─'*60}")

    for test in tech["tests"]:
        perm = test.get("required_permissions", "user")
        perm_tag = f"[ADMIN]" if perm == "administrator" else "[user]"
        print(f"\n  Test #{test['test_number']}: {test['test_name']}  {perm_tag}")
        print(f"  Executor: {test['executor_type']}")
        print(f"  Description: {test['description'][:120]}")
        print(f"  Expected EIDs: {test.get('expected_event_ids', [])}")
        if test.get("input_arguments"):
            print("  Input Arguments:")
            for arg, defn in test["input_arguments"].items():
                print(f"    #{{{arg}}} = {defn.get('default', '')}  ({defn.get('description', '')})")
        print(f"  Command preview:")
        print(f"    {test['command'][:100]}{'...' if len(test['command']) > 100 else ''}")
    print()


def cmd_run(args: argparse.Namespace, engine: AtomicEngine) -> None:
    """Execute a specific test."""
    dry_run = args.dry_run
    confirm = args.confirm

    if not dry_run and not confirm:
        print("[!] Execution requires --confirm flag (or use --dry-run to preview).")
        sys.exit(1)

    # Load input arguments from --args JSON or --arg key=value pairs
    input_arguments: dict = {}
    if args.args:
        try:
            input_arguments = json.loads(args.args)
        except json.JSONDecodeError:
            print(f"[!] --args must be valid JSON: {args.args!r}")
            sys.exit(1)
    if args.arg:
        for kv in args.arg:
            if "=" in kv:
                k, v = kv.split("=", 1)
                input_arguments[k.strip()] = v.strip()

    timeout = args.timeout

    print(f"\nAtomicLoop — Running {args.technique} Test #{args.test}")
    if dry_run:
        print("[DRY RUN] Command will not be executed.\n")
    elif confirm:
        print("[CONFIRMED] Executing...\n")

    result = engine.run_test(
        technique_id=args.technique,
        test_number=args.test,
        confirm=confirm,
        dry_run=dry_run,
        capture_events=not dry_run,
        normalize=True,
        timeout=timeout,
        input_arguments=input_arguments,
        save=not dry_run,
    )

    if not result.get("success") and not dry_run:
        print(f"[!] {result.get('error', 'Unknown error')}")
        sys.exit(1)

    _print_run_summary(result)

    # Optional: validate with Sigma rule
    if args.validate and args.sigma:
        try:
            sigma_rule = open(args.sigma, encoding="utf-8").read()
        except Exception as exc:
            print(f"[!] Could not read Sigma file: {exc}")
            sys.exit(1)

        run_id = result.get("id") or result.get("run_id")
        val_result = engine.validate(
            run_id=run_id,
            sigma_rule=sigma_rule,
            events=result.get("events"),
        )
        _print_validation_result(val_result)

    # Export
    if args.output and result.get("id"):
        output = args.output
        if output.endswith(".md"):
            content = engine.to_markdown(result)
        else:
            content = json.dumps(result, indent=2, ensure_ascii=False)
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"\nSaved to {output}")


def cmd_results(args: argparse.Namespace, engine: AtomicEngine) -> None:
    """List saved runs."""
    data = engine.get_results(
        page=1,
        per_page=50,
        technique_id=args.filter_technique or "",
    )
    items = data.get("items", [])
    if not items:
        print("No saved runs found.")
        return

    print(f"\n{'ID':<36}  {'Technique':<12}  {'Test':<3}  {'ExitCode':<8}  {'Events':<6}  {'Fired':<6}  Executed")
    print("─" * 100)
    for r in items:
        fired_map = {1: "YES", 0: "NO", -1: "—"}
        fired = fired_map.get(r.get("detection_fired", -1), "—")
        print(
            f"{r['id']:<36}  {r['technique_id']:<12}  {r['test_number']:<3}  "
            f"{str(r.get('exit_code', '?')):<8}  {r.get('event_count', 0):<6}  "
            f"{fired:<6}  {(r.get('executed_at') or '')[:19]}"
        )
    print(f"\n{data['total']} total runs\n")


def cmd_result(args: argparse.Namespace, engine: AtomicEngine) -> None:
    """Show a single run by ID."""
    run = engine.get_result(args.result_id)
    if run is None:
        print(f"[!] Run {args.result_id!r} not found.")
        sys.exit(1)
    _print_run_summary(run)
    if run.get("validation"):
        _print_validation_result(run["validation"])


# ── Output helpers ────────────────────────────────────────────────────────────

def _print_run_summary(run: dict) -> None:
    print(f"\n{'─'*60}")
    print(f"  Technique:  {run.get('technique_id')} — {run.get('technique_name', '')}")
    print(f"  Test:       #{run.get('test_number')} — {run.get('test_name', '')}")
    print(f"  Executor:   {run.get('executor_type', '')}")
    print(f"  Exit Code:  {run.get('exit_code', 'N/A')}")
    print(f"  Duration:   {run.get('duration_ms', 0)}ms")
    print(f"  Events:     {run.get('event_count', 0)} captured")
    if run.get("dry_run"):
        print(f"  [DRY RUN — command not executed]")
    print(f"{'─'*60}")

    output = run.get("raw_output", "").strip()
    if output:
        print("\n  --- stdout ---")
        for line in output.splitlines()[:20]:
            print(f"  {line}")
        if len(output.splitlines()) > 20:
            print(f"  ... ({len(output.splitlines()) - 20} more lines)")

    stderr = run.get("stderr", "").strip()
    if stderr:
        print("\n  --- stderr ---")
        for line in stderr.splitlines()[:10]:
            print(f"  {line}")

    events = run.get("events", [])
    if events:
        print(f"\n  Captured {len(events)} event(s):")
        for e in events[:5]:
            ev   = e.get("event", {})
            code = ev.get("code", "?")
            act  = ev.get("action", "")
            ts   = (e.get("@timestamp") or "")[:19]
            src  = e.get("log", {}).get("name", "")
            print(f"    [{code}] {act or src}  {ts}")
        if len(events) > 5:
            print(f"    ... ({len(events) - 5} more)")


def _print_validation_result(result: dict) -> None:
    fired = result.get("detection_fired")
    if fired is True:
        status = "[+] DETECTION FIRED"
    elif fired is False:
        status = "[-] Detection did NOT fire"
    else:
        status = "[?] Detection not evaluated (no Sigma rule)"

    print(f"\n{'─'*60}")
    print(f"  Detection Validation")
    print(f"  {status}")
    print(f"  Matched events: {result.get('match_count', 0)}")
    print(f"  Source: {result.get('source', '')}")
    print()
    print("  Gap Analysis:")
    for line in (result.get("gap_analysis", "") or "").split(". "):
        if line.strip():
            print(f"    {line.strip()}.")
    print(f"{'─'*60}\n")


# ── Argument parser ───────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="AtomicLoop — Atomic Red Team Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py --list
  python cli.py --technique T1059.001
  python cli.py --technique T1059.001 --test 1 --dry-run
  python cli.py --technique T1059.001 --test 1 --confirm
  python cli.py --technique T1059.001 --test 1 --confirm --validate --sigma rule.yml
  python cli.py --results
  python cli.py --result-id <uuid>
        """,
    )
    p.add_argument("--config",    default="config.yaml",
                   help="Config YAML path (default: config.yaml)")
    p.add_argument("--list",      action="store_true",
                   help="List all available techniques")
    p.add_argument("--technique", metavar="ID",
                   help="Technique ID (e.g. T1059.001)")
    p.add_argument("--test",      type=int, metavar="N",
                   help="Test number to run (1-based)")
    p.add_argument("--confirm",   action="store_true",
                   help="Confirm execution (required to run — prevents accidents)")
    p.add_argument("--dry-run",   action="store_true",
                   help="Show command without executing")
    p.add_argument("--timeout",   type=int, default=30,
                   help="Execution timeout in seconds (default: 30)")
    p.add_argument("--args",      metavar="JSON",
                   help="Input arguments as JSON string")
    p.add_argument("--arg",       action="append", metavar="KEY=VALUE",
                   help="Single input argument (repeatable)")
    p.add_argument("--validate",  action="store_true",
                   help="Validate detection after running (requires --sigma)")
    p.add_argument("--sigma",     metavar="FILE",
                   help="Sigma rule YAML file for detection validation")
    p.add_argument("--output",    metavar="FILE",
                   help="Save result to file (.md or .json)")
    p.add_argument("--results",   action="store_true",
                   help="List saved run results")
    p.add_argument("--result-id", dest="result_id", metavar="UUID",
                   help="Show a specific saved run result")
    p.add_argument("--filter-technique", dest="filter_technique", metavar="ID",
                   help="Filter results by technique ID")
    return p.parse_args()


if __name__ == "__main__":
    main()
