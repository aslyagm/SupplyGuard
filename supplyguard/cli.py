"""Command-line interface.

    supplyguard scan requirements.txt [--offline] [--osv] [--json out.json]
        [--csv out.csv] [--sarif out.sarif] [--ignore PATH] [--baseline PATH]
        [--fail-on none|LOW|MEDIUM|HIGH]
    supplyguard slopcheck --tasks eval/tasks_en.txt [--model NAME] [--csv out.csv]
        [--variant plain] [--temperature 0.0,0.7] [--repeats 3] [--out raw.jsonl]
    supplyguard update-popular [--limit 15000]

Exit code for ``scan`` is 1 when a finding at or above ``--fail-on`` (default:
HIGH) is found, ignoring allowlisted and baseline entries.  This is the hook CI
uses; ``--fail-on MEDIUM`` is stricter, ``--fail-on none`` never fails.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from . import __version__, allowlist, baseline, osv, pypi, report
from .parser import Requirement, normalize, parse_requirements_detailed
from .popular import load_popular, refresh_popular
from .scoring import LEVEL_ORDER, Finding, assess

FAIL_ON_CHOICES = ["none", "LOW", "MEDIUM", "HIGH"]
DEFAULT_IGNORE = ".supplyguardignore"


def _collect_requirements(paths: list[str]) -> list[Requirement]:
    """Parse every input file, keeping the first occurrence of each name."""
    seen: set[str] = set()
    out: list[Requirement] = []
    for raw in paths:
        for req in parse_requirements_detailed(raw):
            key = normalize(req.name)
            if key in seen:
                continue
            seen.add(key)
            out.append(req)
    return out


def _report(findings: list[Finding], inputs: list[str], args: argparse.Namespace,
            popular_count: int) -> None:
    print(report.to_console(
        findings,
        show_ok=args.all,
        show_suppressed=args.show_suppressed,
    ))
    meta = {
        "inputs": inputs,
        "popular_count": popular_count,
        "offline": args.offline,
        "osv": args.osv,
        "fail_on": args.fail_on,
    }
    if args.json:
        report.write_json(findings, args.json, meta)
    if args.csv:
        report.write_csv(findings, args.csv)
    if args.sarif:
        report.write_sarif(findings, args.sarif, default_uri=inputs[0] if inputs else "requirements.txt")


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = LEVEL_ORDER[fail_on]
    for f in findings:
        if f.suppressed or f.baseline:
            continue
        if LEVEL_ORDER[f.level] >= threshold:
            return 1
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        popular = load_popular(args.popular)
        requirements = _collect_requirements(args.requirements)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    meta = None if args.offline else pypi.fetch

    findings = []
    for req in requirements:
        finding = assess(req.name, popular, meta)
        finding.source_file = req.file
        finding.source_line = req.line
        findings.append(finding)

    if args.osv:
        try:
            hits = osv.annotate(findings)
        except osv.OsvError as exc:
            print(f"warning: OSV lookup skipped: {exc}", file=sys.stderr)
        else:
            if hits:
                print(f"OSV: {hits} known malicious package(s) found.", file=sys.stderr)

    try:
        ignore_path = args.ignore
        if ignore_path is None:
            ignore_path = DEFAULT_IGNORE if Path(DEFAULT_IGNORE).exists() else None
        if ignore_path:
            suppressions = allowlist.load(ignore_path)
            allowlist.apply(findings, suppressions)
            for name in allowlist.expired(suppressions):
                print(f"warning: suppressed entry expired: {name}", file=sys.stderr)

        if args.baseline:
            baseline.apply(findings, baseline.load(args.baseline))
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    _report(findings, args.requirements, args, len(popular))
    return _exit_code(findings, args.fail_on)


def parse_temperatures(raw: str) -> tuple[float, ...]:
    values = tuple(float(part) for part in raw.split(",") if part.strip())
    if not values:
        raise ValueError("at least one temperature is required")
    for value in values:
        if not 0.0 <= value <= 2.0:
            raise ValueError("temperatures must be between 0 and 2")
    return values


def cmd_slopcheck(args: argparse.Namespace) -> int:
    from .slopsquat import check_task, load_tasks, run_experiment

    tasks = load_tasks(args.tasks)
    try:
        temperatures = parse_temperatures(args.temperature)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    variants = tuple(args.variant) if args.variant else ("plain",)

    if args.out:
        try:
            count = run_experiment(
                tasks,
                args.out,
                model=args.model,
                repeats=args.repeats,
                temperatures=temperatures,
                variants=variants,
                append=args.append,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(f"\n{count} call(s) written to {args.out}")
        print(f"Analyse with: python eval/analyze_llm.py {args.out}")
        return 0

    rows = []
    total = missing = 0
    for task in tasks:
        r = check_task(
            task,
            args.model,
            temperature=temperatures[0],
            prompt_variant=variants[0],
        )
        total += len(r.suggested)
        missing += len(r.missing)
        flag = f"  MISSING: {', '.join(r.missing)}" if r.missing else ""
        flag += f"  SUSPICIOUS: {', '.join(r.suspicious)}" if r.suspicious else ""
        print(f"- {task[:60]:<60} {len(r.suggested)} suggested{flag}")
        rows.append([task, r.model, ";".join(r.suggested), ";".join(r.missing), ";".join(r.suspicious)])
    rate = missing / total if total else 0
    print(f"\n{missing}/{total} suggested packages do not exist on PyPI ({rate:.1%}).")
    if args.csv:
        Path(args.csv).parent.mkdir(parents=True, exist_ok=True)
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["task", "model", "suggested", "missing", "suspicious"])
            w.writerows(rows)
    return 0


def cmd_update_popular(args: argparse.Namespace) -> int:
    try:
        n = refresh_popular(args.limit)
    except (OSError, ValueError) as exc:
        print(f"error: could not update the popular list: {exc}", file=sys.stderr)
        return 2
    print(f"Saved {n} popular package names.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="supplyguard", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a requirements file for typosquatting")
    s.add_argument("requirements", nargs="+", help="requirements.txt file(s); nested -r includes are followed")
    s.add_argument("--offline", action="store_true", help="name checks only, no PyPI lookups")
    s.add_argument("--popular", help="custom popular-package list (<name>[TAB<downloads>] per line)")
    s.add_argument("--all", action="store_true", help="also show packages that look fine")
    s.add_argument("--show-suppressed", action="store_true", help="also show allowlisted findings")
    s.add_argument("--osv", action="store_true", help="query OSV for known malicious packages")
    s.add_argument("--ignore", metavar="PATH",
                   help=f"allowlist file (default: {DEFAULT_IGNORE} when present)")
    s.add_argument("--baseline", metavar="PATH",
                   help="previous --json report; findings already in it are marked [baseline]")
    s.add_argument("--fail-on", choices=FAIL_ON_CHOICES, default="HIGH",
                   help="lowest level that makes the command exit 1 (default: HIGH)")
    s.add_argument("--json", metavar="PATH")
    s.add_argument("--csv", metavar="PATH")
    s.add_argument("--sarif", metavar="PATH", help="SARIF 2.1.0 report for GitHub code scanning")
    s.set_defaults(func=cmd_scan)

    from .slopsquat import DEFAULT_VARIANT, PROMPTS

    c = sub.add_parser("slopcheck", help="check LLM package suggestions against PyPI")
    c.add_argument("--tasks", required=True, help="text file, one programming task per line")
    c.add_argument("--model", default=None)
    c.add_argument("--temperature", default="0.7",
                   help="one value, or comma-separated values for --out experiments")
    c.add_argument("--variant", action="append", choices=sorted(PROMPTS),
                   help=f"prompt variant (default: {DEFAULT_VARIANT}); repeat for several")
    c.add_argument("--repeats", type=int, default=1,
                   help="repetitions per task/variant/temperature (experiment mode)")
    c.add_argument("--out", metavar="JSONL",
                   help="write every raw LLM answer as JSONL (experiment mode)")
    c.add_argument("--append", action="store_true", help="append to an existing --out file")
    c.add_argument("--csv", help="summary CSV (single-shot mode)")
    c.set_defaults(func=cmd_slopcheck)

    u = sub.add_parser("update-popular", help="download the current top PyPI package list")
    u.add_argument("--limit", type=int, default=15000)
    u.set_defaults(func=cmd_update_popular)

    args = p.parse_args(argv)
    if getattr(args, "model", "x") is None:
        from .slopsquat import DEFAULT_MODEL
        args.model = DEFAULT_MODEL
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
