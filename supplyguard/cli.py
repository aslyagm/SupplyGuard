"""Command-line interface.

    supplyguard scan requirements.txt [--offline] [--json out.json] [--csv out.csv]
    supplyguard slopcheck --tasks eval/tasks.txt [--model NAME] [--csv out.csv]
    supplyguard update-popular [--limit 5000]
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

from . import pypi, report
from .parser import parse_requirements
from .popular import load_popular, refresh_popular
from .scoring import assess


def cmd_scan(args: argparse.Namespace) -> int:
    popular = load_popular(args.popular)
    names = parse_requirements(args.requirements)
    meta = None if args.offline else pypi.fetch
    findings = [assess(n, popular, meta) for n in names]
    print(report.to_console(findings, show_ok=args.all))
    if args.json:
        report.write_json(findings, args.json)
    if args.csv:
        report.write_csv(findings, args.csv)
    return 1 if any(f.level == "HIGH" for f in findings) else 0


def cmd_slopcheck(args: argparse.Namespace) -> int:
    from .slopsquat import check_task

    tasks = [t.strip() for t in Path(args.tasks).read_text(encoding="utf-8").splitlines()
             if t.strip() and not t.startswith("#")]
    rows = []
    total = missing = 0
    for task in tasks:
        r = check_task(task, args.model)
        total += len(r.suggested)
        missing += len(r.missing)
        flag = f"  MISSING: {', '.join(r.missing)}" if r.missing else ""
        flag += f"  SUSPICIOUS: {', '.join(r.suspicious)}" if r.suspicious else ""
        print(f"- {task[:60]:<60} {len(r.suggested)} suggested{flag}")
        rows.append([task, r.model, ";".join(r.suggested), ";".join(r.missing), ";".join(r.suspicious)])
    rate = missing / total if total else 0
    print(f"\n{missing}/{total} suggested packages do not exist on PyPI ({rate:.1%}).")
    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["task", "model", "suggested", "missing", "suspicious"])
            w.writerows(rows)
    return 0


def cmd_update_popular(args: argparse.Namespace) -> int:
    n = refresh_popular(args.limit)
    print(f"Saved {n} popular package names.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="supplyguard", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a requirements file for typosquatting")
    s.add_argument("requirements")
    s.add_argument("--offline", action="store_true", help="name checks only, no PyPI lookups")
    s.add_argument("--popular", help="custom popular-package list (one name per line)")
    s.add_argument("--all", action="store_true", help="also show packages that look fine")
    s.add_argument("--json")
    s.add_argument("--csv")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("slopcheck", help="check LLM package suggestions against PyPI")
    c.add_argument("--tasks", required=True, help="text file, one programming task per line")
    c.add_argument("--model", default=None)
    c.add_argument("--csv")
    c.set_defaults(func=cmd_slopcheck)

    u = sub.add_parser("update-popular", help="download the current top PyPI package list")
    u.add_argument("--limit", type=int, default=5000)
    u.set_defaults(func=cmd_update_popular)

    args = p.parse_args(argv)
    if getattr(args, "model", "x") is None:
        from .slopsquat import DEFAULT_MODEL
        args.model = DEFAULT_MODEL
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
