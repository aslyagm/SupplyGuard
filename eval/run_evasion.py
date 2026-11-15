"""Run the adversarial/evasion suite in eval/evasion/cases.json.

    python eval/run_evasion.py
    python eval/run_evasion.py --json eval/results/evasion.json --csv eval/results/evasion.csv

The suite is offline and deterministic.  ``defended`` cases must still be
flagged and ``control`` cases must stay OK; a regression there exits 1.
``known-gap`` / ``known-fp`` rows document current weaknesses.  They never fail
the suite, but if they start behaving differently the runner reports an
improvement so the dataset can be updated.

No package is downloaded or installed; every case is just a line in a temporary
requirements file.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.parser import parse_requirements_detailed  # noqa: E402
from supplyguard.popular import load_popular  # noqa: E402
from supplyguard.scoring import LEVEL_ORDER, assess  # noqa: E402

HERE = Path(__file__).parent
DEFAULT_CASES = HERE / "evasion" / "cases.json"


def load_cases(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = data.get("cases") if isinstance(data, dict) else data
    if not isinstance(cases, list) or not cases:
        raise ValueError(f"{path}: no cases found")
    for case in cases:
        for field in ("id", "technique", "requirement", "status"):
            if not case.get(field):
                raise ValueError(f"{path}: case missing {field!r}: {case}")
        if case["status"] not in {"defended", "control", "known-gap", "known-fp"}:
            raise ValueError(f"{path}: unknown status {case['status']!r}")
    return cases


def evaluate_case(case: dict, popular) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        req = Path(tmp) / "requirements.txt"
        req.write_text(case["requirement"] + "\n", encoding="utf-8")
        parsed = parse_requirements_detailed(req)

    if parsed:
        name = parsed[0].name
        finding = assess(name, popular)
        level, score, target = finding.level, finding.score, finding.target
    else:
        name, level, score, target = "", "OK", 0.0, None

    flagged = LEVEL_ORDER[level] > LEVEL_ORDER["OK"]
    strong = LEVEL_ORDER[level] >= LEVEL_ORDER["MEDIUM"]
    target_ok = (
        not case.get("expected_target")
        or target == case["expected_target"]
    )
    status = case["status"]

    if status == "defended":
        passed = flagged and target_ok
        outcome = "pass" if passed else "FAIL"
    elif status == "control":
        passed = not flagged
        outcome = "pass" if passed else "FAIL"
    elif status == "known-gap":
        passed = True
        outcome = "improved" if flagged else "documented"
    else:  # known-fp
        passed = True
        outcome = "improved" if not flagged else "documented"

    return {
        "id": case["id"],
        "technique": case["technique"],
        "status": status,
        "requirement": case["requirement"],
        "parsed_name": name,
        "level": level,
        "score": score,
        "target": target,
        "expected_target": case.get("expected_target"),
        "flagged": flagged,
        "strong": strong,
        "outcome": outcome,
        "passed": passed,
        "note": case.get("note", ""),
    }


def print_results(rows: list[dict], show_ok: bool) -> None:
    print(
        f"{'case':<24}{'technique':<22}{'status':<11}"
        f"{'parsed':<22}{'level':<7}{'score':>6}  {'target':<20}outcome"
    )
    for row in rows:
        if not show_ok and row["outcome"] == "pass":
            continue
        print(
            f"{row['id']:<24}{row['technique']:<22}{row['status']:<11}"
            f"{(row['parsed_name'] or '-'):<22}{row['level']:<7}{row['score']:>6.2f}"
            f"  {(row['target'] or '-'):<20}{row['outcome']}"
        )
        if row["outcome"] == "FAIL":
            print(
                f"    expected target={row['expected_target']!r}, "
                f"parsed={row['parsed_name']!r}; {row['note']}"
            )


def print_summary(rows: list[dict]) -> None:
    print()
    for status in ("defended", "control", "known-gap", "known-fp"):
        group = [r for r in rows if r["status"] == status]
        if not group:
            continue
        lowered = sum(1 for r in group if r["flagged"])
        strong = sum(1 for r in group if r["strong"])
        passed = sum(1 for r in group if r["passed"])
        if status in {"defended", "control"}:
            print(
                f"{status:<12} {passed}/{len(group)} expectations met, "
                f"{lowered} flagged, {strong} at MEDIUM+"
            )
        else:
            improved = sum(1 for r in group if r["outcome"] == "improved")
            print(
                f"{status:<12} {len(group)} documented, {lowered} flagged, "
                f"{strong} at MEDIUM+, {improved} improved"
            )

    failures = [r for r in rows if not r["passed"]]
    print()
    if failures:
        print(f"{len(failures)} regression(s):")
        for row in failures:
            print(f"  - {row['id']} ({row['technique']}): expected a different result")
    else:
        print("All defended/control expectations met. Known gaps are documented.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default=str(DEFAULT_CASES))
    ap.add_argument("--show-ok", action="store_true", help="also print passing rows")
    ap.add_argument("--json")
    ap.add_argument("--csv")
    args = ap.parse_args()

    cases = load_cases(Path(args.cases))
    popular = load_popular()
    rows = [evaluate_case(case, popular) for case in cases]

    print(f"{len(cases)} evasion case(s), reference: {len(popular)} popular packages\n")
    print_results(rows, args.show_ok)
    print_summary(rows)

    if args.csv:
        path = Path(args.csv)
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = list(rows[0])
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        print(f"\nresults written to {args.csv}")

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "reference_count": len(popular),
            "cases": rows,
            "failures": [r["id"] for r in rows if not r["passed"]],
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"results written to {args.json}")

    raise SystemExit(1 if any(not r["passed"] for r in rows) else 0)


if __name__ == "__main__":
    main()
