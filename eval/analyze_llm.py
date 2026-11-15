"""Analyse raw LLM experiment JSONL written by ``supplyguard slopcheck --out``.

    python eval/analyze_llm.py eval/results/llm.jsonl
    python eval/analyze_llm.py eval/results/*.jsonl --csv eval/results/llm.csv
    python eval/analyze_llm.py eval/results/llm.jsonl --json eval/results/llm.json
    python eval/analyze_llm.py eval/results/llm.jsonl --osv

For every unique suggested name the PyPI JSON API is queried once (cached in
.supplyguard_cache/).  A suggestion is:

* missing     - the name does not exist on PyPI (a true slopsquatting target),
* suspicious  - it exists, but is very new or has only one release,
* known bad   - optional --osv lookup finds an OpenSSF/OSV MAL-* record.

The main metric is the *call-level hallucination rate*: the fraction of model
answers that contain at least one non-existent package.  Unique-name rates are
reported next to it because one bad name repeated in ten answers is still one
bad recommendation.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard import osv, pypi  # noqa: E402
from supplyguard.metrics import format_rate  # noqa: E402
from supplyguard.parser import normalize  # noqa: E402
from supplyguard.slopsquat import extract_names  # noqa: E402

NEW_PACKAGE_DAYS = 90


def read_records(paths: list[str]) -> list[dict]:
    records: list[dict] = []
    for raw_path in paths:
        path = Path(raw_path)
        with open(path, encoding="utf-8-sig") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    print(f"warning: {path}:{lineno}: invalid JSON, skipped",
                          file=sys.stderr)
                    continue
                if not isinstance(record, dict):
                    continue
                # Old records may only have the raw content.
                if "suggested" not in record:
                    record["suggested"] = extract_names(record.get("content", ""))
                record["suggested"] = [
                    normalize(str(n)) for n in record.get("suggested") or []
                    if str(n).strip()
                ]
                records.append(record)
    return records


def group_key(record: dict) -> tuple[str, str, float]:
    return (
        str(record.get("model", "unknown")),
        str(record.get("prompt_variant", "plain")),
        float(record.get("temperature", 0.0)),
    )


def verify_names(names: set[str], lookup: bool) -> dict[str, str]:
    """Map each name to missing / suspicious / ok / unknown."""
    status: dict[str, str] = {}
    for i, name in enumerate(sorted(names), 1):
        if not lookup:
            status[name] = "unknown"
            continue
        info = pypi.fetch(name)
        if info is None:
            status[name] = "unknown"
        elif not info.exists:
            status[name] = "missing"
        else:
            age = info.age_days()
            if (age is not None and age < NEW_PACKAGE_DAYS) or info.release_count <= 1:
                status[name] = "suspicious"
            else:
                status[name] = "ok"
        if i % 50 == 0:
            print(f"  verified {i}/{len(names)} unique names ...", file=sys.stderr)
    return status


def summarize(
    records: list[dict],
    status: dict[str, str],
    malicious: dict[str, osv.MaliciousHit] | None = None,
) -> list[dict]:
    malicious = malicious or {}
    groups: dict[tuple[str, str, float], list[dict]] = defaultdict(list)
    for record in records:
        groups[group_key(record)].append(record)

    rows: list[dict] = []
    for (model, variant, temperature), items in sorted(groups.items()):
        successful = [r for r in items if not r.get("error")]
        unique = {n for r in successful for n in r["suggested"]}
        missing_unique = {n for n in unique if status.get(n) == "missing"}
        suspicious_unique = {n for n in unique if status.get(n) == "suspicious"}
        unknown_unique = {n for n in unique if status.get(n) == "unknown"}
        malicious_unique = {n for n in unique if n in malicious}
        calls_with_missing = sum(
            1 for r in successful if any(status.get(n) == "missing" for n in r["suggested"])
        )
        calls_with_malicious = sum(
            1 for r in successful if any(n in malicious for n in r["suggested"])
        )
        calls_with_suspicious = sum(
            1 for r in successful if any(status.get(n) == "suspicious" for n in r["suggested"])
        )
        suggestions = sum(len(r["suggested"]) for r in successful)

        rows.append({
            "model": model,
            "prompt_variant": variant,
            "temperature": temperature,
            "calls": len(items),
            "errors": len(items) - len(successful),
            "successful_calls": len(successful),
            "suggestions": suggestions,
            "suggestions_per_call": round(suggestions / len(successful), 2) if successful else 0.0,
            "unique_names": len(unique),
            "unique_missing": len(missing_unique),
            "unique_suspicious": len(suspicious_unique),
            "unique_unknown": len(unknown_unique),
            "unique_malicious": len(malicious_unique),
            "calls_with_missing": calls_with_missing,
            "calls_with_suspicious": calls_with_suspicious,
            "calls_with_malicious": calls_with_malicious,
            "call_hallucination_rate": round(calls_with_missing / len(successful), 4) if successful else 0.0,
            "unique_hallucination_rate": round(len(missing_unique) / len(unique), 4) if unique else 0.0,
            "suspicious_call_rate": round(calls_with_suspicious / len(successful), 4) if successful else 0.0,
            "missing_names": sorted(missing_unique),
            "suspicious_names": sorted(suspicious_unique),
            "malicious_names": sorted(malicious_unique),
        })
    return rows


def print_table(rows: list[dict]) -> None:
    print(
        f"{'model':<26}{'variant':<10}{'T':>5}{'calls':>7}{'err':>5}"
        f"{'sugg/call':>11}{'halluc calls':>22}{'missing/uniq':>22}{'susp calls':>20}"
    )
    for row in rows:
        print(
            f"{row['model'][:25]:<26}{row['prompt_variant']:<10}"
            f"{row['temperature']:>5.2f}{row['calls']:>7}{row['errors']:>5}"
            f"{row['suggestions_per_call']:>11.2f}"
            f"{format_rate(row['calls_with_missing'], row['successful_calls']):>22}"
            f"{format_rate(row['unique_missing'], row['unique_names']):>22}"
            f"{format_rate(row['calls_with_suspicious'], row['successful_calls']):>20}"
        )


def print_details(rows: list[dict], missing_counts: Counter, suspicious_counts: Counter,
                  malicious: dict[str, osv.MaliciousHit], top: int) -> None:
    if missing_counts:
        print("\nMost frequently hallucinated names:")
        for name, count in missing_counts.most_common(top):
            print(f"  {name:<40} {count:>4} mention(s)")
    if suspicious_counts:
        print("\nMost frequently suggested new/low-release names:")
        for name, count in suspicious_counts.most_common(top):
            print(f"  {name:<40} {count:>4} mention(s)")
    if malicious:
        print("\nKnown malicious names suggested by the model:")
        for name, hit in sorted(malicious.items()):
            print(f"  {name:<40} {', '.join(hit.ids)}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", nargs="+", help="one or more raw JSONL files")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip PyPI lookups (raw counts only)")
    ap.add_argument("--osv", action="store_true",
                    help="also flag suggestions with an OSV MAL-* record")
    ap.add_argument("--top", type=int, default=20)
    ap.add_argument("--csv")
    ap.add_argument("--json")
    args = ap.parse_args()

    records = read_records(args.jsonl)
    if not records:
        sys.exit("no records found")

    names = {n for r in records for n in r["suggested"]}
    print(f"{len(records)} call(s), {len(names)} unique suggested name(s)")
    if args.no_verify:
        print("PyPI verification skipped (--no-verify): existence rates are not computed.")
    status = verify_names(names, lookup=not args.no_verify)

    malicious: dict[str, osv.MaliciousHit] = {}
    if args.osv and names:
        try:
            malicious = osv.query(sorted(names))
        except osv.OsvError as exc:
            print(f"warning: OSV lookup skipped: {exc}", file=sys.stderr)

    rows = summarize(records, status, malicious)
    print()
    print_table(rows)

    missing_counts = Counter(
        n for r in records if not r.get("error") for n in r["suggested"]
        if status.get(n) == "missing"
    )
    suspicious_counts = Counter(
        n for r in records if not r.get("error") for n in r["suggested"]
        if status.get(n) == "suspicious"
    )
    print_details(rows, missing_counts, suspicious_counts, malicious, args.top)

    if args.csv:
        path = Path(args.csv)
        path.parent.mkdir(parents=True, exist_ok=True)
        fields = [
            "model", "prompt_variant", "temperature", "calls", "errors",
            "successful_calls", "suggestions", "suggestions_per_call",
            "unique_names", "unique_missing", "unique_suspicious", "unique_unknown",
            "unique_malicious", "calls_with_missing", "calls_with_suspicious",
            "calls_with_malicious",
            "call_hallucination_rate", "unique_hallucination_rate",
            "suspicious_call_rate", "missing_names", "suspicious_names",
            "malicious_names",
        ]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                flat = dict(row)
                flat["missing_names"] = ";".join(row["missing_names"])
                flat["suspicious_names"] = ";".join(row["suspicious_names"])
                flat["malicious_names"] = ";".join(row["malicious_names"])
                writer.writerow(flat)
        print(f"\nsummary written to {args.csv}")

    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "records": len(records),
            "unique_names": len(names),
            "verified": not args.no_verify,
            "groups": rows,
            "top_missing": dict(missing_counts.most_common(args.top)),
            "top_suspicious": dict(suspicious_counts.most_common(args.top)),
            "known_malicious": {n: list(h.ids) for n, h in malicious.items()},
        }
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"results written to {args.json}")


if __name__ == "__main__":
    main()
