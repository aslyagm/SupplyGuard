"""Compare naive name-similarity baselines with SupplyGuard.

    python eval/run_eval.py                 # offline, representative sample
    python eval/run_eval.py --all           # every labelled name
    python eval/run_eval.py --online        # also use PyPI metadata
    python eval/run_eval.py --sweep         # score-threshold table
    python eval/run_eval.py --json out.json

Positives: eval/malicious_names.txt      (OpenSSF/OSV malicious PyPI names)
Negatives: eval/benign_names.txt         (real PyPI packages, non-top-15k)
Optional:  eval/benign_pairs.csv         (hard look-alike pairs, reported separately)

The old version filtered positives through the detector's own
``closest_popular`` function.  That guaranteed recall and is not done here;
the full set is evaluated, and the "representable" subset is reported
separately as a coverage diagnostic.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard import pypi  # noqa: E402
from supplyguard.metrics import (  # noqa: E402
    confusion,
    format_rate,
    mcnemar,
    rate_with_ci,
)
from supplyguard.parser import normalize  # noqa: E402
from supplyguard.popular import PopularIndex, load_popular  # noqa: E402
from supplyguard.scoring import LEVEL_ORDER, assess  # noqa: E402
from supplyguard.similarity import (  # noqa: E402
    bag_distance,
    char_counts,
    damerau_levenshtein,
    levenshtein,
)

HERE = Path(__file__).parent


def read_names(path: Path) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name = normalize(line)
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def read_pairs(path: Path) -> list[str]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return [normalize(row["name"]) for row in csv.DictReader(fh) if row.get("name")]


def sample(names: list[str], limit: int | None, seed: int) -> list[str]:
    if limit is None or len(names) <= limit:
        return sorted(names)
    return sorted(random.Random(seed).sample(names, limit))


def within_distance(
    name: str, popular: PopularIndex, metric, k: int
) -> bool:
    """True if any *other* popular name is within k edits (indexed search)."""
    counts = char_counts(name)
    for length in range(len(name) - k, len(name) + k + 1):
        for target in popular.by_length.get(length, ()):
            if target == name:
                continue
            if bag_distance(counts, popular.counts[target]) > k:
                continue
            if metric(name, target) <= k:
                return True
    return False


def predictions_guard(
    names: list[str], popular: PopularIndex, min_level: str, online: bool
) -> tuple[list[bool], list]:
    meta = pypi.fetch if online else None
    findings = [assess(n, popular, meta) for n in names]
    threshold = LEVEL_ORDER[min_level]
    return [LEVEL_ORDER[f.level] >= threshold for f in findings], findings


def print_table(
    y: list[int], methods: dict[str, list[bool]], findings, min_level: str
) -> dict:
    print(
        f"{'method':<24}{'precision [95% CI]':>24}{'recall [95% CI]':>22}"
        f"{'FPR [95% CI]':>22}{'F1':>7}   tp fp fn tn"
    )
    results: dict[str, dict] = {}
    for label, pred in methods.items():
        m = confusion(y, pred)
        p_lo, p_hi = rate_with_ci(m.tp, m.tp + m.fp)[1:]
        r_lo, r_hi = rate_with_ci(m.tp, m.tp + m.fn)[1:]
        f_lo, f_hi = rate_with_ci(m.fp, m.fp + m.tn)[1:]
        print(
            f"{label:<24}"
            f"{m.precision:>8.2f} [{p_lo:.2f}-{p_hi:.2f}]"
            f"{m.recall:>10.2f} [{r_lo:.2f}-{r_hi:.2f}]"
            f"{m.fpr:>10.2f} [{f_lo:.2f}-{f_hi:.2f}]"
            f"{m.f1:>7.2f}   {m.tp:>2} {m.fp:>2} {m.fn:>2} {m.tn:>2}"
        )
        results[label] = m.as_dict()
    return results


def sweep_table(findings, y: list[int]) -> list[dict]:
    thresholds = [0.0001, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5,
                  0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.9, 1.0]
    rows = []
    print("\nSupplyGuard score sweep (offline/online as selected):")
    print(f"{'threshold':>10}{'precision':>11}{'recall':>9}{'FPR':>8}   tp fp fn tn")
    for t in thresholds:
        pred = [f.score >= t for f in findings]
        m = confusion(y, pred)
        print(
            f"{t:>10.2f}{m.precision:>11.2f}{m.recall:>9.2f}{m.fpr:>8.2f}"
            f"   {m.tp:>2} {m.fp:>2} {m.fn:>2} {m.tn:>2}"
        )
        rows.append({"threshold": t, **m.as_dict()})
    return rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--online", action="store_true")
    ap.add_argument("--min-level", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH"])
    ap.add_argument("--popular")
    ap.add_argument("--malicious", default=str(HERE / "malicious_names.txt"))
    ap.add_argument("--benign", default=str(HERE / "benign_names.txt"))
    ap.add_argument("--hard", default=str(HERE / "benign_pairs.csv"))
    ap.add_argument("--limit-pos", type=int, default=1000)
    ap.add_argument("--limit-neg", type=int, default=500)
    ap.add_argument("--all", action="store_true", help="do not sample")
    ap.add_argument("--seed", type=int, default=420)
    ap.add_argument("--sweep", action="store_true")
    ap.add_argument("--json")
    args = ap.parse_args()

    popular = load_popular(args.popular)
    if not isinstance(popular, PopularIndex):
        raise SystemExit("internal error: expected PopularIndex")

    pos_path, neg_path = Path(args.malicious), Path(args.benign)
    positives = read_names(pos_path)
    if neg_path.exists():
        negatives = read_names(neg_path)
    else:
        negatives = read_pairs(Path(args.hard))
        print(f"warning: {neg_path} not found; using {args.hard} (not independent)\n")

    limits = (None, None) if args.all else (args.limit_pos, args.limit_neg)
    positives = sample(positives, limits[0], args.seed)
    negatives = sample(negatives, limits[1], args.seed + 1)
    y = [1] * len(positives) + [0] * len(negatives)
    names = positives + negatives

    print(
        f"{len(positives)} malicious + {len(negatives)} benign names "
        f"(seed={args.seed}, {'all' if args.all else 'sampled'})"
    )
    print(
        f"reference: {len(popular)} popular packages"
        + (f", last_update={popular.last_update}" if popular.last_update else "")
    )

    # A hard-negative file is useful context, but it must not silently
    # contain names that are already in the reference list (trivially OK).
    hard_path = Path(args.hard)
    if hard_path.exists():
        hard = read_pairs(hard_path)
        trivial = sum(1 for n in hard if n in popular)
        print(
            f"hard look-alike set: {len(hard)} names, {trivial} already in the "
            f"top reference (trivial), {len(hard) - trivial} actually exercised"
        )
    print()

    methods: dict[str, list[bool]] = {}
    for k in (1, 2):
        methods[f"Levenshtein<={k}"] = [
            within_distance(n, popular, levenshtein, k) for n in names
        ]
    for k in (1, 2):
        methods[f"Damerau<={k}"] = [
            within_distance(n, popular, damerau_levenshtein, k) for n in names
        ]

    guard_pred, findings = predictions_guard(
        names, popular, args.min_level, args.online
    )
    methods[f"SupplyGuard>={args.min_level}"] = guard_pred

    results = print_table(y, methods, findings, args.min_level)

    # Coverage diagnostic: how many malicious names are even representable by
    # the matcher?  Recall on this subset is not a substitute for full recall.
    pos_findings = findings[: len(positives)]
    representable = [f for f in pos_findings if f.target]
    if representable:
        hit = sum(
            1
            for f in representable
            if LEVEL_ORDER[f.level] >= LEVEL_ORDER[args.min_level]
        )
        print(
            f"\ncoverage: {len(representable)}/{len(positives)} malicious names "
            f"have a similar popular target; SupplyGuard recall on that subset "
            f"= {format_rate(hit, len(representable))}"
        )
    else:
        print("\ncoverage: no malicious name matched a popular target")

    # McNemar against the strongest baseline (highest F1).
    guard_label = f"SupplyGuard>={args.min_level}"
    guard_wrong = [p != bool(t) for p, t in zip(guard_pred, y)]
    baseline_labels = [l for l in methods if l != guard_label]
    best_label = max(
        baseline_labels,
        key=lambda l: confusion(y, methods[l]).f1,
    )
    best_wrong = [p != bool(t) for p, t in zip(methods[best_label], y)]
    b = sum(1 for a, c in zip(guard_wrong, best_wrong) if a and not c)
    c = sum(1 for a, d in zip(guard_wrong, best_wrong) if not a and d)
    p = mcnemar(b, c)
    print(
        f"\nMcNemar vs {best_label}: discordant b={b} (guard wrong, baseline right), "
        f"c={c} (guard right, baseline wrong), p={p:.4g}"
    )

    sweep = sweep_table(findings, y) if args.sweep else []

    if args.json:
        payload = {
            "dataset": {
                "positives": len(positives),
                "negatives": len(negatives),
                "seed": args.seed,
                "sample": not args.all,
                "online": args.online,
            },
            "reference": {
                "count": len(popular),
                "source": popular.source,
                "last_update": popular.last_update,
            },
            "methods": results,
            "mcnemar": {"baseline": best_label, "b": b, "c": c, "p": p},
            "sweep": sweep,
        }
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nresults written to {args.json}")


if __name__ == "__main__":
    main()
