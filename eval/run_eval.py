"""Compare the Levenshtein baseline with SupplyGuard on the labelled set.

    python eval/run_eval.py              # name-only (offline)
    python eval/run_eval.py --online     # also use PyPI metadata

Positives: eval/malicious_names.txt   Negatives: eval/benign_pairs.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard import pypi  # noqa: E402
from supplyguard.parser import normalize  # noqa: E402
from supplyguard.popular import load_popular  # noqa: E402
from supplyguard.scoring import assess  # noqa: E402
from supplyguard.similarity import levenshtein  # noqa: E402

HERE = Path(__file__).parent


def load_set() -> list[tuple[str, int]]:
    pos = [normalize(l.strip()) for l in (HERE / "malicious_names.txt").read_text().splitlines()
           if l.strip() and not l.startswith("#")]
    with open(HERE / "benign_pairs.csv", encoding="utf-8") as fh:
        neg = [normalize(r["name"]) for r in csv.DictReader(fh)]
    return [(n, 1) for n in pos] + [(n, 0) for n in neg]


def baseline(name: str, popular: frozenset[str], k: int = 2) -> bool:
    """Flag if any *other* popular name is within Levenshtein distance k."""
    return any(p != name and abs(len(p) - len(name)) <= k and levenshtein(name, p) <= k
               for p in popular)


def metrics(y: list[int], pred: list[bool]) -> dict[str, float]:
    tp = sum(1 for a, b in zip(y, pred) if a and b)
    fp = sum(1 for a, b in zip(y, pred) if not a and b)
    fn = sum(1 for a, b in zip(y, pred) if a and not b)
    tn = sum(1 for a, b in zip(y, pred) if not a and not b)
    return {
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--online", action="store_true")
    ap.add_argument("--min-level", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH"])
    args = ap.parse_args()

    popular = load_popular()
    data = load_set()
    y = [label for _, label in data]
    order = ["LOW", "MEDIUM", "HIGH"]
    meta = pypi.fetch if args.online else None

    base_pred = [baseline(n, popular) for n, _ in data]
    sg_pred = [assess(n, popular, meta).level in order[order.index(args.min_level):]
               for n, _ in data]

    print(f"{len(data)} names ({sum(y)} malicious, {len(y) - sum(y)} benign)\n")
    print(f"{'method':<22}{'precision':>10}{'recall':>8}{'FPR':>7}   tp fp fn tn")
    for label, pred in [("Levenshtein<=2", base_pred), (f"SupplyGuard>={args.min_level}", sg_pred)]:
        m = metrics(y, pred)
        print(f"{label:<22}{m['precision']:>10.2f}{m['recall']:>8.2f}{m['fpr']:>7.2f}"
              f"   {m['tp']:>2} {m['fp']:>2} {m['fn']:>2} {m['tn']:>2}")


if __name__ == "__main__":
    main()
