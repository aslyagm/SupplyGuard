"""Build a real-world negative (benign) sample for eval/run_eval.py.

A false-positive measurement is only meaningful if the negatives are *not*
already in the popular reference list.  This script samples real projects
from the PyPI simple index, excludes the reference list and known malicious
names, and (optionally) verifies that each sampled project has minimal
metadata.

    python eval/build_benign.py --sample 500 --seed 420 --verify

The generated file is committed so the evaluation runs offline and is
reproducible; re-run this only when you intentionally refresh the sample.
"""

from __future__ import annotations

import argparse
import html
import random
import re
import sys
import urllib.parse
import urllib.request
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard import __version__, pypi  # noqa: E402
from supplyguard.parser import normalize  # noqa: E402
from supplyguard.popular import load_popular  # noqa: E402

HERE = Path(__file__).parent
SIMPLE_URL = "https://pypi.org/simple/"
TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
_NAME_LINK = re.compile(r'<a\s+href="/simple/([^/"]+)/"', re.IGNORECASE)


def names_from_simple(timeout: float) -> list[str]:
    req = urllib.request.Request(
        SIMPLE_URL,
        headers={"User-Agent": f"SupplyGuard/{__version__} (eval setup)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        page = resp.read().decode("utf-8", errors="replace")
    names = {
        normalize(urllib.parse.unquote(html.unescape(m.group(1))))
        for m in _NAME_LINK.finditer(page)
    }
    return sorted(n for n in names if n)


def names_from_top(start_rank: int, end_rank: int, timeout: float) -> list[str]:
    req = urllib.request.Request(
        TOP_URL,
        headers={"User-Agent": f"SupplyGuard/{__version__} (eval setup)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        import json

        rows = json.load(resp)["rows"]
    return [normalize(r["project"]) for r in rows[start_rank - 1:end_rank]]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", choices=["simple", "top"], default="simple")
    ap.add_argument("--sample", type=int, default=500)
    ap.add_argument("--seed", type=int, default=420)
    ap.add_argument("--start-rank", type=int, default=5001)
    ap.add_argument("--end-rank", type=int, default=15000)
    ap.add_argument("--verify", action="store_true", help="require summary or project URL")
    ap.add_argument("--out", default=str(HERE / "benign_names.txt"))
    ap.add_argument("--malicious", default=str(HERE / "malicious_names.txt"))
    ap.add_argument("--timeout", type=float, default=120.0)
    args = ap.parse_args()

    if args.source == "simple":
        candidates = names_from_simple(args.timeout)
        source_note = SIMPLE_URL
    else:
        candidates = names_from_top(args.start_rank, args.end_rank, args.timeout)
        source_note = f"{TOP_URL} ranks {args.start_rank}-{args.end_rank}"

    popular = load_popular()
    excluded = {n for n in candidates if n in popular}

    malicious_path = Path(args.malicious)
    malicious = set()
    if malicious_path.exists():
        malicious = {
            normalize(line.strip())
            for line in malicious_path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip() and not line.startswith("#")
        }

    pool = [n for n in candidates if n not in popular and n not in malicious]
    rng = random.Random(args.seed)
    selected = sorted(rng.sample(pool, min(args.sample, len(pool))))

    if args.verify:
        verified = []
        for i, name in enumerate(selected, 1):
            info = pypi.fetch(name)
            if info is not None and info.exists and (info.summary or info.has_project_url):
                verified.append(name)
            if i % 50 == 0:
                print(f"  verified {i}/{len(selected)} ...", file=sys.stderr)
        selected = verified

    header = (
        f"# Benign evaluation sample: real PyPI projects outside the reference list\n"
        f"# source: {source_note}\n"
        f"# generated: {date.today().isoformat()}  seed={args.seed}  "
        f"excluded_top={len(excluded)}  excluded_malicious={len(malicious)}\n"
        f"# verified_metadata={args.verify}\n"
        f"# {len(selected)} names\n"
    )
    Path(args.out).write_text(header + "\n".join(selected) + "\n", encoding="utf-8")
    print(
        f"{len(candidates)} candidates, {len(pool)} after exclusions, "
        f"{len(selected)} sampled -> {args.out}"
    )


if __name__ == "__main__":
    main()
