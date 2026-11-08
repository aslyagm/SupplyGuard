"""Build eval/malicious_names.txt from the OpenSSF malicious-packages dataset.

Only *names* are read from the OSV JSON reports. No package is downloaded.

1. Get the dataset (sparse checkout, PyPI folder only):
       git clone --depth 1 --filter=blob:none --sparse https://github.com/ossf/malicious-packages eval/openssf
       git -C eval/openssf sparse-checkout set osv/malicious/pypi
2. python eval/fetch_openssf.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard.parser import normalize  # noqa: E402
from supplyguard.popular import load_popular  # noqa: E402
from supplyguard.scoring import closest_popular  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default="eval/openssf/osv/malicious/pypi")
    ap.add_argument("--out", default="eval/malicious_names.txt")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_dir():
        sys.exit(f"{src} not found - see the clone instructions at the top of this file.")

    popular = load_popular()
    all_names = sorted({normalize(p.name) for p in src.iterdir() if p.is_dir()})
    # Most malicious packages use random names; keep the ones that imitate a
    # popular package (this filter is part of the methodology - report it).
    squats = [n for n in all_names if n not in popular and closest_popular(n, popular)]

    Path(args.out).write_text(
        f"# OpenSSF malicious PyPI packages that resemble a top-{len(popular)} package\n"
        f"# {len(squats)} of {len(all_names)} names kept\n" + "\n".join(squats) + "\n",
        encoding="utf-8",
    )
    print(f"{len(all_names)} malicious names, {len(squats)} typosquat-like -> {args.out}")


if __name__ == "__main__":
    main()
