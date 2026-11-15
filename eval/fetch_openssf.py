"""Build eval/malicious_names.txt from OpenSSF/OSV malicious PyPI entries.

Only *names* are read; no package is downloaded or installed.

Preferred source (fast, reproducible): the OSV PyPI data dump, which contains
the OpenSSF ``MAL-*`` entries:

    python eval/fetch_openssf.py

It downloads ~37 MB to eval/openssf/osv-pypi-all.zip (gitignored) and extracts
the PyPI package names.  A sparse clone of ossf/malicious-packages also works:

    git clone --depth 1 --filter=blob:none --sparse \
        https://github.com/ossf/malicious-packages eval/openssf
    git -C eval/openssf sparse-checkout set osv/malicious/pypi
    python eval/fetch_openssf.py --src eval/openssf/osv/malicious/pypi

By default every malicious PyPI name is kept.  Filtering the positives with
the detector's own similarity function (the old behaviour) removes exactly the
cases the detector cannot represent and inflates recall.  Use ``--squat-only``
only for a clearly-labelled secondary analysis.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import zipfile
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from supplyguard import __version__  # noqa: E402
from supplyguard.parser import normalize  # noqa: E402
from supplyguard.popular import load_popular  # noqa: E402
from supplyguard.scoring import closest_popular  # noqa: E402

HERE = Path(__file__).parent
OSV_PYPI_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
DEFAULT_ZIP = HERE / "openssf" / "osv-pypi-all.zip"


def names_from_zip(zip_path: Path) -> set[str]:
    names: set[str] = set()
    with zipfile.ZipFile(zip_path) as zf:
        for entry in zf.namelist():
            if not (entry.startswith("MAL-") and entry.endswith(".json")):
                continue
            try:
                data = json.loads(zf.read(entry))
            except (json.JSONDecodeError, KeyError):
                continue
            for affected in data.get("affected", []):
                package = affected.get("package", {})
                if package.get("ecosystem") == "PyPI" and package.get("name"):
                    names.add(normalize(package["name"]))
    return names


def ensure_zip(path: Path, timeout: float = 180.0) -> Path:
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {OSV_PYPI_ZIP} -> {path}", file=sys.stderr)
    req = urllib.request.Request(
        OSV_PYPI_ZIP,
        headers={"User-Agent": f"SupplyGuard/{__version__} (eval setup)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        path.write_bytes(resp.read())
    return path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--zip", default=str(DEFAULT_ZIP))
    ap.add_argument("--src", help="legacy directory of per-package OSV reports")
    ap.add_argument("--out", default=str(HERE / "malicious_names.txt"))
    ap.add_argument(
        "--squat-only",
        action="store_true",
        help="keep only names the current matcher can represent (secondary analysis)",
    )
    args = ap.parse_args()

    if args.src:
        src = Path(args.src)
        if not src.is_dir():
            sys.exit(f"{src} not found - see the instructions at the top of this file.")
        all_names = sorted({normalize(p.name) for p in src.iterdir() if p.is_dir()})
        source = f"https://github.com/ossf/malicious-packages ({src})"
    else:
        zip_path = ensure_zip(Path(args.zip))
        all_names = sorted(names_from_zip(zip_path))
        source = OSV_PYPI_ZIP

    popular = load_popular()
    if args.squat_only:
        kept = [n for n in all_names if n not in popular and closest_popular(n, popular)]
        note = "squat-looking subset (do not use as the primary recall set)"
    else:
        kept = all_names
        note = "complete malicious PyPI name set"

    header = (
        f"# OpenSSF/OSV malicious PyPI packages: {note}\n"
        f"# source: {source}\n"
        f"# generated: {date.today().isoformat()}\n"
        f"# {len(kept)} names (MAL-* entries, PyPI ecosystem only)\n"
        "# names only: no package is downloaded, installed or executed\n"
    )
    Path(args.out).write_text(header + "\n".join(kept) + "\n", encoding="utf-8")
    print(f"{len(all_names)} malicious names, {len(kept)} -> {args.out}")


if __name__ == "__main__":
    main()
