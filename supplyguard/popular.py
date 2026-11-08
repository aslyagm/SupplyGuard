"""Reference list of popular (legitimate) PyPI packages."""

from __future__ import annotations

import json
import urllib.request
from functools import lru_cache
from pathlib import Path

from .parser import normalize

DATA_FILE = Path(__file__).parent / "data" / "top_packages.txt"

# hugovk/top-pypi-packages: monthly list of most-downloaded PyPI projects.
TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"


@lru_cache(maxsize=None)
def load_popular(path: str | None = None) -> frozenset[str]:
    """Load normalized popular package names from a text file (one per line)."""
    p = Path(path) if path else DATA_FILE
    names = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.add(normalize(line))
    return frozenset(names)


def refresh_popular(limit: int = 5000, url: str = TOP_PACKAGES_URL, out: Path = DATA_FILE) -> int:
    """Download the current top-N list and overwrite the bundled data file."""
    req = urllib.request.Request(url, headers={"User-Agent": "SupplyGuard/0.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    rows = data["rows"][:limit]
    header = f"# Top {len(rows)} PyPI packages, source: {url}\n"
    out.write_text(header + "\n".join(r["project"] for r in rows) + "\n", encoding="utf-8")
    load_popular.cache_clear()
    return len(rows)
