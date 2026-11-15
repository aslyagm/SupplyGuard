"""Reference list of popular (legitimate) PyPI packages.

The bundled file contains the top 15,000 projects by downloads.  Each line is
``<project>\\t<download_count>``; the order is the download rank.  Keeping the
rank lets the scorer break ties deterministically and lets reports show *which*
popular project a suspicious name imitates.

The object returned by :func:`load_popular` behaves like a set (``in``,
iteration, ``len``) so it can be used as a drop-in replacement for a
``frozenset`` of names.
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Iterable

from . import __version__
from .parser import normalize
from .similarity import char_counts

DATA_FILE = Path(__file__).parent / "data" / "top_packages.txt"

# hugovk/top-pypi-packages: monthly list of most-downloaded PyPI projects.
TOP_PACKAGES_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages.min.json"
DEFAULT_LIMIT = 15000


@dataclass
class PopularIndex:
    """Names plus O(1) indexes used by the matcher and the scorer."""

    names: frozenset[str]
    rank: dict[str, int]              # 1 = most downloaded; 0 = unknown
    downloads: dict[str, int]
    source: str = ""
    last_update: str = ""
    by_length: dict[int, tuple[str, ...]] = field(default_factory=dict)
    by_stripped: dict[str, tuple[str, ...]] = field(default_factory=dict)
    counts: dict[str, tuple[int, ...]] = field(default_factory=dict)

    def __contains__(self, name: object) -> bool:
        return name in self.names

    def __iter__(self):
        return iter(self.names)

    def __len__(self) -> int:
        return len(self.names)

    @classmethod
    def from_rows(
        cls,
        rows: Iterable[tuple[str, int]],
        *,
        source: str = "",
        last_update: str = "",
        ranked: bool = True,
    ) -> "PopularIndex":
        rank: dict[str, int] = {}
        downloads: dict[str, int] = {}
        for raw_name, count in rows:
            name = normalize(str(raw_name).strip())
            if not name or name in rank:
                continue
            rank[name] = len(rank) + 1 if ranked else 0
            downloads[name] = int(count) if count else 0

        by_length: dict[int, list[str]] = {}
        by_stripped: dict[str, list[str]] = {}
        counts: dict[str, tuple[int, ...]] = {}
        for name in rank:
            by_length.setdefault(len(name), []).append(name)
            by_stripped.setdefault(name.replace("-", ""), []).append(name)
            counts[name] = char_counts(name)

        return cls(
            names=frozenset(rank),
            rank=rank,
            downloads=downloads,
            source=source,
            last_update=last_update,
            by_length={k: tuple(v) for k, v in by_length.items()},
            by_stripped={k: tuple(v) for k, v in by_stripped.items()},
            counts=counts,
        )

    @classmethod
    def from_names(cls, names: Iterable[str]) -> "PopularIndex":
        """Index a plain set of names (used by tests and custom callers)."""
        return cls.from_rows(((n, 0) for n in names), ranked=False)


def _parse_data_file(path: Path) -> PopularIndex:
    rows: list[tuple[str, int]] = []
    source = ""
    last_update = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            m = re.search(r"(?:source:\s*)?(https?://\S+)", line)
            if m and not source:
                source = m.group(1)
            m = re.search(r"last_update:\s*(.+)$", line)
            if m:
                last_update = m.group(1).strip()
            continue
        parts = line.split("\t", 1) if "\t" in line else line.split(None, 1)
        name = parts[0].strip()
        count = 0
        if len(parts) > 1:
            try:
                count = int(parts[1].strip())
            except ValueError:
                count = 0
        rows.append((name, count))
    return PopularIndex.from_rows(rows, source=source, last_update=last_update)


@lru_cache(maxsize=8)
def _load_popular(path: str | None = None) -> PopularIndex:
    p = Path(path) if path else DATA_FILE
    return _parse_data_file(p)


def load_popular(path: str | Path | None = None) -> PopularIndex:
    """Load the reference index from a text file (one package per line).

    Lines may optionally contain a tab-separated download count.  A custom
    ``path`` is cached separately from the bundled list.
    """
    return _load_popular(str(path) if path else None)


def refresh_popular(
    limit: int = DEFAULT_LIMIT,
    url: str = TOP_PACKAGES_URL,
    out: Path = DATA_FILE,
    timeout: float = 30.0,
) -> int:
    """Download the current top-N list and atomically overwrite `out`."""
    req = urllib.request.Request(url, headers={"User-Agent": f"SupplyGuard/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.load(resp)

    all_rows = data.get("rows")
    if not isinstance(all_rows, list) or not all_rows:
        raise ValueError(f"unexpected top-packages payload from {url}")
    rows = all_rows[: max(1, limit)]
    last_update = str(data.get("last_update") or "")

    header = (
        f"# Top {len(rows)} PyPI packages by downloads\n"
        f"# source: {url}\n"
        f"# last_update: {last_update}\n"
        "# format: <project>\\t<download_count>\n"
    )
    body = "\n".join(
        f"{row['project']}\t{int(row.get('download_count') or 0)}" for row in rows
    )
    payload = header + body + "\n"

    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".tmp")
    tmp.write_text(payload, encoding="utf-8", newline="\n")
    tmp.replace(out)
    _load_popular.cache_clear()
    return len(rows)
