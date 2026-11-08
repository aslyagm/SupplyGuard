"""Read package names from requirements.txt files."""

from __future__ import annotations

import re
from pathlib import Path

# PEP 508 name: starts/ends with alnum, may contain . _ -
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")


def normalize(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of - _ . become a single '-'.

    PyPI treats `python_dateutil` and `python-dateutil` as the same project,
    so comparisons are always done on normalized names.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: str | Path) -> list[str]:
    """Return the (raw) package names listed in a requirements file.

    Skips comments, blank lines, options (-r, -e, --index-url ...) and
    direct URL / VCS requirements. Follows nested `-r other.txt` includes.
    """
    path = Path(path)
    names: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")):
            include = line.split(maxsplit=1)[1]
            names.extend(parse_requirements(path.parent / include))
            continue
        if line.startswith("-") or "://" in line:
            continue
        m = _NAME_RE.match(line)
        if m:
            names.append(m.group(1))
    # keep order, drop duplicates
    seen: set[str] = set()
    return [n for n in names if not (normalize(n) in seen or seen.add(normalize(n)))]
