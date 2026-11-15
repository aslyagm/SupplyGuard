"""Read package names from requirements.txt files."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# PEP 508 name: starts/ends with alnum, may contain . _ -
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)")
_INCLUDE_RE = re.compile(r"^(?:-r|--requirement)(?:\s+|=)(.+)$")
_DIRECT_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*@\s*\S+"
)


@dataclass(frozen=True)
class Requirement:
    """A package name plus where it came from (used by SARIF/reporting)."""

    name: str
    file: str
    line: int


def normalize(name: str) -> str:
    """PEP 503 normalization: lowercase, runs of - _ . become a single '-'.

    PyPI treats `python_dateutil` and `python-dateutil` as the same project,
    so comparisons are always done on normalized names.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def _dedupe(reqs: list[Requirement]) -> list[Requirement]:
    seen: set[str] = set()
    out: list[Requirement] = []
    for req in reqs:
        key = normalize(req.name)
        if key in seen:
            continue
        seen.add(key)
        out.append(req)
    return out


def parse_requirements_detailed(
    path: str | Path, _stack: tuple[Path, ...] = ()
) -> list[Requirement]:
    """Return package names and their source lines, following nested `-r` includes."""
    original = Path(path)
    resolved = original.resolve()
    if resolved in _stack:
        chain = " -> ".join(str(p) for p in (*_stack, resolved))
        raise ValueError(f"recursive -r include: {chain}")

    text = resolved.read_text(encoding="utf-8-sig")  # utf-8-sig also handles BOM
    reqs: list[Requirement] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        # A comment starts at whitespace + '#'.  URLs keep their #egg=... part.
        line = re.sub(r"\s+#.*$", "", raw).strip()
        if not line or line.startswith("#"):
            continue

        include = _INCLUDE_RE.match(line)
        if include:
            target = include.group(1).strip().strip("'\"")
            reqs.extend(
                parse_requirements_detailed(
                    original.parent / target, (*_stack, resolved)
                )
            )
            continue

        # Editable and plain VCS/URL installs often carry a useful #egg=name.
        egg = re.search(
            r"#egg=([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)", line
        )
        if egg:
            reqs.append(Requirement(egg.group(1), str(original), lineno))
            continue

        if line.startswith("-"):
            continue

        # PEP 508 direct reference: "mypkg @ https://..." still names mypkg.
        if "://" in line:
            direct = _DIRECT_RE.match(line)
            if direct:
                reqs.append(Requirement(direct.group(1), str(original), lineno))
            continue

        match = _NAME_RE.match(line)
        if not match:
            continue
        end = match.end()
        # Reject silently truncated names such as "requеsts" (Cyrillic е) and
        # obvious path-like garbage instead of scanning a wrong prefix.
        if end < len(line) and (line[end].isalnum() or line[end] in "_/\\:"):
            continue
        reqs.append(Requirement(match.group(1), str(original), lineno))

    return _dedupe(reqs)


def parse_requirements(path: str | Path) -> list[str]:
    """Return the (raw) package names listed in a requirements file.

    Skips comments, blank lines, options (-r, -e, --index-url ...) and
    direct URL / VCS requirements. Follows nested `-r other.txt` includes.
    """
    return [req.name for req in parse_requirements_detailed(path)]
