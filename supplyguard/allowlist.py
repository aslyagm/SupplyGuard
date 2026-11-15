"""Project-local suppressions for accepted false positives.

``.supplyguardignore`` is intentionally small and auditable::

    # name [until=YYYY-MM-DD] # reason
    cfunits until=2027-01-31 # internal package name, reviewed 2026-11
    attr                       # import-name alias; requirements should use attrs

Expired entries are ignored (and are reported by the CLI).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path

from .parser import normalize
from .scoring import Finding

DEFAULT_FILE = ".supplyguardignore"


@dataclass(frozen=True)
class Suppression:
    name: str
    reason: str = ""
    expires: date | None = None

    def active(self, today: date | None = None) -> bool:
        return self.expires is None or self.expires >= (today or date.today())


def load(path: str | Path = DEFAULT_FILE) -> dict[str, Suppression]:
    p = Path(path)
    if not p.exists():
        return {}
    suppressions: dict[str, Suppression] = {}
    for lineno, raw in enumerate(p.read_text(encoding="utf-8-sig").splitlines(), 1):
        body, _, comment = raw.partition("#")
        parts = body.split()
        if not parts:
            continue
        name = normalize(parts[0])
        expires: date | None = None
        for token in parts[1:]:
            if token.startswith("until="):
                try:
                    expires = date.fromisoformat(token.split("=", 1)[1])
                except ValueError as exc:
                    raise ValueError(
                        f"{p}:{lineno}: invalid until= date: {token}"
                    ) from exc
        suppressions[name] = Suppression(
            name=name, reason=comment.strip(), expires=expires
        )
    return suppressions


def find(
    name: str,
    suppressions: dict[str, Suppression],
    today: date | None = None,
) -> Suppression | None:
    entry = suppressions.get(normalize(name))
    if entry is None or not entry.active(today):
        return None
    return entry


def apply(findings: list[Finding], suppressions: dict[str, Suppression]) -> int:
    today = date.today()
    count = 0
    for finding in findings:
        if finding.level == "OK":
            continue
        entry = find(finding.name, suppressions, today)
        if entry is None:
            continue
        finding.suppressed = True
        until = f" until {entry.expires}" if entry.expires else ""
        finding.suppressed_reason = (entry.reason or "allowlisted") + until
        count += 1
    return count


def expired(suppressions: dict[str, Suppression], today: date | None = None) -> list[str]:
    today = today or date.today()
    return sorted(n for n, s in suppressions.items() if not s.active(today))
