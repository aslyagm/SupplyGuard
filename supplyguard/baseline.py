"""Baseline handling so CI only fails on *new* findings."""

from __future__ import annotations

import json
from pathlib import Path

from .parser import normalize
from .scoring import Finding


def load(path: str | Path) -> set[str]:
    """Read names from a previous ``--json`` report (old list or new object)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        findings = data.get("findings", [])
    else:
        findings = data
    names: set[str] = set()
    for item in findings:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if name and item.get("level", "OK") != "OK":
            names.add(normalize(name))
    return names


def apply(findings: list[Finding], names: set[str]) -> int:
    count = 0
    for finding in findings:
        if finding.level != "OK" and finding.name in names:
            finding.baseline = True
            count += 1
    return count
