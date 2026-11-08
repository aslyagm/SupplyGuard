"""Console, JSON and CSV output."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .scoring import Finding

_ICON = {"HIGH": "[!!]", "MEDIUM": "[! ]", "LOW": "[. ]", "OK": "[ok]"}


def to_console(findings: list[Finding], show_ok: bool = False) -> str:
    lines = []
    for f in sorted(findings, key=lambda f: -f.score):
        if f.level == "OK" and not show_ok:
            continue
        head = f"{_ICON[f.level]} {f.name:<30} {f.level:<6} score={f.score:.2f}"
        if f.target:
            head += f"  ~ {f.target}"
        lines.append(head)
        lines.extend(f"      - {r}" for r in f.reasons)
    flagged = sum(f.level != "OK" for f in findings)
    lines.append(f"\n{len(findings)} package(s) scanned, {flagged} flagged.")
    return "\n".join(lines)


def _row(f: Finding) -> dict:
    d = asdict(f)
    d["typo_types"] = [t.value for t in f.typo_types]
    return d


def write_json(findings: list[Finding], path: str | Path) -> None:
    Path(path).write_text(json.dumps([_row(f) for f in findings], indent=2), encoding="utf-8")


def write_csv(findings: list[Finding], path: str | Path) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["name", "level", "score", "target", "distance", "typo_types", "reasons"])
        for f in findings:
            w.writerow([f.name, f.level, f.score, f.target or "", f.distance or "",
                        ";".join(t.value for t in f.typo_types), " | ".join(f.reasons)])
