"""Console, JSON, CSV and SARIF output."""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .scoring import Finding

_ICON = {"HIGH": "[!!]", "MEDIUM": "[! ]", "LOW": "[. ]", "OK": "[ok]"}
_SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def to_console(
    findings: list[Finding], show_ok: bool = False, show_suppressed: bool = False
) -> str:
    lines: list[str] = []
    flagged = suppressed = baselined = 0
    for f in sorted(findings, key=lambda f: (-f.score, f.name)):
        if f.suppressed:
            suppressed += 1
            if not show_suppressed:
                continue
        elif f.baseline:
            baselined += 1
        elif f.level != "OK":
            flagged += 1

        if f.level == "OK" and not show_ok:
            continue
        head = f"{_ICON[f.level]} {f.name:<30} {f.level:<6} score={f.score:.2f}"
        if f.target:
            head += f"  ~ {f.target}"
            if f.target_rank:
                head += f" (#{f.target_rank})"
        if f.baseline:
            head += "  [baseline]"
        if f.suppressed:
            head += f"  [suppressed: {f.suppressed_reason}]"
        if f.source_line and f.source_file:
            head += f"  ({Path(f.source_file).name}:{f.source_line})"
        lines.append(head)
        lines.extend(f"      - {reason}" for reason in f.reasons)
        lines.extend(f"      ! {warn}" for warn in f.warnings)

    lines.append(
        f"\n{len(findings)} package(s) scanned, {flagged} flagged, "
        f"{suppressed} suppressed, {baselined} in baseline."
    )
    if flagged == 0:
        lines.append("No new suspicious packages.")
    return "\n".join(lines)


def _row(f: Finding) -> dict:
    row = asdict(f)
    row["typo_types"] = [t.value for t in f.typo_types]
    return row


def write_json(
    findings: list[Finding], path: str | Path, meta: dict | None = None
) -> None:
    payload = {
        "schema_version": 2,
        "tool": "supplyguard",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **(meta or {}),
        "findings": [_row(f) for f in findings],
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )


def _csv_safe(value: object) -> object:
    # Prevent spreadsheet formula injection when a report is opened in Excel.
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@"):
        return "'" + value
    return value


def write_csv(findings: list[Finding], path: str | Path) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "name", "level", "score", "target", "target_rank", "distance",
            "typo_types", "suppressed", "suppressed_reason", "baseline",
            "known_malicious", "source_file", "source_line", "reasons",
        ])
        for f in findings:
            writer.writerow([
                _csv_safe(f.name),
                f.level,
                f.score,
                _csv_safe(f.target or ""),
                f.target_rank if f.target_rank is not None else "",
                f.distance if f.distance is not None else "",
                ";".join(t.value for t in f.typo_types),
                f.suppressed,
                _csv_safe(f.suppressed_reason),
                f.baseline,
                ";".join(f.known_malicious),
                _csv_safe(f.source_file or ""),
                f.source_line if f.source_line is not None else "",
                _csv_safe(" | ".join(f.reasons)),
            ])


def to_sarif(findings: list[Finding], default_uri: str = "requirements.txt") -> dict:
    """SARIF 2.1.0 output for GitHub code scanning."""
    results = []
    for f in findings:
        if f.level == "OK":
            continue
        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": (f.source_file or default_uri).replace("\\", "/")
                }
            }
        }
        if f.source_line:
            location["physicalLocation"]["region"] = {"startLine": f.source_line}
        message = "; ".join(f.reasons) or "suspicious package name"
        result = {
            "ruleId": "supplyguard/risk",
            "level": _SARIF_LEVEL.get(f.level, "note"),
            "message": {"text": f"{f.name}: {message}"},
            "locations": [location],
            "properties": {
                "score": f.score,
                "target": f.target,
                "targetRank": f.target_rank,
                "typoTypes": [t.value for t in f.typo_types],
                "knownMalicious": f.known_malicious,
            },
        }
        if f.suppressed:
            result["suppressions"] = [{
                "kind": "external",
                "justification": f.suppressed_reason or "allowlisted",
            }]
        if f.baseline:
            result["baselineState"] = "unchanged"
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SupplyGuard",
                    "semanticVersion": __version__,
                    "informationUri": "https://pypi.org/",
                    "rules": [{
                        "id": "supplyguard/risk",
                        "name": "SuspiciousDependency",
                        "shortDescription": {
                            "text": "Suspicious or malicious PyPI dependency name"
                        },
                    }],
                }
            },
            "results": results,
        }],
    }


def write_sarif(
    findings: list[Finding], path: str | Path, default_uri: str = "requirements.txt"
) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(to_sarif(findings, default_uri), indent=2), encoding="utf-8"
    )
