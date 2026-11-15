"""Known-malicious package lookup via the OSV API.

OSV contains the OpenSSF ``MAL-*`` records for malicious PyPI packages.  A
similarity score cannot catch a malicious package with a random name; this
lookup can.  The API is read-only and supports batching, so scanning a normal
requirements file costs one request per 1,000 names.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import __version__
from .parser import normalize
from .scoring import Finding

OSV_API = "https://api.osv.dev/v1/querybatch"
BATCH_SIZE = 1000
USER_AGENT = f"SupplyGuard/{__version__} (BIL420 course project)"


class OsvError(RuntimeError):
    """The OSV lookup failed (network, HTTP or malformed response)."""


@dataclass(frozen=True)
class MaliciousHit:
    name: str
    ids: tuple[str, ...]
    summaries: tuple[str, ...]


def query(names: list[str], timeout: float = 30.0) -> dict[str, MaliciousHit]:
    """Return MAL-* OSV records for the given PyPI names."""
    unique = sorted({normalize(n) for n in names if n})
    hits: dict[str, MaliciousHit] = {}

    for start in range(0, len(unique), BATCH_SIZE):
        chunk = unique[start:start + BATCH_SIZE]
        body = json.dumps({
            "queries": [
                {"package": {"name": name, "ecosystem": "PyPI"}} for name in chunk
            ]
        }).encode()
        req = urllib.request.Request(
            OSV_API,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise OsvError(f"OSV request failed: {exc}") from exc

        results = data.get("results")
        if not isinstance(results, list) or len(results) != len(chunk):
            raise OsvError("OSV returned an unexpected number of results")

        for name, result in zip(chunk, results):
            vulns = [
                v for v in (result.get("vulns") or [])
                if str(v.get("id", "")).startswith("MAL-")
            ]
            if not vulns:
                continue
            hits[name] = MaliciousHit(
                name=name,
                ids=tuple(str(v.get("id")) for v in vulns),
                summaries=tuple(str(v.get("summary") or "") for v in vulns),
            )
    return hits


def annotate(findings: list[Finding], timeout: float = 30.0) -> int:
    """Upgrade findings whose names are known malicious. Returns hit count."""
    hits = query([f.name for f in findings], timeout=timeout)
    for finding in findings:
        hit = hits.get(finding.name)
        if hit is None:
            continue
        finding.known_malicious = list(hit.ids)
        finding.level = "HIGH"
        finding.score = 1.0
        detail = f"known malicious package ({', '.join(hit.ids)})"
        if hit.summaries and hit.summaries[0]:
            detail += f": {hit.summaries[0]}"
        finding.reasons.append(detail)
    return len(hits)
