"""Fetch package metadata from the PyPI JSON API (read-only, nothing is downloaded or installed)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

API = "https://pypi.org/pypi/{name}/json"
USER_AGENT = "SupplyGuard/0.1 (BIL420 course project)"
CACHE_DIR = Path(".supplyguard_cache")


@dataclass
class PackageInfo:
    name: str
    exists: bool
    first_release: str | None = None   # ISO date of the oldest upload
    release_count: int = 0
    has_project_url: bool = False      # homepage / repository link present
    summary: str = ""

    def age_days(self, now: datetime | None = None) -> int | None:
        if not self.first_release:
            return None
        now = now or datetime.now(timezone.utc)
        return (now - datetime.fromisoformat(self.first_release)).days


def _parse(name: str, data: dict) -> PackageInfo:
    info = data.get("info", {})
    uploads = [
        f["upload_time_iso_8601"]
        for files in data.get("releases", {}).values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    first = min(uploads).replace("Z", "+00:00") if uploads else None
    urls = info.get("project_urls") or {}
    return PackageInfo(
        name=name,
        exists=True,
        first_release=first,
        release_count=sum(1 for files in data.get("releases", {}).values() if files),
        has_project_url=bool(info.get("home_page") or urls),
        summary=(info.get("summary") or "").strip(),
    )


def fetch(name: str, use_cache: bool = True, timeout: float = 10.0) -> PackageInfo | None:
    """Return metadata, PackageInfo(exists=False) for 404, or None on network error."""
    cache_file = CACHE_DIR / f"{name}.json"
    if use_cache and cache_file.exists():
        return PackageInfo(**json.loads(cache_file.read_text(encoding="utf-8")))

    req = urllib.request.Request(API.format(name=name), headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = _parse(name, json.load(resp))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return None
        result = PackageInfo(name=name, exists=False)
    except (urllib.error.URLError, TimeoutError):
        return None

    if use_cache:
        CACHE_DIR.mkdir(exist_ok=True)
        cache_file.write_text(json.dumps(asdict(result)), encoding="utf-8")
    return result
