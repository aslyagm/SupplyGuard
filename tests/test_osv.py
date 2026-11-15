import io
import json
import urllib.error

import pytest

from supplyguard import osv
from supplyguard.scoring import Finding


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _payload(*results):
    return FakeResponse(json.dumps({"results": list(results)}).encode())


def test_query_keeps_only_mal_records(monkeypatch):
    payload = _payload(
        {"vulns": [{"id": "MAL-2026-1", "summary": "malicious"}]},
        {"vulns": [{"id": "GHSA-xxxx", "summary": "a normal CVE"}]},
        {"vulns": []},
    )
    monkeypatch.setattr(osv.urllib.request, "urlopen", lambda *a, **k: payload)
    hits = osv.query(["Bad_Pkg", "normal", "clean"])
    assert list(hits) == ["bad-pkg"]
    assert hits["bad-pkg"].ids == ("MAL-2026-1",)


def test_query_batches_names(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=0):
        calls.append(json.loads(req.data))
        chunk = calls[-1]["queries"]
        return _payload(*[{"vulns": [{"id": "MAL-1"}]} for _ in chunk])

    monkeypatch.setattr(osv.urllib.request, "urlopen", fake_urlopen)
    names = [f"pkg{i}" for i in range(1205)]
    hits = osv.query(names)
    assert len(calls) == 2
    assert len(hits) == 1205


def test_query_wraps_network_errors(monkeypatch):
    def boom(*a, **k):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(osv.urllib.request, "urlopen", boom)
    with pytest.raises(osv.OsvError, match="OSV request failed"):
        osv.query(["requests"])


def test_annotate_upgrades_findings(monkeypatch):
    payload = _payload({"vulns": [{"id": "MAL-2026-9", "summary": "typosquat"}]})
    monkeypatch.setattr(osv.urllib.request, "urlopen", lambda *a, **k: payload)
    findings = [Finding(name="evil", level="LOW", score=0.2)]
    assert osv.annotate(findings) == 1
    assert findings[0].level == "HIGH"
    assert findings[0].score == 1.0
    assert findings[0].known_malicious == ["MAL-2026-9"]
