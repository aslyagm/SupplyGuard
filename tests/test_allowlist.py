from datetime import date

import pytest

from supplyguard.allowlist import apply, expired, find, load
from supplyguard.scoring import Finding


def test_load_entries_with_expiry_and_reason(tmp_path):
    path = tmp_path / ".supplyguardignore"
    path.write_text(
        "# comment line\n"
        "cfunits until=2027-01-31 # reviewed 2026-11\n"
        "attr                       # import alias\n",
        encoding="utf-8",
    )
    entries = load(path)
    assert entries["cfunits"].expires == date(2027, 1, 31)
    assert entries["cfunits"].reason == "reviewed 2026-11"
    assert entries["attr"].expires is None


def test_missing_file_is_empty(tmp_path):
    assert load(tmp_path / "nope") == {}


def test_invalid_expiry_raises(tmp_path):
    path = tmp_path / "ignore"
    path.write_text("pkg until=soon\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid until"):
        load(path)


def test_expired_entries_are_inactive_and_reported(tmp_path):
    path = tmp_path / "ignore"
    path.write_text("old until=2020-01-01\nnew until=2099-01-01\n", encoding="utf-8")
    entries = load(path)
    assert find("old", entries, today=date(2026, 1, 1)) is None
    assert find("new", entries, today=date(2026, 1, 1)) is not None
    assert expired(entries, today=date(2026, 1, 1)) == ["old"]


def test_apply_marks_only_findings(tmp_path):
    path = tmp_path / "ignore"
    path.write_text("reqeusts # known test\nrequests\n", encoding="utf-8")
    findings = [
        Finding(name="reqeusts", level="MEDIUM", score=0.6),
        Finding(name="requests", level="OK", score=0.0),
    ]
    assert apply(findings, load(path)) == 1
    assert findings[0].suppressed is True
    assert findings[0].suppressed_reason == "known test"
    assert findings[1].suppressed is False
