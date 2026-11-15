import json

from supplyguard.baseline import apply, load
from supplyguard.scoring import Finding


def test_load_old_list_format(tmp_path):
    path = tmp_path / "old.json"
    path.write_text(json.dumps([
        {"name": "reqeusts", "level": "MEDIUM"},
        {"name": "requests", "level": "OK"},
    ]), encoding="utf-8")
    assert load(path) == {"reqeusts"}


def test_load_new_object_format_and_normalization(tmp_path):
    path = tmp_path / "new.json"
    path.write_text(json.dumps({
        "schema_version": 2,
        "findings": [{"name": "Python_DateUtil", "level": "MEDIUM"}],
    }), encoding="utf-8")
    assert load(path) == {"python-dateutil"}


def test_apply_marks_known_findings_only(tmp_path):
    path = tmp_path / "base.json"
    path.write_text(json.dumps([{"name": "reqeusts", "level": "MEDIUM"}]), encoding="utf-8")
    findings = [
        Finding(name="reqeusts", level="MEDIUM"),
        Finding(name="colorma", level="MEDIUM"),
        Finding(name="requests", level="OK"),
    ]
    assert apply(findings, load(path)) == 1
    assert [f.baseline for f in findings] == [True, False, False]
