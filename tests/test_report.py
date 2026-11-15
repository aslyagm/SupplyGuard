import csv
import json

from supplyguard.report import to_console, to_sarif, write_csv, write_json
from supplyguard.scoring import Finding


def _findings():
    return [
        Finding(name="reqeusts", target="requests", target_rank=8, distance=1,
                score=0.6, level="MEDIUM", reasons=["transposition"]),
        Finding(name="fine", level="OK"),
        Finding(name="old", score=0.6, level="MEDIUM", baseline=True),
        Finding(name="ignored", score=0.6, level="MEDIUM", suppressed=True,
                suppressed_reason="reviewed"),
    ]


def test_console_counts_and_hides_suppressed_by_default():
    text = to_console(_findings())
    assert "1 flagged" in text
    assert "[baseline]" in text  # kept visible, but not counted as new
    assert "ignored" not in text
    assert "reqeusts" in text


def test_console_can_show_suppressed():
    text = to_console(_findings(), show_ok=True, show_suppressed=True)
    assert "[suppressed: reviewed]" in text
    assert "[baseline]" in text
    assert "[ok] fine" in text


def test_json_has_schema_and_metadata(tmp_path):
    out = tmp_path / "out.json"
    write_json(_findings(), out, {"inputs": ["requirements.txt"]})
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema_version"] == 2
    assert data["tool"] == "supplyguard"
    assert data["inputs"] == ["requirements.txt"]
    assert data["findings"][0]["typo_types"] == []


def test_csv_neutralizes_formulas(tmp_path):
    out = tmp_path / "out.csv"
    write_csv([Finding(name="=cmd|calc", level="MEDIUM")], out)
    with open(out, encoding="utf-8", newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[0][0] == "name"
    assert rows[1][0] == "'=cmd|calc"


def test_sarif_structure_and_states():
    sarif = to_sarif(_findings(), default_uri="requirements.txt")
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert len(results) == 3
    by_name = {r["message"]["text"].split(":")[0]: r for r in results}
    assert by_name["reqeusts"]["level"] == "warning"
    assert by_name["ignored"]["suppressions"][0]["kind"] == "external"
    assert by_name["old"]["baselineState"] == "unchanged"
    assert by_name["reqeusts"]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "requirements.txt"


def test_sarif_prefers_source_file_and_line(tmp_path):
    finding = Finding(name="reqeusts", level="HIGH", source_file="sub\\req.txt", source_line=4)
    location = to_sarif([finding])["runs"][0]["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "sub/req.txt"
    assert location["physicalLocation"]["region"]["startLine"] == 4
