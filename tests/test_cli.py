import json

from supplyguard.cli import main


def test_scan_offline_json_and_reports(tmp_path, capsys):
    req = tmp_path / "requirements.txt"
    req.write_text("requests\nreqeusts\n", encoding="utf-8")
    out = tmp_path / "out.json"
    sarif = tmp_path / "out.sarif"
    code = main([
        "scan", str(req), "--offline", "--json", str(out),
        "--sarif", str(sarif), "--fail-on", "none",
    ])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert [f["name"] for f in data["findings"]] == ["requests", "reqeusts"]
    assert data["findings"][1]["source_line"] == 2
    assert json.loads(sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "1 flagged" in capsys.readouterr().out


def test_fail_on_threshold(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("reqeusts\n", encoding="utf-8")
    assert main(["scan", str(req), "--offline", "--fail-on", "MEDIUM"]) == 1
    assert main(["scan", str(req), "--offline", "--fail-on", "HIGH"]) == 0
    assert main(["scan", str(req), "--offline", "--fail-on", "none"]) == 0


def test_allowlist_and_baseline_suppress_exit(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("reqeusts\n", encoding="utf-8")
    ignore = tmp_path / "ignore"
    ignore.write_text("reqeusts # reviewed\n", encoding="utf-8")
    assert main([
        "scan", str(req), "--offline", "--ignore", str(ignore), "--fail-on", "MEDIUM",
    ]) == 0

    report = tmp_path / "report.json"
    assert main([
        "scan", str(req), "--offline", "--json", str(report), "--fail-on", "none",
    ]) == 0
    assert main([
        "scan", str(req), "--offline", "--baseline", str(report), "--fail-on", "MEDIUM",
    ]) == 0


def test_missing_input_and_bad_ignore_return_2(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "missing.txt"), "--offline"]) == 2
    assert "error:" in capsys.readouterr().err

    req = tmp_path / "requirements.txt"
    req.write_text("reqeusts\n", encoding="utf-8")
    ignore = tmp_path / "ignore"
    ignore.write_text("reqeusts until=not-a-date\n", encoding="utf-8")
    assert main([
        "scan", str(req), "--offline", "--ignore", str(ignore),
    ]) == 2
    assert "invalid until" in capsys.readouterr().err


def test_multiple_inputs_are_deduplicated(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("Requests\n", encoding="utf-8")
    b.write_text("requests==2\nreqeusts\n", encoding="utf-8")
    out = tmp_path / "out.json"
    assert main([
        "scan", str(a), str(b), "--offline", "--json", str(out), "--fail-on", "none",
    ]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert [f["name"] for f in data["findings"]] == ["requests", "reqeusts"]
    assert data["findings"][0]["source_file"] == str(a)
