import pytest

from supplyguard.parser import parse_requirements, parse_requirements_detailed


def test_bom_and_crlf_are_handled(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_bytes("\ufeffrequests>=2.0\r\nnumpy\r\n".encode("utf-8"))
    assert parse_requirements(req) == ["requests", "numpy"]


def test_source_file_and_line_are_tracked(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# comment\n\nrequests\nflask  # web\n", encoding="utf-8")
    detailed = parse_requirements_detailed(req)
    assert [(r.name, r.line) for r in detailed] == [("requests", 3), ("flask", 4)]
    assert all(r.file == str(req) for r in detailed)


def test_nested_includes_are_followed(tmp_path):
    (tmp_path / "base.txt").write_text("numpy\n", encoding="utf-8")
    req = tmp_path / "requirements.txt"
    req.write_text("-r base.txt\n--requirement=other.txt\nrequests\n", encoding="utf-8")
    (tmp_path / "other.txt").write_text("flask\n", encoding="utf-8")
    assert parse_requirements(req) == ["numpy", "flask", "requests"]


def test_recursive_include_raises(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("-r b.txt\n", encoding="utf-8")
    b.write_text("-r a.txt\n", encoding="utf-8")
    with pytest.raises(ValueError, match="recursive"):
        parse_requirements(a)


def test_direct_url_and_editable_egg(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text(
        "mypkg @ https://example.com/mypkg.whl\n"
        "-e git+https://example.com/x.git#egg=editable-pkg\n"
        "git+https://example.com/y.git#egg=vcs-pkg\n"
        "https://example.com/raw.whl\n",
        encoding="utf-8",
    )
    assert parse_requirements(req) == ["mypkg", "editable-pkg", "vcs-pkg"]


def test_non_ascii_truncation_is_rejected(tmp_path):
    req = tmp_path / "requirements.txt"
    # Cyrillic "е": matching only the ASCII prefix would scan the wrong name.
    req.write_text("requ\u0435sts\nrequests\n", encoding="utf-8")
    assert parse_requirements(req) == ["requests"]


def test_names_are_deduplicated_after_normalization(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("Requests\nrequests>=2\npython_dateutil\npython-dateutil\n", encoding="utf-8")
    assert parse_requirements(req) == ["Requests", "python_dateutil"]
