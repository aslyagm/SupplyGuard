import importlib.util
from pathlib import Path

from supplyguard.popular import load_popular

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("run_evasion", ROOT / "eval" / "run_evasion.py")
run_evasion = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(run_evasion)


def test_evasion_cases_schema():
    cases = run_evasion.load_cases(ROOT / "eval" / "evasion" / "cases.json")
    assert len(cases) >= 20
    ids = [case["id"] for case in cases]
    assert len(ids) == len(set(ids))
    assert {case["status"] for case in cases} <= {
        "defended", "control", "known-gap", "known-fp"
    }


def test_defended_and_control_expectations_hold():
    popular = load_popular()
    cases = run_evasion.load_cases(ROOT / "eval" / "evasion" / "cases.json")
    rows = [run_evasion.evaluate_case(case, popular) for case in cases]
    failures = [row for row in rows if not row["passed"]]
    assert failures == []
    assert all(row["flagged"] for row in rows if row["status"] == "defended")
    assert not any(row["flagged"] for row in rows if row["status"] == "control")


def test_unicode_case_is_not_silently_misparsed():
    popular = load_popular()
    case = {
        "id": "unicode",
        "technique": "unicode",
        "requirement": "requ\u0435sts",
        "status": "known-gap",
    }
    row = run_evasion.evaluate_case(case, popular)
    assert row["parsed_name"] == ""
    assert row["level"] == "OK"
