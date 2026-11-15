import pytest

from supplyguard.metrics import (
    Confusion,
    confusion,
    format_rate,
    mcnemar,
    rate_with_ci,
    wilson_interval,
)


def test_confusion_rates():
    m = confusion([1, 1, 0, 0], [True, False, True, False])
    assert (m.tp, m.fp, m.fn, m.tn) == (1, 1, 1, 1)
    assert m.precision == pytest.approx(0.5)
    assert m.recall == pytest.approx(0.5)
    assert m.fpr == pytest.approx(0.5)
    assert m.f1 == pytest.approx(0.5)
    assert m.accuracy == pytest.approx(0.5)


def test_confusion_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        confusion([1], [True, False])


def test_wilson_interval_stays_in_range():
    assert wilson_interval(0, 0) == (0.0, 0.0)
    lo, hi = wilson_interval(5, 10)
    assert 0.0 <= lo <= 0.5 <= hi <= 1.0
    assert rate_with_ci(0, 0) == (0.0, 0.0, 0.0)


def test_mcnemar_symmetric_cases():
    assert mcnemar(0, 0) == 1.0
    assert mcnemar(5, 5) == 1.0
    assert mcnemar(10, 0) < 0.01


def test_format_rate():
    assert format_rate(1, 0) == "n/a"
    assert format_rate(5, 10).startswith("0.50 [")


def test_as_dict_rounding():
    d = Confusion(tp=1, fp=0, fn=1, tn=2).as_dict()
    assert d["precision"] == 1.0
    assert d["recall"] == 0.5
    assert d["fpr"] == 0.0
