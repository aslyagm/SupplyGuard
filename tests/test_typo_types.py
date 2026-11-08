from supplyguard.parser import normalize
from supplyguard.similarity import damerau_levenshtein, levenshtein
from supplyguard.typo_types import TypoType, classify


def test_normalize_pep503():
    assert normalize("Python_DateUtil") == "python-dateutil"
    assert normalize("zope.interface") == "zope-interface"


def test_transposition_is_one_edit():
    assert levenshtein("reqeusts", "requests") == 2
    assert damerau_levenshtein("reqeusts", "requests") == 1


def test_classify():
    assert classify("reqeusts", "requests") == [TypoType.TRANSPOSITION]
    assert classify("requwsts", "requests") == [TypoType.KEYBOARD_ADJACENT]
    assert classify("reqests", "requests") == [TypoType.OMISSION]
    assert classify("requessts", "requests") == [TypoType.INSERTION]
    assert classify("jeiiyfish", "jellyfish") == [TypoType.HOMOGLYPH]
    assert TypoType.HOMOGLYPH in classify("rnatplotlib", "matplotlib")
    assert classify("py-yaml", "pyyaml") == [TypoType.DELIMITER]
    assert classify("python-requests", "requests") == [TypoType.AFFIX]
    assert classify("requests", "requests") == []
