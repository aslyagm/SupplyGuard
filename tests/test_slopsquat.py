from supplyguard.slopsquat import extract_names


def test_extract_names_tolerates_noise():
    text = 'Sure! ```json\n["pdfplumber", "Camelot_py>=0.11", "tabula-py[jpype]"]\n```'
    assert extract_names(text) == ["pdfplumber", "camelot-py", "tabula-py"]


def test_extract_names_no_array():
    assert extract_names("I cannot help with that.") == []
