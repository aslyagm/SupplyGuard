"""Classify *how* a candidate name imitates a popular package.

All inputs are expected to be PEP 503 normalized (see parser.normalize).
"""

from __future__ import annotations

from enum import Enum


class TypoType(str, Enum):
    DELIMITER = "delimiter"            # py-yaml vs pyyaml, pythondateutil vs python-dateutil
    KEYBOARD_ADJACENT = "keyboard"     # requwsts vs requests (w next to e)
    HOMOGLYPH = "homoglyph"            # jeiiyfish / rnatplotlib (look-alike characters)
    TRANSPOSITION = "transposition"    # reqeusts vs requests
    OMISSION = "omission"              # reqests vs requests
    INSERTION = "insertion"            # requessts vs requests
    AFFIX = "affix"                    # python-requests, requests-py
    SUBSTITUTION = "substitution"      # any other single-character swap


# How suspicious each technique is on its own (used by scoring.py)
TYPE_WEIGHT = {
    TypoType.HOMOGLYPH: 0.30,
    TypoType.TRANSPOSITION: 0.25,
    TypoType.KEYBOARD_ADJACENT: 0.25,
    TypoType.DELIMITER: 0.25,
    TypoType.AFFIX: 0.25,
    TypoType.OMISSION: 0.15,
    TypoType.INSERTION: 0.15,
    TypoType.SUBSTITUTION: 0.10,
}

_QWERTY_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def _build_adjacency() -> dict[str, set[str]]:
    pos = {c: (r, i) for r, row in enumerate(_QWERTY_ROWS) for i, c in enumerate(row)}
    adj: dict[str, set[str]] = {c: set() for c in pos}
    for c, (r, i) in pos.items():
        for c2, (r2, i2) in pos.items():
            if c != c2 and abs(r - r2) <= 1 and abs(i - i2) <= 1:
                adj[c].add(c2)
    return adj


KEYBOARD_ADJ = _build_adjacency()

# Look-alike sequences (names are lowercased by PyPI, so "I" already became "i").
HOMOGLYPHS: list[tuple[str, str]] = [
    ("l", "1"), ("l", "i"), ("i", "1"), ("o", "0"), ("m", "rn"),
    ("w", "vv"), ("d", "cl"), ("s", "5"), ("e", "3"), ("a", "4"),
]

PREFIXES = ["python-", "python3-", "python", "py-", "py"]
SUFFIXES = ["-python", "-python3", "python", "-py", "py", "3", "2", "-lib", "lib"]


def _strip_delims(s: str) -> str:
    return s.replace("-", "")


def _single_edit(cand: str, target: str) -> TypoType | None:
    """Classify a single-character edit, if that is all that separates the names."""
    lc, lt = len(cand), len(target)
    if lc == lt:
        diff = [i for i in range(lc) if cand[i] != target[i]]
        if len(diff) == 2 and diff[1] == diff[0] + 1 and \
                cand[diff[0]] == target[diff[1]] and cand[diff[1]] == target[diff[0]]:
            return TypoType.TRANSPOSITION
        if len(diff) == 1:
            a, b = cand[diff[0]], target[diff[0]]
            if (a, b) in HOMOGLYPHS or (b, a) in HOMOGLYPHS:
                return TypoType.HOMOGLYPH
            if a in KEYBOARD_ADJ.get(b, ()):
                return TypoType.KEYBOARD_ADJACENT
            return TypoType.SUBSTITUTION
        return None
    if lc == lt - 1:
        for i in range(lt):
            if target[:i] + target[i + 1:] == cand:
                return TypoType.OMISSION
    if lc == lt + 1:
        for i in range(lc):
            if cand[:i] + cand[i + 1:] == target:
                return TypoType.INSERTION
    return None


def _homoglyph_multi(cand: str, target: str) -> bool:
    """Catch look-alikes beyond a single swap: 'rn' -> 'm', or 'jellyfish' -> 'jeiiyfish'."""
    if len(cand) == len(target):
        diff = [(c, t) for c, t in zip(cand, target) if c != t]
        if len(diff) > 1 and all((c, t) in HOMOGLYPHS or (t, c) in HOMOGLYPHS for c, t in diff):
            return True
    for a, b in HOMOGLYPHS:
        if len(a) != len(b):
            if a in target and target.replace(a, b) == cand:
                return True
            if b in target and target.replace(b, a) == cand:
                return True
    return False


def classify(cand: str, target: str) -> list[TypoType]:
    """Return every imitation technique that explains cand -> target."""
    if cand == target:
        return []
    types: list[TypoType] = []

    if _strip_delims(cand) == _strip_delims(target):
        types.append(TypoType.DELIMITER)

    for p in PREFIXES:
        if cand == p + target and not target.startswith(p):
            types.append(TypoType.AFFIX)
            break
    else:
        for s in SUFFIXES:
            if cand == target + s and not target.endswith(s):
                types.append(TypoType.AFFIX)
                break

    if _homoglyph_multi(cand, target):
        types.append(TypoType.HOMOGLYPH)

    if not types:
        t = _single_edit(cand, target)
        if t:
            types.append(t)
    return types
