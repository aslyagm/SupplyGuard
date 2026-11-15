"""String distance functions and cheap pre-filters."""

from __future__ import annotations

# Character-count vectors are used as a cheap lower bound before running the
# full O(n*m) edit distance.  PyPI names are ASCII (letters, digits, -), but
# anything else is folded into a single "other" bucket, which can only make
# the bound weaker, never skip a real match.
_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"
_INDEX = {c: i for i, c in enumerate(_ALPHABET)}
_OTHER = len(_ALPHABET)


def char_counts(s: str) -> tuple[int, ...]:
    """Count characters of `s` over a small fixed alphabet."""
    counts = [0] * (_OTHER + 1)
    for c in s:
        counts[_INDEX.get(c, _OTHER)] += 1
    return tuple(counts)


def bag_distance(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    """Lower bound on edit distance: unmatched character occurrences.

    Each insertion/deletion/substitution can fix at most one unmatched
    character, so if this value is greater than k the edit distance is too.
    """
    return sum(max(0, x - y) for x, y in zip(a, b))


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance (insert / delete / substitute). Used as the baseline."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment distance: like Levenshtein, but an adjacent
    swap ("reqeusts" vs "requests") counts as one edit instead of two."""
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def similarity(a: str, b: str) -> float:
    """Normalized similarity in [0, 1] based on Damerau-Levenshtein."""
    if not a and not b:
        return 1.0
    return 1.0 - damerau_levenshtein(a, b) / max(len(a), len(b))
