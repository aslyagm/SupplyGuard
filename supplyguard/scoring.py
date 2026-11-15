"""Combine name-based and metadata-based signals into one risk score.

The weights are checked against the evaluation set in ``eval/run_eval.py``;
``--sweep`` prints the precision/recall/FPR trade-off for every threshold.
The default MEDIUM threshold is intentionally broad, so CI users who want fewer
false positives can raise the bar with ``--fail-on HIGH`` or a baseline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Callable, Iterable

from .parser import normalize
from .popular import PopularIndex
from .pypi import PackageInfo
from .similarity import bag_distance, char_counts, damerau_levenshtein
from .typo_types import PREFIXES, SUFFIXES, TYPE_WEIGHT, TypoType, classify

MAX_DISTANCE = 2      # consider popular names within this edit distance
MIN_TARGET_LEN = 4    # very short popular names ("six", "pip") create noise

DISTANCE_WEIGHT = {1: 0.35, 2: 0.20}

# Metadata signals
NEW_PACKAGE_DAYS = 90
W_NEW = 0.20
W_FEW_RELEASES = 0.10
W_NO_URL = 0.10
W_NO_SUMMARY = 0.05
W_NOT_ON_PYPI = 0.15  # name is free: anyone could register it

LEVELS = [(0.70, "HIGH"), (0.40, "MEDIUM"), (0.0001, "LOW")]
LEVEL_ORDER = {"OK": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


@dataclass
class Finding:
    name: str
    target: str | None = None          # popular package it resembles
    target_rank: int | None = None     # download rank of the target (1 = top)
    distance: int | None = None
    typo_types: list[TypoType] = field(default_factory=list)
    score: float = 0.0
    level: str = "OK"
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    known_malicious: list[str] = field(default_factory=list)
    source_file: str | None = None
    source_line: int | None = None
    suppressed: bool = False
    suppressed_reason: str = ""
    baseline: bool = False


def _as_index(popular: PopularIndex | Iterable[str]) -> PopularIndex:
    if isinstance(popular, PopularIndex):
        return popular
    return _index_from_names(frozenset(popular))


@lru_cache(maxsize=8)
def _index_from_names(names: frozenset[str]) -> PopularIndex:
    return PopularIndex.from_names(names)


def closest_popular(
    name: str, popular: PopularIndex | Iterable[str]
) -> tuple[str, int, list[TypoType]] | None:
    """Find the popular package that best explains `name` as an imitation.

    Only candidates that are an exact affix/delimiter variant or that pass a
    character-count lower bound are compared with the full edit distance.
    Ties are broken by distance, then by the target's download rank, then
    alphabetically, so the result does not depend on set iteration order.
    """
    idx = _as_index(popular)
    candidates: set[str] = set()

    # Adding/removing a known prefix or suffix can be arbitrarily long, so
    # look these up exactly instead of scanning every longer target.
    for prefix in PREFIXES:
        if len(name) > len(prefix) and name.startswith(prefix):
            target = name[len(prefix):]
            if target in idx.names:
                candidates.add(target)
    for suffix in SUFFIXES:
        if len(name) > len(suffix) and name.endswith(suffix):
            target = name[:-len(suffix)]
            if target in idx.names:
                candidates.add(target)

    # py-yaml vs pyyaml / pythondateutil vs python-dateutil
    for target in idx.by_stripped.get(name.replace("-", ""), ()):
        candidates.add(target)

    # A single edit changes the length by at most one; a transposition not at
    # all.  Homoglyph sequences ("rn" -> "m") are at most two characters.
    counts = char_counts(name)
    for length in range(len(name) - MAX_DISTANCE, len(name) + MAX_DISTANCE + 1):
        if length < MIN_TARGET_LEN:
            continue
        for target in idx.by_length.get(length, ()):
            if bag_distance(counts, idx.counts[target]) <= MAX_DISTANCE:
                candidates.add(target)

    best: tuple[str, int, list[TypoType]] | None = None
    best_key: tuple[float, int, int] | None = None
    best_target = ""
    for target in candidates:
        if len(target) < MIN_TARGET_LEN:
            continue
        types = classify(name, target)
        dist = damerau_levenshtein(name, target)
        # Distance-2 pairs without a recognisable typo technique are almost
        # always unrelated real packages (e.g. "tabula" vs "tabulate").
        if not types and dist != 1:
            continue
        strength = DISTANCE_WEIGHT.get(dist, 0.0) + sum(TYPE_WEIGHT[t] for t in types)
        rank = idx.rank.get(target, 0)
        key = (strength, -dist, -rank if rank else -(10**9))
        if (
            best_key is None
            or key > best_key
            or (key == best_key and target < best_target)
        ):
            best = (target, dist, types)
            best_key = key
            best_target = target
    return best


def level_for(score: float) -> str:
    for threshold, label in LEVELS:
        if score >= threshold:
            return label
    return "OK"


def assess(
    raw_name: str,
    popular: PopularIndex | Iterable[str],
    metadata: Callable[[str], PackageInfo | None] | None = None,
) -> Finding:
    """Score one dependency. `metadata` is usually pypi.fetch; pass None for offline mode."""
    name = normalize(raw_name)
    f = Finding(name=name)
    idx = _as_index(popular)
    if name in idx.names:
        f.target_rank = idx.rank.get(name) or None
        return f  # it *is* a known popular package

    match = closest_popular(name, idx)
    if match is None:
        # Even without a name-similarity match, an online lookup can tell us
        # that the name is not registered: a classic slopsquatting signal.
        if metadata is not None:
            info = metadata(name)
            if info is None:
                f.warnings.append("PyPI metadata unavailable")
            elif not info.exists:
                f.score = W_NOT_ON_PYPI
                f.level = level_for(f.score)
                f.reasons.append("not found on PyPI: this exact name is not registered")
        return f

    f.target, f.distance, f.typo_types = match
    f.target_rank = idx.rank.get(f.target) or None

    f.score += DISTANCE_WEIGHT.get(f.distance, 0)
    f.reasons.append(f"'{name}' is {f.distance} edit(s) away from popular package '{f.target}'")
    for t in f.typo_types:
        f.score += TYPE_WEIGHT[t]
        f.reasons.append(f"imitation technique: {t.value}")

    info = metadata(name) if metadata else None
    if metadata is not None and info is None:
        f.warnings.append("PyPI metadata unavailable")
    if info is not None:
        if not info.exists:
            f.score += W_NOT_ON_PYPI
            f.reasons.append("not on PyPI: install will fail, but the name is unclaimed")
        else:
            age = info.age_days()
            if age is not None and age < NEW_PACKAGE_DAYS:
                f.score += W_NEW
                f.reasons.append(f"first released only {age} days ago")
            if info.release_count <= 2:
                f.score += W_FEW_RELEASES
                f.reasons.append(f"only {info.release_count} release(s)")
            if not info.has_project_url:
                f.score += W_NO_URL
                f.reasons.append("no homepage or repository link")
            if not info.summary:
                f.score += W_NO_SUMMARY
                f.reasons.append("empty description")

    f.score = round(min(f.score, 1.0), 3)
    f.level = level_for(f.score)
    return f
