"""Combine name-based and metadata-based signals into one risk score.

The weights below are a first guess. Tune them on the evaluation set
(eval/run_eval.py) and document the final choice in the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .parser import normalize
from .pypi import PackageInfo
from .similarity import damerau_levenshtein
from .typo_types import TYPE_WEIGHT, TypoType, classify

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


@dataclass
class Finding:
    name: str
    target: str | None = None          # popular package it resembles
    distance: int | None = None
    typo_types: list[TypoType] = field(default_factory=list)
    score: float = 0.0
    level: str = "OK"
    reasons: list[str] = field(default_factory=list)


def closest_popular(name: str, popular: frozenset[str]) -> tuple[str, int, list[TypoType]] | None:
    """Find the popular package that best explains `name` as an imitation."""
    best: tuple[float, str, int, list[TypoType]] | None = None
    for target in popular:
        if len(target) < MIN_TARGET_LEN:
            continue
        # cheap length filter before the O(n*m) distance; affixes can be longer
        if abs(len(target) - len(name)) > MAX_DISTANCE and not name.__contains__(target):
            continue
        types = classify(name, target)
        dist = damerau_levenshtein(name, target)
        if not types and dist > MAX_DISTANCE:
            continue
        strength = DISTANCE_WEIGHT.get(dist, 0) + sum(TYPE_WEIGHT[t] for t in types)
        if best is None or strength > best[0]:
            best = (strength, target, dist, types)
    return None if best is None else best[1:]


def level_for(score: float) -> str:
    for threshold, label in LEVELS:
        if score >= threshold:
            return label
    return "OK"


def assess(
    raw_name: str,
    popular: frozenset[str],
    metadata: Callable[[str], PackageInfo | None] | None = None,
) -> Finding:
    """Score one dependency. `metadata` is usually pypi.fetch; pass None for offline mode."""
    name = normalize(raw_name)
    f = Finding(name=name)
    if name in popular:
        return f  # it *is* a known popular package

    match = closest_popular(name, popular)
    if match is None:
        return f
    f.target, f.distance, f.typo_types = match

    f.score += DISTANCE_WEIGHT.get(f.distance, 0)
    f.reasons.append(f"'{name}' is {f.distance} edit(s) away from popular package '{f.target}'")
    for t in f.typo_types:
        f.score += TYPE_WEIGHT[t]
        f.reasons.append(f"imitation technique: {t.value}")

    info = metadata(name) if metadata else None
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
