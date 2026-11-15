"""Small, dependency-free evaluation metrics used by eval/run_eval.py.

Keeping them here (instead of in the eval script) makes them testable and
reusable for the LLM experiment analysis.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Sequence


@dataclass(frozen=True)
class Confusion:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total else 0.0

    def as_dict(self) -> dict[str, float | int]:
        d = asdict(self)
        d.update(
            precision=round(self.precision, 4),
            recall=round(self.recall, 4),
            fpr=round(self.fpr, 4),
            f1=round(self.f1, 4),
            accuracy=round(self.accuracy, 4),
        )
        return d


def confusion(y_true: Sequence[int | bool], y_pred: Sequence[bool]) -> Confusion:
    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length")
    tp = fp = fn = tn = 0
    for actual, predicted in zip(y_true, y_pred):
        if actual and predicted:
            tp += 1
        elif actual and not predicted:
            fn += 1
        elif not actual and predicted:
            fp += 1
        else:
            tn += 1
    return Confusion(tp=tp, fp=fp, fn=fn, tn=tn)


def wilson_interval(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion."""
    if n <= 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def rate_with_ci(successes: int, n: int) -> tuple[float, float, float]:
    """Return (rate, lower, upper) for a binomial proportion."""
    if n <= 0:
        return (0.0, 0.0, 0.0)
    lo, hi = wilson_interval(successes, n)
    return (successes / n, lo, hi)


def mcnemar(b: int, c: int) -> float:
    """Two-sided p-value for McNemar's test on discordant pair counts.

    `b` is "method A wrong, method B right"; `c` is the opposite.  Uses the
    exact binomial test for small samples and the continuity-corrected
    chi-square approximation for large ones.
    """
    n = b + c
    if n == 0:
        return 1.0
    if n <= 1000:
        k = min(b, c)
        tail = sum(math.comb(n, i) for i in range(k + 1)) / (2**n)
        return min(1.0, 2 * tail)
    chi2 = (abs(b - c) - 1) ** 2 / n
    return math.erfc(math.sqrt(chi2 / 2))


def format_rate(k: int, n: int) -> str:
    """'0.83 [0.69-0.92]' style formatting for reports."""
    if n <= 0:
        return "n/a"
    rate, lo, hi = rate_with_ci(k, n)
    return f"{rate:.2f} [{lo:.2f}-{hi:.2f}]"
