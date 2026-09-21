"""Dependency-free deterministic release benchmark metrics."""

from __future__ import annotations

import math


def ratio(a: int, b: int) -> float:
    _validate_count_pair(a, b)
    return a / b if b else 0.0


def f1(p: float, r: float) -> float:
    _validate_fraction(p)
    _validate_fraction(r)
    return 2 * p * r / (p + r) if p + r else 0.0


def wilson_lower(success: int, total: int) -> float:
    _validate_count_pair(success, total)
    if not total:
        return 0.0

    z = 1.959963984540054
    proportion = success / total
    denominator = 1 + z * z / total
    numerator = (
        proportion
        + z * z / (2 * total)
        - z * math.sqrt((proportion * (1 - proportion) + z * z / (4 * total)) / total)
    )
    return numerator / denominator


def percentile(values: tuple[int, ...], q: float) -> int:
    if type(values) is not tuple or any(type(value) is not int or value < 0 for value in values):
        raise ValueError("values must be non-negative integer measurements")
    if (
        isinstance(q, bool)
        or not isinstance(q, (int, float))
        or not math.isfinite(q)
        or not 0 <= q <= 1
    ):
        raise ValueError("q must be finite and between zero and one")
    if not values:
        return 0

    ordered = sorted(values)
    index = max(
        0,
        min(
            len(ordered) - 1,
            math.ceil(q * len(ordered)) - 1,
        ),
    )
    return ordered[index]


def _validate_count_pair(success: int, total: int) -> None:
    if (
        type(success) is not int
        or type(total) is not int
        or success < 0
        or total < 0
        or success > total
    ):
        raise ValueError("counts must satisfy 0 <= success <= total")


def _validate_fraction(value: float) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 <= value <= 1
    ):
        raise ValueError("metric fractions must be finite and between zero and one")
