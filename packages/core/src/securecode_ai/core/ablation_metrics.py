"""Deterministic paired ablation statistics."""

from __future__ import annotations

import hashlib
import math

_BOOTSTRAP_SAMPLES = 1_000
_BOOTSTRAP_DOMAIN = b"securecode-paired-bootstrap-v1\x00"


def paired_delta(a: tuple[float, ...], b: tuple[float, ...]) -> float | None:
    differences = _paired_differences(a, b)
    if differences is None:
        return None
    return sum(differences) / len(differences)


def bootstrap_interval(
    a: tuple[float, ...],
    b: tuple[float, ...],
) -> tuple[float, float] | None:
    differences = _paired_differences(a, b)
    if differences is None:
        return None

    values = sorted(
        _resampled_mean(differences, sample_index) for sample_index in range(_BOOTSTRAP_SAMPLES)
    )
    lower_index = math.ceil(0.025 * _BOOTSTRAP_SAMPLES) - 1
    upper_index = math.ceil(0.975 * _BOOTSTRAP_SAMPLES) - 1
    return values[lower_index], values[upper_index]


def _paired_differences(
    a: tuple[float, ...],
    b: tuple[float, ...],
) -> tuple[float, ...] | None:
    if not a or len(a) != len(b):
        return None

    differences: list[float] = []
    for left, right in zip(a, b, strict=True):
        if not _finite_number(left) or not _finite_number(right):
            return None
        difference = left - right
        if not math.isfinite(difference):
            return None
        differences.append(difference)
    return tuple(differences)


def _resampled_mean(
    differences: tuple[float, ...],
    sample_index: int,
) -> float:
    total = 0.0
    for draw_index in range(len(differences)):
        index = _bootstrap_index(
            sample_index,
            draw_index,
            len(differences),
        )
        total += differences[index]
    return total / len(differences)


def _bootstrap_index(
    sample_index: int,
    draw_index: int,
    population_size: int,
) -> int:
    material = _BOOTSTRAP_DOMAIN + sample_index.to_bytes(4, "big") + draw_index.to_bytes(4, "big")
    digest = hashlib.sha256(material).digest()
    return int.from_bytes(digest[:8], "big") % population_size


def _finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False
