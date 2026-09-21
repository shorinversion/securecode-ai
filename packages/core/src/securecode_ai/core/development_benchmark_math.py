"""Fail-closed facts and denominator aggregation for the P7.17 study."""

from __future__ import annotations

from math import ceil


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    return values[max(0, ceil(fraction * len(values)) - 1)]


def _ratio(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else numerator / denominator


def _f_score(precision: float | None, recall: float | None, *, beta_squared: int) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return (1 + beta_squared) * precision * recall / (beta_squared * precision + recall)


def _require_sha256(value: str) -> None:
    if not value.startswith("sha256:") or not _is_lower_hex(value[7:], 64):
        raise ValueError("invalid SHA-256 identity")


def _is_lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_source_alias(value: object) -> bool:
    if type(value) is not str or not value.startswith("file_") or not value.endswith(".py"):
        return False
    number = value[5:-3]
    return number.isdecimal() and number != "0" and str(int(number)) == number
