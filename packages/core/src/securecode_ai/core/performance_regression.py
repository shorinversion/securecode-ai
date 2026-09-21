"""Deterministic performance regression comparison."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from dataclasses import asdict

from .performance_budget import (
    PerformanceBudget,
    PerformanceObservation,
    hard_stop,
    within,
)


def percentile(values: tuple[int, ...], q: float) -> int | None:
    """Return the conservative nearest-rank percentile for integer samples."""
    if type(values) is not tuple or not values:
        return None
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("percentile samples must be non-negative integers")
    if type(q) is not float or not math.isfinite(q) or not 0.0 <= q <= 1.0:
        raise ValueError("percentile quantile must be between zero and one")
    ordered = sorted(values)
    if q == 0.0:
        return ordered[0]
    rank = math.ceil(q * len(ordered)) - 1
    return ordered[rank]


def compare(
    budget: PerformanceBudget,
    current: tuple[PerformanceObservation, ...],
    baseline: tuple[PerformanceObservation, ...],
    tolerance: float = 0.05,
) -> dict[str, object]:
    """Compare matched samples and fail closed on missing or invalid evidence."""
    if type(budget) is not PerformanceBudget:
        return _failure("INVALID_BUDGET", current, baseline)
    if type(current) is not tuple or type(baseline) is not tuple or not current or not baseline:
        return _failure("MISSING_SAMPLES", current, baseline)
    if any(type(item) is not PerformanceObservation for item in current + baseline):
        return _failure("INVALID_SAMPLES", current, baseline)
    if type(tolerance) is not float or not math.isfinite(tolerance) or tolerance < 0.0:
        return _failure("INVALID_TOLERANCE", current, baseline)
    if any(item.status != "completed" for item in current + baseline):
        return _failure("INCOMPLETE_SAMPLES", current, baseline)
    if _sample_shapes(current) != _sample_shapes(baseline):
        return _failure("UNMATCHED_SAMPLES", current, baseline)
    if (
        any(hard_stop(budget, item) for item in current)
        or sum(item.cost_microunits for item in current) > budget.external_remaining_microunits
    ):
        return _failure("EXTERNAL_BUDGET_EXHAUSTED", current, baseline)

    current_p50 = percentile(tuple(item.latency_ms for item in current), 0.50)
    current_p95 = percentile(tuple(item.latency_ms for item in current), 0.95)
    baseline_p95 = percentile(tuple(item.latency_ms for item in baseline), 0.95)
    assert current_p50 is not None and current_p95 is not None and baseline_p95 is not None
    finding_count = sum(item.findings for item in current)
    cost = sum(item.cost_microunits for item in current)
    return {
        "passed": (
            all(within(budget, item) for item in current)
            and current_p95 <= baseline_p95 * (1.0 + tolerance)
        ),
        "reason": "PASS"
        if all(within(budget, item) for item in current)
        and current_p95 <= baseline_p95 * (1.0 + tolerance)
        else "BUDGET_OR_REGRESSION",
        "current_samples": len(current),
        "baseline_samples": len(baseline),
        "p50": current_p50,
        "p95": current_p95,
        "baseline_p95": baseline_p95,
        "cost_per_finding": None if finding_count == 0 else cost / finding_count,
        "finding_denominator": finding_count,
    }


def canonical_hash(values: tuple[PerformanceObservation, ...]) -> str:
    if type(values) is not tuple or any(
        type(item) is not PerformanceObservation for item in values
    ):
        raise ValueError("invalid performance observations")
    payload = json.dumps(
        [asdict(item) for item in values],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _sample_shapes(
    values: tuple[PerformanceObservation, ...],
) -> Counter[tuple[str, int, int]]:
    return Counter((item.configuration, item.files, item.changed_lines) for item in values)


def _failure(
    reason: str,
    current: object,
    baseline: object,
) -> dict[str, object]:
    return {
        "passed": False,
        "reason": reason,
        "current_samples": len(current) if isinstance(current, tuple) else 0,
        "baseline_samples": len(baseline) if isinstance(baseline, tuple) else 0,
        "p50": None,
        "p95": None,
        "baseline_p95": None,
        "cost_per_finding": None,
        "finding_denominator": 0,
    }


__all__ = ["canonical_hash", "compare", "percentile"]
