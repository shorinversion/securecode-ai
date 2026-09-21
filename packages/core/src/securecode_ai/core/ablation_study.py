"""Immutable matched-case lane and component ablation boundary."""

from __future__ import annotations

import hashlib
import json
import math
import random
import re
from dataclasses import asdict, dataclass
from typing import Final

from .ablation_metrics import paired_delta

_TOKEN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]{0,255}\Z")
_VARIANTS: Final = frozenset(
    {
        "deterministic_lane",
        "model_native_lane",
        "evidence_graph",
        "skeptic",
        "validator",
        "root_cause",
    }
)
_QUALITY_METRICS: Final = (
    "precision",
    "recall",
    "f1",
    "localization",
    "correct_secure",
)
_RESOURCE_METRICS: Final = ("latency_ms", "cost_microunits")


class AblationValidationError(ValueError):
    """Raised for malformed ablation evidence."""


@dataclass(frozen=True, slots=True)
class AblationCell:
    case_id: str
    lineage: str
    repetition: int
    variant: str
    pins: tuple[str, ...]
    status: str
    precision: float
    recall: float
    f1: float
    localization: float
    correct_secure: float
    latency_ms: float
    cost_microunits: float

    def __post_init__(self) -> None:
        if (
            not _token(self.case_id)
            or not _token(self.lineage)
            or type(self.repetition) is not int
            or not 1 <= self.repetition <= 3
            or self.variant not in _VARIANTS
            or type(self.pins) is not tuple
            or not self.pins
            or any(not _token(pin) for pin in self.pins)
            or not _token(self.status)
        ):
            raise AblationValidationError("invalid ablation cell identity")
        quality = tuple(getattr(self, name) for name in _QUALITY_METRICS)
        resources = tuple(getattr(self, name) for name in _RESOURCE_METRICS)
        if any(not _finite_number(value) or not 0.0 <= value <= 1.0 for value in quality):
            raise AblationValidationError("quality metrics must be between zero and one")
        if any(not _finite_number(value) or value < 0.0 for value in resources):
            raise AblationValidationError("resource metrics must be non-negative")


def compare(
    control: tuple[AblationCell, ...],
    variant: tuple[AblationCell, ...],
) -> dict[str, object]:
    """Compare two complete, exactly matched variants using paired bootstrap."""
    if type(control) is not tuple or type(variant) is not tuple:
        return {"contribution": False, "reason": "MISSING_OR_UNMATCHED"}
    if any(type(cell) is not AblationCell for cell in control + variant):
        return {"contribution": False, "reason": "INVALID_CELL"}
    left = sorted(control, key=_identity)
    right = sorted(variant, key=_identity)
    if not left or len(left) != len(right):
        return {"contribution": False, "reason": "MISSING_OR_UNMATCHED"}
    if any(
        _identity(a) != _identity(b) or a.pins != b.pins for a, b in zip(left, right, strict=True)
    ):
        return {"contribution": False, "reason": "MISSING_OR_UNMATCHED"}
    if any(cell.status != "completed" for cell in left + right):
        return {"contribution": False, "reason": "INCOMPLETE_CELL"}
    left_variants = {cell.variant for cell in left}
    right_variants = {cell.variant for cell in right}
    if len(left_variants) != 1 or len(right_variants) != 1 or left_variants == right_variants:
        return {"contribution": False, "reason": "INVALID_VARIANT_PAIR"}

    result: dict[str, object] = {}
    contributions = []
    for name in _QUALITY_METRICS + _RESOURCE_METRICS:
        current = tuple(float(getattr(cell, name)) for cell in right)
        baseline = tuple(float(getattr(cell, name)) for cell in left)
        interval = _bootstrap_interval(current, baseline)
        if name in _QUALITY_METRICS:
            significant = interval is not None and interval[0] > 0.0
        else:
            significant = interval is not None and interval[1] < 0.0
        result[name] = {
            "delta": paired_delta(current, baseline),
            "interval": interval,
            "contribution": significant,
        }
        contributions.append(significant)
    result["contribution"] = all(contributions)
    return result


def canonical_hash(cells: tuple[AblationCell, ...]) -> str:
    if type(cells) is not tuple or any(type(cell) is not AblationCell for cell in cells):
        raise AblationValidationError("invalid ablation hash request")
    identities = [(_identity(cell), cell.variant) for cell in cells]
    if len(set(identities)) != len(identities):
        raise AblationValidationError("duplicate ablation cell")
    material = [
        asdict(cell) for cell in sorted(cells, key=lambda cell: (*_identity(cell), cell.variant))
    ]
    payload = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _bootstrap_interval(
    current: tuple[float, ...],
    baseline: tuple[float, ...],
    samples: int = 2_000,
) -> tuple[float, float] | None:
    if not current or len(current) != len(baseline):
        return None
    deltas = tuple(a - b for a, b in zip(current, baseline, strict=True))
    generator = random.Random(0)
    estimates = sorted(
        sum(generator.choice(deltas) for _ in deltas) / len(deltas) for _ in range(samples)
    )
    return (
        estimates[max(0, math.ceil(0.025 * samples) - 1)],
        estimates[min(samples - 1, math.ceil(0.975 * samples) - 1)],
    )


def _identity(cell: AblationCell) -> tuple[str, str, int]:
    return cell.case_id, cell.lineage, cell.repetition


def _finite_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _token(value: object) -> bool:
    return type(value) is str and _TOKEN.fullmatch(value) is not None


__all__ = [
    "AblationCell",
    "AblationValidationError",
    "canonical_hash",
    "compare",
]
