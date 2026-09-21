"""Fail-closed facts and denominator aggregation for the P7.17 study."""

from __future__ import annotations

from .development_benchmark_aggregate import aggregate, planned_cells
from .development_benchmark_models import (
    CONFIGURATIONS,
    Configuration,
    FindingOrigin,
    Label,
    Record,
)

Record.__module__ = __name__
__all__ = [
    "CONFIGURATIONS",
    "Configuration",
    "FindingOrigin",
    "Label",
    "Record",
    "aggregate",
    "planned_cells",
]
