"""Validated performance and external-spend budgets."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

_VERSION: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
_CONFIGURATION: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMPLETED: Final = "completed"
_TARGET_MAX_FILES: Final = 20
_TARGET_MAX_CHANGED_LINES: Final = 2_000
_TARGET_MAX_LATENCY_MS: Final = 600_000


class PerformanceBudgetError(ValueError):
    """Raised when performance evidence cannot be interpreted safely."""


@dataclass(frozen=True, slots=True)
class PerformanceBudget:
    version: str
    max_calls: int
    max_tokens: int
    max_cost_microunits: int
    max_ram_mb: int
    max_vram_mb: int
    external_remaining_microunits: int

    def __post_init__(self) -> None:
        if type(self.version) is not str or _VERSION.fullmatch(self.version) is None:
            raise PerformanceBudgetError("invalid budget version")
        limits = (
            self.max_calls,
            self.max_tokens,
            self.max_cost_microunits,
            self.max_ram_mb,
            self.max_vram_mb,
        )
        if any(type(value) is not int or value < 0 for value in limits):
            raise PerformanceBudgetError("budget limits must be non-negative integers")
        if (
            type(self.external_remaining_microunits) is not int
            or self.external_remaining_microunits < 0
        ):
            raise PerformanceBudgetError("external budget must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class PerformanceObservation:
    configuration: str
    status: str
    files: int
    changed_lines: int
    calls: int
    tokens: int
    cost_microunits: int
    ram_mb: int
    vram_mb: int
    latency_ms: int
    findings: int

    def __post_init__(self) -> None:
        if (
            type(self.configuration) is not str
            or _CONFIGURATION.fullmatch(self.configuration) is None
            or type(self.status) is not str
            or _CONFIGURATION.fullmatch(self.status) is None
        ):
            raise PerformanceBudgetError("invalid observation identity")
        values = (
            self.files,
            self.changed_lines,
            self.calls,
            self.tokens,
            self.cost_microunits,
            self.ram_mb,
            self.vram_mb,
            self.latency_ms,
            self.findings,
        )
        if any(type(value) is not int or value < 0 for value in values):
            raise PerformanceBudgetError("observation values must be non-negative integers")


def within(budget: PerformanceBudget, observation: PerformanceObservation) -> bool:
    """Return whether one completed observation stays inside every hard limit."""
    if type(budget) is not PerformanceBudget or type(observation) is not PerformanceObservation:
        return False
    if observation.status != _COMPLETED or hard_stop(budget, observation):
        return False
    if (
        observation.calls > budget.max_calls
        or observation.tokens > budget.max_tokens
        or observation.cost_microunits > budget.max_cost_microunits
        or observation.ram_mb > budget.max_ram_mb
        or observation.vram_mb > budget.max_vram_mb
    ):
        return False
    target_sized = (
        observation.files <= _TARGET_MAX_FILES
        and observation.changed_lines <= _TARGET_MAX_CHANGED_LINES
    )
    return target_sized and observation.latency_ms <= _TARGET_MAX_LATENCY_MS


def hard_stop(budget: PerformanceBudget, observation: PerformanceObservation) -> bool:
    """Stop before a request can overrun either the run or external cost cap."""
    if type(budget) is not PerformanceBudget or type(observation) is not PerformanceObservation:
        return True
    return (
        budget.external_remaining_microunits <= 0
        or observation.cost_microunits > budget.external_remaining_microunits
        or observation.cost_microunits > budget.max_cost_microunits
        or observation.calls > budget.max_calls
        or observation.tokens > budget.max_tokens
    )


__all__ = [
    "PerformanceBudget",
    "PerformanceBudgetError",
    "PerformanceObservation",
    "hard_stop",
    "within",
]
