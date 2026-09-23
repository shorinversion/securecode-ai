"""Bounded capacity measurements where incomplete cells never pass."""

from __future__ import annotations

from dataclasses import dataclass

_MAX_COUNTER = 9_223_372_036_854_775_807


@dataclass(frozen=True, slots=True)
class CapacityCell:
    scenario: str
    completed: bool
    throughput: int
    queue_p50: int | None
    queue_p95: int | None
    run_p50: int | None
    run_p95: int | None
    errors: int
    cancellations: int
    live_leases: int

    def __post_init__(self) -> None:
        counters = (
            self.throughput,
            self.errors,
            self.cancellations,
            self.live_leases,
        )
        percentiles = (
            self.queue_p50,
            self.queue_p95,
            self.run_p50,
            self.run_p95,
        )
        if (
            not isinstance(self.scenario, str)
            or not self.scenario
            or len(self.scenario) > 128
            or type(self.completed) is not bool
            or any(type(value) is not int or not 0 <= value <= _MAX_COUNTER for value in counters)
            or any(
                value is not None and (type(value) is not int or not 0 <= value <= _MAX_COUNTER)
                for value in percentiles
            )
            or (
                self.queue_p50 is not None
                and self.queue_p95 is not None
                and self.queue_p50 > self.queue_p95
            )
            or (
                self.run_p50 is not None
                and self.run_p95 is not None
                and self.run_p50 > self.run_p95
            )
        ):
            raise ValueError("capacity cell is invalid")

    @property
    def passed(self) -> bool:
        capacity_pass = (
            self.completed
            and self.throughput > 0
            and self.queue_p50 is not None
            and self.queue_p95 is not None
            and self.run_p50 is not None
            and self.run_p95 is not None
            and self.errors == 0
            and self.live_leases == 0
        )
        if self.scenario == "cancellation":
            return capacity_pass and self.cancellations > 0 and not self.completed
        return capacity_pass


@dataclass(frozen=True, slots=True)
class CapacityReceipt:
    cells: tuple[CapacityCell, ...]

    def __post_init__(self) -> None:
        if (
            type(self.cells) is not tuple
            or any(type(item) is not CapacityCell for item in self.cells)
            or len({item.scenario for item in self.cells}) != len(self.cells)
        ):
            raise ValueError("capacity receipt is invalid")

    @property
    def passed(self) -> bool:
        return bool(self.cells) and all(item.passed for item in self.cells)

    def metadata(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "cells": tuple(
                {
                    "scenario": item.scenario,
                    "completed": item.completed,
                    "throughput": item.throughput,
                    "queue_p50": item.queue_p50,
                    "queue_p95": item.queue_p95,
                    "run_p50": item.run_p50,
                    "run_p95": item.run_p95,
                    "errors": item.errors,
                    "cancellations": item.cancellations,
                    "live_leases": item.live_leases,
                    "passed": item.passed,
                }
                for item in self.cells
            ),
        }


__all__ = ["CapacityCell", "CapacityReceipt"]
