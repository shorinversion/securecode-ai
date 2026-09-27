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
    planned_requests: int | None = None
    observed_requests: int | None = None
    completed_requests: int | None = None
    unfinished_requests: int | None = None
    cancelled_requests: int | None = None
    deadline_reached: bool = False
    request_cap_reached: bool = False

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
        denominators = (
            self.planned_requests,
            self.observed_requests,
            self.completed_requests,
            self.unfinished_requests,
            self.cancelled_requests,
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
            or any(
                value is not None and (type(value) is not int or not 0 <= value <= _MAX_COUNTER)
                for value in denominators
            )
            or type(self.deadline_reached) is not bool
            or type(self.request_cap_reached) is not bool
            or (
                self.planned_requests is not None
                and self.observed_requests is not None
                and self.observed_requests > self.planned_requests
            )
            or (
                self.observed_requests is not None
                and self.completed_requests is not None
                and self.completed_requests > self.observed_requests
            )
            or (
                self.planned_requests is not None
                and self.unfinished_requests is not None
                and self.unfinished_requests > self.planned_requests
            )
            or (
                self.observed_requests is not None
                and self.unfinished_requests is not None
                and self.planned_requests is not None
                and self.observed_requests + self.unfinished_requests
                > self.planned_requests
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
        observed_cleanly = (
            self.throughput > 0
            and self.queue_p50 is not None
            and self.queue_p95 is not None
            and self.run_p50 is not None
            and self.run_p95 is not None
            and self.errors == 0
            and self.live_leases == 0
        )
        return observed_cleanly and self.completed and self.result == "PASSED"

    @property
    def result(self) -> str:
        """Return an explicit outcome for operators and machine consumers.

        A workload that was interrupted or did not observe every planned request
        is indeterminate. It is never silently converted into a successful
        capacity result. A completed workload with HTTP/runtime errors is failed.
        """

        if self.scenario in {"cancellation", "worker_lifecycle"}:
            if self.cancellations == 0 or self.cancelled_requests in (None, 0):
                return "FAILED"
            if (
                not self.completed
                or self.unfinished_requests not in (None, 0)
            ):
                return "INDETERMINATE"
            if not observed_cleanly_for_result(self):
                return "FAILED"
            return "PASSED"
        if (
            not self.completed
            or self.cancellations > 0
            or self.unfinished_requests not in (None, 0)
            or self.cancelled_requests not in (None, 0)
            or (self.scenario == "soak" and not self.deadline_reached)
        ):
            return "INDETERMINATE"
        if not observed_cleanly_for_result(self):
            return "FAILED"
        return "PASSED"


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

    @property
    def result(self) -> str:
        if not self.cells or any(item.result == "INDETERMINATE" for item in self.cells):
            return "INDETERMINATE"
        if any(item.result == "FAILED" for item in self.cells):
            return "FAILED"
        return "PASSED"

    def metadata(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "result": self.result,
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
                    "planned_requests": item.planned_requests,
                    "observed_requests": item.observed_requests,
                    "completed_requests": item.completed_requests,
                    "unfinished_requests": item.unfinished_requests,
                    "cancelled_requests": item.cancelled_requests,
                    "deadline_reached": item.deadline_reached,
                    "request_cap_reached": item.request_cap_reached,
                    "result": item.result,
                    "passed": item.passed,
                }
                for item in self.cells
            ),
        }


def observed_cleanly_for_result(cell: CapacityCell) -> bool:
    """Check result-quality counters without conflating status with outcome."""

    return (
        cell.throughput > 0
        and cell.queue_p50 is not None
        and cell.queue_p95 is not None
        and cell.run_p50 is not None
        and cell.run_p95 is not None
        and cell.errors == 0
        and cell.live_leases == 0
    )


__all__ = ["CapacityCell", "CapacityReceipt", "observed_cleanly_for_result"]
