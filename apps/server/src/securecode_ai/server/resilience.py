"""Injected deterministic load and soak orchestration without side effects."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .capacity import CapacityCell, CapacityReceipt
from .chaos import SCENARIOS, ChaosScenario


class ScenarioExecutor(Protocol):
    def execute(
        self,
        scenario: ChaosScenario,
        *,
        concurrency: int,
        iterations: int,
    ) -> CapacityCell: ...


@dataclass(frozen=True, slots=True)
class ResiliencePlan:
    concurrency: int
    iterations: int
    scenarios: tuple[ChaosScenario, ...] = SCENARIOS

    def __post_init__(self) -> None:
        if (
            type(self.concurrency) is not int
            or not 1 <= self.concurrency <= 128
            or type(self.iterations) is not int
            or not 1 <= self.iterations <= 10_000
            or type(self.scenarios) is not tuple
            or not self.scenarios
            or any(type(item) is not ChaosScenario for item in self.scenarios)
            or len(self.scenarios) != len(set(self.scenarios))
        ):
            raise ValueError("resilience plan is invalid")


def run(plan: ResiliencePlan, executor: ScenarioExecutor) -> CapacityReceipt:
    if type(plan) is not ResiliencePlan or not callable(getattr(executor, "execute", None)):
        raise TypeError("resilience dependencies are invalid")
    cells: list[CapacityCell] = []
    for scenario in plan.scenarios:
        cell = executor.execute(
            scenario,
            concurrency=plan.concurrency,
            iterations=plan.iterations,
        )
        if type(cell) is not CapacityCell or cell.scenario != scenario.value:
            raise ValueError("resilience result is invalid")
        cells.append(cell)
    return CapacityReceipt(tuple(cells))


__all__ = ["ResiliencePlan", "ScenarioExecutor", "run"]
