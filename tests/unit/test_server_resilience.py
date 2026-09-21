from __future__ import annotations

from securecode_ai.server.capacity import CapacityCell
from securecode_ai.server.chaos import ChaosScenario
from securecode_ai.server.resilience import ResiliencePlan, run


class E:
    def execute(
        self,
        scenario: ChaosScenario,
        *,
        concurrency: int,
        iterations: int,
    ) -> CapacityCell:
        del concurrency, iterations
        return CapacityCell(scenario.value, False, 0, None, None, None, None, 1, 0, 1)


def test_missing_cells_cannot_pass() -> None:
    assert not run(ResiliencePlan(1, 1), E()).passed
