from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping

from securecode_ai.server.capacity_profile import InProcessCapacityExecutor, profile
from securecode_ai.server.chaos import ChaosScenario

Receive = Callable[[], Awaitable[Mapping[str, object]]]
Send = Callable[[Mapping[str, object]], Awaitable[None]]


async def _application(scope: Mapping[str, object], receive: Receive, send: Send) -> None:
    del scope
    await receive()
    await asyncio.sleep(0)
    await send({"type": "http.response.start", "status": 200})
    await send({"type": "http.response.body", "body": b"{}"})


def test_cancellation_counts_workers_cancelled_before_they_start() -> None:
    cell = InProcessCapacityExecutor(_application).execute(
        ChaosScenario.CANCEL, concurrency=4, iterations=8
    )

    assert cell.scenario == "cancellation"
    assert cell.cancellations == 2
    assert not cell.completed
    assert not cell.passed
    assert cell.live_leases == 0


def test_duplicate_capacity_profile_reports_a_passing_real_application_cell() -> None:
    receipt = profile(
        _application,
        concurrency=2,
        iterations=4,
        scenarios=(ChaosScenario.DUPLICATE,),
    )

    assert receipt.passed
    assert receipt.cells[0].scenario == "duplicate_delivery"
    assert receipt.cells[0].completed
    assert receipt.cells[0].cancellations == 0


def test_capacity_executor_can_run_from_an_async_server_path() -> None:
    async def invoke() -> str:
        return (
            InProcessCapacityExecutor(_application)
            .execute(ChaosScenario.DUPLICATE, concurrency=2, iterations=4)
            .scenario
        )

    assert asyncio.run(invoke()) == "duplicate_delivery"
