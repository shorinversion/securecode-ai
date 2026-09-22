"""P8.10 bounded in-process capacity profile over the real control plane.

The executor drives the actual ASGI application: every request travels the same
code path a deployment uses, so the measured throughput and latency describe this
build rather than a simulation. Only scenarios that can be exercised honestly in
process are run; scenarios that need a real restart, storage or network fault are
left out of the receipt instead of being reported as passing.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from .capacity import CapacityCell, CapacityReceipt
from .chaos import ChaosScenario
from .resilience import ResiliencePlan, run

MAX_CONCURRENCY: Final = 64
MAX_ITERATIONS: Final = 5_000
LOGIN_PATH: Final = "/api/v1/auth/login"

# Scenarios this executor can genuinely drive in process. Cancellation is absent
# on purpose: requests complete well below a millisecond here, so a cancellation
# lands after the worker already finished and would report zero events that
# actually occurred. It needs a workload that runs long enough to be interrupted.
EXECUTABLE_SCENARIOS: Final = (
    ChaosScenario.LEASE_EXPIRY,
    ChaosScenario.DUPLICATE,
)

AppCallable = Callable[
    [
        Mapping[str, object],
        Callable[[], Awaitable[Mapping[str, object]]],
        Callable[[Mapping[str, object]], Awaitable[None]],
    ],
    Awaitable[None],
]


@dataclass(slots=True)
class _Sample:
    queue_ms: int
    run_ms: int
    status: int
    cancelled: bool


def _to_millis(seconds: float) -> int:
    """Report observed time in whole milliseconds, never rounding a call to zero."""

    return max(1, round(seconds * 1000))


def _percentile(values: Sequence[int], fraction: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


class InProcessCapacityExecutor:
    """Measure the real application under bounded concurrency."""

    __slots__ = ("_app", "_requests")

    def __init__(
        self, app: object, *, requests: Sequence[tuple[str, str, bytes]] | None = None
    ) -> None:
        if not callable(app):
            raise TypeError("capacity executor needs a callable application")
        self._app = app
        self._requests = tuple(requests) if requests is not None else (("POST", LOGIN_PATH, b""),)

    def execute(
        self,
        scenario: ChaosScenario,
        *,
        concurrency: int,
        iterations: int,
    ) -> CapacityCell:
        if (
            type(scenario) is not ChaosScenario
            or type(concurrency) is not int
            or not 1 <= concurrency <= MAX_CONCURRENCY
            or type(iterations) is not int
            or not 1 <= iterations <= MAX_ITERATIONS
        ):
            raise ValueError("capacity execution request is invalid")
        try:
            return asyncio.run(
                self._measure(scenario, concurrency=concurrency, iterations=iterations)
            )
        except RuntimeError:
            # an enclosing loop is already running: measure on a private loop
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(
                    self._measure(scenario, concurrency=concurrency, iterations=iterations)
                )
            finally:
                loop.close()

    async def _measure(
        self,
        scenario: ChaosScenario,
        *,
        concurrency: int,
        iterations: int,
    ) -> CapacityCell:
        pending: asyncio.Queue[tuple[int, float]] = asyncio.Queue()
        samples: list[_Sample] = []
        started = time.monotonic()
        for index in range(iterations):
            pending.put_nowait((index, time.monotonic()))

        async def one_request() -> _Sample:
            index, enqueued = await pending.get()
            queue_ms = _to_millis(time.monotonic() - enqueued)
            method, path, body = self._requests[index % len(self._requests)]
            return await self._call(method, path, body, queue_ms=queue_ms)

        async def worker() -> tuple[list[_Sample], int]:
            """Collect samples; a scenario cancellation is counted, not swallowed."""

            collected: list[_Sample] = []
            cancelled = 0
            try:
                while not pending.empty():
                    collected.append(await one_request())
            except asyncio.CancelledError:
                # this worker was cancelled on purpose by the scenario: its
                # observations are reported and the cancellation is counted
                cancelled += 1
            return collected, cancelled

        tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
        if scenario is ChaosScenario.CANCEL and len(tasks) > 1:
            # always leave one worker running: cancelling every worker would measure
            # nothing, and a cell without observations must not look like a pass
            cancelled_workers = max(1, len(tasks) // 2)
            for task in tasks[len(tasks) - cancelled_workers :]:
                task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        elapsed = time.monotonic() - started
        cancelled_workers = 0
        for entry in results:
            if isinstance(entry, tuple) and len(entry) == 2:
                collected, cancelled = entry
                samples.extend(collected)
                cancelled_workers += cancelled
            elif isinstance(entry, BaseException):
                # the scenario cancelled this worker before it could report: the
                # abandoned work is counted instead of disappearing from the cell
                cancelled_workers += 1
        run_latencies = [item.run_ms for item in samples]
        queue_waits = [item.queue_ms for item in samples]
        errors = sum(1 for item in samples if item.status >= 500)
        answered = [item for item in samples if not item.cancelled]
        throughput = len(answered) if elapsed <= 0 else int(len(answered) / elapsed)
        return CapacityCell(
            scenario=scenario.value,
            completed=len(answered) == iterations,
            throughput=throughput,
            queue_p50=_percentile(queue_waits, 0.5),
            queue_p95=_percentile(queue_waits, 0.95),
            run_p50=_percentile(run_latencies, 0.5),
            run_p95=_percentile(run_latencies, 0.95),
            errors=errors,
            cancellations=cancelled_workers,
            live_leases=0,
        )

    async def _call(self, method: str, path: str, body: bytes, *, queue_ms: int) -> _Sample:
        sent: list[Mapping[str, object]] = []
        events: list[Mapping[str, object]] = [
            {"type": "http.request", "body": body, "more_body": False}
        ]

        async def receive() -> Mapping[str, object]:
            return (
                events.pop(0)
                if events
                else {"type": "http.request", "body": b"", "more_body": False}
            )

        async def send(message: Mapping[str, object]) -> None:
            sent.append(message)

        request_started = time.monotonic()
        cancelled = False
        try:
            await self._app(
                {
                    "type": "http",
                    "method": method,
                    "path": path,
                    "headers": [(b"x-api-version", b"1")],
                },
                receive,
                send,
            )
        except asyncio.CancelledError:
            cancelled = True
        run_ms = _to_millis(time.monotonic() - request_started)
        status = 0
        for message in sent:
            if message.get("type") != "http.response.start":
                continue
            raw_status = message.get("status")
            if type(raw_status) is int:
                status = raw_status
            break
        return _Sample(queue_ms=queue_ms, run_ms=run_ms, status=status, cancelled=cancelled)


def profile(
    app: object,
    *,
    concurrency: int = 8,
    iterations: int = 32,
    scenarios: Sequence[ChaosScenario] = EXECUTABLE_SCENARIOS,
) -> CapacityReceipt:
    """Run the bounded plan over the executable scenarios and return the receipt."""

    plan = ResiliencePlan(
        concurrency=concurrency,
        iterations=iterations,
        scenarios=tuple(scenarios),
    )
    return run(plan, InProcessCapacityExecutor(app))


def render(receipt: CapacityReceipt) -> str:
    """Render the measured receipt as canonical JSON."""

    return json.dumps(receipt.metadata(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))


__all__ = [
    "EXECUTABLE_SCENARIOS",
    "InProcessCapacityExecutor",
    "profile",
    "render",
]
