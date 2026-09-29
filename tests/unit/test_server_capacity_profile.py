"""P8.10 in-process capacity executor: honest counters and bounded profiles."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping

import pytest
from securecode_ai.server.capacity import CapacityCell, CapacityReceipt
from securecode_ai.server.capacity_profile import (
    EXECUTABLE_SCENARIOS,
    InProcessCapacityExecutor,
    profile,
    render,
)
from securecode_ai.server.chaos import ChaosScenario
from securecode_ai.server.runtime import RuntimeSettings

from scripts import capacity_profile as capacity_cli

Handler = Callable[
    [Mapping[str, object]],
    Awaitable[None],
]


class _App:
    """Minimal ASGI callable: answers with the configured status after a delay."""

    def __init__(self, *, status: int = 200, delay: float = 0.0) -> None:
        self._status = status
        self._delay = delay
        self.calls = 0

    async def __call__(
        self,
        scope: Mapping[str, object],
        receive: object,
        send: Callable[[Mapping[str, object]], Awaitable[None]],
    ) -> None:
        self.calls += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        await send({"type": "http.response.start", "status": self._status, "headers": []})
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})


def test_executor_requires_a_callable_application() -> None:
    with pytest.raises(TypeError):
        InProcessCapacityExecutor(object())


@pytest.mark.parametrize(
    "arguments",
    [
        {"concurrency": 0, "iterations": 1},
        {"concurrency": 65, "iterations": 1},
        {"concurrency": 1, "iterations": 0},
        {"concurrency": 1, "iterations": 5_001},
    ],
)
def test_execute_validates_bounds(arguments: dict[str, int]) -> None:
    executor = InProcessCapacityExecutor(_App())
    with pytest.raises(ValueError):
        executor.execute(ChaosScenario.LEASE_EXPIRY, **arguments)


def test_healthy_run_reports_a_passing_cell() -> None:
    app = _App(status=200)
    cell = InProcessCapacityExecutor(app).execute(
        ChaosScenario.LEASE_EXPIRY, concurrency=4, iterations=32
    )
    assert isinstance(cell, CapacityCell)
    assert cell.scenario == ChaosScenario.LEASE_EXPIRY.value
    assert cell.completed and cell.passed
    assert cell.errors == 0
    assert cell.cancellations == 0
    assert cell.throughput > 0
    assert app.calls == 32
    assert cell.run_p50 is not None and cell.run_p50 >= 1
    assert cell.queue_p95 is not None and cell.queue_p95 >= 1


def test_server_errors_are_counted() -> None:
    cell = InProcessCapacityExecutor(_App(status=503)).execute(
        ChaosScenario.DUPLICATE, concurrency=4, iterations=16
    )
    assert cell.errors == 16
    assert not cell.passed
    assert cell.completed


def test_client_error_status_is_counted_as_a_capacity_failure() -> None:
    cell = InProcessCapacityExecutor(_App(status=401)).execute(
        ChaosScenario.DUPLICATE, concurrency=2, iterations=4
    )

    assert cell.errors == 4
    assert cell.completed
    assert not cell.passed


def test_cancelled_workers_are_reported_not_hidden() -> None:
    """Abandoned workers must appear in the cell; completion describes the workload."""

    app = _App(status=200, delay=0.05)
    cell = InProcessCapacityExecutor(app).execute(
        ChaosScenario.CANCEL, concurrency=4, iterations=16
    )
    assert cell.cancellations >= 1
    assert type(cell.completed) is bool
    assert cell.errors == 0


def test_cancellation_profile_does_not_pass_without_an_interrupted_request() -> None:
    cell = InProcessCapacityExecutor(_App()).execute(
        ChaosScenario.CANCEL, concurrency=4, iterations=16
    )

    assert cell.completed
    assert cell.cancellations == 0
    assert not cell.passed


def test_profile_covers_only_the_measurable_scenarios() -> None:
    receipt = profile(_App(), concurrency=2, iterations=8)
    assert isinstance(receipt, CapacityReceipt)
    assert [cell.scenario for cell in receipt.cells] == [
        item.value for item in EXECUTABLE_SCENARIOS
    ]
    assert ChaosScenario.CANCEL not in EXECUTABLE_SCENARIOS
    assert receipt.passed


def test_render_is_canonical_json() -> None:
    document = render(profile(_App(), concurrency=1, iterations=4))
    assert '"cells"' in document
    assert " " not in document
    assert document.startswith("{") and document.endswith("}")


def test_explicit_request_set_is_used() -> None:
    app = _App()
    executor = InProcessCapacityExecutor(app, requests=(("GET", "/api/v1/health/live", b""),))
    cell = executor.execute(ChaosScenario.LEASE_EXPIRY, concurrency=2, iterations=6)
    assert cell.completed
    assert app.calls == 6


def test_executor_forwards_validated_headers_without_recording_them() -> None:
    received: list[Mapping[str, object]] = []

    async def app(
        scope: Mapping[str, object],
        receive: Callable[[], Awaitable[Mapping[str, object]]],
        send: Callable[[Mapping[str, object]], Awaitable[None]],
    ) -> None:
        del receive
        received.append(scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    token = "private-capacity-token"
    cell = InProcessCapacityExecutor(
        app,
        requests=(("GET", "/api/v1/policies", b""),),
        headers={"authorization": f"Bearer {token}"},
    ).execute(ChaosScenario.LEASE_EXPIRY, concurrency=1, iterations=1)

    assert cell.completed
    request_headers = received[0]["headers"]
    assert isinstance(request_headers, list)
    assert (b"authorization", f"Bearer {token}".encode("ascii")) in request_headers
    assert token not in render(CapacityReceipt((cell,)))


def test_capacity_cli_uses_environment_bearer_with_local_composition(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    token = "private-capacity-token"
    received_headers: list[object] = []

    async def app(
        scope: Mapping[str, object],
        receive: Callable[[], Awaitable[Mapping[str, object]]],
        send: Callable[[Mapping[str, object]], Awaitable[None]],
    ) -> None:
        del receive
        received_headers.append(scope["headers"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    settings = RuntimeSettings("127.0.0.1", 8080, "/tmp/securecode", "/tmp/securecode-tmp")
    monkeypatch.setenv("SECURECODE_CAPACITY_BEARER", token)
    monkeypatch.setattr(capacity_cli, "load_settings", lambda: settings)
    monkeypatch.setattr(capacity_cli, "build_local_app", lambda _settings: app)

    exit_code = capacity_cli.main(
        ["--path", "/api/v1/policies", "--concurrency", "1", "--iterations", "1"]
    )

    assert exit_code == 0
    assert len(received_headers) == len(EXECUTABLE_SCENARIOS)
    assert all(
        (b"authorization", f"Bearer {token}".encode("ascii")) in headers
        for headers in received_headers
        if isinstance(headers, list)
    )
    assert token not in capsys.readouterr().out


@pytest.mark.parametrize(
    "headers",
    [
        {"x-api-version": "2"},
        {"authorization": "Bearer bad\r\nInjected: yes"},
        {"authorization": "Bearer bad\x00token"},
        {"bad header": "value"},
        {"authorization": "ключ"},
    ],
)
def test_executor_rejects_unsafe_request_headers(headers: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="headers are invalid"):
        InProcessCapacityExecutor(_App(), headers=headers)


async def _cooperative_application(
    scope: Mapping[str, object],
    receive: Callable[[], Awaitable[Mapping[str, object]]],
    send: Callable[[Mapping[str, object]], Awaitable[None]],
) -> None:
    del scope
    await receive()
    await asyncio.sleep(0)
    await send({"type": "http.response.start", "status": 200})
    await send({"type": "http.response.body", "body": b"{}"})


def test_cancellation_interrupts_in_flight_requests_and_counts_them() -> None:
    cell = InProcessCapacityExecutor(_cooperative_application).execute(
        ChaosScenario.CANCEL, concurrency=4, iterations=8
    )

    assert cell.scenario == "cancellation"
    assert cell.cancellations == 2
    # A cancellation cell is terminal once every scheduled request has an
    # observed outcome.  The scenario passes because the interrupted requests
    # were observed and counted rather than silently lost.
    assert cell.completed
    assert cell.cancelled_requests == 2
    assert cell.unfinished_requests == 0
    assert cell.observed_requests == cell.planned_requests
    assert cell.result == "PASSED"
    assert cell.passed
    assert cell.live_leases == 0


def test_capacity_executor_can_run_from_an_async_server_path() -> None:
    async def invoke() -> str:
        return (
            InProcessCapacityExecutor(_cooperative_application)
            .execute(ChaosScenario.DUPLICATE, concurrency=2, iterations=4)
            .scenario
        )

    assert asyncio.run(invoke()) == "duplicate_delivery"
