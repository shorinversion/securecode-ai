"""P8.10 bounded capacity profiles over the real control plane.

The in-process executor drives the actual ASGI application. The explicit worker
lifecycle profile uses the authenticated connected protocol against a separately
running control plane and worker. Scenarios that need a real restart, storage or
network fault are left out of the receipt instead of being reported as passing.
"""

from __future__ import annotations

import asyncio
import json
import math
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Final, Protocol

from .capacity import CapacityCell, CapacityReceipt
from .chaos import ChaosScenario
from .resilience import ResiliencePlan, run

MAX_CONCURRENCY: Final = 64
MAX_ITERATIONS: Final = 5_000
MAX_DURATION_SECONDS: Final = 300.0
MIN_DURATION_SECONDS: Final = 0.01
MAX_SOAK_REQUESTS: Final = 1_000_000
SOAK_DRAIN_GRACE_SECONDS: Final = 5.0
MAX_LIFECYCLE_RUNS: Final = 32
MIN_POLL_INTERVAL_SECONDS: Final = 0.01
MAX_POLL_INTERVAL_SECONDS: Final = 5.0
LIVE_PATH: Final = "/api/v1/health/live"

# The in-process operator profile exposes read-only health checks and a bounded
# soak over the same ASGI endpoint. The connected worker lifecycle is opt-in and
# is driven separately by ``profile_worker_lifecycle``.
EXECUTABLE_SCENARIOS: Final = (
    ChaosScenario.HEALTH_LIVE,
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


@dataclass(frozen=True, slots=True)
class WorkerLifecycleRequest:
    """Source-free shorthand identity for one connected worker run."""

    tenant_id: str
    repository_id: str
    head_sha: str
    base_sha: str | None = None
    change_id: str | None = None
    operation: str = "SCAN"
    scm_provider: str | None = None

    def __post_init__(self) -> None:
        if (
            not _identifier(self.tenant_id)
            or not _identifier(self.repository_id)
            or not _commit(self.head_sha)
            or (self.base_sha is not None and not _commit(self.base_sha))
            or (self.change_id is not None and not _identifier(self.change_id))
            or type(self.operation) is not str
            or self.operation not in {"SCAN", "REPAIR"}
            or (
                self.scm_provider is not None
                and (
                    type(self.scm_provider) is not str
                    or self.scm_provider not in {"github", "gitlab"}
                )
            )
        ):
            raise ValueError("worker lifecycle request is invalid")

    def document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "tenant_id": self.tenant_id,
            "repository_id": self.repository_id,
            "head_sha": self.head_sha,
            "operation": self.operation,
        }
        if self.base_sha is not None:
            document["base_sha"] = self.base_sha
        if self.change_id is not None:
            document["change_id"] = self.change_id
        if self.scm_provider is not None:
            document["scm_provider"] = self.scm_provider
        return document


class WorkerLifecycleApi(Protocol):
    """Authenticated connected-control-plane transport used by the profile."""

    def submit(
        self, document: Mapping[str, object], *, idempotency_key: str
    ) -> Mapping[str, object]: ...

    def status(self, run_id: str) -> Mapping[str, object]: ...

    def cancel(
        self, run_id: str, *, if_match: str, idempotency_key: str
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class _WorkerRunReceipt:
    run_id: str
    disposition: str
    lifecycle: str
    head_sha: str
    outcome: str | None
    state_version: int

    @property
    def terminal(self) -> bool:
        return (
            self.outcome is not None
            or self.disposition in {"BLOCKED", "FAILED", "SUPERSEDED"}
            or self.lifecycle in {"COMPLETED", "SUPERSEDED"}
        )


@dataclass(slots=True)
class _LifecycleAttempt:
    terminal: bool
    cancelled: bool
    cancellation_accepted: bool
    error: bool
    queue_ms: int | None
    run_ms: int | None


_RECEIPT_TRIPLES: Final = frozenset(
    {
        ("PENDING", "ADMITTED", None),
        ("ADMITTED", "ADMITTED", None),
        ("BLOCKED", "COMPLETED", None),
        ("FAILED", "COMPLETED", None),
        ("COMPLETED", "COMPLETED", "PASS"),
        ("COMPLETED", "COMPLETED", "FAIL"),
        ("COMPLETED", "COMPLETED", "INDETERMINATE"),
        ("COMPLETED", "COMPLETED", "CANCELLED"),
        ("SUPERSEDED", "SUPERSEDED", "SUPERSEDED"),
    }
)


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

    __slots__ = (
        "_app",
        "_headers",
        "_requests",
        "_duration_seconds",
        "_max_requests",
    )

    def __init__(
        self,
        app: object,
        *,
        requests: Sequence[tuple[str, str, bytes]] | None = None,
        headers: Mapping[str, str] | None = None,
        duration_seconds: float | None = None,
        max_requests: int | None = None,
    ) -> None:
        if not callable(app) or (headers is not None and not isinstance(headers, Mapping)):
            raise TypeError("capacity executor needs a callable application")
        if duration_seconds is not None and (
            type(duration_seconds) not in (int, float)
            or isinstance(duration_seconds, bool)
            or not math.isfinite(float(duration_seconds))
            or not MIN_DURATION_SECONDS <= float(duration_seconds) <= MAX_DURATION_SECONDS
        ):
            raise ValueError("capacity duration is invalid")
        if max_requests is not None and (
            type(max_requests) is not int
            or not 1 <= max_requests <= MAX_SOAK_REQUESTS
        ):
            raise ValueError("capacity request limit is invalid")
        request_headers = dict(headers or {})
        if len(request_headers) > 32:
            raise ValueError("capacity request headers are invalid")
        encoded_headers: list[tuple[bytes, bytes]] = []
        seen_names: set[str] = {"x-api-version"}
        for name, value in request_headers.items():
            if (
                type(name) is not str
                or type(value) is not str
                or not name.isascii()
                or not 1 <= len(name) <= 128
                or any(not (character.isalnum() or character == "-") for character in name)
                or not value.isascii()
                or not 1 <= len(value) <= 8192
                or any(not 32 <= ord(character) <= 126 for character in value)
            ):
                raise ValueError("capacity request headers are invalid")
            normalized = name.casefold()
            if normalized in seen_names:
                raise ValueError("capacity request headers are invalid")
            seen_names.add(normalized)
            encoded_headers.append((normalized.encode("ascii"), value.encode("ascii")))
        if sum(len(name) + len(value) for name, value in encoded_headers) > 16_384:
            raise ValueError("capacity request headers are invalid")
        self._app = app
        self._duration_seconds = (
            None if duration_seconds is None else float(duration_seconds)
        )
        self._max_requests = max_requests
        self._requests = (
            tuple(requests)
            if requests is not None
            else (("GET", LIVE_PATH, b""),)
        )
        if not self._requests:
            raise ValueError("capacity requests are invalid")
        self._headers = tuple(encoded_headers)

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
            or (scenario is ChaosScenario.SOAK and self._duration_seconds is None)
        ):
            raise ValueError("capacity execution request is invalid")
        measurement = self._measure(scenario, concurrency=concurrency, iterations=iterations)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(measurement)

        # asyncio prohibits driving a second loop in a thread that already owns
        # one. Capacity profiling is synchronous by design, so move its private
        # loop to one bounded worker when an API handler invokes it.
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="securecode-capacity") as pool:
            return pool.submit(asyncio.run, measurement).result()

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
        request_limit = (
            self._max_requests if scenario is ChaosScenario.SOAK else iterations
        )
        if request_limit is None:
            request_limit = MAX_SOAK_REQUESTS
        initial_requests = min(concurrency, request_limit)
        initial_count = initial_requests if scenario is ChaosScenario.SOAK else request_limit
        for index in range(initial_count):
            pending.put_nowait((index, time.monotonic()))
        next_index = initial_requests if scenario is ChaosScenario.SOAK else request_limit

        stop_event = asyncio.Event()
        deadline_reached = False

        async def one_request() -> _Sample | None:
            try:
                index, enqueued = pending.get_nowait()
            except asyncio.QueueEmpty:
                return None
            queue_ms = _to_millis(time.monotonic() - enqueued)
            method, path, body = self._requests[index % len(self._requests)]
            return await self._call(method, path, body, queue_ms=queue_ms)

        async def worker() -> tuple[list[_Sample], int]:
            """Collect samples; a scenario cancellation is counted, not swallowed."""

            nonlocal next_index
            collected: list[_Sample] = []
            cancelled = 0
            try:
                while not stop_event.is_set():
                    sample = await one_request()
                    if sample is None:
                        break
                    collected.append(sample)
                    if sample.cancelled:
                        cancelled += 1
                        if scenario is ChaosScenario.CANCEL or stop_event.is_set():
                            break
                    if (
                        scenario is ChaosScenario.SOAK
                        and not stop_event.is_set()
                        and next_index < request_limit
                    ):
                        pending.put_nowait((next_index, time.monotonic()))
                        next_index += 1
            except asyncio.CancelledError:
                # this worker was cancelled on purpose by the scenario: its
                # observations are reported and the cancellation is counted
                cancelled += 1
            return collected, cancelled

        tasks = [asyncio.create_task(worker()) for _ in range(concurrency)]
        cancelled_workers = 0
        deadline_task: asyncio.Task[None] | None = None

        async def stop_at_deadline() -> None:
            nonlocal deadline_reached
            assert self._duration_seconds is not None
            await asyncio.sleep(self._duration_seconds)
            deadline_reached = True
            stop_event.set()
            await asyncio.sleep(SOAK_DRAIN_GRACE_SECONDS)
            for task in tasks:
                if not task.done():
                    task.cancel()

        if scenario is ChaosScenario.SOAK:
            deadline_task = asyncio.create_task(stop_at_deadline())
        if scenario is ChaosScenario.CANCEL and len(tasks) > 1:
            # Let every worker enter the ASGI request before interrupting some of
            # them. Cancelling before the first scheduling point only measures
            # task startup and misses cancellation propagation through a request.
            await asyncio.sleep(0)
            # Always leave one worker running so the interrupted workload still
            # produces observations and an incomplete cell cannot pass.
            active = [task for task in tasks if not task.done()]
            requested_cancellations = max(1, len(tasks) // 2)
            for task in active[-requested_cancellations:]:
                task.cancel()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        if deadline_task is not None:
            deadline_task.cancel()
            await asyncio.gather(deadline_task, return_exceptions=True)
        elapsed = time.monotonic() - started
        for entry in results:
            # A task cancelled before its coroutine receives its first time slice
            # never reaches ``worker``'s CancelledError handler. Gather returns
            # that cancellation directly, and it still represents a deliberately
            # interrupted worker that must appear in the receipt.
            if isinstance(entry, asyncio.CancelledError):
                cancelled_workers += 1
                continue
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
        errors = sum(1 for item in samples if not item.cancelled and not 200 <= item.status < 300)
        answered = [item for item in samples if not item.cancelled]
        scheduled_requests = next_index
        observed_requests = len(samples)
        cancelled_requests = sum(item.cancelled for item in samples)
        unfinished_requests = max(0, scheduled_requests - observed_requests)
        throughput = len(answered) if elapsed <= 0 else int(len(answered) / elapsed)
        return CapacityCell(
            scenario=scenario.value,
            # Cancellation is terminal only when every scheduled request has an
            # observed outcome; an abandoned queue item keeps the cell open.
            completed=(
                observed_requests == scheduled_requests
                and (
                    scenario is ChaosScenario.CANCEL
                    or (cancelled_workers == 0 and cancelled_requests == 0)
                )
            ),
            throughput=throughput,
            queue_p50=_percentile(queue_waits, 0.5),
            queue_p95=_percentile(queue_waits, 0.95),
            run_p50=_percentile(run_latencies, 0.5),
            run_p95=_percentile(run_latencies, 0.95),
            errors=errors,
            cancellations=cancelled_workers,
            live_leases=0,
            planned_requests=scheduled_requests,
            observed_requests=observed_requests,
            completed_requests=len(answered),
            unfinished_requests=unfinished_requests,
            cancelled_requests=cancelled_requests,
            deadline_reached=deadline_reached,
            request_cap_reached=scheduled_requests >= request_limit,
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
        failed = False
        try:
            await self._app(
                {
                    "type": "http",
                    "method": method,
                    "path": path,
                    "headers": [(b"x-api-version", b"1"), *self._headers],
                },
                receive,
                send,
            )
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            # Runtime/application failures remain observed requests and become
            # capacity errors through the non-2xx sentinel status.
            failed = True
        run_ms = _to_millis(time.monotonic() - request_started)
        status = 0
        for message in sent:
            if message.get("type") != "http.response.start":
                continue
            raw_status = message.get("status")
            if type(raw_status) is int:
                status = raw_status
            break
        if failed:
            status = 0
        return _Sample(queue_ms=queue_ms, run_ms=run_ms, status=status, cancelled=cancelled)


class WorkerLifecycleExecutor:
    """Exercise submit, exact-run polling and cancellation on a real worker path."""

    __slots__ = ("_api", "_request", "_runs", "_duration", "_poll_interval")

    def __init__(
        self,
        api: WorkerLifecycleApi,
        request: WorkerLifecycleRequest,
        *,
        runs: int,
        duration_seconds: float,
        poll_interval_seconds: float,
    ) -> None:
        if (
            not callable(getattr(api, "submit", None))
            or not callable(getattr(api, "status", None))
            or not callable(getattr(api, "cancel", None))
            or type(request) is not WorkerLifecycleRequest
            or type(runs) is not int
            or not 1 <= runs <= MAX_LIFECYCLE_RUNS
            or type(duration_seconds) not in (int, float)
            or isinstance(duration_seconds, bool)
            or not math.isfinite(float(duration_seconds))
            or not MIN_DURATION_SECONDS <= float(duration_seconds) <= MAX_DURATION_SECONDS
            or type(poll_interval_seconds) not in (int, float)
            or isinstance(poll_interval_seconds, bool)
            or not math.isfinite(float(poll_interval_seconds))
            or not MIN_POLL_INTERVAL_SECONDS
            <= float(poll_interval_seconds)
            <= MAX_POLL_INTERVAL_SECONDS
        ):
            raise ValueError("worker lifecycle profile is invalid")
        self._api = api
        self._request = request
        self._runs = runs
        self._duration = float(duration_seconds)
        self._poll_interval = float(poll_interval_seconds)

    def execute(
        self,
        scenario: ChaosScenario,
        *,
        concurrency: int,
        iterations: int,
    ) -> CapacityCell:
        if (
            scenario is not ChaosScenario.WORKER_LIFECYCLE
            or type(concurrency) is not int
            or concurrency != 1
            or type(iterations) is not int
            or iterations != self._runs
        ):
            raise ValueError("worker lifecycle execution request is invalid")
        return self._measure()

    def _measure(self) -> CapacityCell:
        started = time.monotonic()
        deadline = started + self._duration
        attempts = 0
        terminal_runs = 0
        cancelled_runs = 0
        accepted_cancellations = 0
        errors = 0
        queue_latencies: list[int] = []
        run_latencies: list[int] = []
        while attempts < self._runs and time.monotonic() < deadline:
            attempt = attempts
            attempts += 1
            result = self._run_one(attempt, deadline)
            if result.terminal:
                terminal_runs += 1
            if result.cancelled:
                cancelled_runs += 1
            if result.cancellation_accepted:
                accepted_cancellations += 1
            if result.error:
                errors += 1
            if result.queue_ms is not None:
                queue_latencies.append(result.queue_ms)
            if result.run_ms is not None:
                run_latencies.append(result.run_ms)

        elapsed = max(time.monotonic() - started, 0.001)
        unfinished = max(0, self._runs - terminal_runs)
        throughput = 0 if terminal_runs == 0 else max(1, int(terminal_runs / elapsed))
        return CapacityCell(
            scenario=ChaosScenario.WORKER_LIFECYCLE.value,
            completed=terminal_runs == self._runs,
            throughput=throughput,
            queue_p50=_percentile(queue_latencies, 0.5),
            queue_p95=_percentile(queue_latencies, 0.95),
            run_p50=_percentile(run_latencies, 0.5),
            run_p95=_percentile(run_latencies, 0.95),
            errors=errors,
            cancellations=accepted_cancellations,
            # A nonzero value is an unaccounted-live sentinel when a terminal
            # receipt was not observed; this profile does not invent lease data.
            live_leases=0 if unfinished == 0 else 1,
            planned_requests=self._runs,
            observed_requests=terminal_runs,
            completed_requests=terminal_runs,
            unfinished_requests=unfinished,
            cancelled_requests=cancelled_runs,
            deadline_reached=time.monotonic() >= deadline,
            request_cap_reached=attempts >= self._runs,
        )

    def _run_one(self, attempt: int, deadline: float) -> _LifecycleAttempt:
        started = time.monotonic()
        try:
            submitted = _read_worker_receipt(
                self._api.submit(
                    self._request.document(),
                    idempotency_key=_operation_key("submit", attempt),
                )
            )
            _require_run(submitted, self._request.head_sha)
            if submitted.terminal:
                return _LifecycleAttempt(
                    terminal=True,
                    cancelled=False,
                    cancellation_accepted=False,
                    error=True,
                    queue_ms=None,
                    run_ms=_to_millis(time.monotonic() - started),
                )
            current = _read_worker_receipt(self._api.status(submitted.run_id))
            _require_run(current, self._request.head_sha, run_id=submitted.run_id)
            if current.state_version < submitted.state_version:
                raise ValueError("worker receipt version regressed")
            if current.terminal:
                return _LifecycleAttempt(
                    terminal=True,
                    cancelled=False,
                    cancellation_accepted=False,
                    error=True,
                    queue_ms=None,
                    run_ms=_to_millis(time.monotonic() - started),
                )
            if time.monotonic() >= deadline or current.state_version < 1:
                return _LifecycleAttempt(
                    terminal=False,
                    cancelled=False,
                    cancellation_accepted=False,
                    error=False,
                    queue_ms=None,
                    run_ms=None,
                )
            cancellation_started = time.monotonic()
            cancelled = _read_worker_receipt(
                self._api.cancel(
                    current.run_id,
                    if_match=str(current.state_version),
                    idempotency_key=_operation_key("cancel", attempt),
                )
            )
            _require_run(cancelled, self._request.head_sha, run_id=current.run_id)
            if (
                cancelled.state_version <= current.state_version
                and cancelled.outcome != "CANCELLED"
            ):
                raise ValueError("worker cancellation was not applied")
            queue_ms = _to_millis(time.monotonic() - cancellation_started)
            accepted = True
            final = self._poll_terminal(cancelled, deadline)
            if final is None:
                return _LifecycleAttempt(
                    terminal=False,
                    cancelled=False,
                    cancellation_accepted=accepted,
                    error=False,
                    queue_ms=queue_ms,
                    run_ms=None,
                )
            run_ms = _to_millis(time.monotonic() - started)
            is_cancelled = final.outcome == "CANCELLED" and final.lifecycle == "COMPLETED"
            return _LifecycleAttempt(
                terminal=True,
                cancelled=is_cancelled,
                cancellation_accepted=accepted,
                error=not is_cancelled,
                queue_ms=queue_ms,
                run_ms=run_ms,
            )
        except Exception:
            return _LifecycleAttempt(
                terminal=False,
                cancelled=False,
                cancellation_accepted=False,
                error=True,
                queue_ms=None,
                run_ms=None,
            )

    def _poll_terminal(
        self, current: _WorkerRunReceipt, deadline: float
    ) -> _WorkerRunReceipt | None:
        run_id = current.run_id
        while not current.terminal:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            time.sleep(min(self._poll_interval, remaining))
            previous_version = current.state_version
            current = _read_worker_receipt(self._api.status(run_id))
            _require_run(current, self._request.head_sha, run_id=run_id)
            if current.state_version < previous_version:
                raise ValueError("worker receipt version regressed")
        return current


def profile_worker_lifecycle(
    api: WorkerLifecycleApi,
    request: WorkerLifecycleRequest,
    *,
    runs: int = 1,
    duration_seconds: float = 30.0,
    poll_interval_seconds: float = 0.5,
) -> CapacityReceipt:
    """Run a bounded authenticated worker lifecycle against a connected server."""

    executor = WorkerLifecycleExecutor(
        api,
        request,
        runs=runs,
        duration_seconds=duration_seconds,
        poll_interval_seconds=poll_interval_seconds,
    )
    plan = ResiliencePlan(
        concurrency=1,
        iterations=runs,
        scenarios=(ChaosScenario.WORKER_LIFECYCLE,),
    )
    return run(plan, executor)


def _read_worker_receipt(document: Mapping[str, object]) -> _WorkerRunReceipt:
    if not isinstance(document, Mapping):
        raise ValueError("worker receipt is invalid")
    run_id = document.get("run_id")
    state = document.get("state")
    disposition = document.get("disposition", state)
    lifecycle = document.get("lifecycle", state)
    head_sha = document.get("head_sha")
    outcome = document.get("outcome")
    state_version = document.get("state_version", document.get("version"))
    if (
        not isinstance(run_id, str)
        or not _identifier(run_id)
        or not isinstance(disposition, str)
        or not isinstance(lifecycle, str)
        or not isinstance(head_sha, str)
        or not _commit(head_sha)
        or (outcome is not None and not isinstance(outcome, str))
        or type(state_version) is not int
        or state_version < 0
        or (disposition, lifecycle, outcome) not in _RECEIPT_TRIPLES
    ):
        raise ValueError("worker receipt is invalid")
    return _WorkerRunReceipt(
        run_id=run_id,
        disposition=disposition,
        lifecycle=lifecycle,
        head_sha=head_sha,
        outcome=outcome,
        state_version=state_version,
    )


def _require_run(
    receipt: _WorkerRunReceipt,
    head_sha: str,
    *,
    run_id: str | None = None,
) -> None:
    if receipt.head_sha != head_sha or (run_id is not None and receipt.run_id != run_id):
        raise ValueError("worker receipt identity changed")


def _operation_key(operation: str, attempt: int) -> str:
    if operation not in {"submit", "cancel"} or type(attempt) is not int or attempt < 0:
        raise ValueError("worker operation key is invalid")
    return f"capacity-{operation}-{attempt}-{secrets.token_hex(12)}"


def _identifier(value: object) -> bool:
    return (
        type(value) is str
        and value.isascii()
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


def _commit(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def profile(
    app: object,
    *,
    concurrency: int = 8,
    iterations: int = 32,
    scenarios: Sequence[ChaosScenario] = EXECUTABLE_SCENARIOS,
    requests: Sequence[tuple[str, str, bytes]] | None = None,
    duration_seconds: float | None = None,
    max_requests: int | None = None,
) -> CapacityReceipt:
    """Run the bounded plan over the executable scenarios and return the receipt."""

    plan = ResiliencePlan(
        concurrency=concurrency,
        iterations=iterations,
        scenarios=tuple(scenarios),
    )
    return run(
        plan,
        InProcessCapacityExecutor(
            app,
            requests=requests,
            duration_seconds=duration_seconds,
            max_requests=max_requests,
        ),
    )


def render(receipt: CapacityReceipt) -> str:
    """Render the measured receipt as canonical JSON."""

    return json.dumps(receipt.metadata(), ensure_ascii=True, sort_keys=True, separators=(",", ":"))


__all__ = [
    "EXECUTABLE_SCENARIOS",
    "InProcessCapacityExecutor",
    "MAX_DURATION_SECONDS",
    "MIN_DURATION_SECONDS",
    "MAX_SOAK_REQUESTS",
    "SOAK_DRAIN_GRACE_SECONDS",
    "MAX_LIFECYCLE_RUNS",
    "MIN_POLL_INTERVAL_SECONDS",
    "MAX_POLL_INTERVAL_SECONDS",
    "WorkerLifecycleApi",
    "WorkerLifecycleExecutor",
    "WorkerLifecycleRequest",
    "profile",
    "profile_worker_lifecycle",
    "render",
]
