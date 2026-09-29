"""Connected, cancellation-aware worker service application."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import replace
from functools import partial
from pathlib import Path
from threading import Event as ThreadingEvent
from threading import Thread
from typing import TextIO, TypeVar
from uuid import uuid4

from securecode_ai.adapters.remote_provider_budget import RemoteProviderCostReceipt
from securecode_ai.contracts import ModelUsage
from securecode_ai.core.resource_governor import (
    PerRunResourceEnforcer,
    ResourceGovernorError,
    ResourceGovernorErrorCode,
    ResourceUsage,
)

from .control_plane import (
    _MAX_SESSION_VERSION,
    ControlPlaneClient,
    ControlPlaneRejected,
    LeaseLost,
    NoWork,
    RetryableControlPlaneError,
)
from .execution import (
    ExecutionControl,
    ProductCancelled,
    ProductExecutionError,
    ProductExecutor,
    ProductSuperseded,
    ResourceLimitExceeded,
    WorkerExecutionResult,
)
from .liveness import heartbeat_path
from .liveness import touch as touch_liveness
from .protocol import WorkerCommand, WorkerEvent, WorkerJob
from .runtime_config import RuntimeSettings
from .service_state import ActiveSession as _ActiveSession
from .service_state import Backoff as _Backoff
from .service_state import await_task_completion as _await_task_completion
from .usage import WorkerResourceUsage, WorkerUsageMeter

_T = TypeVar("_T")
_HELP = """usage: securecode-worker-service

Run the connected worker service using SECURECODE_WORKER_* environment values.
"""


def _next_claim_attempt(value: int) -> int:
    """Return a positive claim attempt within the control-plane contract."""

    return value % _MAX_SESSION_VERSION + 1


def _lease_deadline(active: _ActiveSession) -> Callable[[], float]:
    return lambda: active.last_heartbeat + active.job.lease_seconds - 0.5


def _core_usage(usage: WorkerResourceUsage) -> ResourceUsage:
    return ResourceUsage(
        tokens=usage.tokens,
        cost_microunits=usage.cost_microunits,
        cpu_ms=usage.cpu_ms,
        peak_memory_bytes=usage.peak_memory_bytes,
        wall_ms=usage.wall_ms,
    )


def _bounded_completion_usage(
    active: _ActiveSession,
    usage: WorkerResourceUsage | None,
) -> WorkerResourceUsage | None:
    """Return a settlement that cannot exceed the admission reservation.

    A telemetry failure must still reach a terminal control-plane state.  The
    reservation is the only trusted upper bound available in that case, and
    it is also the safe charge when the meter observes an over-budget run.
    """

    budget = active.job.resource_budget
    if budget is None:
        return usage
    reserved = budget.reserved
    if usage is None or any(
        actual > limit
        for actual, limit in zip(
            (
                usage.tokens,
                usage.cost_microunits,
                usage.cpu_ms,
                usage.peak_memory_bytes,
                usage.wall_ms,
            ),
            (
                reserved.tokens,
                reserved.cost_microunits,
                reserved.cpu_ms,
                reserved.peak_memory_bytes,
                reserved.wall_ms,
            ),
            strict=True,
        )
    ):
        return reserved
    return usage


def _terminal_event_kind(command: WorkerCommand) -> str:
    return "RUN_SUPERSEDED" if command is WorkerCommand.SUPERSEDE else "RUN_CANCELLED"


def _request_resource_stop(control: ExecutionControl, exceeded: ThreadingEvent) -> None:
    exceeded.set()

    def request() -> None:
        with suppress(Exception):
            control.request(WorkerCommand.CANCEL)

    Thread(target=request, name="securecode-worker-resource-stop", daemon=True).start()


class WorkerCompletionUnconfirmed(RuntimeError):
    """A requested one-shot run did not confirm a terminal control-plane state."""


class WorkerService:
    """Claim exact jobs, execute the shared product, and publish bounded results."""

    def __init__(
        self,
        *,
        client: ControlPlaneClient,
        executor: ProductExecutor,
        settings: RuntimeSettings,
        stopping: asyncio.Event,
    ) -> None:
        self._client = client
        self._executor = executor
        self._settings = settings
        self._stopping = stopping

    async def run(self) -> None:
        # A claim keeps its idempotency identity across transport retries. A
        # fresh process gets a fresh identity, so it cannot replay an old
        # session after restarting with the same worker ID.
        claim_attempt = _next_claim_attempt(uuid4().int)
        # Keep the original request timestamp across transport retries for the
        # same idempotency key. The control plane may have granted the lease
        # before a delayed or replayed response reaches this process.
        claim_started_at = time.monotonic()
        backoff = _Backoff(self._settings.poll_seconds, self._settings.max_backoff_seconds)
        while not self._stopping.is_set():
            try:
                job = await asyncio.to_thread(
                    self._client.open_session,
                    attempt=claim_attempt,
                    requested_run_id=self._settings.requested_run_id,
                )
            except NoWork:
                claim_attempt = _next_claim_attempt(claim_attempt)
                backoff.reset()
                await self._wait(self._settings.poll_seconds)
                claim_started_at = time.monotonic()
                continue
            except RetryableControlPlaneError:
                await self._wait(backoff.next_delay())
                continue
            except ControlPlaneRejected:
                raise
            if self._stopping.is_set():
                return
            claim_attempt = _next_claim_attempt(claim_attempt)
            backoff.reset()
            terminal_confirmed = await self._process(job, lease_started_at=claim_started_at)
            # The next loop iteration uses the next idempotency key.  Start a
            # fresh lease clock only after this job has finished; transport
            # retries above still retain the original claim timestamp.
            claim_started_at = time.monotonic()
            if self._settings.requested_run_id is not None:
                if not terminal_confirmed:
                    raise WorkerCompletionUnconfirmed()
                return

    async def _process(self, job: WorkerJob, *, lease_started_at: float) -> bool:
        active = _ActiveSession(
            job,
            sequence=job.next_event_sequence - 1,
            last_heartbeat=lease_started_at,
        )
        if job.command is not WorkerCommand.CONTINUE:
            return await self._finish_command(active, job.command)
        try:
            await self._append_event(active, "RUN_STARTED")
        except (LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
            return False
        if active.job.command is not WorkerCommand.CONTINUE:
            return await self._finish_command(active, active.job.command)

        monitor_stop = asyncio.Event()
        command_seen = asyncio.Event()
        lease_lost = asyncio.Event()
        monitor_failed = asyncio.Event()
        resource_monitor_stop = asyncio.Event()
        control = ExecutionControl()
        monitor: asyncio.Task[None] | None = None
        execution: WorkerExecutionResult | None = None
        failure: ProductExecutionError | None = None
        resource_usage: WorkerResourceUsage | None = None
        execution_started = False
        resource_limit_exceeded = ThreadingEvent()
        resource_monitor_failed = ThreadingEvent()
        try:
            meter: WorkerUsageMeter | None = WorkerUsageMeter(
                run_id=active.job.run_id,
                execution_identity_hash=active.job.execution_identity.execution_identity_hash,
            )
        except Exception:
            meter = None
        resource_enforcer: PerRunResourceEnforcer | None = None
        resource_monitor: asyncio.Task[None] | None = None
        if meter is not None and active.job.resource_budget is not None:
            resource_enforcer = PerRunResourceEnforcer(
                _core_usage(active.job.resource_budget.reserved),
                lambda: _request_resource_stop(
                    control,
                    resource_limit_exceeded,
                ),
            )
            resource_monitor = asyncio.create_task(
                self._resource_monitor(
                    meter,
                    resource_enforcer,
                    resource_monitor_stop,
                    control,
                    resource_limit_exceeded,
                    resource_monitor_failed,
                )
            )
        elif active.job.resource_budget is None:
            failure = ProductExecutionError("worker resource budget unavailable")

        monitor = asyncio.create_task(
            self._monitor(
                active,
                monitor_stop,
                command_seen,
                lease_lost,
                monitor_failed,
                control,
            )
        )
        resource_usage_meter_finished = False

        def observe_model_usage(usage: ModelUsage) -> None:
            if meter is None or resource_enforcer is None:
                raise ProductExecutionError("worker resource enforcement unavailable")
            try:
                meter.observe_model_usage(usage)
                resource_enforcer.observe(_core_usage(meter.snapshot()))
            except ResourceGovernorError as error:
                if error.code is ResourceGovernorErrorCode.QUOTA_EXCEEDED:
                    resource_limit_exceeded.set()
                    raise ResourceLimitExceeded("worker resource budget exceeded") from None
                resource_monitor_failed.set()
                _request_resource_stop(control, resource_monitor_failed)
                raise ProductExecutionError("worker resource enforcement failed") from None
            except Exception:
                resource_monitor_failed.set()
                _request_resource_stop(control, resource_monitor_failed)
                raise ProductExecutionError("worker resource telemetry failed") from None

        def observe_remote_cost(receipt: RemoteProviderCostReceipt) -> None:
            if meter is None or resource_enforcer is None:
                raise ProductExecutionError("worker resource enforcement unavailable")
            try:
                meter.observe_remote_cost(receipt)
                resource_enforcer.observe(_core_usage(meter.snapshot()))
            except ResourceGovernorError as error:
                if error.code is ResourceGovernorErrorCode.QUOTA_EXCEEDED:
                    resource_limit_exceeded.set()
                    raise ResourceLimitExceeded("worker resource budget exceeded") from None
                resource_monitor_failed.set()
                _request_resource_stop(control, resource_monitor_failed)
                raise ProductExecutionError("worker resource enforcement failed") from None
            except Exception:
                resource_monitor_failed.set()
                _request_resource_stop(control, resource_monitor_failed)
                raise ProductExecutionError("worker remote cost telemetry failed") from None

        if resource_enforcer is None:

            async def reject_unmetered_execution() -> WorkerExecutionResult:
                raise ProductExecutionError("worker resource enforcement unavailable")

            execution_task = asyncio.create_task(reject_unmetered_execution())
        else:

            def execute_product() -> WorkerExecutionResult:
                nonlocal execution_started
                execution_started = True
                return self._executor.execute(
                    active.job,
                    control=control,
                    usage_observer=observe_model_usage,
                    cost_observer=observe_remote_cost,
                )

            execution_task = asyncio.create_task(asyncio.to_thread(execute_product))
        try:
            execution = await asyncio.shield(execution_task)
        except asyncio.CancelledError:
            # Cancelling asyncio.to_thread does not stop its OS thread. Signal the
            # cooperative execution control, then wait for the executor to leave
            # its bounded provider calls before settling and releasing the lease.
            self._stopping.set()
            control.request(WorkerCommand.CANCEL)
            command_seen.set()
            try:
                execution = await _await_task_completion(execution_task)
            except ProductExecutionError as error:
                failure = error
            except asyncio.CancelledError:
                failure = ProductCancelled("product execution was cancelled")
            except Exception:
                failure = ProductExecutionError("product execution failed")
        except ProductExecutionError as error:
            failure = error
        except Exception:
            # Unexpected executor errors must settle as INDETERMINATE rather
            # than escaping the worker loop and leaving the run non-terminal.
            failure = ProductExecutionError("product execution failed")

        if execution is not None and meter is not None:
            try:
                resource_usage = meter.snapshot(execution)
                if resource_enforcer is None:
                    raise ProductExecutionError("worker resource enforcement unavailable")
                resource_enforcer.observe(_core_usage(resource_usage))
            except Exception:
                resource_monitor_failed.set()
                failure = failure or ProductExecutionError(
                    "worker resource telemetry is unavailable"
                )
        if execution is None or failure is not None:
            resource_monitor_stop.set()
            if resource_monitor is not None:
                try:
                    await _await_task_completion(resource_monitor)
                except Exception:
                    resource_monitor_failed.set()
            if meter is not None:
                try:
                    resource_usage = meter.finish(execution if execution is not None else None)
                    resource_usage_meter_finished = True
                except Exception:
                    resource_usage = None
                    failure = failure or ProductExecutionError(
                        "worker resource telemetry is unavailable"
                    )
            if resource_enforcer is not None and resource_usage is not None:
                try:
                    resource_enforcer.observe(_core_usage(resource_usage))
                except ResourceGovernorError as error:
                    if error.code is ResourceGovernorErrorCode.QUOTA_EXCEEDED:
                        resource_limit_exceeded.set()
                    else:
                        resource_monitor_failed.set()
                except Exception:
                    resource_monitor_failed.set()
        else:
            if meter is None or resource_enforcer is None:
                failure = ProductExecutionError("worker resource enforcement unavailable")
            else:
                resource_monitor_stop.set()
                if resource_monitor is not None:
                    try:
                        await _await_task_completion(resource_monitor)
                    except Exception:
                        resource_monitor_failed.set()
                if not resource_monitor_failed.is_set():
                    try:
                        resource_usage = meter.finish(execution)
                        resource_usage_meter_finished = True
                        resource_enforcer.observe(_core_usage(resource_usage))
                    except ResourceGovernorError as error:
                        if error.code is ResourceGovernorErrorCode.QUOTA_EXCEEDED:
                            resource_limit_exceeded.set()
                        else:
                            resource_monitor_failed.set()
                    except Exception:
                        resource_monitor_failed.set()
                if resource_monitor_failed.is_set():
                    failure = ProductExecutionError("worker resource telemetry is unavailable")
            monitor_stop.set()
            try:
                await _await_task_completion(monitor)
            except Exception:
                monitor_failed.set()
                failure = failure or ProductExecutionError("worker monitoring failed")

        if resource_limit_exceeded.is_set():
            if execution is not None:
                with suppress(Exception):
                    execution.cancel()
            return await self._finish_failure(
                active,
                ResourceLimitExceeded("worker resource budget exceeded"),
                resource_usage,
                execution_started=execution_started,
            )
        if resource_monitor_failed.is_set():
            if execution is not None:
                with suppress(Exception):
                    execution.cancel()
            return await self._finish_failure(
                active,
                ProductExecutionError("worker resource monitoring failed"),
                resource_usage,
                execution_started=execution_started,
            )
        if monitor_failed.is_set():
            if execution is not None:
                with suppress(Exception):
                    execution.cancel()
            return await self._finish_failure(
                active,
                ProductExecutionError("worker monitoring failed"),
                resource_usage,
                execution_started=execution_started,
            )
        if lease_lost.is_set():
            if execution is not None:
                with suppress(Exception):
                    execution.cancel()
            return False
        if command_seen.is_set() or self._stopping.is_set():
            if execution is not None:
                with suppress(Exception):
                    execution.cancel()
            command = (
                active.job.command
                if active.job.command is not WorkerCommand.CONTINUE
                else WorkerCommand.CANCEL
            )
            return await self._finish_command(
                active,
                command,
                resource_usage=resource_usage,
                execution_started=execution_started,
            )
        if resource_usage is None:
            if execution is not None:
                with suppress(Exception):
                    execution.cancel()
            return await self._finish_failure(
                active,
                failure or ProductExecutionError("resource telemetry is unavailable"),
                None,
                execution_started=execution_started,
            )
        if failure is not None:
            return await self._finish_failure(
                active,
                failure,
                resource_usage,
                execution_started=execution_started,
            )
        if execution is None:
            return await self._finish_failure(
                active,
                ProductExecutionError("product execution failed"),
                resource_usage,
                execution_started=execution_started,
            )

        try:
            active.heartbeat_attempt += 1
            heartbeat_attempt = active.heartbeat_attempt
            update = await self._retry_call(
                active,
                lambda: self._client.heartbeat(active.job, attempt=heartbeat_attempt),
                apply=lambda value: active.apply(
                    version=value.version,
                    command=value.command,
                ),
                lease_renewal=True,
            )
            if update.command is not WorkerCommand.CONTINUE:
                with suppress(Exception):
                    execution.cancel()
                return await self._finish_command(
                    active,
                    update.command,
                    resource_usage=resource_usage,
                    execution_started=execution_started,
                )
            requested_command = self._requested_command(active, command_seen)
            if requested_command is not None:
                with suppress(Exception):
                    execution.cancel()
                return await self._finish_command(
                    active,
                    requested_command,
                    resource_usage=resource_usage,
                    execution_started=execution_started,
                )
            for artifact_index, artifact in enumerate(execution.artifacts):
                if artifact_index:
                    active.heartbeat_attempt += 1
                    artifact_heartbeat = await self._retry_call(
                        active,
                        lambda: self._client.heartbeat(
                            active.job,
                            attempt=active.heartbeat_attempt,
                        ),
                        apply=lambda value: active.apply(
                            version=value.version,
                            command=value.command,
                        ),
                        lease_renewal=True,
                    )
                    if artifact_heartbeat.command is not WorkerCommand.CONTINUE:
                        with suppress(Exception):
                            execution.cancel()
                        return await self._finish_command(
                            active,
                            artifact_heartbeat.command,
                            resource_usage=resource_usage,
                            execution_started=execution_started,
                        )
                try:
                    execution.require_publication()
                except Exception:
                    execution.cancel()
                    return await self._finish_failure(
                        active,
                        ProductSuperseded("product revision was superseded"),
                        resource_usage,
                        execution_started=execution_started,
                    )

                def artifact_deadline() -> float:
                    return active.last_heartbeat + active.job.lease_seconds - 0.5

                update = await self._retry_call(
                    active,
                    partial(
                        self._client.publish_artifact,
                        active.job,
                        artifact,
                        deadline=artifact_deadline,
                    ),
                    apply=lambda value: active.apply(
                        version=value.version,
                        command=value.command,
                    ),
                    deadline=artifact_deadline,
                )
                try:
                    resource_usage = meter.snapshot(execution) if meter is not None else None
                    if resource_usage is None or resource_enforcer is None:
                        raise ProductExecutionError("worker resource enforcement unavailable")
                    resource_enforcer.observe(_core_usage(resource_usage))
                except ResourceGovernorError as error:
                    if error.code is ResourceGovernorErrorCode.QUOTA_EXCEEDED:
                        resource_limit_exceeded.set()
                        execution.cancel()
                        return await self._finish_failure(
                            active,
                            ResourceLimitExceeded("worker resource budget exceeded"),
                            resource_usage,
                            execution_started=execution_started,
                        )
                    resource_monitor_failed.set()
                    execution.cancel()
                    return await self._finish_failure(
                        active,
                        ProductExecutionError("worker resource enforcement failed"),
                        resource_usage,
                        execution_started=execution_started,
                    )
                except Exception:
                    resource_monitor_failed.set()
                    execution.cancel()
                    return await self._finish_failure(
                        active,
                        ProductExecutionError("worker resource telemetry failed"),
                        resource_usage,
                        execution_started=execution_started,
                    )
                if update.command is not WorkerCommand.CONTINUE:
                    with suppress(Exception):
                        execution.cancel()
                    return await self._finish_command(
                        active,
                        update.command,
                        resource_usage=resource_usage,
                        execution_started=execution_started,
                    )
                if resource_limit_exceeded.is_set():
                    execution.cancel()
                    return await self._finish_failure(
                        active,
                        ResourceLimitExceeded("worker resource budget exceeded"),
                        resource_usage,
                        execution_started=execution_started,
                    )
                if resource_monitor_failed.is_set():
                    execution.cancel()
                    return await self._finish_failure(
                        active,
                        ProductExecutionError("worker resource monitoring failed"),
                        resource_usage,
                        execution_started=execution_started,
                    )
                requested_command = self._requested_command(active, command_seen)
                if requested_command is not None:
                    with suppress(Exception):
                        execution.cancel()
                    return await self._finish_command(
                        active,
                        requested_command,
                        resource_usage=resource_usage,
                        execution_started=execution_started,
                    )
                try:
                    execution.require_publication()
                except Exception:
                    execution.cancel()
                    return await self._finish_failure(
                        active,
                        ProductSuperseded("product revision was superseded"),
                        resource_usage,
                        execution_started=execution_started,
                    )
            try:
                execution.require_publication()
            except Exception:
                execution.cancel()
                return await self._finish_failure(
                    active,
                    ProductSuperseded("product revision was superseded"),
                    resource_usage,
                    execution_started=execution_started,
                )
            requested_command = self._requested_command(active, command_seen)
            if requested_command is not None:
                with suppress(Exception):
                    execution.cancel()
                return await self._finish_command(
                    active,
                    requested_command,
                    resource_usage=resource_usage,
                    execution_started=execution_started,
                )
            if resource_limit_exceeded.is_set():
                execution.cancel()
                return await self._finish_failure(
                    active,
                    ResourceLimitExceeded("worker resource budget exceeded"),
                    resource_usage,
                    execution_started=execution_started,
                )
            if resource_monitor_failed.is_set():
                execution.cancel()
                return await self._finish_failure(
                    active,
                    ProductExecutionError("worker resource monitoring failed"),
                    resource_usage,
                    execution_started=execution_started,
                )
            resource_monitor_stop.set()
            if resource_monitor is not None:
                try:
                    await _await_task_completion(resource_monitor)
                except Exception:
                    return await self._finish_failure(
                        active,
                        ProductExecutionError("worker resource monitoring failed"),
                        resource_usage,
                        execution_started=execution_started,
                    )
            if resource_limit_exceeded.is_set():
                return await self._finish_failure(
                    active,
                    ResourceLimitExceeded("worker resource budget exceeded"),
                    resource_usage,
                    execution_started=execution_started,
                )
            if resource_monitor_failed.is_set() or monitor_failed.is_set():
                return await self._finish_failure(
                    active,
                    ProductExecutionError("worker monitoring failed"),
                    resource_usage,
                    execution_started=execution_started,
                )
            if meter is None or resource_enforcer is None:
                return await self._finish_failure(
                    active,
                    ProductExecutionError("worker resource enforcement unavailable"),
                    resource_usage,
                    execution_started=execution_started,
                )
            try:
                if not resource_usage_meter_finished:
                    resource_usage = meter.finish(execution)
                    resource_usage_meter_finished = True
                resource_enforcer.observe(_core_usage(resource_usage))
            except ResourceGovernorError as error:
                if error.code is ResourceGovernorErrorCode.QUOTA_EXCEEDED:
                    resource_limit_exceeded.set()
                    return await self._finish_failure(
                        active,
                        ResourceLimitExceeded("worker resource budget exceeded"),
                        resource_usage,
                        execution_started=execution_started,
                    )
                return await self._finish_failure(
                    active,
                    ProductExecutionError("worker resource enforcement failed"),
                    resource_usage,
                    execution_started=execution_started,
                )
            except Exception:
                return await self._finish_failure(
                    active,
                    ProductExecutionError("worker resource telemetry is unavailable"),
                    None,
                    execution_started=execution_started,
                )
            if resource_limit_exceeded.is_set():
                return await self._finish_failure(
                    active,
                    ResourceLimitExceeded("worker resource budget exceeded"),
                    resource_usage,
                    execution_started=execution_started,
                )
            if self._requested_command(active, command_seen) is not None:
                return await self._finish_command(
                    active,
                    self._requested_command(active, command_seen) or WorkerCommand.CANCEL,
                    resource_usage=resource_usage,
                    execution_started=execution_started,
                )
            # Keep renewing the lease while the durable terminal write is
            # reconciled.  Only stop this monitor after the server confirms
            # an outcome or another terminal command is observed.
            monitor_stop.clear()
            monitor = asyncio.create_task(
                self._monitor(
                    active,
                    monitor_stop,
                    command_seen,
                    lease_lost,
                    monitor_failed,
                    control,
                )
            )
            completion_command = await self._append_event(active, "RUN_COMPLETED")
            if completion_command is not WorkerCommand.CONTINUE:
                with suppress(Exception):
                    execution.cancel()
                monitor_stop.set()
                with suppress(Exception):
                    await _await_task_completion(monitor)
                return await self._finish_command(
                    active,
                    completion_command,
                    resource_usage=resource_usage,
                    execution_started=execution_started,
                )
            try:
                execution.require_publication()
            except Exception:
                execution.cancel()
                monitor_stop.set()
                with suppress(Exception):
                    await _await_task_completion(monitor)
                return await self._finish_failure(
                    active,
                    ProductSuperseded("product revision was superseded"),
                    resource_usage,
                    execution_started=execution_started,
                )
            completion_deadline = _lease_deadline(active)
            await self._retry_call(
                active,
                lambda: self._client.complete(
                    active.job,
                    outcome=execution.outcome,
                    resource_usage=resource_usage,
                    findings=execution.findings,
                    deadline=completion_deadline,
                ),
                deadline=completion_deadline,
            )
            monitor_stop.set()
            await _await_task_completion(monitor)
            return True
        except RetryableControlPlaneError:
            if monitor is not None and not monitor.done():
                monitor_stop.set()
                with suppress(Exception):
                    await _await_task_completion(monitor)
            if await self._finish_failure(
                active,
                ProductExecutionError("result publication failed"),
                resource_usage,
                execution_started=execution_started,
            ):
                return True
            return await self._finish_remote_command_if_requested(
                active,
                resource_usage=resource_usage,
                execution_started=execution_started,
            )
        except LeaseLost:
            with suppress(Exception):
                execution.cancel()
            if monitor is not None and not monitor.done():
                monitor_stop.set()
                with suppress(Exception):
                    await _await_task_completion(monitor)
            return await self._finish_remote_command_if_requested(
                active,
                resource_usage=resource_usage,
                execution_started=execution_started,
            )
        except ControlPlaneRejected:
            with suppress(Exception):
                execution.cancel()
            if monitor is not None and not monitor.done():
                monitor_stop.set()
                with suppress(Exception):
                    await _await_task_completion(monitor)
            if await self._finish_failure(
                active,
                ProductExecutionError("result publication was rejected"),
                resource_usage,
                execution_started=execution_started,
            ):
                return True
            return await self._finish_remote_command_if_requested(
                active,
                resource_usage=resource_usage,
                execution_started=execution_started,
            )
        except Exception:
            with suppress(Exception):
                if execution is not None:
                    execution.cancel()
            if monitor is not None and not monitor.done():
                monitor_stop.set()
                with suppress(Exception):
                    await _await_task_completion(monitor)
            with suppress(Exception):
                return await self._finish_failure(
                    active,
                    ProductExecutionError("worker lifecycle failed"),
                    resource_usage,
                    execution_started=execution_started,
                )
            return False

    async def _monitor(
        self,
        active: _ActiveSession,
        monitor_stop: asyncio.Event,
        command_seen: asyncio.Event,
        lease_lost: asyncio.Event,
        monitor_failed: asyncio.Event,
        control: ExecutionControl,
    ) -> None:
        try:
            await self._monitor_loop(
                active,
                monitor_stop,
                command_seen,
                lease_lost,
                control,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            # A monitor failure invalidates the live lease supervision. Stop the
            # product cooperatively and route the run through the generic,
            # source-free failure completion path. Do not expose the exception.
            monitor_failed.set()
            with suppress(Exception):
                control.request(WorkerCommand.CANCEL)
            command_seen.set()

    async def _resource_monitor(
        self,
        meter: WorkerUsageMeter,
        enforcer: PerRunResourceEnforcer,
        monitor_stop: asyncio.Event,
        control: ExecutionControl,
        resource_limit_exceeded: ThreadingEvent,
        resource_monitor_failed: ThreadingEvent,
    ) -> None:
        try:
            while not monitor_stop.is_set() and not self._stopping.is_set():
                await self._wait(0.1)
                if monitor_stop.is_set():
                    return
                try:
                    enforcer.observe(_core_usage(meter.snapshot()))
                except ResourceGovernorError as error:
                    if error.code is ResourceGovernorErrorCode.QUOTA_EXCEEDED:
                        if not resource_limit_exceeded.is_set():
                            _request_resource_stop(control, resource_limit_exceeded)
                    else:
                        if not resource_monitor_failed.is_set():
                            _request_resource_stop(control, resource_monitor_failed)
                    return
                except Exception:
                    if not resource_monitor_failed.is_set():
                        _request_resource_stop(control, resource_monitor_failed)
                    return
        except asyncio.CancelledError:
            raise

    async def _monitor_loop(
        self,
        active: _ActiveSession,
        monitor_stop: asyncio.Event,
        command_seen: asyncio.Event,
        lease_lost: asyncio.Event,
        control: ExecutionControl,
    ) -> None:
        interval = max(1.0, min(10.0, active.job.lease_seconds / 3))
        while not monitor_stop.is_set() and not self._stopping.is_set():
            await self._wait(interval)
            if monitor_stop.is_set():
                break
            if self._stopping.is_set():
                control.request(WorkerCommand.CANCEL)
                command_seen.set()
                return
            active.heartbeat_attempt += 1
            heartbeat_attempt = active.heartbeat_attempt
            try:
                update = await self._retry_call(
                    active,
                    partial(
                        self._client.heartbeat,
                        active.job,
                        attempt=heartbeat_attempt,
                    ),
                    apply=lambda value: active.apply(
                        version=value.version,
                        command=value.command,
                    ),
                    lease_renewal=True,
                )
                if update.command is not WorkerCommand.CONTINUE:
                    control.request(update.command)
                    command_seen.set()
                    return
            except LeaseLost:
                control.request(WorkerCommand.CANCEL)
                lease_lost.set()
                return
            except ControlPlaneRejected:
                control.request(WorkerCommand.CANCEL)
                lease_lost.set()
                return
            except RetryableControlPlaneError:
                control.request(WorkerCommand.CANCEL)
                lease_lost.set()
                return
        if not monitor_stop.is_set() and self._stopping.is_set():
            control.request(WorkerCommand.CANCEL)
            command_seen.set()

    def _requested_command(
        self,
        active: _ActiveSession,
        command_seen: asyncio.Event,
    ) -> WorkerCommand | None:
        if self._stopping.is_set():
            command_seen.set()
        if not command_seen.is_set():
            return None
        return (
            active.job.command
            if active.job.command is not WorkerCommand.CONTINUE
            else WorkerCommand.CANCEL
        )

    async def _finish_remote_command_if_requested(
        self,
        active: _ActiveSession,
        *,
        resource_usage: WorkerResourceUsage | None = None,
        execution_started: bool = False,
    ) -> bool:
        if active.job.command is WorkerCommand.CONTINUE:
            active.heartbeat_attempt += 1
            try:
                await self._retry_call(
                    active,
                    partial(
                        self._client.heartbeat,
                        active.job,
                        attempt=active.heartbeat_attempt,
                    ),
                    apply=lambda value: active.apply(
                        version=value.version,
                        command=value.command,
                    ),
                    lease_renewal=True,
                )
            except (LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
                return False
        if active.job.command is WorkerCommand.CONTINUE:
            return False
        return await self._finish_command(
            active,
            active.job.command,
            resource_usage=resource_usage,
            execution_started=execution_started,
        )

    async def _append_event(self, active: _ActiveSession, kind: str) -> WorkerCommand:
        async with active.control_plane_lock:
            active.sequence += 1
            event = WorkerEvent.build(
                run_id=active.job.run_id,
                execution_identity_hash=active.job.execution_identity.execution_identity_hash,
                sequence=active.sequence,
                kind=kind,
            )
            update = await self._retry_call(
                active,
                lambda: self._client.append_events(active.job, (event,)),
                locked=False,
                apply=lambda value: active.apply(
                    version=value.version,
                    command=value.command,
                ),
            )
            return update.command

    async def _finish_command(
        self,
        active: _ActiveSession,
        command: WorkerCommand,
        *,
        event_already_recorded: bool = False,
        resource_usage: WorkerResourceUsage | None = None,
        execution_started: bool = False,
    ) -> bool:
        effective_command = command
        if not event_already_recorded:
            for _ in range(3):
                if active.job.version >= _MAX_SESSION_VERSION:
                    return False
                active.heartbeat_attempt += 1
                try:
                    update = await self._retry_call(
                        active,
                        lambda: self._client.heartbeat(
                            active.job,
                            attempt=active.heartbeat_attempt,
                        ),
                        apply=lambda value: active.apply(
                            version=value.version,
                            command=value.command,
                        ),
                        lease_renewal=True,
                    )
                except (LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
                    return False
                if update.command is WorkerCommand.CONTINUE:
                    if active.job.command is not WorkerCommand.CONTINUE:
                        effective_command = active.job.command
                    else:
                        return False
                else:
                    effective_command = update.command
                try:
                    appended_command = await self._append_event(
                        active,
                        _terminal_event_kind(effective_command),
                    )
                except LeaseLost:
                    return False
                except (ControlPlaneRejected, RetryableControlPlaneError):
                    continue
                if appended_command is WorkerCommand.CONTINUE:
                    break
                effective_command = appended_command
            else:
                return False
        elif active.job.command is not WorkerCommand.CONTINUE:
            effective_command = active.job.command
        outcome = "SUPERSEDED" if effective_command is WorkerCommand.SUPERSEDE else "CANCELLED"
        try:
            completion_deadline = _lease_deadline(active)
            settlement_usage = (
                _bounded_completion_usage(active, resource_usage) if execution_started else None
            )
            await self._retry_call(
                active,
                lambda: self._client.complete(
                    active.job,
                    outcome=outcome,
                    resource_usage=settlement_usage,
                    deadline=completion_deadline,
                ),
                deadline=completion_deadline,
            )
            return True
        except ControlPlaneRejected:
            return False
        except (LeaseLost, RetryableControlPlaneError):
            return False

    async def _finish_failure(
        self,
        active: _ActiveSession,
        failure: ProductExecutionError,
        resource_usage: WorkerResourceUsage | None,
        *,
        execution_started: bool = False,
    ) -> bool:
        if active.job.command is not WorkerCommand.CONTINUE:
            return await self._finish_command(
                active,
                active.job.command,
                resource_usage=resource_usage,
                execution_started=execution_started,
            )
        if isinstance(failure, ProductSuperseded):
            outcome, kind = "SUPERSEDED", "RUN_SUPERSEDED"
        elif isinstance(failure, ProductCancelled):
            outcome, kind = "CANCELLED", "RUN_CANCELLED"
        else:
            outcome, kind = "INDETERMINATE", "RUN_FAILED"
        if outcome == "INDETERMINATE" or execution_started:
            resource_usage = _bounded_completion_usage(active, resource_usage)
            if outcome == "INDETERMINATE" and resource_usage is None:
                return False
        with suppress(LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
            await self._append_event(active, kind)
        try:
            completion_deadline = _lease_deadline(active)
            await self._retry_call(
                active,
                lambda: self._client.complete(
                    active.job,
                    outcome=outcome,
                    resource_usage=resource_usage,
                    findings=(),
                    deadline=completion_deadline,
                ),
                deadline=completion_deadline,
            )
            return True
        except ControlPlaneRejected:
            return False
        except (LeaseLost, RetryableControlPlaneError):
            return False

    async def _retry_call(
        self,
        active: _ActiveSession,
        operation: Callable[[], _T],
        *,
        deadline: Callable[[], float] | None = None,
        apply: Callable[[_T], None] | None = None,
        locked: bool = True,
        lease_renewal: bool = False,
    ) -> _T:
        backoff = _Backoff(0.25, min(5.0, active.job.lease_seconds / 4))
        lease_started_at = time.monotonic() if lease_renewal else None
        while True:
            try:
                if locked:
                    async with active.control_plane_lock:
                        result = await asyncio.to_thread(operation)
                        if apply is not None:
                            apply(result)
                        if lease_started_at is not None:
                            active.last_heartbeat = lease_started_at
                        return result
                result = await asyncio.to_thread(operation)
                if apply is not None:
                    apply(result)
                if lease_started_at is not None:
                    active.last_heartbeat = lease_started_at
                return result
            except RetryableControlPlaneError:
                remaining = active.job.lease_seconds - (time.monotonic() - active.last_heartbeat)
                if deadline is not None:
                    remaining = min(remaining, deadline() - time.monotonic())
                delay = backoff.next_delay()
                if self._stopping.is_set() or remaining <= delay + 0.25:
                    raise
                await self._wait(delay)

    async def _wait(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=seconds)
        except TimeoutError:
            return


async def serve(
    *,
    environment: Mapping[str, str] | None = None,
    stopping: asyncio.Event | None = None,
) -> None:
    values = os.environ if environment is None else environment
    settings = RuntimeSettings.from_environment(values)
    stop_event = stopping or asyncio.Event()
    data_dir = Path(values.get("SECURECODE_DATA_DIR", "/var/lib/securecode"))
    heartbeat_path(data_dir)
    loop = asyncio.get_running_loop()
    if stopping is None:
        for value in (signal.SIGTERM, signal.SIGINT):
            with suppress(NotImplementedError, RuntimeError):
                loop.add_signal_handler(value, stop_event.set)
    client = ControlPlaneClient(
        base_url=settings.control_plane_url,
        token=settings.token,
        worker_id=settings.worker_id,
        timeout_seconds=settings.request_timeout_seconds,
        artifact_hosts=settings.artifact_hosts,
    )
    liveness = asyncio.create_task(_liveness_loop(data_dir, stop_event))
    try:
        if settings.requested_run_id is None and settings.scm_resolution is not None:
            requested_run_id = await _resolve_scm_run(
                client,
                settings.scm_resolution,
                stopping=stop_event,
                poll_seconds=settings.poll_seconds,
            )
            settings = replace(settings, requested_run_id=requested_run_id)
        executor = ProductExecutor(
            target=settings.target,
            environment=values,
            dependency_scanner_for=client.osv_scanner,
        )
        service = WorkerService(
            client=client,
            executor=executor,
            settings=settings,
            stopping=stop_event,
        )
        await service.run()
    finally:
        stop_event.set()
        liveness.cancel()
        with suppress(asyncio.CancelledError):
            await liveness


async def _liveness_loop(data_dir: Path, stopping: asyncio.Event) -> None:
    while not stopping.is_set():
        try:
            await asyncio.to_thread(touch_liveness, data_dir)
        except Exception:
            # A dead heartbeat must stop the worker.  Letting this task fail
            # independently would leave the worker processing jobs while the
            # container health check can no longer observe it.
            stopping.set()
            return
        try:
            await asyncio.wait_for(stopping.wait(), timeout=5.0)
        except TimeoutError:
            continue


async def _resolve_scm_run(
    client: ControlPlaneClient,
    resolution: tuple[str, str, str, str],
    *,
    stopping: asyncio.Event,
    poll_seconds: float,
) -> str:
    provider, repository_id, change_id, head_sha = resolution
    deadline = time.monotonic() + 120.0
    while not stopping.is_set():
        try:
            return await asyncio.to_thread(
                client.resolve_scm_run,
                provider=provider,
                repository_id=repository_id,
                change_id=change_id,
                head_sha=head_sha,
            )
        except (NoWork, RetryableControlPlaneError):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                await asyncio.wait_for(stopping.wait(), timeout=min(poll_seconds, remaining))
            except TimeoutError:
                continue
    raise ControlPlaneRejected("SCM run resolution timed out")


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    tokens = tuple(sys.argv[1:] if argv is None else argv)
    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    if tokens in {("--help",), ("-h",)}:
        output.write(_HELP)
        return 0
    if tokens:
        errors.write("worker service arguments are invalid\n")
        return 2
    try:
        asyncio.run(serve())
        return 0
    except ValueError:
        errors.write("worker configuration is invalid\n")
        return 2
    except ControlPlaneRejected:
        errors.write("worker control-plane request was rejected\n")
        return 3
    except WorkerCompletionUnconfirmed:
        errors.write("worker terminal completion was not confirmed\n")
        return 4
    except KeyboardInterrupt:
        return 130
    except Exception:
        errors.write("worker service failed\n")
        return 4


__all__ = ["RuntimeSettings", "WorkerService", "main", "serve"]


if __name__ == "__main__":
    raise SystemExit(main())
