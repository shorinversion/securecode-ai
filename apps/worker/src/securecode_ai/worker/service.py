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
from typing import TextIO, TypeVar
from uuid import uuid4

from .control_plane import (
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
    WorkerExecutionResult,
)
from .liveness import touch as touch_liveness
from .protocol import WorkerCommand, WorkerEvent, WorkerJob
from .runtime_config import RuntimeSettings
from .service_state import ActiveSession as _ActiveSession
from .service_state import Backoff as _Backoff
from .service_state import await_task_completion as _await_task_completion
from .usage import WorkerResourceUsage, WorkerUsageError, WorkerUsageMeter

_T = TypeVar("_T")
_HELP = """usage: securecode-worker-service

Run the connected worker service using SECURECODE_WORKER_* environment values.
"""


def _lease_deadline(active: _ActiveSession) -> Callable[[], float]:
    return lambda: active.last_heartbeat + active.job.lease_seconds - 0.5


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
        claim_attempt = uuid4().int
        backoff = _Backoff(self._settings.poll_seconds, self._settings.max_backoff_seconds)
        while not self._stopping.is_set():
            try:
                job = await asyncio.to_thread(
                    self._client.open_session,
                    attempt=claim_attempt,
                    requested_run_id=self._settings.requested_run_id,
                )
            except NoWork:
                claim_attempt += 1
                backoff.reset()
                await self._wait(self._settings.poll_seconds)
                continue
            except RetryableControlPlaneError:
                await self._wait(backoff.next_delay())
                continue
            except ControlPlaneRejected:
                raise
            claim_attempt += 1
            backoff.reset()
            terminal_confirmed = await self._process(job)
            if self._settings.requested_run_id is not None:
                if not terminal_confirmed:
                    raise WorkerCompletionUnconfirmed()
                return

    async def _process(self, job: WorkerJob) -> bool:
        active = _ActiveSession(job)
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
        control = ExecutionControl()
        monitor = asyncio.create_task(
            self._monitor(active, monitor_stop, command_seen, lease_lost, control)
        )
        execution: WorkerExecutionResult | None = None
        failure: ProductExecutionError | None = None
        resource_usage: WorkerResourceUsage | None = None
        meter = WorkerUsageMeter()
        execution_task = asyncio.create_task(
            asyncio.to_thread(
                self._executor.execute,
                active.job,
                control=control,
            )
        )
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
        finally:
            try:
                resource_usage = meter.finish(execution.scan if execution is not None else None)
            except WorkerUsageError:
                resource_usage = None
            monitor_stop.set()
            try:
                await _await_task_completion(monitor)
            except Exception:
                control.request(WorkerCommand.CANCEL)
                command_seen.set()
                failure = failure or ProductExecutionError("worker monitoring failed")

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
            return await self._finish_command(active, command)
        if resource_usage is None:
            if execution is not None:
                with suppress(Exception):
                    execution.cancel()
            return await self._finish_failure(
                active,
                failure or ProductExecutionError("resource telemetry is unavailable"),
                None,
            )
        if failure is not None:
            return await self._finish_failure(active, failure, resource_usage)
        if execution is None:
            return await self._finish_failure(
                active,
                ProductExecutionError("product execution failed"),
                resource_usage,
            )

        try:
            active.heartbeat_attempt += 1
            heartbeat_job = active.job
            heartbeat_attempt = active.heartbeat_attempt
            update = await self._retry_call(
                active,
                lambda: self._client.heartbeat(heartbeat_job, attempt=heartbeat_attempt),
            )
            active.apply(version=update.version, command=update.command, renewed=True)
            if update.command is not WorkerCommand.CONTINUE:
                with suppress(Exception):
                    execution.cancel()
                return await self._finish_command(active, update.command)
            requested_command = self._requested_command(active, command_seen)
            if requested_command is not None:
                with suppress(Exception):
                    execution.cancel()
                return await self._finish_command(active, requested_command)
            for artifact_index, artifact in enumerate(execution.artifacts):
                if artifact_index:
                    active.heartbeat_attempt += 1
                    artifact_heartbeat = await self._retry_call(
                        active,
                        lambda: self._client.heartbeat(
                            active.job,
                            attempt=active.heartbeat_attempt,
                        ),
                    )
                    active.apply(
                        version=artifact_heartbeat.version,
                        command=artifact_heartbeat.command,
                        renewed=True,
                    )
                    if artifact_heartbeat.command is not WorkerCommand.CONTINUE:
                        with suppress(Exception):
                            execution.cancel()
                        return await self._finish_command(active, artifact_heartbeat.command)
                artifact_deadline = lambda: (
                    active.last_heartbeat + active.job.lease_seconds - 0.5
                )
                update = await self._retry_call(
                    active,
                    lambda: self._client.publish_artifact(
                        active.job,
                        artifact,
                        deadline=artifact_deadline,
                    ),
                    deadline=artifact_deadline,
                )
                active.apply(version=update.version, command=update.command)
                if update.command is not WorkerCommand.CONTINUE:
                    with suppress(Exception):
                        execution.cancel()
                    return await self._finish_command(active, update.command)
                requested_command = self._requested_command(active, command_seen)
                if requested_command is not None:
                    with suppress(Exception):
                        execution.cancel()
                    return await self._finish_command(active, requested_command)
            completion_command = await self._append_event(active, "RUN_COMPLETED")
            if completion_command is not WorkerCommand.CONTINUE:
                with suppress(Exception):
                    execution.cancel()
                return await self._finish_command(
                    active,
                    completion_command,
                    event_already_recorded=True,
                )
            requested_command = self._requested_command(active, command_seen)
            if requested_command is not None:
                with suppress(Exception):
                    execution.cancel()
                return await self._finish_command(
                    active,
                    requested_command,
                    event_already_recorded=True,
                )
            completion_job = active.job
            completion_deadline = _lease_deadline(active)
            await self._retry_call(
                active,
                lambda: self._client.complete(
                    completion_job,
                    outcome=execution.outcome,
                    resource_usage=resource_usage,
                    findings=execution.findings,
                    deadline=completion_deadline,
                ),
                deadline=completion_deadline,
            )
            return True
        except RetryableControlPlaneError:
            if await self._finish_failure(
                active,
                ProductExecutionError("result publication failed"),
                resource_usage,
            ):
                return True
            return await self._finish_remote_command_if_requested(active)
        except LeaseLost:
            with suppress(Exception):
                execution.cancel()
            return await self._finish_remote_command_if_requested(active)
        except ControlPlaneRejected:
            with suppress(Exception):
                execution.cancel()
            return await self._finish_remote_command_if_requested(active)

    async def _monitor(
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
            heartbeat_job = active.job
            heartbeat_attempt = active.heartbeat_attempt
            try:
                update = await self._retry_call(
                    active,
                    partial(
                        self._client.heartbeat,
                        heartbeat_job,
                        attempt=heartbeat_attempt,
                    ),
                )
                active.apply(version=update.version, command=update.command, renewed=True)
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

    async def _finish_remote_command_if_requested(self, active: _ActiveSession) -> bool:
        if active.job.command is WorkerCommand.CONTINUE:
            active.heartbeat_attempt += 1
            try:
                update = await asyncio.to_thread(
                    self._client.heartbeat,
                    active.job,
                    attempt=active.heartbeat_attempt,
                )
            except (LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
                return False
            active.apply(version=update.version, command=update.command, renewed=True)
        if active.job.command is WorkerCommand.CONTINUE:
            return False
        return await self._finish_command(active, active.job.command)

    async def _append_event(self, active: _ActiveSession, kind: str) -> WorkerCommand:
        active.sequence += 1
        event = WorkerEvent.build(
            run_id=active.job.run_id,
            execution_identity_hash=active.job.execution_identity.execution_identity_hash,
            sequence=active.sequence,
            kind=kind,
        )
        event_job = active.job
        update = await self._retry_call(
            active,
            lambda: self._client.append_events(event_job, (event,)),
        )
        active.apply(version=update.version, command=update.command)
        return update.command

    async def _finish_command(
        self,
        active: _ActiveSession,
        command: WorkerCommand,
        *,
        event_already_recorded: bool = False,
    ) -> bool:
        outcome = "SUPERSEDED" if command is WorkerCommand.SUPERSEDE else "CANCELLED"
        kind = "RUN_SUPERSEDED" if outcome == "SUPERSEDED" else "RUN_CANCELLED"
        if not event_already_recorded:
            with suppress(LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
                await self._append_event(active, kind)
        try:
            completion_job = active.job
            completion_deadline = _lease_deadline(active)
            await self._retry_call(
                active,
                lambda: self._client.complete(
                    completion_job,
                    outcome=outcome,
                    deadline=completion_deadline,
                ),
                deadline=completion_deadline,
            )
            return True
        except (LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
            return False

    async def _finish_failure(
        self,
        active: _ActiveSession,
        failure: ProductExecutionError,
        resource_usage: WorkerResourceUsage | None,
    ) -> bool:
        if isinstance(failure, ProductSuperseded):
            outcome, kind = "SUPERSEDED", "RUN_SUPERSEDED"
        elif isinstance(failure, ProductCancelled):
            outcome, kind = "CANCELLED", "RUN_CANCELLED"
        else:
            outcome, kind = "INDETERMINATE", "RUN_FAILED"
        with suppress(LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
            await self._append_event(active, kind)
        try:
            completion_job = active.job
            completion_deadline = _lease_deadline(active)
            await self._retry_call(
                active,
                lambda: self._client.complete(
                    completion_job,
                    outcome=outcome,
                    resource_usage=resource_usage if outcome == "INDETERMINATE" else None,
                    findings=(),
                    deadline=completion_deadline,
                ),
                deadline=completion_deadline,
            )
            return True
        except (LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
            return False

    async def _retry_call(
        self,
        active: _ActiveSession,
        operation: Callable[[], _T],
        *,
        deadline: Callable[[], float] | None = None,
    ) -> _T:
        backoff = _Backoff(0.25, min(5.0, active.job.lease_seconds / 4))
        while True:
            try:
                return await asyncio.to_thread(operation)
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
        executor = ProductExecutor(target=settings.target, environment=values)
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
