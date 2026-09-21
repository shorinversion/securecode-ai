"""Connected, cancellation-aware worker service application."""

from __future__ import annotations

import asyncio
import os
import re
import signal
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field, replace
from functools import partial
from pathlib import Path
from typing import TextIO, TypeVar
from urllib.parse import urlsplit

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
from .protocol import WorkerCommand, WorkerEvent, WorkerJob
from .secure_files import read_ascii_secret
from .usage import WorkerResourceUsage, WorkerUsageError, WorkerUsageMeter

_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_T = TypeVar("_T")
_HELP = """usage: securecode-worker-service

Run the connected worker service using SECURECODE_WORKER_* environment values.
"""


@dataclass(frozen=True, slots=True)
class RuntimeSettings:
    control_plane_url: str
    token: str = field(repr=False)
    worker_id: str
    target: Path
    requested_run_id: str | None
    scm_resolution: tuple[str, str, str, str] | None
    request_timeout_seconds: float
    poll_seconds: float
    max_backoff_seconds: float
    artifact_hosts: frozenset[str]

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> RuntimeSettings:
        try:
            url = environment["SECURECODE_CONTROL_PLANE_URL"]
            token = _worker_token(environment)
            worker_id = environment["SECURECODE_WORKER_ID"]
            target = Path(environment["SECURECODE_WORKER_TARGET"])
            requested_run_id = environment.get("SECURECODE_WORKER_RUN_ID")
            gitlab_values = (
                environment.get("CI_PROJECT_ID"),
                environment.get("CI_MERGE_REQUEST_IID"),
                environment.get("CI_COMMIT_SHA"),
            )
            if requested_run_id is None and all(gitlab_values):
                scm_resolution = (
                    "gitlab",
                    _ci_value(gitlab_values[0]),
                    _ci_value(gitlab_values[1]),
                    _ci_value(gitlab_values[2]),
                )
            elif requested_run_id is None and any(gitlab_values):
                raise ValueError
            else:
                scm_resolution = None
            timeout = float(environment.get("SECURECODE_WORKER_REQUEST_TIMEOUT_SECONDS", "15"))
            poll = float(environment.get("SECURECODE_WORKER_POLL_SECONDS", "2"))
            maximum = float(environment.get("SECURECODE_WORKER_MAX_BACKOFF_SECONDS", "30"))
            parsed = urlsplit(url)
            default_host = parsed.hostname
            configured_hosts = environment.get("SECURECODE_WORKER_ARTIFACT_HOSTS")
            artifact_hosts = (
                frozenset(
                    item.strip().lower() for item in configured_hosts.split(",") if item.strip()
                )
                if configured_hosts is not None
                else frozenset({default_host})
                if default_host
                else frozenset()
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError("worker configuration is invalid") from None
        if (
            type(url) is not str
            or type(token) is not str
            or len(token) < 32
            or type(worker_id) is not str
            or _OPAQUE_ID.fullmatch(worker_id) is None
            or not target.is_absolute()
            or not target.is_dir()
            or target.is_symlink()
            or (requested_run_id is not None and _OPAQUE_ID.fullmatch(requested_run_id) is None)
            or (
                scm_resolution is not None
                and (
                    any(_OPAQUE_ID.fullmatch(item) is None for item in scm_resolution[:3])
                    or re.fullmatch(r"[0-9a-f]{40}", scm_resolution[3]) is None
                )
            )
            or not 1.0 <= timeout <= 120.0
            or not 0.1 <= poll <= 60.0
            or not poll <= maximum <= 300.0
            or not artifact_hosts
        ):
            raise ValueError("worker configuration is invalid")
        return cls(
            control_plane_url=url,
            token=token,
            worker_id=worker_id,
            target=target,
            requested_run_id=requested_run_id,
            scm_resolution=scm_resolution,
            request_timeout_seconds=timeout,
            poll_seconds=poll,
            max_backoff_seconds=maximum,
            artifact_hosts=artifact_hosts,
        )


def _ci_value(value: str | None) -> str:
    if type(value) is not str or not value:
        raise ValueError("worker CI identity is invalid")
    return value


def _worker_token(environment: Mapping[str, str]) -> str:
    direct = environment.get("SECURECODE_WORKER_TOKEN")
    file_name = environment.get("SECURECODE_WORKER_TOKEN_FILE")
    if (direct is None) == (file_name is None):
        raise ValueError("worker token source is invalid")
    if direct is not None:
        return direct
    if not isinstance(file_name, str):
        raise ValueError("worker token source is invalid")
    try:
        token = read_ascii_secret(Path(file_name), minimum=32, maximum=8192)
    except ValueError:
        raise ValueError("worker token source is invalid") from None
    return token


class WorkerCompletionUnconfirmed(RuntimeError):
    """A requested one-shot run did not confirm a terminal control-plane state."""


@dataclass(slots=True)
class _ActiveSession:
    job: WorkerJob
    sequence: int = 0
    heartbeat_attempt: int = 0
    last_heartbeat: float = field(default_factory=time.monotonic)

    def apply(self, *, version: int, command: WorkerCommand, renewed: bool = False) -> None:
        self.job = replace(self.job, version=version, command=command)
        if renewed:
            self.last_heartbeat = time.monotonic()


class _Backoff:
    def __init__(self, initial: float, maximum: float) -> None:
        self._initial = initial
        self._maximum = maximum
        self._failures = 0

    def reset(self) -> None:
        self._failures = 0

    def next_delay(self) -> float:
        growth: float = 2.0 ** min(self._failures, 12)
        ceiling: float = min(self._maximum, self._initial * growth)
        self._failures += 1
        jitter_units = int.from_bytes(os.urandom(3), "big") % 1_000_000
        jitter: float = jitter_units / 1_000_000
        return ceiling * (0.8 + jitter * 0.4)


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
        claim_attempt = 0
        backoff = _Backoff(self._settings.poll_seconds, self._settings.max_backoff_seconds)
        while not self._stopping.is_set():
            claim_attempt += 1
            try:
                job = await asyncio.to_thread(
                    self._client.open_session,
                    attempt=claim_attempt,
                    requested_run_id=self._settings.requested_run_id,
                )
            except NoWork:
                backoff.reset()
                await self._wait(self._settings.poll_seconds)
                continue
            except RetryableControlPlaneError:
                await self._wait(backoff.next_delay())
                continue
            except ControlPlaneRejected:
                raise
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
        try:
            execution = await asyncio.to_thread(
                self._executor.execute,
                active.job,
                control=control,
            )
        except ProductExecutionError as error:
            failure = error
        finally:
            try:
                resource_usage = meter.finish(execution.scan if execution is not None else None)
            except WorkerUsageError:
                resource_usage = None
            monitor_stop.set()
            await monitor

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
            for artifact in execution.artifacts:
                artifact_job = active.job
                update = await self._retry_call(
                    active,
                    partial(self._client.publish_artifact, artifact_job, artifact),
                )
                active.apply(version=update.version, command=update.command)
                if update.command is not WorkerCommand.CONTINUE:
                    with suppress(Exception):
                        execution.cancel()
                    return await self._finish_command(active, update.command)
            completion_command = await self._append_event(active, "RUN_COMPLETED")
            if completion_command is not WorkerCommand.CONTINUE:
                with suppress(Exception):
                    execution.cancel()
                return await self._finish_command(active, completion_command)
            completion_job = active.job
            await self._retry_call(
                active,
                lambda: self._client.complete(
                    completion_job,
                    outcome=execution.outcome,
                    resource_usage=resource_usage,
                    findings=execution.findings,
                ),
            )
            return True
        except RetryableControlPlaneError:
            return await self._finish_failure(
                active,
                ProductExecutionError("result publication failed"),
                resource_usage,
            )
        except (LeaseLost, ControlPlaneRejected):
            with suppress(Exception):
                execution.cancel()
            return False

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

    async def _finish_command(self, active: _ActiveSession, command: WorkerCommand) -> bool:
        outcome = "SUPERSEDED" if command is WorkerCommand.SUPERSEDE else "CANCELLED"
        kind = "RUN_SUPERSEDED" if outcome == "SUPERSEDED" else "RUN_CANCELLED"
        with suppress(LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
            await self._append_event(active, kind)
        try:
            completion_job = active.job
            await self._retry_call(
                active,
                lambda: self._client.complete(completion_job, outcome=outcome),
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
            await self._retry_call(
                active,
                lambda: self._client.complete(
                    completion_job,
                    outcome=outcome,
                    resource_usage=resource_usage if outcome == "INDETERMINATE" else None,
                    findings=(),
                ),
            )
            return True
        except (LeaseLost, ControlPlaneRejected, RetryableControlPlaneError):
            return False

    async def _retry_call(
        self,
        active: _ActiveSession,
        operation: Callable[[], _T],
    ) -> _T:
        backoff = _Backoff(0.25, min(5.0, active.job.lease_seconds / 4))
        while True:
            try:
                return await asyncio.to_thread(operation)
            except RetryableControlPlaneError:
                remaining = active.job.lease_seconds - (time.monotonic() - active.last_heartbeat)
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


__all__ = ["RuntimeSettings", "WorkerService", "main", "serve"]


if __name__ == "__main__":
    raise SystemExit(main())
