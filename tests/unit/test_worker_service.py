from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from securecode_ai.adapters.local_product_runner_config import LocalProductScanResult
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    ComponentPin,
    DataClass,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.worker import service as worker_service
from securecode_ai.worker.control_plane import (
    ControlPlaneClient,
    NoWork,
    RetryableControlPlaneError,
    SessionUpdate,
)
from securecode_ai.worker.execution import (
    ExecutionControl,
    ProductExecutor,
    WorkerExecutionResult,
)
from securecode_ai.worker.liveness import heartbeat_path
from securecode_ai.worker.protocol import (
    WorkerArtifact,
    WorkerCommand,
    WorkerEvent,
    WorkerFinding,
    WorkerJob,
    WorkerResourceBudget,
)
from securecode_ai.worker.runtime_config import RuntimeSettings
from securecode_ai.worker.usage import WorkerResourceUsage, WorkerUsageMeter


@pytest.mark.parametrize("failure", (OSError("socket failed"), RuntimeError("unexpected")))
def test_service_main_maps_unexpected_failures_to_operational_exit_without_details(
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    async def fail() -> None:
        raise failure

    stderr = StringIO()
    monkeypatch.setattr(worker_service, "serve", fail)

    code = worker_service.main([], stdout=StringIO(), stderr=stderr)

    assert code == 4
    assert stderr.getvalue() == "worker service failed\n"


def test_worker_liveness_starts_while_waiting_for_scm_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = RuntimeSettings(
        control_plane_url="http://127.0.0.1:8080",
        token="x" * 48,
        worker_id="worker-1",
        target=tmp_path,
        requested_run_id=None,
        scm_resolution=("gitlab", "project-1", "mr-1", "a" * 40),
        request_timeout_seconds=15,
        poll_seconds=0.1,
        max_backoff_seconds=1,
        artifact_hosts=frozenset({"127.0.0.1"}),
    )
    monkeypatch.setattr(worker_service.RuntimeSettings, "from_environment", lambda _: settings)
    monkeypatch.setattr(
        worker_service,
        "ControlPlaneClient",
        lambda **_: SimpleNamespace(osv_scanner=lambda _job: None),
    )
    monkeypatch.setattr(worker_service, "ProductExecutor", lambda **_: object())

    async def resolve(
        client: object,
        resolution: tuple[str, str, str, str],
        *,
        stopping: asyncio.Event,
        poll_seconds: float,
    ) -> str:
        del client, resolution, poll_seconds
        path = heartbeat_path(tmp_path)
        for _ in range(50):
            if path.exists():
                return "run-1"
            if stopping.is_set():
                break
            await asyncio.sleep(0.01)
        raise AssertionError("worker liveness did not start before SCM resolution")

    async def run(self: worker_service.WorkerService) -> None:
        self._stopping.set()

    monkeypatch.setattr(worker_service, "_resolve_scm_run", resolve)
    monkeypatch.setattr(worker_service.WorkerService, "run", run)

    asyncio.run(
        worker_service.serve(
            environment={"SECURECODE_DATA_DIR": str(tmp_path)},
            stopping=asyncio.Event(),
        )
    )

    assert heartbeat_path(tmp_path).is_file()


def test_claim_retry_reuses_idempotency_attempt_but_next_poll_is_fresh(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    stopping = asyncio.Event()

    class FakeClient:
        def __init__(self) -> None:
            self.attempts: list[int] = []

        def open_session(self, *, attempt: int, requested_run_id: str | None) -> WorkerJob:
            self.attempts.append(attempt)
            if len(self.attempts) == 1:
                raise RetryableControlPlaneError("transient")
            if len(self.attempts) == 3:
                stopping.set()
                raise NoWork("empty queue")
            return cast(WorkerJob, object())

    async def wait(self: worker_service.WorkerService, seconds: float) -> None:
        del self, seconds

    async def process(
        self: worker_service.WorkerService, job: WorkerJob, *, lease_started_at: float
    ) -> bool:
        del self, job, lease_started_at
        return True

    client = FakeClient()
    monkeypatch.setattr(worker_service.WorkerService, "_wait", wait)
    monkeypatch.setattr(worker_service.WorkerService, "_process", process)
    service = worker_service.WorkerService(
        client=cast(ControlPlaneClient, client),
        executor=cast(ProductExecutor, object()),
        settings=settings,
        stopping=stopping,
    )

    asyncio.run(service.run())

    assert len(client.attempts) == 3
    assert client.attempts[0] == client.attempts[1]
    assert client.attempts[2] != client.attempts[1]


def test_empty_queue_starts_a_new_idempotent_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    stopping = asyncio.Event()

    class FakeClient:
        def __init__(self) -> None:
            self.attempts: list[int] = []

        def open_session(self, *, attempt: int, requested_run_id: str | None) -> WorkerJob:
            del requested_run_id
            self.attempts.append(attempt)
            if len(self.attempts) == 2:
                stopping.set()
            raise NoWork("empty queue")

    async def wait(self: worker_service.WorkerService, seconds: float) -> None:
        del self, seconds

    client = FakeClient()
    monkeypatch.setattr(worker_service.WorkerService, "_wait", wait)
    service = worker_service.WorkerService(
        client=cast(ControlPlaneClient, client),
        executor=cast(ProductExecutor, object()),
        settings=settings,
        stopping=stopping,
    )

    asyncio.run(service.run())

    assert len(client.attempts) == 2
    assert client.attempts[0] != client.attempts[1]


@pytest.mark.parametrize("stop_phase", ("artifact", "completion-event"))
def test_local_stop_during_publication_never_fabricates_a_cancelled_terminal_event(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stop_phase: str,
) -> None:
    stopping = asyncio.Event()
    settings = _settings(tmp_path)
    identity = _identity()
    job = WorkerJob(
        session_id="session-1",
        run_id="run-1",
        version=1,
        lease_seconds=30,
        command=WorkerCommand.CONTINUE,
        execution_identity=identity,
        resource_budget=WorkerResourceBudget(
            profile_sha256="b" * 64,
            reservation_id="reservation-1",
            reservation_version=1,
            reserved=WorkerResourceUsage(
                tokens=1_000,
                cost_microunits=1_000,
                cpu_ms=60_000,
                peak_memory_bytes=1 << 30,
                wall_ms=60_000,
            ),
        ),
    )
    content = b"artifact"
    artifact = WorkerArtifact(
        reference=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            content_id="artifact-1",
            content_sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            data_class=DataClass.CONFIDENTIAL_SECURITY,
        ),
        purpose="audit-report",
        content=content,
    )

    class ScanProbe:
        tokens = 1
        cost_microunits = 2
        cancelled = False

        def cancel(self) -> None:
            self.cancelled = True

        def require_publication(self) -> None:
            return None

    scan = ScanProbe()
    execution = WorkerExecutionResult(
        outcome="PASS",
        artifacts=(artifact,),
        findings=(),
        scan=cast(LocalProductScanResult, scan),
    )

    class FakeExecutor:
        def execute(
            self,
            job: WorkerJob,
            *,
            control: ExecutionControl,
            **_observers: object,
        ) -> WorkerExecutionResult:
            del job, control
            return execution

    class FakeClient:
        def __init__(self) -> None:
            self.completions: list[str] = []
            self.events: list[str] = []

        def append_events(
            self,
            job: WorkerJob,
            events: tuple[WorkerEvent, ...],
        ) -> SessionUpdate:
            self.events.extend(event.kind for event in events)
            if stop_phase == "completion-event" and any(
                event.kind == "RUN_COMPLETED" for event in events
            ):
                stopping.set()
            return SessionUpdate(version=job.version + 1, command=WorkerCommand.CONTINUE)

        def heartbeat(self, job: WorkerJob, *, attempt: int) -> SessionUpdate:
            del attempt
            return SessionUpdate(version=job.version + 1, command=WorkerCommand.CONTINUE)

        def publish_artifact(
            self,
            job: WorkerJob,
            artifact: WorkerArtifact,
            *,
            deadline: Callable[[], float] | None = None,
        ) -> SessionUpdate:
            del artifact, deadline
            if stop_phase == "artifact":
                stopping.set()
            return SessionUpdate(version=job.version + 1, command=WorkerCommand.CONTINUE)

        def complete(
            self,
            job: WorkerJob,
            *,
            outcome: str,
            resource_usage: WorkerResourceUsage | None = None,
            findings: tuple[WorkerFinding, ...] = (),
            deadline: Callable[[], float] | None = None,
        ) -> SessionUpdate:
            del resource_usage, findings, deadline
            self.completions.append(outcome)
            return SessionUpdate(version=job.version + 1, command=WorkerCommand.CONTINUE)

    async def retry(
        service: worker_service.WorkerService,
        active: object,
        operation: Callable[[], object],
        *,
        apply: Callable[[object], None] | None = None,
        **_options: object,
    ) -> object:
        del service, active
        result = operation()
        if apply is not None:
            apply(result)
        return result

    usage = WorkerResourceUsage(
        tokens=1, cost_microunits=2, cpu_ms=1, peak_memory_bytes=1, wall_ms=1
    )
    monkeypatch.setattr(WorkerUsageMeter, "finish", lambda *_args: usage)
    monkeypatch.setattr(WorkerUsageMeter, "snapshot", lambda *_args: usage)
    monkeypatch.setattr(worker_service.WorkerService, "_retry_call", retry)

    client = FakeClient()
    service = worker_service.WorkerService(
        client=cast(ControlPlaneClient, client),
        executor=cast(ProductExecutor, FakeExecutor()),
        settings=settings,
        stopping=stopping,
    )

    confirmed = asyncio.run(service._process(job, lease_started_at=time.monotonic()))

    # A local shutdown is not a control-plane CANCEL: the server only accepts
    # RUN_CANCELLED after it issued the command, so the worker must not settle
    # the run as CANCELLED on its own.
    assert client.events.count("RUN_CANCELLED") == 0
    if stop_phase == "artifact":
        # Unconfirmed stop before the terminal event: stop the product and
        # release the lease for redelivery instead of committing a result.
        assert confirmed is False
        assert client.completions == []
        assert scan.cancelled
        assert client.events.count("RUN_COMPLETED") == 0
    else:
        # RUN_COMPLETED is already durable; reconcile it exactly once.
        assert confirmed is True
        assert client.completions == ["PASS"]
        assert client.events.count("RUN_COMPLETED") == 1


def _settings(target: Path) -> RuntimeSettings:
    return RuntimeSettings(
        control_plane_url="http://127.0.0.1:8080",
        token="x" * 48,
        worker_id="worker-1",
        target=target,
        requested_run_id=None,
        scm_resolution=None,
        request_timeout_seconds=15,
        poll_seconds=0.1,
        max_backoff_seconds=1,
        artifact_hosts=frozenset({"127.0.0.1"}),
    )


def _identity() -> RunExecutionIdentity:
    def pin(name: str, suffix: str) -> ComponentPin:
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=name,
            component_version=CONTRACT_SCHEMA_VERSION,
            content_sha256=suffix * 64,
        )

    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            scm_provider="github",
            repository_id="repo-1",
            head_sha="a" * 40,
            base_sha="b" * 40,
        ),
        stage_catalogue=pin("catalogue", "1"),
        workflow=pin("workflow", "2"),
        policy=pin("policy", "3"),
        configuration=pin("configuration", "4"),
        provider_profile=pin("provider", "5"),
        capability_profile=pin("capability", "6"),
        egress_profile=pin("egress", "7"),
    )
