from __future__ import annotations

import asyncio
from io import StringIO
from pathlib import Path
from typing import cast

import pytest
from securecode_ai.worker import service as worker_service
from securecode_ai.worker.control_plane import (
    ControlPlaneClient,
    NoWork,
    RetryableControlPlaneError,
)
from securecode_ai.worker.execution import ProductExecutor
from securecode_ai.worker.liveness import heartbeat_path
from securecode_ai.worker.protocol import WorkerJob
from securecode_ai.worker.runtime_config import RuntimeSettings


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
    monkeypatch.setattr(worker_service, "ControlPlaneClient", lambda **_: object())
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

    async def process(self: worker_service.WorkerService, job: WorkerJob) -> bool:
        del self, job
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
