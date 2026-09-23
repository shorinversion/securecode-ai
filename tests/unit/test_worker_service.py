from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from securecode_ai.worker import service as worker_service
from securecode_ai.worker.liveness import heartbeat_path
from securecode_ai.worker.runtime_config import RuntimeSettings


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
