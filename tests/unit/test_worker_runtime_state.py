from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from securecode_ai.worker.runtime_config import RuntimeSettings
from securecode_ai.worker.service_state import Backoff, await_task_completion


@pytest.mark.skipif(os.name != "posix", reason="descriptor-bound secret files are POSIX-only")
def test_runtime_settings_reads_secret_file_without_exposing_token(tmp_path: Path) -> None:
    target = tmp_path / "checkout"
    target.mkdir()
    token_file = tmp_path / "worker-token"
    token_file.write_text("x" * 48, encoding="ascii")
    token_file.chmod(0o600)
    settings = RuntimeSettings.from_environment(
        {
            "SECURECODE_CONTROL_PLANE_URL": "http://127.0.0.1:8080",
            "SECURECODE_WORKER_TOKEN_FILE": str(token_file),
            "SECURECODE_WORKER_ID": "worker-1",
            "SECURECODE_WORKER_TARGET": str(target),
        }
    )

    assert settings.token == "x" * 48
    assert settings.target == target
    assert "x" * 48 not in repr(settings)


def test_runtime_settings_rejects_multiple_token_sources(tmp_path: Path) -> None:
    target = tmp_path / "checkout"
    target.mkdir()
    with pytest.raises(ValueError, match="worker configuration is invalid"):
        RuntimeSettings.from_environment(
            {
                "SECURECODE_CONTROL_PLANE_URL": "http://127.0.0.1:8080",
                "SECURECODE_WORKER_TOKEN": "x" * 48,
                "SECURECODE_WORKER_TOKEN_FILE": str(tmp_path / "worker-token"),
                "SECURECODE_WORKER_ID": "worker-1",
                "SECURECODE_WORKER_TARGET": str(target),
            }
        )


def test_backoff_stays_bounded_and_reset_returns_to_initial_range() -> None:
    backoff = Backoff(2.0, 5.0)
    first = backoff.next_delay()
    second = backoff.next_delay()

    assert 1.6 <= first <= 2.4
    assert 3.2 <= second <= 4.8
    backoff.reset()
    assert 1.6 <= backoff.next_delay() <= 2.4


def test_task_completion_survives_repeated_cancellation() -> None:
    async def scenario() -> str:
        started = asyncio.Event()
        release = asyncio.Event()

        async def background() -> str:
            started.set()
            await release.wait()
            return "settled"

        task = asyncio.create_task(background())
        waiter = asyncio.create_task(await_task_completion(task))
        await started.wait()
        waiter.cancel()
        await asyncio.sleep(0)
        waiter.cancel()
        await asyncio.sleep(0)
        assert not waiter.done()
        release.set()
        return await waiter

    assert asyncio.run(asyncio.wait_for(scenario(), timeout=1)) == "settled"
