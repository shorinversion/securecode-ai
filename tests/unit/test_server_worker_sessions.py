import pytest
from securecode_ai.server.worker_sessions import WorkerCommand, WorkerDenied, WorkerSessions

IDENTITY_HASH = "a" * 64


def test_worker_session_is_tenant_worker_identity_bound() -> None:
    sessions = WorkerSessions()
    view = sessions.create(
        tenant_id="t",
        run_id="r",
        worker_id="w",
        identity_hash=IDENTITY_HASH,
        idempotency_key="k",
    )
    with pytest.raises(WorkerDenied):
        sessions.heartbeat(
            session_id=view.session_id,
            tenant_id="x",
            worker_id="w",
            identity_hash=IDENTITY_HASH,
            expected_version=1,
        )


@pytest.mark.parametrize(
    ("worker_id", "identity_hash"),
    [("other-worker", IDENTITY_HASH), ("w", "b" * 64)],
)
def test_command_requires_the_bound_worker_identity(
    worker_id: str,
    identity_hash: str,
) -> None:
    sessions = WorkerSessions()
    view = sessions.create(
        tenant_id="t",
        run_id="r",
        worker_id="w",
        identity_hash=IDENTITY_HASH,
        idempotency_key="k",
    )

    with pytest.raises(WorkerDenied):
        sessions.command(
            session_id=view.session_id,
            tenant_id="t",
            worker_id=worker_id,
            identity_hash=identity_hash,
            command=WorkerCommand.CANCEL,
            expected_version=view.version,
        )

    current = sessions.heartbeat(
        session_id=view.session_id,
        tenant_id="t",
        worker_id="w",
        identity_hash=IDENTITY_HASH,
        expected_version=view.version,
    )
    assert current.command is WorkerCommand.CONTINUE


def test_bound_worker_can_request_cancellation_once() -> None:
    sessions = WorkerSessions()
    view = sessions.create(
        tenant_id="t",
        run_id="r",
        worker_id="w",
        identity_hash=IDENTITY_HASH,
        idempotency_key="k",
    )

    cancelled = sessions.command(
        session_id=view.session_id,
        tenant_id="t",
        worker_id="w",
        identity_hash=IDENTITY_HASH,
        command=WorkerCommand.CANCEL,
        expected_version=view.version,
    )

    assert cancelled.version == view.version + 1
    assert cancelled.command is WorkerCommand.CANCEL
