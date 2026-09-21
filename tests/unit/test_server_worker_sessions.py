import pytest
from securecode_ai.server.worker_sessions import WorkerDenied, WorkerSessions


def test_worker_session_is_tenant_worker_identity_bound() -> None:
    sessions = WorkerSessions()
    view = sessions.create(
        tenant_id="t",
        run_id="r",
        worker_id="w",
        identity_hash="a" * 64,
        idempotency_key="k",
    )
    with pytest.raises(WorkerDenied):
        sessions.heartbeat(
            session_id=view.session_id,
            tenant_id="x",
            worker_id="w",
            identity_hash="a" * 64,
            expected_version=1,
        )
