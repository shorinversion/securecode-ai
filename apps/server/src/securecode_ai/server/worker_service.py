"""P6.1 route-facing worker service adapter protocol."""

from __future__ import annotations

from .worker_sessions import WorkerSessions


class WorkerService:
    def __init__(self, sessions: WorkerSessions) -> None:
        self.sessions = sessions

    def command(
        self,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        version: int,
    ) -> str:
        receipt = self.sessions.heartbeat(
            session_id=session_id,
            tenant_id=tenant_id,
            worker_id=worker_id,
            identity_hash=identity_hash,
            expected_version=version,
        )
        return receipt.command.value
