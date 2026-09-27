"""CAS workflow orchestration with lease claims and source-free durable receipts."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from .checkpoints import CheckpointConflict, SqliteCheckpointStore, WorkflowCheckpoint


class WorkflowState(StrEnum):
    QUEUED = "QUEUED"
    CLAIMED = "CLAIMED"
    RUNNING = "RUNNING"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    SUPERSEDED = "SUPERSEDED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"
    CANCELLED = "CANCELLED"


_TERMINAL = frozenset(
    {
        WorkflowState.SUPERSEDED,
        WorkflowState.SUCCEEDED,
        WorkflowState.FAILED,
        WorkflowState.INDETERMINATE,
        WorkflowState.CANCELLED,
    }
)
_LEGAL = {
    WorkflowState.QUEUED: {
        WorkflowState.CLAIMED,
        WorkflowState.CANCEL_REQUESTED,
        WorkflowState.SUPERSEDED,
    },
    WorkflowState.CLAIMED: {
        WorkflowState.CLAIMED,
        WorkflowState.RUNNING,
        WorkflowState.QUEUED,
        WorkflowState.CANCEL_REQUESTED,
        WorkflowState.SUPERSEDED,
    },
    WorkflowState.RUNNING: {
        WorkflowState.SUCCEEDED,
        WorkflowState.FAILED,
        WorkflowState.INDETERMINATE,
        WorkflowState.CANCEL_REQUESTED,
        WorkflowState.SUPERSEDED,
    },
    WorkflowState.CANCEL_REQUESTED: {WorkflowState.CANCELLED, WorkflowState.SUPERSEDED},
}


class WorkflowConflict(Exception):
    pass


@dataclass(frozen=True, slots=True)
class WorkflowReceipt:
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    state: WorkflowState
    version: int
    lease_owner: str | None
    lease_expires_at: datetime | None
    outcome: str | None


class DurableWorkflow:
    def __init__(
        self,
        store: SqliteCheckpointStore,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._store = store
        self._now = now

    def start(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        idempotency_key: str,
    ) -> WorkflowReceipt:
        existing = self._restore(tenant_id, run_id)
        if existing is not None:
            if (
                existing.execution_identity_hash == execution_identity_hash
                and existing.metadata.get("repository_id") == repository_id
                and existing.metadata.get("start_key") == idempotency_key
            ):
                return self._receipt(existing)
            raise WorkflowConflict()
        checkpoint = WorkflowCheckpoint(
            tenant_id,
            run_id,
            execution_identity_hash,
            WorkflowState.QUEUED.value,
            1,
            {
                "repository_id": repository_id,
                "start_key": idempotency_key,
                "lease_owner": None,
                "lease_until": None,
                "outcome": None,
            },
        )
        try:
            return self._receipt(self._store.save(checkpoint, None))
        except CheckpointConflict as error:
            existing = self._restore(tenant_id, run_id)
            if (
                existing is not None
                and existing.execution_identity_hash == execution_identity_hash
                and existing.metadata.get("repository_id") == repository_id
                and existing.metadata.get("start_key") == idempotency_key
            ):
                return self._receipt(existing)
            raise WorkflowConflict() from error

    def claim(
        self,
        *,
        tenant_id: str,
        run_id: str,
        worker_id: str,
        identity_hash: str,
        lease_seconds: int,
        idempotency_key: str,
    ) -> WorkflowReceipt:
        current = self._require(tenant_id, run_id, identity_hash)
        if current.state in _TERMINAL or current.state is WorkflowState.CANCEL_REQUESTED:
            return self._receipt(current)
        now = self._now()
        expires = _parse_time(current.metadata.get("lease_until"))
        if (
            current.metadata.get("claim_key") == idempotency_key
            and current.metadata.get("lease_owner") == worker_id
            and expires is not None
            and expires > now
        ):
            return self._receipt(current)
        if (
            current.state is WorkflowState.CLAIMED
            and expires is not None
            and expires > now
        ):
            raise WorkflowConflict()
        return self._transition(
            current,
            WorkflowState.CLAIMED,
            {
                "lease_owner": worker_id,
                "lease_until": (self._now() + timedelta(seconds=lease_seconds)).isoformat(),
                "claim_key": idempotency_key,
            },
        )

    def heartbeat(
        self, *, tenant_id: str, run_id: str, worker_id: str, identity_hash: str, lease_seconds: int
    ) -> WorkflowReceipt:
        current = self._require(tenant_id, run_id, identity_hash)
        if current.state in {WorkflowState.CANCEL_REQUESTED, WorkflowState.SUPERSEDED} | _TERMINAL:
            return self._receipt(current)
        if (
            current.metadata.get("lease_owner") != worker_id
            or (_parse_time(current.metadata.get("lease_until")) or self._now()) <= self._now()
        ):
            raise WorkflowConflict()
        return self._transition(
            current,
            WorkflowState.RUNNING,
            {"lease_until": (self._now() + timedelta(seconds=lease_seconds)).isoformat()},
        )

    def request_cancel(self, *, tenant_id: str, run_id: str, identity_hash: str) -> WorkflowReceipt:
        current = self._require(tenant_id, run_id, identity_hash)
        return (
            self._receipt(current)
            if current.state in _TERMINAL
            else self._transition(current, WorkflowState.CANCEL_REQUESTED, {})
        )

    def supersede(self, *, tenant_id: str, run_id: str, identity_hash: str) -> WorkflowReceipt:
        current = self._require(tenant_id, run_id, identity_hash)
        return (
            self._receipt(current)
            if current.state is WorkflowState.SUPERSEDED
            else self._transition(
                current, WorkflowState.SUPERSEDED, {"lease_owner": None, "lease_until": None}
            )
        )

    def complete(
        self, *, tenant_id: str, run_id: str, worker_id: str, identity_hash: str, outcome: str
    ) -> WorkflowReceipt:
        current = self._require(tenant_id, run_id, identity_hash)
        if current.state in _TERMINAL:
            if current.metadata.get("outcome") == outcome:
                return self._receipt(current)
            raise WorkflowConflict()
        expires = _parse_time(current.metadata.get("lease_until"))
        if (
            current.metadata.get("lease_owner") != worker_id
            or expires is None
            or expires <= self._now()
        ):
            raise WorkflowConflict()
        target = {
            "PASS": WorkflowState.SUCCEEDED,
            "FAIL": WorkflowState.FAILED,
            "INDETERMINATE": WorkflowState.INDETERMINATE,
            "CANCELLED": WorkflowState.CANCELLED,
        }.get(outcome)
        if target is None or (
            current.state is WorkflowState.CANCEL_REQUESTED
            and target is not WorkflowState.CANCELLED
        ):
            raise WorkflowConflict()
        return self._transition(
            current, target, {"outcome": outcome, "lease_owner": None, "lease_until": None}
        )

    def resume(self, *, tenant_id: str, run_id: str, identity_hash: str) -> WorkflowReceipt:
        return self._receipt(self._require(tenant_id, run_id, identity_hash))

    def publication_allowed(
        self,
        *,
        tenant_id: str,
        run_id: str,
        identity_hash: str,
        current_head_sha: str,
        stored_head_sha: str,
    ) -> bool:
        receipt = self._require(tenant_id, run_id, identity_hash)
        return receipt.state is WorkflowState.SUCCEEDED and current_head_sha == stored_head_sha

    def _require(self, tenant_id: str, run_id: str, identity_hash: str) -> WorkflowCheckpoint:
        checkpoint = self._restore(tenant_id, run_id)
        if checkpoint is None or checkpoint.execution_identity_hash != identity_hash:
            raise WorkflowConflict()
        return checkpoint

    def _restore(self, tenant_id: str, run_id: str) -> WorkflowCheckpoint | None:
        return self._store.load(tenant_id, run_id)

    def _transition(
        self, current: WorkflowCheckpoint, state: WorkflowState, changes: dict[str, object]
    ) -> WorkflowReceipt:
        old = WorkflowState(current.state)
        if state not in _LEGAL.get(old, set()):
            raise WorkflowConflict()
        metadata = {**current.metadata, **changes}
        next_value = WorkflowCheckpoint(
            current.tenant_id,
            current.run_id,
            current.execution_identity_hash,
            state.value,
            current.version + 1,
            metadata,
        )
        try:
            return self._receipt(self._store.save(next_value, current.version))
        except CheckpointConflict as error:
            raise WorkflowConflict() from error

    def _receipt(self, checkpoint: WorkflowCheckpoint) -> WorkflowReceipt:
        lease_owner = checkpoint.metadata.get("lease_owner")
        outcome = checkpoint.metadata.get("outcome")
        return WorkflowReceipt(
            checkpoint.tenant_id,
            str(checkpoint.metadata["repository_id"]),
            checkpoint.run_id,
            checkpoint.execution_identity_hash,
            WorkflowState(checkpoint.state),
            checkpoint.version,
            lease_owner if isinstance(lease_owner, str) else None,
            _parse_time(checkpoint.metadata.get("lease_until")),
            outcome if isinstance(outcome, str) else None,
        )


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None
