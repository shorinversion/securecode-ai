"""P6.3 workflow state and restart controls."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from securecode_ai.server.checkpoints import SqliteCheckpointStore
from securecode_ai.server.workflow import DurableWorkflow, WorkflowConflict, WorkflowState

HASH = "a" * 64


def _workflow() -> DurableWorkflow:
    return DurableWorkflow(
        SqliteCheckpointStore.in_memory(), now=lambda: datetime(2026, 9, 19, tzinfo=UTC)
    )


def test_exact_start_replays_but_identity_mutation_conflicts() -> None:
    flow = _workflow()
    first = flow.start(
        tenant_id="t",
        repository_id="r",
        run_id="run",
        execution_identity_hash=HASH,
        idempotency_key="key",
    )
    assert (
        flow.start(
            tenant_id="t",
            repository_id="r",
            run_id="run",
            execution_identity_hash=HASH,
            idempotency_key="key",
        )
        == first
    )
    with pytest.raises(WorkflowConflict):
        flow.start(
            tenant_id="t",
            repository_id="r",
            run_id="run",
            execution_identity_hash="b" * 64,
            idempotency_key="key",
        )


def test_claim_heartbeat_cancel_and_terminal_immutability() -> None:
    flow = _workflow()
    flow.start(
        tenant_id="t",
        repository_id="r",
        run_id="run",
        execution_identity_hash=HASH,
        idempotency_key="key",
    )
    assert (
        flow.claim(
            tenant_id="t",
            run_id="run",
            worker_id="w",
            identity_hash=HASH,
            lease_seconds=30,
            idempotency_key="claim",
        ).state
        is WorkflowState.CLAIMED
    )
    assert (
        flow.heartbeat(
            tenant_id="t", run_id="run", worker_id="w", identity_hash=HASH, lease_seconds=30
        ).state
        is WorkflowState.RUNNING
    )
    flow.request_cancel(tenant_id="t", run_id="run", identity_hash=HASH)
    assert (
        flow.complete(
            tenant_id="t", run_id="run", worker_id="w", identity_hash=HASH, outcome="CANCELLED"
        ).state
        is WorkflowState.CANCELLED
    )
    with pytest.raises(WorkflowConflict):
        flow.complete(
            tenant_id="t", run_id="run", worker_id="w", identity_hash=HASH, outcome="PASS"
        )


def test_publication_refuses_stale_head() -> None:
    flow = _workflow()
    flow.start(
        tenant_id="t",
        repository_id="r",
        run_id="run",
        execution_identity_hash=HASH,
        idempotency_key="key",
    )
    flow.claim(
        tenant_id="t",
        run_id="run",
        worker_id="w",
        identity_hash=HASH,
        lease_seconds=30,
        idempotency_key="claim",
    )
    flow.heartbeat(tenant_id="t", run_id="run", worker_id="w", identity_hash=HASH, lease_seconds=30)
    flow.complete(tenant_id="t", run_id="run", worker_id="w", identity_hash=HASH, outcome="PASS")
    assert not flow.publication_allowed(
        tenant_id="t",
        run_id="run",
        identity_hash=HASH,
        current_head_sha="b" * 40,
        stored_head_sha="a" * 40,
    )
