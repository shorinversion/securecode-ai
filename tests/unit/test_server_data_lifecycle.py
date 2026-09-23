from __future__ import annotations

import hashlib
import sqlite3

import pytest
from securecode_ai.server.data_lifecycle import DeletionRequest, LifecycleConflict, LifecycleLedger
from securecode_ai.server.migrations import apply_schema
from securecode_ai.server.residency import ResidencyDenied, ResidencyProfile, require_transfer


def test_deletion_requires_separate_approver_and_identity() -> None:
    connection = sqlite3.connect(":memory:")
    apply_schema(connection)
    ledger = LifecycleLedger(connection)
    ledger.request(
        DeletionRequest("d", "t", "a" * 64, "artifact", "b" * 64, "requester", 1),
        repository_id="repo",
        idempotency_key="k",
    )
    with pytest.raises(LifecycleConflict):
        ledger.approve(
            deletion_id="d",
            tenant_id="t",
            actor_id="requester",
            expected_version=1,
        )
    ledger.approve(
        deletion_id="d",
        tenant_id="t",
        actor_id="approver",
        expected_version=1,
    )
    assert ledger.execute(
        deletion_id="d",
        tenant_id="t",
        identity_hash="b" * 64,
        expected_version=2,
    ).executed


def test_residency_denies_unallowlisted_transfer() -> None:
    with pytest.raises(ResidencyDenied):
        require_transfer(
            ResidencyProfile("t", frozenset({"eu"})),
            source_region="eu",
            destination_region="us",
        )


def test_held_deletion_receipt_records_the_hold_actor() -> None:
    ledger = LifecycleLedger.in_memory()
    request = DeletionRequest("delete-1", "tenant", "a" * 64, "artifact", "b" * 64, "owner", 1)
    ledger.request(request, repository_id="repo", idempotency_key="request-key")
    ledger.set_legal_hold(
        deletion_id=request.deletion_id,
        tenant_id=request.tenant_id,
        identity_hash=request.identity_hash,
        actor_id="legal-admin",
        enabled=True,
        reason="active investigation",
        expected_version=1,
    )

    receipt = ledger.receipt(tenant_id=request.tenant_id, deletion_id=request.deletion_id)

    assert receipt.state == "HELD"
    assert receipt.actor_id_hash == hashlib.sha256(b"legal-admin").hexdigest()


def test_releasing_a_hold_requires_a_fresh_deletion_approval() -> None:
    ledger = LifecycleLedger.in_memory()
    request = DeletionRequest("delete-held", "tenant", "a" * 64, "artifact", "b" * 64, "owner", 1)
    ledger.request(request, repository_id="repo", idempotency_key="request-key")
    approved = ledger.approve(
        deletion_id=request.deletion_id,
        tenant_id=request.tenant_id,
        actor_id="approver-one",
        expected_version=request.version,
    )
    held = ledger.set_legal_hold(
        deletion_id=request.deletion_id,
        tenant_id=request.tenant_id,
        identity_hash=request.identity_hash,
        actor_id="legal-admin",
        enabled=True,
        reason="active investigation",
        expected_version=approved.version,
    )
    released = ledger.set_legal_hold(
        deletion_id=request.deletion_id,
        tenant_id=request.tenant_id,
        identity_hash=request.identity_hash,
        actor_id="legal-admin",
        enabled=False,
        reason="investigation closed",
        expected_version=held.version,
    )

    assert held.approved_by is None
    assert released.approved_by is None
    with pytest.raises(LifecycleConflict, match="deletion cannot be executed"):
        ledger.execute(
            deletion_id=request.deletion_id,
            tenant_id=request.tenant_id,
            identity_hash=request.identity_hash,
            expected_version=released.version,
        )
    reapproved = ledger.approve(
        deletion_id=request.deletion_id,
        tenant_id=request.tenant_id,
        actor_id="approver-two",
        expected_version=released.version,
    )
    assert ledger.execute(
        deletion_id=request.deletion_id,
        tenant_id=request.tenant_id,
        identity_hash=request.identity_hash,
        expected_version=reapproved.version,
    ).executed


def test_inconsistent_persisted_hold_and_execution_state_fails_closed() -> None:
    ledger = LifecycleLedger.in_memory()
    request = DeletionRequest("corrupt-state", "tenant", "a" * 64, "artifact", "b" * 64, "owner", 1)
    ledger.request(request, repository_id="repo", idempotency_key="request-key")
    ledger._connection.execute(
        """UPDATE lifecycle_deletions
           SET approved_by='approver', approved_at='2026-01-01T00:00:00+00:00',
               executed=1, legal_hold=1
           WHERE tenant_id=? AND deletion_id=?""",
        (request.tenant_id, request.deletion_id),
    )
    ledger._connection.commit()

    with pytest.raises(LifecycleConflict, match="lifecycle state is inconsistent"):
        ledger.receipt(tenant_id=request.tenant_id, deletion_id=request.deletion_id)


@pytest.mark.parametrize("operation", ("hold", "execute", "receipt"))
def test_lifecycle_operations_reject_invalid_deletion_ids(operation: str) -> None:
    ledger = LifecycleLedger.in_memory()

    with pytest.raises(LifecycleConflict, match="deletion_id is invalid"):
        if operation == "hold":
            ledger.set_legal_hold(
                deletion_id="",
                tenant_id="tenant",
                identity_hash="a" * 64,
                actor_id="admin",
                enabled=True,
                reason="incident",
                expected_version=1,
            )
        elif operation == "execute":
            ledger.execute(
                deletion_id="",
                tenant_id="tenant",
                identity_hash="a" * 64,
                expected_version=1,
            )
        else:
            ledger.receipt(tenant_id="tenant", deletion_id="")
