from __future__ import annotations

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
