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
