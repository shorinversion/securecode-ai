"""P6.7 approval separation and waiver scope controls."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from securecode_ai.server.approvals import (
    ApprovalConflict,
    ApprovalLedger,
    ApprovalRequest,
    ApprovalState,
)
from securecode_ai.server.waivers import WaiverRecord, WaiverScope

NOW = datetime(2026, 9, 19, tzinfo=UTC)


def test_requester_cannot_approve_and_a_granted_other_actor_can() -> None:
    ledger = ApprovalLedger(now=lambda: NOW)
    request = ApprovalRequest(
        "approval",
        "tenant",
        "repo",
        "run",
        "finding",
        "a" * 64,
        "requester",
        NOW + timedelta(days=1),
        1,
    )
    ledger.request(request, idempotency_key="create")
    with pytest.raises(ApprovalConflict):
        ledger.decide(
            approval_id="approval",
            tenant_id="tenant",
            actor_id="requester",
            approver_granted=True,
            expected_version=1,
            approve=True,
            reason_code="RISK_ACCEPTED",
            rationale="bounded",
            idempotency_key="decision",
        )
    result = ledger.decide(
        approval_id="approval",
        tenant_id="tenant",
        actor_id="approver",
        approver_granted=True,
        expected_version=1,
        approve=True,
        reason_code="RISK_ACCEPTED",
        rationale="bounded",
        idempotency_key="decision",
    )
    assert result.state is ApprovalState.APPROVED


def test_waiver_scope_refuses_stale_identity() -> None:
    scope = WaiverScope("tenant", "repo", "run", "a" * 64, finding_fingerprint="b" * 64)
    waiver = WaiverRecord("w", scope, NOW + timedelta(days=1), "approval", "c" * 64)
    assert waiver.applies(
        tenant_id="tenant", repository_id="repo", run_id="run", identity_hash="a" * 64, now=NOW
    )
    assert not waiver.applies(
        tenant_id="tenant", repository_id="repo", run_id="run", identity_hash="d" * 64, now=NOW
    )
