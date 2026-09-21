"""P6.11 fail-closed enterprise composition."""

from __future__ import annotations

from securecode_ai.server.audit_log import AuditLog
from securecode_ai.server.checkpoints import SqliteCheckpointStore
from securecode_ai.server.enterprise import EnterpriseOutcome
from securecode_ai.server.enterprise_service import EnterpriseService
from securecode_ai.server.evidence_egress import EgressPolicy
from securecode_ai.server.evidence_packages import EvidencePackageRegistry
from securecode_ai.server.identity import Principal, Role
from securecode_ai.server.policy_store import PolicyStore
from securecode_ai.server.profiles import RolloutMode, ScanProfile
from securecode_ai.server.workflow import DurableWorkflow


def test_admission_resolves_immutable_profile_without_publication() -> None:
    profiles = PolicyStore()
    profile = ScanProfile.build(
        tenant_id="t",
        profile_id="p",
        version=1,
        rollout=RolloutMode.ADVISORY,
        calibrated=False,
        content={},
    )
    profiles.create(profile, idempotency_key="profile")
    profiles.set_tenant_default(tenant_id="t", profile_id="p", version=1)
    service = EnterpriseService(
        profiles=profiles,
        workflow=DurableWorkflow(SqliteCheckpointStore.in_memory()),
        audit=AuditLog(),
        packages=EvidencePackageRegistry(),
        egress=EgressPolicy("dest", "profile", "cap"),
    )
    principal = Principal("auditor", "t", frozenset({Role.AUDITOR}), frozenset({"r"}))
    receipt = service.admit(
        principal=principal,
        repository_id="r",
        run_id="run",
        identity_hash="a" * 64,
        idempotency_key="run-key",
    )
    assert receipt.outcome is EnterpriseOutcome.ACCEPTED
    assert not receipt.published
