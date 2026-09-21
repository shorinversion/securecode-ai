"""P6.7 EvidencePackage egress controls."""

from __future__ import annotations

import pytest
from securecode_ai.server.evidence_egress import DataClass, EgressDenied, EgressPolicy, authorize
from securecode_ai.server.evidence_packages import (
    EvidenceItem,
    EvidencePackageRegistry,
)


def test_no_code_egress_only_allows_source_free_manifest_metadata() -> None:
    policy = EgressPolicy("dest", "profile", "cap")
    auth = authorize(
        policy,
        tenant_id="t",
        repository_id="r",
        run_id="run",
        execution_identity_hash="a" * 64,
        destination_id="dest",
        profile_id="profile",
        capability_id="cap",
    )
    registry = EvidencePackageRegistry()
    package = registry.prepare(
        idempotency_key="key",
        authorization=auth,
        policy=policy,
        items=(
            EvidenceItem(
                "receipt",
                DataClass.DC1_INTERNAL_METADATA,
                "b" * 64,
                10,
                "application/json",
                "receipt",
            ),
        ),
    )
    assert "payload" not in repr(package.receipt()).lower()
    with pytest.raises(EgressDenied):
        registry.prepare(
            idempotency_key="raw",
            authorization=auth,
            policy=policy,
            items=(
                EvidenceItem(
                    "source", DataClass.DC3_RAW_SOURCE, "c" * 64, 1, "text/plain", "prompt"
                ),
            ),
        )


def test_identity_or_replay_divergence_fails_closed() -> None:
    policy = EgressPolicy("dest", "profile", "cap")
    with pytest.raises(EgressDenied):
        authorize(
            policy,
            tenant_id="t",
            repository_id="r",
            run_id="run",
            execution_identity_hash="x",
            destination_id="dest",
            profile_id="profile",
            capability_id="cap",
        )
