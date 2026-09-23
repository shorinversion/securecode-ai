"""P5.4 SHA-bound SCM admission and stale-publication contracts."""

from __future__ import annotations

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AuditRunOutcome,
    ComponentPin,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core.scm_run_state import (
    AdmissionDisposition,
    PublicationDisposition,
    SCMRunAdmissionRequest,
    SCMRunLifecycle,
    SCMRunState,
    SCMRunStateError,
    SCMRunStateErrorCode,
)

HEAD_A = "a" * 40
HEAD_B = "b" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64


def _pin(component_id: str, digest: str = HASH_A) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=component_id,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _identity(*, head_sha: str = HEAD_A, policy_hash: str = HASH_A) -> RunExecutionIdentity:
    shared = _pin("component", policy_hash)
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            scm_provider="github",
            repository_id="repository-1",
            head_sha=head_sha,
        ),
        stage_catalogue=shared,
        workflow=shared,
        policy=_pin("policy", policy_hash),
        configuration=shared,
        provider_profile=shared,
        capability_profile=shared,
        egress_profile=shared,
    )


def _request(
    delivery_id: str,
    *,
    identity: RunExecutionIdentity | None = None,
) -> SCMRunAdmissionRequest:
    selected = identity or _identity()
    return SCMRunAdmissionRequest(
        delivery_id=delivery_id,
        installation_id="installation-1",
        execution_identity=selected,
        authorized_head_sha=selected.repository_revision.head_sha,
    )


def test_exact_duplicate_delivery_starts_one_semantic_run() -> None:
    state = SCMRunState()
    request = _request("delivery-1")

    first = state.admit(request, current_head_sha=HEAD_A)
    duplicate = state.admit(request, current_head_sha=HEAD_A)

    assert first.disposition is AdmissionDisposition.ADMITTED
    assert duplicate.disposition is AdmissionDisposition.DUPLICATE
    assert duplicate.run_id == first.run_id
    assert duplicate.lifecycle is SCMRunLifecycle.ADMITTED


def test_delivery_or_semantic_replay_with_different_canonical_bytes_fails_closed() -> None:
    state = SCMRunState()
    first = _request("delivery-1")
    state.admit(first, current_head_sha=HEAD_A)

    with pytest.raises(SCMRunStateError) as delivery_error:
        state.admit(
            _request("delivery-1", identity=_identity(policy_hash=HASH_B)),
            current_head_sha=HEAD_A,
        )
    assert delivery_error.value.code is SCMRunStateErrorCode.DELIVERY_CONFLICT

    second = state.admit(
        _request("delivery-2", identity=_identity(policy_hash=HASH_B)), current_head_sha=HEAD_A
    )
    assert second.disposition is AdmissionDisposition.ADMITTED
    assert second.run_id != state.admit(first, current_head_sha=HEAD_A).run_id


def test_stale_admission_creates_no_run_and_returns_superseded_receipt() -> None:
    state = SCMRunState()

    stale = state.admit(_request("delivery-1"), current_head_sha=HEAD_B)

    assert stale.disposition is AdmissionDisposition.SUPERSEDED
    assert stale.lifecycle is SCMRunLifecycle.SUPERSEDED
    assert stale.state_version == 0
    with pytest.raises(SCMRunStateError) as error:
        state.authorize_publication(stale.run_id, current_head_sha=HEAD_B)
    assert error.value.code is SCMRunStateErrorCode.RUN_UNKNOWN


def test_stale_delivery_replay_stays_superseded_after_head_returns() -> None:
    state = SCMRunState()
    request = _request("delivery-1")

    stale = state.admit(request, current_head_sha=HEAD_B)
    replay = state.admit(request, current_head_sha=HEAD_A)

    assert stale.disposition is AdmissionDisposition.SUPERSEDED
    assert replay == stale
    with pytest.raises(SCMRunStateError) as error:
        state.authorize_publication(replay.run_id, current_head_sha=HEAD_A)
    assert error.value.code is SCMRunStateErrorCode.RUN_UNKNOWN


def test_new_head_supersedes_old_run_and_late_result_cannot_publish() -> None:
    state = SCMRunState()
    old = state.admit(_request("delivery-a"), current_head_sha=HEAD_A)
    current = state.admit(
        _request("delivery-b", identity=_identity(head_sha=HEAD_B)), current_head_sha=HEAD_B
    )

    assert current.superseded_run_ids == (old.run_id,)
    late = state.complete(old.run_id, AuditRunOutcome.PASS, current_head_sha=HEAD_B)
    authorized = state.authorize_publication(current.run_id, current_head_sha=HEAD_B)

    assert late.disposition is PublicationDisposition.SUPERSEDED
    assert late.outcome is AuditRunOutcome.SUPERSEDED
    assert authorized.disposition is PublicationDisposition.AUTHORIZED


def test_completion_is_idempotent_but_divergent_late_update_is_rejected() -> None:
    state = SCMRunState()
    admission = state.admit(_request("delivery-1"), current_head_sha=HEAD_A)

    first = state.complete(admission.run_id, AuditRunOutcome.INDETERMINATE, current_head_sha=HEAD_A)
    duplicate = state.complete(
        admission.run_id, AuditRunOutcome.INDETERMINATE, current_head_sha=HEAD_A
    )

    assert first.disposition is PublicationDisposition.COMPLETED
    assert duplicate.disposition is PublicationDisposition.DUPLICATE
    with pytest.raises(SCMRunStateError) as error:
        state.complete(admission.run_id, AuditRunOutcome.PASS, current_head_sha=HEAD_A)
    assert error.value.code is SCMRunStateErrorCode.TRANSITION_CONFLICT
