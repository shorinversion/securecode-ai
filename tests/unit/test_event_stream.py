"""Append-only, idempotency, hash-chain and replay tests for P1.6."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TypedDict

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ActorRef,
    ActorType,
    AnalysisHealth,
    ArtifactRef,
    AuditEvent,
    AuditRun,
    AuditRunOutcome,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    ComponentPin,
    ContractExtension,
    CoverageManifest,
    CoverageScenario,
    CoverageStatus,
    CoverageUnit,
    DataClass,
    DiscoveryCandidate,
    DiscoveryLane,
    EventSafePayload,
    EventType,
    ExtensionDataClass,
    FindingGateState,
    LineageRef,
    ModelBudgetUsage,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    ProducerRef,
    RepositoryRevision,
    RunExecutionIdentity,
    derive_event_id,
    derive_idempotency_key,
)
from securecode_ai.core import (
    AppendDisposition,
    EventConflict,
    EventConflictCode,
    EventStream,
    rebuild_projection,
)


class WireArguments(TypedDict):
    schema_version: str


WIRE: WireArguments = {"schema_version": CONTRACT_SCHEMA_VERSION}
NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
HEAD_SHA = "a" * 40
BASE_SHA = "b" * 40
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def _pin(name: str, digest: str = HASH_A) -> ComponentPin:
    return ComponentPin(
        **WIRE,
        component_id="core-mvp-0.2.0" if name == "catalogue" else name,
        component_version="0.2.0" if name == "catalogue" else "1.0.0",
        content_sha256=(
            "adad2e05fc822485f45ac164299462d360ecb015327b84d09c064a697c193d1d"
            if name == "catalogue"
            else digest
        ),
    )


def _identity() -> RunExecutionIdentity:
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            **WIRE,
            tenant_id="tenant-1",
            scm_provider="github",
            repository_id="repo-1",
            head_sha=HEAD_SHA,
            base_sha=BASE_SHA,
        ),
        stage_catalogue=_pin("catalogue"),
        workflow=_pin("workflow", HASH_B),
        policy=_pin("policy", HASH_C),
        configuration=_pin("configuration", "d" * 64),
        provider_profile=_pin("provider", "e" * 64),
        capability_profile=_pin("capability", "f" * 64),
        egress_profile=_pin("egress", "1" * 64),
    )


def _producer(name: str = "worker") -> ProducerRef:
    return ProducerRef(
        **WIRE,
        producer_id=name,
        producer_version="1.0.0",
        producer_sha256=HASH_B,
    )


def _budget() -> ModelBudgetUsage:
    return ModelBudgetUsage(
        **WIRE,
        token_limit=100,
        tokens_used=10,
        repository_call_limit=10,
        repository_calls_used=1,
        time_limit_ms=1000,
        elapsed_ms=10,
    )


def _discovery_receipt(
    *,
    receipt_id: str = "receipt-discovery",
    candidate_ids: tuple[str, ...] = (),
) -> ModelDiscoveryReceipt:
    return ModelDiscoveryReceipt(
        **WIRE,
        receipt_id=receipt_id,
        tenant_id="tenant-1",
        head_sha=HEAD_SHA,
        scope_sha256=HASH_A,
        model_profile=_pin("model"),
        prompt=_pin("prompt"),
        budget_usage=_budget(),
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        input_sha256=HASH_B,
        output_sha256=HASH_C,
        candidate_ids=candidate_ids,
    )


def _unit(
    stage_id: str,
    *,
    subject_id: str | None = None,
    receipt_id: str | None = None,
    model: bool = False,
) -> CoverageUnit:
    return CoverageUnit(
        **WIRE,
        coverage_unit_id=(
            f"unit-{stage_id}" if subject_id is None else f"unit-{stage_id}-{subject_id}"
        ),
        stage_id=stage_id,
        subject_id=subject_id,
        required=True,
        applicable=True,
        coverage_status=CoverageStatus.COMPLETED,
        producer_version="1.0.0",
        input_hashes=(HASH_A,),
        output_hashes=(HASH_B,),
        model_call_status=ModelCallStatus.SUCCEEDED if model else None,
        schema_valid_result=True if model else None,
        receipt_id=receipt_id,
    )


def _clean_manifest(identity: RunExecutionIdentity) -> CoverageManifest:
    stages = (
        "intake",
        "language_discovery",
        "deterministic_analysis",
        "model_native_discovery",
        "normalization",
        "coverage_guard",
        "reporting",
    )
    units = tuple(
        _unit(
            stage,
            receipt_id="receipt-discovery" if stage == "model_native_discovery" else None,
            model=stage == "model_native_discovery",
        )
        for stage in stages
    )
    return CoverageManifest(
        **WIRE,
        catalogue=_pin("catalogue"),
        execution_identity_hash=identity.execution_identity_hash,
        scenario=CoverageScenario.CLEAN_NO_CANDIDATE,
        required_unit_ids=tuple(unit.coverage_unit_id for unit in units),
        units=units,
        model_discovery_receipts=(_discovery_receipt(),),
        coverage_complete=True,
    )


def _candidate(*, version: int = 1, head_sha: str = HEAD_SHA) -> DiscoveryCandidate:
    lineages = tuple(
        LineageRef(
            **WIRE,
            lineage_id=f"lineage-{lane.value}",
            lane=lane,
            producer=_producer(lane.value),
            root_cause_fingerprint=HASH_C,
            input_signal_ids=(f"signal-{lane.value}",),
            evidence_ids=(f"evidence-{lane.value}",),
        )
        for lane in (DiscoveryLane.DETERMINISTIC, DiscoveryLane.MODEL_NATIVE)
    )
    return DiscoveryCandidate(
        **WIRE,
        candidate_id="candidate-1",
        tenant_id="tenant-1",
        candidate_version=version,
        head_sha=head_sha,
        root_cause_fingerprint=HASH_C,
        candidate_origin=CandidateOrigin.HYBRID,
        lineage=lineages,
        evidence_ids=("evidence-deterministic", "evidence-model_native"),
    )


def _deterministic_candidate() -> DiscoveryCandidate:
    hybrid = _candidate()
    deterministic_lineage = hybrid.lineage[0]
    return DiscoveryCandidate(
        **WIRE,
        candidate_id=hybrid.candidate_id,
        tenant_id=hybrid.tenant_id,
        candidate_version=hybrid.candidate_version,
        head_sha=hybrid.head_sha,
        root_cause_fingerprint=hybrid.root_cause_fingerprint,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        lineage=(deterministic_lineage,),
        evidence_ids=deterministic_lineage.evidence_ids,
    )


def _interpretation(*, version: int = 1) -> CandidateInterpretationReceipt:
    return CandidateInterpretationReceipt(
        **WIRE,
        receipt_id=f"receipt-interpretation-{version}",
        tenant_id="tenant-1",
        candidate_id="candidate-1",
        candidate_version=version,
        head_sha=HEAD_SHA,
        auditor=_pin("auditor"),
        model_profile=_pin("model"),
        prompt=_pin("auditor-prompt"),
        evidence_sha256=HASH_A,
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        verdict_ref="verdict-1",
        input_sha256=HASH_B,
        output_sha256=HASH_C,
    )


def _candidate_manifest(
    identity: RunExecutionIdentity, *, candidate_version: int = 1
) -> CoverageManifest:
    candidate = _candidate(version=candidate_version)
    interpretation = _interpretation(version=candidate_version)
    stages = (
        "intake",
        "language_discovery",
        "deterministic_analysis",
        "model_native_discovery",
        "normalization",
        "evidence_graph",
        "coverage_guard",
        "reporting",
    )
    units = (
        *(
            _unit(
                stage,
                receipt_id="receipt-discovery" if stage == "model_native_discovery" else None,
                model=stage == "model_native_discovery",
            )
            for stage in stages
        ),
        _unit(
            "auditor_investigation",
            subject_id=candidate.candidate_id,
            receipt_id=interpretation.receipt_id,
            model=True,
        ),
        _unit(
            "skeptic_review",
            subject_id=candidate.candidate_id,
            receipt_id="receipt-skeptic",
            model=True,
        ),
        _unit("finding_gate", subject_id=candidate.candidate_id),
    )
    return CoverageManifest(
        **WIRE,
        catalogue=_pin("catalogue"),
        execution_identity_hash=identity.execution_identity_hash,
        scenario=CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR,
        required_unit_ids=tuple(unit.coverage_unit_id for unit in units),
        units=units,
        discovery_candidates=(candidate,),
        model_discovery_receipts=(_discovery_receipt(candidate_ids=(candidate.candidate_id,)),),
        candidate_interpretation_receipts=(interpretation,),
        coverage_complete=True,
    )


def _audit_run(identity: RunExecutionIdentity, manifest: CoverageManifest) -> AuditRun:
    return AuditRun(
        **WIRE,
        run_id="run-1",
        execution_identity=identity,
        current_head_sha=HEAD_SHA,
        audit_outcome=AuditRunOutcome.PASS,
        analysis_health=AnalysisHealth.HEALTHY,
        finding_gate_state=FindingGateState.CLEAN,
        coverage_manifest=manifest,
        publication_preconditions_met=True,
        created_at=NOW,
        completed_at=NOW + timedelta(seconds=5),
    )


def _event(
    *,
    identity: RunExecutionIdentity,
    sequence: int,
    previous_event_hash: str | None,
    operation_hash: str,
    event_type: EventType = EventType.RUN_STARTED,
    payload: EventSafePayload | None = None,
    payload_ref: ArtifactRef | None = None,
    tenant_id: str = "tenant-1",
    run_id: str = "run-1",
    occurred_at: datetime = NOW,
) -> AuditEvent:
    key = derive_idempotency_key(
        tenant_id=tenant_id,
        run_id=run_id,
        operation_sha256=operation_hash,
    )
    safe_payload = (
        None if payload_ref is not None else payload or EventSafePayload(**WIRE, head_sha=HEAD_SHA)
    )
    return AuditEvent(
        **WIRE,
        event_id=derive_event_id(tenant_id=tenant_id, run_id=run_id, idempotency_key=key),
        event_type=event_type,
        event_version="1.0.0",
        occurred_at=occurred_at,
        recorded_at=NOW,
        tenant_id=tenant_id,
        run_id=run_id,
        sequence=sequence,
        previous_event_hash=previous_event_hash,
        actor=ActorRef(**WIRE, actor_id="worker-1", actor_type=ActorType.WORKER),
        correlation_id="correlation-1",
        causation_id=None if sequence == 1 else f"event-{sequence - 1}",
        idempotency_key=key,
        execution_identity_hash=identity.execution_identity_hash,
        data_class=(
            payload_ref.data_class
            if payload_ref is not None
            else DataClass.CONFIDENTIAL_SECURITY
            if safe_payload is not None and safe_payload.carries_security_state
            else DataClass.INTERNAL_METADATA
        ),
        payload_ref=payload_ref,
        safe_payload=safe_payload,
    )


def _empty_stream(identity: RunExecutionIdentity) -> EventStream:
    return EventStream(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
    )


def _normalized_candidate_event(
    identity: RunExecutionIdentity,
    candidate: DiscoveryCandidate,
    *,
    sequence: int,
    previous_event_hash: str | None,
    operation_hash: str,
) -> AuditEvent:
    lane = {
        CandidateOrigin.DETERMINISTIC: DiscoveryLane.DETERMINISTIC,
        CandidateOrigin.MODEL_NATIVE: DiscoveryLane.MODEL_NATIVE,
        CandidateOrigin.HYBRID: None,
    }[candidate.candidate_origin]
    return _event(
        identity=identity,
        sequence=sequence,
        previous_event_hash=previous_event_hash,
        operation_hash=operation_hash,
        event_type=EventType.CANDIDATE_NORMALIZED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=candidate.head_sha,
            producer=_producer("normalizer"),
            lane=lane,
            candidate_origin=candidate.candidate_origin,
            input_hashes=(HASH_A,),
            output_hashes=(HASH_B,),
            terminal_reason_code="CANDIDATE_NORMALIZED",
            discovery_candidate=candidate,
        ),
    )


def test_append_is_immutable_and_exact_replay_is_accepted_once() -> None:
    identity = _identity()
    empty = _empty_stream(identity)
    event = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
    )
    stream, appended = empty.append(event)
    replayed, replay = stream.append(event)
    assert empty.events == ()
    assert stream.events == (event,)
    assert replayed is stream
    assert appended.disposition is AppendDisposition.APPENDED
    assert replay.disposition is AppendDisposition.REPLAYED
    assert appended.event_hash == event.canonical_hash()


def test_divergent_duplicate_event_or_idempotency_key_conflicts() -> None:
    identity = _identity()
    event = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
    )
    stream, _ = _empty_stream(identity).append(event)
    divergent = event.model_copy(update={"recorded_at": NOW + timedelta(seconds=1)})
    with pytest.raises(EventConflict) as raised:
        stream.append(divergent)
    assert raised.value.code is EventConflictCode.DUPLICATE_MISMATCH


@pytest.mark.parametrize(
    ("sequence", "previous", "code"),
    [
        (3, HASH_A, EventConflictCode.SEQUENCE_GAP),
        (2, HASH_A, EventConflictCode.PREVIOUS_HASH_MISMATCH),
    ],
)
def test_gap_and_previous_hash_substitution_are_rejected(
    sequence: int, previous: str, code: EventConflictCode
) -> None:
    identity = _identity()
    first = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
    )
    stream, _ = _empty_stream(identity).append(first)
    bad = _event(
        identity=identity,
        sequence=sequence,
        previous_event_hash=previous,
        operation_hash=HASH_B,
    )
    with pytest.raises(EventConflict) as raised:
        stream.append(bad)
    assert raised.value.code is code


@pytest.mark.parametrize("scope", ["tenant", "run", "identity"])
def test_cross_scope_append_is_rejected(scope: str) -> None:
    identity = _identity()
    other_identity = RunExecutionIdentity.build(
        repository_revision=identity.repository_revision,
        stage_catalogue=identity.stage_catalogue,
        workflow=identity.workflow,
        policy=identity.policy,
        configuration=identity.configuration,
        provider_profile=_pin("other-provider", "2" * 64),
        capability_profile=identity.capability_profile,
        egress_profile=identity.egress_profile,
    )
    event = _event(
        identity=other_identity if scope == "identity" else identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
        tenant_id="tenant-2" if scope == "tenant" else "tenant-1",
        run_id="run-2" if scope == "run" else "run-1",
    )
    with pytest.raises(EventConflict) as raised:
        _empty_stream(identity).append(event)
    assert raised.value.code is EventConflictCode.STREAM_SCOPE_MISMATCH


def test_event_revision_must_equal_the_admitted_stream_head() -> None:
    identity = _identity()
    candidate = _candidate(head_sha="f" * 40)
    event = _normalized_candidate_event(
        identity,
        candidate,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
    )
    with pytest.raises(EventConflict, match="admitted stream HEAD"):
        _empty_stream(identity).append(event)


def test_stream_revalidates_the_complete_admitted_execution_identity() -> None:
    identity = _identity()
    forged_revision = identity.repository_revision.model_copy(update={"head_sha": "f" * 40})
    forged_identity = identity.model_copy(update={"repository_revision": forged_revision})
    with pytest.raises(EventConflict) as forged:
        EventStream(
            tenant_id="tenant-1",
            run_id="run-1",
            execution_identity=forged_identity,
        )
    assert forged.value.code is EventConflictCode.INVALID_EVENT

    other_tenant_revision = identity.repository_revision.model_copy(
        update={"tenant_id": "tenant-2"}
    )
    other_tenant_identity = RunExecutionIdentity.build(
        repository_revision=other_tenant_revision,
        stage_catalogue=identity.stage_catalogue,
        workflow=identity.workflow,
        policy=identity.policy,
        configuration=identity.configuration,
        provider_profile=identity.provider_profile,
        capability_profile=identity.capability_profile,
        egress_profile=identity.egress_profile,
    )
    with pytest.raises(EventConflict) as cross_tenant:
        EventStream(
            tenant_id="tenant-1",
            run_id="run-1",
            execution_identity=other_tenant_identity,
        )
    assert cross_tenant.value.code is EventConflictCode.STREAM_SCOPE_MISMATCH


def test_replay_rejects_reorder_and_event_stream_has_no_mutation_api() -> None:
    identity = _identity()
    first = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
    )
    second = _event(
        identity=identity,
        sequence=2,
        previous_event_hash=first.canonical_hash(),
        operation_hash=HASH_B,
    )
    restored = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(first, second),
    )
    assert restored.events == (first, second)
    with pytest.raises(EventConflict):
        EventStream.replay(
            tenant_id="tenant-1",
            run_id="run-1",
            execution_identity=identity,
            events=(second, first),
        )
    assert not hasattr(restored, "update")
    assert not hasattr(restored, "delete")


def test_direct_stream_constructor_and_model_copy_cannot_bypass_validation() -> None:
    identity = _identity()
    valid = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
    )
    forged = valid.model_copy(update={"sequence": 2})
    with pytest.raises(EventConflict) as constructed:
        EventStream(
            tenant_id="tenant-1",
            run_id="run-1",
            execution_identity=identity,
            events=(forged,),
        )
    assert constructed.value.code is EventConflictCode.INVALID_EVENT
    with pytest.raises(EventConflict) as appended:
        _empty_stream(identity).append(forged)
    assert appended.value.code is EventConflictCode.INVALID_EVENT

    extensions = tuple(
        ContractExtension(
            namespace=namespace,
            extension_version="0.2.0",
            data_class=ExtensionDataClass.INTERNAL_METADATA,
            tenant_id="tenant-1",
            content_id=f"content-{namespace}",
            payload_sha256=digest,
            payload_size_bytes=1,
        )
        for namespace, digest in (("vendor.first", HASH_A), ("vendor.second", HASH_B))
    )
    canonical = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_B,
        payload=EventSafePayload(**WIRE, extensions=extensions, head_sha=HEAD_SHA),
    )
    assert canonical.safe_payload is not None
    reversed_payload = canonical.safe_payload.model_copy(
        update={"extensions": tuple(reversed(canonical.safe_payload.extensions))}
    )
    uncanonical = canonical.model_copy(update={"safe_payload": reversed_payload})
    restored = EventStream(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(uncanonical,),
    )
    assert restored.events == (canonical,)


def test_skewed_timestamps_do_not_change_hash_chain_order() -> None:
    identity = _identity()
    first = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
        occurred_at=NOW + timedelta(days=2),
    )
    second = _event(
        identity=identity,
        sequence=2,
        previous_event_hash=first.canonical_hash(),
        operation_hash=HASH_B,
        occurred_at=NOW - timedelta(days=2),
    )
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(first, second),
    )
    assert [event.sequence for event in stream.events] == [1, 2]


def test_candidate_normalization_requires_closed_provenance_and_exact_head() -> None:
    identity = _identity()
    candidate = _candidate()
    base_payload = EventSafePayload(
        **WIRE,
        head_sha=HEAD_SHA,
        producer=_producer("normalizer"),
        candidate_origin=candidate.candidate_origin,
        input_hashes=(HASH_A,),
        output_hashes=(HASH_B,),
        terminal_reason_code="CANDIDATE_NORMALIZED",
        discovery_candidate=candidate,
    )
    event = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
        event_type=EventType.CANDIDATE_NORMALIZED,
        payload=base_payload,
    )
    assert event.safe_payload == base_payload
    for update, message in (
        ({"candidate_origin": None}, "explicit candidate_origin"),
        ({"producer": None}, "requires producer"),
        ({"head_sha": "f" * 40}, "bind to payload head_sha"),
        ({"lane": DiscoveryLane.DETERMINISTIC}, "lane must match"),
    ):
        payload = EventSafePayload.model_validate(
            {**base_payload.model_dump(mode="python"), **update}
        )
        with pytest.raises(ValueError, match=message):
            _event(
                identity=identity,
                sequence=1,
                previous_event_hash=None,
                operation_hash=HASH_A,
                event_type=EventType.CANDIDATE_NORMALIZED,
                payload=payload,
            )


def test_discovery_lane_and_receipt_semantics_are_fail_closed() -> None:
    identity = _identity()
    payload = EventSafePayload(
        **WIRE,
        head_sha=HEAD_SHA,
        producer=_producer("deterministic-scanner"),
        lane=DiscoveryLane.DETERMINISTIC,
        input_hashes=(HASH_B,),
        output_hashes=(HASH_A,),
        terminal_reason_code="COMPLETED_ZERO",
        model_discovery_receipt=_discovery_receipt(),
    )
    with pytest.raises(ValueError, match="cannot carry a model receipt"):
        _event(
            identity=identity,
            sequence=1,
            previous_event_hash=None,
            operation_hash=HASH_A,
            event_type=EventType.DISCOVERY_COMPLETED,
            payload=payload,
        )
    for output_hashes, reason, message in (
        ((HASH_A,), "COMPLETED_ZERO", "retain its receipt output hash"),
        ((HASH_C,), "CANDIDATES_RECORDED", "must exactly match"),
    ):
        model_payload = EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            producer=_producer("model-native"),
            lane=DiscoveryLane.MODEL_NATIVE,
            input_hashes=(HASH_B,),
            output_hashes=output_hashes,
            terminal_reason_code=reason,
            model_discovery_receipt=_discovery_receipt(),
        )
        with pytest.raises(ValueError, match=message):
            _event(
                identity=identity,
                sequence=1,
                previous_event_hash=None,
                operation_hash=HASH_A,
                event_type=EventType.DISCOVERY_COMPLETED,
                payload=model_payload,
            )


def test_typed_receipt_cannot_be_smuggled_through_unrelated_event() -> None:
    identity = _identity()
    payload = EventSafePayload(
        **WIRE,
        head_sha=HEAD_SHA,
        candidate_interpretation_receipt=_interpretation(),
    )
    with pytest.raises(ValueError, match="not permitted for event type RunStarted"):
        _event(
            identity=identity,
            sequence=1,
            previous_event_hash=None,
            operation_hash=HASH_A,
            event_type=EventType.RUN_STARTED,
            payload=payload,
        )


def test_golden_replay_reconstructs_coverage_and_terminal_run() -> None:
    identity = _identity()
    manifest = _clean_manifest(identity)
    audit_run = _audit_run(identity, manifest)
    discovery = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
        event_type=EventType.DISCOVERY_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            producer=_producer("model-native"),
            lane=DiscoveryLane.MODEL_NATIVE,
            input_hashes=(HASH_B,),
            output_hashes=(HASH_C,),
            terminal_reason_code="COMPLETED_ZERO",
            model_discovery_receipt=_discovery_receipt(),
        ),
    )
    coverage = _event(
        identity=identity,
        sequence=2,
        previous_event_hash=discovery.canonical_hash(),
        operation_hash=HASH_B,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest),
    )
    completed = _event(
        identity=identity,
        sequence=3,
        previous_event_hash=coverage.canonical_hash(),
        operation_hash=HASH_C,
        event_type=EventType.RUN_COMPLETED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, audit_run=audit_run),
    )
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(discovery, coverage, completed),
    )
    projection = rebuild_projection(stream)
    assert projection.coverage_manifest == manifest
    assert projection.audit_run == audit_run
    assert projection.model_discovery_receipts == (_discovery_receipt(),)
    assert projection.canonical_hash() == (
        "3cc44fd150f90fa618de1ada2b7c41f2994f7045a8ccee8f87609b13eb022d35"
    )


def test_normalized_candidate_cannot_be_dropped_from_clean_coverage() -> None:
    identity = _identity()
    manifest = _clean_manifest(identity)
    discovery = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
        event_type=EventType.DISCOVERY_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            producer=_producer("model-native"),
            lane=DiscoveryLane.MODEL_NATIVE,
            input_hashes=(HASH_B,),
            output_hashes=(HASH_C,),
            terminal_reason_code="COMPLETED_ZERO",
            model_discovery_receipt=_discovery_receipt(),
        ),
    )
    normalized = _normalized_candidate_event(
        identity,
        _deterministic_candidate(),
        sequence=2,
        previous_event_hash=discovery.canonical_hash(),
        operation_hash="d" * 64,
    )
    coverage = _event(
        identity=identity,
        sequence=3,
        previous_event_hash=normalized.canonical_hash(),
        operation_hash="e" * 64,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest),
    )
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(discovery, normalized, coverage),
    )
    with pytest.raises(EventConflict, match="normalized candidates"):
        rebuild_projection(stream)

    coverage_before_candidate = _event(
        identity=identity,
        sequence=2,
        previous_event_hash=discovery.canonical_hash(),
        operation_hash="f" * 64,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest),
    )
    late_candidate = _normalized_candidate_event(
        identity,
        _deterministic_candidate(),
        sequence=3,
        previous_event_hash=coverage_before_candidate.canonical_hash(),
        operation_hash="0" * 64,
    )
    completed = _event(
        identity=identity,
        sequence=4,
        previous_event_hash=late_candidate.canonical_hash(),
        operation_hash="1" * 64,
        event_type=EventType.RUN_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            audit_run=_audit_run(identity, manifest),
        ),
    )
    stale_stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(discovery, coverage_before_candidate, late_candidate, completed),
    )
    with pytest.raises(EventConflict, match="prior latest CoverageManifest"):
        rebuild_projection(stale_stream)


def test_coverage_accounts_for_every_recorded_model_discovery_receipt() -> None:
    identity = _identity()
    manifest = _clean_manifest(identity)

    def discovery_event(
        receipt: ModelDiscoveryReceipt,
        *,
        sequence: int,
        previous: str | None,
        operation: str,
    ) -> AuditEvent:
        return _event(
            identity=identity,
            sequence=sequence,
            previous_event_hash=previous,
            operation_hash=operation,
            event_type=EventType.DISCOVERY_COMPLETED,
            payload=EventSafePayload(
                **WIRE,
                head_sha=HEAD_SHA,
                producer=_producer("model-native"),
                lane=DiscoveryLane.MODEL_NATIVE,
                input_hashes=(HASH_B,),
                output_hashes=(HASH_C,),
                terminal_reason_code=(
                    "COMPLETED_ZERO" if receipt.is_completed_zero else "CANDIDATES_RECORDED"
                ),
                model_discovery_receipt=receipt,
            ),
        )

    first = discovery_event(
        _discovery_receipt(),
        sequence=1,
        previous=None,
        operation=HASH_A,
    )
    hidden = discovery_event(
        _discovery_receipt(
            receipt_id="receipt-hidden",
            candidate_ids=("candidate-hidden",),
        ),
        sequence=2,
        previous=first.canonical_hash(),
        operation="d" * 64,
    )
    coverage = _event(
        identity=identity,
        sequence=3,
        previous_event_hash=hidden.canonical_hash(),
        operation_hash="e" * 64,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest),
    )
    omitted_stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(first, hidden, coverage),
    )
    with pytest.raises(EventConflict, match="receipts"):
        rebuild_projection(omitted_stream)

    early_coverage = _event(
        identity=identity,
        sequence=2,
        previous_event_hash=first.canonical_hash(),
        operation_hash="f" * 64,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest),
    )
    late = discovery_event(
        _discovery_receipt(receipt_id="receipt-late"),
        sequence=3,
        previous=early_coverage.canonical_hash(),
        operation="0" * 64,
    )
    completed = _event(
        identity=identity,
        sequence=4,
        previous_event_hash=late.canonical_hash(),
        operation_hash="1" * 64,
        event_type=EventType.RUN_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            audit_run=_audit_run(identity, manifest),
        ),
    )
    stale_stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(first, early_coverage, late, completed),
    )
    with pytest.raises(EventConflict, match="prior latest CoverageManifest"):
        rebuild_projection(stale_stream)


@pytest.mark.parametrize(
    "late_type",
    [EventType.COVERAGE_UPDATED, EventType.RUN_STARTED, EventType.SCANNER_COMPLETED],
)
def test_analysis_state_cannot_change_after_run_completed(late_type: EventType) -> None:
    identity = _identity()
    manifest = _clean_manifest(identity)
    discovery = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
        event_type=EventType.DISCOVERY_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            producer=_producer("model-native"),
            lane=DiscoveryLane.MODEL_NATIVE,
            input_hashes=(HASH_B,),
            output_hashes=(HASH_C,),
            terminal_reason_code="COMPLETED_ZERO",
            model_discovery_receipt=_discovery_receipt(),
        ),
    )
    coverage = _event(
        identity=identity,
        sequence=2,
        previous_event_hash=discovery.canonical_hash(),
        operation_hash=HASH_B,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest),
    )
    completed = _event(
        identity=identity,
        sequence=3,
        previous_event_hash=coverage.canonical_hash(),
        operation_hash=HASH_C,
        event_type=EventType.RUN_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            audit_run=_audit_run(identity, manifest),
        ),
    )
    late_payload = (
        EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest)
        if late_type is EventType.COVERAGE_UPDATED
        else EventSafePayload(**WIRE, head_sha=HEAD_SHA)
    )
    late = _event(
        identity=identity,
        sequence=4,
        previous_event_hash=completed.canonical_hash(),
        operation_hash="d" * 64,
        event_type=late_type,
        payload=late_payload,
        payload_ref=(
            ArtifactRef(
                **WIRE,
                tenant_id="tenant-1",
                content_id="scanner-output",
                content_sha256="e" * 64,
                size_bytes=12,
                data_class=DataClass.CONFIDENTIAL_SOURCE,
            )
            if late_type is EventType.SCANNER_COMPLETED
            else None
        ),
    )
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(discovery, coverage, completed, late),
    )
    with pytest.raises(EventConflict, match="after RunCompleted"):
        rebuild_projection(stream)


def _candidate_projection_events(
    identity: RunExecutionIdentity,
    *,
    receipt: CandidateInterpretationReceipt | None,
) -> tuple[AuditEvent, ...]:
    manifest = _candidate_manifest(identity)
    discovery_receipt = manifest.model_discovery_receipts[0]
    discovery = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
        event_type=EventType.DISCOVERY_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            producer=_producer("model-native"),
            lane=DiscoveryLane.MODEL_NATIVE,
            input_hashes=(HASH_B,),
            output_hashes=(HASH_C,),
            terminal_reason_code="CANDIDATES_RECORDED",
            model_discovery_receipt=discovery_receipt,
        ),
    )
    normalized = _normalized_candidate_event(
        identity,
        manifest.discovery_candidates[0],
        sequence=2,
        previous_event_hash=discovery.canonical_hash(),
        operation_hash="d" * 64,
    )
    events: tuple[AuditEvent, ...] = (discovery, normalized)
    previous = normalized.canonical_hash()
    sequence = 3
    if receipt is not None:
        interpretation = _event(
            identity=identity,
            sequence=sequence,
            previous_event_hash=previous,
            operation_hash="e" * 64,
            event_type=EventType.CANDIDATE_INTERPRETATION_RECORDED,
            payload=EventSafePayload(
                **WIRE,
                head_sha=HEAD_SHA,
                candidate_interpretation_receipt=receipt,
            ),
        )
        events = (*events, interpretation)
        previous = interpretation.canonical_hash()
        sequence += 1
    coverage = _event(
        identity=identity,
        sequence=sequence,
        previous_event_hash=previous,
        operation_hash="0" * 64,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest),
    )
    return (*events, coverage)


def test_late_candidate_interpretation_cannot_leave_prior_coverage_current() -> None:
    identity = _identity()
    manifest = _candidate_manifest(identity)
    events = _candidate_projection_events(identity, receipt=_interpretation())
    coverage = events[-1]
    late_receipt = _interpretation().model_copy(update={"receipt_id": "receipt-late"})
    late = _event(
        identity=identity,
        sequence=len(events) + 1,
        previous_event_hash=coverage.canonical_hash(),
        operation_hash="2" * 64,
        event_type=EventType.CANDIDATE_INTERPRETATION_RECORDED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            candidate_interpretation_receipt=late_receipt,
        ),
    )
    completed = _event(
        identity=identity,
        sequence=len(events) + 2,
        previous_event_hash=late.canonical_hash(),
        operation_hash="3" * 64,
        event_type=EventType.RUN_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            audit_run=_audit_run(identity, manifest),
        ),
    )
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(*events, late, completed),
    )
    with pytest.raises(EventConflict, match="duplicate candidate interpretation"):
        rebuild_projection(stream)


@pytest.mark.parametrize("receipt", [None, _interpretation(version=2)])
def test_projection_rejects_missing_or_stale_candidate_interpretation(
    receipt: CandidateInterpretationReceipt | None,
) -> None:
    identity = _identity()
    events = _candidate_projection_events(identity, receipt=receipt)
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=events,
    )
    with pytest.raises(EventConflict) as raised:
        rebuild_projection(stream)
    assert raised.value.code is EventConflictCode.PROJECTION_CONFLICT


def test_projection_rejects_duplicate_candidate_interpretation() -> None:
    identity = _identity()
    receipt = _interpretation()
    normalized = _normalized_candidate_event(
        identity,
        _candidate(),
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
    )
    first = _event(
        identity=identity,
        sequence=2,
        previous_event_hash=normalized.canonical_hash(),
        operation_hash=HASH_B,
        event_type=EventType.CANDIDATE_INTERPRETATION_RECORDED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            candidate_interpretation_receipt=receipt,
        ),
    )
    second = _event(
        identity=identity,
        sequence=3,
        previous_event_hash=first.canonical_hash(),
        operation_hash=HASH_C,
        event_type=EventType.CANDIDATE_INTERPRETATION_RECORDED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            candidate_interpretation_receipt=receipt,
        ),
    )
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(normalized, first, second),
    )
    with pytest.raises(EventConflict) as raised:
        rebuild_projection(stream)
    assert raised.value.code is EventConflictCode.PROJECTION_CONFLICT


def test_late_receipt_cannot_retroactively_complete_prior_coverage() -> None:
    identity = _identity()
    events = _candidate_projection_events(identity, receipt=None)
    coverage = events[-1]
    late_receipt = _event(
        identity=identity,
        sequence=4,
        previous_event_hash=coverage.canonical_hash(),
        operation_hash="f" * 64,
        event_type=EventType.CANDIDATE_INTERPRETATION_RECORDED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            candidate_interpretation_receipt=_interpretation(),
        ),
    )
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(*events, late_receipt),
    )
    with pytest.raises(EventConflict, match="prior event receipts"):
        rebuild_projection(stream)


def test_run_completion_cannot_be_backfilled_by_later_coverage_event() -> None:
    identity = _identity()
    manifest = _clean_manifest(identity)
    completed = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
        event_type=EventType.RUN_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            audit_run=_audit_run(identity, manifest),
        ),
    )
    coverage = _event(
        identity=identity,
        sequence=2,
        previous_event_hash=completed.canonical_hash(),
        operation_hash=HASH_B,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest),
    )
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(completed, coverage),
    )
    with pytest.raises(EventConflict, match="prior latest CoverageManifest"):
        rebuild_projection(stream)


def test_latest_coverage_allows_prior_candidate_version_history() -> None:
    identity = _identity()
    discovery_receipt = _discovery_receipt(candidate_ids=("candidate-1",))
    discovery = _event(
        identity=identity,
        sequence=1,
        previous_event_hash=None,
        operation_hash=HASH_A,
        event_type=EventType.DISCOVERY_COMPLETED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            producer=_producer("model-native"),
            lane=DiscoveryLane.MODEL_NATIVE,
            input_hashes=(HASH_B,),
            output_hashes=(HASH_C,),
            terminal_reason_code="CANDIDATES_RECORDED",
            model_discovery_receipt=discovery_receipt,
        ),
    )
    events: list[AuditEvent] = [discovery]
    operations = iter(("d" * 64, "e" * 64, "f" * 64, "0" * 64))
    for version in (1, 2):
        candidate = _candidate(version=version)
        normalized = _normalized_candidate_event(
            identity,
            candidate,
            sequence=len(events) + 1,
            previous_event_hash=events[-1].canonical_hash(),
            operation_hash=next(operations),
        )
        events.append(normalized)
        receipt = _interpretation(version=version)
        event = _event(
            identity=identity,
            sequence=len(events) + 1,
            previous_event_hash=events[-1].canonical_hash(),
            operation_hash=next(operations),
            event_type=EventType.CANDIDATE_INTERPRETATION_RECORDED,
            payload=EventSafePayload(
                **WIRE,
                head_sha=HEAD_SHA,
                candidate_interpretation_receipt=receipt,
            ),
        )
        events.append(event)
    manifest = _candidate_manifest(identity, candidate_version=2)
    coverage = _event(
        identity=identity,
        sequence=len(events) + 1,
        previous_event_hash=events[-1].canonical_hash(),
        operation_hash="1" * 64,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(**WIRE, head_sha=HEAD_SHA, coverage_manifest=manifest),
    )
    events.append(coverage)
    stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=tuple(events),
    )
    projection = rebuild_projection(stream)
    assert projection.coverage_manifest == manifest
    assert [
        receipt.candidate_version for receipt in projection.candidate_interpretation_receipts
    ] == [
        1,
        2,
    ]
    future_coverage = _event(
        identity=identity,
        sequence=len(events),
        previous_event_hash=events[-2].canonical_hash(),
        operation_hash="2" * 64,
        event_type=EventType.COVERAGE_UPDATED,
        payload=EventSafePayload(
            **WIRE,
            head_sha=HEAD_SHA,
            coverage_manifest=_candidate_manifest(identity, candidate_version=1),
        ),
    )
    future_stream = EventStream.replay(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=identity,
        events=(*events[:-1], future_coverage),
    )
    with pytest.raises(EventConflict, match="current CoverageManifest"):
        rebuild_projection(future_stream)
