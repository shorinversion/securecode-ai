"""Integration coverage for P3.11 mandatory dual-lane convergence."""

from __future__ import annotations

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AuditRunOutcome,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    ComponentPin,
    CoverageManifest,
    CoverageScenario,
    CoverageStatus,
    CoverageUnit,
    DataClass,
    DiscoveryCandidate,
    DiscoveryLane,
    Evidence,
    EvidenceKind,
    LineageRef,
    ModelBudgetUsage,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    ProducerRef,
    RepositoryRevision,
    RunExecutionIdentity,
    TrustLabel,
)
from securecode_ai.core.convergence import (
    ConvergenceCoverageState,
    DualLaneConvergenceInput,
    converge_dual_lanes,
)
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HEAD_SHA = "d" * 40
CATALOGUE_DIGEST_BYTES = (
    173,
    173,
    46,
    5,
    252,
    130,
    36,
    133,
    244,
    90,
    193,
    100,
    41,
    148,
    98,
    211,
    96,
    236,
    176,
    21,
    50,
    123,
    132,
    208,
    156,
    6,
    74,
    105,
    124,
    25,
    61,
    29,
)


def _pin(name: str, digest: str) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _identity() -> RunExecutionIdentity:
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            scm_provider="github",
            repository_id="repo-1",
            base_sha="e" * 40,
            head_sha=HEAD_SHA,
        ),
        stage_catalogue=ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id="core-mvp-0.2.0",
            component_version="0.2.0",
            content_sha256="".join(f"{byte:02x}" for byte in CATALOGUE_DIGEST_BYTES),
        ),
        workflow=_pin("workflow", HASH_A),
        policy=_pin("policy", HASH_B),
        configuration=_pin("configuration", HASH_C),
        provider_profile=_pin("provider", "1" * 64),
        capability_profile=_pin("capability", "2" * 64),
        egress_profile=_pin("egress", "3" * 64),
    )


def _candidate(
    *,
    candidate_id: str,
    origin: CandidateOrigin,
    fingerprint: str,
) -> DiscoveryCandidate:
    lane = (
        DiscoveryLane.DETERMINISTIC
        if origin is CandidateOrigin.DETERMINISTIC
        else DiscoveryLane.MODEL_NATIVE
    )
    return DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id=candidate_id,
        tenant_id="tenant-1",
        candidate_version=1,
        head_sha=HEAD_SHA,
        root_cause_fingerprint=fingerprint,
        candidate_origin=origin,
        lineage=(
            LineageRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                lineage_id=f"lineage-{lane.value}-{candidate_id}",
                lane=lane,
                producer=ProducerRef(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    producer_id=f"producer-{lane.value}",
                    producer_version="1.0.0",
                    producer_sha256=HASH_A,
                ),
                root_cause_fingerprint=fingerprint,
                input_signal_ids=(f"signal-{lane.value}-{candidate_id}",),
                evidence_ids=(f"evidence-{lane.value}-{candidate_id}",),
            ),
        ),
        evidence_ids=(f"evidence-{lane.value}-{candidate_id}",),
    )


def _discovery_receipt(candidate_id: str) -> ModelDiscoveryReceipt:
    return ModelDiscoveryReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id="model-discovery-1",
        tenant_id="tenant-1",
        head_sha=HEAD_SHA,
        scope_sha256=HASH_A,
        model_profile=_pin("provider", "1" * 64),
        prompt=_pin("discovery-prompt", HASH_B),
        budget_usage=ModelBudgetUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            token_limit=100,
            tokens_used=10,
            repository_call_limit=10,
            repository_calls_used=1,
            time_limit_ms=1_000,
            elapsed_ms=10,
        ),
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        input_sha256=HASH_B,
        output_sha256=HASH_C,
        candidate_ids=(candidate_id,),
    )


def _interpretation(candidate_id: str) -> CandidateInterpretationReceipt:
    return CandidateInterpretationReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id="interpretation-1",
        tenant_id="tenant-1",
        candidate_id=candidate_id,
        candidate_version=1,
        head_sha=HEAD_SHA,
        auditor=_pin("auditor", HASH_A),
        model_profile=_pin("provider", "1" * 64),
        prompt=_pin("auditor-prompt", HASH_B),
        evidence_sha256=HASH_C,
        model_call_status=ModelCallStatus.SUCCEEDED,
        schema_valid_result=True,
        verdict_ref="verdict-1",
        input_sha256=HASH_A,
        output_sha256=HASH_B,
    )


def _unit(
    stage_id: str,
    *,
    subject_id: str | None = None,
    receipt_id: str | None = None,
) -> CoverageUnit:
    model_stage = stage_id in {"model_native_discovery", "auditor_investigation", "skeptic_review"}
    return CoverageUnit(
        schema_version=CONTRACT_SCHEMA_VERSION,
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
        model_call_status=ModelCallStatus.SUCCEEDED if model_stage else None,
        schema_valid_result=True if model_stage else None,
        receipt_id=receipt_id if model_stage else None,
    )


def _manifest(
    *,
    identity: RunExecutionIdentity,
    candidate: DiscoveryCandidate,
    discovery: ModelDiscoveryReceipt,
    interpretation: CandidateInterpretationReceipt,
) -> CoverageManifest:
    atomic = (
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
                receipt_id="model-discovery-1" if stage == "model_native_discovery" else None,
            )
            for stage in atomic
        ),
        _unit(
            "auditor_investigation",
            subject_id=candidate.candidate_id,
            receipt_id="interpretation-1",
        ),
        _unit(
            "skeptic_review",
            subject_id=candidate.candidate_id,
            receipt_id="skeptic-1",
        ),
        _unit("finding_gate", subject_id=candidate.candidate_id),
    )
    return CoverageManifest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        catalogue=identity.stage_catalogue,
        execution_identity_hash=identity.execution_identity_hash,
        scenario=CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR,
        required_unit_ids=tuple(unit.coverage_unit_id for unit in units),
        units=units,
        discovery_candidates=(candidate,),
        model_discovery_receipts=(
            discovery.model_copy(update={"candidate_ids": (candidate.candidate_id,)}),
        ),
        candidate_interpretation_receipts=(interpretation,),
        coverage_complete=True,
    )


def _graph(
    candidate: DiscoveryCandidate | None = None,
    *,
    head_sha: str = HEAD_SHA,
) -> EvidenceGraph:
    """Build the exact P2.10 graph representation for one converged candidate."""

    if candidate is None:
        return EvidenceGraph(
            graph_id="graph-1",
            tenant_id="tenant-1",
            head_sha=head_sha,
            candidates=(),
            evidence=(),
            edges=(),
        )
    evidence_by_id: dict[str, Evidence] = {}
    for lineage in candidate.lineage:
        for evidence_id in lineage.evidence_ids:
            evidence_by_id[evidence_id] = Evidence(
                schema_version=CONTRACT_SCHEMA_VERSION,
                evidence_id=evidence_id,
                tenant_id="tenant-1",
                head_sha=head_sha,
                evidence_kind=EvidenceKind.SCANNER_SIGNAL,
                producer=lineage.producer,
                trust_label=TrustLabel.TRUSTED_DETERMINISTIC,
                data_class=DataClass.INTERNAL_METADATA,
                evidence_sha256=HASH_A,
            )
    return EvidenceGraph(
        graph_id="graph-1",
        tenant_id="tenant-1",
        head_sha=head_sha,
        candidates=(candidate,),
        evidence=tuple(evidence_by_id.values()),
        edges=tuple(
            EvidenceGraphEdge(
                kind=EvidenceEdgeKind.CANDIDATE_EVIDENCE,
                source=EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
                target=EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
            )
            for evidence_id in candidate.evidence_ids
        ),
    )


def test_identical_root_cause_converges_to_hybrid_with_complete_coverage() -> None:
    identity = _identity()
    deterministic = _candidate(
        candidate_id="deterministic-source-1",
        origin=CandidateOrigin.DETERMINISTIC,
        fingerprint=HASH_C,
    )
    model_native = _candidate(
        candidate_id="model-source-1",
        origin=CandidateOrigin.MODEL_NATIVE,
        fingerprint=HASH_C,
    )
    first = converge_dual_lanes(
        DualLaneConvergenceInput(
            execution_identity=identity,
            deterministic_candidates=(deterministic,),
            model_native_candidates=(model_native,),
            model_discovery_receipt=None,
            interpretation_receipts=(),
            coverage_manifest=None,
            evidence_graph=None,
        )
    )
    candidate = first.candidates[0]
    discovery = _discovery_receipt(model_native.candidate_id)
    interpretation = _interpretation(candidate.candidate_id)
    graph = _graph(candidate)

    result = converge_dual_lanes(
        DualLaneConvergenceInput(
            execution_identity=identity,
            deterministic_candidates=(deterministic,),
            model_native_candidates=(model_native,),
            model_discovery_receipt=discovery,
            interpretation_receipts=(interpretation,),
            coverage_manifest=_manifest(
                identity=identity,
                candidate=candidate,
                discovery=discovery,
                interpretation=interpretation,
            ),
            evidence_graph=graph,
        )
    )

    assert result.coverage_state is ConvergenceCoverageState.COMPLETE
    assert result.required_terminal_outcome is None
    assert graph.candidates == result.candidates
    assert result.candidates[0].candidate_origin is CandidateOrigin.HYBRID
    assert {lineage.lane for lineage in result.candidates[0].lineage} == {
        DiscoveryLane.DETERMINISTIC,
        DiscoveryLane.MODEL_NATIVE,
    }
    assert "deterministic-source-1" in result.candidates[0].lineage[0].input_candidate_ids


def test_missing_interpretation_receipt_is_indeterminate_not_clean() -> None:
    identity = _identity()
    deterministic = _candidate(
        candidate_id="deterministic-source-1",
        origin=CandidateOrigin.DETERMINISTIC,
        fingerprint=HASH_C,
    )
    model_native = _candidate(
        candidate_id="model-source-1",
        origin=CandidateOrigin.MODEL_NATIVE,
        fingerprint=HASH_C,
    )

    result = converge_dual_lanes(
        DualLaneConvergenceInput(
            execution_identity=identity,
            deterministic_candidates=(deterministic,),
            model_native_candidates=(model_native,),
            model_discovery_receipt=_discovery_receipt(model_native.candidate_id),
            interpretation_receipts=(),
            coverage_manifest=None,
            evidence_graph=None,
        )
    )

    assert result.coverage_state is ConvergenceCoverageState.INDETERMINATE
    assert result.required_terminal_outcome is AuditRunOutcome.INDETERMINATE


def test_distinct_fingerprints_remain_separate_lineages() -> None:
    identity = _identity()
    deterministic = _candidate(
        candidate_id="deterministic-source-1",
        origin=CandidateOrigin.DETERMINISTIC,
        fingerprint=HASH_A,
    )
    model_native = _candidate(
        candidate_id="model-source-1",
        origin=CandidateOrigin.MODEL_NATIVE,
        fingerprint=HASH_B,
    )

    result = converge_dual_lanes(
        DualLaneConvergenceInput(
            execution_identity=identity,
            deterministic_candidates=(deterministic,),
            model_native_candidates=(model_native,),
            model_discovery_receipt=None,
            interpretation_receipts=(),
            coverage_manifest=None,
            evidence_graph=None,
        )
    )

    assert result.coverage_state is ConvergenceCoverageState.INDETERMINATE
    assert [candidate.candidate_origin for candidate in result.candidates] == [
        CandidateOrigin.DETERMINISTIC,
        CandidateOrigin.MODEL_NATIVE,
    ]


def test_model_receipt_cannot_replace_its_source_id_with_a_normalized_id() -> None:
    identity = _identity()
    model_native = _candidate(
        candidate_id="model-source-1",
        origin=CandidateOrigin.MODEL_NATIVE,
        fingerprint=HASH_C,
    )

    result = converge_dual_lanes(
        DualLaneConvergenceInput(
            execution_identity=identity,
            deterministic_candidates=(),
            model_native_candidates=(model_native,),
            model_discovery_receipt=_discovery_receipt(f"candidate-{HASH_C}"),
            interpretation_receipts=(),
            coverage_manifest=None,
            evidence_graph=None,
        )
    )

    assert result.coverage_state is ConvergenceCoverageState.INDETERMINATE


def test_missing_evidence_graph_is_indeterminate_even_when_other_coverage_is_complete() -> None:
    identity = _identity()
    deterministic = _candidate(
        candidate_id="deterministic-source-1",
        origin=CandidateOrigin.DETERMINISTIC,
        fingerprint=HASH_C,
    )
    model_native = _candidate(
        candidate_id="model-source-1",
        origin=CandidateOrigin.MODEL_NATIVE,
        fingerprint=HASH_C,
    )
    preliminary = converge_dual_lanes(
        DualLaneConvergenceInput(
            execution_identity=identity,
            deterministic_candidates=(deterministic,),
            model_native_candidates=(model_native,),
            model_discovery_receipt=None,
            interpretation_receipts=(),
            coverage_manifest=None,
            evidence_graph=None,
        )
    )
    candidate = preliminary.candidates[0]
    discovery = _discovery_receipt(model_native.candidate_id)
    interpretation = _interpretation(candidate.candidate_id)

    result = converge_dual_lanes(
        DualLaneConvergenceInput(
            execution_identity=identity,
            deterministic_candidates=(deterministic,),
            model_native_candidates=(model_native,),
            model_discovery_receipt=discovery,
            interpretation_receipts=(interpretation,),
            coverage_manifest=_manifest(
                identity=identity,
                candidate=candidate,
                discovery=discovery,
                interpretation=interpretation,
            ),
            evidence_graph=None,
        )
    )

    assert result.coverage_state is ConvergenceCoverageState.INDETERMINATE


def test_stale_or_candidate_mismatched_graph_is_indeterminate() -> None:
    identity = _identity()
    deterministic = _candidate(
        candidate_id="deterministic-source-1",
        origin=CandidateOrigin.DETERMINISTIC,
        fingerprint=HASH_C,
    )
    model_native = _candidate(
        candidate_id="model-source-1",
        origin=CandidateOrigin.MODEL_NATIVE,
        fingerprint=HASH_C,
    )
    preliminary = converge_dual_lanes(
        DualLaneConvergenceInput(
            execution_identity=identity,
            deterministic_candidates=(deterministic,),
            model_native_candidates=(model_native,),
            model_discovery_receipt=None,
            interpretation_receipts=(),
            coverage_manifest=None,
            evidence_graph=None,
        )
    )
    candidate = preliminary.candidates[0]
    discovery = _discovery_receipt(model_native.candidate_id)
    interpretation = _interpretation(candidate.candidate_id)
    manifest = _manifest(
        identity=identity,
        candidate=candidate,
        discovery=discovery,
        interpretation=interpretation,
    )

    for graph in (_graph(head_sha="e" * 40), _graph()):
        result = converge_dual_lanes(
            DualLaneConvergenceInput(
                execution_identity=identity,
                deterministic_candidates=(deterministic,),
                model_native_candidates=(model_native,),
                model_discovery_receipt=discovery,
                interpretation_receipts=(interpretation,),
                coverage_manifest=manifest,
                evidence_graph=graph,
            )
        )
        assert result.coverage_state is ConvergenceCoverageState.INDETERMINATE
