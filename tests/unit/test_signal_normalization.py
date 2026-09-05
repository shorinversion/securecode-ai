"""Deferred acceptance tests for deterministic P2.9 signal normalization."""

from __future__ import annotations

import hashlib

import pytest
from securecode_ai.contracts import (
    CandidateOrigin,
    DataClass,
    DiscoveryCandidate,
    DiscoveryLane,
    LineageRef,
    ProducerRef,
    RawSignal,
    SourceLocation,
    SourcePosition,
)
from securecode_ai.core.normalization import (
    NormalizationError,
    NormalizationErrorCode,
    normalize_raw_signal,
    normalize_signals,
    root_cause_fingerprint,
)

SCHEMA_VERSION = "0.2.0"
TENANT_ID = "tenant-1"
HEAD_SHA = "a" * 40
NEXT_HEAD_SHA = "b" * 40
CONTENT_SHA = hashlib.sha256(b"query = request.args.get('id')\n").hexdigest()
PRODUCER_SHA = "1" * 64
MODEL_PRODUCER_SHA = "2" * 64


def _producer(name: str, digest: str = PRODUCER_SHA) -> ProducerRef:
    return ProducerRef(
        schema_version=SCHEMA_VERSION,
        producer_id=name,
        producer_version="1.0.0",
        producer_sha256=digest,
    )


def _location(
    *,
    content_sha256: str = CONTENT_SHA,
    start_line: int = 1,
    start_column: int = 1,
) -> SourceLocation:
    return SourceLocation(
        schema_version=SCHEMA_VERSION,
        path="src/app.py",
        start=SourcePosition(schema_version=SCHEMA_VERSION, line=start_line, column=start_column),
        end=SourcePosition(
            schema_version=SCHEMA_VERSION, line=start_line, column=start_column + 20
        ),
        content_sha256=content_sha256,
    )


def _signal(
    *,
    signal_id: str = "signal-1",
    head_sha: str = HEAD_SHA,
    producer: ProducerRef | None = None,
    rule_id: str = "python-cwe89",
    location: SourceLocation | None = None,
) -> RawSignal:
    return RawSignal(
        schema_version=SCHEMA_VERSION,
        raw_signal_id=signal_id,
        tenant_id=TENANT_ID,
        head_sha=head_sha,
        producer=producer or _producer("cwe89-scanner"),
        rule_id=rule_id,
        location=location or _location(),
        payload_classification=DataClass.INTERNAL_METADATA,
        signal_sha256=hashlib.sha256(signal_id.encode("ascii")).hexdigest(),
    )


def _model_candidate(fingerprint: str, *, head_sha: str = HEAD_SHA) -> DiscoveryCandidate:
    lineage = LineageRef(
        schema_version=SCHEMA_VERSION,
        lineage_id="model-lineage-1",
        lane=DiscoveryLane.MODEL_NATIVE,
        producer=_producer("model-native-discovery", MODEL_PRODUCER_SHA),
        root_cause_fingerprint=fingerprint,
        input_candidate_ids=("model-source-1",),
        evidence_ids=("evidence-model-1",),
    )
    return DiscoveryCandidate(
        schema_version=SCHEMA_VERSION,
        candidate_id="model-source-1",
        tenant_id=TENANT_ID,
        candidate_version=2,
        head_sha=head_sha,
        root_cause_fingerprint=fingerprint,
        candidate_origin=CandidateOrigin.MODEL_NATIVE,
        lineage=(lineage,),
        evidence_ids=("evidence-model-1",),
    )


def test_fingerprint_is_domain_separated_and_independent_of_head_sha() -> None:
    signal = _signal()
    unchanged_across_commit = _signal(head_sha=NEXT_HEAD_SHA)

    assert root_cause_fingerprint(signal) == root_cause_fingerprint(unchanged_across_commit)
    assert root_cause_fingerprint(signal) != root_cause_fingerprint(
        _signal(location=_location(content_sha256="3" * 64))
    )
    assert root_cause_fingerprint(signal) != root_cause_fingerprint(
        _signal(location=_location(start_line=2))
    )
    assert root_cause_fingerprint(signal) != root_cause_fingerprint(_signal(rule_id="python-cwe79"))
    assert root_cause_fingerprint(signal) != hashlib.sha256(b"src/app.py").hexdigest()


def test_raw_signals_deduplicate_to_one_stable_candidate_with_all_lineage() -> None:
    first = _signal(signal_id="signal-a", producer=_producer("cwe89-a"))
    second = _signal(signal_id="signal-b", producer=_producer("cwe89-b", "4" * 64))

    candidates = normalize_signals(raw_signals=(second, first, first))

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.candidate_id == f"candidate-{root_cause_fingerprint(first)}"
    assert candidate.candidate_origin is CandidateOrigin.DETERMINISTIC
    assert candidate.candidate_version == 1
    assert tuple(lineage.input_signal_ids for lineage in candidate.lineage) == (
        ("signal-a",),
        ("signal-b",),
    )
    assert tuple(lineage.producer.producer_id for lineage in candidate.lineage) == (
        "cwe89-a",
        "cwe89-b",
    )
    assert normalize_raw_signal(first).candidate_id == candidate.candidate_id


def test_exact_cross_lane_fingerprint_converges_to_hybrid_without_losing_origin() -> None:
    signal = _signal()
    fingerprint = root_cause_fingerprint(signal)

    candidate = normalize_signals(
        raw_signals=(signal,), discovery_candidates=(_model_candidate(fingerprint),)
    )[0]

    assert candidate.candidate_origin is CandidateOrigin.HYBRID
    assert candidate.candidate_id == f"candidate-{fingerprint}"
    assert candidate.candidate_version == 2
    assert {lineage.lane for lineage in candidate.lineage} == {
        DiscoveryLane.DETERMINISTIC,
        DiscoveryLane.MODEL_NATIVE,
    }
    model_lineage = next(
        lineage for lineage in candidate.lineage if lineage.lane is DiscoveryLane.MODEL_NATIVE
    )
    assert model_lineage.input_candidate_ids == ("model-source-1",)
    assert candidate.evidence_ids == ("evidence-model-1",)


def test_similar_but_nonidentical_fingerprints_never_create_a_hybrid() -> None:
    signal = _signal()
    unrelated = _model_candidate("5" * 64)

    candidates = normalize_signals(raw_signals=(signal,), discovery_candidates=(unrelated,))

    assert len(candidates) == 2
    assert {candidate.candidate_origin for candidate in candidates} == {
        CandidateOrigin.DETERMINISTIC,
        CandidateOrigin.MODEL_NATIVE,
    }


def test_revision_and_duplicate_identity_conflicts_fail_closed() -> None:
    signal = _signal()
    with pytest.raises(NormalizationError) as mismatch:
        normalize_signals(
            raw_signals=(signal,),
            discovery_candidates=(_model_candidate("5" * 64, head_sha=NEXT_HEAD_SHA),),
        )
    assert mismatch.value.code is NormalizationErrorCode.IDENTITY_MISMATCH
    assert mismatch.value.__cause__ is None
    assert mismatch.value.__context__ is None

    with pytest.raises(NormalizationError) as collision:
        normalize_signals(
            raw_signals=(
                signal,
                _signal(signal_id=signal.raw_signal_id, rule_id="different-rule"),
            )
        )
    assert collision.value.code is NormalizationErrorCode.INTEGRITY_FAILURE
