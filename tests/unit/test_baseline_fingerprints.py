"""P5.2 contracts for exact, source-free baseline fingerprinting."""

from __future__ import annotations

from dataclasses import fields
from hashlib import sha256

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CandidateOrigin,
    DiscoveryCandidate,
    DiscoveryLane,
    LineageRef,
    ProducerRef,
)
from securecode_ai.core.baseline_fingerprints import (
    BASELINE_FINGERPRINT_SCHEMA_VERSION,
    BaselineFindingRelation,
    BaselineFingerprintComparison,
    BaselineFingerprintError,
    BaselineFingerprintErrorCode,
    BaselineFingerprintSnapshot,
    compare_baseline_fingerprints,
)

BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
OTHER_SHA = "c" * 40
TENANT_ID = "tenant-1"


def _fingerprint(label: str) -> str:
    return sha256(label.encode("ascii")).hexdigest()


def _candidate(*, label: str, revision_sha: str, candidate_id: str) -> DiscoveryCandidate:
    fingerprint = _fingerprint(label)
    producer = ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="scanner-1",
        producer_version="1.0.0",
        producer_sha256="d" * 64,
    )
    lineage = LineageRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        lineage_id=f"lineage-{candidate_id}",
        lane=DiscoveryLane.DETERMINISTIC,
        producer=producer,
        root_cause_fingerprint=fingerprint,
        input_signal_ids=(f"signal-{candidate_id}",),
    )
    return DiscoveryCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        candidate_id=candidate_id,
        tenant_id=TENANT_ID,
        candidate_version=1,
        head_sha=revision_sha,
        root_cause_fingerprint=fingerprint,
        candidate_origin=CandidateOrigin.DETERMINISTIC,
        lineage=(lineage,),
    )


def _snapshot(
    *, revision_sha: str, findings: tuple[DiscoveryCandidate, ...]
) -> BaselineFingerprintSnapshot:
    return BaselineFingerprintSnapshot(
        schema_version=BASELINE_FINGERPRINT_SCHEMA_VERSION,
        tenant_id=TENANT_ID,
        revision_sha=revision_sha,
        findings=findings,
    )


def _compare(
    *,
    baseline_findings: tuple[DiscoveryCandidate, ...],
    head_findings: tuple[DiscoveryCandidate, ...],
    current_head_sha: str = HEAD_SHA,
    commit_lineage: tuple[str, ...] = (BASE_SHA, HEAD_SHA),
) -> BaselineFingerprintComparison:
    return compare_baseline_fingerprints(
        baseline=_snapshot(revision_sha=BASE_SHA, findings=baseline_findings),
        head=_snapshot(revision_sha=HEAD_SHA, findings=head_findings),
        current_head_sha=current_head_sha,
        commit_lineage=commit_lineage,
    )


def test_legacy_only_fingerprint_is_not_new_code() -> None:
    baseline = _candidate(label="legacy", revision_sha=BASE_SHA, candidate_id="base-1")
    head = _candidate(label="legacy", revision_sha=HEAD_SHA, candidate_id="head-1")

    result = _compare(baseline_findings=(baseline,), head_findings=(head,))

    assert result.schema_version == BASELINE_FINGERPRINT_SCHEMA_VERSION
    assert result.baseline_fingerprints == (_fingerprint("legacy"),)
    assert result.head_fingerprints == (_fingerprint("legacy"),)
    assert result.new_fingerprints == ()
    assert result.relation_for(_fingerprint("legacy")) is BaselineFindingRelation.LEGACY


def test_new_fingerprint_is_stable_regardless_of_input_order() -> None:
    old_base = _candidate(label="old", revision_sha=BASE_SHA, candidate_id="base-1")
    old_head = _candidate(label="old", revision_sha=HEAD_SHA, candidate_id="head-1")
    new_head = _candidate(label="new", revision_sha=HEAD_SHA, candidate_id="head-2")

    first = _compare(baseline_findings=(old_base,), head_findings=(old_head, new_head))
    second = _compare(baseline_findings=(old_base,), head_findings=(new_head, old_head))

    assert first == second
    assert first.new_fingerprints == (_fingerprint("new"),)
    assert first.relation_for(_fingerprint("new")) is BaselineFindingRelation.NEW
    assert first.relation_for(_fingerprint("absent")) is BaselineFindingRelation.UNKNOWN


def test_result_retains_hashes_and_metadata_not_findings_or_source() -> None:
    result = _compare(baseline_findings=(), head_findings=())

    field_names = {field.name for field in fields(result)}

    assert field_names == {
        "schema_version",
        "tenant_id",
        "base_sha",
        "head_sha",
        "baseline_fingerprints",
        "head_fingerprints",
        "new_fingerprints",
    }
    assert "source" not in repr(result).lower()
    assert "finding" not in field_names


def test_stale_current_head_fails_closed() -> None:
    with pytest.raises(BaselineFingerprintError) as raised:
        _compare(baseline_findings=(), head_findings=(), current_head_sha=OTHER_SHA)

    assert raised.value.code is BaselineFingerprintErrorCode.STALE_HEAD


def test_snapshot_candidate_identity_mismatch_fails_closed() -> None:
    wrong_revision = _candidate(label="wrong", revision_sha=HEAD_SHA, candidate_id="base-1")

    with pytest.raises(BaselineFingerprintError) as raised:
        _snapshot(revision_sha=BASE_SHA, findings=(wrong_revision,))

    assert raised.value.code is BaselineFingerprintErrorCode.IDENTITY_MISMATCH


def test_duplicate_fingerprint_fails_closed() -> None:
    first = _candidate(label="same", revision_sha=HEAD_SHA, candidate_id="head-1")
    second = _candidate(label="same", revision_sha=HEAD_SHA, candidate_id="head-2")

    with pytest.raises(BaselineFingerprintError) as raised:
        _compare(baseline_findings=(), head_findings=(first, second))

    assert raised.value.code is BaselineFingerprintErrorCode.DUPLICATE_FINGERPRINT


@pytest.mark.parametrize(
    "lineage",
    ((), (HEAD_SHA,), (BASE_SHA, OTHER_SHA), (BASE_SHA, HEAD_SHA, HEAD_SHA)),
)
def test_unknown_or_ambiguous_commit_lineage_fails_closed(lineage: tuple[str, ...]) -> None:
    with pytest.raises(BaselineFingerprintError) as raised:
        _compare(baseline_findings=(), head_findings=(), commit_lineage=lineage)

    assert raised.value.code is BaselineFingerprintErrorCode.UNKNOWN_LINEAGE
