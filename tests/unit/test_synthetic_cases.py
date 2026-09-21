"""P7.13 governed synthetic case pipeline contracts."""

from __future__ import annotations

import pytest
from securecode_ai.core.synthetic_cases import (
    SyntheticArtifactStore,
    SyntheticCandidateDisposition,
    SyntheticCandidateStore,
    SyntheticCaseCandidate,
    SyntheticCaseKind,
    SyntheticGeneratorProvenance,
)
from securecode_ai.core.synthetic_lineage import (
    SyntheticAdmissionDisposition,
    SyntheticAdmissionRequest,
    SyntheticLineageError,
    SyntheticLineageGovernor,
    SyntheticRootCauseReview,
    SyntheticSplit,
    summarize_oracle_receipts,
)
from securecode_ai.core.synthetic_oracle import (
    SyntheticOracleDefinition,
    SyntheticOracleDisposition,
    SyntheticOracleExecution,
    SyntheticOracleReceipt,
    evaluate_oracle,
    launch_oracle,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64


def _provenance() -> SyntheticGeneratorProvenance:
    return SyntheticGeneratorProvenance(17, "generator-1", "1.0.0", HASH_A)


def _oracle() -> SyntheticOracleDefinition:
    return SyntheticOracleDefinition("oracle-1", "1.0.0", HASH_B, HASH_C)


def _candidate(
    artifact_store: SyntheticArtifactStore,
    *,
    case_id: str = "case-1",
    kind: SyntheticCaseKind = SyntheticCaseKind.VULNERABLE,
    source: bytes = b"synthetic-source-1",
    root: str = HASH_D,
    group: str = HASH_E,
) -> SyntheticCaseCandidate:
    return SyntheticCaseCandidate(
        case_id=case_id,
        tenant_id="tenant-1",
        provenance=_provenance(),
        kind=kind,
        language="python",
        cwe_id="CWE-89",
        label="sqli",
        topology_sha256=HASH_A,
        root_cause_sha256=root,
        near_duplicate_group_sha256=group,
        source_artifact=artifact_store.store_source(tenant_id="tenant-1", source=source),
    )


def _oracle_receipt(
    candidate: SyntheticCaseCandidate, *, regression_failed: bool = True
) -> SyntheticOracleReceipt:
    return evaluate_oracle(
        candidate,
        _oracle(),
        SyntheticOracleExecution(
            candidate.case_id,
            "oracle-1",
            regression_failed,
            False,
            HASH_B,
        ),
    )


def _review(
    candidate: SyntheticCaseCandidate, *, reviewer: str = "reviewer-1"
) -> SyntheticRootCauseReview:
    return SyntheticRootCauseReview(candidate.case_id, reviewer, candidate.root_cause_sha256, True)


def test_generated_case_is_candidate_with_private_source_artifact_and_fixed_provenance() -> None:
    artifacts = SyntheticArtifactStore()
    candidate = _candidate(artifacts)
    store = SyntheticCandidateStore()

    receipt = store.submit(candidate)
    duplicate = store.submit(candidate)

    assert receipt.disposition is SyntheticCandidateDisposition.CREATED
    assert duplicate.disposition is SyntheticCandidateDisposition.IDEMPOTENT
    assert candidate.source_artifact.content_sha256 not in candidate.case_id
    assert candidate.source_artifact.data_class.value == "DC3_CONFIDENTIAL_SOURCE"
    assert receipt.state.value == "CANDIDATE"


def test_oracle_requires_vulnerable_regression_failure_and_fixed_safe_pass() -> None:
    artifacts = SyntheticArtifactStore()
    vulnerable = _candidate(artifacts)
    fixed = _candidate(
        artifacts,
        case_id="case-fixed",
        kind=SyntheticCaseKind.FIXED_SAFE,
        source=b"fixed-source",
    )

    vulnerable_receipt = _oracle_receipt(vulnerable, regression_failed=True)
    fixed_receipt = _oracle_receipt(fixed, regression_failed=False)
    incorrect = _oracle_receipt(vulnerable, regression_failed=False)
    envelope = launch_oracle(vulnerable, _oracle())

    assert vulnerable_receipt.disposition is SyntheticOracleDisposition.PASSED
    assert fixed_receipt.disposition is SyntheticOracleDisposition.PASSED
    assert incorrect.disposition is SyntheticOracleDisposition.FAILED
    assert envelope.network_disabled
    assert envelope.credentials_disabled
    assert envelope.read_only_source_artifact
    assert envelope.isolated_scratch
    summary = summarize_oracle_receipts((vulnerable_receipt, incorrect))
    assert (summary.passed_cases, summary.failed_cases, summary.denominator_cases) == (1, 1, 2)


def test_admission_requires_oracle_and_independent_root_cause_review() -> None:
    artifacts = SyntheticArtifactStore()
    candidate = _candidate(artifacts)
    candidates = SyntheticCandidateStore()
    candidates.submit(candidate)
    governor = SyntheticLineageGovernor(candidates)
    request = SyntheticAdmissionRequest(
        candidate.case_id,
        SyntheticSplit.TRAIN,
        _oracle(),
        _oracle_receipt(candidate),
        _review(candidate),
    )

    admitted = governor.admit(request)
    duplicate = governor.admit(request)

    assert admitted.disposition is SyntheticAdmissionDisposition.ADMITTED
    assert duplicate.disposition is SyntheticAdmissionDisposition.IDEMPOTENT
    assert not admitted.source_disclosed

    with pytest.raises(SyntheticLineageError):
        governor.admit(
            SyntheticAdmissionRequest(
                candidate.case_id,
                SyntheticSplit.DEV,
                _oracle(),
                _oracle_receipt(candidate),
                _review(candidate),
            )
        )
    with pytest.raises(SyntheticLineageError):
        SyntheticLineageGovernor(candidates).admit(
            SyntheticAdmissionRequest(
                candidate.case_id,
                SyntheticSplit.TRAIN,
                _oracle(),
                _oracle_receipt(candidate),
                _review(candidate, reviewer="generator-1"),
            )
        )


def test_duplicate_and_cross_split_lineage_leakage_are_rejected() -> None:
    artifacts = SyntheticArtifactStore()
    first = _candidate(artifacts, case_id="case-1")
    sibling = _candidate(
        artifacts,
        case_id="case-2",
        source=b"related-but-not-identical",
        root=HASH_D,
        group=HASH_E,
    )
    duplicate_source = _candidate(artifacts, case_id="case-3")
    candidates = SyntheticCandidateStore()
    for candidate in (first, sibling, duplicate_source):
        candidates.submit(candidate)
    governor = SyntheticLineageGovernor(candidates)
    governor.admit(
        SyntheticAdmissionRequest(
            first.case_id, SyntheticSplit.TRAIN, _oracle(), _oracle_receipt(first), _review(first)
        )
    )

    with pytest.raises(SyntheticLineageError):
        governor.admit(
            SyntheticAdmissionRequest(
                sibling.case_id,
                SyntheticSplit.LOCKED_TEST,
                _oracle(),
                _oracle_receipt(sibling),
                _review(sibling),
            )
        )
    with pytest.raises(SyntheticLineageError):
        governor.admit(
            SyntheticAdmissionRequest(
                duplicate_source.case_id,
                SyntheticSplit.TRAIN,
                _oracle(),
                _oracle_receipt(duplicate_source),
                _review(duplicate_source),
            )
        )
