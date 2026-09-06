"""Focused P4.3 security-regression contract tests."""

from __future__ import annotations

import hashlib
import json

import pytest
from securecode_ai.core.regression import (
    RegressionCase,
    RegressionCaseKind,
    RegressionCaseResult,
    RegressionContractError,
    RegressionDisposition,
    RegressionExpectedOutcome,
    RegressionObservationStatus,
    RegressionRevisionRole,
    build_security_regression_descriptor,
    evaluate_regression,
)
from securecode_ai.core.root_cause import RootCauseEvidenceRefs, RootCauseRecord
from securecode_ai.core.security_invariants import SecurityInvariant

HEAD = "a" * 40
FIXED_HEAD = "d" * 40
HASH = "b" * 64
GRAPH_HASH = "c" * 64
EVIDENCE = ("evidence-source", "evidence-propagation", "evidence-sink")


def _root() -> RootCauseRecord:
    evidence = RootCauseEvidenceRefs(*EVIDENCE)
    material = {
        "candidate_id": "candidate-1",
        "candidate_version": 1,
        "evidence": {
            "propagation_evidence_id": EVIDENCE[1],
            "sink_evidence_id": EVIDENCE[2],
            "source_evidence_id": EVIDENCE[0],
        },
        "evidence_graph_id": "graph-1",
        "evidence_graph_sha256": GRAPH_HASH,
        "finding_id": "finding-1",
        "head_sha": HEAD,
        "repository_id": "repo-1",
        "root_cause_fingerprint": HASH,
        "schema_version": "1.0.0",
        "tenant_id": "tenant-1",
    }
    digest = hashlib.sha256(
        json.dumps(material, separators=(",", ":"), sort_keys=True).encode("ascii")
    ).hexdigest()
    return RootCauseRecord(
        record_id=f"root-cause-{digest}",
        schema_version="1.0.0",
        finding_id="finding-1",
        candidate_id="candidate-1",
        candidate_version=1,
        tenant_id="tenant-1",
        repository_id="repo-1",
        head_sha=HEAD,
        root_cause_fingerprint=HASH,
        evidence_graph_id="graph-1",
        evidence_graph_sha256=GRAPH_HASH,
        evidence=evidence,
    )


def _invariant(root: RootCauseRecord) -> SecurityInvariant:
    from securecode_ai.core.security_invariants import _invariant_hash, _unchecked_invariant

    value = _unchecked_invariant(
        invariant_id="CWE-89-PARAMETER-BINDING",
        invariant_version="1.0.0",
        property_name="database driver parameter binding",
        finding_id=root.finding_id,
        root_cause_id=root.record_id,
        candidate_id=root.candidate_id,
        candidate_version=root.candidate_version,
        tenant_id=root.tenant_id,
        repository_id=root.repository_id,
        head_sha=root.head_sha,
        root_cause_fingerprint=root.root_cause_fingerprint,
        evidence_graph_id=root.evidence_graph_id,
        evidence_graph_sha256=root.evidence_graph_sha256,
        required_evidence_ids=tuple(sorted(EVIDENCE)),
        invariant_sha256="0" * 64,
        schema_version="1.0.0",
    )
    return SecurityInvariant(
        **{
            **{name: getattr(value, name) for name in SecurityInvariant.__dataclass_fields__},
            "invariant_sha256": _invariant_hash(value),
        }
    )


def _cases() -> tuple[RegressionCase, ...]:
    return (
        RegressionCase("case-poc", RegressionCaseKind.POC, "1" * 64, 12, "4" * 64),
        RegressionCase("case-plus", RegressionCaseKind.POC_PLUS, "2" * 64, 16, "5" * 64),
        RegressionCase("case-safe", RegressionCaseKind.SAFE_CONTROL, "3" * 64, 10, "6" * 64),
    )


def _results(outcome: RegressionExpectedOutcome) -> tuple[RegressionCaseResult, ...]:
    return tuple(
        RegressionCaseResult(
            case.case_id,
            RegressionObservationStatus.OBSERVED,
            RegressionExpectedOutcome.NO_VIOLATION
            if case.kind is RegressionCaseKind.SAFE_CONTROL
            else outcome,
            str(index) * 64,
            4,
        )
        for index, case in enumerate(_cases(), start=7)
    )


def test_vulnerable_revision_and_fixed_candidate_have_distinct_results() -> None:
    root = _root()
    invariant = _invariant(root)
    descriptor = build_security_regression_descriptor(root, invariant, _cases())

    vulnerable = evaluate_regression(
        descriptor,
        root,
        invariant,
        revision_role=RegressionRevisionRole.VULNERABLE,
        evaluated_head_sha=HEAD,
        observations=_results(RegressionExpectedOutcome.VIOLATION_OBSERVED),
    )
    fixed = evaluate_regression(
        descriptor,
        root,
        invariant,
        revision_role=RegressionRevisionRole.FIXED_CANDIDATE,
        evaluated_head_sha=FIXED_HEAD,
        observations=_results(RegressionExpectedOutcome.NO_VIOLATION),
    )

    assert vulnerable.disposition is RegressionDisposition.VULNERABLE_FAILURE_DEMONSTRATED
    assert fixed.disposition is RegressionDisposition.FIXED_CANDIDATE_PASSED
    assert not vulnerable.approval_eligible and not fixed.approval_eligible


def test_oracle_error_is_indeterminate() -> None:
    root = _root()
    invariant = _invariant(root)
    descriptor = build_security_regression_descriptor(root, invariant, _cases())
    results = list(_results(RegressionExpectedOutcome.NO_VIOLATION))
    results[0] = RegressionCaseResult(
        results[0].case_id,
        RegressionObservationStatus.ORACLE_ERROR,
        None,
        None,
        0,
    )

    result = evaluate_regression(
        descriptor,
        root,
        invariant,
        revision_role=RegressionRevisionRole.FIXED_CANDIDATE,
        evaluated_head_sha=FIXED_HEAD,
        observations=tuple(results),
    )
    assert result.disposition is RegressionDisposition.INDETERMINATE


def test_safe_control_violation_fails_closed() -> None:
    root = _root()
    invariant = _invariant(root)
    descriptor = build_security_regression_descriptor(root, invariant, _cases())
    results = list(_results(RegressionExpectedOutcome.NO_VIOLATION))
    results[2] = RegressionCaseResult(
        "case-safe",
        RegressionObservationStatus.OBSERVED,
        RegressionExpectedOutcome.VIOLATION_OBSERVED,
        "9" * 64,
        3,
    )
    result = evaluate_regression(
        descriptor,
        root,
        invariant,
        revision_role=RegressionRevisionRole.FIXED_CANDIDATE,
        evaluated_head_sha=FIXED_HEAD,
        observations=tuple(results),
    )
    assert result.disposition is RegressionDisposition.SAFE_CONTROL_FAILED


def test_missing_poc_plus_and_duplicate_results_are_rejected() -> None:
    root = _root()
    invariant = _invariant(root)
    with pytest.raises(RegressionContractError):
        build_security_regression_descriptor(root, invariant, _cases()[:2])

    descriptor = build_security_regression_descriptor(root, invariant, _cases())
    duplicate = (_results(RegressionExpectedOutcome.NO_VIOLATION)[0],) * 3
    with pytest.raises(RegressionContractError):
        evaluate_regression(
            descriptor,
            root,
            invariant,
            revision_role=RegressionRevisionRole.FIXED_CANDIDATE,
            evaluated_head_sha=FIXED_HEAD,
            observations=duplicate,
        )


def test_identity_drift_and_same_fixed_head_are_rejected() -> None:
    root = _root()
    invariant = _invariant(root)
    descriptor = build_security_regression_descriptor(root, invariant, _cases())
    with pytest.raises(RegressionContractError):
        evaluate_regression(
            descriptor,
            root,
            invariant,
            revision_role=RegressionRevisionRole.FIXED_CANDIDATE,
            evaluated_head_sha=HEAD,
            observations=_results(RegressionExpectedOutcome.NO_VIOLATION),
        )
    object.__setattr__(root, "tenant_id", "other-tenant")
    with pytest.raises(RegressionContractError):
        evaluate_regression(
            descriptor,
            root,
            invariant,
            revision_role=RegressionRevisionRole.VULNERABLE,
            evaluated_head_sha=HEAD,
            observations=_results(RegressionExpectedOutcome.VIOLATION_OBSERVED),
        )
