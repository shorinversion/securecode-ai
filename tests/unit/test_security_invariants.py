"""Focused P4.2 security-invariant contract tests."""

from __future__ import annotations

import hashlib
import json

import pytest
from securecode_ai.core.root_cause import RootCauseEvidenceRefs, RootCauseRecord
from securecode_ai.core.security_invariants import (
    InvariantEvaluationReason,
    SecurityInvariant,
    SecurityInvariantError,
    evaluate_security_invariant,
)

HEAD = "a" * 40
FINGERPRINT = "b" * 64
GRAPH_SHA = "c" * 64
EVIDENCE = ("evidence-source", "evidence-propagation", "evidence-sink")


def _record() -> RootCauseRecord:
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
        "evidence_graph_sha256": GRAPH_SHA,
        "finding_id": "finding-1",
        "head_sha": HEAD,
        "repository_id": "repo-1",
        "root_cause_fingerprint": FINGERPRINT,
        "schema_version": "1.0.0",
        "tenant_id": "tenant-1",
    }
    digest = hashlib.sha256(
        json.dumps(material, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
    ).hexdigest()
    from securecode_ai.core.root_cause import RootCauseRecord as Record

    return Record(
        record_id=f"root-cause-{digest}",
        schema_version="1.0.0",
        finding_id="finding-1",
        candidate_id="candidate-1",
        candidate_version=1,
        tenant_id="tenant-1",
        repository_id="repo-1",
        head_sha=HEAD,
        root_cause_fingerprint=FINGERPRINT,
        evidence_graph_id="graph-1",
        evidence_graph_sha256=GRAPH_SHA,
        evidence=evidence,
    )


def _invariant(record: RootCauseRecord) -> SecurityInvariant:
    from securecode_ai.core.security_invariants import _unchecked_invariant

    value = _unchecked_invariant(
        invariant_id="CWE-89-PARAMETER-BINDING",
        invariant_version="1.0.0",
        property_name="database driver parameter binding",
        finding_id=record.finding_id,
        root_cause_id=record.record_id,
        candidate_id=record.candidate_id,
        candidate_version=record.candidate_version,
        tenant_id=record.tenant_id,
        repository_id=record.repository_id,
        head_sha=record.head_sha,
        root_cause_fingerprint=record.root_cause_fingerprint,
        evidence_graph_id=record.evidence_graph_id,
        evidence_graph_sha256=record.evidence_graph_sha256,
        required_evidence_ids=tuple(sorted(EVIDENCE)),
        invariant_sha256="0" * 64,
        schema_version="1.0.0",
    )
    from securecode_ai.core.security_invariants import _invariant_hash

    return SecurityInvariant(
        invariant_id=value.invariant_id,
        invariant_version=value.invariant_version,
        property_name=value.property_name,
        finding_id=value.finding_id,
        root_cause_id=value.root_cause_id,
        candidate_id=value.candidate_id,
        candidate_version=value.candidate_version,
        tenant_id=value.tenant_id,
        repository_id=value.repository_id,
        head_sha=value.head_sha,
        root_cause_fingerprint=value.root_cause_fingerprint,
        evidence_graph_id=value.evidence_graph_id,
        evidence_graph_sha256=value.evidence_graph_sha256,
        required_evidence_ids=value.required_evidence_ids,
        invariant_sha256=_invariant_hash(value),
        schema_version=value.schema_version,
    )


def test_unknown_invariant_never_satisfies() -> None:
    record = _record()
    value = _invariant(record)
    object.__setattr__(value, "invariant_id", "UNKNOWN")
    with pytest.raises(SecurityInvariantError):
        evaluate_security_invariant(value, record)


def test_mismatched_root_cause_is_not_satisfied() -> None:
    record = _record()
    value = _invariant(record)
    other = _record()
    object.__setattr__(other, "record_id", "root-cause-other")
    with pytest.raises(SecurityInvariantError):
        evaluate_security_invariant(value, other)


def test_root_cause_evidence_is_sorted_and_complete() -> None:
    record = _record()
    value = _invariant(record)
    result = evaluate_security_invariant(value, record)
    assert result.satisfied
    assert result.reason is InvariantEvaluationReason.SATISFIED
    assert result.evidence_ids == tuple(sorted(EVIDENCE))
