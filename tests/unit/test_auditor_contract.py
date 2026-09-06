"""Focused P3.2 contracts for structured, cited Auditor results."""

from __future__ import annotations

import pytest
from securecode_ai.contracts import DataClass, ModelCallStatus
from securecode_ai.core.auditor import (
    AuditorContractError,
    AuditorContractErrorCode,
    parse_auditor_verdict,
    validate_auditor_response,
)
from securecode_ai.core.evidence_package import EvidenceContextRef, EvidencePackage


def _package() -> EvidencePackage:
    reference = EvidenceContextRef(
        evidence_id="evidence-a",
        content_id="content-a",
        data_class=DataClass.CONFIDENTIAL_SECURITY,
        evidence_sha256="a" * 64,
        producer_id="scanner",
        producer_version="1.0.0",
        producer_sha256="b" * 64,
        context_bytes=4,
        estimated_tokens=1,
    )
    return EvidencePackage(
        candidate_id="candidate-a",
        candidate_version=1,
        tenant_id="tenant-a",
        head_sha="1" * 40,
        graph_id="graph-a",
        graph_sha256="c" * 64,
        selection_sha256="d" * 64,
        selected=(reference,),
        omitted_evidence_ids=(),
        total_context_bytes=4,
        total_input_tokens=1,
        truncated=False,
    )


def _payload(*, citation: str = "evidence-a") -> dict[str, object]:
    return {
        "verdict_id": "verdict-a",
        "finding_verdict": "CONFIRMED",
        "cited_evidence_ids": [citation],
        "rationale_sha256": "e" * 64,
    }


def test_successful_response_exposes_only_a_structured_cited_verdict() -> None:
    response = validate_auditor_response(_package(), ModelCallStatus.SUCCEEDED, _payload())

    assert response.model_call_status is ModelCallStatus.SUCCEEDED
    assert response.schema_valid_result
    assert response.verdict is not None
    assert response.verdict.cited_evidence_ids == ("evidence-a",)


def test_invented_evidence_citation_is_not_a_valid_model_success() -> None:
    response = validate_auditor_response(
        _package(), ModelCallStatus.SUCCEEDED, _payload(citation="invented-evidence")
    )

    assert response.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert not response.schema_valid_result
    assert response.verdict is None


def test_direct_parser_labels_invented_citations_without_echoing_them() -> None:
    with pytest.raises(AuditorContractError) as raised:
        parse_auditor_verdict(_package(), _payload(citation="invented-evidence"))

    assert raised.value.code is AuditorContractErrorCode.INVALID_CITATION
    assert "invented-evidence" not in str(raised.value)


def test_model_non_success_remains_disjoint_from_verdict() -> None:
    response = validate_auditor_response(_package(), ModelCallStatus.REFUSED, None)

    assert response.model_call_status is ModelCallStatus.REFUSED
    assert not response.schema_valid_result
    assert response.verdict is None


def test_non_success_cannot_smuggle_a_payload() -> None:
    with pytest.raises(AuditorContractError) as raised:
        validate_auditor_response(_package(), ModelCallStatus.TIMEOUT, _payload())

    assert raised.value.code is AuditorContractErrorCode.STATUS_CONFLICT


def test_malformed_success_payload_becomes_invalid_schema() -> None:
    response = validate_auditor_response(
        _package(),
        ModelCallStatus.SUCCEEDED,
        {"finding_verdict": "CONFIRMED"},
    )

    assert response.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert not response.schema_valid_result
    assert response.verdict is None
