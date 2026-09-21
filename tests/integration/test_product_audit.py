"""Distinct actual hybrid convergence through scanner and all guarded roles."""

import json

import pytest
from securecode_ai.adapters.product_audit import (
    ProductAuditComposition,
    compose_product_audit,
)
from securecode_ai.adapters.product_scan import ProductCandidatePreparationFailure
from securecode_ai.contracts import CandidateOrigin, CoverageStatus, DiscoveryLane, ModelCallStatus

from tests.unit.test_product_audit import _actual_flow


def test_actual_hybrid_convergence_to_exact_core_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    flow, review, host, endpoint, discovery_bytes = _actual_flow(monkeypatch, hybrid=True)
    assert len(flow.graph.candidates) == len(flow.investigations) == 1
    candidate = flow.graph.candidates[0]
    assert candidate.candidate_origin is CandidateOrigin.HYBRID
    assert {item.lane for item in candidate.lineage} == {
        DiscoveryLane.DETERMINISTIC,
        DiscoveryLane.MODEL_NATIVE,
    }
    assert flow.discovery.receipt.candidate_ids != (candidate.candidate_id,)
    investigation = flow.investigations[0]
    assert not isinstance(investigation, ProductCandidatePreparationFailure)
    assert investigation.final_model_call_status is ModelCallStatus.SUCCEEDED
    skeptic_review = review.outcomes[0].skeptic_review
    assert skeptic_review is not None
    assert skeptic_review.model_call_status is ModelCallStatus.SUCCEEDED
    assert review.outcomes[0].finding_gate is not None
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert result.run.audit_outcome.value == "FAIL"
    assert result.report.run == result.run
    assert result.report.findings[0].finding.candidate_origin is CandidateOrigin.HYBRID
    assert (
        result.run.coverage_manifest.model_discovery_receipts[0].model_dump_json()
        == discovery_bytes
    )
    units = {unit.stage_id: unit for unit in result.run.coverage_manifest.units}
    for stage in (
        "deterministic_analysis",
        "normalization",
        "evidence_graph",
        "auditor_investigation",
        "skeptic_review",
        "finding_gate",
    ):
        assert units[stage].coverage_status is CoverageStatus.COMPLETED
    for stage in ("normalization", "evidence_graph"):
        assert flow.discovery.receipt.input_sha256 in units[stage].input_hashes
        assert flow.discovery.receipt.output_sha256 in units[stage].input_hashes
        assert len(units[stage].input_hashes) >= 3
        assert set(
            units["deterministic_analysis"].input_hashes
            + units["deterministic_analysis"].output_hashes
        ) <= set(units[stage].input_hashes)
    assert len(endpoint.requests) == 3
    roles = [
        json.loads(json.loads(item[2])["messages"][0]["content"])["trusted_controls"]["role"]
        for item in endpoint.requests
    ]
    assert roles == ["discovery", "auditor", "skeptic"]


def test_actual_ssrf_portfolio_flow_renders_product_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, review, host, endpoint, _ = _actual_flow(monkeypatch, hybrid=True, ssrf=True)
    assert flow.graph.candidates[0].candidate_origin is CandidateOrigin.HYBRID
    assert review.has_known_blocking_finding
    investigation = flow.investigations[0]
    assert not isinstance(investigation, ProductCandidatePreparationFailure)
    assert investigation.final_model_call_status is ModelCallStatus.SUCCEEDED
    skeptic_review = review.outcomes[0].skeptic_review
    assert skeptic_review is not None
    assert skeptic_review.model_call_status is ModelCallStatus.SUCCEEDED
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    finding = result.report.findings[0]
    assert finding.classification.cwe_id == "CWE-918"
    assert finding.classification.owasp_category == "A10:2021"
    assert finding.classification.confidence.value == "UNSCORED"
    assert result.run.audit_outcome.value == "FAIL"
    assert len(endpoint.requests) == 3
