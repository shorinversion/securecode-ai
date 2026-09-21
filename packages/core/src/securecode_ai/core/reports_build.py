"""Canonical report construction from validated audit outcomes."""

from __future__ import annotations

import hashlib

from securecode_ai.contracts import AuditRun, ComponentPin, FindingCase

from .reports_contracts import (
    REPORT_FORMAT_VERSION,
    REPORT_SCHEMA_VERSION,
    DeterministicReport,
    ReportError,
    ReportErrorCode,
    ReportFinding,
    _canonical_json,
)


def build_deterministic_report(
    run: AuditRun,
    findings: tuple[ReportFinding, ...],
    tools: tuple[ComponentPin, ...],
) -> DeterministicReport:
    """Validate one exact run and build its canonical semantic JSON source."""

    if (
        type(run) is not AuditRun
        or type(findings) is not tuple
        or any(type(item) is not ReportFinding for item in findings)
        or type(tools) is not tuple
        or any(type(item) is not ComponentPin for item in tools)
    ):
        raise ReportError(ReportErrorCode.INPUT_INVALID)
    try:
        validated_run = AuditRun.model_validate(run.model_dump(mode="python"))
        validated_findings = tuple(
            ReportFinding(
                FindingCase.model_validate(item.finding.model_dump(mode="python")),
                item.classification,
            )
            for item in findings
        )
        validated_tools = tuple(
            ComponentPin.model_validate(item.model_dump(mode="python")) for item in tools
        )
    except Exception:
        raise ReportError(ReportErrorCode.INPUT_INVALID) from None

    revision = validated_run.execution_identity.repository_revision
    finding_ids = tuple(item.finding.finding_id for item in validated_findings)
    if finding_ids != tuple(sorted(finding_ids)) or len(finding_ids) != len(set(finding_ids)):
        raise ReportError(ReportErrorCode.FINDING_MISMATCH)
    if set(finding_ids) != set(validated_run.finding_ids):
        raise ReportError(ReportErrorCode.FINDING_MISMATCH)
    if len({(item.component_id, item.component_version) for item in validated_tools}) != len(
        validated_tools
    ) or validated_tools != tuple(
        sorted(validated_tools, key=lambda item: (item.component_id, item.component_version))
    ):
        raise ReportError(ReportErrorCode.INPUT_INVALID)
    for item in validated_findings:
        finding = item.finding
        if finding.repository_revision != revision or finding.root_cause_fingerprint != next(
            (
                candidate.root_cause_fingerprint
                for candidate in validated_run.coverage_manifest.discovery_candidates
                if candidate.candidate_id == finding.candidate_id
                and candidate.candidate_version == finding.candidate_version
            ),
            None,
        ):
            raise ReportError(ReportErrorCode.IDENTITY_MISMATCH)

    document: dict[str, object] = {
        "analysis_health": validated_run.analysis_health.value,
        "coverage_manifest": validated_run.coverage_manifest.model_dump(mode="json"),
        "execution_identity": validated_run.execution_identity.model_dump(mode="json"),
        "execution_identity_hash": validated_run.execution_identity.execution_identity_hash,
        "findings": [_finding_document(item) for item in validated_findings],
        "model_profile": validated_run.execution_identity.provider_profile.model_dump(mode="json"),
        "outcome": validated_run.audit_outcome.value,
        "policy": validated_run.execution_identity.policy.model_dump(mode="json"),
        "report_version": REPORT_FORMAT_VERSION,
        "repository_revision": revision.model_dump(mode="json"),
        "run_id": validated_run.run_id,
        "schema_version": REPORT_SCHEMA_VERSION,
        "tools": [item.model_dump(mode="json") for item in validated_tools],
        "workflow": validated_run.execution_identity.workflow.model_dump(mode="json"),
    }
    report_hash = hashlib.sha256(_canonical_json(document)).hexdigest()
    return DeterministicReport(
        run=validated_run,
        findings=validated_findings,
        tools=validated_tools,
        document=document,
        report_sha256=report_hash,
    )


def _finding_document(item: ReportFinding) -> dict[str, object]:
    finding = item.finding
    classification = item.classification
    return {
        "blocking": finding.blocking,
        "candidate_id": finding.candidate_id,
        "candidate_origin": finding.candidate_origin.value,
        "confidence": classification.confidence.value,
        "cwe_id": finding.cwe_id,
        "evidence_graph_ref": finding.evidence_graph_ref.model_dump(mode="json"),
        "evidence_ids": list(finding.evidence_ids),
        "finding_id": finding.finding_id,
        "locations": [location.model_dump(mode="json") for location in finding.locations],
        "mapping_provenance": {
            "calibration_record_id": classification.provenance.calibration_record_id,
            "confidence_basis": classification.provenance.confidence_basis,
            "mapping_id": classification.provenance.mapping_id,
            "mapping_sha256": classification.provenance.mapping_sha256,
            "mapping_version": classification.provenance.mapping_version,
            "severity_basis": classification.provenance.severity_basis,
        },
        "owasp_category": classification.owasp_category,
        "patch_refs": [],
        "producer_lineage": [
            lineage.model_dump(mode="json") for lineage in finding.producer_lineage
        ],
        "root_cause_fingerprint": finding.root_cause_fingerprint,
        "severity": classification.severity.value,
        "validation_refs": [],
        "verdict": finding.finding_verdict.value,
    }
