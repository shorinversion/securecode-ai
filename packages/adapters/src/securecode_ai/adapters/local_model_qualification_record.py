from __future__ import annotations

from securecode_ai.core import (
    AuditRunOutcome,
)

from .local_model_qualification_models import (
    LocalModelQualificationError,
    LocalModelQualificationEvidence,
    LocalModelQualificationRecord,
    LocalModelQualificationRequest,
    QualificationErrorCode,
    QualificationState,
)
from .local_model_qualification_validation import (
    _copy_qualification_evidence,
    _copy_qualification_request,
    _validate_evidence_binding,
)


def record_local_model_qualification(
    request: LocalModelQualificationRequest,
    *,
    evidence: LocalModelQualificationEvidence | None = None,
) -> LocalModelQualificationRecord:
    """Record generic P3.13 evidence without performing I/O or returning PASS."""

    if type(request) is not LocalModelQualificationRequest:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    request = _copy_qualification_request(request)
    if evidence is None:
        return LocalModelQualificationRecord(
            qualification_id=request.qualification_id,
            request_sha256=request.request_sha256,
            artifact=request.artifact,
            runtime=request.runtime,
            hardware=request.hardware,
            provider_profile=request.provider_profile,
            connector=request.connector,
            expected_repository_scope_sha256=request.expected_repository_scope_sha256,
            monetary_cost_usd_micros=request.monetary_cost_usd_micros,
            state=QualificationState.AWAITING_REAL_EVIDENCE,
            required_terminal_outcome=AuditRunOutcome.INDETERMINATE,
            receipt_hashes=(),
            tool_receipt_hashes=(),
        )
    if type(evidence) is not LocalModelQualificationEvidence:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    evidence = _copy_qualification_evidence(evidence)
    _validate_evidence_binding(request, evidence)
    return LocalModelQualificationRecord(
        qualification_id=request.qualification_id,
        request_sha256=request.request_sha256,
        artifact=request.artifact,
        runtime=request.runtime,
        hardware=request.hardware,
        provider_profile=request.provider_profile,
        connector=request.connector,
        expected_repository_scope_sha256=request.expected_repository_scope_sha256,
        monetary_cost_usd_micros=request.monetary_cost_usd_micros,
        state=QualificationState.REAL_EVIDENCE_RECORDED,
        required_terminal_outcome=None,
        receipt_hashes=evidence.receipt_hashes,
        tool_receipt_hashes=evidence.tool_receipt_hashes,
    )
