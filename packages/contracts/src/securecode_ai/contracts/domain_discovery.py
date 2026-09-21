"""Versioned, provider-neutral domain contracts for SecureCode AI."""

from __future__ import annotations

from typing import Self

from pydantic import Field, model_validator

from .base import (
    CommitSha,
    DataClass,
    OpaqueId,
    Sha256,
    WireModel,
)
from .domain_coverage import ArtifactRef, LineageRef, ProducerRef, SourceLocation
from .domain_primitives import (
    CandidateOrigin,
    ComponentPin,
    DiscoveryLane,
    EvidenceKind,
    ModelCallStatus,
    NonNegativeInt,
    PositiveInt,
    TrustLabel,
    _require_extension_tenant,
)


class RawSignal(WireModel):
    """Untrusted deterministic fact; intentionally has no verdict field."""

    raw_signal_id: OpaqueId
    tenant_id: OpaqueId
    head_sha: CommitSha
    producer: ProducerRef
    rule_id: OpaqueId
    location: SourceLocation
    payload_classification: DataClass
    payload_ref: ArtifactRef | None = None
    signal_sha256: Sha256

    @model_validator(mode="after")
    def _require_sensitive_payload_reference(self) -> Self:
        if self.payload_classification in {
            DataClass.CONFIDENTIAL_SOURCE,
            DataClass.RESTRICTED,
        } and (
            self.payload_ref is None
            or self.payload_ref.data_class is not self.payload_classification
        ):
            raise ValueError("DC3/DC4 signal payload requires a same-class ArtifactRef")
        if self.payload_ref is not None and self.payload_ref.tenant_id != self.tenant_id:
            raise ValueError("signal and payload reference must belong to the same tenant")
        return self


class DiscoveryCandidate(WireModel):
    candidate_id: OpaqueId
    tenant_id: OpaqueId
    candidate_version: PositiveInt
    head_sha: CommitSha
    root_cause_fingerprint: Sha256
    candidate_origin: CandidateOrigin
    lineage: tuple[LineageRef, ...] = Field(min_length=1, max_length=4096)
    evidence_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=4096)

    @model_validator(mode="after")
    def _validate_origin_lineage(self) -> Self:
        _validate_origin(
            self.candidate_origin,
            self.root_cause_fingerprint,
            self.lineage,
        )
        lineage_ids = [item.lineage_id for item in self.lineage]
        if len(lineage_ids) != len(set(lineage_ids)):
            raise ValueError("candidate lineage IDs must be unique")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("candidate evidence IDs must be unique")
        lineage_evidence_ids = {
            evidence_id for item in self.lineage for evidence_id in item.evidence_ids
        }
        if not lineage_evidence_ids.issubset(self.evidence_ids):
            raise ValueError("candidate must retain every lineage evidence ID")
        return self


class ModelBudgetUsage(WireModel):
    token_limit: PositiveInt
    tokens_used: NonNegativeInt
    repository_call_limit: PositiveInt
    repository_calls_used: NonNegativeInt
    time_limit_ms: PositiveInt
    elapsed_ms: NonNegativeInt

    @model_validator(mode="after")
    def _validate_limits(self) -> Self:
        if self.tokens_used > self.token_limit:
            raise ValueError("tokens_used exceeds token_limit")
        if self.repository_calls_used > self.repository_call_limit:
            raise ValueError("repository_calls_used exceeds repository_call_limit")
        if self.elapsed_ms > self.time_limit_ms:
            raise ValueError("elapsed_ms exceeds time_limit_ms")
        return self


class ModelDiscoveryReceipt(WireModel):
    receipt_id: OpaqueId
    tenant_id: OpaqueId
    head_sha: CommitSha
    scope_sha256: Sha256
    model_profile: ComponentPin
    prompt: ComponentPin
    repository_view_call_hashes: tuple[Sha256, ...] = Field(default=(), max_length=4096)
    budget_usage: ModelBudgetUsage
    model_call_status: ModelCallStatus
    schema_valid_result: bool
    input_sha256: Sha256
    output_sha256: Sha256 | None = None
    candidate_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=4096)

    @model_validator(mode="after")
    def _validate_model_result(self) -> Self:
        if self.model_call_status is ModelCallStatus.SUCCEEDED:
            if not self.schema_valid_result or self.output_sha256 is None:
                raise ValueError("SUCCEEDED discovery requires schema-valid output and output hash")
        elif self.schema_valid_result or self.candidate_ids:
            raise ValueError("non-success discovery cannot claim valid candidates or coverage")
        if len(self.candidate_ids) != len(set(self.candidate_ids)):
            raise ValueError("candidate_ids must be unique")
        return self

    @property
    def is_completed_zero(self) -> bool:
        return (
            self.model_call_status is ModelCallStatus.SUCCEEDED
            and self.schema_valid_result
            and not self.candidate_ids
        )


class CandidateInterpretationReceipt(WireModel):
    receipt_id: OpaqueId
    tenant_id: OpaqueId
    candidate_id: OpaqueId
    candidate_version: PositiveInt
    head_sha: CommitSha
    auditor: ComponentPin
    model_profile: ComponentPin
    prompt: ComponentPin
    evidence_sha256: Sha256
    model_call_status: ModelCallStatus
    schema_valid_result: bool
    verdict_ref: OpaqueId | None = None
    input_sha256: Sha256
    output_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def _validate_terminal_interpretation(self) -> Self:
        if self.model_call_status is ModelCallStatus.SUCCEEDED:
            if (
                not self.schema_valid_result
                or self.verdict_ref is None
                or self.output_sha256 is None
            ):
                raise ValueError("SUCCEEDED interpretation requires schema-valid verdict output")
        elif self.schema_valid_result or self.verdict_ref is not None:
            raise ValueError("non-success interpretation cannot claim a valid verdict")
        return self


class Evidence(WireModel):
    evidence_id: OpaqueId
    tenant_id: OpaqueId
    head_sha: CommitSha
    evidence_kind: EvidenceKind
    producer: ProducerRef
    trust_label: TrustLabel
    data_class: DataClass
    evidence_sha256: Sha256
    location: SourceLocation | None = None
    artifact_ref: ArtifactRef | None = None

    @model_validator(mode="after")
    def _validate_sensitive_reference(self) -> Self:
        if self.data_class in {
            DataClass.CONFIDENTIAL_SOURCE,
            DataClass.RESTRICTED,
        } and (self.artifact_ref is None or self.artifact_ref.data_class is not self.data_class):
            raise ValueError("DC3/DC4 evidence requires a same-class ArtifactRef")
        if self.artifact_ref is not None and self.artifact_ref.tenant_id != self.tenant_id:
            raise ValueError("evidence and artifact reference must belong to the same tenant")
        _require_extension_tenant(self, self.tenant_id)
        return self


def _validate_origin(
    origin: CandidateOrigin,
    root_cause_fingerprint: str,
    lineage: tuple[LineageRef, ...],
) -> None:
    lanes = {item.lane for item in lineage}
    expected = {
        CandidateOrigin.DETERMINISTIC: {DiscoveryLane.DETERMINISTIC},
        CandidateOrigin.MODEL_NATIVE: {DiscoveryLane.MODEL_NATIVE},
        CandidateOrigin.HYBRID: {DiscoveryLane.DETERMINISTIC, DiscoveryLane.MODEL_NATIVE},
    }[origin]
    if lanes != expected:
        raise ValueError("candidate_origin does not match immutable discovery lineage")
    if any(item.root_cause_fingerprint != root_cause_fingerprint for item in lineage):
        raise ValueError("all merged lineage must resolve to the same root-cause fingerprint")
