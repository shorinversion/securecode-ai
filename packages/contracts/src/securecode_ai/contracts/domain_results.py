"""Versioned, provider-neutral domain contracts for SecureCode AI."""

from __future__ import annotations

from typing import Self

from pydantic import Field, model_validator

from .base import (
    CommitSha,
    DataClass,
    OpaqueId,
    ReasonCode,
    Sha256,
    WireModel,
)
from .domain_coverage import (
    ArtifactRef,
    CoverageManifest,
    LineageRef,
    ProducerRef,
    RunExecutionIdentity,
    SourceLocation,
)
from .domain_discovery import CommandOperationEvidence, _validate_origin
from .domain_primitives import (
    AnalysisHealth,
    AuditRunOutcome,
    CandidateOrigin,
    ComponentPin,
    DecisionOutcome,
    FindingGateState,
    FindingVerdict,
    NonNegativeInt,
    PatchStatus,
    PositiveInt,
    RepositoryRevision,
    UtcTimestamp,
    ValidationGateOutcome,
    ValidationOutcome,
    _require_extension_tenant,
)


class FindingCase(WireModel):
    finding_id: OpaqueId
    candidate_id: OpaqueId
    candidate_version: PositiveInt
    repository_revision: RepositoryRevision
    root_cause_fingerprint: Sha256
    candidate_origin: CandidateOrigin
    producer_lineage: tuple[LineageRef, ...] = Field(min_length=1, max_length=4096)
    locations: tuple[SourceLocation, ...] = Field(min_length=1, max_length=4096)
    cwe_id: str = Field(pattern=r"^CWE-[1-9][0-9]{0,5}$", max_length=10)
    evidence_graph_ref: ArtifactRef
    evidence_ids: tuple[OpaqueId, ...] = Field(min_length=1, max_length=4096)
    interpretation_receipt_id: OpaqueId
    finding_verdict: FindingVerdict
    verdict_evidence_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=4096)
    blocking: bool
    command_operation_evidence: tuple[CommandOperationEvidence, ...] = Field(
        default=(), max_length=64
    )

    @model_validator(mode="after")
    def _validate_finding(self) -> Self:
        _validate_origin(
            self.candidate_origin,
            self.root_cause_fingerprint,
            self.producer_lineage,
        )
        lineage_ids = [item.lineage_id for item in self.producer_lineage]
        if len(lineage_ids) != len(set(lineage_ids)):
            raise ValueError("finding producer lineage IDs must be unique")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("finding evidence_ids must be unique")
        if not set(self.verdict_evidence_ids).issubset(self.evidence_ids):
            raise ValueError("verdict evidence must reference finding evidence_ids")
        command_ids = tuple(item.scanner_signal_id for item in self.command_operation_evidence)
        if len(command_ids) != len(set(command_ids)):
            raise ValueError("finding command operation evidence must be unique")
        if self.command_operation_evidence and self.cwe_id != "CWE-78":
            raise ValueError("command operation evidence requires CWE-78")
        if not set(command_ids).issubset(self.evidence_ids):
            raise ValueError("command operation evidence must cite finding evidence")
        bound_ids = tuple(
            value
            for item in self.command_operation_evidence
            for value in (
                item.source_evidence_id,
                item.sink_evidence_id,
                item.flow_evidence_id,
            )
            if value is not None
        )
        if not set(bound_ids).issubset(self.evidence_ids):
            raise ValueError("bound command operation evidence must cite finding evidence")
        if (
            self.finding_verdict
            in {
                FindingVerdict.CONFIRMED,
                FindingVerdict.REJECTED_WITH_EVIDENCE,
            }
            and not self.verdict_evidence_ids
        ):
            raise ValueError("terminal positive/negative verdict requires cited evidence")
        if self.evidence_graph_ref.tenant_id != self.repository_revision.tenant_id:
            raise ValueError("finding and EvidenceGraph reference must belong to the same tenant")
        _require_extension_tenant(self, self.repository_revision.tenant_id)
        return self


class PatchCandidate(WireModel):
    patch_id: OpaqueId
    finding_id: OpaqueId
    repository_revision: RepositoryRevision
    unified_diff_sha256: Sha256
    diff_ref: ArtifactRef
    author: ProducerRef
    patch_status: PatchStatus
    parent_patch_id: OpaqueId | None = None

    @model_validator(mode="after")
    def _validate_diff_reference(self) -> Self:
        if self.diff_ref.content_sha256 != self.unified_diff_sha256:
            raise ValueError("diff_ref hash must match unified_diff_sha256")
        if self.diff_ref.data_class is not DataClass.CONFIDENTIAL_SOURCE:
            raise ValueError("diff bytes require a DC3_CONFIDENTIAL_SOURCE ArtifactRef")
        if self.diff_ref.tenant_id != self.repository_revision.tenant_id:
            raise ValueError("patch and diff reference must belong to the same tenant")
        _require_extension_tenant(self, self.repository_revision.tenant_id)
        return self


class ResourceUsage(WireModel):
    elapsed_ms: NonNegativeInt
    peak_memory_bytes: NonNegativeInt
    cpu_time_ms: NonNegativeInt


class ValidationGateResult(WireModel):
    ordinal: PositiveInt
    gate_id: OpaqueId
    gate_outcome: ValidationGateOutcome
    producer: ProducerRef
    input_hashes: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    output_hashes: tuple[Sha256, ...] = Field(default=(), max_length=4096)
    reason_code: ReasonCode | None = None
    resource_usage: ResourceUsage

    @model_validator(mode="after")
    def _validate_gate(self) -> Self:
        if self.gate_outcome is ValidationGateOutcome.PASSED and not self.output_hashes:
            raise ValueError("PASSED validation gate requires output hashes")
        if self.gate_outcome is not ValidationGateOutcome.PASSED and self.reason_code is None:
            raise ValueError("non-passing validation gate requires reason_code")
        return self


class ValidationResult(WireModel):
    validation_id: OpaqueId
    tenant_id: OpaqueId
    patch_id: OpaqueId
    head_sha: CommitSha
    sandbox_profile: ComponentPin
    gates: tuple[ValidationGateResult, ...] = Field(min_length=1, max_length=128)
    validation_outcome: ValidationOutcome
    result_sha256: Sha256

    @model_validator(mode="after")
    def _validate_ordered_gates(self) -> Self:
        ordinals = [gate.ordinal for gate in self.gates]
        if ordinals != list(range(1, len(self.gates) + 1)):
            raise ValueError("validation gate ordinals must be contiguous and ordered")
        if self.validation_outcome is ValidationOutcome.VALIDATED and any(
            gate.gate_outcome is not ValidationGateOutcome.PASSED for gate in self.gates
        ):
            raise ValueError("VALIDATED requires every ordered gate to pass")
        _require_extension_tenant(self, self.tenant_id)
        return self


class Decision(WireModel):
    decision_id: OpaqueId
    actor_id: OpaqueId
    policy: ComponentPin
    decided_at: UtcTimestamp
    scope_sha256: Sha256
    head_sha: CommitSha
    decision_outcome: DecisionOutcome
    reason_code: ReasonCode


class AuditRun(WireModel):
    run_id: OpaqueId
    execution_identity: RunExecutionIdentity
    current_head_sha: CommitSha
    audit_outcome: AuditRunOutcome
    analysis_health: AnalysisHealth
    finding_gate_state: FindingGateState
    coverage_manifest: CoverageManifest
    finding_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=100000)
    blocking_finding_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=100000)
    unresolved_gate_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=100000)
    publication_preconditions_met: bool
    cancelled: bool = False
    created_at: UtcTimestamp
    completed_at: UtcTimestamp

    @model_validator(mode="after")
    def _validate_run_outcome(self) -> Self:
        if len(self.finding_ids) != len(set(self.finding_ids)):
            raise ValueError("finding_ids must be unique")
        if len(self.blocking_finding_ids) != len(set(self.blocking_finding_ids)):
            raise ValueError("blocking_finding_ids must be unique")
        if not set(self.blocking_finding_ids).issubset(self.finding_ids):
            raise ValueError("blocking_finding_ids must reference finding_ids")
        if len(self.unresolved_gate_ids) != len(set(self.unresolved_gate_ids)):
            raise ValueError("unresolved_gate_ids must be unique")
        if self.completed_at < self.created_at:
            raise ValueError("completed_at cannot precede created_at")
        if self.coverage_manifest.catalogue != self.execution_identity.stage_catalogue:
            raise ValueError("coverage catalogue must equal the execution identity pin")
        if (
            self.coverage_manifest.execution_identity_hash
            != self.execution_identity.execution_identity_hash
        ):
            raise ValueError("coverage manifest must bind the exact execution identity hash")
        revision_head = self.execution_identity.repository_revision.head_sha
        revision_tenant = self.execution_identity.repository_revision.tenant_id
        if any(
            candidate.head_sha != revision_head
            for candidate in self.coverage_manifest.discovery_candidates
        ):
            raise ValueError("every discovery candidate must bind to the execution HEAD")
        if any(
            receipt.head_sha != revision_head
            for receipt in self.coverage_manifest.model_discovery_receipts
        ) or any(
            receipt.head_sha != revision_head
            for receipt in self.coverage_manifest.candidate_interpretation_receipts
        ):
            raise ValueError("every model receipt must bind to the execution HEAD")
        if (
            any(
                candidate.tenant_id != revision_tenant
                for candidate in self.coverage_manifest.discovery_candidates
            )
            or any(
                receipt.tenant_id != revision_tenant
                for receipt in self.coverage_manifest.model_discovery_receipts
            )
            or any(
                receipt.tenant_id != revision_tenant
                for receipt in self.coverage_manifest.candidate_interpretation_receipts
            )
        ):
            raise ValueError("every candidate and model receipt must bind to the execution tenant")

        has_blocking = bool(self.blocking_finding_ids)
        if has_blocking is not (self.finding_gate_state is FindingGateState.BLOCKING):
            raise ValueError("finding_gate_state must agree with blocking_finding_ids")

        if self.current_head_sha != revision_head:
            expected_outcome = AuditRunOutcome.SUPERSEDED
        elif self.cancelled:
            expected_outcome = AuditRunOutcome.CANCELLED
        elif has_blocking:
            expected_outcome = AuditRunOutcome.FAIL
        elif self.analysis_health is AnalysisHealth.UNAVAILABLE:
            expected_outcome = AuditRunOutcome.ERROR
        elif (
            self.analysis_health is not AnalysisHealth.HEALTHY
            or self.finding_gate_state is FindingGateState.INCONCLUSIVE
            or not self.coverage_manifest.coverage_complete
            or self.unresolved_gate_ids
            or not self.publication_preconditions_met
        ):
            expected_outcome = AuditRunOutcome.INDETERMINATE
        else:
            expected_outcome = AuditRunOutcome.PASS
        if self.audit_outcome is not expected_outcome:
            raise ValueError(
                f"audit_outcome must be {expected_outcome.value} for recorded evidence"
            )
        _require_extension_tenant(self, revision_tenant)
        return self
