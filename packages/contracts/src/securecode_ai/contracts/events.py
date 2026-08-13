"""Immutable, versioned AuditEvent envelope and typed safe payloads."""

from __future__ import annotations

import hashlib
import json
import re
from enum import StrEnum
from typing import Annotated, Self

from pydantic import Field, model_validator

from .base import (
    CommitSha,
    DataClass,
    OpaqueId,
    ReasonCode,
    SemVer,
    Sha256,
    WireModel,
)
from .domain import (
    ArtifactRef,
    AuditRun,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    CoverageManifest,
    Decision,
    DiscoveryCandidate,
    DiscoveryLane,
    Evidence,
    FindingCase,
    ModelDiscoveryReceipt,
    PatchCandidate,
    ProducerRef,
    RawSignal,
    UtcTimestamp,
    ValidationResult,
    _require_extension_tenant,
)
from .ids import derive_event_id

PositiveSequence = Annotated[int, Field(ge=1, le=9_007_199_254_740_991)]
_EVENT_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class EventType(StrEnum):
    RUN_REQUESTED = "RunRequested"
    RUN_STARTED = "RunStarted"
    RUN_CANCELLED = "RunCancelled"
    RUN_SUPERSEDED = "RunSuperseded"
    RUN_COMPLETED = "RunCompleted"
    INTAKE_COMPLETED = "IntakeCompleted"
    COVERAGE_UPDATED = "CoverageUpdated"
    SCANNER_COMPLETED = "ScannerCompleted"
    RAW_SIGNAL_CREATED = "RawSignalCreated"
    DISCOVERY_STARTED = "DiscoveryStarted"
    DISCOVERY_COMPLETED = "DiscoveryCompleted"
    CANDIDATE_NORMALIZED = "CandidateNormalized"
    FINDING_CREATED = "FindingCreated"
    EVIDENCE_ADDED = "EvidenceAdded"
    MODEL_CALL_COMPLETED = "ModelCallCompleted"
    CANDIDATE_INTERPRETATION_RECORDED = "CandidateInterpretationRecorded"
    VERDICT_RECORDED = "VerdictRecorded"
    PATCH_PROPOSED = "PatchProposed"
    VALIDATION_GATE_COMPLETED = "ValidationGateCompleted"
    PATCH_VALIDATED = "PatchValidated"
    HUMAN_DECISION_RECORDED = "HumanDecisionRecorded"
    WAIVER_EXPIRED = "WaiverExpired"
    ARTIFACT_RECORDED = "ArtifactRecorded"
    EGRESS_EVALUATED = "EgressEvaluated"
    SCM_PUBLICATION_RECORDED = "ScmPublicationRecorded"


_INLINE_TYPED_EVENT_TYPES = frozenset(
    {
        EventType.RUN_COMPLETED,
        EventType.COVERAGE_UPDATED,
        EventType.RAW_SIGNAL_CREATED,
        EventType.DISCOVERY_STARTED,
        EventType.DISCOVERY_COMPLETED,
        EventType.CANDIDATE_NORMALIZED,
        EventType.FINDING_CREATED,
        EventType.EVIDENCE_ADDED,
        EventType.VERDICT_RECORDED,
        EventType.CANDIDATE_INTERPRETATION_RECORDED,
        EventType.PATCH_PROPOSED,
        EventType.VALIDATION_GATE_COMPLETED,
        EventType.PATCH_VALIDATED,
        EventType.HUMAN_DECISION_RECORDED,
        EventType.WAIVER_EXPIRED,
        EventType.SCM_PUBLICATION_RECORDED,
    }
)
_HEAD_BOUND_EVENT_TYPES = frozenset(
    {
        EventType.RUN_COMPLETED,
        EventType.COVERAGE_UPDATED,
        EventType.RAW_SIGNAL_CREATED,
        EventType.DISCOVERY_STARTED,
        EventType.DISCOVERY_COMPLETED,
        EventType.CANDIDATE_NORMALIZED,
        EventType.FINDING_CREATED,
        EventType.EVIDENCE_ADDED,
        EventType.VERDICT_RECORDED,
        EventType.CANDIDATE_INTERPRETATION_RECORDED,
        EventType.PATCH_PROPOSED,
        EventType.VALIDATION_GATE_COMPLETED,
        EventType.PATCH_VALIDATED,
        EventType.HUMAN_DECISION_RECORDED,
        EventType.WAIVER_EXPIRED,
    }
)
_DATA_CLASS_RANK = {data_class.value: rank for rank, data_class in enumerate(DataClass)}
_TYPED_PAYLOAD_OWNERS: dict[str, frozenset[EventType]] = {
    "model_discovery_receipt": frozenset({EventType.DISCOVERY_COMPLETED}),
    "discovery_candidate": frozenset({EventType.CANDIDATE_NORMALIZED}),
    "candidate_interpretation_receipt": frozenset({EventType.CANDIDATE_INTERPRETATION_RECORDED}),
    "coverage_manifest": frozenset({EventType.COVERAGE_UPDATED}),
    "audit_run": frozenset({EventType.RUN_COMPLETED}),
    "raw_signal": frozenset({EventType.RAW_SIGNAL_CREATED}),
    "evidence": frozenset({EventType.EVIDENCE_ADDED}),
    "finding_case": frozenset({EventType.FINDING_CREATED, EventType.VERDICT_RECORDED}),
    "patch_candidate": frozenset({EventType.PATCH_PROPOSED}),
    "validation_result": frozenset(
        {EventType.VALIDATION_GATE_COMPLETED, EventType.PATCH_VALIDATED}
    ),
    "decision": frozenset({EventType.HUMAN_DECISION_RECORDED, EventType.WAIVER_EXPIRED}),
    "artifact_ref": frozenset({EventType.ARTIFACT_RECORDED, EventType.EGRESS_EVALUATED}),
}
_PRIMITIVE_PAYLOAD_OWNERS: dict[str, frozenset[EventType]] = {
    "requested_head_sha": frozenset({EventType.SCM_PUBLICATION_RECORDED}),
    "current_head_sha": frozenset({EventType.SCM_PUBLICATION_RECORDED}),
    "platform_response_id": frozenset({EventType.SCM_PUBLICATION_RECORDED}),
    "candidate_origin": frozenset({EventType.CANDIDATE_NORMALIZED}),
    "lane": frozenset(
        {
            EventType.DISCOVERY_STARTED,
            EventType.DISCOVERY_COMPLETED,
            EventType.CANDIDATE_NORMALIZED,
        }
    ),
    "producer": frozenset(
        {
            EventType.DISCOVERY_STARTED,
            EventType.DISCOVERY_COMPLETED,
            EventType.CANDIDATE_NORMALIZED,
        }
    ),
    "input_hashes": frozenset(
        {
            EventType.INTAKE_COMPLETED,
            EventType.SCANNER_COMPLETED,
            EventType.DISCOVERY_STARTED,
            EventType.DISCOVERY_COMPLETED,
            EventType.CANDIDATE_NORMALIZED,
            EventType.MODEL_CALL_COMPLETED,
            EventType.VALIDATION_GATE_COMPLETED,
            EventType.EGRESS_EVALUATED,
        }
    ),
    "output_hashes": frozenset(
        {
            EventType.INTAKE_COMPLETED,
            EventType.SCANNER_COMPLETED,
            EventType.DISCOVERY_COMPLETED,
            EventType.CANDIDATE_NORMALIZED,
            EventType.MODEL_CALL_COMPLETED,
            EventType.VALIDATION_GATE_COMPLETED,
            EventType.EGRESS_EVALUATED,
        }
    ),
    "terminal_reason_code": frozenset(
        {
            EventType.INTAKE_COMPLETED,
            EventType.SCANNER_COMPLETED,
            EventType.DISCOVERY_COMPLETED,
            EventType.CANDIDATE_NORMALIZED,
            EventType.MODEL_CALL_COMPLETED,
            EventType.VALIDATION_GATE_COMPLETED,
            EventType.EGRESS_EVALUATED,
        }
    ),
}


def _extension_data_classes(value: object) -> tuple[str, ...]:
    """Collect extension classifications across a public event envelope."""

    if isinstance(value, WireModel):
        classes = tuple(extension.data_class.value for extension in value.extensions)
        nested = tuple(
            data_class
            for field_name in type(value).model_fields
            if field_name != "extensions"
            for data_class in _extension_data_classes(getattr(value, field_name))
        )
        return (*classes, *nested)
    if isinstance(value, tuple):
        return tuple(data_class for item in value for data_class in _extension_data_classes(item))
    return ()


class ActorType(StrEnum):
    USER = "user"
    SERVICE = "service"
    WORKER = "worker"
    POLICY = "policy"
    SYSTEM = "system"


class ActorRef(WireModel):
    actor_id: OpaqueId
    actor_type: ActorType


class EventSafePayload(WireModel):
    """Closed metadata-only payload; intentionally has no free-form text field."""

    head_sha: CommitSha | None = None
    requested_head_sha: CommitSha | None = None
    current_head_sha: CommitSha | None = None
    producer: ProducerRef | None = None
    lane: DiscoveryLane | None = None
    candidate_origin: CandidateOrigin | None = None
    input_hashes: tuple[Sha256, ...] = Field(default=(), max_length=4096)
    output_hashes: tuple[Sha256, ...] = Field(default=(), max_length=4096)
    terminal_reason_code: ReasonCode | None = None
    model_discovery_receipt: ModelDiscoveryReceipt | None = None
    discovery_candidate: DiscoveryCandidate | None = None
    candidate_interpretation_receipt: CandidateInterpretationReceipt | None = None
    coverage_manifest: CoverageManifest | None = None
    audit_run: AuditRun | None = None
    raw_signal: RawSignal | None = None
    evidence: Evidence | None = None
    finding_case: FindingCase | None = None
    patch_candidate: PatchCandidate | None = None
    validation_result: ValidationResult | None = None
    decision: Decision | None = None
    artifact_ref: ArtifactRef | None = None
    platform_response_id: OpaqueId | None = None

    @property
    def carries_security_state(self) -> bool:
        return bool(
            self.head_sha
            or self.requested_head_sha
            or self.current_head_sha
            or self.input_hashes
            or self.output_hashes
            or self.candidate_origin
            or self.artifact_ref
        ) or any(
            item is not None
            for item in (
                self.model_discovery_receipt,
                self.discovery_candidate,
                self.candidate_interpretation_receipt,
                self.coverage_manifest,
                self.audit_run,
                self.raw_signal,
                self.evidence,
                self.finding_case,
                self.patch_candidate,
                self.validation_result,
                self.decision,
            )
        )


class AuditEvent(WireModel):
    event_id: OpaqueId
    event_type: EventType
    event_version: SemVer
    occurred_at: UtcTimestamp
    recorded_at: UtcTimestamp
    tenant_id: OpaqueId
    run_id: OpaqueId
    sequence: PositiveSequence
    previous_event_hash: Sha256 | None
    actor: ActorRef
    correlation_id: OpaqueId
    causation_id: OpaqueId | None = None
    idempotency_key: OpaqueId
    execution_identity_hash: Sha256
    data_class: DataClass
    safe_payload: EventSafePayload | None = None
    payload_ref: ArtifactRef | None = None

    @model_validator(mode="after")
    def _validate_event(self) -> Self:
        version_match = _EVENT_VERSION_PATTERN.fullmatch(self.event_version)
        if version_match is None or int(version_match.group(1)) != 1:
            raise ValueError("unsupported event payload major version")
        if self.event_id != derive_event_id(
            tenant_id=self.tenant_id,
            run_id=self.run_id,
            idempotency_key=self.idempotency_key,
        ):
            raise ValueError("event_id does not match stable event identity material")
        if (self.sequence == 1) is not (self.previous_event_hash is None):
            raise ValueError("only sequence one may omit previous_event_hash")
        if (self.safe_payload is None) is (self.payload_ref is None):
            raise ValueError("event requires exactly one safe_payload or payload_ref")
        if self.event_type in _INLINE_TYPED_EVENT_TYPES and self.safe_payload is None:
            raise ValueError(f"{self.event_type.value} requires an inline typed safe payload")
        if self.payload_ref is not None:
            if self.payload_ref.tenant_id != self.tenant_id:
                raise ValueError("event payload reference must belong to the event tenant")
            if self.payload_ref.data_class is not self.data_class:
                raise ValueError("event and payload reference data classes must match")
        elif self.data_class in {DataClass.CONFIDENTIAL_SOURCE, DataClass.RESTRICTED}:
            raise ValueError("DC3/DC4 event payload must use ArtifactRef")
        if self.safe_payload is not None:
            if self.safe_payload.carries_security_state and self.data_class not in {
                DataClass.CONFIDENTIAL_SECURITY,
            }:
                raise ValueError("security-state safe payload requires DC2 classification")
            self._validate_typed_payload(self.safe_payload)
        _require_extension_tenant(self, self.tenant_id)
        if any(
            _DATA_CLASS_RANK[extension_class] > _DATA_CLASS_RANK[self.data_class.value]
            for extension_class in _extension_data_classes(self)
        ):
            raise ValueError("event data class must not downgrade a nested extension")
        return self

    def _validate_typed_payload(self, payload: EventSafePayload) -> None:
        if payload.artifact_ref is not None and payload.artifact_ref.data_class in {
            DataClass.CONFIDENTIAL_SOURCE,
            DataClass.RESTRICTED,
        }:
            raise ValueError("DC3/DC4 artifact events must use the top-level payload_ref")
        for field_name, owners in _TYPED_PAYLOAD_OWNERS.items():
            if getattr(payload, field_name) is not None and self.event_type not in owners:
                raise ValueError(
                    f"{field_name} is not permitted for event type {self.event_type.value}"
                )
        for field_name, owners in _PRIMITIVE_PAYLOAD_OWNERS.items():
            value = getattr(payload, field_name)
            is_present = bool(value) if isinstance(value, tuple) else value is not None
            if is_present and self.event_type not in owners:
                raise ValueError(
                    f"{field_name} is not permitted for event type {self.event_type.value}"
                )
        if self.event_type in _HEAD_BOUND_EVENT_TYPES and payload.head_sha is None:
            raise ValueError(f"{self.event_type.value} requires exact payload head_sha")
        if payload.head_sha is not None:
            for bound in (
                payload.model_discovery_receipt,
                payload.discovery_candidate,
                payload.candidate_interpretation_receipt,
                payload.raw_signal,
                payload.evidence,
                payload.validation_result,
            ):
                if bound is not None and bound.head_sha != payload.head_sha:
                    raise ValueError("event payload objects must bind to payload head_sha")
            if payload.coverage_manifest is not None and (
                any(
                    candidate.head_sha != payload.head_sha
                    for candidate in payload.coverage_manifest.discovery_candidates
                )
                or any(
                    receipt.head_sha != payload.head_sha
                    for receipt in payload.coverage_manifest.model_discovery_receipts
                )
                or any(
                    receipt.head_sha != payload.head_sha
                    for receipt in payload.coverage_manifest.candidate_interpretation_receipts
                )
            ):
                raise ValueError("coverage payload objects must bind to payload head_sha")
            if (
                payload.audit_run is not None
                and payload.audit_run.current_head_sha != payload.head_sha
            ):
                raise ValueError("completed AuditRun must bind to payload head_sha")
            if (
                payload.finding_case is not None
                and payload.finding_case.repository_revision.head_sha != payload.head_sha
            ):
                raise ValueError("finding must bind to payload head_sha")
            if (
                payload.patch_candidate is not None
                and payload.patch_candidate.repository_revision.head_sha != payload.head_sha
            ):
                raise ValueError("patch must bind to payload head_sha")
            if payload.decision is not None and payload.decision.head_sha != payload.head_sha:
                raise ValueError("decision must bind to payload head_sha")
        if self.event_type in {
            EventType.DISCOVERY_STARTED,
            EventType.DISCOVERY_COMPLETED,
        } and (payload.lane is None or payload.producer is None or payload.head_sha is None):
            raise ValueError("discovery event requires lane, producer and exact head")
        if self.event_type is EventType.DISCOVERY_STARTED and not payload.input_hashes:
            raise ValueError("DiscoveryStarted requires input hashes")
        if self.event_type is EventType.DISCOVERY_COMPLETED:
            if (
                not payload.input_hashes
                or not payload.output_hashes
                or payload.terminal_reason_code is None
            ):
                raise ValueError(
                    "DiscoveryCompleted requires input/output hashes and terminal reason"
                )
            if (
                payload.lane is DiscoveryLane.MODEL_NATIVE
                and payload.model_discovery_receipt is None
            ):
                raise ValueError("model-native DiscoveryCompleted requires its receipt")
            if (
                payload.lane is DiscoveryLane.DETERMINISTIC
                and payload.model_discovery_receipt is not None
            ):
                raise ValueError("deterministic DiscoveryCompleted cannot carry a model receipt")
            if payload.model_discovery_receipt is not None:
                receipt = payload.model_discovery_receipt
                if receipt.input_sha256 not in payload.input_hashes:
                    raise ValueError("DiscoveryCompleted must retain its receipt input hash")
                if (
                    receipt.output_sha256 is not None
                    and receipt.output_sha256 not in payload.output_hashes
                ):
                    raise ValueError("DiscoveryCompleted must retain its receipt output hash")
                if (payload.terminal_reason_code == "COMPLETED_ZERO") is not (
                    receipt.is_completed_zero
                ):
                    raise ValueError(
                        "COMPLETED_ZERO terminal reason must exactly match its model receipt"
                    )
        required_payloads: dict[EventType, object | None] = {
            EventType.CANDIDATE_NORMALIZED: payload.discovery_candidate,
            EventType.CANDIDATE_INTERPRETATION_RECORDED: (payload.candidate_interpretation_receipt),
            EventType.COVERAGE_UPDATED: payload.coverage_manifest,
            EventType.RUN_COMPLETED: payload.audit_run,
            EventType.RAW_SIGNAL_CREATED: payload.raw_signal,
            EventType.EVIDENCE_ADDED: payload.evidence,
            EventType.FINDING_CREATED: payload.finding_case,
            EventType.VERDICT_RECORDED: payload.finding_case,
            EventType.PATCH_PROPOSED: payload.patch_candidate,
            EventType.VALIDATION_GATE_COMPLETED: payload.validation_result,
            EventType.PATCH_VALIDATED: payload.validation_result,
            EventType.HUMAN_DECISION_RECORDED: payload.decision,
            EventType.WAIVER_EXPIRED: payload.decision,
        }
        if self.event_type in required_payloads and required_payloads[self.event_type] is None:
            raise ValueError(f"{self.event_type.value} requires its typed payload")
        if payload.discovery_candidate is not None:
            if payload.candidate_origin is None:
                raise ValueError("CandidateNormalized requires explicit candidate_origin")
            if payload.candidate_origin is not payload.discovery_candidate.candidate_origin:
                raise ValueError("event candidate_origin must match the normalized candidate")
            if self.event_type is EventType.CANDIDATE_NORMALIZED and (
                payload.producer is None
                or not payload.input_hashes
                or not payload.output_hashes
                or payload.terminal_reason_code is None
            ):
                raise ValueError(
                    "CandidateNormalized requires producer, input/output hashes and terminal reason"
                )
            if self.event_type is EventType.CANDIDATE_NORMALIZED:
                expected_lane = {
                    CandidateOrigin.DETERMINISTIC: DiscoveryLane.DETERMINISTIC,
                    CandidateOrigin.MODEL_NATIVE: DiscoveryLane.MODEL_NATIVE,
                    CandidateOrigin.HYBRID: None,
                }[payload.discovery_candidate.candidate_origin]
                if payload.lane is not expected_lane:
                    raise ValueError(
                        "CandidateNormalized lane must match its closed CandidateOrigin"
                    )
        if payload.coverage_manifest is not None and (
            payload.coverage_manifest.execution_identity_hash != self.execution_identity_hash
        ):
            raise ValueError("coverage event identity must match the event identity")
        if payload.audit_run is not None:
            if payload.audit_run.run_id != self.run_id:
                raise ValueError("completed AuditRun must match event run_id")
            if (
                payload.audit_run.execution_identity.execution_identity_hash
                != self.execution_identity_hash
            ):
                raise ValueError("completed AuditRun identity must match the event identity")
            if payload.audit_run.execution_identity.repository_revision.tenant_id != self.tenant_id:
                raise ValueError("completed AuditRun tenant must match the event tenant")
        if self.event_type is EventType.SCM_PUBLICATION_RECORDED and any(
            value is None
            for value in (
                payload.requested_head_sha,
                payload.current_head_sha,
                payload.platform_response_id,
            )
        ):
            raise ValueError("SCM publication requires requested/current HEAD and response ID")
        if self.event_type is EventType.ARTIFACT_RECORDED and payload.artifact_ref is None:
            raise ValueError("ArtifactRecorded safe payload requires ArtifactRef")
        for tenant_bound in (
            payload.model_discovery_receipt,
            payload.discovery_candidate,
            payload.candidate_interpretation_receipt,
            payload.raw_signal,
            payload.evidence,
            payload.validation_result,
            payload.artifact_ref,
        ):
            if tenant_bound is not None and tenant_bound.tenant_id != self.tenant_id:
                raise ValueError("event payload objects must belong to the event tenant")
        for revision_bound in (payload.finding_case, payload.patch_candidate):
            if (
                revision_bound is not None
                and revision_bound.repository_revision.tenant_id != self.tenant_id
            ):
                raise ValueError("event revision payload must belong to the event tenant")

    def canonical_hash(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()


__all__ = ["ActorRef", "ActorType", "AuditEvent", "EventSafePayload", "EventType"]
