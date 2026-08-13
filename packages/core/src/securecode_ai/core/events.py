"""Pure append-only event stream and deterministic replay projection."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from enum import StrEnum

from securecode_ai.contracts import (
    AuditEvent,
    AuditRun,
    CandidateInterpretationReceipt,
    CoverageManifest,
    DiscoveryCandidate,
    EventType,
    ModelDiscoveryReceipt,
    RunExecutionIdentity,
)


class AppendDisposition(StrEnum):
    APPENDED = "APPENDED"
    REPLAYED = "REPLAYED"


class EventConflictCode(StrEnum):
    INVALID_EVENT = "INVALID_EVENT"
    DUPLICATE_MISMATCH = "DUPLICATE_MISMATCH"
    STREAM_SCOPE_MISMATCH = "STREAM_SCOPE_MISMATCH"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    PREVIOUS_HASH_MISMATCH = "PREVIOUS_HASH_MISMATCH"
    PROJECTION_CONFLICT = "PROJECTION_CONFLICT"


_ANALYSIS_STATE_EVENT_TYPES = frozenset(
    {
        EventType.RUN_REQUESTED,
        EventType.RUN_STARTED,
        EventType.RUN_CANCELLED,
        EventType.RUN_SUPERSEDED,
        EventType.RUN_COMPLETED,
        EventType.INTAKE_COMPLETED,
        EventType.COVERAGE_UPDATED,
        EventType.SCANNER_COMPLETED,
        EventType.RAW_SIGNAL_CREATED,
        EventType.DISCOVERY_STARTED,
        EventType.DISCOVERY_COMPLETED,
        EventType.CANDIDATE_NORMALIZED,
        EventType.FINDING_CREATED,
        EventType.EVIDENCE_ADDED,
        EventType.MODEL_CALL_COMPLETED,
        EventType.CANDIDATE_INTERPRETATION_RECORDED,
        EventType.VERDICT_RECORDED,
        EventType.PATCH_PROPOSED,
        EventType.VALIDATION_GATE_COMPLETED,
        EventType.PATCH_VALIDATED,
    }
)

_COVERAGE_INVALIDATING_EVENT_TYPES = _ANALYSIS_STATE_EVENT_TYPES - {
    EventType.RUN_REQUESTED,
    EventType.RUN_STARTED,
    EventType.RUN_CANCELLED,
    EventType.RUN_SUPERSEDED,
    EventType.RUN_COMPLETED,
    EventType.COVERAGE_UPDATED,
}


class EventConflict(ValueError):
    def __init__(self, code: EventConflictCode, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class AppendReceipt:
    disposition: AppendDisposition
    sequence: int
    event_hash: str


@dataclass(frozen=True, slots=True)
class EventStream:
    tenant_id: str
    run_id: str
    execution_identity: RunExecutionIdentity
    events: tuple[AuditEvent, ...] = ()

    def __post_init__(self) -> None:
        try:
            identity = RunExecutionIdentity.model_validate(
                self.execution_identity.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise EventConflict(
                EventConflictCode.INVALID_EVENT,
                "execution identity failed trust-boundary validation",
            ) from error
        if identity.repository_revision.tenant_id != self.tenant_id:
            raise EventConflict(
                EventConflictCode.STREAM_SCOPE_MISMATCH,
                "execution identity tenant differs from the stream",
            )
        object.__setattr__(self, "execution_identity", identity)
        seen_event_ids: set[str] = set()
        seen_idempotency_keys: set[str] = set()
        validated_events: list[AuditEvent] = []
        previous_hash: str | None = None
        for expected_sequence, supplied_event in enumerate(self.events, start=1):
            event = self._validated_event(supplied_event)
            self._validate_scope(event)
            if event.event_id in seen_event_ids or event.idempotency_key in seen_idempotency_keys:
                raise EventConflict(
                    EventConflictCode.DUPLICATE_MISMATCH,
                    "stored stream cannot contain duplicate event/idempotency keys",
                )
            if event.sequence != expected_sequence:
                raise EventConflict(
                    EventConflictCode.SEQUENCE_GAP,
                    f"expected sequence {expected_sequence}, got {event.sequence}",
                )
            if event.previous_event_hash != previous_hash:
                raise EventConflict(
                    EventConflictCode.PREVIOUS_HASH_MISMATCH,
                    "previous_event_hash does not match canonical prior event",
                )
            seen_event_ids.add(event.event_id)
            seen_idempotency_keys.add(event.idempotency_key)
            previous_hash = event.canonical_hash()
            validated_events.append(event)
        object.__setattr__(self, "events", tuple(validated_events))

    @property
    def execution_identity_hash(self) -> str:
        return self.execution_identity.execution_identity_hash

    @property
    def head_sha(self) -> str:
        return self.execution_identity.repository_revision.head_sha

    @staticmethod
    def _validated_event(event: AuditEvent) -> AuditEvent:
        try:
            return AuditEvent.model_validate(event.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as error:
            raise EventConflict(
                EventConflictCode.INVALID_EVENT,
                "event failed trust-boundary validation",
            ) from error

    def _validate_scope(self, event: AuditEvent) -> None:
        if (
            event.tenant_id != self.tenant_id
            or event.run_id != self.run_id
            or event.execution_identity_hash != self.execution_identity_hash
        ):
            raise EventConflict(
                EventConflictCode.STREAM_SCOPE_MISMATCH,
                "event tenant/run/execution identity differs from the stream",
            )
        payload = event.safe_payload
        if payload is not None:
            if payload.head_sha is not None and payload.head_sha != self.head_sha:
                raise EventConflict(
                    EventConflictCode.STREAM_SCOPE_MISMATCH,
                    "event revision differs from the admitted stream HEAD",
                )
            if (
                event.event_type is EventType.SCM_PUBLICATION_RECORDED
                and payload.requested_head_sha != self.head_sha
            ):
                raise EventConflict(
                    EventConflictCode.STREAM_SCOPE_MISMATCH,
                    "SCM publication requested HEAD differs from the admitted stream HEAD",
                )

    def append(self, event: AuditEvent) -> tuple[EventStream, AppendReceipt]:
        event = self._validated_event(event)
        duplicate_indexes = {
            index
            for index, existing in enumerate(self.events)
            if existing.event_id == event.event_id
            or existing.idempotency_key == event.idempotency_key
        }
        if duplicate_indexes:
            if len(duplicate_indexes) != 1:
                raise EventConflict(
                    EventConflictCode.DUPLICATE_MISMATCH,
                    "event/idempotency keys resolve to different existing events",
                )
            existing = self.events[duplicate_indexes.pop()]
            if existing != event:
                raise EventConflict(
                    EventConflictCode.DUPLICATE_MISMATCH,
                    "duplicate event/idempotency key has divergent canonical content",
                )
            return self, AppendReceipt(
                AppendDisposition.REPLAYED,
                existing.sequence,
                existing.canonical_hash(),
            )
        self._validate_scope(event)
        expected_sequence = len(self.events) + 1
        if event.sequence != expected_sequence:
            raise EventConflict(
                EventConflictCode.SEQUENCE_GAP,
                f"expected sequence {expected_sequence}, got {event.sequence}",
            )
        expected_previous = self.events[-1].canonical_hash() if self.events else None
        if event.previous_event_hash != expected_previous:
            raise EventConflict(
                EventConflictCode.PREVIOUS_HASH_MISMATCH,
                "previous_event_hash does not match canonical prior event",
            )
        appended = replace(self, events=(*self.events, event))
        return appended, AppendReceipt(
            AppendDisposition.APPENDED,
            event.sequence,
            event.canonical_hash(),
        )

    @classmethod
    def replay(
        cls,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity: RunExecutionIdentity,
        events: tuple[AuditEvent, ...],
    ) -> EventStream:
        stream = cls(
            tenant_id=tenant_id,
            run_id=run_id,
            execution_identity=execution_identity,
        )
        for event in events:
            stream, receipt = stream.append(event)
            if receipt.disposition is not AppendDisposition.APPENDED:
                raise EventConflict(
                    EventConflictCode.DUPLICATE_MISMATCH,
                    "stored replay cannot contain duplicate events",
                )
        return stream


@dataclass(frozen=True, slots=True)
class RunProjection:
    tenant_id: str
    run_id: str
    execution_identity_hash: str
    head_sha: str
    last_sequence: int
    last_event_hash: str | None
    coverage_manifest: CoverageManifest | None
    audit_run: AuditRun | None
    discovery_candidates: tuple[DiscoveryCandidate, ...]
    model_discovery_receipts: tuple[ModelDiscoveryReceipt, ...]
    candidate_interpretation_receipts: tuple[CandidateInterpretationReceipt, ...]

    def canonical_hash(self) -> str:
        material = {
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "execution_identity_hash": self.execution_identity_hash,
            "head_sha": self.head_sha,
            "last_sequence": self.last_sequence,
            "last_event_hash": self.last_event_hash,
            "coverage_manifest": (
                self.coverage_manifest.model_dump(mode="json")
                if self.coverage_manifest is not None
                else None
            ),
            "audit_run": (
                self.audit_run.model_dump(mode="json") if self.audit_run is not None else None
            ),
            "discovery_candidates": [
                candidate.model_dump(mode="json") for candidate in self.discovery_candidates
            ],
            "model_discovery_receipts": [
                receipt.model_dump(mode="json") for receipt in self.model_discovery_receipts
            ],
            "candidate_interpretation_receipts": [
                receipt.model_dump(mode="json")
                for receipt in self.candidate_interpretation_receipts
            ],
        }
        payload = json.dumps(
            material,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()


def _validate_coverage_receipts(
    coverage: CoverageManifest,
    discovery: dict[str, ModelDiscoveryReceipt],
    interpretations: dict[tuple[str, int], CandidateInterpretationReceipt],
) -> None:
    expected_discovery = {
        receipt.receipt_id: receipt for receipt in coverage.model_discovery_receipts
    }
    expected_interpretations = {
        (receipt.candidate_id, receipt.candidate_version): receipt
        for receipt in coverage.candidate_interpretation_receipts
    }
    current_versions = {
        candidate.candidate_id: candidate.candidate_version
        for candidate in coverage.discovery_candidates
    }
    unexpected_current_or_future = any(
        key not in expected_interpretations
        and key[0] in current_versions
        and key[1] >= current_versions[key[0]]
        for key in interpretations
    )
    if (
        discovery != expected_discovery
        or any(interpretations.get(key) != value for key, value in expected_interpretations.items())
        or unexpected_current_or_future
    ):
        raise EventConflict(
            EventConflictCode.PROJECTION_CONFLICT,
            "prior event receipts do not reconstruct the current CoverageManifest",
        )


def _validate_coverage_snapshot(
    coverage: CoverageManifest,
    discovery: dict[str, ModelDiscoveryReceipt],
    candidates: dict[str, DiscoveryCandidate],
    interpretations: dict[tuple[str, int], CandidateInterpretationReceipt],
) -> None:
    _validate_coverage_receipts(coverage, discovery, interpretations)
    expected_candidates = {
        candidate.candidate_id: candidate for candidate in coverage.discovery_candidates
    }
    if candidates != expected_candidates:
        raise EventConflict(
            EventConflictCode.PROJECTION_CONFLICT,
            "normalized candidates do not exactly reconstruct CoverageManifest",
        )


def rebuild_projection(stream: EventStream) -> RunProjection:
    discovery: dict[str, ModelDiscoveryReceipt] = {}
    candidates: dict[str, DiscoveryCandidate] = {}
    interpretations: dict[tuple[str, int], CandidateInterpretationReceipt] = {}
    coverage: CoverageManifest | None = None
    audit_run: AuditRun | None = None
    terminal = False
    for event in stream.events:
        if terminal and event.event_type in _ANALYSIS_STATE_EVENT_TYPES:
            raise EventConflict(
                EventConflictCode.PROJECTION_CONFLICT,
                "analysis state cannot change after RunCompleted",
            )
        if coverage is not None and event.event_type in _COVERAGE_INVALIDATING_EVENT_TYPES:
            coverage = None
        payload = event.safe_payload
        if payload is None:
            continue
        if (
            event.event_type is EventType.DISCOVERY_COMPLETED
            and payload.model_discovery_receipt is not None
        ):
            discovery_receipt = payload.model_discovery_receipt
            if discovery_receipt.receipt_id in discovery:
                raise EventConflict(
                    EventConflictCode.PROJECTION_CONFLICT,
                    "duplicate model discovery receipt in replay",
                )
            discovery[discovery_receipt.receipt_id] = discovery_receipt
        if event.event_type is EventType.CANDIDATE_NORMALIZED:
            candidate = payload.discovery_candidate
            if candidate is None:  # pragma: no cover - AuditEvent rejects this first
                raise EventConflict(
                    EventConflictCode.PROJECTION_CONFLICT,
                    "CandidateNormalized is missing its typed candidate",
                )
            previous_candidate = candidates.get(candidate.candidate_id)
            expected_version = (
                1 if previous_candidate is None else previous_candidate.candidate_version + 1
            )
            if candidate.candidate_version != expected_version:
                raise EventConflict(
                    EventConflictCode.PROJECTION_CONFLICT,
                    "candidate versions must be contiguous append-only revisions",
                )
            candidates[candidate.candidate_id] = candidate
        if (
            event.event_type is EventType.CANDIDATE_INTERPRETATION_RECORDED
            and payload.candidate_interpretation_receipt is not None
        ):
            interpretation_receipt = payload.candidate_interpretation_receipt
            key = (
                interpretation_receipt.candidate_id,
                interpretation_receipt.candidate_version,
            )
            if key in interpretations:
                raise EventConflict(
                    EventConflictCode.PROJECTION_CONFLICT,
                    "duplicate candidate interpretation receipt in replay",
                )
            if candidates.get(key[0]) is None or candidates[key[0]].candidate_version != key[1]:
                raise EventConflict(
                    EventConflictCode.PROJECTION_CONFLICT,
                    "interpretation must bind the current normalized candidate version",
                )
            interpretations[key] = interpretation_receipt
        if event.event_type is EventType.COVERAGE_UPDATED:
            next_coverage = payload.coverage_manifest
            if next_coverage is None:  # pragma: no cover - AuditEvent rejects this first
                raise EventConflict(
                    EventConflictCode.PROJECTION_CONFLICT,
                    "CoverageUpdated is missing its typed manifest",
                )
            _validate_coverage_snapshot(
                next_coverage,
                discovery,
                candidates,
                interpretations,
            )
            coverage = next_coverage
        if event.event_type is EventType.RUN_COMPLETED:
            next_run = payload.audit_run
            if next_run is None:  # pragma: no cover - AuditEvent rejects this first
                raise EventConflict(
                    EventConflictCode.PROJECTION_CONFLICT,
                    "RunCompleted is missing its typed AuditRun",
                )
            if coverage is None or next_run.coverage_manifest != coverage:
                raise EventConflict(
                    EventConflictCode.PROJECTION_CONFLICT,
                    "RunCompleted does not reproduce the prior latest CoverageManifest",
                )
            _validate_coverage_snapshot(
                coverage,
                discovery,
                candidates,
                interpretations,
            )
            audit_run = next_run
            terminal = True
    last = stream.events[-1] if stream.events else None
    return RunProjection(
        tenant_id=stream.tenant_id,
        run_id=stream.run_id,
        execution_identity_hash=stream.execution_identity_hash,
        head_sha=stream.head_sha,
        last_sequence=last.sequence if last is not None else 0,
        last_event_hash=last.canonical_hash() if last is not None else None,
        coverage_manifest=coverage,
        audit_run=audit_run,
        discovery_candidates=tuple(candidates[key] for key in sorted(candidates)),
        model_discovery_receipts=tuple(discovery[key] for key in sorted(discovery)),
        candidate_interpretation_receipts=tuple(
            interpretations[key] for key in sorted(interpretations)
        ),
    )


__all__ = [
    "AppendDisposition",
    "AppendReceipt",
    "EventConflict",
    "EventConflictCode",
    "EventStream",
    "RunProjection",
    "rebuild_projection",
]
