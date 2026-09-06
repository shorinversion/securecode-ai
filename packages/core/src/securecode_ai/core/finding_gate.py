"""Deterministic, fail-closed policy routing for one investigated candidate.

The Finding Gate accepts only typed receipt metadata.  In particular, it does
not receive model prose, a policy selected by a model, a repository handle, or
any effect capability.  An integration adapter may construct
``FindingGateInput`` from the P3.3 terminal receipt and the P3.4
``SkepticReview`` without coupling this policy reducer to the Auditor loop.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import FindingGateState, FindingVerdict, ModelCallStatus

from .classification import FindingSeverity
from .skeptic import SkepticObjection, SkepticReview

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_MAX_EVIDENCE_IDS: Final = 4_096
_MAX_OBJECTIONS: Final = 1_024


class FindingGateErrorCode(StrEnum):
    """Closed, source-free failure codes for trusted gate construction."""

    INVALID_INPUT = "INVALID_INPUT"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"


class FindingGateContractError(ValueError):
    """A boundary error that intentionally never echoes supplied data."""

    __slots__ = ("code",)

    def __init__(self, code: FindingGateErrorCode) -> None:
        if type(code) is not FindingGateErrorCode:
            raise TypeError("finding gate error code is invalid")
        self.code = code
        super().__init__("finding gate contract validation failed")
        self.__cause__ = None
        self.__context__ = None


class InvestigationTerminalStatus(StrEnum):
    """Typed terminal information supplied by the bounded Auditor loop."""

    COMPLETED = "COMPLETED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    NO_PROGRESS = "NO_PROGRESS"
    CONTEXT_EXHAUSTED = "CONTEXT_EXHAUSTED"
    CANCELLED = "CANCELLED"
    INVALID_RECEIPT = "INVALID_RECEIPT"


class FindingRoute(StrEnum):
    """Policy-selected next actions; this is not a model-controlled field."""

    CONFIRMED = "CONFIRMED"
    REJECTED_WITH_EVIDENCE = "REJECTED_WITH_EVIDENCE"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    HUMAN_ESCALATION = "HUMAN_ESCALATION"
    INDETERMINATE = "INDETERMINATE"


class FindingGateReason(StrEnum):
    """Closed explanation of the deterministic route decision."""

    CONFIRMED = "CONFIRMED"
    REJECTED_WITH_EVIDENCE = "REJECTED_WITH_EVIDENCE"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    AUDITOR_SKEPTIC_CONFLICT = "AUDITOR_SKEPTIC_CONFLICT"
    HIGH_CRITICAL_CONFLICT = "HIGH_CRITICAL_CONFLICT"
    AUDITOR_NON_SUCCESS = "AUDITOR_NON_SUCCESS"
    SKEPTIC_NON_SUCCESS = "SKEPTIC_NON_SUCCESS"
    EVIDENCE_INTEGRITY_FAILURE = "EVIDENCE_INTEGRITY_FAILURE"
    INVESTIGATION_BUDGET_EXHAUSTED = "INVESTIGATION_BUDGET_EXHAUSTED"
    INVESTIGATION_NO_PROGRESS = "INVESTIGATION_NO_PROGRESS"
    INVESTIGATION_CONTEXT_EXHAUSTED = "INVESTIGATION_CONTEXT_EXHAUSTED"
    INVESTIGATION_CANCELLED = "INVESTIGATION_CANCELLED"
    INVESTIGATION_INVALID_RECEIPT = "INVESTIGATION_INVALID_RECEIPT"


@dataclass(frozen=True, slots=True)
class FindingGateInput:
    """Complete metadata seam between investigation/Skeptic and routing policy.

    ``known_evidence_ids`` is the authoritative set accessible to this
    candidate.  The gate retains citation IDs and safe receipt hashes, never
    their content.  Missing or invalid evidence is deliberately constructible
    as a typed input so ``route_finding`` can return ``INDETERMINATE`` rather
    than accidentally treating it as a clean result.
    """

    candidate_id: str
    candidate_version: int
    head_sha: str
    severity: FindingSeverity
    known_evidence_ids: tuple[str, ...]
    auditor_identity: str
    auditor_receipt_sha256: str | None
    auditor_model_call_status: ModelCallStatus
    auditor_verdict: FindingVerdict
    auditor_cited_evidence_ids: tuple[str, ...]
    skeptic_identity: str
    skeptic_receipt_sha256: str | None
    skeptic_model_call_status: ModelCallStatus
    skeptic_verdict: FindingVerdict
    skeptic_effective_verdict: FindingVerdict
    skeptic_objections: tuple[SkepticObjection, ...]
    skeptic_cited_evidence_ids: tuple[str, ...]
    investigation_terminal_status: InvestigationTerminalStatus

    def __post_init__(self) -> None:
        _validate_input_shape(self)
        object.__setattr__(self, "known_evidence_ids", tuple(sorted(self.known_evidence_ids)))
        object.__setattr__(
            self,
            "auditor_cited_evidence_ids",
            tuple(sorted(self.auditor_cited_evidence_ids)),
        )
        object.__setattr__(
            self,
            "skeptic_objections",
            tuple(
                sorted(
                    self.skeptic_objections,
                    key=lambda item: (item.kind.value, item.evidence_ids),
                )
            ),
        )
        object.__setattr__(
            self,
            "skeptic_cited_evidence_ids",
            tuple(sorted(self.skeptic_cited_evidence_ids)),
        )

    @classmethod
    def from_skeptic_review(
        cls,
        review: SkepticReview,
        *,
        severity: FindingSeverity,
        known_evidence_ids: tuple[str, ...],
        auditor_receipt_sha256: str | None,
        auditor_cited_evidence_ids: tuple[str, ...],
        skeptic_receipt_sha256: str | None,
        investigation_terminal_status: InvestigationTerminalStatus,
    ) -> FindingGateInput:
        """Adapt P3.4 metadata without granting P3.5 any loop authority."""

        if type(review) is not SkepticReview:
            raise FindingGateContractError(FindingGateErrorCode.INVALID_INPUT)
        return cls(
            candidate_id=review.candidate_id,
            candidate_version=review.candidate_version,
            head_sha=review.head_sha,
            severity=severity,
            known_evidence_ids=known_evidence_ids,
            auditor_identity=review.auditor_identity,
            auditor_receipt_sha256=auditor_receipt_sha256,
            auditor_model_call_status=ModelCallStatus.SUCCEEDED,
            auditor_verdict=review.auditor_verdict,
            auditor_cited_evidence_ids=auditor_cited_evidence_ids,
            skeptic_identity=review.skeptic_identity,
            skeptic_receipt_sha256=skeptic_receipt_sha256,
            skeptic_model_call_status=review.model_call_status,
            skeptic_verdict=review.skeptic_verdict,
            skeptic_effective_verdict=review.effective_verdict,
            skeptic_objections=review.objections,
            skeptic_cited_evidence_ids=review.cited_evidence_ids,
            investigation_terminal_status=investigation_terminal_status,
        )


@dataclass(frozen=True, slots=True)
class FindingGateDecision:
    """Immutable routing receipt preserving both independent review records."""

    candidate_id: str
    candidate_version: int
    head_sha: str
    severity: FindingSeverity
    known_evidence_ids: tuple[str, ...]
    route: FindingRoute
    finding_gate_state: FindingGateState
    reason: FindingGateReason
    auditor_identity: str
    auditor_receipt_sha256: str | None
    auditor_model_call_status: ModelCallStatus
    auditor_verdict: FindingVerdict
    auditor_cited_evidence_ids: tuple[str, ...]
    skeptic_identity: str
    skeptic_receipt_sha256: str | None
    skeptic_model_call_status: ModelCallStatus
    skeptic_verdict: FindingVerdict
    skeptic_effective_verdict: FindingVerdict
    skeptic_objections: tuple[SkepticObjection, ...]
    skeptic_cited_evidence_ids: tuple[str, ...]
    investigation_terminal_status: InvestigationTerminalStatus

    def __post_init__(self) -> None:
        _validate_decision_shape(self)
        object.__setattr__(self, "known_evidence_ids", tuple(sorted(self.known_evidence_ids)))
        object.__setattr__(
            self,
            "auditor_cited_evidence_ids",
            tuple(sorted(self.auditor_cited_evidence_ids)),
        )
        object.__setattr__(
            self,
            "skeptic_objections",
            tuple(
                sorted(
                    self.skeptic_objections,
                    key=lambda item: (item.kind.value, item.evidence_ids),
                )
            ),
        )
        object.__setattr__(
            self,
            "skeptic_cited_evidence_ids",
            tuple(sorted(self.skeptic_cited_evidence_ids)),
        )


def route_finding(value: FindingGateInput) -> FindingGateDecision:
    """Route one candidate only through deterministic policy and typed metadata.

    No model string, untrusted text, or caller-selected route influences the
    result.  Every invalid/incomplete condition maps to ``INDETERMINATE``;
    only a matching, cited ``REJECTED_WITH_EVIDENCE`` result can yield ``CLEAN``.
    """

    if type(value) is not FindingGateInput:
        raise FindingGateContractError(FindingGateErrorCode.INVALID_INPUT)
    try:
        value = _revalidated_input(value)
    except FindingGateContractError:
        return _integrity_failure_decision(value)

    if not _citations_are_bound(value):
        return _integrity_failure_decision(value)
    if value.investigation_terminal_status is not InvestigationTerminalStatus.COMPLETED:
        return _decision(
            value,
            FindingRoute.INDETERMINATE,
            _terminal_reason(value.investigation_terminal_status),
        )
    if value.auditor_model_call_status is not ModelCallStatus.SUCCEEDED:
        return _decision(value, FindingRoute.INDETERMINATE, FindingGateReason.AUDITOR_NON_SUCCESS)
    if value.skeptic_model_call_status is not ModelCallStatus.SUCCEEDED:
        return _decision(value, FindingRoute.INDETERMINATE, FindingGateReason.SKEPTIC_NON_SUCCESS)
    if not _has_valid_evidence(value):
        return _integrity_failure_decision(value)
    if _has_conflict(value):
        reason = (
            FindingGateReason.HIGH_CRITICAL_CONFLICT
            if value.severity in {FindingSeverity.HIGH, FindingSeverity.CRITICAL}
            else FindingGateReason.AUDITOR_SKEPTIC_CONFLICT
        )
        return _decision(value, FindingRoute.HUMAN_ESCALATION, reason)
    if value.auditor_verdict is FindingVerdict.CONFIRMED:
        return _decision(value, FindingRoute.CONFIRMED, FindingGateReason.CONFIRMED)
    if value.auditor_verdict is FindingVerdict.REJECTED_WITH_EVIDENCE:
        return _decision(
            value,
            FindingRoute.REJECTED_WITH_EVIDENCE,
            FindingGateReason.REJECTED_WITH_EVIDENCE,
        )
    if value.auditor_verdict is FindingVerdict.NEEDS_MORE_EVIDENCE:
        return _decision(
            value,
            FindingRoute.NEEDS_MORE_EVIDENCE,
            FindingGateReason.NEEDS_MORE_EVIDENCE,
        )
    return _integrity_failure_decision(value)


def _revalidated_input(value: FindingGateInput) -> FindingGateInput:
    """Reconstruct the immutable value to detect retained-object mutation."""

    try:
        return FindingGateInput(
            candidate_id=value.candidate_id,
            candidate_version=value.candidate_version,
            head_sha=value.head_sha,
            severity=value.severity,
            known_evidence_ids=value.known_evidence_ids,
            auditor_identity=value.auditor_identity,
            auditor_receipt_sha256=value.auditor_receipt_sha256,
            auditor_model_call_status=value.auditor_model_call_status,
            auditor_verdict=value.auditor_verdict,
            auditor_cited_evidence_ids=value.auditor_cited_evidence_ids,
            skeptic_identity=value.skeptic_identity,
            skeptic_receipt_sha256=value.skeptic_receipt_sha256,
            skeptic_model_call_status=value.skeptic_model_call_status,
            skeptic_verdict=value.skeptic_verdict,
            skeptic_effective_verdict=value.skeptic_effective_verdict,
            skeptic_objections=value.skeptic_objections,
            skeptic_cited_evidence_ids=value.skeptic_cited_evidence_ids,
            investigation_terminal_status=value.investigation_terminal_status,
        )
    except (TypeError, ValueError, AttributeError) as error:
        raise FindingGateContractError(FindingGateErrorCode.INTEGRITY_FAILURE) from error


def _validate_input_shape(value: FindingGateInput) -> None:
    if (
        type(value.candidate_id) is not str
        or _ID.fullmatch(value.candidate_id) is None
        or type(value.candidate_version) is not int
        or isinstance(value.candidate_version, bool)
        or value.candidate_version < 1
        or type(value.head_sha) is not str
        or _COMMIT_SHA.fullmatch(value.head_sha) is None
        or type(value.severity) is not FindingSeverity
        or not _valid_ids(value.known_evidence_ids)
        or type(value.auditor_identity) is not str
        or _ID.fullmatch(value.auditor_identity) is None
        or not _valid_optional_sha(value.auditor_receipt_sha256)
        or type(value.auditor_model_call_status) is not ModelCallStatus
        or type(value.auditor_verdict) is not FindingVerdict
        or not _valid_ids(value.auditor_cited_evidence_ids)
        or type(value.skeptic_identity) is not str
        or _ID.fullmatch(value.skeptic_identity) is None
        or value.skeptic_identity == value.auditor_identity
        or not _valid_optional_sha(value.skeptic_receipt_sha256)
        or type(value.skeptic_model_call_status) is not ModelCallStatus
        or type(value.skeptic_verdict) is not FindingVerdict
        or type(value.skeptic_effective_verdict) is not FindingVerdict
        or type(value.skeptic_objections) is not tuple
        or len(value.skeptic_objections) > _MAX_OBJECTIONS
        or any(type(item) is not SkepticObjection for item in value.skeptic_objections)
        or not _valid_ids(value.skeptic_cited_evidence_ids)
        or type(value.investigation_terminal_status) is not InvestigationTerminalStatus
    ):
        raise FindingGateContractError(FindingGateErrorCode.INVALID_INPUT)


def _validate_decision_shape(value: FindingGateDecision) -> None:
    if (
        type(value.route) is not FindingRoute
        or type(value.finding_gate_state) is not FindingGateState
        or type(value.reason) is not FindingGateReason
        or not _decision_state_is_valid(value.route, value.finding_gate_state)
    ):
        raise FindingGateContractError(FindingGateErrorCode.INVALID_INPUT)
    input_value = FindingGateInput(
        candidate_id=value.candidate_id,
        candidate_version=value.candidate_version,
        head_sha=value.head_sha,
        severity=value.severity,
        known_evidence_ids=value.known_evidence_ids,
        auditor_identity=value.auditor_identity,
        auditor_receipt_sha256=value.auditor_receipt_sha256,
        auditor_model_call_status=value.auditor_model_call_status,
        auditor_verdict=value.auditor_verdict,
        auditor_cited_evidence_ids=value.auditor_cited_evidence_ids,
        skeptic_identity=value.skeptic_identity,
        skeptic_receipt_sha256=value.skeptic_receipt_sha256,
        skeptic_model_call_status=value.skeptic_model_call_status,
        skeptic_verdict=value.skeptic_verdict,
        skeptic_effective_verdict=value.skeptic_effective_verdict,
        skeptic_objections=value.skeptic_objections,
        skeptic_cited_evidence_ids=value.skeptic_cited_evidence_ids,
        investigation_terminal_status=value.investigation_terminal_status,
    )
    if not _citations_are_bound(input_value):
        raise FindingGateContractError(FindingGateErrorCode.INTEGRITY_FAILURE)
    if value.finding_gate_state is FindingGateState.CLEAN and not _has_valid_evidence(input_value):
        raise FindingGateContractError(FindingGateErrorCode.INTEGRITY_FAILURE)


def _valid_ids(values: object) -> bool:
    return (
        type(values) is tuple
        and len(values) <= _MAX_EVIDENCE_IDS
        and all(type(item) is str and _ID.fullmatch(item) is not None for item in values)
        and len(values) == len(set(values))
    )


def _valid_optional_sha(value: object) -> bool:
    return value is None or (type(value) is str and _SHA256.fullmatch(value) is not None)


def _has_valid_evidence(value: FindingGateInput) -> bool:
    known = set(value.known_evidence_ids)
    auditor = set(value.auditor_cited_evidence_ids)
    expected_effective = (
        FindingVerdict.CONFLICTING
        if value.skeptic_objections or value.skeptic_verdict is not value.auditor_verdict
        else value.auditor_verdict
    )
    return (
        bool(known)
        and value.auditor_receipt_sha256 is not None
        and value.skeptic_receipt_sha256 is not None
        and bool(auditor)
        and _citations_are_bound(value)
        and value.auditor_verdict is not FindingVerdict.NOT_EVALUATED
        and value.skeptic_verdict is not FindingVerdict.NOT_EVALUATED
        and value.skeptic_effective_verdict is expected_effective
    )


def _citations_are_bound(value: FindingGateInput) -> bool:
    known = set(value.known_evidence_ids)
    auditor = set(value.auditor_cited_evidence_ids)
    skeptic = set(value.skeptic_cited_evidence_ids)
    objection_ids = {
        evidence_id
        for objection in value.skeptic_objections
        for evidence_id in objection.evidence_ids
    }
    return auditor.issubset(known) and skeptic.issubset(known) and skeptic == objection_ids


def _integrity_failure_decision(value: FindingGateInput) -> FindingGateDecision:
    """Keep only citations still bound to the retained authoritative set."""

    known = set(value.known_evidence_ids)
    objections = tuple(
        item for item in value.skeptic_objections if set(item.evidence_ids).issubset(known)
    )
    skeptic_citations = tuple(
        sorted({evidence_id for item in objections for evidence_id in item.evidence_ids})
    )
    sanitized = FindingGateInput(
        candidate_id=value.candidate_id,
        candidate_version=value.candidate_version,
        head_sha=value.head_sha,
        severity=value.severity,
        known_evidence_ids=value.known_evidence_ids,
        auditor_identity=value.auditor_identity,
        auditor_receipt_sha256=value.auditor_receipt_sha256,
        auditor_model_call_status=value.auditor_model_call_status,
        auditor_verdict=value.auditor_verdict,
        auditor_cited_evidence_ids=tuple(
            item for item in value.auditor_cited_evidence_ids if item in known
        ),
        skeptic_identity=value.skeptic_identity,
        skeptic_receipt_sha256=value.skeptic_receipt_sha256,
        skeptic_model_call_status=value.skeptic_model_call_status,
        skeptic_verdict=value.skeptic_verdict,
        skeptic_effective_verdict=value.skeptic_effective_verdict,
        skeptic_objections=objections,
        skeptic_cited_evidence_ids=skeptic_citations,
        investigation_terminal_status=value.investigation_terminal_status,
    )
    return _decision(
        sanitized,
        FindingRoute.INDETERMINATE,
        FindingGateReason.EVIDENCE_INTEGRITY_FAILURE,
    )


def _has_conflict(value: FindingGateInput) -> bool:
    return value.skeptic_effective_verdict is FindingVerdict.CONFLICTING


def _terminal_reason(status: InvestigationTerminalStatus) -> FindingGateReason:
    return {
        InvestigationTerminalStatus.BUDGET_EXHAUSTED: (
            FindingGateReason.INVESTIGATION_BUDGET_EXHAUSTED
        ),
        InvestigationTerminalStatus.NO_PROGRESS: FindingGateReason.INVESTIGATION_NO_PROGRESS,
        InvestigationTerminalStatus.CONTEXT_EXHAUSTED: (
            FindingGateReason.INVESTIGATION_CONTEXT_EXHAUSTED
        ),
        InvestigationTerminalStatus.CANCELLED: FindingGateReason.INVESTIGATION_CANCELLED,
        InvestigationTerminalStatus.INVALID_RECEIPT: (
            FindingGateReason.INVESTIGATION_INVALID_RECEIPT
        ),
    }[status]


def _decision(
    value: FindingGateInput,
    route: FindingRoute,
    reason: FindingGateReason,
) -> FindingGateDecision:
    return FindingGateDecision(
        candidate_id=value.candidate_id,
        candidate_version=value.candidate_version,
        head_sha=value.head_sha,
        severity=value.severity,
        known_evidence_ids=value.known_evidence_ids,
        route=route,
        finding_gate_state={
            FindingRoute.CONFIRMED: FindingGateState.BLOCKING,
            FindingRoute.REJECTED_WITH_EVIDENCE: FindingGateState.CLEAN,
            FindingRoute.NEEDS_MORE_EVIDENCE: FindingGateState.INCONCLUSIVE,
            FindingRoute.HUMAN_ESCALATION: FindingGateState.INCONCLUSIVE,
            FindingRoute.INDETERMINATE: FindingGateState.INCONCLUSIVE,
        }[route],
        reason=reason,
        auditor_identity=value.auditor_identity,
        auditor_receipt_sha256=value.auditor_receipt_sha256,
        auditor_model_call_status=value.auditor_model_call_status,
        auditor_verdict=value.auditor_verdict,
        auditor_cited_evidence_ids=value.auditor_cited_evidence_ids,
        skeptic_identity=value.skeptic_identity,
        skeptic_receipt_sha256=value.skeptic_receipt_sha256,
        skeptic_model_call_status=value.skeptic_model_call_status,
        skeptic_verdict=value.skeptic_verdict,
        skeptic_effective_verdict=value.skeptic_effective_verdict,
        skeptic_objections=value.skeptic_objections,
        skeptic_cited_evidence_ids=value.skeptic_cited_evidence_ids,
        investigation_terminal_status=value.investigation_terminal_status,
    )


def _decision_state_is_valid(route: FindingRoute, state: FindingGateState) -> bool:
    return {
        FindingRoute.CONFIRMED: FindingGateState.BLOCKING,
        FindingRoute.REJECTED_WITH_EVIDENCE: FindingGateState.CLEAN,
        FindingRoute.NEEDS_MORE_EVIDENCE: FindingGateState.INCONCLUSIVE,
        FindingRoute.HUMAN_ESCALATION: FindingGateState.INCONCLUSIVE,
        FindingRoute.INDETERMINATE: FindingGateState.INCONCLUSIVE,
    }[route] is state


__all__ = [
    "FindingGateContractError",
    "FindingGateDecision",
    "FindingGateErrorCode",
    "FindingGateInput",
    "FindingGateReason",
    "FindingRoute",
    "InvestigationTerminalStatus",
    "route_finding",
]
