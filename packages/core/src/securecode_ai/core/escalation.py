"""Immutable, source-free human escalation cases.

The case is a hand-off envelope, not a human decision.  It contains enough
typed provenance for a reviewer to locate the run and its evidence, while
never retaining source text, model output, or credentials.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import AuditEvent, FindingVerdict, RunExecutionIdentity

from .events import EventStream
from .finding_gate import FindingGateDecision, FindingGateReason, FindingRoute
from .investigation import AuditorInvestigationReceipt, InvestigationBudget

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EVENT_TYPE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_EVENTS: Final = 4096
_MAX_HASHES: Final = 128
ESCALATION_SCHEMA_VERSION: Final = "0.1.0"


class EscalationErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    CROSS_SCOPE = "CROSS_SCOPE"
    TAMPERED = "TAMPERED"


class EscalationCaseError(ValueError):
    """Fixed error which never echoes caller-controlled data."""

    __slots__ = ("code",)

    def __init__(self, code: EscalationErrorCode) -> None:
        if type(code) is not EscalationErrorCode:
            raise TypeError("escalation error code is invalid")
        self.code = code
        super().__init__("escalation case validation failed")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class SafeEventLink:
    """Only the non-sensitive identity of an audit event is retained."""

    event_id: str
    sequence: int
    event_type: str
    event_hash: str
    previous_event_hash: str | None

    def __post_init__(self) -> None:
        if (
            type(self.event_id) is not str
            or _ID.fullmatch(self.event_id) is None
            or type(self.sequence) is not int
            or self.sequence < 1
            or type(self.event_type) is not str
            or _EVENT_TYPE.fullmatch(self.event_type.replace("_", "-")) is None
            or not _valid_sha(self.event_hash)
            or (self.previous_event_hash is not None and not _valid_sha(self.previous_event_hash))
        ):
            raise EscalationCaseError(EscalationErrorCode.INVALID_INPUT)


@dataclass(frozen=True, slots=True)
class HumanEscalationCase:
    """Review packet created by policy; approval/rejection is deliberately absent."""

    schema_version: str
    case_id: str
    tenant_id: str
    run_id: str
    candidate_id: str
    candidate_version: int
    head_sha: str
    execution_identity: RunExecutionIdentity
    route: FindingRoute
    source_route: FindingRoute
    investigation_receipt: AuditorInvestigationReceipt
    reason: FindingGateReason
    known_evidence_ids: tuple[str, ...]
    auditor_identity: str
    auditor_receipt_sha256: str | None
    auditor_cited_evidence_ids: tuple[str, ...]
    auditor_verdict: str
    skeptic_identity: str
    skeptic_receipt_sha256: str | None
    skeptic_cited_evidence_ids: tuple[str, ...]
    skeptic_objections: tuple[tuple[str, tuple[str, ...]], ...]
    skeptic_verdict: str
    skeptic_effective_verdict: str
    investigation_terminal_status: str
    investigation_stop_reason: str
    model_non_success_reason: str | None
    budget: InvestigationBudget
    no_progress_count: int
    context_exhausted: bool
    policy_hashes: tuple[str, ...]
    route_policy_sha256: str | None
    event_chain: tuple[SafeEventLink, ...]

    def __post_init__(self) -> None:
        try:
            identity = RunExecutionIdentity.model_validate(
                self.execution_identity.model_dump(mode="python")
            )
        except (AttributeError, TypeError, ValueError):
            raise EscalationCaseError(EscalationErrorCode.TAMPERED) from None
        if (
            type(self.schema_version) is not str
            or self.schema_version != ESCALATION_SCHEMA_VERSION
            or _ID.fullmatch(self.case_id or "") is None
            or _ID.fullmatch(self.tenant_id or "") is None
            or _ID.fullmatch(self.run_id or "") is None
            or identity.repository_revision.tenant_id != self.tenant_id
            or identity.repository_revision.head_sha != self.head_sha
            or type(self.head_sha) is not str
            or not re.fullmatch(r"[0-9a-f]{40}", self.head_sha)
            or type(self.candidate_id) is not str
            or _ID.fullmatch(self.candidate_id or "") is None
            or type(self.candidate_version) is not int
            or self.candidate_version < 1
            or type(self.known_evidence_ids) is not tuple
            or any(
                type(item) is not str or _ID.fullmatch(item) is None
                for item in self.known_evidence_ids
            )
            or len(self.known_evidence_ids) != len(set(self.known_evidence_ids))
            or any(
                type(item) is not str or _ID.fullmatch(item) is None
                for item in (
                    self.auditor_identity,
                    self.skeptic_identity,
                )
            )
            or type(self.auditor_cited_evidence_ids) is not tuple
            or type(self.skeptic_cited_evidence_ids) is not tuple
            or not set(self.auditor_cited_evidence_ids).issubset(self.known_evidence_ids)
            or not set(self.skeptic_cited_evidence_ids).issubset(self.known_evidence_ids)
            or type(self.skeptic_objections) is not tuple
            or not _valid_objections(self.skeptic_objections, self.known_evidence_ids)
            or any(
                type(item) is not str or _ID.fullmatch(item) is None
                for item in self.auditor_cited_evidence_ids
            )
            or any(
                type(item) is not str or _ID.fullmatch(item) is None
                for item in self.skeptic_cited_evidence_ids
            )
            or type(self.route) is not FindingRoute
            or self.route is not FindingRoute.HUMAN_ESCALATION
            or type(self.source_route) is not FindingRoute
            or type(self.reason) is not FindingGateReason
            or self.auditor_verdict not in {item.value for item in FindingVerdict}
            or self.skeptic_verdict not in {item.value for item in FindingVerdict}
            or self.skeptic_effective_verdict not in {item.value for item in FindingVerdict}
            or self.investigation_terminal_status
            not in {
                "COMPLETED",
                "BUDGET_EXHAUSTED",
                "NO_PROGRESS",
                "CONTEXT_EXHAUSTED",
                "CANCELLED",
                "INVALID_RECEIPT",
            }
            or (
                self.model_non_success_reason is not None
                and _ID.fullmatch(self.model_non_success_reason) is None
            )
            or type(self.no_progress_count) is not int
            or self.no_progress_count < 0
            or type(self.context_exhausted) is not bool
            or len(self.event_chain) > _MAX_EVENTS
            or any(type(item) is not SafeEventLink for item in self.event_chain)
            or len(self.policy_hashes) > _MAX_HASHES
            or any(not _valid_sha(item) for item in self.policy_hashes)
            or (self.route_policy_sha256 is not None and not _valid_sha(self.route_policy_sha256))
            or (
                self.auditor_receipt_sha256 is not None
                and not _valid_sha(self.auditor_receipt_sha256)
            )
            or (
                self.skeptic_receipt_sha256 is not None
                and not _valid_sha(self.skeptic_receipt_sha256)
            )
        ):
            raise EscalationCaseError(EscalationErrorCode.INVALID_INPUT)
        if any(
            item.sequence != index
            or (index == 1 and item.previous_event_hash is not None)
            or (index > 1 and item.previous_event_hash != self.event_chain[index - 2].event_hash)
            for index, item in enumerate(self.event_chain, start=1)
        ):
            raise EscalationCaseError(EscalationErrorCode.TAMPERED)
        try:
            budget = replace(self.budget)
            receipt = replace(self.investigation_receipt)
        except (AttributeError, TypeError, ValueError):
            raise EscalationCaseError(EscalationErrorCode.INVALID_INPUT) from None
        if (
            (receipt.candidate_id, receipt.candidate_version, receipt.tenant_id, receipt.head_sha)
            != (self.candidate_id, self.candidate_version, self.tenant_id, self.head_sha)
            or receipt.tokens_used > budget.max_tokens
            or receipt.tool_calls > budget.max_tool_calls
            or receipt.elapsed_ms > budget.max_elapsed_ms
            or len(receipt.attempts) > budget.max_attempts
            or receipt.no_progress_count > budget.max_no_progress
            or receipt.context_rounds > budget.max_context_rounds
        ):
            raise EscalationCaseError(EscalationErrorCode.TAMPERED)
        object.__setattr__(self, "budget", budget)
        object.__setattr__(self, "investigation_receipt", receipt)
        object.__setattr__(self, "execution_identity", identity)
        object.__setattr__(self, "known_evidence_ids", tuple(sorted(self.known_evidence_ids)))
        object.__setattr__(self, "policy_hashes", tuple(sorted(self.policy_hashes)))

    def canonical_payload(self) -> dict[str, object]:
        """Canonical metadata only; no source or model text can enter it."""
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "tenant_id": self.tenant_id,
            "run_id": self.run_id,
            "candidate_id": self.candidate_id,
            "candidate_version": self.candidate_version,
            "head_sha": self.head_sha,
            "execution_identity": self.execution_identity.model_dump(mode="json"),
            "route": self.route.value,
            "reason": self.reason.value,
            "known_evidence_ids": self.known_evidence_ids,
            "source_route": self.source_route.value,
            "auditor_identity": self.auditor_identity,
            "auditor_receipt_sha256": self.auditor_receipt_sha256,
            "auditor_cited_evidence_ids": self.auditor_cited_evidence_ids,
            "auditor_verdict": self.auditor_verdict,
            "skeptic_identity": self.skeptic_identity,
            "skeptic_receipt_sha256": self.skeptic_receipt_sha256,
            "skeptic_cited_evidence_ids": self.skeptic_cited_evidence_ids,
            "skeptic_objections": self.skeptic_objections,
            "skeptic_verdict": self.skeptic_verdict,
            "skeptic_effective_verdict": self.skeptic_effective_verdict,
            "investigation_terminal_status": self.investigation_terminal_status,
            "model_non_success_reason": self.model_non_success_reason,
            "investigation_stop_reason": self.investigation_stop_reason,
            "budget": {
                "max_attempts": self.budget.max_attempts,
                "max_tokens": self.budget.max_tokens,
                "max_tool_calls": self.budget.max_tool_calls,
                "max_elapsed_ms": self.budget.max_elapsed_ms,
                "max_no_progress": self.budget.max_no_progress,
                "max_context_rounds": self.budget.max_context_rounds,
            },
            "no_progress_count": self.no_progress_count,
            "context_exhausted": self.context_exhausted,
            "policy_hashes": self.policy_hashes,
            "route_policy_sha256": self.route_policy_sha256,
            "event_chain": tuple(
                {
                    "event_id": e.event_id,
                    "sequence": e.sequence,
                    "event_type": e.event_type,
                    "event_hash": e.event_hash,
                    "previous_event_hash": e.previous_event_hash,
                }
                for e in self.event_chain
            ),
            "investigation_receipt": {
                "initial_selection_sha256": self.investigation_receipt.initial_selection_sha256,
                "final_selection_sha256": self.investigation_receipt.final_selection_sha256,
                "attempts": len(self.investigation_receipt.attempts),
                "context_rounds": self.investigation_receipt.context_rounds,
                "tokens_used": self.investigation_receipt.tokens_used,
                "tool_calls": self.investigation_receipt.tool_calls,
                "elapsed_ms": self.investigation_receipt.elapsed_ms,
                "no_progress_count": self.investigation_receipt.no_progress_count,
                "final_model_call_status": self.investigation_receipt.final_model_call_status.value,
                "stop_reason": self.investigation_receipt.stop_reason.value,
            },
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.canonical_payload(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @property
    def case_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def create_escalation_case(
    decision: FindingGateDecision,
    *,
    tenant_id: str,
    run_id: str,
    execution_identity: RunExecutionIdentity,
    policy_hashes: tuple[str, ...] = (),
    route_policy_sha256: str | None = None,
    investigation_receipt: AuditorInvestigationReceipt,
    budget: InvestigationBudget,
    event_chain: tuple[AuditEvent, ...] = (),
) -> HumanEscalationCase:
    """Create a case from a gate decision and safe execution metadata."""
    if type(decision) is not FindingGateDecision:
        raise EscalationCaseError(EscalationErrorCode.INVALID_INPUT)
    try:
        decision = FindingGateDecision(
            candidate_id=decision.candidate_id,
            candidate_version=decision.candidate_version,
            head_sha=decision.head_sha,
            severity=decision.severity,
            known_evidence_ids=decision.known_evidence_ids,
            route=decision.route,
            finding_gate_state=decision.finding_gate_state,
            reason=decision.reason,
            auditor_identity=decision.auditor_identity,
            auditor_receipt_sha256=decision.auditor_receipt_sha256,
            auditor_model_call_status=decision.auditor_model_call_status,
            auditor_verdict=decision.auditor_verdict,
            auditor_cited_evidence_ids=decision.auditor_cited_evidence_ids,
            skeptic_identity=decision.skeptic_identity,
            skeptic_receipt_sha256=decision.skeptic_receipt_sha256,
            skeptic_model_call_status=decision.skeptic_model_call_status,
            skeptic_verdict=decision.skeptic_verdict,
            skeptic_effective_verdict=decision.skeptic_effective_verdict,
            skeptic_objections=decision.skeptic_objections,
            skeptic_cited_evidence_ids=decision.skeptic_cited_evidence_ids,
            investigation_terminal_status=decision.investigation_terminal_status,
        )
    except (AttributeError, TypeError, ValueError):
        raise EscalationCaseError(EscalationErrorCode.TAMPERED) from None
    if decision.route not in {FindingRoute.HUMAN_ESCALATION, FindingRoute.INDETERMINATE}:
        raise EscalationCaseError(EscalationErrorCode.INVALID_INPUT)
    if (
        type(investigation_receipt) is not AuditorInvestigationReceipt
        or type(budget) is not InvestigationBudget
    ):
        raise EscalationCaseError(EscalationErrorCode.INVALID_INPUT)
    if (
        investigation_receipt.candidate_id,
        investigation_receipt.candidate_version,
        investigation_receipt.tenant_id,
        investigation_receipt.head_sha,
    ) != (decision.candidate_id, decision.candidate_version, tenant_id, decision.head_sha):
        raise EscalationCaseError(EscalationErrorCode.CROSS_SCOPE)
    if (
        investigation_receipt.tokens_used > budget.max_tokens
        or investigation_receipt.tool_calls > budget.max_tool_calls
        or investigation_receipt.elapsed_ms > budget.max_elapsed_ms
        or len(investigation_receipt.attempts) > budget.max_attempts
        or investigation_receipt.no_progress_count > budget.max_no_progress
        or investigation_receipt.context_rounds > budget.max_context_rounds
    ):
        raise EscalationCaseError(EscalationErrorCode.TAMPERED)
    try:
        identity = RunExecutionIdentity.model_validate(execution_identity.model_dump(mode="python"))
        stream = EventStream(
            tenant_id=tenant_id,
            run_id=run_id,
            execution_identity=identity,
            events=tuple(event_chain),
        )
    except (AttributeError, TypeError, ValueError):
        raise EscalationCaseError(EscalationErrorCode.CROSS_SCOPE) from None
    links = tuple(
        SafeEventLink(
            e.event_id, e.sequence, e.event_type.value, e.canonical_hash(), e.previous_event_hash
        )
        for e in stream.events
    )
    objections = tuple((item.kind.value, item.evidence_ids) for item in decision.skeptic_objections)
    material = {
        "tenant_id": tenant_id,
        "run_id": run_id,
        "candidate_id": decision.candidate_id,
        "head_sha": decision.head_sha,
        "execution_identity_hash": identity.execution_identity_hash,
        "reason": decision.reason.value,
    }
    case_id = (
        "esc-"
        + hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:32]
    )
    return HumanEscalationCase(
        schema_version=ESCALATION_SCHEMA_VERSION,
        case_id=case_id,
        tenant_id=tenant_id,
        run_id=run_id,
        candidate_id=decision.candidate_id,
        candidate_version=decision.candidate_version,
        head_sha=decision.head_sha,
        execution_identity=identity,
        route=FindingRoute.HUMAN_ESCALATION,
        source_route=decision.route,
        investigation_receipt=investigation_receipt,
        reason=decision.reason,
        known_evidence_ids=decision.known_evidence_ids,
        auditor_identity=decision.auditor_identity,
        auditor_receipt_sha256=decision.auditor_receipt_sha256,
        auditor_cited_evidence_ids=decision.auditor_cited_evidence_ids,
        auditor_verdict=decision.auditor_verdict.value,
        skeptic_identity=decision.skeptic_identity,
        skeptic_receipt_sha256=decision.skeptic_receipt_sha256,
        skeptic_cited_evidence_ids=decision.skeptic_cited_evidence_ids,
        skeptic_objections=objections,
        skeptic_verdict=decision.skeptic_verdict.value,
        skeptic_effective_verdict=decision.skeptic_effective_verdict.value,
        investigation_terminal_status=decision.investigation_terminal_status.value,
        investigation_stop_reason=investigation_receipt.stop_reason.value,
        model_non_success_reason=(
            investigation_receipt.final_model_call_status.value
            if investigation_receipt.final_model_call_status.value != "SUCCEEDED"
            else None
        ),
        budget=budget,
        no_progress_count=investigation_receipt.no_progress_count,
        context_exhausted=investigation_receipt.stop_reason.value.startswith("CONTEXT"),
        policy_hashes=policy_hashes,
        route_policy_sha256=route_policy_sha256,
        event_chain=links,
    )


__all__ = [
    "EscalationCaseError",
    "EscalationErrorCode",
    "HumanEscalationCase",
    "SafeEventLink",
    "create_escalation_case",
]


def _valid_objections(values: object, known: tuple[str, ...]) -> bool:
    if type(values) is not tuple:
        return False
    for value in values:
        if type(value) is not tuple or len(value) != 2:
            return False
        kind, ids = value
        if type(kind) is not str or _ID.fullmatch(kind.replace("_", "-")) is None:
            return False
        if type(ids) is not tuple or any(
            type(item) is not str or item not in known for item in ids
        ):
            return False
    return True


def _valid_sha(value: object) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None
