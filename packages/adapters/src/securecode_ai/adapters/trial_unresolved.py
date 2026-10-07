"""Candidates of a trial analysis that ended without a final decision, with the reason.

A finding gate decision is either blocking (a confirmed finding), clean (rejected with
evidence) or inconclusive. Inconclusive candidates make the run ``INDETERMINATE`` when
nothing is confirmed; the readable report lists them so a reviewer knows what to check
by hand and why the models did not decide.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from securecode_ai.contracts import (
    CandidateOrigin,
    DiscoveryCandidate,
    Evidence,
    FindingGateState,
    FindingVerdict,
    ModelCallStatus,
)
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.investigation_models import InvestigationStopReason

from .local_product_runner_execution_family import _candidate_family
from .product_audit_types import ProductAuditComposition
from .product_review_contracts import ProductCandidateReviewOutcome

_STATUS: Final = {
    ModelCallStatus.INVALID_SCHEMA: "ответ модели не прошёл схему",
    ModelCallStatus.EMPTY_OUTPUT: "модель вернула пустой ответ",
    ModelCallStatus.BUDGET_EXHAUSTED: "исчерпан бюджет запроса (токены, время или --max-cost-usd)",
    ModelCallStatus.TIMEOUT: "тайм-аут запроса к модели",
    ModelCallStatus.PROVIDER_ERROR: "ошибка провайдера или чтения доказательств",
    ModelCallStatus.REFUSED: "модель отказалась отвечать",
    ModelCallStatus.GUARDRAIL_BLOCKED: "запрос заблокирован политикой исходящих данных",
}
_VERDICT: Final = {
    FindingVerdict.NEEDS_MORE_EVIDENCE: "нужно больше доказательств",
    FindingVerdict.CONFLICTING: "Аудитор и Скептик разошлись во мнении",
    FindingVerdict.NOT_EVALUATED: "решение не вынесено",
}


@dataclass(frozen=True, slots=True)
class UnresolvedCandidate:
    cwe_id: str
    path: str
    line: int
    origin: str
    reason: str


def unresolved_candidates(composition: ProductAuditComposition) -> tuple[UnresolvedCandidate, ...]:
    """Inconclusive candidates of one run, ordered by place (see ``unresolved_report``)."""

    return unresolved_report(composition)[0]


def unresolved_report(
    composition: ProductAuditComposition,
) -> tuple[tuple[UnresolvedCandidate, ...], int]:
    """Inconclusive candidates and how many were covered by a confirmed finding.

    Several candidates may describe one weakness (a scanner rule, a second secret rule
    and model Discovery on the same line). When the weakness (CWE in one file) is
    already confirmed, the other candidates add nothing to check by hand: they are
    counted, not listed. Candidates at one place with one CWE are listed once.
    """

    flow, review = composition.flow, composition.review
    if flow is None or review is None:
        return (), 0
    candidates = {candidate.candidate_id: candidate for candidate in flow.graph.candidates}
    records = {record.evidence_id: record for record in flow.graph.evidence}
    receipts = {receipt.candidate_id: receipt for receipt in flow.investigations}
    confirmed: set[tuple[str, str]] = set()
    pending: list[tuple[ProductCandidateReviewOutcome, DiscoveryCandidate, str, str, int]] = []
    for outcome in review.outcomes:
        candidate = candidates.get(outcome.candidate_id)
        if candidate is None:
            continue
        cwe_id, path, line = _place(candidate, flow.graph, records)
        gate = outcome.finding_gate
        if gate is not None and gate.finding_gate_state is FindingGateState.BLOCKING:
            confirmed.add((cwe_id, path))
            continue
        if gate is not None and gate.finding_gate_state is FindingGateState.CLEAN:
            continue
        pending.append((outcome, candidate, cwe_id, path, line))
    result: dict[tuple[str, str, int], UnresolvedCandidate] = {}
    covered = 0
    for outcome, candidate, cwe_id, path, line in pending:
        if (cwe_id, path) in confirmed:
            covered += 1
            continue
        result.setdefault(
            (cwe_id, path, line),
            UnresolvedCandidate(
                cwe_id=cwe_id,
                path=path,
                line=line,
                origin="сканер"
                if candidate.candidate_origin is CandidateOrigin.DETERMINISTIC
                else "модель",
                reason=_reason(receipts.get(outcome.candidate_id), outcome),
            ),
        )
    ordered = tuple(sorted(result.values(), key=lambda item: (item.path, item.line, item.cwe_id)))
    return ordered, covered


def _place(
    candidate: DiscoveryCandidate, graph: EvidenceGraph, records: dict[str, Evidence]
) -> tuple[str, str, int]:
    try:
        cwe_id = _candidate_family(candidate, graph)[1]
    except Exception:
        cwe_id = "—"
    locations = [
        record.location
        for evidence_id in candidate.evidence_ids
        if (record := records.get(evidence_id)) is not None and record.location is not None
    ]
    narrow = min(
        locations,
        key=lambda location: (location.end.line - location.start.line, location.start.line),
        default=None,
    )
    if narrow is None:
        return cwe_id, "—", 0
    return cwe_id, narrow.path, narrow.start.line


def finding_decisions(composition: ProductAuditComposition) -> dict[str, dict[str, str]]:
    """The finding gate decision of every candidate that has one, by candidate id.

    ``authority`` says who may confirm (``MODEL_REVIEW`` or ``DETERMINISTIC_DETECTOR``,
    D-117); ``reason`` and ``route`` are the gate result; the Auditor and Skeptic
    verdicts are the model reviews, kept even when the detector decided.
    """

    review = composition.review
    if review is None:
        return {}
    decisions: dict[str, dict[str, str]] = {}
    for outcome in review.outcomes:
        gate = outcome.finding_gate
        if gate is None:
            continue
        decisions[outcome.candidate_id] = {
            "authority": gate.authority.value,
            "route": gate.route.value,
            "reason": gate.reason.value,
            "auditor_verdict": gate.auditor_verdict.value,
            "skeptic_verdict": gate.skeptic_verdict.value,
            "skeptic_effective_verdict": gate.skeptic_effective_verdict.value,
        }
    return decisions


def _reason(receipt: object, outcome: object) -> str:
    stop = getattr(receipt, "stop_reason", None)
    if receipt is not None and stop is None:
        return "Аудитор: не удалось подготовить доказательства"
    if stop is InvestigationStopReason.MODEL_NON_SUCCESS:
        status = getattr(receipt, "final_model_call_status", None)
        text = _STATUS.get(status) if isinstance(status, ModelCallStatus) else None
        return "Аудитор: " + (text or "ответ модели не получен")
    if stop is InvestigationStopReason.BUDGET_EXHAUSTED:
        return "Аудитор: " + _STATUS[ModelCallStatus.BUDGET_EXHAUSTED]
    if stop in {
        InvestigationStopReason.CONTEXT_ROUNDS_EXHAUSTED,
        InvestigationStopReason.NO_NEW_EVIDENCE,
    }:
        return "Аудитор: нужно больше доказательств, чем удалось собрать"
    if stop is InvestigationStopReason.CONTEXT_PORT_FAILURE:
        return "Аудитор: не удалось получить дополнительный контекст"
    skeptic = getattr(outcome, "skeptic_review", None)
    if skeptic is not None:
        if skeptic.model_call_status is not ModelCallStatus.SUCCEEDED:
            return "Скептик: " + _STATUS.get(skeptic.model_call_status, "ответ модели не получен")
        verdict = _VERDICT.get(skeptic.effective_verdict)
        if verdict is not None:
            return "Скептик: " + verdict
    if stop is InvestigationStopReason.CONFIRMED and skeptic is None:
        return "Скептик: проверка не выполнена"
    return "решение не вынесено"
