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
    FindingGateState,
    FindingVerdict,
    ModelCallStatus,
)
from securecode_ai.core.investigation_models import InvestigationStopReason

from .local_product_runner_execution_family import _candidate_family
from .product_audit_types import ProductAuditComposition

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
    """Inconclusive candidates of one run, ordered by place."""

    flow, review = composition.flow, composition.review
    if flow is None or review is None:
        return ()
    candidates = {candidate.candidate_id: candidate for candidate in flow.graph.candidates}
    records = {record.evidence_id: record for record in flow.graph.evidence}
    receipts = {receipt.candidate_id: receipt for receipt in flow.investigations}
    result: list[UnresolvedCandidate] = []
    for outcome in review.outcomes:
        gate = outcome.finding_gate
        if gate is not None and gate.finding_gate_state in {
            FindingGateState.BLOCKING,
            FindingGateState.CLEAN,
        }:
            continue
        candidate = candidates.get(outcome.candidate_id)
        if candidate is None:
            continue
        try:
            cwe_id = _candidate_family(candidate, flow.graph)[1]
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
        result.append(
            UnresolvedCandidate(
                cwe_id=cwe_id,
                path=narrow.path if narrow is not None else "—",
                line=narrow.start.line if narrow is not None else 0,
                origin="сканер"
                if candidate.candidate_origin is CandidateOrigin.DETERMINISTIC
                else "модель",
                reason=_reason(receipts.get(outcome.candidate_id), outcome),
            )
        )
    return tuple(sorted(result, key=lambda item: (item.path, item.line, item.cwe_id)))


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
