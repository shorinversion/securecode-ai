"""Candidates of a trial analysis that ended without a final decision, with the reason.

A finding gate decision is either blocking (a confirmed finding), clean (rejected with
evidence) or inconclusive. Inconclusive candidates make the run ``INDETERMINATE`` when
nothing is confirmed; the readable report lists them so a reviewer knows what to check
by hand and why the models did not decide.
"""

from __future__ import annotations

import json
from collections import Counter
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
from .product_skeptic_port import _MAX_REGENERATIONS, _REGENERATE_ON

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
    # Model calls behind the decision: Auditor calls (investigation rounds included)
    # and Skeptic attempts (retries of a malformed answer included).
    auditor_calls: int = 0
    skeptic_attempts: int = 0
    # The Skeptic asked again as many times as allowed and still got no valid answer.
    retries_exhausted: bool = False


_SKEPTIC_ATTEMPTS: Final = 1 + _MAX_REGENERATIONS


def unresolved_candidates(composition: ProductAuditComposition) -> tuple[UnresolvedCandidate, ...]:
    """Inconclusive candidates of one run, ordered by place (see ``unresolved_report``)."""

    return unresolved_report(composition)[0]


def unresolved_report(
    composition: ProductAuditComposition,
) -> tuple[tuple[UnresolvedCandidate, ...], int]:
    """Inconclusive candidates and how many were covered by a confirmed finding.

    Several candidates may describe one weakness (a scanner rule, a second secret rule
    and model Discovery on the same line). When a finding of the same CWE is already
    confirmed at overlapping lines of the same file, the other candidates add nothing
    to check by hand: they are counted, not listed. A candidate elsewhere in the file
    (another hardcoded key ten lines below) stays listed. Candidates at one place with
    one CWE are listed once.
    """

    flow, review = composition.flow, composition.review
    if flow is None or review is None:
        return (), 0
    candidates = {candidate.candidate_id: candidate for candidate in flow.graph.candidates}
    records = {record.evidence_id: record for record in flow.graph.evidence}
    receipts = {receipt.candidate_id: receipt for receipt in flow.investigations}
    auditor_calls, skeptic_attempts = model_attempts(composition)
    confirmed: dict[tuple[str, str], list[tuple[int, int]]] = {}
    pending: list[
        tuple[ProductCandidateReviewOutcome, DiscoveryCandidate, str, str, tuple[int, int]]
    ] = []
    for outcome in review.outcomes:
        candidate = candidates.get(outcome.candidate_id)
        if candidate is None:
            continue
        cwe_id, path, lines = _place(candidate, flow.graph, records)
        gate = outcome.finding_gate
        if gate is not None and gate.finding_gate_state is FindingGateState.BLOCKING:
            confirmed.setdefault((cwe_id, path), []).append(lines)
            continue
        if gate is not None and gate.finding_gate_state is FindingGateState.CLEAN:
            continue
        pending.append((outcome, candidate, cwe_id, path, lines))
    result: dict[tuple[str, str, int], UnresolvedCandidate] = {}
    covered = 0
    for outcome, candidate, cwe_id, path, (line, end) in pending:
        if any(start <= end and line <= stop for start, stop in confirmed.get((cwe_id, path), ())):
            covered += 1
            continue
        attempts = skeptic_attempts.get(outcome.candidate_id, 0)
        skeptic = outcome.skeptic_review
        exhausted = (
            attempts >= _SKEPTIC_ATTEMPTS
            and skeptic is not None
            and skeptic.model_call_status in _REGENERATE_ON
        )
        reason = _reason(receipts.get(outcome.candidate_id), outcome)
        if reason.startswith("Скептик") and attempts > 1:
            reason += f" (попыток: {attempts}" + (", повторы исчерпаны)" if exhausted else ")")
        result.setdefault(
            (cwe_id, path, line),
            UnresolvedCandidate(
                cwe_id=cwe_id,
                path=path,
                line=line,
                origin="сканер"
                if candidate.candidate_origin is CandidateOrigin.DETERMINISTIC
                else "модель",
                reason=reason,
                auditor_calls=auditor_calls.get(outcome.candidate_id, 0),
                skeptic_attempts=attempts,
                retries_exhausted=exhausted,
            ),
        )
    ordered = tuple(sorted(result.values(), key=lambda item: (item.path, item.line, item.cwe_id)))
    return ordered, covered


def model_attempts(
    composition: ProductAuditComposition,
) -> tuple[Counter[str], Counter[str]]:
    """Auditor model calls and Skeptic attempts of every candidate, by candidate id."""

    host = composition.host_inputs
    if host is None:
        return Counter(), Counter()
    return (
        Counter(item.package.candidate_id for item in host.auditor_observations),
        Counter(candidate_id for candidate_id, _ in host.skeptic_attempts),
    )


def _place(
    candidate: DiscoveryCandidate, graph: EvidenceGraph, records: dict[str, Evidence]
) -> tuple[str, str, tuple[int, int]]:
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
        return cwe_id, "—", (0, 0)
    return cwe_id, narrow.path, (narrow.start.line, narrow.end.line)


def finding_decisions(composition: ProductAuditComposition) -> dict[str, dict[str, object]]:
    """The finding gate decision of every candidate that has one, by candidate id.

    ``authority`` says who may confirm (``MODEL_REVIEW`` or ``DETERMINISTIC_DETECTOR``,
    D-117); ``reason`` and ``route`` are the gate result; the Auditor and Skeptic
    verdicts are the model reviews, kept even when the detector decided;
    ``auditor_calls`` and ``skeptic_attempts`` count the model calls behind them.
    """

    review = composition.review
    if review is None:
        return {}
    auditor_calls, skeptic_attempts = model_attempts(composition)
    decisions: dict[str, dict[str, object]] = {}
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
            "auditor_calls": auditor_calls.get(outcome.candidate_id, 0),
            "skeptic_attempts": skeptic_attempts.get(outcome.candidate_id, 0),
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


def attach_undecided_to_json(rendered: bytes, composition: ProductAuditComposition) -> bytes:
    """Add the candidates left without a final decision to a JSON report.

    ``undecided_candidates`` lists them with the reason and the model calls behind it;
    ``undecided_covered`` counts the ones folded into an already confirmed finding.
    """

    listed, covered = unresolved_report(composition)
    document = json.loads(rendered)
    document["undecided_candidates"] = [
        {
            "cwe_id": item.cwe_id,
            "path": item.path,
            "line": item.line,
            "origin": "DETERMINISTIC" if item.origin == "сканер" else "MODEL",
            "reason": item.reason,
            "auditor_calls": item.auditor_calls,
            "skeptic_attempts": item.skeptic_attempts,
            "retries_exhausted": item.retries_exhausted,
        }
        for item in listed
    ]
    document["undecided_covered"] = covered
    return (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
