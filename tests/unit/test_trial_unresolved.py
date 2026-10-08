from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from securecode_ai.adapters import trial_unresolved
from securecode_ai.adapters.trial_unresolved import _reason
from securecode_ai.contracts import (
    CandidateOrigin,
    FindingGateState,
    FindingVerdict,
    ModelCallStatus,
)
from securecode_ai.core.investigation_models import InvestigationStopReason


def _receipt(stop: InvestigationStopReason, status: ModelCallStatus) -> object:
    return SimpleNamespace(stop_reason=stop, final_model_call_status=status)


@pytest.mark.parametrize(
    ("receipt", "skeptic", "expected"),
    [
        (
            _receipt(InvestigationStopReason.MODEL_NON_SUCCESS, ModelCallStatus.INVALID_SCHEMA),
            None,
            "Аудитор: ответ модели не прошёл схему",
        ),
        (
            _receipt(InvestigationStopReason.BUDGET_EXHAUSTED, ModelCallStatus.BUDGET_EXHAUSTED),
            None,
            "Аудитор: исчерпан бюджет запроса",
        ),
        (
            _receipt(InvestigationStopReason.NO_NEW_EVIDENCE, ModelCallStatus.SUCCEEDED),
            None,
            "Аудитор: нужно больше доказательств",
        ),
        (
            _receipt(InvestigationStopReason.CONFIRMED, ModelCallStatus.SUCCEEDED),
            SimpleNamespace(
                model_call_status=ModelCallStatus.BUDGET_EXHAUSTED,
                effective_verdict=FindingVerdict.NOT_EVALUATED,
            ),
            "Скептик: исчерпан бюджет запроса",
        ),
        (
            _receipt(InvestigationStopReason.CONFIRMED, ModelCallStatus.SUCCEEDED),
            SimpleNamespace(
                model_call_status=ModelCallStatus.SUCCEEDED,
                effective_verdict=FindingVerdict.CONFLICTING,
            ),
            "Скептик: Аудитор и Скептик разошлись во мнении",
        ),
        (SimpleNamespace(), None, "Аудитор: не удалось подготовить доказательства"),
    ],
)
def test_each_undecided_candidate_gets_a_readable_reason(
    receipt: object, skeptic: object, expected: str
) -> None:
    assert _reason(receipt, SimpleNamespace(skeptic_review=skeptic)).startswith(expected)


def _composition(*items: tuple[str, str, int, int, FindingGateState | None]) -> object:
    candidates, evidence, outcomes = [], [], []
    for index, (cwe_id, path, start, end, state) in enumerate(items):
        location = SimpleNamespace(
            path=path, start=SimpleNamespace(line=start), end=SimpleNamespace(line=end)
        )
        evidence.append(SimpleNamespace(evidence_id=f"e{index}", location=location))
        candidates.append(
            SimpleNamespace(
                candidate_id=f"c{index}",
                evidence_ids=(f"e{index}",),
                candidate_origin=CandidateOrigin.DETERMINISTIC,
                cwe=cwe_id,
            )
        )
        gate = None if state is None else SimpleNamespace(finding_gate_state=state)
        outcomes.append(
            SimpleNamespace(candidate_id=f"c{index}", finding_gate=gate, skeptic_review=None)
        )
    return SimpleNamespace(
        flow=SimpleNamespace(
            graph=SimpleNamespace(candidates=candidates, evidence=evidence), investigations=()
        ),
        review=SimpleNamespace(outcomes=outcomes),
        host_inputs=None,
    )


def test_only_candidates_at_a_confirmed_place_are_folded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 1.2.5 folded every CWE-798 candidate of sql.py into the confirmed password and
    # hid a second hardcoded key on another line (E2E of 1.2.5).
    monkeypatch.setattr(
        trial_unresolved, "_candidate_family", lambda candidate, graph: ("", candidate.cwe)
    )
    composition = _composition(
        ("CWE-798", "sql.py", 4, 4, FindingGateState.BLOCKING),
        ("CWE-798", "sql.py", 4, 4, None),
        ("CWE-798", "sql.py", 2, 6, None),
        ("CWE-798", "sql.py", 9, 9, None),
        ("CWE-89", "sql.py", 4, 4, None),
    )

    listed, covered = trial_unresolved.unresolved_report(composition)  # type: ignore[arg-type]

    # Folded candidates stay observable with the finding that covers them.
    assert [(item.line, item.covered_by) for item in covered] == [(2, "c0"), (4, "c0")]
    assert [(item.cwe_id, item.line) for item in listed] == [("CWE-89", 4), ("CWE-798", 9)]


def test_undecided_candidates_carry_their_model_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        trial_unresolved, "_candidate_family", lambda candidate, graph: ("", candidate.cwe)
    )
    composition = _composition(("CWE-89", "sql.py", 7, 7, None))
    skeptic = SimpleNamespace(
        model_call_status=ModelCallStatus.INVALID_SCHEMA,
        effective_verdict=FindingVerdict.NOT_EVALUATED,
    )
    composition.review.outcomes[0].skeptic_review = skeptic  # type: ignore[attr-defined]
    composition.flow.investigations = (  # type: ignore[attr-defined]
        SimpleNamespace(
            candidate_id="c0",
            stop_reason=InvestigationStopReason.CONFIRMED,
            final_model_call_status=ModelCallStatus.SUCCEEDED,
        ),
    )
    composition.host_inputs = SimpleNamespace(  # type: ignore[attr-defined]
        auditor_observations=(SimpleNamespace(package=SimpleNamespace(candidate_id="c0")),) * 2,
        skeptic_attempts=(("c0", ModelCallStatus.INVALID_SCHEMA),) * 3,
    )

    (item,), _ = trial_unresolved.unresolved_report(composition)  # type: ignore[arg-type]
    exported = json.loads(
        trial_unresolved.attach_undecided_to_json(b"{}", composition)  # type: ignore[arg-type]
    )

    assert item.reason == ("Скептик: ответ модели не прошёл схему (попыток: 3, повторы исчерпаны)")
    assert (item.auditor_calls, item.skeptic_attempts, item.retries_exhausted) == (2, 3, True)
    assert exported["undecided_covered"] == 0 and exported["covered_candidates"] == []
    assert exported["undecided_candidates"][0] == {
        "candidate_id": "c0",
        "cwe_id": "CWE-89",
        "path": "sql.py",
        "line": 7,
        "origin": "DETERMINISTIC",
        "reason": item.reason,
        "auditor_calls": 2,
        "skeptic_attempts": 3,
        "retries_exhausted": True,
    }


def test_a_whole_file_finding_does_not_hide_a_key_on_one_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Live 1.2.8 run: the model confirmed CWE-798 for lines 1-21 and hid API_KEY on line 5.
    monkeypatch.setattr(
        trial_unresolved, "_candidate_family", lambda candidate, graph: ("", candidate.cwe)
    )
    composition = _composition(
        ("CWE-798", "sql.py", 1, 21, FindingGateState.BLOCKING),
        ("CWE-798", "sql.py", 5, 5, None),
    )

    listed, covered = trial_unresolved.unresolved_report(composition)  # type: ignore[arg-type]

    assert [(item.cwe_id, item.line) for item in listed] == [("CWE-798", 5)]
    assert covered == ()
