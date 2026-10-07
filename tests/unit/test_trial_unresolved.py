from __future__ import annotations

from types import SimpleNamespace

import pytest
from securecode_ai.adapters.trial_unresolved import _reason
from securecode_ai.contracts import FindingVerdict, ModelCallStatus
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
