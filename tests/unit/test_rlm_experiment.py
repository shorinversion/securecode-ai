from securecode_ai.core.code_index import CodeIndexEntry, StaticCodeIndex
from securecode_ai.core.rlm_experiment import (
    ExperimentBudget,
    ExperimentPins,
    ExperimentSplit,
    canonical_receipt,
    run_cell,
)


def test_rlm_result_is_evaluation_only() -> None:
    pins = ExperimentPins(*("a" * 64,) * 6)
    cell = run_cell(
        index=StaticCodeIndex((CodeIndexEntry("x.py", "b" * 64, 1, "python"),)),
        case_id="case",
        split=ExperimentSplit.DEVELOPMENT,
        variant="rlm",
        pins=pins,
        budget=ExperimentBudget(1, 1, 10, 1, 0),
        query_id="q",
    )
    metadata = canonical_receipt(pins=pins, cells=(cell,))["metadata"]
    assert isinstance(metadata, dict)
    assert metadata["promoted"] is False
