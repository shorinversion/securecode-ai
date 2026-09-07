from typing import Any, cast

import pytest
from securecode_ai.core.development_benchmark import (
    Configuration,
    Label,
    Record,
    aggregate,
    planned_cells,
)

SHA = "sha256:" + "a" * 64


def _record(**changes: object) -> Record:
    values: dict[str, object] = {
        "schema_version": "development-benchmark-record-1.0",
        "study_id": "study",
        "case_id": "case",
        "configuration": "one_shot_llm",
        "repetition": 1,
        "expected_label": "vulnerable",
        "state": "executed",
        "predicted_label": "vulnerable",
        "confirmed_finding": True,
        "policy_matched": True,
        "returned_category": "sql",
        "returned_source_alias": "file_1.py",
        "reason": None,
        "run_plan_sha256": SHA,
        "candidate_commit": "git-sha1:" + "b" * 40,
        "corpus_content_sha256": SHA,
        "component_sha256": SHA,
        "prompt_sha256": SHA,
        "policy_sha256": SHA,
        "schema_sha256": SHA,
        "model_name": "model",
        "model_digest": "sha256:" + "d" * 64,
        "runtime_name": "ollama",
        "runtime_version": "1",
        "quantization": "Q4",
        "temperature": 0.0,
        "seed": None,
        "budget_tokens": 1,
        "budget_calls": 1,
        "budget_wall_seconds": 1,
        "budget_retries": 0,
        "wall_seconds": 0.1,
        "prompt_tokens": 1,
        "generated_tokens": 1,
        "scanner_signal_count": None,
        "provider_cost": None,
    }
    values.update(changes)
    return Record(**values)  # type: ignore[arg-type]


def test_stochastic_matrix_has_three_repetitions() -> None:
    repetitions = {
        "deterministic_only": 1,
        "scanner_seeded_investigation": 3,
        "model_native_only": 3,
        "one_shot_llm": 3,
        "full_hybrid": 3,
    }
    assert (
        len(planned_cells([(f"case-{index}", "safe") for index in range(24)], repetitions)) == 312
    )


def test_non_success_never_becomes_true_negative() -> None:
    plan: tuple[tuple[str, Configuration, int, Label], ...] = (("case", "one_shot_llm", 1, "safe"),)
    record = _record(
        expected_label="safe",
        state="not_run",
        predicted_label=None,
        confirmed_finding=None,
        policy_matched=None,
        returned_category=None,
        returned_source_alias=None,
        reason="unavailable",
    )
    configurations = cast(dict[str, dict[str, Any]], aggregate(plan, (record,))["configurations"])
    result = configurations["one_shot_llm"]
    assert result["TN"] == 0
    assert result["missing_safe"] == 1


def test_unmatched_finding_is_false_positive_and_false_negative() -> None:
    plan: tuple[tuple[str, Configuration, int, Label], ...] = (
        ("case", "one_shot_llm", 1, "vulnerable"),
    )
    configurations = cast(
        dict[str, dict[str, Any]],
        aggregate(plan, (_record(policy_matched=False),))["configurations"],
    )
    result = configurations["one_shot_llm"]
    assert (result["TP"], result["FP"], result["FN"]) == (0, 1, 1)


def test_duplicate_and_fail_open_records_reject() -> None:
    plan: tuple[tuple[str, Configuration, int, Label], ...] = (
        ("case", "one_shot_llm", 1, "vulnerable"),
    )
    record = _record()
    with pytest.raises(ValueError):
        aggregate(plan, (record, record))
    with pytest.raises(ValueError):
        _record(state="failed", reason="failure")


def test_missing_planned_cell_rejects() -> None:
    plan: tuple[tuple[str, Configuration, int, Label], ...] = (
        ("case", "one_shot_llm", 1, "vulnerable"),
    )
    with pytest.raises(ValueError, match="missing planned record"):
        aggregate(plan, ())
