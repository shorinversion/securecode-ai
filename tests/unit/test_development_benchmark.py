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
        "schema_version": "development-benchmark-record-1.1",
        "study_id": "study",
        "case_id": "case",
        "root_cause_group": "group",
        "source_aliases": ("file_1.py",),
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
        "finding_origin": "model_native",
        "remediation_attempted": False,
        "remediation_data_only": None,
        "remediation_sandbox_receipt_sha256": None,
        "remediation_sandbox_validated": None,
        "remediation_oracle_validated": None,
        "remediation_existing_regression_passed": None,
        "remediation_no_new_blocking_regressions": None,
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


def test_legacy_record_schema_rejects() -> None:
    with pytest.raises(ValueError, match="invalid record identity"):
        _record(schema_version="development-benchmark-record-1.0")


def test_aggregate_uses_current_schema() -> None:
    plan: tuple[tuple[str, Configuration, int, Label], ...] = (
        ("case", "one_shot_llm", 1, "vulnerable"),
    )
    assert aggregate(plan, (_record(),))["schema_version"] == "development-benchmark-aggregate-1.1"


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
        finding_origin=None,
    )
    configurations = cast(dict[str, dict[str, Any]], aggregate(plan, (record,))["configurations"])
    result = configurations["one_shot_llm"]
    assert result["TN"] == 0
    assert result["missing_safe"] == 1


@pytest.mark.parametrize("configuration", ["scanner_seeded_investigation", "full_hybrid"])
def test_not_run_has_no_invented_scanner_receipt(configuration: str) -> None:
    values = {
        "configuration": configuration,
        "state": "not_run",
        "predicted_label": None,
        "confirmed_finding": None,
        "policy_matched": None,
        "returned_category": None,
        "returned_source_alias": None,
        "reason": "runtime_unavailable",
        "finding_origin": None,
    }
    assert _record(**values).scanner_signal_count is None
    for count in (0, 1):
        with pytest.raises(ValueError, match="scanner receipt applicability"):
            _record(**values, scanner_signal_count=count)
    with pytest.raises(ValueError, match="scanner receipt applicability"):
        _record(**{**values, "state": "failed"})


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


def test_scanner_seeded_zero_cannot_claim_model_discovery() -> None:
    with pytest.raises(ValueError, match="zero scanner seed"):
        _record(
            configuration="scanner_seeded_investigation",
            scanner_signal_count=0,
            finding_origin="deterministic",
        )


def test_remediation_cannot_claim_validation_without_a_matched_vulnerable_finding() -> None:
    with pytest.raises(ValueError, match="validated remediation requires"):
        _record(
            expected_label="safe",
            remediation_attempted=True,
            remediation_data_only=True,
            remediation_sandbox_receipt_sha256="c" * 64,
            remediation_sandbox_validated=True,
            remediation_oracle_validated=True,
            remediation_existing_regression_passed=True,
            remediation_no_new_blocking_regressions=True,
        )


def test_aggregate_reports_origin_and_truthful_unattempted_remediation() -> None:
    plan: tuple[tuple[str, Configuration, int, Label], ...] = (
        ("case", "one_shot_llm", 1, "vulnerable"),
    )
    result = aggregate(plan, (_record(),))
    assert result["repair_metrics"] == {
        "attempted_patches": 0,
        "sandbox_validated_patches": 0,
        "independently_validated_patches": 0,
        "correct_and_secure_rate": None,
        "root_cause_repair_rate": None,
    }
    origins = cast(dict[str, dict[str, int]], result["additional_finding_overlap"])
    assert origins["one_shot_llm"] == {"deterministic": 0, "model_native": 1, "hybrid": 0}


def test_deterministic_record_rejects_model_contamination() -> None:
    with pytest.raises(ValueError, match="deterministic record cannot carry model facts"):
        _record(configuration="deterministic_only", scanner_signal_count=0)


@pytest.mark.parametrize(
    ("returned_category", "returned_source_alias"),
    (("other", "file_1.py"), ("sql", "file_2.py")),
)
def test_confirmed_finding_requires_bound_category_and_alias(
    returned_category: str, returned_source_alias: str
) -> None:
    with pytest.raises(ValueError, match="confirmed finding requires match inputs"):
        _record(
            policy_matched=False,
            returned_category=returned_category,
            returned_source_alias=returned_source_alias,
        )


def test_full_hybrid_origin_attribution_reconciles_each_matrix_cell() -> None:
    plan: tuple[tuple[str, Configuration, int, Label], ...] = (
        ("tp", "full_hybrid", 1, "vulnerable"),
        ("fp", "full_hybrid", 1, "safe"),
        ("fn", "full_hybrid", 2, "vulnerable"),
        ("tn", "full_hybrid", 2, "safe"),
        ("missing", "full_hybrid", 3, "safe"),
    )
    records = (
        _record(
            case_id="tp",
            configuration="full_hybrid",
            repetition=1,
            scanner_signal_count=1,
            finding_origin="deterministic",
        ),
        _record(
            case_id="fp",
            configuration="full_hybrid",
            repetition=1,
            expected_label="safe",
            policy_matched=False,
            returned_category="path",
            finding_origin="model_native",
            scanner_signal_count=0,
        ),
        _record(
            case_id="fn",
            configuration="full_hybrid",
            repetition=2,
            predicted_label="safe",
            confirmed_finding=False,
            policy_matched=False,
            returned_category=None,
            returned_source_alias=None,
            finding_origin=None,
            scanner_signal_count=0,
        ),
        _record(
            case_id="tn",
            configuration="full_hybrid",
            repetition=2,
            expected_label="safe",
            predicted_label="safe",
            confirmed_finding=False,
            policy_matched=False,
            returned_category=None,
            returned_source_alias=None,
            finding_origin=None,
            scanner_signal_count=0,
        ),
        _record(
            case_id="missing",
            configuration="full_hybrid",
            repetition=3,
            expected_label="safe",
            state="failed",
            predicted_label=None,
            confirmed_finding=None,
            policy_matched=None,
            returned_category=None,
            returned_source_alias=None,
            reason="timeout",
            finding_origin=None,
            scanner_signal_count=1,
        ),
    )
    result = aggregate(plan, records)
    attribution = cast(dict[str, Any], result["full_hybrid_origin_attribution"])
    origins = cast(dict[str, dict[str, float | int | None]], attribution["per_origin"])
    assert origins["deterministic"] == {
        "TP": 1,
        "FP": 0,
        "confirmed_precision": 1.0,
        "recall_contribution": 0.5,
    }
    assert origins["model_native"] == {
        "TP": 0,
        "FP": 1,
        "confirmed_precision": 0.0,
        "recall_contribution": 0.0,
    }
    assert attribution["unattributed"] == {"FN": 1, "TN": 1, "missing_safe": 1}
    assert attribution["zero_scanner_signal_stratum"]["matrix"] == {
        "TP": 0,
        "FP": 1,
        "safe_FP": 1,
        "unmatched_FP": 0,
        "FN": 1,
        "TN": 1,
        "missing_safe": 0,
        "planned": 3,
        "executed": 3,
        "not_run": 0,
        "failed": 0,
        "precision": 0.0,
        "recall": 0.0,
        "f1": None,
        "f2": None,
        "vulnerable_reconciles": True,
        "safe_reconciles": True,
    }
    assert attribution["zero_scanner_signal_stratum"]["complete"] is True
    assert attribution["deterministic_candidate_auditor_receipt_coverage"] == {
        "deterministic_candidate_cells": 2,
        "auditor_receipt_cells": 1,
        "dropped_candidate_cells": 1,
        "coverage": 0.5,
        "complete": False,
    }
    assert attribution["confirmed_cell_origin_coverage"] == {
        "confirmed_cells": 2,
        "attributed_cells": 2,
        "complete": True,
    }
    assert attribution["reconciliation"]["complete"] is True
