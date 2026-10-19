# ruff: noqa: RUF001 - the reports under test are written in Russian
"""The reports name why a stage did not complete, with fixed codes only."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from securecode_ai.adapters.coverage_causes import (
    attach_diagnostics_to_json,
    coverage_diagnostics,
    deterministic_reasons,
    gap_detail,
)
from securecode_ai.adapters.trial_report import _coverage_gaps


def _composition(*, reasons: tuple[str, ...], with_execution: bool = True) -> Any:
    execution = SimpleNamespace(
        is_complete=not reasons,
        incompleteness_reasons=lambda: reasons,
        obstacles=("PRODUCT_STATIC_EXECUTION_FAILED",) if reasons else (),
        obstacle_errors=(("PRODUCT_DEPENDENCY_EXECUTION_FAILED", "DependencyScanError/X"),)
        if reasons
        else (),
        scan=SimpleNamespace(receipts=(1, 2)),
        catalogue=SimpleNamespace(indexes=(1, 2, 3)),
    )
    host = SimpleNamespace(deterministic_execution=execution if with_execution else None)
    return SimpleNamespace(host_inputs=host)


def _manifest(*units: dict[str, object]) -> dict[str, object]:
    return {"coverage_manifest": {"units": list(units)}}


SKIPPED = {
    "stage_id": "deterministic_analysis",
    "required": True,
    "coverage_status": "SKIPPED",
    "reason_code": "DETERMINISTIC_CHILD_EXECUTION_INCOMPLETE",
}


def test_reasons_come_from_the_deterministic_execution() -> None:
    reasons = ("OBSTACLE:PRODUCT_STATIC_EXECUTION_FAILED", "SCAN_INCOMPLETE")

    assert deterministic_reasons(_composition(reasons=reasons)) == reasons
    assert deterministic_reasons(_composition(reasons=())) == ()
    assert deterministic_reasons(_composition(reasons=reasons, with_execution=False)) == ()


def test_diagnostics_list_obstacles_errors_and_scanned_files() -> None:
    diagnostics = coverage_diagnostics(_composition(reasons=("SCAN_INCOMPLETE",)))

    assert diagnostics == {
        "deterministic": {
            "complete": False,
            "reasons": ["SCAN_INCOMPLETE"],
            "obstacles": ["PRODUCT_STATIC_EXECUTION_FAILED"],
            "obstacle_errors": [
                {
                    "obstacle": "PRODUCT_DEPENDENCY_EXECUTION_FAILED",
                    "error": "DependencyScanError/X",
                }
            ],
            "scanner_files": 2,
            "scanner_files_expected": 3,
        }
    }


def test_json_report_gets_diagnostics_and_the_unfinished_units() -> None:
    report = json.dumps(
        {
            "outcome": "INDETERMINATE",
            **_manifest(
                SKIPPED,
                {"stage_id": "intake", "required": True, "coverage_status": "COMPLETED"},
                {"stage_id": "x", "required": False, "coverage_status": "FAILED"},
            ),
        }
    ).encode()

    document = json.loads(attach_diagnostics_to_json(report, _composition(reasons=("A",))))

    assert document["coverage_diagnostics"]["unfinished_units"] == [
        {
            "stage_id": "deterministic_analysis",
            "coverage_status": "SKIPPED",
            "reason_code": "DETERMINISTIC_CHILD_EXECUTION_INCOMPLETE",
        }
    ]
    assert document["coverage_diagnostics"]["deterministic"]["reasons"] == ["A"]


def test_a_complete_run_without_execution_details_is_left_untouched() -> None:
    report = json.dumps({"outcome": "PASS", **_manifest()}).encode()

    assert attach_diagnostics_to_json(report, _composition(reasons=(), with_execution=False)) == (
        report
    )


def test_skipped_deterministic_unit_is_named_with_its_reasons() -> None:
    reasons = ("OBSTACLE:PRODUCT_STATIC_EXECUTION_FAILED", "SCAN_INCOMPLETE")

    gaps = _coverage_gaps(_manifest(SKIPPED), reasons)

    assert gaps == (
        "детерминированные сканеры: не завершена, причина "
        "OBSTACLE:PRODUCT_STATIC_EXECUTION_FAILED; SCAN_INCOMPLETE",
    )


def test_other_skipped_units_show_their_reason_code_and_failed_ones_are_counted() -> None:
    failed = {
        "stage_id": "model_native_discovery",
        "required": True,
        "coverage_status": "FAILED",
        "reason_code": "MODEL_DISCOVERY_NON_SUCCESS",
    }
    other = {
        "stage_id": "coverage_guard",
        "required": True,
        "coverage_status": "SKIPPED",
        "reason_code": "COVERAGE_GUARD_RECEIPT_MISSING",
    }

    gaps = _coverage_gaps(_manifest(failed, failed, other, {**SKIPPED, "required": False}))

    assert gaps == (
        "поиск уязвимостей моделью: не завершена (2)",
        "coverage_guard: не завершена, причина COVERAGE_GUARD_RECEIPT_MISSING",
    )


def test_gap_detail_prefers_reasons_only_for_the_incomplete_execution_code() -> None:
    assert gap_detail("DETERMINISTIC_CHILD_EXECUTION_INCOMPLETE", ()) == (
        "DETERMINISTIC_CHILD_EXECUTION_INCOMPLETE"
    )
    assert gap_detail("OTHER", ("A",)) == "OTHER"
    assert gap_detail("DETERMINISTIC_CHILD_EXECUTION_INCOMPLETE", ("A", "B")) == "A; B"


def test_discovery_mode_counts_the_seed_or_all_windows() -> None:
    from securecode_ai.adapters.coverage_causes import discovery_mode

    anchors = tuple(range(40))

    def composition(seed: str, ids: tuple[str, ...]) -> Any:
        host = SimpleNamespace(
            discovery_seed=seed,
            discovery_seed_evidence_ids=ids,
            source_catalogue=SimpleNamespace(anchors=anchors),
        )
        return SimpleNamespace(host_inputs=host)

    assert discovery_mode(composition("scanner", ("a", "b", "c"))) == {
        "discovery_seed": "scanner",
        "seed_windows": 3,
        "total_windows": 40,
    }
    assert discovery_mode(composition("full", ())) == {
        "discovery_seed": "full",
        "seed_windows": 40,
        "total_windows": 40,
    }


def test_readable_report_says_how_many_windows_discovery_read() -> None:
    from pathlib import Path

    from securecode_ai.adapters.trial_report import TrialReportContext, render_trial_report

    document: dict[str, object] = {"outcome": "PASS", "findings": [], **_manifest()}
    shown = TrialReportContext(
        Path("repo"), "a" * 40, "local", "qwen", 0, {}, discovery_seed=(3, 40)
    )
    plain = TrialReportContext(Path("repo"), "a" * 40, "local", "qwen", 0, {})

    assert (
        "окна со сработками сканеров (3 из 40)"
        in render_trial_report(document, shown, (), html_format=False).decode()
    )
    assert (
        "окна со сработками"
        not in render_trial_report(document, plain, (), html_format=False).decode()
    )
