"""The opt-in stage trace: silent by default, source-free always."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from securecode_ai.adapters.dependency_scanning import DependencyScanError, DependencyScanErrorCode
from securecode_ai.adapters.local_product_trial import TrialAnalysisError, run_trial_analysis
from securecode_ai.adapters.trace import (
    configure_trace,
    exception_label,
    trace_enabled,
    trace_event,
)
from securecode_ai.core.reports import ReportFormat


@pytest.fixture(autouse=True)
def _trace_off() -> Iterator[None]:
    configure_trace(None)
    yield
    configure_trace(None)


def _events(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_without_a_path_nothing_is_written(tmp_path: Path) -> None:
    trace_event("child_stage", stage="scan")

    assert not trace_enabled()
    assert list(tmp_path.iterdir()) == []


def test_events_are_appended_as_json_lines(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    configure_trace(str(path))

    trace_event("child_stage", stage="scan", complete=False, seconds=1.23456, receipts=3)
    trace_event("run_end", exit_code=3, reasons=("OBSTACLE:X", "SCAN_INCOMPLETE"))

    first, second = _events(path)
    assert first["kind"] == "child_stage" and first["stage"] == "scan"
    assert first["complete"] is False and first["seconds"] == 1.235 and first["receipts"] == 3
    assert second["reasons"] == ["OBSTACLE:X", "SCAN_INCOMPLETE"]
    assert {"time", "t"} <= first.keys()


def test_values_that_could_carry_source_are_cut_or_dropped(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"
    configure_trace(str(path))

    trace_event("x", text="a" * 500, nested={"source": "password"}, blob=b"bytes", many=["a", 1])

    (event,) = _events(path)
    assert str(event["text"]).endswith("...") and len(str(event["text"])) < 130
    assert not {"nested", "blob", "many"} & event.keys()


def test_an_unwritable_trace_never_breaks_the_run(tmp_path: Path) -> None:
    configure_trace(str(tmp_path / "missing-directory" / "trace.jsonl"))

    trace_event("child_stage", stage="scan")  # must not raise


def test_exception_label_adds_the_closed_error_code() -> None:
    assert exception_label(ValueError("secret text")) == "ValueError"
    error = DependencyScanError(DependencyScanErrorCode.SCANNER_FAILURE)
    assert exception_label(error) == "DependencyScanError/SCANNER_FAILURE"


def test_run_trial_analysis_traces_a_failed_run_and_turns_the_trace_off(tmp_path: Path) -> None:
    path = tmp_path / "trace.jsonl"

    with pytest.raises(TrialAnalysisError):
        run_trial_analysis(
            str(tmp_path / "not-a-checkout"),
            provider="nonsense",
            report_format=ReportFormat.JSON,
            environment={"SECURECODE_TRACE": str(path)},
        )

    kinds = [event["kind"] for event in _events(path)]
    assert kinds == ["run_start", "run_end"]
    assert _events(path)[-1]["error"] == "TrialAnalysisError"
    assert not trace_enabled()


@pytest.mark.parametrize("value", ["59", "601", "abc", "-1"])
def test_scan_budget_variable_is_bounded(tmp_path: Path, value: str) -> None:
    with pytest.raises(TrialAnalysisError, match="SECURECODE_SCAN_BUDGET_SECONDS"):
        run_trial_analysis(
            str(tmp_path),
            provider="local",
            report_format=ReportFormat.JSON,
            environment={"SECURECODE_SCAN_BUDGET_SECONDS": value},
        )
