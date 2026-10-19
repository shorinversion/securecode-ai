# ruff: noqa: RUF001 - the report under test is written in Russian
"""The readable report names the scope of an incremental run."""

from __future__ import annotations

from pathlib import Path

from securecode_ai.adapters.trial_report import TrialReportContext, render_trial_report


def test_report_says_how_many_changed_files_were_audited() -> None:
    document: dict[str, object] = {"outcome": "PASS", "findings": []}
    scoped = TrialReportContext(
        Path("repo"), "a" * 40, "local", "qwen", 0, {}, scope=(3, "bbbbbbbbbbbb")
    )
    whole = TrialReportContext(Path("repo"), "a" * 40, "local", "qwen", 0, {})

    text = render_trial_report(document, scoped, (), html_format=False).decode()

    assert "3 изменённых файлов с bbbbbbbbbbbb" in text
    assert (
        "изменённых файлов"
        not in render_trial_report(document, whole, (), html_format=False).decode()
    )
