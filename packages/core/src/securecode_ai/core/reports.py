"""Canonical deterministic JSON, Markdown, HTML and SARIF report rendering."""

from __future__ import annotations

from .reports_build import build_deterministic_report
from .reports_contracts import (
    REPORT_FORMAT_VERSION,
    REPORT_SCHEMA_VERSION,
    SARIF_SCHEMA_SHA256,
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    DeterministicReport,
    ReportError,
    ReportErrorCode,
    ReportFinding,
    ReportFormat,
)
from .reports_render import _render_report
from .reports_sarif import _sarif_document as _sarif_document


def render_report(report: DeterministicReport, format: ReportFormat) -> bytes:
    """Render through the facade-visible, closed SARIF construction seam."""
    return _render_report(report, format, _sarif_document)


for _report_type in (
    ReportFormat,
    ReportErrorCode,
    ReportError,
    ReportFinding,
    DeterministicReport,
):
    _report_type.__module__ = __name__
del _report_type

__all__ = [
    "REPORT_FORMAT_VERSION",
    "REPORT_SCHEMA_VERSION",
    "SARIF_SCHEMA_SHA256",
    "SARIF_SCHEMA_URI",
    "SARIF_VERSION",
    "DeterministicReport",
    "ReportError",
    "ReportErrorCode",
    "ReportFinding",
    "ReportFormat",
    "build_deterministic_report",
    "render_report",
]
