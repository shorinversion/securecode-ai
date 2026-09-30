"""Safe JSON, Markdown, and HTML report output rendering."""

from __future__ import annotations

import hashlib
import html
from collections.abc import Callable

from securecode_ai.contracts import SourceLocation

from .classification import FindingSeverity
from .reports_contracts import (
    _CONTROL,
    DeterministicReport,
    ReportError,
    ReportErrorCode,
    ReportFinding,
    ReportFormat,
    _canonical_json,
)
from .reports_sarif import _assert_pinned_sarif_conformance, _sarif_document

_SarifDocumentBuilder = Callable[[DeterministicReport], dict[str, object]]


def render_report(report: DeterministicReport, format: ReportFormat) -> bytes:
    return _render_report(report, format, _sarif_document)


def _render_report(
    report: DeterministicReport,
    format: ReportFormat,
    sarif_document_builder: _SarifDocumentBuilder,
) -> bytes:
    if type(report) is not DeterministicReport or type(format) is not ReportFormat:
        raise ReportError(ReportErrorCode.INPUT_INVALID)
    _assert_report_integrity(report)
    if format is ReportFormat.JSON:
        return _canonical_json(report.document) + b"\n"
    if format is ReportFormat.SARIF:
        document = sarif_document_builder(report)
        _assert_pinned_sarif_conformance(document)
        return _canonical_json(document) + b"\n"
    if format is ReportFormat.MARKDOWN:
        return _render_markdown(report).encode("utf-8")
    if format is ReportFormat.HTML:
        return _render_html(report).encode("utf-8")
    raise ReportError(ReportErrorCode.FORMAT_INVALID)


def _assert_report_integrity(report: DeterministicReport) -> None:
    """Reject retained-state mutation before any report reaches an output sink."""

    try:
        document_hash = hashlib.sha256(_canonical_json(report.document)).hexdigest()
    except (TypeError, ValueError):
        raise ReportError(ReportErrorCode.INPUT_INVALID) from None
    if document_hash != report.report_sha256:
        raise ReportError(ReportErrorCode.INPUT_INVALID)
    try:
        # The report object is a public frozen container, but its nested model
        # and document references can still be replaced or mutated by callers.
        # Rebuild the semantic source from the retained run/findings/tools so a
        # caller cannot pair a valid hash with unrelated report metadata.
        from .reports_build import build_deterministic_report

        expected = build_deterministic_report(report.run, report.findings, report.tools)
    except Exception:
        raise ReportError(ReportErrorCode.INPUT_INVALID) from None
    if expected.document != report.document or expected.report_sha256 != report.report_sha256:
        raise ReportError(ReportErrorCode.INPUT_INVALID)


def _render_markdown(report: DeterministicReport) -> str:
    lines = [
        "# SecureCode AI deterministic report",
        "",
        f"- Run: `{_markdown(report.run.run_id)}`",
        f"- Outcome: `{report.run.audit_outcome.value}`",
        f"- Analysis health: `{report.run.analysis_health.value}`",
        f"- Findings: `{len(report.findings)}`",
        "",
    ]
    if not report.run.coverage_manifest.coverage_complete:
        lines.extend(["Coverage is incomplete; this report is not a clean result.", ""])
    for item, origin, locations in _presentation_groups(report):
        finding = item.finding
        classification = item.classification
        lines.extend(
            [
                f"## {_markdown(finding.cwe_id)}",
                "",
                f"- Severity: `{classification.severity.value}`",
                f"- Confidence: `{classification.confidence.value}`",
                f"- OWASP: `{classification.owasp_category}`",
                f"- Verdict: `{finding.finding_verdict.value}`",
                f"- Origin: `{origin}`",
            ]
        )
        for location in locations:
            lines.append(
                f"- Location: `{_markdown(location.path)}` "
                f"({location.start.line}:{location.start.column})"
            )
        lines.append("")
    lines.extend(
        ["## Canonical semantics", "", "```json", _safe_json_text(report.document), "```", ""]
    )
    return "\n".join(lines)


def _presentation_groups(
    report: DeterministicReport,
) -> list[tuple[ReportFinding, str, tuple[SourceLocation, ...]]]:
    """Merge one weakness confirmed by both lanes into one human-readable entry.

    A scanner and the model can each confirm the same CWE in the same file; the canonical
    semantics keep both findings, while Markdown and HTML show one entry with both origins.
    A finding without a same-file, same-CWE partner from another lane renders unchanged.
    """

    groups: list[tuple[ReportFinding, list[str], list[SourceLocation]]] = []
    for item in report.findings:
        finding = item.finding
        origin = finding.candidate_origin.value
        path = finding.locations[0].path if finding.locations else ""
        for first, origins, locations in groups:
            if (
                first.finding.cwe_id == finding.cwe_id
                and first.finding.locations
                and first.finding.locations[0].path == path
                and origin not in origins
            ):
                origins.append(origin)
                locations.extend(item for item in finding.locations if item not in locations)
                break
        else:
            groups.append((item, [origin], list(finding.locations)))
    return [
        (
            first,
            " + ".join(sorted(origins)),
            tuple(
                sorted(locations, key=lambda item: (item.path, item.start.line, item.start.column))
            ),
        )
        for first, origins, locations in groups
    ]


def _render_html(report: DeterministicReport) -> str:
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(item.finding.cwe_id)}</td>"
        f"<td>{html.escape(item.classification.severity.value)}</td>"
        f"<td>{html.escape(item.classification.confidence.value)}</td>"
        f"<td>{html.escape(item.classification.owasp_category)}</td>"
        f"<td>{html.escape(item.finding.finding_verdict.value)}</td>"
        "<td>"
        + "<br>".join(
            f"{html.escape(location.path)} ({location.start.line}:{location.start.column})"
            for location in locations
        )
        + "</td>"
        "</tr>"
        for item, _origin, locations in _presentation_groups(report)
    )
    warning = (
        "<p><strong>Coverage is incomplete; this is not a clean result.</strong></p>"
        if not report.run.coverage_manifest.coverage_complete
        else ""
    )
    semantic = html.escape(_safe_json_text(report.document))
    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
        '<meta name="referrer" content="no-referrer">'
        "<title>SecureCode AI deterministic report</title>"
        "<style>body{font-family:sans-serif;max-width:72rem;margin:auto;padding:2rem}"
        "table{border-collapse:collapse}td,th{border:1px solid #999;padding:.4rem}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere}</style></head><body>"
        "<h1>SecureCode AI deterministic report</h1>"
        f"<p>Run: <code>{html.escape(report.run.run_id)}</code></p>"
        f"<p>Outcome: <code>{html.escape(report.run.audit_outcome.value)}</code></p>"
        f"{warning}<table><thead><tr><th>CWE</th><th>Severity</th><th>Confidence</th>"
        f"<th>OWASP</th><th>Verdict</th><th>Location</th></tr></thead><tbody>{rows}</tbody></table>"
        f'<h2>Canonical semantics</h2><pre id="semantic-json">{semantic}</pre>'
        "</body></html>\n"
    )


def _sarif_level(severity: FindingSeverity) -> str:
    return {
        FindingSeverity.LOW: "note",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.HIGH: "error",
        FindingSeverity.CRITICAL: "error",
    }[severity]


def _markdown(value: str) -> str:
    clean = _CONTROL.sub("", value)
    return "".join("\\" + char if char in r"\\`*_{}[]()#+-!|<>&" else char for char in clean)


def _safe_json_text(document: dict[str, object]) -> str:
    return (
        _canonical_json(document)
        .decode("utf-8")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
