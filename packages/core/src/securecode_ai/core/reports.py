"""Canonical deterministic JSON, Markdown, HTML and SARIF report rendering."""

from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, TypeGuard
from urllib.parse import quote, unquote

from securecode_ai.contracts import AuditRun, ComponentPin, FindingCase

from .classification import FindingClassification, FindingSeverity

REPORT_SCHEMA_VERSION: Final = "0.2.0"
REPORT_FORMAT_VERSION: Final = "1.0.0"
SARIF_VERSION: Final = "2.1.0"
SARIF_SCHEMA_URI: Final = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
SARIF_SCHEMA_SHA256: Final = "".join(
    ("c3b4bb2d", "60938974", "83348925", "aaa73af0", "3b3e3f4b", "d4ca38ce", "f26dcb42", "12a2682e")
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_SARIF_ENCODED_URI = re.compile(r"(?:[A-Za-z0-9._~/-]|%[0-9A-F]{2})+")
_SARIF_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")


class ReportFormat(StrEnum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    SARIF = "sarif"


class ReportErrorCode(StrEnum):
    INPUT_INVALID = "INPUT_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    FINDING_MISMATCH = "FINDING_MISMATCH"
    FORMAT_INVALID = "FORMAT_INVALID"


class ReportError(ValueError):
    code: ReportErrorCode
    safe_message: str

    def __init__(self, code: ReportErrorCode) -> None:
        if type(code) is not ReportErrorCode:
            raise TypeError("report error code is invalid")
        self.code = code
        self.safe_message = "deterministic report operation failed"
        super().__init__(self.safe_message)


@dataclass(frozen=True, slots=True)
class ReportFinding:
    finding: FindingCase
    classification: FindingClassification

    def __post_init__(self) -> None:
        if (
            type(self.finding) is not FindingCase
            or type(self.classification) is not FindingClassification
            or self.finding.cwe_id != self.classification.cwe_id
        ):
            raise ValueError("report finding is invalid")


@dataclass(frozen=True, slots=True)
class DeterministicReport:
    run: AuditRun
    findings: tuple[ReportFinding, ...]
    tools: tuple[ComponentPin, ...]
    document: dict[str, object]
    report_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.run) is not AuditRun
            or type(self.findings) is not tuple
            or any(type(item) is not ReportFinding for item in self.findings)
            or type(self.tools) is not tuple
            or any(type(item) is not ComponentPin for item in self.tools)
            or type(self.document) is not dict
            or self.report_sha256 != hashlib.sha256(_canonical_json(self.document)).hexdigest()
        ):
            raise ValueError("deterministic report is invalid")


def build_deterministic_report(
    run: AuditRun,
    findings: tuple[ReportFinding, ...],
    tools: tuple[ComponentPin, ...],
) -> DeterministicReport:
    """Validate one exact run and build its canonical semantic JSON source."""

    if (
        type(run) is not AuditRun
        or type(findings) is not tuple
        or any(type(item) is not ReportFinding for item in findings)
        or type(tools) is not tuple
        or any(type(item) is not ComponentPin for item in tools)
    ):
        raise ReportError(ReportErrorCode.INPUT_INVALID)
    try:
        validated_run = AuditRun.model_validate(run.model_dump(mode="python"))
        validated_findings = tuple(
            ReportFinding(
                FindingCase.model_validate(item.finding.model_dump(mode="python")),
                item.classification,
            )
            for item in findings
        )
        validated_tools = tuple(
            ComponentPin.model_validate(item.model_dump(mode="python")) for item in tools
        )
    except Exception:
        raise ReportError(ReportErrorCode.INPUT_INVALID) from None

    revision = validated_run.execution_identity.repository_revision
    finding_ids = tuple(item.finding.finding_id for item in validated_findings)
    if finding_ids != tuple(sorted(finding_ids)) or len(finding_ids) != len(set(finding_ids)):
        raise ReportError(ReportErrorCode.FINDING_MISMATCH)
    if set(finding_ids) != set(validated_run.finding_ids):
        raise ReportError(ReportErrorCode.FINDING_MISMATCH)
    if len({(item.component_id, item.component_version) for item in validated_tools}) != len(
        validated_tools
    ) or validated_tools != tuple(
        sorted(validated_tools, key=lambda item: (item.component_id, item.component_version))
    ):
        raise ReportError(ReportErrorCode.INPUT_INVALID)
    for item in validated_findings:
        finding = item.finding
        if finding.repository_revision != revision or finding.root_cause_fingerprint != next(
            (
                candidate.root_cause_fingerprint
                for candidate in validated_run.coverage_manifest.discovery_candidates
                if candidate.candidate_id == finding.candidate_id
                and candidate.candidate_version == finding.candidate_version
            ),
            None,
        ):
            raise ReportError(ReportErrorCode.IDENTITY_MISMATCH)

    document: dict[str, object] = {
        "analysis_health": validated_run.analysis_health.value,
        "coverage_manifest": validated_run.coverage_manifest.model_dump(mode="json"),
        "execution_identity": validated_run.execution_identity.model_dump(mode="json"),
        "execution_identity_hash": validated_run.execution_identity.execution_identity_hash,
        "findings": [_finding_document(item) for item in validated_findings],
        "model_profile": validated_run.execution_identity.provider_profile.model_dump(mode="json"),
        "outcome": validated_run.audit_outcome.value,
        "policy": validated_run.execution_identity.policy.model_dump(mode="json"),
        "report_version": REPORT_FORMAT_VERSION,
        "repository_revision": revision.model_dump(mode="json"),
        "run_id": validated_run.run_id,
        "schema_version": REPORT_SCHEMA_VERSION,
        "tools": [item.model_dump(mode="json") for item in validated_tools],
        "workflow": validated_run.execution_identity.workflow.model_dump(mode="json"),
    }
    report_hash = hashlib.sha256(_canonical_json(document)).hexdigest()
    return DeterministicReport(
        run=validated_run,
        findings=validated_findings,
        tools=validated_tools,
        document=document,
        report_sha256=report_hash,
    )


def render_report(report: DeterministicReport, format: ReportFormat) -> bytes:
    if type(report) is not DeterministicReport or type(format) is not ReportFormat:
        raise ReportError(ReportErrorCode.INPUT_INVALID)
    _assert_report_integrity(report)
    if format is ReportFormat.JSON:
        return _canonical_json(report.document) + b"\n"
    if format is ReportFormat.SARIF:
        document = _sarif_document(report)
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


def _finding_document(item: ReportFinding) -> dict[str, object]:
    finding = item.finding
    classification = item.classification
    return {
        "blocking": finding.blocking,
        "candidate_id": finding.candidate_id,
        "candidate_origin": finding.candidate_origin.value,
        "confidence": classification.confidence.value,
        "cwe_id": finding.cwe_id,
        "evidence_graph_ref": finding.evidence_graph_ref.model_dump(mode="json"),
        "evidence_ids": list(finding.evidence_ids),
        "finding_id": finding.finding_id,
        "locations": [location.model_dump(mode="json") for location in finding.locations],
        "mapping_provenance": {
            "calibration_record_id": classification.provenance.calibration_record_id,
            "confidence_basis": classification.provenance.confidence_basis,
            "mapping_id": classification.provenance.mapping_id,
            "mapping_sha256": classification.provenance.mapping_sha256,
            "mapping_version": classification.provenance.mapping_version,
            "severity_basis": classification.provenance.severity_basis,
        },
        "owasp_category": classification.owasp_category,
        "patch_refs": [],
        "producer_lineage": [
            lineage.model_dump(mode="json") for lineage in finding.producer_lineage
        ],
        "root_cause_fingerprint": finding.root_cause_fingerprint,
        "severity": classification.severity.value,
        "validation_refs": [],
        "verdict": finding.finding_verdict.value,
    }


def _sarif_document(report: DeterministicReport) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for item in report.findings:
        finding = item.finding
        classification = item.classification
        rules.setdefault(
            finding.cwe_id,
            {
                "id": finding.cwe_id,
                "name": finding.cwe_id,
                "properties": {
                    "owasp": classification.owasp_category,
                    "severity": classification.severity.value,
                },
                "shortDescription": {"text": "Security analysis candidate"},
            },
        )
        results.append(
            {
                "fingerprints": {"securecodeRootCause/v1": finding.root_cause_fingerprint},
                "level": _sarif_level(classification.severity),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": quote(location.path, safe="/-._~")},
                            "region": {
                                "endColumn": location.end.column,
                                "endLine": location.end.line,
                                "startColumn": location.start.column,
                                "startLine": location.start.line,
                            },
                        }
                    }
                    for location in finding.locations
                ],
                "message": {
                    "text": "Security candidate requires evidence-grounded interpretation."
                },
                "properties": {
                    "candidateOrigin": finding.candidate_origin.value,
                    "confidence": classification.confidence.value,
                    "verdict": finding.finding_verdict.value,
                },
                "ruleId": finding.cwe_id,
            }
        )
    return {
        "$schema": SARIF_SCHEMA_URI,
        "runs": [
            {
                "automationDetails": {"id": report.run.run_id},
                "properties": {
                    "analysisHealth": report.run.analysis_health.value,
                    "executionIdentityHash": report.run.execution_identity.execution_identity_hash,
                    "outcome": report.run.audit_outcome.value,
                    "reportSha256": report.report_sha256,
                },
                "results": results,
                "tool": {
                    "driver": {
                        "informationUri": "https://securecode.ai/",
                        "name": "SecureCode AI",
                        "rules": [rules[key] for key in sorted(rules)],
                        "semanticVersion": REPORT_FORMAT_VERSION,
                    }
                },
            }
        ],
        "version": SARIF_VERSION,
    }


def _assert_pinned_sarif_conformance(document: dict[str, object]) -> None:
    """Validate every OASIS constraint reachable from this emitter's closed shape.

    The OASIS SARIF 2.1.0 Errata 01 schema is a 112,768-byte, 3,097-line
    document. The renderer intentionally emits one small closed subset. This
    validator mirrors every structural, type, enum, and location constraint
    reachable from that subset before bytes are returned. It is not a general
    arbitrary-SARIF validator. The URI and digest below pin the official source
    bytes without a runtime resolver or a runtime JSON-schema dependency.
    """

    if type(document) is not dict or set(document) != {"$schema", "runs", "version"}:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    if document.get("$schema") != SARIF_SCHEMA_URI or document.get("version") != SARIF_VERSION:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    runs = document.get("runs")
    if type(runs) is not list or len(runs) != 1:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    _assert_sarif_run(runs[0])


def _assert_sarif_run(value: object) -> None:
    if type(value) is not dict or set(value) != {
        "automationDetails",
        "properties",
        "results",
        "tool",
    }:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    automation = value.get("automationDetails")
    if (
        type(automation) is not dict
        or set(automation) != {"id"}
        or not _is_text(automation.get("id"))
    ):
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    properties = value.get("properties")
    if (
        type(properties) is not dict
        or set(properties)
        != {
            "analysisHealth",
            "executionIdentityHash",
            "outcome",
            "reportSha256",
        }
        or not all(_is_text(item) for item in properties.values())
    ):
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    tool = value.get("tool")
    if type(tool) is not dict or set(tool) != {"driver"}:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    _assert_sarif_driver(tool.get("driver"))
    results = value.get("results")
    if type(results) is not list:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    for result in results:
        _assert_sarif_result(result)


def _assert_sarif_driver(value: object) -> None:
    if type(value) is not dict or set(value) != {
        "informationUri",
        "name",
        "rules",
        "semanticVersion",
    }:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    if (
        value.get("informationUri") != "https://securecode.ai/"
        or value.get("name") != "SecureCode AI"
        or value.get("semanticVersion") != REPORT_FORMAT_VERSION
    ):
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    rules = value.get("rules")
    if type(rules) is not list:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    rule_ids: list[str] = []
    for rule in rules:
        if type(rule) is not dict or set(rule) != {"id", "name", "properties", "shortDescription"}:
            raise ReportError(ReportErrorCode.FORMAT_INVALID)
        rule_id = rule.get("id")
        if (
            not _is_text(rule_id)
            or not _SARIF_CWE.fullmatch(rule_id)
            or rule.get("name") != rule_id
        ):
            raise ReportError(ReportErrorCode.FORMAT_INVALID)
        properties = rule.get("properties")
        description = rule.get("shortDescription")
        if (
            type(properties) is not dict
            or set(properties) != {"owasp", "severity"}
            or not all(_is_text(item) for item in properties.values())
            or type(description) is not dict
            or set(description) != {"text"}
            or not _is_text(description.get("text"))
        ):
            raise ReportError(ReportErrorCode.FORMAT_INVALID)
        rule_ids.append(rule_id)
    if rule_ids != sorted(rule_ids) or len(rule_ids) != len(set(rule_ids)):
        raise ReportError(ReportErrorCode.FORMAT_INVALID)


def _assert_sarif_result(value: object) -> None:
    if type(value) is not dict or set(value) != {
        "fingerprints",
        "level",
        "locations",
        "message",
        "properties",
        "ruleId",
    }:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    rule_id = value.get("ruleId")
    if (
        not _is_text(rule_id)
        or not _SARIF_CWE.fullmatch(rule_id)
        or value.get("level")
        not in {
            "note",
            "warning",
            "error",
        }
    ):
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    fingerprints = value.get("fingerprints")
    message = value.get("message")
    properties = value.get("properties")
    if (
        type(fingerprints) is not dict
        or set(fingerprints) != {"securecodeRootCause/v1"}
        or not _is_text(fingerprints.get("securecodeRootCause/v1"))
        or type(message) is not dict
        or set(message) != {"text"}
        or not _is_text(message.get("text"))
        or type(properties) is not dict
        or set(properties) != {"candidateOrigin", "confidence", "verdict"}
        or not all(_is_text(item) for item in properties.values())
    ):
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    locations = value.get("locations")
    if type(locations) is not list:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    for location in locations:
        _assert_sarif_location(location)


def _assert_sarif_location(value: object) -> None:
    if type(value) is not dict or set(value) != {"physicalLocation"}:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    physical = value.get("physicalLocation")
    if type(physical) is not dict or set(physical) != {"artifactLocation", "region"}:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    if type(artifact) is not dict or set(artifact) != {"uri"}:
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    uri = artifact.get("uri")
    if (
        not _is_text(uri)
        or uri.startswith(("/", "//"))
        or "//" in uri
        or not _SARIF_ENCODED_URI.fullmatch(uri)
        or uri != quote(unquote(uri), safe="/-._~")
    ):
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    if (
        type(region) is not dict
        or set(region)
        != {
            "endColumn",
            "endLine",
            "startColumn",
            "startLine",
        }
        or any(type(item) is not int or item < 1 for item in region.values())
    ):
        raise ReportError(ReportErrorCode.FORMAT_INVALID)
    if (region["endLine"], region["endColumn"]) < (region["startLine"], region["startColumn"]):
        raise ReportError(ReportErrorCode.FORMAT_INVALID)


def _is_text(value: object) -> TypeGuard[str]:
    return type(value) is str and bool(value) and _CONTROL.search(value) is None


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
    for item in report.findings:
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
                f"- Origin: `{finding.candidate_origin.value}`",
            ]
        )
        for location in finding.locations:
            lines.append(
                f"- Location: `{_markdown(location.path)}` "
                f"({location.start.line}:{location.start.column})"
            )
        lines.append("")
    lines.extend(
        ["## Canonical semantics", "", "```json", _safe_json_text(report.document), "```", ""]
    )
    return "\n".join(lines)


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
            for location in item.finding.locations
        )
        + "</td>"
        "</tr>"
        for item in report.findings
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


def _canonical_json(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


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
