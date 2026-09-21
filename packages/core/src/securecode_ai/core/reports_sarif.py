"""SARIF document rendering and pinned closed-shape validation."""

from __future__ import annotations

from typing import TypeGuard
from urllib.parse import quote, unquote

from .classification import FindingSeverity
from .reports_contracts import (
    _CONTROL,
    _SARIF_CWE,
    _SARIF_ENCODED_URI,
    REPORT_FORMAT_VERSION,
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    DeterministicReport,
    ReportError,
    ReportErrorCode,
)


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


def _sarif_level(severity: FindingSeverity) -> str:
    return {
        FindingSeverity.LOW: "note",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.HIGH: "error",
        FindingSeverity.CRITICAL: "error",
    }[severity]
