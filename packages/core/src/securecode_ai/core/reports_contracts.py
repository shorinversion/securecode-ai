"""Canonical deterministic JSON, Markdown, HTML and SARIF report rendering."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import AuditRun, ComponentPin, FindingCase

from .classification import FindingClassification

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


def _canonical_json(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
