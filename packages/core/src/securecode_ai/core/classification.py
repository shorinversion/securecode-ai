"""Deterministic pre-calibration CWE, OWASP, severity and confidence mapping."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

_SHA256 = re.compile(r"[0-9a-f]{64}")
_SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}")
_OWASP = re.compile(r"A(?:0[1-9]|10):[0-9]{4}")


class FindingSeverity(StrEnum):
    """Closed deterministic rule-severity vocabulary."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingConfidence(StrEnum):
    """Confidence state before an accepted calibration exists."""

    UNSCORED = "UNSCORED"


class ClassificationErrorCode(StrEnum):
    INPUT_INVALID = "INPUT_INVALID"
    UNSUPPORTED_CWE = "UNSUPPORTED_CWE"


class ClassificationError(ValueError):
    """Fixed, non-echo classification failure."""

    code: ClassificationErrorCode
    safe_message: str

    def __init__(self, code: ClassificationErrorCode) -> None:
        if type(code) is not ClassificationErrorCode:
            raise TypeError("classification error code is invalid")
        self.code = code
        self.safe_message = "finding classification failed"
        super().__init__(self.safe_message)


@dataclass(frozen=True, slots=True)
class ClassificationProvenance:
    mapping_id: str
    mapping_version: str
    mapping_sha256: str
    severity_basis: str
    confidence_basis: str
    calibration_record_id: None = None

    def __post_init__(self) -> None:
        expected = _provenance_config(self.mapping_id)
        if self.mapping_id == "securecode-core-mvp-classification":
            mapping_valid = (
                _SEMVER.fullmatch(self.mapping_version) is not None
                and _SHA256.fullmatch(self.mapping_sha256) is not None
            )
        else:
            mapping_valid = (
                expected is not None
                and self.mapping_version == expected[0]
                and self.mapping_sha256 == expected[1]
            )
        if (
            not mapping_valid
            or self.severity_basis != "RULE_CATALOG"
            or self.confidence_basis != "PRE_CALIBRATION_UNSCORED"
            or self.calibration_record_id is not None
        ):
            raise ValueError("classification provenance is invalid")


@dataclass(frozen=True, slots=True)
class FindingClassification:
    cwe_id: str
    owasp_category: str
    severity: FindingSeverity
    confidence: FindingConfidence
    provenance: ClassificationProvenance
    classification_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.cwe_id) is not str
            or _CWE.fullmatch(self.cwe_id) is None
            or type(self.owasp_category) is not str
            or _OWASP.fullmatch(self.owasp_category) is None
            or type(self.severity) is not FindingSeverity
            or type(self.confidence) is not FindingConfidence
            or type(self.provenance) is not ClassificationProvenance
            or self.confidence is not FindingConfidence.UNSCORED
            or self.classification_sha256
            != _classification_hash(
                self.cwe_id,
                self.owasp_category,
                self.severity,
                self.confidence,
                self.provenance,
            )
        ):
            raise ValueError("finding classification is invalid")


@dataclass(frozen=True, slots=True)
class _MappingEntry:
    owasp_category: str
    severity: FindingSeverity


_MAPPING_VERSION: Final = "1.0.0"
_MAPPING_ROWS: Final = (("CWE-89", "A03:2021", FindingSeverity.HIGH),)
_MAPPING_SHA256: Final = hashlib.sha256(
    json.dumps(
        [(cwe, owasp, severity.value) for cwe, owasp, severity in _MAPPING_ROWS],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")
).hexdigest()
_MAPPINGS: Final[Mapping[str, _MappingEntry]] = MappingProxyType(
    {cwe: _MappingEntry(owasp, severity) for cwe, owasp, severity in _MAPPING_ROWS}
)
_PRODUCT_MAPPING_ID: Final = "securecode-product-portfolio-classification"
_PRODUCT_MAPPING_VERSION: Final = "1.0.0"
_PRODUCT_MAPPING_ROWS: Final = (
    ("CWE-22", "A01:2021", FindingSeverity.HIGH),
    ("CWE-78", "A03:2021", FindingSeverity.HIGH),
    ("CWE-862", "A01:2021", FindingSeverity.HIGH),
    ("CWE-918", "A10:2021", FindingSeverity.HIGH),
)
_PRODUCT_MAPPING_SHA256: Final = hashlib.sha256(
    json.dumps(
        [(cwe, owasp, severity.value) for cwe, owasp, severity in _PRODUCT_MAPPING_ROWS],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")
).hexdigest()
_PRODUCT_MAPPINGS: Final[Mapping[str, _MappingEntry]] = MappingProxyType(
    {cwe: _MappingEntry(owasp, severity) for cwe, owasp, severity in _PRODUCT_MAPPING_ROWS}
)


def _provenance_config(mapping_id: str) -> tuple[str, str] | None:
    """Return only one exact, versioned policy family for each closed mapping ID."""

    if mapping_id == _PRODUCT_MAPPING_ID:
        return (_PRODUCT_MAPPING_VERSION, _PRODUCT_MAPPING_SHA256)
    return None


DEFAULT_CLASSIFICATION_PROVENANCE: Final = ClassificationProvenance(
    mapping_id="securecode-core-mvp-classification",
    mapping_version=_MAPPING_VERSION,
    mapping_sha256=_MAPPING_SHA256,
    severity_basis="RULE_CATALOG",
    confidence_basis="PRE_CALIBRATION_UNSCORED",
)
PRODUCT_CLASSIFICATION_PROVENANCE: Final = ClassificationProvenance(
    mapping_id=_PRODUCT_MAPPING_ID,
    mapping_version=_PRODUCT_MAPPING_VERSION,
    mapping_sha256=_PRODUCT_MAPPING_SHA256,
    severity_basis="RULE_CATALOG",
    confidence_basis="PRE_CALIBRATION_UNSCORED",
)


def classify_cwe(cwe_id: str) -> FindingClassification:
    """Return the pinned Core-MVP classification without a statistical score."""

    if type(cwe_id) is not str or _CWE.fullmatch(cwe_id) is None:
        raise ClassificationError(ClassificationErrorCode.INPUT_INVALID)
    entry = _MAPPINGS.get(cwe_id)
    if entry is None:
        raise ClassificationError(ClassificationErrorCode.UNSUPPORTED_CWE)
    provenance = DEFAULT_CLASSIFICATION_PROVENANCE
    confidence = FindingConfidence.UNSCORED
    return FindingClassification(
        cwe_id=cwe_id,
        owasp_category=entry.owasp_category,
        severity=entry.severity,
        confidence=confidence,
        provenance=provenance,
        classification_sha256=_classification_hash(
            cwe_id,
            entry.owasp_category,
            entry.severity,
            confidence,
            provenance,
        ),
    )


def classify_product_cwe(cwe_id: str) -> FindingClassification:
    """Classify the closed product portfolio without changing Core-MVP bytes.

    CWE-89 delegates to the historical Core entrypoint.  The four existing
    product rules use a separately pinned policy family, so extending reports
    never redefines the original Core-MVP mapping.
    """

    if type(cwe_id) is not str or _CWE.fullmatch(cwe_id) is None:
        raise ClassificationError(ClassificationErrorCode.INPUT_INVALID)
    if cwe_id == "CWE-89":
        return classify_cwe(cwe_id)
    entry = _PRODUCT_MAPPINGS.get(cwe_id)
    if entry is None:
        raise ClassificationError(ClassificationErrorCode.UNSUPPORTED_CWE)
    provenance = PRODUCT_CLASSIFICATION_PROVENANCE
    confidence = FindingConfidence.UNSCORED
    return FindingClassification(
        cwe_id=cwe_id,
        owasp_category=entry.owasp_category,
        severity=entry.severity,
        confidence=confidence,
        provenance=provenance,
        classification_sha256=_classification_hash(
            cwe_id,
            entry.owasp_category,
            entry.severity,
            confidence,
            provenance,
        ),
    )


def _classification_hash(
    cwe_id: str,
    owasp_category: str,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    provenance: ClassificationProvenance,
) -> str:
    material = {
        "confidence": confidence.value,
        "cwe_id": cwe_id,
        "owasp_category": owasp_category,
        "provenance": {
            "calibration_record_id": provenance.calibration_record_id,
            "confidence_basis": provenance.confidence_basis,
            "mapping_id": provenance.mapping_id,
            "mapping_sha256": provenance.mapping_sha256,
            "mapping_version": provenance.mapping_version,
            "severity_basis": provenance.severity_basis,
        },
        "severity": severity.value,
    }
    return hashlib.sha256(
        json.dumps(
            material,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "DEFAULT_CLASSIFICATION_PROVENANCE",
    "PRODUCT_CLASSIFICATION_PROVENANCE",
    "ClassificationError",
    "ClassificationErrorCode",
    "ClassificationProvenance",
    "FindingClassification",
    "FindingConfidence",
    "FindingSeverity",
    "classify_cwe",
    "classify_product_cwe",
]
