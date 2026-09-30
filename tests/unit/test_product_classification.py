"""Closed product portfolio classification controls for P7.56."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace

import pytest
from securecode_ai.core.classification import (
    DEFAULT_CLASSIFICATION_PROVENANCE,
    PRODUCT_CLASSIFICATION_PROVENANCE,
    ClassificationError,
    ClassificationErrorCode,
    ClassificationProvenance,
    FindingConfidence,
    FindingSeverity,
    classify_cwe,
    classify_product_cwe,
)

_FIXED_CWE89_MAPPING_ROWS = [["CWE-89", "A03:2021", "HIGH"]]


def _fixed_sha256(value: object, *, sort_keys: bool = False) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=sort_keys,
        ).encode("ascii")
    ).hexdigest()


def _fixed_cwe89_provenance() -> dict[str, str | None]:
    return {
        "calibration_record_id": None,
        "confidence_basis": "PRE_CALIBRATION_UNSCORED",
        "mapping_id": "securecode-core-mvp-classification",
        "mapping_sha256": _fixed_sha256(_FIXED_CWE89_MAPPING_ROWS),
        "mapping_version": "1.0.0",
        "severity_basis": "RULE_CATALOG",
    }


def _fixed_cwe89_classification_sha256() -> str:
    return _fixed_sha256(
        {
            "confidence": "UNSCORED",
            "cwe_id": "CWE-89",
            "owasp_category": "A03:2021",
            "provenance": _fixed_cwe89_provenance(),
            "severity": "HIGH",
        },
        sort_keys=True,
    )


def test_product_mapping_keeps_historical_cwe89_result_byte_identical() -> None:
    historical = classify_cwe("CWE-89")
    product = classify_product_cwe("CWE-89")

    assert product == historical
    assert historical.provenance is DEFAULT_CLASSIFICATION_PROVENANCE
    assert asdict(historical.provenance) == _fixed_cwe89_provenance()
    assert historical.cwe_id == "CWE-89"
    assert historical.owasp_category == "A03:2021"
    assert historical.severity is FindingSeverity.HIGH
    assert historical.confidence is FindingConfidence.UNSCORED
    assert historical.classification_sha256 == _fixed_cwe89_classification_sha256()


@pytest.mark.parametrize(
    ("cwe_id", "owasp_category"),
    [
        ("CWE-78", "A03:2021"),
        ("CWE-22", "A01:2021"),
        ("CWE-918", "A10:2021"),
        ("CWE-862", "A01:2021"),
    ],
)
def test_product_mapping_is_closed_versioned_rule_policy(cwe_id: str, owasp_category: str) -> None:
    result = classify_product_cwe(cwe_id)

    assert result.cwe_id == cwe_id
    assert result.owasp_category == owasp_category
    assert result.severity is FindingSeverity.HIGH
    assert result.confidence is FindingConfidence.UNSCORED
    assert result.provenance is PRODUCT_CLASSIFICATION_PROVENANCE
    assert result.provenance.mapping_id == "securecode-product-portfolio-classification"
    assert result.provenance.mapping_version == "1.3.0"
    assert result.provenance.severity_basis == "RULE_CATALOG"
    assert result.provenance.confidence_basis == "PRE_CALIBRATION_UNSCORED"
    assert result.provenance.calibration_record_id is None


@pytest.mark.parametrize("cwe_id", ["CWE-190", "CWE-89 ", "", 918])
def test_product_mapping_rejects_unknown_or_invalid_cwes_without_echo(cwe_id: object) -> None:
    with pytest.raises(ClassificationError) as captured:
        classify_product_cwe(cwe_id)  # type: ignore[arg-type]

    expected = (
        ClassificationErrorCode.UNSUPPORTED_CWE
        if cwe_id == "CWE-190"
        else ClassificationErrorCode.INPUT_INVALID
    )
    assert captured.value.code is expected
    assert str(captured.value) == "finding classification failed"


def test_product_provenance_rejects_unknown_id_and_mapping_hash_tampering() -> None:
    with pytest.raises(ValueError, match="classification provenance is invalid"):
        replace(PRODUCT_CLASSIFICATION_PROVENANCE, mapping_sha256="0" * 64)
    with pytest.raises(ValueError, match="classification provenance is invalid"):
        ClassificationProvenance(
            mapping_id="foreign-classification",
            mapping_version="1.0.0",
            mapping_sha256="a" * 64,
            severity_basis="RULE_CATALOG",
            confidence_basis="PRE_CALIBRATION_UNSCORED",
        )


def test_legacy_provenance_constructor_retains_its_syntactic_compatibility() -> None:
    legacy = ClassificationProvenance(
        mapping_id="securecode-core-mvp-classification",
        mapping_version="9.9.9",
        mapping_sha256="a" * 64,
        severity_basis="RULE_CATALOG",
        confidence_basis="PRE_CALIBRATION_UNSCORED",
    )

    assert legacy.mapping_version == "9.9.9"
    assert legacy.mapping_sha256 == "a" * 64


@pytest.mark.parametrize(
    ("cwe_id", "owasp_category"),
    [
        ("CWE-434", "A04:2021"),
        ("CWE-287", "A07:2021"),
        ("CWE-319", "A02:2021"),
        ("CWE-863", "A01:2021"),
        ("CWE-917", "A03:2021"),
        ("CWE-829", "A08:2021"),
    ],
)
def test_owasp_mapping_covers_model_native_cwes(cwe_id: str, owasp_category: str) -> None:
    # Model-native discovery may report CWEs without a deterministic detector; every
    # classified CWE must still carry its OWASP Top 10 2021 category.
    assert classify_product_cwe(cwe_id).owasp_category == owasp_category


def test_every_classified_cwe_is_reportable_by_the_model() -> None:
    from securecode_ai.adapters.product_rule_catalogue import PRODUCT_RULE_CWE
    from securecode_ai.core.classification import PRODUCT_CLASSIFIED_CWES

    assert len(PRODUCT_CLASSIFIED_CWES) > 100
    for cwe_id in PRODUCT_CLASSIFIED_CWES:
        assert PRODUCT_RULE_CWE["model-" + cwe_id.lower()] == cwe_id
        classify_product_cwe(cwe_id)
