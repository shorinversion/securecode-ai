from __future__ import annotations

from dataclasses import replace

import pytest
from securecode_ai.core.classification import (
    DEFAULT_CLASSIFICATION_PROVENANCE,
    ClassificationError,
    ClassificationErrorCode,
    FindingClassification,
    FindingConfidence,
    FindingSeverity,
    classify_cwe,
)


def test_cwe89_mapping_is_deterministic_and_pre_calibration_unscored() -> None:
    first = classify_cwe("CWE-89")
    second = classify_cwe("CWE-89")

    assert first == second
    assert first.owasp_category == "A03:2021"
    assert first.severity is FindingSeverity.HIGH
    assert first.confidence is FindingConfidence.UNSCORED
    assert first.provenance is DEFAULT_CLASSIFICATION_PROVENANCE
    assert first.provenance.calibration_record_id is None
    assert first.provenance.confidence_basis == "PRE_CALIBRATION_UNSCORED"


@pytest.mark.parametrize("value", ["", "CWE-0", "cwe-89", "CWE-89\n", 89])
def test_invalid_cwe_is_fixed_non_echo_failure(value: object) -> None:
    with pytest.raises(ClassificationError) as captured:
        classify_cwe(value)  # type: ignore[arg-type]

    assert captured.value.code is ClassificationErrorCode.INPUT_INVALID
    assert str(captured.value) == "finding classification failed"
    assert repr(value) not in str(captured.value)


def test_valid_but_unsupported_cwe_fails_closed() -> None:
    with pytest.raises(ClassificationError) as captured:
        classify_cwe("CWE-79")

    assert captured.value.code is ClassificationErrorCode.UNSUPPORTED_CWE


def test_classification_rejects_tampered_hash_or_confidence() -> None:
    result = classify_cwe("CWE-89")
    with pytest.raises(ValueError, match="finding classification is invalid"):
        replace(result, classification_sha256="0" * 64)
    with pytest.raises(ValueError, match="finding classification is invalid"):
        FindingClassification(
            cwe_id=result.cwe_id,
            owasp_category=result.owasp_category,
            severity=result.severity,
            confidence="HIGH",  # type: ignore[arg-type]
            provenance=result.provenance,
            classification_sha256=result.classification_sha256,
        )


def test_provenance_is_pinned_and_contains_no_threshold() -> None:
    provenance = DEFAULT_CLASSIFICATION_PROVENANCE
    assert provenance.mapping_id == "securecode-core-mvp-classification"
    assert provenance.mapping_version == "1.0.0"
    assert len(provenance.mapping_sha256) == 64
    assert not hasattr(provenance, "threshold")
    assert not hasattr(provenance, "score")
