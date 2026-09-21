"""P8.14 independent finding validation and parent promotion controls."""

from __future__ import annotations

from typing import cast

import pytest
from securecode_ai.core.finding_validation import (
    AttackControlClass,
    AuthenticatedVerifier,
    FindingProductSnapshot,
    FindingValidationDisposition,
    FindingValidationError,
    FindingValidationObservation,
    FindingValidationRecord,
    FindingValidationRegistry,
    FindingValidationRequest,
    canonical_validation_json,
)
from securecode_ai.core.validation_promotion import (
    BoundedSandboxPromotionEvidence,
    ValidationPromotionDisposition,
    ValidationPromotionError,
    ValidationPromotionRegistry,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64


def _product() -> FindingProductSnapshot:
    return FindingProductSnapshot(
        "finding-1", HASH_A, HASH_B, HASH_C, "CONFIRMED", "HIGH", "HIGH", "producer-1", HASH_D
    )


def _request(*, reproduced: bool = True, controls: bool = True) -> FindingValidationRequest:
    product = _product()
    return FindingValidationRequest(
        product,
        AuthenticatedVerifier("verifier-1", HASH_E),
        FindingValidationObservation(
            "finding-1",
            HASH_A,
            HASH_B,
            HASH_C,
            "CONFIRMED",
            "HIGH",
            "HIGH",
            AttackControlClass.SANDBOX,
            reproduced,
            controls,
            HASH_E,
        ),
    )


def test_independent_verifier_binds_exact_product_fields_and_canonical_receipt_is_source_free() -> (
    None
):
    record = FindingValidationRegistry().validate(_request())
    document = canonical_validation_json(record)

    assert record.disposition is FindingValidationDisposition.CONFIRMED
    assert record.product == _product()
    assert record.source_disclosed is False
    assert "source_disclosed" in document
    assert "producer-1" not in document


def test_missing_or_forged_provenance_and_self_verification_are_rejected() -> None:
    product = _product()
    forged = FindingValidationObservation(
        "finding-1",
        HASH_A,
        HASH_D,
        HASH_C,
        "CONFIRMED",
        "HIGH",
        "HIGH",
        AttackControlClass.LOCAL_IPC,
        True,
        True,
        HASH_E,
    )
    with pytest.raises(FindingValidationError):
        FindingValidationRegistry().validate(
            FindingValidationRequest(product, AuthenticatedVerifier("verifier-1", HASH_E), forged)
        )
    with pytest.raises(FindingValidationError):
        FindingValidationRegistry().validate(
            FindingValidationRequest(
                product, AuthenticatedVerifier("producer-1", HASH_E), _request().observation
            )
        )


def test_needs_validation_and_rejected_preserve_original_product_without_mutation() -> None:
    needs = FindingValidationRegistry().validate(_request(reproduced=False, controls=False))
    rejected = FindingValidationRegistry().validate(_request(reproduced=False, controls=True))

    assert needs.disposition is FindingValidationDisposition.NEEDS_VALIDATION
    assert rejected.disposition is FindingValidationDisposition.REJECTED
    assert needs.product.verdict == rejected.product.verdict == "CONFIRMED"


def test_parent_promotion_requires_confirmed_and_clean_complete_sandbox_hash_chain() -> None:
    record = FindingValidationRegistry().validate(_request())
    sandbox = BoundedSandboxPromotionEvidence(HASH_A, HASH_B, HASH_C, HASH_D, 0, 0, 0)
    promoted = ValidationPromotionRegistry().promote(record, sandbox)

    assert promoted.disposition is ValidationPromotionDisposition.PROMOTED
    assert promoted.source_disclosed is False

    failed = ValidationPromotionRegistry().promote(
        record,
        BoundedSandboxPromotionEvidence(HASH_A, HASH_B, HASH_C, HASH_D, 1, 0, 0),
    )
    assert failed.disposition is ValidationPromotionDisposition.NO_PROMOTION

    with pytest.raises(ValidationPromotionError):
        ValidationPromotionRegistry().promote(cast(FindingValidationRecord, object()), sandbox)
