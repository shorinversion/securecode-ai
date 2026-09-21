"""Parent-side bounded sandbox validation promotion controls."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from .finding_validation import FindingValidationDisposition, FindingValidationRecord

_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/validation-promotion/v1\x00"


class ValidationPromotionError(ValueError):
    """Safe parent promotion error without source or sandbox output."""

    def __init__(self) -> None:
        super().__init__("Validation promotion was rejected")
        self.__cause__ = None
        self.__context__ = None


class ValidationPromotionDisposition(StrEnum):
    PROMOTED = "PROMOTED"
    NO_PROMOTION = "NO_PROMOTION"


@dataclass(frozen=True, slots=True)
class BoundedSandboxPromotionEvidence:
    profile_sha256: str
    attestation_sha256: str
    result_sha256: str
    teardown_sha256: str
    network_attempts: int
    live_workloads: int
    reusable_volumes: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not str or _HASH.fullmatch(value) is None
            for value in (
                self.profile_sha256,
                self.attestation_sha256,
                self.result_sha256,
                self.teardown_sha256,
            )
        ) or any(
            type(value) is not int or value < 0
            for value in (
                self.network_attempts,
                self.live_workloads,
                self.reusable_volumes,
            )
        ):
            raise ValidationPromotionError()


@dataclass(frozen=True, slots=True)
class ValidationPromotionReceipt:
    disposition: ValidationPromotionDisposition
    finding_id: str
    fingerprint_sha256: str
    validation_sha256: str
    sandbox_evidence_sha256: str
    source_disclosed: bool = False


class ValidationPromotionRegistry:
    """Promote only exact confirmed findings with complete clean sandbox evidence."""

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[tuple[str, str], ValidationPromotionReceipt] = {}

    def promote(
        self,
        record: FindingValidationRecord,
        sandbox: BoundedSandboxPromotionEvidence,
    ) -> ValidationPromotionReceipt:
        if (
            type(record) is not FindingValidationRecord
            or type(sandbox) is not BoundedSandboxPromotionEvidence
        ):
            raise ValidationPromotionError()
        clean = (
            record.disposition is FindingValidationDisposition.CONFIRMED
            and sandbox.network_attempts == 0
            and sandbox.live_workloads == 0
            and sandbox.reusable_volumes == 0
        )
        sandbox_hash = _hash(
            {
                "attestation": sandbox.attestation_sha256,
                "profile": sandbox.profile_sha256,
                "result": sandbox.result_sha256,
                "teardown": sandbox.teardown_sha256,
            }
        )
        receipt = ValidationPromotionReceipt(
            ValidationPromotionDisposition.PROMOTED
            if clean
            else ValidationPromotionDisposition.NO_PROMOTION,
            record.product.finding_id,
            record.product.fingerprint_sha256,
            record.canonical_sha256,
            sandbox_hash,
        )
        key = (receipt.finding_id, receipt.fingerprint_sha256)
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                self._records[key] = receipt
                return receipt
            if existing == receipt:
                return existing
        raise ValidationPromotionError()


def _hash(value: dict[str, str]) -> str:
    return hashlib.sha256(
        _HASH_DOMAIN + json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


__all__ = [
    "BoundedSandboxPromotionEvidence",
    "ValidationPromotionDisposition",
    "ValidationPromotionError",
    "ValidationPromotionReceipt",
    "ValidationPromotionRegistry",
]
