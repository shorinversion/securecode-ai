"""Independent immutable validation records for product findings."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/finding-validation/v1\x00"


class FindingValidationError(ValueError):
    """Source-free finding validation failure."""

    def __init__(self) -> None:
        super().__init__("Finding validation was rejected")
        self.__cause__ = None
        self.__context__ = None


class FindingValidationDisposition(StrEnum):
    CONFIRMED = "CONFIRMED"
    NEEDS_VALIDATION = "NEEDS_VALIDATION"
    REJECTED = "REJECTED"


class AttackControlClass(StrEnum):
    LLM_MISUSE = "LLM_MISUSE"
    TENANT_LIFECYCLE = "TENANT_LIFECYCLE"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"
    LOCAL_IPC = "LOCAL_IPC"
    SANDBOX = "SANDBOX"


@dataclass(frozen=True, slots=True)
class FindingProductSnapshot:
    finding_id: str
    fingerprint_sha256: str
    source_sha256: str
    execution_identity_sha256: str
    verdict: str
    severity: str
    confidence: str
    producer_id: str
    producer_auth_sha256: str

    def __post_init__(self) -> None:
        if any(
            type(value) is not str or _ID.fullmatch(value) is None
            for value in (
                self.finding_id,
                self.verdict,
                self.severity,
                self.confidence,
                self.producer_id,
            )
        ) or any(
            type(value) is not str or _HASH.fullmatch(value) is None
            for value in (
                self.fingerprint_sha256,
                self.source_sha256,
                self.execution_identity_sha256,
                self.producer_auth_sha256,
            )
        ):
            raise FindingValidationError()


@dataclass(frozen=True, slots=True)
class AuthenticatedVerifier:
    verifier_id: str
    verifier_auth_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.verifier_id) is not str
            or _ID.fullmatch(self.verifier_id) is None
            or type(self.verifier_auth_sha256) is not str
            or _HASH.fullmatch(self.verifier_auth_sha256) is None
        ):
            raise FindingValidationError()


@dataclass(frozen=True, slots=True)
class FindingValidationObservation:
    finding_id: str
    fingerprint_sha256: str
    source_sha256: str
    execution_identity_sha256: str
    verdict: str
    severity: str
    confidence: str
    attack_class: AttackControlClass
    reproduced: bool
    controls_complete: bool
    result_sha256: str

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.finding_id,
                    self.verdict,
                    self.severity,
                    self.confidence,
                )
            )
            or any(
                type(value) is not str or _HASH.fullmatch(value) is None
                for value in (
                    self.fingerprint_sha256,
                    self.source_sha256,
                    self.execution_identity_sha256,
                    self.result_sha256,
                )
            )
            or type(self.attack_class) is not AttackControlClass
            or type(self.reproduced) is not bool
            or type(self.controls_complete) is not bool
        ):
            raise FindingValidationError()


@dataclass(frozen=True, slots=True)
class FindingValidationRequest:
    product: FindingProductSnapshot
    verifier: AuthenticatedVerifier
    observation: FindingValidationObservation

    def __post_init__(self) -> None:
        if (
            type(self.product) is not FindingProductSnapshot
            or type(self.verifier) is not AuthenticatedVerifier
            or type(self.observation) is not FindingValidationObservation
        ):
            raise FindingValidationError()


@dataclass(frozen=True, slots=True)
class FindingValidationRecord:
    disposition: FindingValidationDisposition
    product: FindingProductSnapshot
    verifier_id: str
    verifier_auth_sha256: str
    attack_class: AttackControlClass
    result_sha256: str
    canonical_sha256: str
    source_disclosed: bool = False


class FindingValidationRegistry:
    """Record independent validation without mutating the original finding product."""

    __slots__ = ("_lock", "_records")

    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[tuple[str, str], FindingValidationRecord] = {}

    def validate(self, request: FindingValidationRequest) -> FindingValidationRecord:
        if type(request) is not FindingValidationRequest:
            raise FindingValidationError()
        product, verifier, observed = request.product, request.verifier, request.observation
        if verifier.verifier_id == product.producer_id or not _matches(product, observed):
            raise FindingValidationError()
        disposition = (
            FindingValidationDisposition.CONFIRMED
            if observed.reproduced and observed.controls_complete
            else FindingValidationDisposition.REJECTED
            if observed.controls_complete
            else FindingValidationDisposition.NEEDS_VALIDATION
        )
        record = _record(disposition, product, verifier, observed)
        key = (product.finding_id, product.fingerprint_sha256)
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                self._records[key] = record
                return record
            if existing == record:
                return existing
        raise FindingValidationError()


def canonical_validation_json(record: FindingValidationRecord) -> str:
    if type(record) is not FindingValidationRecord:
        raise FindingValidationError()
    data = {
        "attack_class": record.attack_class.value,
        "canonical_sha256": record.canonical_sha256,
        "disposition": record.disposition.value,
        "finding_id": record.product.finding_id,
        "fingerprint_sha256": record.product.fingerprint_sha256,
        "result_sha256": record.result_sha256,
        "source_disclosed": False,
        "verifier_id": record.verifier_id,
    }
    return (
        json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    )


def _matches(product: FindingProductSnapshot, observed: FindingValidationObservation) -> bool:
    return (
        product.finding_id == observed.finding_id
        and product.fingerprint_sha256 == observed.fingerprint_sha256
        and product.source_sha256 == observed.source_sha256
        and product.execution_identity_sha256 == observed.execution_identity_sha256
        and product.verdict == observed.verdict
        and product.severity == observed.severity
        and product.confidence == observed.confidence
    )


def _record(
    disposition: FindingValidationDisposition,
    product: FindingProductSnapshot,
    verifier: AuthenticatedVerifier,
    observed: FindingValidationObservation,
) -> FindingValidationRecord:
    material = {
        "attack_class": observed.attack_class.value,
        "disposition": disposition.value,
        "fingerprint": product.fingerprint_sha256,
        "finding": product.finding_id,
        "result": observed.result_sha256,
        "verifier": verifier.verifier_auth_sha256,
    }
    return FindingValidationRecord(
        disposition,
        product,
        verifier.verifier_id,
        verifier.verifier_auth_sha256,
        observed.attack_class,
        observed.result_sha256,
        hashlib.sha256(
            _HASH_DOMAIN
            + json.dumps(material, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest(),
    )


__all__ = [
    "AttackControlClass",
    "AuthenticatedVerifier",
    "FindingProductSnapshot",
    "FindingValidationDisposition",
    "FindingValidationError",
    "FindingValidationObservation",
    "FindingValidationRecord",
    "FindingValidationRegistry",
    "FindingValidationRequest",
    "canonical_validation_json",
]
