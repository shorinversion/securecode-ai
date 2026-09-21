"""Lineage governance, independent review, and split admission for synthetic cases."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

from .synthetic_cases import SyntheticCandidateStore, SyntheticCaseCandidate
from .synthetic_oracle import (
    SyntheticOracleDefinition,
    SyntheticOracleDisposition,
    SyntheticOracleReceipt,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/synthetic-lineage/v1\x00"


class SyntheticLineageErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    ORACLE_FAILED = "ORACLE_FAILED"
    REVIEW_DENIED = "REVIEW_DENIED"
    CROSS_SPLIT_LEAKAGE = "CROSS_SPLIT_LEAKAGE"
    DUPLICATE = "DUPLICATE"
    REPLAY_CONFLICT = "REPLAY_CONFLICT"


class SyntheticLineageError(ValueError):
    """Source-free synthetic lineage governance failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: SyntheticLineageErrorCode) -> None:
        if type(code) is not SyntheticLineageErrorCode:
            raise TypeError("synthetic lineage error code is invalid")
        self.code = code
        self.safe_message = "Synthetic lineage admission was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class SyntheticSplit(StrEnum):
    TRAIN = "TRAIN"
    DEV = "DEV"
    CALIBRATION = "CALIBRATION"
    LOCKED_TEST = "LOCKED_TEST"


class SyntheticAdmissionDisposition(StrEnum):
    ADMITTED = "ADMITTED"
    IDEMPOTENT = "IDEMPOTENT"


@dataclass(frozen=True, slots=True)
class SyntheticRootCauseReview:
    """Independent root-cause review. No source excerpt or expected output exists here."""

    case_id: str
    reviewer_id: str
    root_cause_sha256: str
    approved: bool

    def __post_init__(self) -> None:
        if (
            type(self.case_id) is not str
            or _ID.fullmatch(self.case_id) is None
            or type(self.reviewer_id) is not str
            or _ID.fullmatch(self.reviewer_id) is None
            or type(self.root_cause_sha256) is not str
            or _HASH.fullmatch(self.root_cause_sha256) is None
            or type(self.approved) is not bool
        ):
            raise SyntheticLineageError(SyntheticLineageErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class SyntheticAdmissionRequest:
    case_id: str
    split: SyntheticSplit
    oracle: SyntheticOracleDefinition
    oracle_receipt: SyntheticOracleReceipt
    root_cause_review: SyntheticRootCauseReview

    def __post_init__(self) -> None:
        if (
            type(self.case_id) is not str
            or _ID.fullmatch(self.case_id) is None
            or type(self.split) is not SyntheticSplit
            or type(self.oracle) is not SyntheticOracleDefinition
            or type(self.oracle_receipt) is not SyntheticOracleReceipt
            or type(self.root_cause_review) is not SyntheticRootCauseReview
        ):
            raise SyntheticLineageError(SyntheticLineageErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class SyntheticAdmissionReceipt:
    disposition: SyntheticAdmissionDisposition
    case_id: str
    split: SyntheticSplit
    source_sha256: str
    topology_sha256: str
    root_cause_sha256: str
    near_duplicate_group_sha256: str
    oracle_sha256: str
    review_sha256: str
    source_disclosed: bool = False


@dataclass(frozen=True, slots=True)
class SyntheticRegressionSummary:
    """Includes every failing case in the denominator."""

    passed_cases: int
    failed_cases: int
    denominator_cases: int

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not int or value < 0
                for value in (self.passed_cases, self.failed_cases)
            )
            or self.denominator_cases != self.passed_cases + self.failed_cases
            or self.denominator_cases < 1
        ):
            raise SyntheticLineageError(SyntheticLineageErrorCode.INVALID_REQUEST)


class SyntheticLineageGovernor:
    """Admit reviewed, oracle-validated candidates without cross-split leakage."""

    __slots__ = ("_admissions", "_candidate_store", "_groups", "_lock", "_sources")

    def __init__(self, candidate_store: SyntheticCandidateStore) -> None:
        if type(candidate_store) is not SyntheticCandidateStore:
            raise SyntheticLineageError(SyntheticLineageErrorCode.INVALID_REQUEST)
        self._candidate_store = candidate_store
        self._admissions: dict[str, SyntheticAdmissionReceipt] = {}
        self._groups: dict[tuple[str, str], SyntheticSplit] = {}
        self._sources: dict[str, str] = {}
        self._lock = RLock()

    def admit(self, request: SyntheticAdmissionRequest) -> SyntheticAdmissionReceipt:
        if type(request) is not SyntheticAdmissionRequest:
            raise SyntheticLineageError(SyntheticLineageErrorCode.INVALID_REQUEST)
        try:
            candidate = self._candidate_store.resolve(request.case_id)
        except Exception:
            raise SyntheticLineageError(SyntheticLineageErrorCode.INVALID_REQUEST) from None
        self._validate_evidence(candidate, request)
        receipt = _admission_receipt(candidate, request)
        with self._lock:
            existing = self._admissions.get(candidate.case_id)
            if existing is not None:
                if existing == receipt:
                    return SyntheticAdmissionReceipt(
                        SyntheticAdmissionDisposition.IDEMPOTENT,
                        existing.case_id,
                        existing.split,
                        existing.source_sha256,
                        existing.topology_sha256,
                        existing.root_cause_sha256,
                        existing.near_duplicate_group_sha256,
                        existing.oracle_sha256,
                        existing.review_sha256,
                    )
                raise SyntheticLineageError(SyntheticLineageErrorCode.REPLAY_CONFLICT)
            prior_case = self._sources.get(candidate.source_artifact.content_sha256)
            if prior_case is not None and prior_case != candidate.case_id:
                raise SyntheticLineageError(SyntheticLineageErrorCode.DUPLICATE)
            group = (candidate.root_cause_sha256, candidate.near_duplicate_group_sha256)
            existing_split = self._groups.get(group)
            if existing_split is not None and existing_split is not request.split:
                raise SyntheticLineageError(SyntheticLineageErrorCode.CROSS_SPLIT_LEAKAGE)
            self._sources[candidate.source_artifact.content_sha256] = candidate.case_id
            self._groups[group] = request.split
            self._admissions[candidate.case_id] = receipt
            return receipt

    @staticmethod
    def _validate_evidence(
        candidate: SyntheticCaseCandidate,
        request: SyntheticAdmissionRequest,
    ) -> None:
        review = request.root_cause_review
        oracle = request.oracle_receipt
        if (
            oracle.case_id != candidate.case_id
            or oracle.oracle_id != request.oracle.oracle_id
            or oracle.disposition is not SyntheticOracleDisposition.PASSED
        ):
            raise SyntheticLineageError(SyntheticLineageErrorCode.ORACLE_FAILED)
        if (
            review.case_id != candidate.case_id
            or review.reviewer_id == candidate.provenance.generator_id
            or review.root_cause_sha256 != candidate.root_cause_sha256
            or not review.approved
        ):
            raise SyntheticLineageError(SyntheticLineageErrorCode.REVIEW_DENIED)


def summarize_oracle_receipts(
    receipts: tuple[SyntheticOracleReceipt, ...],
) -> SyntheticRegressionSummary:
    if (
        type(receipts) is not tuple
        or not receipts
        or any(type(item) is not SyntheticOracleReceipt for item in receipts)
    ):
        raise SyntheticLineageError(SyntheticLineageErrorCode.INVALID_REQUEST)
    passed = sum(item.disposition is SyntheticOracleDisposition.PASSED for item in receipts)
    return SyntheticRegressionSummary(passed, len(receipts) - passed, len(receipts))


def _admission_receipt(
    candidate: SyntheticCaseCandidate,
    request: SyntheticAdmissionRequest,
) -> SyntheticAdmissionReceipt:
    return SyntheticAdmissionReceipt(
        SyntheticAdmissionDisposition.ADMITTED,
        candidate.case_id,
        request.split,
        candidate.source_artifact.content_sha256,
        candidate.topology_sha256,
        candidate.root_cause_sha256,
        candidate.near_duplicate_group_sha256,
        _hash(
            {
                "executable_sha256": request.oracle.executable_sha256,
                "oracle_id": request.oracle.oracle_id,
                "oracle_version": request.oracle.oracle_version,
                "profile_sha256": request.oracle.profile_sha256,
            }
        ),
        _hash(
            {
                "approved": request.root_cause_review.approved,
                "reviewer_id": request.root_cause_review.reviewer_id,
                "root_cause_sha256": request.root_cause_review.root_cause_sha256,
            }
        ),
    )


def _hash(material: dict[str, object]) -> str:
    return hashlib.sha256(
        _HASH_DOMAIN
        + json.dumps(
            material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "SyntheticAdmissionDisposition",
    "SyntheticAdmissionReceipt",
    "SyntheticAdmissionRequest",
    "SyntheticLineageError",
    "SyntheticLineageErrorCode",
    "SyntheticLineageGovernor",
    "SyntheticRegressionSummary",
    "SyntheticRootCauseReview",
    "SyntheticSplit",
    "summarize_oracle_receipts",
]
