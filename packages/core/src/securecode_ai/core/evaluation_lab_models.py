"""Immutable public contracts for the governed Evaluation Lab."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .evaluation_access import EvaluationAccessGrant, EvaluationRole
from .evaluation_authority import (
    FIXED_MAX_CASES,
    FIXED_MAX_ELAPSED_MS,
    FIXED_MAX_TOKENS,
    EvaluationSecurityReceipt,
)
from .evaluation_candidate_store import EvaluationCandidateHandle

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")


class EvaluationLabErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    ACCESS_DENIED = "ACCESS_DENIED"
    LINEAGE_CONFLICT = "LINEAGE_CONFLICT"
    REPLAY_CONFLICT = "REPLAY_CONFLICT"
    PROMOTION_DENIED = "PROMOTION_DENIED"


class EvaluationLabError(ValueError):
    __slots__ = ("code", "safe_message")

    def __init__(self, code: EvaluationLabErrorCode) -> None:
        if type(code) is not EvaluationLabErrorCode:
            raise TypeError("Evaluation Lab error code is invalid")
        self.code = code
        self.safe_message = "Evaluation Lab request was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class EvaluationPartition(StrEnum):
    TRAIN = "TRAIN"
    DEV = "DEV"
    CALIBRATION = "CALIBRATION"
    LOCKED_TEST = "LOCKED_TEST"


class EvaluationLaunchDisposition(StrEnum):
    CREATED = "CREATED"
    IDEMPOTENT = "IDEMPOTENT"


class EvaluationRunDisposition(StrEnum):
    RECORDED = "RECORDED"
    IDEMPOTENT = "IDEMPOTENT"


class EvaluationPromotionDisposition(StrEnum):
    PROMOTED = "PROMOTED"
    IDEMPOTENT = "IDEMPOTENT"


@dataclass(frozen=True, slots=True)
class EvaluationDatasetRef:
    dataset_id: str
    partition: EvaluationPartition
    dataset_sha256: str
    lineage_sha256: str
    case_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.dataset_id) is not str
            or _ID.fullmatch(self.dataset_id) is None
            or type(self.partition) is not EvaluationPartition
            or any(
                type(value) is not str or _HASH.fullmatch(value) is None
                for value in (self.dataset_sha256, self.lineage_sha256)
            )
            or type(self.case_ids) is not tuple
            or not self.case_ids
            or len(self.case_ids) > FIXED_MAX_CASES
            or tuple(sorted(set(self.case_ids))) != self.case_ids
            or any(
                type(value) is not str or _ID.fullmatch(value) is None for value in self.case_ids
            )
        ):
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class EvaluationPinSet:
    profile_sha256: str
    prompt_sha256: str
    tool_sha256: str
    model_sha256: str
    policy_sha256: str

    def __post_init__(self) -> None:
        if any(
            type(value) is not str or _HASH.fullmatch(value) is None
            for value in (
                self.profile_sha256,
                self.prompt_sha256,
                self.tool_sha256,
                self.model_sha256,
                self.policy_sha256,
            )
        ):
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class EvaluationBudget:
    max_cases: int = FIXED_MAX_CASES
    max_tokens: int = FIXED_MAX_TOKENS
    max_elapsed_ms: int = FIXED_MAX_ELAPSED_MS

    def __post_init__(self) -> None:
        if (
            type(self.max_cases) is not int
            or type(self.max_tokens) is not int
            or type(self.max_elapsed_ms) is not int
            or self.max_cases != FIXED_MAX_CASES
            or self.max_tokens != FIXED_MAX_TOKENS
            or self.max_elapsed_ms != FIXED_MAX_ELAPSED_MS
        ):
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class EvaluationSandboxEnvelope:
    network_disabled: bool
    credentials_disabled: bool
    read_only_candidate: bool
    isolated_scratch: bool
    locked_expectations_exposed_to_candidate: bool
    budget: EvaluationBudget

    def __post_init__(self) -> None:
        if (
            self.network_disabled is not True
            or self.credentials_disabled is not True
            or self.read_only_candidate is not True
            or self.isolated_scratch is not True
            or self.locked_expectations_exposed_to_candidate is not False
            or type(self.budget) is not EvaluationBudget
        ):
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class EvaluationLaunchRequest:
    role: EvaluationRole
    actor_id: str
    candidate_key: str
    dataset: EvaluationDatasetRef
    pins: EvaluationPinSet
    access_grant: EvaluationAccessGrant

    def __post_init__(self) -> None:
        if (
            type(self.role) is not EvaluationRole
            or type(self.actor_id) is not str
            or _ID.fullmatch(self.actor_id) is None
            or type(self.candidate_key) is not str
            or _ID.fullmatch(self.candidate_key) is None
            or type(self.dataset) is not EvaluationDatasetRef
            or type(self.pins) is not EvaluationPinSet
            or type(self.access_grant) is not EvaluationAccessGrant
        ):
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class EvaluationLaunchReceipt:
    disposition: EvaluationLaunchDisposition
    run_id: str
    candidate: EvaluationCandidateHandle
    dataset_sha256: str
    partition: EvaluationPartition
    pins: EvaluationPinSet
    envelope: EvaluationSandboxEnvelope
    launch_evidence_sha256: str
    source_disclosed: bool = False
    locked_expectations_disclosed: bool = False


@dataclass(frozen=True, slots=True)
class EvaluationRunReceipt:
    disposition: EvaluationRunDisposition
    run_id: str
    candidate_key: str
    partition: EvaluationPartition
    passed_cases: int
    failed_cases: int
    error_cases: int
    denominator_cases: int
    observed_tokens: int
    observed_elapsed_ms: int
    result_sha256: str
    observed_case_ids: tuple[str, ...]
    execution_receipt_sha256: str
    run_evidence_sha256: str
    source_disclosed: bool = False
    locked_expectations_disclosed: bool = False


@dataclass(frozen=True, slots=True)
class EvaluationPromotionRequest:
    role: EvaluationRole
    actor_id: str
    reviewer_id: str
    candidate_key: str
    held_out_run_id: str
    security_receipt: EvaluationSecurityReceipt
    access_grant: EvaluationAccessGrant

    def __post_init__(self) -> None:
        if (
            type(self.role) is not EvaluationRole
            or type(self.actor_id) is not str
            or _ID.fullmatch(self.actor_id) is None
            or type(self.reviewer_id) is not str
            or _ID.fullmatch(self.reviewer_id) is None
            or any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (self.candidate_key, self.held_out_run_id)
            )
            or type(self.security_receipt) is not EvaluationSecurityReceipt
            or type(self.access_grant) is not EvaluationAccessGrant
        ):
            raise EvaluationLabError(EvaluationLabErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class EvaluationPromotionReceipt:
    disposition: EvaluationPromotionDisposition
    candidate_key: str
    held_out_run_id: str
    reviewer_id: str
    security_receipt_sha256: str
    source_disclosed: bool = False
    locked_expectations_disclosed: bool = False


__all__ = [
    "EvaluationBudget",
    "EvaluationDatasetRef",
    "EvaluationLabError",
    "EvaluationLabErrorCode",
    "EvaluationLaunchDisposition",
    "EvaluationLaunchReceipt",
    "EvaluationLaunchRequest",
    "EvaluationPartition",
    "EvaluationPinSet",
    "EvaluationPromotionDisposition",
    "EvaluationPromotionReceipt",
    "EvaluationPromotionRequest",
    "EvaluationRunDisposition",
    "EvaluationRunReceipt",
    "EvaluationSandboxEnvelope",
]
