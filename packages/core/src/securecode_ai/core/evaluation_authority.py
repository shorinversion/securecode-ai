"""Integrity authority for Evaluation Lab execution and AppSec evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import asdict, dataclass
from typing import Final

from .evaluation_access import (
    EvaluationAccessAuthority,
    EvaluationAccessGrant,
    EvaluationCapability,
    require_access,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_EXECUTION_DOMAIN: Final = b"securecode-ai/evaluation-execution-authority/v1\x00"
_SECURITY_DOMAIN: Final = b"securecode-ai/evaluation-security-authority/v1\x00"
FIXED_MAX_CASES: Final = 100
FIXED_MAX_TOKENS: Final = 100_000
FIXED_MAX_ELAPSED_MS: Final = 60_000


class EvaluationAuthorityError(ValueError):
    def __init__(self) -> None:
        super().__init__("Evaluation evidence authority rejected the request")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class EvaluationObservedExecution:
    """Executor observation presented only to the trusted evidence authority."""

    run_id: str
    launch_evidence_sha256: str
    envelope_sha256: str
    passed_cases: int
    failed_cases: int
    error_cases: int
    observed_tokens: int
    observed_elapsed_ms: int
    result_sha256: str
    observed_case_ids: tuple[str, ...]
    network_accessed: bool
    credentials_accessed: bool
    source_disclosed: bool
    locked_expectations_accessed: bool

    def __post_init__(self) -> None:
        counts = (self.passed_cases, self.failed_cases, self.error_cases)
        if (
            not _identifier(self.run_id)
            or not _digest(self.launch_evidence_sha256)
            or not _digest(self.envelope_sha256)
            or any(type(value) is not int or value < 0 for value in counts)
            or sum(counts) < 1
            or type(self.observed_tokens) is not int
            or self.observed_tokens < 0
            or type(self.observed_elapsed_ms) is not int
            or self.observed_elapsed_ms < 0
            or not _digest(self.result_sha256)
            or type(self.observed_case_ids) is not tuple
            or len(self.observed_case_ids) != sum(counts)
            or tuple(sorted(set(self.observed_case_ids))) != self.observed_case_ids
            or any(not _identifier(value) for value in self.observed_case_ids)
            or any(
                type(value) is not bool
                for value in (
                    self.network_accessed,
                    self.credentials_accessed,
                    self.source_disclosed,
                    self.locked_expectations_accessed,
                )
            )
        ):
            raise EvaluationAuthorityError()


@dataclass(frozen=True, slots=True)
class EvaluationExecutionReceipt:
    authority_id: str
    actor_id: str
    access_grant_sha256: str
    run_id: str
    launch_evidence_sha256: str
    envelope_sha256: str
    passed_cases: int
    failed_cases: int
    error_cases: int
    observed_cases: int
    observed_tokens: int
    observed_elapsed_ms: int
    result_sha256: str
    observed_case_ids: tuple[str, ...]
    network_accessed: bool
    credentials_accessed: bool
    source_disclosed: bool
    locked_expectations_accessed: bool
    execution_receipt_sha256: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.authority_id)
            or not _identifier(self.actor_id)
            or not _digest(self.access_grant_sha256)
            or not _identifier(self.run_id)
            or not _digest(self.launch_evidence_sha256)
            or not _digest(self.envelope_sha256)
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.passed_cases,
                    self.failed_cases,
                    self.error_cases,
                    self.observed_cases,
                    self.observed_tokens,
                    self.observed_elapsed_ms,
                )
            )
            or self.observed_cases != self.passed_cases + self.failed_cases + self.error_cases
            or self.observed_cases < 1
            or not _digest(self.result_sha256)
            or type(self.observed_case_ids) is not tuple
            or len(self.observed_case_ids) != self.observed_cases
            or tuple(sorted(set(self.observed_case_ids))) != self.observed_case_ids
            or any(not _identifier(value) for value in self.observed_case_ids)
            or any(
                type(value) is not bool
                for value in (
                    self.network_accessed,
                    self.credentials_accessed,
                    self.source_disclosed,
                    self.locked_expectations_accessed,
                )
            )
            or not _digest(self.execution_receipt_sha256)
        ):
            raise EvaluationAuthorityError()


@dataclass(frozen=True, slots=True)
class EvaluationSecurityReceipt:
    authority_id: str
    actor_id: str
    access_grant_sha256: str
    reviewer_id: str
    run_id: str
    candidate_key: str
    candidate_content_sha256: str
    run_evidence_sha256: str
    approved: bool
    security_receipt_sha256: str

    def __post_init__(self) -> None:
        if (
            not all(
                _identifier(value)
                for value in (self.authority_id, self.reviewer_id, self.run_id, self.candidate_key)
            )
            or not _identifier(self.actor_id)
            or not _digest(self.access_grant_sha256)
            or not _digest(self.candidate_content_sha256)
            or not _digest(self.run_evidence_sha256)
            or type(self.approved) is not bool
            or not _digest(self.security_receipt_sha256)
        ):
            raise EvaluationAuthorityError()


class EvaluationEvidenceAuthority:
    """Issue and verify domain-separated receipts from trusted observations."""

    __slots__ = ("_authority_id", "_key", "_key_check")

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("EvaluationEvidenceAuthority is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, *, authority_id: str, signing_key: bytes) -> None:
        if not _identifier(authority_id) or type(signing_key) is not bytes or len(signing_key) < 32:
            raise EvaluationAuthorityError()
        self._authority_id = authority_id
        self._key = bytes(signing_key)
        self._key_check = hashlib.sha256(signing_key).digest()

    @property
    def authority_id(self) -> str:
        return self._authority_id

    def issue_execution(
        self,
        observation: EvaluationObservedExecution,
        *,
        access_authority: EvaluationAccessAuthority,
        access_grant: EvaluationAccessGrant,
        actor_id: str,
        capability: EvaluationCapability,
        candidate_key: str,
        dataset_id: str,
        dataset_sha256: str,
        expected_run_id: str,
        expected_launch_evidence_sha256: str,
        expected_envelope_sha256: str,
        expected_case_ids: tuple[str, ...],
    ) -> EvaluationExecutionReceipt:
        if not self._intact() or type(observation) is not EvaluationObservedExecution:
            raise EvaluationAuthorityError()
        try:
            verified_grant = require_access(
                access_authority,
                access_grant,
                capability=capability,
                actor_id=actor_id,
                candidate_key=candidate_key,
                dataset_id=dataset_id,
                dataset_sha256=dataset_sha256,
                run_id=expected_run_id,
            )
        except Exception:
            raise EvaluationAuthorityError() from None
        if (
            observation.run_id != expected_run_id
            or observation.launch_evidence_sha256 != expected_launch_evidence_sha256
            or observation.envelope_sha256 != expected_envelope_sha256
            or observation.observed_case_ids != expected_case_ids
        ):
            raise EvaluationAuthorityError()
        material: dict[str, object] = {
            "authority_id": self._authority_id,
            "actor_id": actor_id,
            "access_grant_sha256": verified_grant.grant_sha256,
            **asdict(observation),
            "observed_cases": observation.passed_cases
            + observation.failed_cases
            + observation.error_cases,
        }
        return EvaluationExecutionReceipt(
            authority_id=self._authority_id,
            actor_id=actor_id,
            access_grant_sha256=verified_grant.grant_sha256,
            run_id=observation.run_id,
            launch_evidence_sha256=observation.launch_evidence_sha256,
            envelope_sha256=observation.envelope_sha256,
            passed_cases=observation.passed_cases,
            failed_cases=observation.failed_cases,
            error_cases=observation.error_cases,
            observed_cases=(
                observation.passed_cases + observation.failed_cases + observation.error_cases
            ),
            observed_tokens=observation.observed_tokens,
            observed_elapsed_ms=observation.observed_elapsed_ms,
            result_sha256=observation.result_sha256,
            observed_case_ids=observation.observed_case_ids,
            network_accessed=observation.network_accessed,
            credentials_accessed=observation.credentials_accessed,
            source_disclosed=observation.source_disclosed,
            locked_expectations_accessed=observation.locked_expectations_accessed,
            execution_receipt_sha256=self._mac(_EXECUTION_DOMAIN, material),
        )

    def verify_execution(self, receipt: EvaluationExecutionReceipt) -> bool:
        return self.verify_and_copy_execution(receipt) is not None

    def verify_and_copy_execution(
        self, receipt: EvaluationExecutionReceipt
    ) -> EvaluationExecutionReceipt | None:
        if not self._intact() or type(receipt) is not EvaluationExecutionReceipt:
            return None
        try:
            copied = EvaluationExecutionReceipt(
                receipt.authority_id,
                receipt.actor_id,
                receipt.access_grant_sha256,
                receipt.run_id,
                receipt.launch_evidence_sha256,
                receipt.envelope_sha256,
                receipt.passed_cases,
                receipt.failed_cases,
                receipt.error_cases,
                receipt.observed_cases,
                receipt.observed_tokens,
                receipt.observed_elapsed_ms,
                receipt.result_sha256,
                tuple(receipt.observed_case_ids),
                receipt.network_accessed,
                receipt.credentials_accessed,
                receipt.source_disclosed,
                receipt.locked_expectations_accessed,
                receipt.execution_receipt_sha256,
            )
        except (EvaluationAuthorityError, AttributeError, TypeError):
            return None
        material = asdict(copied)
        supplied = material.pop("execution_receipt_sha256")
        if material.get("authority_id") != self._authority_id or not hmac.compare_digest(
            supplied, self._mac(_EXECUTION_DOMAIN, material)
        ):
            return None
        return copied

    def issue_security_approval(
        self,
        *,
        reviewer_id: str,
        run_id: str,
        candidate_key: str,
        candidate_content_sha256: str,
        run_evidence_sha256: str,
        approved: bool,
        access_authority: EvaluationAccessAuthority,
        access_grant: EvaluationAccessGrant,
        authoritative_execution: EvaluationExecutionReceipt,
    ) -> EvaluationSecurityReceipt:
        if not self._intact():
            raise EvaluationAuthorityError()
        execution = self.verify_and_copy_execution(authoritative_execution)
        try:
            verified_grant = require_access(
                access_authority,
                access_grant,
                capability=EvaluationCapability.REVIEW_PROMOTION,
                actor_id=reviewer_id,
                candidate_key=candidate_key,
                dataset_id=None,
                dataset_sha256=None,
                run_id=run_id,
            )
        except Exception:
            raise EvaluationAuthorityError() from None
        if (
            execution is None
            or execution.run_id != run_id
            or execution.actor_id == reviewer_id
            or (approved and (execution.failed_cases != 0 or execution.error_cases != 0))
        ):
            raise EvaluationAuthorityError()
        material: dict[str, object] = {
            "access_grant_sha256": verified_grant.grant_sha256,
            "approved": approved,
            "actor_id": reviewer_id,
            "authority_id": self._authority_id,
            "candidate_content_sha256": candidate_content_sha256,
            "candidate_key": candidate_key,
            "reviewer_id": reviewer_id,
            "run_evidence_sha256": run_evidence_sha256,
            "run_id": run_id,
        }
        return EvaluationSecurityReceipt(
            authority_id=self._authority_id,
            actor_id=reviewer_id,
            access_grant_sha256=verified_grant.grant_sha256,
            reviewer_id=reviewer_id,
            run_id=run_id,
            candidate_key=candidate_key,
            candidate_content_sha256=candidate_content_sha256,
            run_evidence_sha256=run_evidence_sha256,
            approved=approved,
            security_receipt_sha256=self._mac(_SECURITY_DOMAIN, material),
        )

    def verify_security(self, receipt: EvaluationSecurityReceipt) -> bool:
        return self.verify_and_copy_security(receipt) is not None

    def verify_and_copy_security(
        self, receipt: EvaluationSecurityReceipt
    ) -> EvaluationSecurityReceipt | None:
        if not self._intact() or type(receipt) is not EvaluationSecurityReceipt:
            return None
        try:
            copied = EvaluationSecurityReceipt(
                receipt.authority_id,
                receipt.actor_id,
                receipt.access_grant_sha256,
                receipt.reviewer_id,
                receipt.run_id,
                receipt.candidate_key,
                receipt.candidate_content_sha256,
                receipt.run_evidence_sha256,
                receipt.approved,
                receipt.security_receipt_sha256,
            )
        except (EvaluationAuthorityError, AttributeError, TypeError):
            return None
        material = asdict(copied)
        supplied = material.pop("security_receipt_sha256")
        if material.get("authority_id") != self._authority_id or not hmac.compare_digest(
            supplied, self._mac(_SECURITY_DOMAIN, material)
        ):
            return None
        return copied

    def _mac(self, domain: bytes, material: dict[str, object]) -> str:
        if not self._intact():
            raise EvaluationAuthorityError()
        encoded = json.dumps(
            material,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        return hmac.new(self._key, domain + encoded, hashlib.sha256).hexdigest()

    def _intact(self) -> bool:
        try:
            return (
                type(self) is EvaluationEvidenceAuthority
                and _identifier(self._authority_id)
                and type(self._key) is bytes
                and len(self._key) >= 32
                and hmac.compare_digest(hashlib.sha256(self._key).digest(), self._key_check)
            )
        except Exception:
            return False


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _digest(value: object) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


__all__ = [
    "FIXED_MAX_CASES",
    "FIXED_MAX_ELAPSED_MS",
    "FIXED_MAX_TOKENS",
    "EvaluationAuthorityError",
    "EvaluationEvidenceAuthority",
    "EvaluationExecutionReceipt",
    "EvaluationObservedExecution",
    "EvaluationSecurityReceipt",
]
