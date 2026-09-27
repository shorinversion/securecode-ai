"""Offline, metadata-only CI worker result adapter.

The worker receives a completed ``AuditRun`` rather than source, credentials,
an SCM client, or a transport. It revalidates that admitted Core receipt before
deriving the accepted CLI machine exit code.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Final

from securecode_ai.contracts import (
    AuditRun,
    AuditRunOutcome,
    CliErrorCode,
    CliExitCode,
    exit_code_for_audit_outcome,
)

CI_WORKER_RECEIPT_SCHEMA_VERSION: Final = "securecode.ci-worker.v1"
_OPAQUE_ID_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_LOWER_SHA256_PATTERN: Final = re.compile(r"^[0-9a-f]{64}$")
_LOWER_COMMIT_SHA_PATTERN: Final = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True, slots=True)
class CiWorkerRequest:
    """One completed, admitted Core receipt for an air-gapped CI invocation."""

    audit_run: AuditRun

    def __post_init__(self) -> None:
        if type(self.audit_run) is not AuditRun:
            raise TypeError("audit_run must be an AuditRun")


@dataclass(frozen=True, slots=True)
class CiWorkerReceipt:
    """Canonical output metadata with no source or credential fields."""

    run_id: str
    execution_identity_hash: str
    revision: str
    audit_outcome: AuditRunOutcome
    exit_code: CliExitCode
    network_attempts: int
    scm_write_attempts: int
    receipt_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.run_id) is not str
            or _OPAQUE_ID_PATTERN.fullmatch(self.run_id) is None
            or type(self.execution_identity_hash) is not str
            or _LOWER_SHA256_PATTERN.fullmatch(self.execution_identity_hash) is None
            or type(self.revision) is not str
            or _LOWER_COMMIT_SHA_PATTERN.fullmatch(self.revision) is None
            or type(self.audit_outcome) is not AuditRunOutcome
            or type(self.exit_code) is not CliExitCode
            or self.exit_code is not exit_code_for_audit_outcome(self.audit_outcome)
            or type(self.network_attempts) is not int
            or self.network_attempts != 0
            or type(self.scm_write_attempts) is not int
            or self.scm_write_attempts != 0
            or type(self.receipt_sha256) is not str
            or _LOWER_SHA256_PATTERN.fullmatch(self.receipt_sha256) is None
            or self.receipt_sha256
            != _receipt_sha256(
                run_id=self.run_id,
                execution_identity_hash=self.execution_identity_hash,
                revision=self.revision,
                audit_outcome=self.audit_outcome,
                exit_code=self.exit_code,
            )
        ):
            raise ValueError("CI worker receipt is invalid")

    def metadata(self) -> dict[str, object]:
        """Return the closed, source-free receipt document."""

        return {
            "audit_outcome": self.audit_outcome.value,
            "execution_identity_hash": self.execution_identity_hash,
            "exit_code": int(self.exit_code),
            "network_attempts": self.network_attempts,
            "receipt_sha256": self.receipt_sha256,
            "revision": self.revision,
            "run_id": self.run_id,
            "schema_version": CI_WORKER_RECEIPT_SCHEMA_VERSION,
            "scm_write_attempts": self.scm_write_attempts,
        }


@dataclass(frozen=True, slots=True)
class CiWorkerResult:
    """One machine result with admitted metadata or a closed usage error."""

    exit_code: CliExitCode
    receipt: CiWorkerReceipt | None
    error_code: CliErrorCode | None

    def __post_init__(self) -> None:
        if type(self.exit_code) is not CliExitCode:
            raise TypeError("exit_code must be a CliExitCode")
        if self.receipt is None:
            if (
                self.error_code is not CliErrorCode.INVALID_USAGE
                or self.exit_code is not CliExitCode.INVALID_USAGE_OR_CONFIG
            ):
                raise ValueError("invalid worker input requires the closed usage result")
        elif (
            type(self.receipt) is not CiWorkerReceipt
            or self.error_code is not None
            or self.exit_code is not self.receipt.exit_code
        ):
            raise ValueError("admitted worker result is invalid")

    @property
    def audit_outcome(self) -> AuditRunOutcome | None:
        return None if self.receipt is None else self.receipt.audit_outcome

    def document(self) -> dict[str, object]:
        """Return one canonical machine result without echoing raw input."""

        if self.receipt is None:
            error_code = self.error_code
            if error_code is None:
                raise ValueError("invalid worker result is missing its error code")
            return {
                "error_code": error_code.value,
                "exit_code": int(self.exit_code),
                "schema_version": CI_WORKER_RECEIPT_SCHEMA_VERSION,
            }
        return self.receipt.metadata()


class OfflineCiWorker:
    """Offline entrypoint with no provider, SCM, backend, or network interface."""

    __slots__ = ()

    def run(self, request: object) -> CiWorkerResult:
        try:
            admitted = _admit(request)
        except (AttributeError, OverflowError, RecursionError, TypeError, ValueError):
            return CiWorkerResult(
                exit_code=CliExitCode.INVALID_USAGE_OR_CONFIG,
                receipt=None,
                error_code=CliErrorCode.INVALID_USAGE,
            )

        outcome = admitted.audit_outcome
        exit_code = exit_code_for_audit_outcome(outcome)
        revision = admitted.execution_identity.repository_revision.head_sha
        identity_hash = admitted.execution_identity.execution_identity_hash
        receipt = CiWorkerReceipt(
            run_id=admitted.run_id,
            execution_identity_hash=identity_hash,
            revision=revision,
            audit_outcome=outcome,
            exit_code=exit_code,
            network_attempts=0,
            scm_write_attempts=0,
            receipt_sha256=_receipt_sha256(
                run_id=admitted.run_id,
                execution_identity_hash=identity_hash,
                revision=revision,
                audit_outcome=outcome,
                exit_code=exit_code,
            ),
        )
        return CiWorkerResult(exit_code=exit_code, receipt=receipt, error_code=None)


def run_ci_worker(request: object) -> CiWorkerResult:
    """Run one bounded air-gapped worker invocation."""

    return OfflineCiWorker().run(request)


def canonical_ci_worker_result_json(result: CiWorkerResult) -> str:
    """Serialize one result with stable key order and a terminal newline."""

    if type(result) is not CiWorkerResult:
        raise TypeError("result must be a CiWorkerResult")
    return (
        json.dumps(
            result.document(),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def _admit(request: object) -> AuditRun:
    if type(request) is not CiWorkerRequest:
        raise TypeError("request must be a CiWorkerRequest")
    try:
        return AuditRun.model_validate_json(request.audit_run.model_dump_json())
    except (OverflowError, RecursionError, TypeError, ValueError):
        raise TypeError("request audit run is invalid") from None


def _receipt_sha256(
    *,
    run_id: str,
    execution_identity_hash: str,
    revision: str,
    audit_outcome: AuditRunOutcome,
    exit_code: CliExitCode,
) -> str:
    document = {
        "audit_outcome": audit_outcome.value,
        "execution_identity_hash": execution_identity_hash,
        "exit_code": int(exit_code),
        "network_attempts": 0,
        "revision": revision,
        "run_id": run_id,
        "schema_version": CI_WORKER_RECEIPT_SCHEMA_VERSION,
        "scm_write_attempts": 0,
    }
    return hashlib.sha256(
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


__all__ = [
    "CI_WORKER_RECEIPT_SCHEMA_VERSION",
    "CiWorkerReceipt",
    "CiWorkerRequest",
    "CiWorkerResult",
    "OfflineCiWorker",
    "canonical_ci_worker_result_json",
    "run_ci_worker",
]
