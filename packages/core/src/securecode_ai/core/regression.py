"""Deterministic metadata contracts for security regression oracles.

This module describes PoC, strengthened PoC+ and safe-control observations.  It
does not execute repository code or retain test inputs, outputs or commands.
Execution belongs to the sandbox and validation layers.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from .root_cause import RootCauseEvidenceRefs, RootCauseRecord
from .security_invariants import SecurityInvariant, evaluate_security_invariant

_SCHEMA_VERSION: Final = "1.0.0"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/security-regression/v1\x00"
_MAX_CASES: Final = 64
_MAX_PAYLOAD_BYTES: Final = 1_048_576


class RegressionErrorCode(StrEnum):
    """Closed errors which never include repository-controlled values."""

    REQUEST_INVALID = "REQUEST_INVALID"
    DESCRIPTOR_INVALID = "DESCRIPTOR_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"


class RegressionContractError(ValueError):
    """Safe boundary error for malformed regression metadata."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: RegressionErrorCode) -> None:
        if type(code) is not RegressionErrorCode:
            raise TypeError("regression error code is invalid")
        self.code = code
        self.safe_message = "security regression contract validation failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class RegressionCaseKind(StrEnum):
    POC = "POC"
    POC_PLUS = "POC_PLUS"
    SAFE_CONTROL = "SAFE_CONTROL"


class RegressionExpectedOutcome(StrEnum):
    VIOLATION_OBSERVED = "VIOLATION_OBSERVED"
    NO_VIOLATION = "NO_VIOLATION"


class RegressionObservationStatus(StrEnum):
    OBSERVED = "OBSERVED"
    ORACLE_ERROR = "ORACLE_ERROR"
    MALFORMED = "MALFORMED"


class RegressionRevisionRole(StrEnum):
    VULNERABLE = "VULNERABLE"
    FIXED_CANDIDATE = "FIXED_CANDIDATE"


class RegressionDisposition(StrEnum):
    VULNERABLE_FAILURE_DEMONSTRATED = "VULNERABLE_FAILURE_DEMONSTRATED"
    FIXED_CANDIDATE_PASSED = "FIXED_CANDIDATE_PASSED"
    SAFE_CONTROL_FAILED = "SAFE_CONTROL_FAILED"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True, slots=True)
class RegressionCase:
    """A bounded test descriptor containing hashes, never executable payloads."""

    case_id: str
    kind: RegressionCaseKind
    input_sha256: str
    input_size_bytes: int
    oracle_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.case_id) is not str
            or _ID.fullmatch(self.case_id) is None
            or type(self.kind) is not RegressionCaseKind
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in (self.input_sha256, self.oracle_sha256)
            )
            or type(self.input_size_bytes) is not int
            or not 0 <= self.input_size_bytes <= _MAX_PAYLOAD_BYTES
        ):
            raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)


@dataclass(frozen=True, slots=True)
class SecurityRegressionDescriptor:
    """Canonical regression set bound to one root cause and invariant."""

    descriptor_id: str
    finding_id: str
    tenant_id: str
    repository_id: str
    vulnerable_head_sha: str
    root_cause_id: str
    root_cause_fingerprint: str
    invariant_id: str
    invariant_version: str
    invariant_sha256: str
    cases: tuple[RegressionCase, ...]
    descriptor_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.descriptor_id,
                    self.finding_id,
                    self.tenant_id,
                    self.repository_id,
                    self.root_cause_id,
                    self.invariant_id,
                )
            )
            or type(self.invariant_version) is not str
            or _ID.fullmatch(self.invariant_version) is None
            or _COMMIT_SHA.fullmatch(self.vulnerable_head_sha) is None
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in (
                    self.root_cause_fingerprint,
                    self.invariant_sha256,
                    self.descriptor_sha256,
                )
            )
            or type(self.cases) is not tuple
            or not 3 <= len(self.cases) <= _MAX_CASES
            or any(type(case) is not RegressionCase for case in self.cases)
            or tuple(sorted(self.cases, key=lambda case: case.case_id)) != self.cases
            or len({case.case_id for case in self.cases}) != len(self.cases)
            or {case.kind for case in self.cases} != set(RegressionCaseKind)
            or self.descriptor_sha256 != _descriptor_hash(self)
        ):
            raise RegressionContractError(RegressionErrorCode.DESCRIPTOR_INVALID)


@dataclass(frozen=True, slots=True)
class RegressionCaseResult:
    """One sanitized oracle observation."""

    case_id: str
    status: RegressionObservationStatus
    observed_outcome: RegressionExpectedOutcome | None
    output_sha256: str | None
    output_size_bytes: int

    def __post_init__(self) -> None:
        observed = self.status is RegressionObservationStatus.OBSERVED
        if (
            type(self.case_id) is not str
            or _ID.fullmatch(self.case_id) is None
            or type(self.status) is not RegressionObservationStatus
            or (
                self.observed_outcome is not None
                and type(self.observed_outcome) is not RegressionExpectedOutcome
            )
            or (self.output_sha256 is not None and _SHA256.fullmatch(self.output_sha256) is None)
            or type(self.output_size_bytes) is not int
            or not 0 <= self.output_size_bytes <= _MAX_PAYLOAD_BYTES
            or observed != (self.observed_outcome is not None and self.output_sha256 is not None)
            or (not observed and self.output_size_bytes != 0)
        ):
            raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)


@dataclass(frozen=True, slots=True)
class RegressionResult:
    """Fail-closed aggregate; generated tests are never approval evidence alone."""

    descriptor_id: str
    descriptor_sha256: str
    revision_role: RegressionRevisionRole
    evaluated_head_sha: str
    disposition: RegressionDisposition
    case_result_hashes: tuple[str, ...]
    approval_eligible: bool
    result_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or _ID.fullmatch(self.descriptor_id) is None
            or _SHA256.fullmatch(self.descriptor_sha256) is None
            or type(self.revision_role) is not RegressionRevisionRole
            or _COMMIT_SHA.fullmatch(self.evaluated_head_sha) is None
            or type(self.disposition) is not RegressionDisposition
            or type(self.case_result_hashes) is not tuple
            or len(self.case_result_hashes) < 1
            or any(_SHA256.fullmatch(value) is None for value in self.case_result_hashes)
            or tuple(sorted(self.case_result_hashes)) != self.case_result_hashes
            or type(self.approval_eligible) is not bool
            or self.approval_eligible
            or _SHA256.fullmatch(self.result_sha256) is None
            or self.result_sha256 != _result_hash(self)
        ):
            raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)


def build_security_regression_descriptor(
    root_cause: RootCauseRecord,
    invariant: SecurityInvariant,
    cases: tuple[RegressionCase, ...],
) -> SecurityRegressionDescriptor:
    """Bind a canonical PoC/PoC+/safe-control set to exact immutable identity."""

    root = _copy_root(root_cause)
    checked_invariant = _copy_invariant(invariant)
    if not evaluate_security_invariant(checked_invariant, root).satisfied:
        raise RegressionContractError(RegressionErrorCode.IDENTITY_MISMATCH)
    canonical_cases = _copy_cases(cases)
    preimage = _unchecked_descriptor(
        descriptor_id="regression-placeholder",
        finding_id=root.finding_id,
        tenant_id=root.tenant_id,
        repository_id=root.repository_id,
        vulnerable_head_sha=root.head_sha,
        root_cause_id=root.record_id,
        root_cause_fingerprint=root.root_cause_fingerprint,
        invariant_id=checked_invariant.invariant_id,
        invariant_version=checked_invariant.invariant_version,
        invariant_sha256=checked_invariant.invariant_sha256,
        cases=canonical_cases,
        descriptor_sha256="0" * 64,
        schema_version=_SCHEMA_VERSION,
    )
    digest = _descriptor_hash(preimage)
    final_preimage = _unchecked_descriptor(
        **{
            **_descriptor_values(preimage),
            "descriptor_id": f"regression-{digest}",
            "descriptor_sha256": "0" * 64,
        }
    )
    final_digest = _descriptor_hash(final_preimage)
    return SecurityRegressionDescriptor(
        descriptor_id=final_preimage.descriptor_id,
        finding_id=final_preimage.finding_id,
        tenant_id=final_preimage.tenant_id,
        repository_id=final_preimage.repository_id,
        vulnerable_head_sha=final_preimage.vulnerable_head_sha,
        root_cause_id=final_preimage.root_cause_id,
        root_cause_fingerprint=final_preimage.root_cause_fingerprint,
        invariant_id=final_preimage.invariant_id,
        invariant_version=final_preimage.invariant_version,
        invariant_sha256=final_preimage.invariant_sha256,
        cases=final_preimage.cases,
        descriptor_sha256=final_digest,
        schema_version=final_preimage.schema_version,
    )


def evaluate_regression(
    descriptor: SecurityRegressionDescriptor,
    root_cause: RootCauseRecord,
    invariant: SecurityInvariant,
    *,
    revision_role: RegressionRevisionRole,
    evaluated_head_sha: str,
    observations: tuple[RegressionCaseResult, ...],
) -> RegressionResult:
    """Reduce sandbox observations without executing or interpreting payload bytes."""

    checked = _copy_descriptor(descriptor)
    root = _copy_root(root_cause)
    checked_invariant = _copy_invariant(invariant)
    if (
        type(revision_role) is not RegressionRevisionRole
        or _COMMIT_SHA.fullmatch(evaluated_head_sha) is None
    ):
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)
    if not _identity_matches(checked, root, checked_invariant):
        raise RegressionContractError(RegressionErrorCode.IDENTITY_MISMATCH)
    if revision_role is RegressionRevisionRole.VULNERABLE:
        if evaluated_head_sha != checked.vulnerable_head_sha:
            raise RegressionContractError(RegressionErrorCode.IDENTITY_MISMATCH)
    elif evaluated_head_sha == checked.vulnerable_head_sha:
        raise RegressionContractError(RegressionErrorCode.IDENTITY_MISMATCH)

    results = _copy_results(observations)
    by_id = {result.case_id: result for result in results}
    cases = {case.case_id: case for case in checked.cases}
    disposition = RegressionDisposition.INDETERMINATE
    if set(by_id) == set(cases) and all(
        result.status is RegressionObservationStatus.OBSERVED for result in results
    ):
        safe_failed = any(
            case.kind is RegressionCaseKind.SAFE_CONTROL
            and by_id[case.case_id].observed_outcome is not RegressionExpectedOutcome.NO_VIOLATION
            for case in checked.cases
        )
        if safe_failed:
            disposition = RegressionDisposition.SAFE_CONTROL_FAILED
        elif revision_role is RegressionRevisionRole.VULNERABLE:
            poc = next(case for case in checked.cases if case.kind is RegressionCaseKind.POC)
            if by_id[poc.case_id].observed_outcome is RegressionExpectedOutcome.VIOLATION_OBSERVED:
                disposition = RegressionDisposition.VULNERABLE_FAILURE_DEMONSTRATED
        elif all(
            by_id[case.case_id].observed_outcome is RegressionExpectedOutcome.NO_VIOLATION
            for case in checked.cases
        ):
            disposition = RegressionDisposition.FIXED_CANDIDATE_PASSED

    hashes = tuple(sorted(_case_result_hash(result) for result in results))
    preimage = _unchecked_result(
        descriptor_id=checked.descriptor_id,
        descriptor_sha256=checked.descriptor_sha256,
        revision_role=revision_role,
        evaluated_head_sha=evaluated_head_sha,
        disposition=disposition,
        case_result_hashes=hashes,
        approval_eligible=False,
        result_sha256="0" * 64,
        schema_version=_SCHEMA_VERSION,
    )
    return RegressionResult(
        descriptor_id=preimage.descriptor_id,
        descriptor_sha256=preimage.descriptor_sha256,
        revision_role=preimage.revision_role,
        evaluated_head_sha=preimage.evaluated_head_sha,
        disposition=preimage.disposition,
        case_result_hashes=preimage.case_result_hashes,
        approval_eligible=False,
        result_sha256=_result_hash(preimage),
    )


def _identity_matches(
    value: SecurityRegressionDescriptor, root: RootCauseRecord, invariant: SecurityInvariant
) -> bool:
    return (
        value.finding_id == root.finding_id == invariant.finding_id
        and value.tenant_id == root.tenant_id == invariant.tenant_id
        and value.repository_id == root.repository_id == invariant.repository_id
        and value.vulnerable_head_sha == root.head_sha == invariant.head_sha
        and value.root_cause_id == root.record_id == invariant.root_cause_id
        and value.root_cause_fingerprint
        == root.root_cause_fingerprint
        == invariant.root_cause_fingerprint
        and value.invariant_id == invariant.invariant_id
        and value.invariant_version == invariant.invariant_version
        and value.invariant_sha256 == invariant.invariant_sha256
        and evaluate_security_invariant(invariant, root).satisfied
    )


def _copy_root(value: RootCauseRecord) -> RootCauseRecord:
    if type(value) is not RootCauseRecord:
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)
    try:
        return RootCauseRecord(
            record_id=value.record_id,
            schema_version=value.schema_version,
            finding_id=value.finding_id,
            candidate_id=value.candidate_id,
            candidate_version=value.candidate_version,
            tenant_id=value.tenant_id,
            repository_id=value.repository_id,
            head_sha=value.head_sha,
            root_cause_fingerprint=value.root_cause_fingerprint,
            evidence_graph_id=value.evidence_graph_id,
            evidence_graph_sha256=value.evidence_graph_sha256,
            evidence=RootCauseEvidenceRefs(
                value.evidence.source_evidence_id,
                value.evidence.propagation_evidence_id,
                value.evidence.sink_evidence_id,
            ),
            command_operation_evidence=tuple(value.command_operation_evidence),
        )
    except (AttributeError, TypeError, ValueError):
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID) from None


def _copy_invariant(value: SecurityInvariant) -> SecurityInvariant:
    if type(value) is not SecurityInvariant:
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)
    try:
        return SecurityInvariant(
            **{name: getattr(value, name) for name in SecurityInvariant.__dataclass_fields__}
        )
    except (AttributeError, TypeError, ValueError):
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID) from None


def _copy_cases(values: tuple[RegressionCase, ...]) -> tuple[RegressionCase, ...]:
    if type(values) is not tuple:
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)
    try:
        copied = tuple(
            RegressionCase(
                case.case_id,
                case.kind,
                case.input_sha256,
                case.input_size_bytes,
                case.oracle_sha256,
            )
            for case in values
        )
        return tuple(sorted(copied, key=lambda case: case.case_id))
    except (AttributeError, TypeError, ValueError):
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID) from None


def _copy_results(values: tuple[RegressionCaseResult, ...]) -> tuple[RegressionCaseResult, ...]:
    if type(values) is not tuple or not values or len(values) > _MAX_CASES:
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)
    try:
        copied = tuple(
            RegressionCaseResult(
                value.case_id,
                value.status,
                value.observed_outcome,
                value.output_sha256,
                value.output_size_bytes,
            )
            for value in values
        )
    except (AttributeError, TypeError, ValueError):
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID) from None
    if len({value.case_id for value in copied}) != len(copied):
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)
    return tuple(sorted(copied, key=lambda value: value.case_id))


def _copy_descriptor(value: SecurityRegressionDescriptor) -> SecurityRegressionDescriptor:
    if type(value) is not SecurityRegressionDescriptor:
        raise RegressionContractError(RegressionErrorCode.REQUEST_INVALID)
    try:
        return SecurityRegressionDescriptor(
            **{
                **{
                    name: getattr(value, name)
                    for name in SecurityRegressionDescriptor.__dataclass_fields__
                },
                "cases": _copy_cases(value.cases),
            }
        )
    except (AttributeError, TypeError, ValueError):
        raise RegressionContractError(RegressionErrorCode.DESCRIPTOR_INVALID) from None


def _descriptor_values(value: SecurityRegressionDescriptor) -> dict[str, object]:
    return {
        name: getattr(value, name) for name in SecurityRegressionDescriptor.__dataclass_fields__
    }


def _descriptor_material(value: SecurityRegressionDescriptor) -> dict[str, object]:
    return {
        "cases": [
            {
                "case_id": case.case_id,
                "input_sha256": case.input_sha256,
                "input_size_bytes": case.input_size_bytes,
                "kind": case.kind.value,
                "oracle_sha256": case.oracle_sha256,
            }
            for case in value.cases
        ],
        "descriptor_id": value.descriptor_id,
        "finding_id": value.finding_id,
        "invariant_id": value.invariant_id,
        "invariant_sha256": value.invariant_sha256,
        "invariant_version": value.invariant_version,
        "repository_id": value.repository_id,
        "root_cause_fingerprint": value.root_cause_fingerprint,
        "root_cause_id": value.root_cause_id,
        "schema_version": value.schema_version,
        "tenant_id": value.tenant_id,
        "vulnerable_head_sha": value.vulnerable_head_sha,
    }


def _descriptor_hash(value: SecurityRegressionDescriptor) -> str:
    return _hash(_descriptor_material(value))


def _case_result_hash(value: RegressionCaseResult) -> str:
    return _hash(
        {
            "case_id": value.case_id,
            "observed_outcome": value.observed_outcome.value if value.observed_outcome else None,
            "output_sha256": value.output_sha256,
            "output_size_bytes": value.output_size_bytes,
            "status": value.status.value,
        }
    )


def _result_hash(value: RegressionResult) -> str:
    return _hash(
        {
            "approval_eligible": value.approval_eligible,
            "case_result_hashes": list(value.case_result_hashes),
            "descriptor_id": value.descriptor_id,
            "descriptor_sha256": value.descriptor_sha256,
            "disposition": value.disposition.value,
            "evaluated_head_sha": value.evaluated_head_sha,
            "revision_role": value.revision_role.value,
            "schema_version": value.schema_version,
        }
    )


def _hash(material: dict[str, object]) -> str:
    return hashlib.sha256(
        _HASH_DOMAIN
        + json.dumps(
            material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()


def _unchecked_descriptor(**values: object) -> SecurityRegressionDescriptor:
    value = object.__new__(SecurityRegressionDescriptor)
    for name, item in values.items():
        object.__setattr__(value, name, item)
    return value


def _unchecked_result(**values: object) -> RegressionResult:
    value = object.__new__(RegressionResult)
    for name, item in values.items():
        object.__setattr__(value, name, item)
    return value


__all__ = [
    "RegressionCase",
    "RegressionCaseKind",
    "RegressionCaseResult",
    "RegressionContractError",
    "RegressionDisposition",
    "RegressionErrorCode",
    "RegressionExpectedOutcome",
    "RegressionObservationStatus",
    "RegressionResult",
    "RegressionRevisionRole",
    "SecurityRegressionDescriptor",
    "build_security_regression_descriptor",
    "evaluate_regression",
]
