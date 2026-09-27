"""Fail-closed, metadata-only security invariant evaluation.

An invariant is a deterministic assertion about one already-localized finding.
This module deliberately does not inspect source, execute a regression test, or
interpret a model response.  It binds the assertion to the immutable
``RootCauseRecord`` produced by :mod:`root_cause`.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import CommandOperationEvidence, FindingCase

from .root_cause import RootCauseEvidenceRefs, RootCauseRecord

_SCHEMA_VERSION: Final = "1.0.0"
_INVARIANT_VERSION: Final = "1.0.0"
_PARAMETER_BINDING_ID: Final = "CWE-89-PARAMETER-BINDING"
_COMMAND_SAFETY_ID: Final = "CWE-78-COMMAND-SAFETY"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_MAX_EVIDENCE_IDS: Final = 16
_HASH_DOMAIN: Final = b"securecode-ai/security-invariant/v1\x00"


class SecurityInvariantErrorCode(StrEnum):
    """Closed request failures; values never contain caller data."""

    REQUEST_INVALID = "REQUEST_INVALID"
    INVARIANT_INVALID = "INVARIANT_INVALID"
    ROOT_CAUSE_INVALID = "ROOT_CAUSE_INVALID"


class SecurityInvariantError(ValueError):
    """Safe boundary error for malformed request objects."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: SecurityInvariantErrorCode) -> None:
        if type(code) is not SecurityInvariantErrorCode:
            raise TypeError("security invariant error code is invalid")
        self.code = code
        self.safe_message = "security invariant contract validation failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class InvariantEvaluationReason(StrEnum):
    """Closed outcomes for deterministic invariant evaluation."""

    SATISFIED = "SATISFIED"
    UNKNOWN_INVARIANT = "UNKNOWN_INVARIANT"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    INCOMPLETE_ROOT_CAUSE = "INCOMPLETE_ROOT_CAUSE"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    UNSUPPORTED = "UNSUPPORTED"


@dataclass(frozen=True, slots=True)
class SecurityInvariant:
    """Immutable property assertion bound to one exact finding/root cause."""

    invariant_id: str
    invariant_version: str
    property_name: str
    finding_id: str
    root_cause_id: str
    candidate_id: str
    candidate_version: int
    tenant_id: str
    repository_id: str
    head_sha: str
    root_cause_fingerprint: str
    evidence_graph_id: str
    evidence_graph_sha256: str
    required_evidence_ids: tuple[str, ...]
    invariant_sha256: str
    schema_version: str = _SCHEMA_VERSION
    command_operation_evidence: tuple[CommandOperationEvidence, ...] = ()

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or self.invariant_version != _INVARIANT_VERSION
            or type(self.property_name) is not str
            or not self.property_name
            or len(self.property_name) > 256
            or any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.invariant_id,
                    self.finding_id,
                    self.root_cause_id,
                    self.candidate_id,
                    self.tenant_id,
                    self.repository_id,
                    self.evidence_graph_id,
                )
            )
            or type(self.candidate_version) is not int
            or self.candidate_version < 1
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in (
                    self.root_cause_fingerprint,
                    self.evidence_graph_sha256,
                    self.invariant_sha256,
                )
            )
            or type(self.required_evidence_ids) is not tuple
            or not 1 <= len(self.required_evidence_ids) <= _MAX_EVIDENCE_IDS
            or any(_ID.fullmatch(value) is None for value in self.required_evidence_ids)
            or tuple(sorted(self.required_evidence_ids)) != self.required_evidence_ids
            or len(set(self.required_evidence_ids)) != len(self.required_evidence_ids)
            or type(self.command_operation_evidence) is not tuple
            or any(
                type(value) is not CommandOperationEvidence
                for value in self.command_operation_evidence
            )
            or (
                self.invariant_id == _PARAMETER_BINDING_ID
                and (
                    self.property_name != "database driver parameter binding"
                    or self.command_operation_evidence
                )
            )
            or (
                self.invariant_id == _COMMAND_SAFETY_ID
                and (
                    self.property_name != "command execution operation safety"
                    or len(self.command_operation_evidence) != 1
                    or any(
                        value.source_evidence_id is None
                        or value.sink_evidence_id is None
                        or value.flow_evidence_id is None
                        for value in self.command_operation_evidence
                    )
                )
            )
            or self.invariant_id not in {_PARAMETER_BINDING_ID, _COMMAND_SAFETY_ID}
            or self.invariant_sha256 != _invariant_hash(self)
        ):
            raise SecurityInvariantError(SecurityInvariantErrorCode.INVARIANT_INVALID)


@dataclass(frozen=True, slots=True)
class InvariantEvaluation:
    """Deterministic, source-free result of checking one invariant."""

    invariant_id: str
    invariant_version: str
    finding_id: str
    root_cause_id: str
    tenant_id: str
    repository_id: str
    head_sha: str
    evidence_ids: tuple[str, ...]
    satisfied: bool
    reason: InvariantEvaluationReason
    evaluation_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.invariant_id,
                    self.finding_id,
                    self.root_cause_id,
                    self.tenant_id,
                    self.repository_id,
                )
            )
            or self.invariant_version != _INVARIANT_VERSION
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or type(self.evidence_ids) is not tuple
            or tuple(sorted(self.evidence_ids)) != self.evidence_ids
            or len(set(self.evidence_ids)) != len(self.evidence_ids)
            or any(_ID.fullmatch(value) is None for value in self.evidence_ids)
            or type(self.satisfied) is not bool
            or type(self.reason) is not InvariantEvaluationReason
            or self.satisfied != (self.reason is InvariantEvaluationReason.SATISFIED)
            or _SHA256.fullmatch(self.evaluation_sha256) is None
            or self.evaluation_sha256 != _evaluation_hash(self)
        ):
            raise SecurityInvariantError(SecurityInvariantErrorCode.REQUEST_INVALID)


def build_security_invariant(
    finding: FindingCase, root_cause: RootCauseRecord
) -> SecurityInvariant:
    """Build the pinned CWE-89 parameter-binding invariant for a finding."""

    checked_finding = _copy_finding(finding)
    checked_root = _copy_root_cause(root_cause)
    revision = checked_finding.repository_revision
    if (
        checked_finding.finding_id != checked_root.finding_id
        or checked_finding.candidate_id != checked_root.candidate_id
        or checked_finding.candidate_version != checked_root.candidate_version
        or checked_finding.root_cause_fingerprint != checked_root.root_cause_fingerprint
        or revision.tenant_id != checked_root.tenant_id
        or revision.repository_id != checked_root.repository_id
        or revision.head_sha != checked_root.head_sha
    ):
        raise SecurityInvariantError(SecurityInvariantErrorCode.REQUEST_INVALID)
    evidence_ids = tuple(
        sorted(
            (
                checked_root.evidence.source_evidence_id,
                checked_root.evidence.propagation_evidence_id,
                checked_root.evidence.sink_evidence_id,
            )
        )
    )
    if checked_finding.cwe_id == "CWE-89":
        invariant_id = _PARAMETER_BINDING_ID
        property_name = "database driver parameter binding"
        command_operation_evidence: tuple[CommandOperationEvidence, ...] = ()
    elif checked_finding.cwe_id == "CWE-78" and len(checked_root.command_operation_evidence) == 1:
        invariant_id = _COMMAND_SAFETY_ID
        property_name = "command execution operation safety"
        command_operation_evidence = checked_root.command_operation_evidence
    else:
        raise SecurityInvariantError(SecurityInvariantErrorCode.INVARIANT_INVALID)
    value = _unchecked_invariant(
        invariant_id=invariant_id,
        invariant_version=_INVARIANT_VERSION,
        property_name=property_name,
        finding_id=checked_finding.finding_id,
        root_cause_id=checked_root.record_id,
        candidate_id=checked_root.candidate_id,
        candidate_version=checked_root.candidate_version,
        tenant_id=checked_root.tenant_id,
        repository_id=checked_root.repository_id,
        head_sha=checked_root.head_sha,
        root_cause_fingerprint=checked_root.root_cause_fingerprint,
        evidence_graph_id=checked_root.evidence_graph_id,
        evidence_graph_sha256=checked_root.evidence_graph_sha256,
        required_evidence_ids=evidence_ids,
        invariant_sha256="0" * 64,
        schema_version=_SCHEMA_VERSION,
        command_operation_evidence=command_operation_evidence,
    )
    return _with_invariant_hash(value)


def evaluate_security_invariant(
    invariant: SecurityInvariant,
    root_cause: RootCauseRecord,
    finding: FindingCase | None = None,
) -> InvariantEvaluation:
    """Evaluate an invariant without source access; unknown/failed is unsatisfied."""

    checked_invariant = _copy_invariant(invariant)
    checked_root = _copy_root_cause(root_cause)
    checked_finding = _copy_finding(finding) if finding is not None else None
    reason = InvariantEvaluationReason.SATISFIED
    if checked_invariant.invariant_id not in {_PARAMETER_BINDING_ID, _COMMAND_SAFETY_ID}:
        reason = InvariantEvaluationReason.UNKNOWN_INVARIANT
    elif (
        checked_finding is not None
        and not _finding_matches_invariant(checked_finding, checked_invariant)
    ) or (
        checked_root.record_id != checked_invariant.root_cause_id
        or checked_root.finding_id != checked_invariant.finding_id
        or checked_root.candidate_id != checked_invariant.candidate_id
        or checked_root.candidate_version != checked_invariant.candidate_version
        or checked_root.tenant_id != checked_invariant.tenant_id
        or checked_root.repository_id != checked_invariant.repository_id
        or checked_root.head_sha != checked_invariant.head_sha
        or checked_root.root_cause_fingerprint != checked_invariant.root_cause_fingerprint
        or checked_root.evidence_graph_id != checked_invariant.evidence_graph_id
        or checked_root.evidence_graph_sha256 != checked_invariant.evidence_graph_sha256
    ):
        reason = InvariantEvaluationReason.IDENTITY_MISMATCH
    elif (
        tuple(
            sorted(
                (
                    checked_root.evidence.source_evidence_id,
                    checked_root.evidence.propagation_evidence_id,
                    checked_root.evidence.sink_evidence_id,
                )
            )
        )
        != checked_invariant.required_evidence_ids
    ):
        reason = InvariantEvaluationReason.MISSING_EVIDENCE
    elif checked_invariant.invariant_id == _COMMAND_SAFETY_ID and (
        checked_root.command_operation_evidence != checked_invariant.command_operation_evidence
        or checked_finding is not None
        and checked_finding.command_operation_evidence
        != checked_invariant.command_operation_evidence
    ):
        reason = InvariantEvaluationReason.CONFLICTING_EVIDENCE
    return _evaluation(checked_invariant, reason)


def _finding_matches_invariant(
    finding: FindingCase,
    invariant: SecurityInvariant,
) -> bool:
    """Require the optional finding witness to carry the full invariant identity.

    Matching only ``finding_id`` and HEAD is insufficient because a producer
    can reuse an identifier while changing the candidate, repository scope, or
    EvidenceGraph binding.  An invariant evaluation that accepts such a
    witness would make the wrong finding appear independently validated.
    """

    revision = finding.repository_revision
    return (
        finding.finding_id == invariant.finding_id
        and finding.candidate_id == invariant.candidate_id
        and finding.candidate_version == invariant.candidate_version
        and finding.root_cause_fingerprint == invariant.root_cause_fingerprint
        and revision.tenant_id == invariant.tenant_id
        and revision.repository_id == invariant.repository_id
        and revision.head_sha == invariant.head_sha
        and finding.evidence_graph_ref.tenant_id == invariant.tenant_id
        and finding.evidence_graph_ref.content_id == invariant.evidence_graph_id
        and finding.evidence_graph_ref.content_sha256 == invariant.evidence_graph_sha256
        and set(invariant.required_evidence_ids).issubset(set(finding.evidence_ids))
    )


def _copy_finding(value: FindingCase) -> FindingCase:
    if type(value) is not FindingCase:
        raise SecurityInvariantError(SecurityInvariantErrorCode.REQUEST_INVALID)
    try:
        return FindingCase.model_validate(value.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError):
        raise SecurityInvariantError(SecurityInvariantErrorCode.REQUEST_INVALID) from None


def _copy_root_cause(value: RootCauseRecord) -> RootCauseRecord:
    if type(value) is not RootCauseRecord:
        raise SecurityInvariantError(SecurityInvariantErrorCode.ROOT_CAUSE_INVALID)
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
                source_evidence_id=value.evidence.source_evidence_id,
                propagation_evidence_id=value.evidence.propagation_evidence_id,
                sink_evidence_id=value.evidence.sink_evidence_id,
            ),
            command_operation_evidence=tuple(value.command_operation_evidence),
        )
    except (AttributeError, TypeError, ValueError):
        raise SecurityInvariantError(SecurityInvariantErrorCode.ROOT_CAUSE_INVALID) from None


def _copy_invariant(value: SecurityInvariant) -> SecurityInvariant:
    if type(value) is not SecurityInvariant:
        raise SecurityInvariantError(SecurityInvariantErrorCode.REQUEST_INVALID)
    try:
        return SecurityInvariant(
            invariant_id=value.invariant_id,
            invariant_version=value.invariant_version,
            property_name=value.property_name,
            finding_id=value.finding_id,
            root_cause_id=value.root_cause_id,
            candidate_id=value.candidate_id,
            candidate_version=value.candidate_version,
            tenant_id=value.tenant_id,
            repository_id=value.repository_id,
            head_sha=value.head_sha,
            root_cause_fingerprint=value.root_cause_fingerprint,
            evidence_graph_id=value.evidence_graph_id,
            evidence_graph_sha256=value.evidence_graph_sha256,
            required_evidence_ids=tuple(value.required_evidence_ids),
            invariant_sha256=value.invariant_sha256,
            schema_version=value.schema_version,
            command_operation_evidence=tuple(value.command_operation_evidence),
        )
    except (AttributeError, TypeError, ValueError):
        raise SecurityInvariantError(SecurityInvariantErrorCode.INVARIANT_INVALID) from None


def _invariant_material(value: SecurityInvariant) -> dict[str, object]:
    material: dict[str, object] = {
        "candidate_id": value.candidate_id,
        "candidate_version": value.candidate_version,
        "evidence_graph_id": value.evidence_graph_id,
        "evidence_graph_sha256": value.evidence_graph_sha256,
        "finding_id": value.finding_id,
        "head_sha": value.head_sha,
        "invariant_id": value.invariant_id,
        "invariant_version": value.invariant_version,
        "property_name": value.property_name,
        "repository_id": value.repository_id,
        "required_evidence_ids": list(value.required_evidence_ids),
        "root_cause_fingerprint": value.root_cause_fingerprint,
        "root_cause_id": value.root_cause_id,
        "schema_version": value.schema_version,
        "tenant_id": value.tenant_id,
    }
    if value.command_operation_evidence:
        material["command_operation_evidence"] = [
            item.model_dump(mode="json") for item in value.command_operation_evidence
        ]
    return material


def _invariant_hash(value: SecurityInvariant) -> str:
    return hashlib.sha256(
        _HASH_DOMAIN
        + json.dumps(
            _invariant_material(value), ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()


def _with_invariant_hash(value: SecurityInvariant) -> SecurityInvariant:
    return SecurityInvariant(
        invariant_id=value.invariant_id,
        invariant_version=value.invariant_version,
        property_name=value.property_name,
        finding_id=value.finding_id,
        root_cause_id=value.root_cause_id,
        candidate_id=value.candidate_id,
        candidate_version=value.candidate_version,
        tenant_id=value.tenant_id,
        repository_id=value.repository_id,
        head_sha=value.head_sha,
        root_cause_fingerprint=value.root_cause_fingerprint,
        evidence_graph_id=value.evidence_graph_id,
        evidence_graph_sha256=value.evidence_graph_sha256,
        required_evidence_ids=value.required_evidence_ids,
        invariant_sha256=_invariant_hash(value),
        schema_version=value.schema_version,
        command_operation_evidence=value.command_operation_evidence,
    )


def _unchecked_invariant(**values: object) -> SecurityInvariant:
    """Create an internal hash preimage; callers must immediately revalidate it."""

    value = object.__new__(SecurityInvariant)
    for name, item in values.items():
        object.__setattr__(value, name, item)
    return value


def _evaluation_material(value: InvariantEvaluation) -> dict[str, object]:
    return {
        "evidence_ids": list(value.evidence_ids),
        "finding_id": value.finding_id,
        "head_sha": value.head_sha,
        "invariant_id": value.invariant_id,
        "invariant_version": value.invariant_version,
        "reason": value.reason.value,
        "root_cause_id": value.root_cause_id,
        "satisfied": value.satisfied,
        "schema_version": value.schema_version,
        "repository_id": value.repository_id,
        "tenant_id": value.tenant_id,
    }


def _evaluation_hash(value: InvariantEvaluation) -> str:
    return hashlib.sha256(
        _HASH_DOMAIN
        + json.dumps(
            _evaluation_material(value), ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()


def _evaluation(value: SecurityInvariant, reason: InvariantEvaluationReason) -> InvariantEvaluation:
    result = _unchecked_evaluation(
        invariant_id=value.invariant_id,
        invariant_version=value.invariant_version,
        finding_id=value.finding_id,
        root_cause_id=value.root_cause_id,
        tenant_id=value.tenant_id,
        repository_id=value.repository_id,
        head_sha=value.head_sha,
        evidence_ids=value.required_evidence_ids,
        satisfied=reason is InvariantEvaluationReason.SATISFIED,
        reason=reason,
        evaluation_sha256="0" * 64,
        schema_version=_SCHEMA_VERSION,
    )
    return InvariantEvaluation(
        invariant_id=result.invariant_id,
        invariant_version=result.invariant_version,
        finding_id=result.finding_id,
        root_cause_id=result.root_cause_id,
        tenant_id=result.tenant_id,
        repository_id=result.repository_id,
        head_sha=result.head_sha,
        evidence_ids=result.evidence_ids,
        satisfied=result.satisfied,
        reason=result.reason,
        evaluation_sha256=_evaluation_hash(result),
        schema_version=result.schema_version,
    )


def _unchecked_evaluation(**values: object) -> InvariantEvaluation:
    value = object.__new__(InvariantEvaluation)
    for name, item in values.items():
        object.__setattr__(value, name, item)
    return value


__all__ = [
    "InvariantEvaluation",
    "InvariantEvaluationReason",
    "SecurityInvariant",
    "SecurityInvariantError",
    "SecurityInvariantErrorCode",
    "build_security_invariant",
    "evaluate_security_invariant",
]
