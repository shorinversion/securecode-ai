"""Deterministic metadata-only SCM policy evaluation for P5.3."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Final, cast

from securecode_ai.contracts import AuditRun, AuditRunOutcome

from .baseline_fingerprints import (
    BASELINE_FINGERPRINT_SCHEMA_VERSION,
    BaselineFingerprintComparison,
)

SCM_POLICY_SCHEMA_VERSION: Final = "securecode.scm-policy.v1"
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VERSION: Final = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?\Z")


class ScmPolicyMode(StrEnum):
    ADVISORY = "advisory"
    NEW_CODE = "new_code"
    STRICT = "strict"


class ScmPolicyEnforcement(StrEnum):
    ADVISORY = "ADVISORY"
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    NON_PASS = "NON_PASS"


class ScmPolicyErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    PRECALIBRATION_BLOCKING = "PRECALIBRATION_BLOCKING"
    BASELINE_REQUIRED = "BASELINE_REQUIRED"
    BASELINE_IDENTITY_MISMATCH = "BASELINE_IDENTITY_MISMATCH"
    UNMAPPED_BLOCKING_FINDING = "UNMAPPED_BLOCKING_FINDING"


@dataclass(frozen=True, slots=True)
class ScmPolicyDocument:
    """Pinned policy metadata. Policy bytes are never retained by this evaluator."""

    policy_id: str
    policy_version: str
    content_sha256: str
    calibration_record_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.policy_id) is not str
            or _ID.fullmatch(self.policy_id) is None
            or type(self.policy_version) is not str
            or _VERSION.fullmatch(self.policy_version) is None
            or not _is_sha(self.content_sha256)
            or (
                self.calibration_record_sha256 is not None
                and not _is_sha(self.calibration_record_sha256)
            )
        ):
            raise ValueError("SCM policy document metadata is invalid")

    @property
    def calibrated(self) -> bool:
        return self.calibration_record_sha256 is not None


@dataclass(frozen=True, slots=True)
class ScmPolicyInputHashes:
    """All valid evaluator inputs, represented only by canonical hashes."""

    policy_document_sha256: str
    audit_run_sha256: str
    execution_identity_sha256: str
    baseline_comparison_sha256: str | None

    def __post_init__(self) -> None:
        if not all(
            _is_sha(value)
            for value in (
                self.policy_document_sha256,
                self.audit_run_sha256,
                self.execution_identity_sha256,
            )
        ) or (
            self.baseline_comparison_sha256 is not None
            and not _is_sha(self.baseline_comparison_sha256)
        ):
            raise ValueError("SCM policy input hashes are invalid")


@dataclass(frozen=True, slots=True)
class ScmPolicyRequest:
    """Untrusted internal input; validation belongs to ``evaluate_scm_policy``."""

    policy: object
    mode: object
    audit_run: object
    baseline_comparison: object | None = None


@dataclass(frozen=True, slots=True)
class ScmPolicyDecision:
    """Source-free receipt. Enforcement never mutates the admitted audit outcome."""

    schema_version: str
    policy_id: str | None
    policy_version: str | None
    mode: ScmPolicyMode | None
    observed_audit_outcome: AuditRunOutcome | None
    enforcement: ScmPolicyEnforcement
    is_passing: bool
    blocks_merge: bool
    publication_permitted: bool
    input_hashes: ScmPolicyInputHashes | None
    matched_rule_ids: tuple[str, ...]
    error_code: ScmPolicyErrorCode | None
    decision_sha256: str

    def __post_init__(self) -> None:
        valid_rules = (
            type(self.matched_rule_ids) is tuple
            and 0 < len(self.matched_rule_ids) <= 16
            and len(self.matched_rule_ids) == len(set(self.matched_rule_ids))
            and all(
                type(rule) is str and _ID.fullmatch(rule) is not None
                for rule in self.matched_rule_ids
            )
        )
        if (
            self.schema_version != SCM_POLICY_SCHEMA_VERSION
            or type(self.enforcement) is not ScmPolicyEnforcement
            or type(self.is_passing) is not bool
            or type(self.blocks_merge) is not bool
            or type(self.publication_permitted) is not bool
            or not valid_rules
            or not _is_sha(self.decision_sha256)
        ):
            raise ValueError("SCM policy decision is invalid")
        if self.error_code is not None and type(self.error_code) is not ScmPolicyErrorCode:
            raise ValueError("SCM policy error code is invalid")
        if self.error_code is None:
            if (
                self.policy_id is None
                or self.policy_version is None
                or type(self.mode) is not ScmPolicyMode
                or type(self.observed_audit_outcome) is not AuditRunOutcome
                or type(self.input_hashes) is not ScmPolicyInputHashes
            ):
                raise ValueError("complete policy receipt metadata is required")
        elif self.enforcement is not ScmPolicyEnforcement.NON_PASS or any(
            (self.is_passing, self.blocks_merge, self.publication_permitted)
        ):
            raise ValueError("policy evaluation error must fail closed")
        if self.enforcement is ScmPolicyEnforcement.BLOCK and not self.blocks_merge:
            raise ValueError("blocking policy decision must block merge")
        if self.enforcement is ScmPolicyEnforcement.ADVISORY and self.blocks_merge:
            raise ValueError("advisory policy decision cannot block merge")

    def metadata(self) -> dict[str, object]:
        return {
            "blocks_merge": self.blocks_merge,
            "decision_sha256": self.decision_sha256,
            "enforcement": self.enforcement.value,
            "error_code": None if self.error_code is None else self.error_code.value,
            "input_hashes": None if self.input_hashes is None else asdict(self.input_hashes),
            "is_passing": self.is_passing,
            "matched_rule_ids": self.matched_rule_ids,
            "mode": None if self.mode is None else self.mode.value,
            "observed_audit_outcome": (
                None if self.observed_audit_outcome is None else self.observed_audit_outcome.value
            ),
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "publication_permitted": self.publication_permitted,
            "schema_version": self.schema_version,
        }


def evaluate_scm_policy(request: object) -> ScmPolicyDecision:
    """Return one pure fail-closed policy decision without network or SCM I/O."""

    try:
        policy, mode, audit_run, comparison = _admit(request)
    except (AttributeError, TypeError, ValueError):
        return _invalid_decision(ScmPolicyErrorCode.INVALID_INPUT)
    hashes = ScmPolicyInputHashes(
        policy_document_sha256=policy.content_sha256,
        audit_run_sha256=_sha(_canonical_json(audit_run.model_dump(mode="json"))),
        execution_identity_sha256=audit_run.execution_identity.execution_identity_hash,
        baseline_comparison_sha256=(
            None if comparison is None else _sha(_canonical_json(asdict(comparison)))
        ),
    )
    if mode is not ScmPolicyMode.ADVISORY and not policy.calibrated:
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            False,
            ("precalibration_blocking_rejected",),
            ScmPolicyErrorCode.PRECALIBRATION_BLOCKING,
        )
    if mode is ScmPolicyMode.ADVISORY:
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.ADVISORY,
            audit_run.audit_outcome is AuditRunOutcome.PASS,
            False,
            True,
            ("advisory_non_blocking",),
            None,
        )
    if comparison is None:
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            False,
            ("baseline_required",),
            ScmPolicyErrorCode.BASELINE_REQUIRED,
        )
    if not _comparison_matches_run(comparison, audit_run):
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            False,
            ("baseline_identity_mismatch",),
            ScmPolicyErrorCode.BASELINE_IDENTITY_MISMATCH,
        )
    if audit_run.audit_outcome is AuditRunOutcome.PASS:
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.ALLOW,
            True,
            False,
            True,
            ("complete_non_blocking",),
            None,
        )
    if audit_run.audit_outcome is not AuditRunOutcome.FAIL:
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            True,
            ("underlying_outcome_non_passing",),
            None,
        )
    if not comparison.head_fingerprints:
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            False,
            ("unmapped_blocking_finding",),
            ScmPolicyErrorCode.UNMAPPED_BLOCKING_FINDING,
        )
    if mode is ScmPolicyMode.NEW_CODE and not comparison.new_fingerprints:
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.ALLOW,
            False,
            False,
            True,
            ("legacy_debt_non_blocking",),
            None,
        )
    rule = "new_confirmed_finding" if mode is ScmPolicyMode.NEW_CODE else "confirmed_finding"
    return _decision(
        policy,
        mode,
        audit_run,
        hashes,
        ScmPolicyEnforcement.BLOCK,
        False,
        True,
        True,
        (rule,),
        None,
    )


def canonical_scm_policy_decision_json(decision: ScmPolicyDecision) -> str:
    if type(decision) is not ScmPolicyDecision:
        raise TypeError("decision must be an ScmPolicyDecision")
    return _canonical_json(decision.metadata()) + "\n"


def _admit(
    request: object,
) -> tuple[ScmPolicyDocument, ScmPolicyMode, AuditRun, BaselineFingerprintComparison | None]:
    if type(request) is not ScmPolicyRequest:
        raise TypeError("request must be an ScmPolicyRequest")
    if type(request.policy) is not ScmPolicyDocument or type(request.mode) is not ScmPolicyMode:
        raise TypeError("policy request metadata is invalid")
    if type(request.audit_run) is not AuditRun:
        raise TypeError("audit run is invalid")
    comparison = request.baseline_comparison
    if comparison is not None:
        _validate_comparison(comparison)
        comparison = cast(BaselineFingerprintComparison, comparison)
    audit_run = AuditRun.model_validate_json(request.audit_run.model_dump_json())
    return request.policy, request.mode, audit_run, comparison


def _validate_comparison(value: object) -> None:
    if type(value) is not BaselineFingerprintComparison:
        raise TypeError("baseline comparison is invalid")
    fields = (
        value.baseline_fingerprints,
        value.head_fingerprints,
        value.new_fingerprints,
    )
    if (
        value.schema_version != BASELINE_FINGERPRINT_SCHEMA_VERSION
        or type(value.tenant_id) is not str
        or not value.tenant_id
        or not _is_commit(value.base_sha)
        or not _is_commit(value.head_sha)
        or any(type(field) is not tuple for field in fields)
        or any(
            not all(_is_sha(item) for item in field) or tuple(sorted(field)) != field
            for field in fields
        )
        or any(len(field) != len(set(field)) for field in fields)
        or not set(value.new_fingerprints).issubset(value.head_fingerprints)
        or set(value.new_fingerprints) & set(value.baseline_fingerprints)
        or set(value.head_fingerprints) - set(value.baseline_fingerprints)
        != set(value.new_fingerprints)
    ):
        raise ValueError("baseline comparison is invalid")


def _comparison_matches_run(comparison: BaselineFingerprintComparison, audit_run: AuditRun) -> bool:
    revision = audit_run.execution_identity.repository_revision
    return (
        comparison.tenant_id == revision.tenant_id
        and comparison.base_sha == revision.base_sha
        and comparison.head_sha == revision.head_sha
    )


def _decision(
    policy: ScmPolicyDocument,
    mode: ScmPolicyMode,
    audit_run: AuditRun,
    hashes: ScmPolicyInputHashes,
    enforcement: ScmPolicyEnforcement,
    is_passing: bool,
    blocks_merge: bool,
    publication_permitted: bool,
    matched_rule_ids: tuple[str, ...],
    error_code: ScmPolicyErrorCode | None,
) -> ScmPolicyDecision:
    metadata = {
        "schema_version": SCM_POLICY_SCHEMA_VERSION,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "mode": mode.value,
        "observed_audit_outcome": audit_run.audit_outcome.value,
        "enforcement": enforcement.value,
        "is_passing": is_passing,
        "blocks_merge": blocks_merge,
        "publication_permitted": publication_permitted,
        "input_hashes": asdict(hashes),
        "matched_rule_ids": matched_rule_ids,
        "error_code": None if error_code is None else error_code.value,
    }
    return ScmPolicyDecision(
        schema_version=SCM_POLICY_SCHEMA_VERSION,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        mode=mode,
        observed_audit_outcome=audit_run.audit_outcome,
        enforcement=enforcement,
        is_passing=is_passing,
        blocks_merge=blocks_merge,
        publication_permitted=publication_permitted,
        input_hashes=hashes,
        matched_rule_ids=matched_rule_ids,
        error_code=error_code,
        decision_sha256=_sha(_canonical_json(metadata)),
    )


def _invalid_decision(error_code: ScmPolicyErrorCode) -> ScmPolicyDecision:
    metadata = {
        "schema_version": SCM_POLICY_SCHEMA_VERSION,
        "policy_id": None,
        "policy_version": None,
        "mode": None,
        "observed_audit_outcome": None,
        "enforcement": ScmPolicyEnforcement.NON_PASS.value,
        "is_passing": False,
        "blocks_merge": False,
        "publication_permitted": False,
        "input_hashes": None,
        "matched_rule_ids": ("invalid_input",),
        "error_code": error_code.value,
    }
    return ScmPolicyDecision(
        schema_version=SCM_POLICY_SCHEMA_VERSION,
        policy_id=None,
        policy_version=None,
        mode=None,
        observed_audit_outcome=None,
        enforcement=ScmPolicyEnforcement.NON_PASS,
        is_passing=False,
        blocks_merge=False,
        publication_permitted=False,
        input_hashes=None,
        matched_rule_ids=("invalid_input",),
        error_code=error_code,
        decision_sha256=_sha(_canonical_json(metadata)),
    )


def _is_sha(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _is_commit(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    )


__all__ = [
    "SCM_POLICY_SCHEMA_VERSION",
    "ScmPolicyDecision",
    "ScmPolicyDocument",
    "ScmPolicyEnforcement",
    "ScmPolicyErrorCode",
    "ScmPolicyInputHashes",
    "ScmPolicyMode",
    "ScmPolicyRequest",
    "canonical_scm_policy_decision_json",
    "evaluate_scm_policy",
]
