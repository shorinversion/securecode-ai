"""Deterministic metadata-only SCM policy evaluation for P5.3."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final, cast

from securecode_ai.contracts import AuditRun, AuditRunOutcome

from .baseline_fingerprints import (
    BASELINE_FINGERPRINT_SCHEMA_VERSION,
    BaselineChangedScope,
    BaselineFindingRelation,
    BaselineFingerprintComparison,
)

SCM_POLICY_SCHEMA_VERSION: Final = "securecode.scm-policy.v1"
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VERSION: Final = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?\Z")
_COMMIT: Final = re.compile(r"[0-9a-f]{40}\Z")
_SEVERITIES: Final = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_VERDICTS: Final = frozenset(
    {"CONFIRMED", "REJECTED_WITH_EVIDENCE", "NEEDS_MORE_EVIDENCE", "CONFLICTING", "NOT_EVALUATED"}
)
_RISK_LABEL: Final = re.compile(r"[a-z][a-z0-9_.:-]{0,63}\Z")
_CONFIDENCE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}\Z")
_MAX_FINDINGS: Final = 100_000
_POLICY_GATE_KEYS: Final = frozenset(
    {
        "mode",
        "scope",
        "block_on",
        "needs_human",
        "timeout",
        "refusal_or_incomplete",
        "require_mandatory_coverage",
    }
)
_POLICY_ROOT_KEYS: Final = frozenset(
    {"gate", "schema_version", "calibration_record_sha256"}
)


class ScmPolicyMode(StrEnum):
    ADVISORY = "advisory"
    NEW_CODE = "new_code"
    STRICT = "strict"


@dataclass(frozen=True, slots=True)
class ScmPolicyRules:
    """Typed, source-free gate rules extracted from one policy document."""

    block_severities: tuple[str, ...] = ("HIGH", "CRITICAL")
    block_verdicts: tuple[str, ...] = ("CONFIRMED",)
    min_confidence: str | None = None
    human_review_risk_labels: tuple[str, ...] = ()
    require_mandatory_coverage: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.block_severities) is not tuple
            or not self.block_severities
            or any(item not in _SEVERITIES for item in self.block_severities)
            or len(set(self.block_severities)) != len(self.block_severities)
            or tuple(sorted(self.block_severities, key=_severity_rank)) != self.block_severities
            or type(self.block_verdicts) is not tuple
            or not self.block_verdicts
            or self.block_verdicts != ("CONFIRMED",)
            or len(set(self.block_verdicts)) != len(self.block_verdicts)
            or tuple(sorted(self.block_verdicts)) != self.block_verdicts
            or (
                self.min_confidence is not None
                and (
                    type(self.min_confidence) is not str
                    or not self.min_confidence
                    or len(self.min_confidence) > 64
                )
            )
            or type(self.human_review_risk_labels) is not tuple
            or len(self.human_review_risk_labels) > 32
            or any(
                type(item) is not str or _RISK_LABEL.fullmatch(item) is None
                for item in self.human_review_risk_labels
            )
            or len(set(self.human_review_risk_labels)) != len(self.human_review_risk_labels)
            or tuple(sorted(self.human_review_risk_labels)) != self.human_review_risk_labels
            or self.require_mandatory_coverage is not True
        ):
            raise ValueError("SCM policy rules are invalid")

    @classmethod
    def from_content(cls, content: Mapping[str, object]) -> ScmPolicyRules:
        """Parse the closed policy rule shape without retaining source bytes."""

        if not isinstance(content, Mapping):
            raise ValueError("SCM policy content is invalid")
        gate, _ = _policy_content_parts(content)
        if not isinstance(gate, Mapping) or not gate:
            raise ValueError("SCM policy gate is invalid")
        if any(type(key) is not str or key not in _POLICY_GATE_KEYS for key in gate):
            raise ValueError("SCM policy gate contains an unknown field")
        scope = gate.get("scope", "changed_code")
        if scope != "changed_code":
            raise ValueError("SCM policy scope is invalid")
        for behavior_key in ("timeout", "refusal_or_incomplete"):
            behavior = gate.get(behavior_key)
            if behavior is None:
                continue
            if (
                not isinstance(behavior, Mapping)
                or set(behavior) != {"behavior"}
                or behavior.get("behavior") != "action_required"
            ):
                raise ValueError("SCM policy incomplete behavior is invalid")
        block_on = gate.get("block_on", {})
        if not isinstance(block_on, Mapping):
            raise ValueError("SCM policy block_on is invalid")
        if any(
            type(key) is not str or key not in {"severity", "status", "min_confidence"}
            for key in block_on
        ):
            raise ValueError("SCM policy block_on contains an unknown field")
        severities = _policy_severities(block_on.get("severity", ("HIGH", "CRITICAL")))
        status = block_on.get("status", ("CONFIRMED",))
        verdicts = _policy_verdicts(status)
        min_confidence = block_on.get("min_confidence")
        if min_confidence is not None and (
            type(min_confidence) is not str or not min_confidence or len(min_confidence) > 64
        ):
            raise ValueError("SCM policy confidence threshold is invalid")
        needs_human = gate.get("needs_human", ())
        if not isinstance(needs_human, Sequence) or isinstance(needs_human, (str, bytes, bytearray)):
            raise ValueError("SCM policy human review rules are invalid")
        if any(type(item) is not str or _RISK_LABEL.fullmatch(item) is None for item in needs_human):
            raise ValueError("SCM policy human review rules are invalid")
        human_labels = tuple(sorted(needs_human))
        require_coverage = gate.get("require_mandatory_coverage", True)
        if require_coverage is not True:
            raise ValueError("SCM policy coverage rule is invalid")
        return cls(
            block_severities=severities,
            block_verdicts=verdicts,
            min_confidence=min_confidence,
            human_review_risk_labels=human_labels,
            require_mandatory_coverage=require_coverage,
        )


@dataclass(frozen=True, slots=True)
class ScmPolicyFinding:
    """Verified finding metadata used by the policy evaluator.

    This deliberately contains no source text or evidence bytes.  The server
    adapter constructs it only after terminal worker evidence has been
    independently verified.
    """

    finding_id: str
    revision_sha: str
    root_cause_fingerprint: str
    severity: str
    verdict: str
    blocking: bool
    risk_labels: tuple[str, ...] = ()
    tenant_id: str | None = None
    confidence: str = "UNSCORED"

    def __post_init__(self) -> None:
        if (
            type(self.finding_id) is not str
            or _ID.fullmatch(self.finding_id) is None
            or not _is_commit(self.revision_sha)
            or not _is_sha(self.root_cause_fingerprint)
            or self.severity not in _SEVERITIES
            or self.verdict not in _VERDICTS
            or type(self.blocking) is not bool
            or type(self.confidence) is not str
            or _CONFIDENCE.fullmatch(self.confidence) is None
            or type(self.risk_labels) is not tuple
            or len(self.risk_labels) > 32
            or any(
                type(item) is not str or _RISK_LABEL.fullmatch(item) is None
                for item in self.risk_labels
            )
            or len(set(self.risk_labels)) != len(self.risk_labels)
            or tuple(sorted(self.risk_labels)) != self.risk_labels
            or (
                self.tenant_id is not None
                and (
                    type(self.tenant_id) is not str
                    or _ID.fullmatch(self.tenant_id) is None
                )
            )
        ):
            raise ValueError("SCM policy finding metadata is invalid")

    def metadata(self) -> dict[str, object]:
        return {
            "blocking": self.blocking,
            "confidence": self.confidence,
            "finding_id": self.finding_id,
            "revision_sha": self.revision_sha,
            "risk_labels": self.risk_labels,
            "root_cause_fingerprint": self.root_cause_fingerprint,
            "severity": self.severity,
            "tenant_id": self.tenant_id,
            "verdict": self.verdict,
        }


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
    CHANGED_SCOPE_REQUIRED = "CHANGED_SCOPE_REQUIRED"
    UNMAPPED_BLOCKING_FINDING = "UNMAPPED_BLOCKING_FINDING"
    MANDATORY_COVERAGE_INCOMPLETE = "MANDATORY_COVERAGE_INCOMPLETE"
    HUMAN_REVIEW_REQUIRED = "HUMAN_REVIEW_REQUIRED"
    CONFIDENCE_UNAVAILABLE = "CONFIDENCE_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class ScmPolicyDocument:
    """Pinned policy metadata with an immutable, validated policy projection."""

    policy_id: str
    policy_version: str
    content_sha256: str
    calibration_record_sha256: str | None = None
    mode: ScmPolicyMode | None = None
    rules: ScmPolicyRules | None = None
    content: Mapping[str, object] | None = None
    calibration_verified: bool = False

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
            or type(self.calibration_verified) is not bool
            or (self.calibration_verified and self.calibration_record_sha256 is None)
            or (self.mode is not None and type(self.mode) is not ScmPolicyMode)
            or (self.rules is not None and type(self.rules) is not ScmPolicyRules)
        ):
            raise ValueError("SCM policy document metadata is invalid")
        if self.mode is not None and self.mode is not ScmPolicyMode.ADVISORY and self.content is None:
            raise ValueError("SCM policy blocking mode is not bound to content")
        if self.content is not None:
            if not isinstance(self.content, Mapping):
                raise ValueError("SCM policy content is invalid")
            try:
                frozen_content = _freeze_policy_json(self.content)
                canonical = _canonical_json(frozen_content)
                content_rules = ScmPolicyRules.from_content(frozen_content)
                gate, root = _policy_content_parts(frozen_content)
                raw_mode = gate.get("mode")
                parsed_mode = None if raw_mode is None else ScmPolicyMode(raw_mode)
                embedded_calibration = root.get("calibration_record_sha256")
                if embedded_calibration is not None and not _is_sha(embedded_calibration):
                    raise ValueError("SCM policy calibration hash is invalid")
            except (TypeError, ValueError):
                raise ValueError("SCM policy content is invalid") from None
            if hashlib.sha256(canonical.encode("ascii")).hexdigest() != self.content_sha256:
                raise ValueError("SCM policy content hash does not match")
            if self.rules is not None and self.rules != content_rules:
                raise ValueError("SCM policy rules do not match content")
            if self.rules is None:
                object.__setattr__(self, "rules", content_rules)
            if (
                self.mode is not None
                and parsed_mode is not None
                and self.mode is not parsed_mode
            ):
                raise ValueError("SCM policy mode conflicts with content")
            if (
                self.mode is not None
                and parsed_mode is None
                and self.mode is not ScmPolicyMode.ADVISORY
            ):
                raise ValueError("SCM policy mode is not bound to content")
            if self.mode is None and parsed_mode is not None:
                object.__setattr__(self, "mode", parsed_mode)
            if (
                self.calibration_record_sha256 is not None
                and embedded_calibration is not None
                and self.calibration_record_sha256 != embedded_calibration
            ):
                raise ValueError("SCM policy calibration hash conflicts with content")
            if self.calibration_record_sha256 is None and embedded_calibration is not None:
                object.__setattr__(self, "calibration_record_sha256", embedded_calibration)
            if (
                self.mode is not None
                and self.mode is not ScmPolicyMode.ADVISORY
                and self.calibration_record_sha256 is not None
                and embedded_calibration is None
            ):
                raise ValueError("SCM policy calibration is not bound to content")
            object.__setattr__(self, "content", frozen_content)
        if self.rules is None:
            object.__setattr__(self, "rules", ScmPolicyRules())

    @property
    def calibrated(self) -> bool:
        return self.calibration_record_sha256 is not None and self.calibration_verified

    @property
    def effective_mode(self) -> ScmPolicyMode:
        return ScmPolicyMode.ADVISORY if self.mode is None else self.mode

    @classmethod
    def from_content(
        cls,
        *,
        policy_id: str,
        policy_version: str,
        content_sha256: str,
        content: Mapping[str, object],
        calibration_record_sha256: str | None = None,
        calibration_verified: bool = False,
        mode: ScmPolicyMode | None = None,
    ) -> ScmPolicyDocument:
        """Build a policy only when the supplied bytes match the pinned digest."""

        if not isinstance(content, Mapping):
            raise ValueError("SCM policy content is invalid")
        selected_mode = mode
        gate, root = _policy_content_parts(content)
        raw_mode = gate.get("mode")
        if raw_mode is not None:
            try:
                parsed_mode = ScmPolicyMode(raw_mode)
            except (TypeError, ValueError):
                raise ValueError("SCM policy mode is invalid") from None
            if selected_mode is not None and selected_mode is not parsed_mode:
                raise ValueError("SCM policy mode conflicts with content")
            selected_mode = parsed_mode
        elif selected_mode is not None and selected_mode is not ScmPolicyMode.ADVISORY:
            raise ValueError("SCM policy mode is not bound to content")
        embedded_calibration = root.get("calibration_record_sha256")
        if embedded_calibration is not None:
            if not _is_sha(embedded_calibration):
                raise ValueError("SCM policy calibration hash is invalid")
            if (
                calibration_record_sha256 is not None
                and calibration_record_sha256 != embedded_calibration
            ):
                raise ValueError("SCM policy calibration hash conflicts with content")
            calibration_record_sha256 = embedded_calibration
        elif (
            selected_mode is not None
            and selected_mode is not ScmPolicyMode.ADVISORY
            and calibration_record_sha256 is not None
        ):
            raise ValueError("SCM policy calibration is not bound to content")
        return cls(
            policy_id=policy_id,
            policy_version=policy_version,
            content_sha256=content_sha256,
            calibration_record_sha256=calibration_record_sha256,
            calibration_verified=calibration_verified,
            mode=selected_mode,
            rules=ScmPolicyRules.from_content(content),
            content=content,
        )


@dataclass(frozen=True, slots=True)
class ScmPolicyInputHashes:
    """All valid evaluator inputs, represented only by canonical hashes."""

    policy_document_sha256: str
    audit_run_sha256: str
    execution_identity_sha256: str
    baseline_comparison_sha256: str | None
    changed_scope_sha256: str | None = None

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
        ) or (
            self.changed_scope_sha256 is not None
            and not _is_sha(self.changed_scope_sha256)
        ):
            raise ValueError("SCM policy input hashes are invalid")


@dataclass(frozen=True, slots=True)
class ScmPolicyRequest:
    """Untrusted internal input; validation belongs to ``evaluate_scm_policy``."""

    policy: object
    mode: object
    audit_run: object
    baseline_comparison: object | None = None
    verified_findings: object = ()
    changed_scope: object | None = None


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
        if self.enforcement is ScmPolicyEnforcement.ALLOW and self.blocks_merge:
            raise ValueError("allowing policy decision cannot block merge")
        if self.enforcement is ScmPolicyEnforcement.ADVISORY and self.blocks_merge:
            raise ValueError("advisory policy decision cannot block merge")
        if (
            self.error_code is None
            and self.mode is ScmPolicyMode.STRICT
            and self.enforcement is ScmPolicyEnforcement.ALLOW
            and self.observed_audit_outcome is not AuditRunOutcome.PASS
        ):
            raise ValueError("strict policy cannot allow a non-passing audit")

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
        policy, mode, audit_run, comparison, verified_findings, changed_scope = _admit(request)
    except (AttributeError, TypeError, ValueError):
        return _invalid_decision(ScmPolicyErrorCode.INVALID_INPUT)
    hashes = ScmPolicyInputHashes(
        policy_document_sha256=policy.content_sha256,
        audit_run_sha256=_sha(
            _canonical_json(
                {
                    "audit_run": audit_run.model_dump(mode="json"),
                    "calibration_record_sha256": policy.calibration_record_sha256,
                    "calibration_verified": policy.calibration_verified,
                    "verified_findings": tuple(item.metadata() for item in verified_findings),
                    "changed_scope": (
                        None
                        if changed_scope is None
                        else _changed_scope_document(changed_scope)
                    ),
                }
            )
        ),
        execution_identity_sha256=audit_run.execution_identity.execution_identity_hash,
        baseline_comparison_sha256=(
            None if comparison is None else _sha(_canonical_json(asdict(comparison)))
        ),
        changed_scope_sha256=(
            None
            if changed_scope is None
            else _sha(_canonical_json(_changed_scope_document(changed_scope)))
        ),
    )
    coverage_ready = _coverage_ready(audit_run)
    if not _verified_findings_match_run(audit_run, verified_findings):
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            False,
            ("verified_findings_mismatch",),
            ScmPolicyErrorCode.INVALID_INPUT,
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
    if _human_review_required(policy, verified_findings):
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            False,
            ("human_review_required",),
            ScmPolicyErrorCode.HUMAN_REVIEW_REQUIRED,
        )
    if mode is ScmPolicyMode.ADVISORY:
        if audit_run.audit_outcome in {AuditRunOutcome.PASS, AuditRunOutcome.FAIL} and not coverage_ready:
            return _decision(
                policy,
                mode,
                audit_run,
                hashes,
                ScmPolicyEnforcement.NON_PASS,
                False,
                False,
                False,
                ("mandatory_coverage_incomplete",),
                ScmPolicyErrorCode.MANDATORY_COVERAGE_INCOMPLETE,
            )
        if audit_run.audit_outcome is AuditRunOutcome.FAIL and _blocking_findings_match(
            audit_run,
            verified_findings,
            comparison=None,
        ) is None:
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
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.ADVISORY,
            audit_run.audit_outcome is AuditRunOutcome.PASS,
            False,
            audit_run.audit_outcome in {AuditRunOutcome.PASS, AuditRunOutcome.FAIL},
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
    if mode is ScmPolicyMode.NEW_CODE and changed_scope is not None:
        try:
            changed_scope.validate_for(comparison)
        except (TypeError, ValueError):
            return _decision(
                policy,
                mode,
                audit_run,
                hashes,
                ScmPolicyEnforcement.NON_PASS,
                False,
                False,
                False,
                ("changed_scope_invalid",),
                ScmPolicyErrorCode.CHANGED_SCOPE_REQUIRED,
            )
    if (
        mode is not ScmPolicyMode.ADVISORY
        and audit_run.audit_outcome is AuditRunOutcome.PASS
        and not coverage_ready
    ):
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            False,
            ("mandatory_coverage_incomplete",),
            ScmPolicyErrorCode.MANDATORY_COVERAGE_INCOMPLETE,
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
            False,
            ("underlying_outcome_non_passing",),
            None,
        )
    matched = _blocking_findings_match(
        audit_run,
        verified_findings,
        comparison=comparison,
    )
    if matched is None:
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
    if policy.rules.min_confidence is not None:
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            False,
            ("confidence_threshold_unavailable",),
            ScmPolicyErrorCode.CONFIDENCE_UNAVAILABLE,
        )
    eligible = tuple(
        item
        for item in matched
        if item.verdict in policy.rules.block_verdicts
        and item.severity in policy.rules.block_severities
    )
    if mode is ScmPolicyMode.NEW_CODE:
        raw_new = tuple(
            item
            for item in eligible
            if comparison.relation_for(item.root_cause_fingerprint)
            is BaselineFindingRelation.NEW
        )
        if raw_new:
            if changed_scope is None:
                return _decision(
                    policy,
                    mode,
                    audit_run,
                    hashes,
                    ScmPolicyEnforcement.NON_PASS,
                    False,
                    False,
                    False,
                    ("changed_scope_required",),
                    ScmPolicyErrorCode.CHANGED_SCOPE_REQUIRED,
                )
            try:
                scoped_new = set(comparison.new_code_fingerprints(changed_scope=changed_scope))
            except (TypeError, ValueError):
                scoped_new = set()
            if any(item.root_cause_fingerprint not in scoped_new for item in raw_new):
                return _decision(
                    policy,
                    mode,
                    audit_run,
                    hashes,
                    ScmPolicyEnforcement.NON_PASS,
                    False,
                    False,
                    False,
                    ("changed_scope_unproven",),
                    ScmPolicyErrorCode.CHANGED_SCOPE_REQUIRED,
                )
        if not raw_new:
            if any(
                comparison.relation_for(item.root_cause_fingerprint)
                is not BaselineFindingRelation.LEGACY
                for item in eligible
            ):
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
            return _decision(
                policy,
                mode,
                audit_run,
                hashes,
                ScmPolicyEnforcement.ALLOW,
                False,
                False,
                coverage_ready,
                ("legacy_debt_non_blocking" if eligible else "policy_threshold_non_blocking",),
                None,
            )
    if mode is ScmPolicyMode.STRICT and not eligible:
        return _decision(
            policy,
            mode,
            audit_run,
            hashes,
            ScmPolicyEnforcement.NON_PASS,
            False,
            False,
            False,
            ("strict_policy_threshold_unresolved",),
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
        coverage_ready,
        (rule,),
        None,
    )


def canonical_scm_policy_decision_json(decision: ScmPolicyDecision) -> str:
    if type(decision) is not ScmPolicyDecision:
        raise TypeError("decision must be an ScmPolicyDecision")
    return _canonical_json(decision.metadata()) + "\n"


def _admit(
    request: object,
) -> tuple[
    ScmPolicyDocument,
    ScmPolicyMode,
    AuditRun,
    BaselineFingerprintComparison | None,
    tuple[ScmPolicyFinding, ...],
    BaselineChangedScope | None,
]:
    if type(request) is not ScmPolicyRequest:
        raise TypeError("request must be an ScmPolicyRequest")
    if type(request.policy) is not ScmPolicyDocument or type(request.mode) is not ScmPolicyMode:
        raise TypeError("policy request metadata is invalid")
    if request.policy.mode is not None and request.policy.mode is not request.mode:
        raise ValueError("SCM policy mode conflicts with the document")
    if request.mode is not ScmPolicyMode.ADVISORY and (
        request.policy.content is None or request.policy.mode is not request.mode
    ):
        raise ValueError("SCM policy blocking mode is not bound to content")
    if type(request.audit_run) is not AuditRun:
        raise TypeError("audit run is invalid")
    comparison = request.baseline_comparison
    if comparison is not None:
        _validate_comparison(comparison)
        comparison = cast(BaselineFingerprintComparison, comparison)
    audit_run = AuditRun.model_validate_json(request.audit_run.model_dump_json())
    verified_findings = _validate_verified_findings(request.verified_findings)
    changed_scope = request.changed_scope
    if changed_scope is not None and type(changed_scope) is not BaselineChangedScope:
        raise TypeError("changed scope is invalid")
    return request.policy, request.mode, audit_run, comparison, verified_findings, changed_scope


def _validate_verified_findings(value: object) -> tuple[ScmPolicyFinding, ...]:
    if type(value) is not tuple or len(value) > _MAX_FINDINGS:
        raise TypeError("verified findings are invalid")
    findings = tuple(value)
    if any(type(item) is not ScmPolicyFinding for item in findings):
        raise TypeError("verified findings are invalid")
    finding_ids = tuple(item.finding_id for item in findings)
    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("verified finding IDs are duplicated")
    return tuple(sorted(findings, key=lambda item: item.finding_id))


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


def _coverage_ready(audit_run: AuditRun) -> bool:
    """Require the independent coverage facts before publishing a clean gate."""

    return (
        audit_run.analysis_health.value == "HEALTHY"
        and audit_run.coverage_manifest.coverage_complete
        and not audit_run.unresolved_gate_ids
        and audit_run.publication_preconditions_met
    )


def _verified_findings_match_run(
    audit_run: AuditRun,
    verified_findings: tuple[ScmPolicyFinding, ...],
) -> bool:
    """Require a complete, exact projection of terminal worker findings."""

    revision = audit_run.execution_identity.repository_revision
    expected_ids = set(audit_run.finding_ids)
    by_id = {item.finding_id: item for item in verified_findings}
    if len(by_id) != len(verified_findings) or set(by_id) != expected_ids:
        return False
    blocking_ids = set(audit_run.blocking_finding_ids)
    return all(
        item.tenant_id == revision.tenant_id
        and item.revision_sha == revision.head_sha
        and item.blocking is (item.finding_id in blocking_ids)
        for item in verified_findings
    )


def _human_review_required(
    policy: ScmPolicyDocument,
    verified_findings: tuple[ScmPolicyFinding, ...],
) -> bool:
    labels = set(policy.rules.human_review_risk_labels)
    return any(
        item.verdict == "CONFLICTING" or bool(labels & set(item.risk_labels))
        for item in verified_findings
    )


def _blocking_findings_match(
    audit_run: AuditRun,
    verified_findings: tuple[ScmPolicyFinding, ...],
    *,
    comparison: BaselineFingerprintComparison | None,
) -> tuple[ScmPolicyFinding, ...] | None:
    """Return verified blocking records bound to the exact audit and baseline."""

    expected_ids = tuple(audit_run.blocking_finding_ids)
    if not _verified_findings_match_run(audit_run, verified_findings):
        return None
    by_id = {item.finding_id: item for item in verified_findings}
    if any(identifier not in by_id for identifier in expected_ids):
        return None
    selected = tuple(by_id[identifier] for identifier in expected_ids)
    if not selected:
        return None
    if any(item.verdict not in {"CONFIRMED", "CONFLICTING"} for item in selected):
        return None
    if comparison is not None and any(
        item.root_cause_fingerprint not in comparison.head_fingerprints for item in selected
    ):
        return None
    return selected


def _comparison_matches_run(comparison: BaselineFingerprintComparison, audit_run: AuditRun) -> bool:
    revision = audit_run.execution_identity.repository_revision
    return (
        comparison.tenant_id == revision.tenant_id
        and comparison.base_sha == revision.base_sha
        and comparison.head_sha == revision.head_sha
    )


def _changed_scope_document(scope: BaselineChangedScope) -> dict[str, object]:
    return {
        "base_sha": scope.base_sha,
        "changed_lines": scope.changed_lines,
        "data_flow_locations": scope.data_flow_locations,
        "finding_locations": scope.finding_locations,
        "head_sha": scope.head_sha,
        "tenant_id": scope.tenant_id,
    }


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
    return type(value) is str and _COMMIT.fullmatch(value) is not None


def _policy_content_parts(
    content: Mapping[str, object],
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    """Split the closed policy envelope from its gate rules."""

    if not isinstance(content, Mapping) or not content:
        raise ValueError("SCM policy content is invalid")
    if "gate" in content:
        if any(type(key) is not str or key not in _POLICY_ROOT_KEYS for key in content):
            raise ValueError("SCM policy document contains an unknown field")
        gate = content.get("gate")
        if not isinstance(gate, Mapping) or not gate:
            raise ValueError("SCM policy gate is invalid")
        root = content
    else:
        if any(
            type(key) is not str
            or key not in _POLICY_GATE_KEYS
            and key not in {"schema_version", "calibration_record_sha256"}
            for key in content
        ):
            raise ValueError("SCM policy document contains an unknown field")
        gate = {key: value for key, value in content.items() if key in _POLICY_GATE_KEYS}
        if not gate:
            raise ValueError("SCM policy gate is invalid")
        root = {
            key: value
            for key, value in content.items()
            if key in {"schema_version", "calibration_record_sha256"}
        }
    schema_version = root.get("schema_version")
    if schema_version is not None and schema_version != SCM_POLICY_SCHEMA_VERSION:
        raise ValueError("SCM policy schema version is invalid")
    return cast(Mapping[str, object], gate), root


def _severity_rank(value: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[value]


def _policy_severities(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError("SCM policy severity threshold is invalid")
    values = tuple(item.upper() if isinstance(item, str) else item for item in value)
    if (
        not values
        or any(type(item) is not str or item not in _SEVERITIES for item in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("SCM policy severity threshold is invalid")
    return tuple(sorted(values, key=_severity_rank))


def _policy_verdicts(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        value = (value,)
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        raise ValueError("SCM policy verdict threshold is invalid")
    values = tuple(item.upper() if isinstance(item, str) else item for item in value)
    if (
        not values
        or any(type(item) is not str or item not in _VERDICTS for item in values)
        or len(set(values)) != len(values)
    ):
        raise ValueError("SCM policy verdict threshold is invalid")
    return tuple(sorted(values))


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _canonical_json(value: object) -> str:
    return json.dumps(
        _plain_json(value),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _freeze_policy_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_policy_json(item) for key, item in value.items()})
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(_freeze_policy_json(item) for item in value)
    return value


def _plain_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_plain_json(item) for item in value]
    return value


__all__ = [
    "SCM_POLICY_SCHEMA_VERSION",
    "ScmPolicyDecision",
    "ScmPolicyDocument",
    "ScmPolicyEnforcement",
    "ScmPolicyErrorCode",
    "ScmPolicyFinding",
    "ScmPolicyInputHashes",
    "ScmPolicyMode",
    "ScmPolicyRequest",
    "ScmPolicyRules",
    "canonical_scm_policy_decision_json",
    "evaluate_scm_policy",
]
