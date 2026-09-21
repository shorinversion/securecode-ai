"""Versioned, provider-neutral domain contracts for SecureCode AI."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Final, Self

from pydantic import AfterValidator, Field, model_validator

from .base import (
    CommitSha,
    OpaqueId,
    SemVer,
    Sha256,
    WireModel,
)


def _require_utc(value: datetime) -> datetime:
    if value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be timezone-aware UTC")
    return value


UtcTimestamp = Annotated[datetime, AfterValidator(_require_utc)]
PositiveInt = Annotated[int, Field(ge=1)]
NonNegativeInt = Annotated[int, Field(ge=0)]


class ModelCallStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    REFUSED = "REFUSED"
    CONTENT_FILTERED = "CONTENT_FILTERED"
    INCOMPLETE = "INCOMPLETE"
    TRUNCATED = "TRUNCATED"
    CONTEXT_EXHAUSTED = "CONTEXT_EXHAUSTED"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    EMPTY_OUTPUT = "EMPTY_OUTPUT"
    TIMEOUT = "TIMEOUT"
    RATE_LIMITED = "RATE_LIMITED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    GUARDRAIL_BLOCKED = "GUARDRAIL_BLOCKED"
    CANCELLED = "CANCELLED"


class FindingVerdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    REJECTED_WITH_EVIDENCE = "REJECTED_WITH_EVIDENCE"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    CONFLICTING = "CONFLICTING"
    NOT_EVALUATED = "NOT_EVALUATED"


class AuditRunOutcome(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"
    ERROR = "ERROR"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"


class CandidateOrigin(StrEnum):
    DETERMINISTIC = "deterministic"
    MODEL_NATIVE = "model_native"
    HYBRID = "hybrid"


class DiscoveryLane(StrEnum):
    DETERMINISTIC = "deterministic"
    MODEL_NATIVE = "model_native"


class CoverageStatus(StrEnum):
    COMPLETED = "COMPLETED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    SKIPPED = "SKIPPED"


class AnalysisHealth(StrEnum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class FindingGateState(StrEnum):
    CLEAN = "CLEAN"
    BLOCKING = "BLOCKING"
    INCONCLUSIVE = "INCONCLUSIVE"


class TrustLabel(StrEnum):
    TRUSTED_DETERMINISTIC = "trusted_deterministic"
    UNTRUSTED_REPOSITORY = "untrusted_repository"
    UNTRUSTED_TOOL_OUTPUT = "untrusted_tool_output"
    MODEL_GENERATED = "model_generated"
    HUMAN_ATTESTED = "human_attested"


class EvidenceKind(StrEnum):
    SOURCE_LOCATION = "source_location"
    DATA_FLOW = "data_flow"
    SCANNER_SIGNAL = "scanner_signal"
    CONFIGURATION = "configuration"
    DEPENDENCY = "dependency"
    TEST_RESULT = "test_result"
    MODEL_ANALYSIS = "model_analysis"
    POLICY_DECISION = "policy_decision"


class PatchStatus(StrEnum):
    SUGGESTED = "SUGGESTED"
    CANDIDATE = "CANDIDATE"
    VALIDATED = "VALIDATED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class ValidationGateOutcome(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class ValidationOutcome(StrEnum):
    VALIDATED = "VALIDATED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"
    ERROR = "ERROR"


class DecisionOutcome(StrEnum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    WAIVE = "WAIVE"
    ESCALATE = "ESCALATE"


class CoverageScenario(StrEnum):
    DEMO_CWE89_SCAN = "demo_cwe89_scan"
    CLEAN_NO_CANDIDATE = "clean_no_candidate"
    CONFIRMED_FINDING_WITHOUT_REPAIR = "confirmed_finding_without_repair"
    REPAIR_REQUESTED = "repair_requested"
    UNSUPPORTED_REQUIRED_LANGUAGE = "unsupported_required_language"


MODEL_STAGE_IDS: Final = frozenset(
    {
        "model_native_discovery",
        "auditor_investigation",
        "skeptic_review",
        "security_test_generation",
        "architect",
    }
)
ACCEPTED_STAGE_CATALOGUE_PIN: Final = (
    "core-mvp-0.2.0",
    "0.2.0",
    "\x61\x64\x61\x64\x32\x65\x30\x35\x66\x63\x38\x32\x32\x34\x38\x35\x66\x34\x35\x61\x63\x31\x36\x34\x32\x39\x39\x34\x36\x32\x64\x33\x36\x30\x65\x63\x62\x30\x31\x35\x33\x32\x37\x62\x38\x34\x64\x30\x39\x63\x30\x36\x34\x61\x36\x39\x37\x63\x31\x39\x33\x64\x31\x64",
)
KNOWN_STAGE_IDS: Final = frozenset(
    {
        "intake",
        "language_discovery",
        "python_parse_symbols",
        "secret_scan",
        "dependency_scan",
        "cwe89_scan",
        "deterministic_analysis",
        "model_native_discovery",
        "normalization",
        "evidence_graph",
        "auditor_investigation",
        "skeptic_review",
        "finding_gate",
        "root_cause_localization",
        "security_test_generation",
        "architect",
        "validation_ladder",
        "coverage_guard",
        "reporting",
    }
)
SCENARIO_ATOMIC_REQUIRED_STAGE_IDS: Final = {
    CoverageScenario.DEMO_CWE89_SCAN: frozenset(
        {
            "intake",
            "language_discovery",
            "python_parse_symbols",
            "secret_scan",
            "dependency_scan",
            "cwe89_scan",
            "model_native_discovery",
            "normalization",
            "evidence_graph",
            "coverage_guard",
            "reporting",
        }
    ),
    CoverageScenario.CLEAN_NO_CANDIDATE: frozenset(
        {
            "intake",
            "language_discovery",
            "deterministic_analysis",
            "model_native_discovery",
            "normalization",
            "coverage_guard",
            "reporting",
        }
    ),
    CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR: frozenset(
        {
            "intake",
            "language_discovery",
            "deterministic_analysis",
            "model_native_discovery",
            "normalization",
            "evidence_graph",
            "coverage_guard",
            "reporting",
        }
    ),
    CoverageScenario.REPAIR_REQUESTED: frozenset(
        {
            "intake",
            "language_discovery",
            "deterministic_analysis",
            "model_native_discovery",
            "normalization",
            "evidence_graph",
            "coverage_guard",
            "reporting",
        }
    ),
    CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE: frozenset(
        {
            "intake",
            "language_discovery",
            "deterministic_analysis",
            "coverage_guard",
            "reporting",
        }
    ),
}


class ComponentPin(WireModel):
    """Immutable ID/version/content tuple for an execution-semantic component."""

    component_id: OpaqueId
    component_version: SemVer
    content_sha256: Sha256


class RepositoryRevision(WireModel):
    """One immutable tenant-scoped SCM revision."""

    tenant_id: OpaqueId
    scm_provider: OpaqueId
    repository_id: OpaqueId
    head_sha: CommitSha
    base_sha: CommitSha | None = None

    @model_validator(mode="after")
    def _reject_identical_base_and_head(self) -> Self:
        if self.base_sha == self.head_sha:
            raise ValueError("base_sha and head_sha must identify different revisions")
        return self


def _canonical_sha256(value: object) -> str:
    """Hash the ASCII-only SecureCode canonical JSON identity subset.

    Identity fields contain only validated ASCII IDs, versions and hashes;
    mappings are key-sorted, extensions are namespace-sorted, numbers are
    bounded integers and insignificant whitespace is absent. This deliberately
    avoids implementation-dependent floats and unordered collections.
    """

    payload = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _require_extension_tenant(value: object, tenant_id: str) -> None:
    """Recursively bind every extension envelope to its public-root tenant."""

    if isinstance(value, WireModel):
        if any(extension.tenant_id != tenant_id for extension in value.extensions):
            raise ValueError("every extension must belong to the public-root tenant")
        for field_name in type(value).model_fields:
            _require_extension_tenant(getattr(value, field_name), tenant_id)
    elif isinstance(value, tuple):
        for item in value:
            _require_extension_tenant(item, tenant_id)
