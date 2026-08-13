"""Versioned, provider-neutral domain contracts for SecureCode AI."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Any, Final, Self

from pydantic import AfterValidator, Field, field_validator, model_validator

from .base import (
    CONTRACT_SCHEMA_VERSION,
    CommitSha,
    ContractExtension,
    DataClass,
    OpaqueId,
    ReasonCode,
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
    "adad2e05fc822485f45ac164299462d360ecb015327b84d09c064a697c193d1d",
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


class RunExecutionIdentity(WireModel):
    """Canonical identity shared unchanged across every run transport."""

    repository_revision: RepositoryRevision
    stage_catalogue: ComponentPin
    workflow: ComponentPin
    policy: ComponentPin
    configuration: ComponentPin
    provider_profile: ComponentPin
    capability_profile: ComponentPin
    egress_profile: ComponentPin
    execution_identity_hash: Sha256

    def _material(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"execution_identity_hash"})

    @model_validator(mode="after")
    def _validate_execution_identity_hash(self) -> Self:
        if self.execution_identity_hash != _canonical_sha256(self._material()):
            raise ValueError("execution_identity_hash does not match canonical identity bytes")
        return self

    @classmethod
    def build(
        cls,
        *,
        repository_revision: RepositoryRevision,
        stage_catalogue: ComponentPin,
        workflow: ComponentPin,
        policy: ComponentPin,
        configuration: ComponentPin,
        provider_profile: ComponentPin,
        capability_profile: ComponentPin,
        egress_profile: ComponentPin,
        schema_version: SemVer = CONTRACT_SCHEMA_VERSION,
        extensions: tuple[ContractExtension, ...] = (),
    ) -> Self:
        """Build an identity while deriving its only valid canonical hash."""

        canonical_extensions = tuple(sorted(extensions, key=lambda item: item.namespace))
        material = {
            "schema_version": schema_version,
            "extensions": [extension.model_dump(mode="json") for extension in canonical_extensions],
            "repository_revision": repository_revision.model_dump(mode="json"),
            "stage_catalogue": stage_catalogue.model_dump(mode="json"),
            "workflow": workflow.model_dump(mode="json"),
            "policy": policy.model_dump(mode="json"),
            "configuration": configuration.model_dump(mode="json"),
            "provider_profile": provider_profile.model_dump(mode="json"),
            "capability_profile": capability_profile.model_dump(mode="json"),
            "egress_profile": egress_profile.model_dump(mode="json"),
        }
        return cls(
            schema_version=schema_version,
            extensions=canonical_extensions,
            repository_revision=repository_revision,
            stage_catalogue=stage_catalogue,
            workflow=workflow,
            policy=policy,
            configuration=configuration,
            provider_profile=provider_profile,
            capability_profile=capability_profile,
            egress_profile=egress_profile,
            execution_identity_hash=_canonical_sha256(material),
        )


class SourcePosition(WireModel):
    line: PositiveInt
    column: PositiveInt


class SourceLocation(WireModel):
    """Normalized repository-relative one-based source interval."""

    path: str = Field(min_length=1, max_length=1024)
    start: SourcePosition
    end: SourcePosition
    content_sha256: Sha256

    @field_validator("path")
    @classmethod
    def _validate_repository_path(cls, value: str) -> str:
        if (
            value != value.strip()
            or "\\" in value
            or not value
            or any(not char.isprintable() for char in value)
            or unicodedata.normalize("NFC", value) != value
        ):
            raise ValueError("path must be a normalized printable POSIX path")
        path = PurePosixPath(value)
        if not path.parts or path.is_absolute() or path.as_posix() != value:
            raise ValueError("path must be normalized and repository-relative")
        if any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("path cannot contain empty, current or parent segments")
        if path.parts[0].endswith(":"):
            raise ValueError("host drive paths are forbidden")
        return value

    @model_validator(mode="after")
    def _validate_interval(self) -> Self:
        start = (self.start.line, self.start.column)
        end = (self.end.line, self.end.column)
        if end < start:
            raise ValueError("source interval end must not precede start")
        return self


class ArtifactRef(WireModel):
    """Metadata-only content-addressed reference; never embeds artifact bytes."""

    tenant_id: OpaqueId
    content_id: OpaqueId
    content_sha256: Sha256
    size_bytes: NonNegativeInt
    data_class: DataClass
    expires_at: UtcTimestamp | None = None


class ProducerRef(WireModel):
    producer_id: OpaqueId
    producer_version: SemVer
    producer_sha256: Sha256


class LineageRef(WireModel):
    lineage_id: OpaqueId
    lane: DiscoveryLane
    producer: ProducerRef
    root_cause_fingerprint: Sha256
    input_signal_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=4096)
    input_candidate_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=4096)
    evidence_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=4096)

    @model_validator(mode="after")
    def _validate_unique_evidence_ids(self) -> Self:
        for field_name, values in (
            ("input_signal_ids", self.input_signal_ids),
            ("input_candidate_ids", self.input_candidate_ids),
            ("evidence_ids", self.evidence_ids),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"lineage {field_name} must be unique")
        if not self.input_signal_ids and not self.input_candidate_ids:
            raise ValueError("lineage must retain at least one input signal/candidate ID")
        return self


class CoverageUnit(WireModel):
    coverage_unit_id: OpaqueId
    stage_id: OpaqueId
    subject_id: OpaqueId | None = None
    required: bool
    applicable: bool
    coverage_status: CoverageStatus
    reason_code: ReasonCode | None = None
    producer_version: SemVer | None = None
    input_hashes: tuple[Sha256, ...] = Field(default=(), max_length=4096)
    output_hashes: tuple[Sha256, ...] = Field(default=(), max_length=4096)
    model_call_status: ModelCallStatus | None = None
    schema_valid_result: bool | None = None
    receipt_id: OpaqueId | None = None

    @model_validator(mode="after")
    def _validate_coverage_unit(self) -> Self:
        if self.coverage_status is CoverageStatus.NOT_APPLICABLE:
            if self.applicable:
                raise ValueError("an applicable stage cannot be NOT_APPLICABLE")
            if self.reason_code is None:
                raise ValueError("NOT_APPLICABLE requires a policy reason_code")
        elif not self.applicable:
            raise ValueError("a non-applicable stage must use NOT_APPLICABLE")
        if self.coverage_status is CoverageStatus.COMPLETED:
            if self.producer_version is None or not self.input_hashes or not self.output_hashes:
                raise ValueError("COMPLETED coverage requires producer and input/output hashes")
            if self.stage_id in MODEL_STAGE_IDS and (
                self.model_call_status is not ModelCallStatus.SUCCEEDED
                or self.schema_valid_result is not True
                or self.receipt_id is None
            ):
                raise ValueError(
                    "completed model coverage requires receipt and SUCCEEDED schema-valid output"
                )
            if self.model_call_status is not None and (
                self.model_call_status is not ModelCallStatus.SUCCEEDED
                or self.schema_valid_result is not True
            ):
                raise ValueError("completed model coverage requires SUCCEEDED schema-valid output")
        elif self.reason_code is None:
            raise ValueError("non-completed coverage requires reason_code")
        if self.model_call_status is None and self.schema_valid_result is not None:
            raise ValueError("schema_valid_result requires model_call_status")
        if (
            self.applicable
            and self.stage_id in MODEL_STAGE_IDS
            and (self.model_call_status is None or self.receipt_id is None)
        ):
            raise ValueError("applicable model stage requires status and receipt_id")
        if self.model_call_status is not None and self.receipt_id is None:
            raise ValueError("model_call_status requires receipt_id")
        return self

    @property
    def satisfies_required_coverage(self) -> bool:
        return self.coverage_status in {
            CoverageStatus.COMPLETED,
            CoverageStatus.NOT_APPLICABLE,
        }


class CoverageManifest(WireModel):
    catalogue: ComponentPin
    execution_identity_hash: Sha256
    scenario: CoverageScenario
    required_unit_ids: tuple[OpaqueId, ...] = Field(min_length=1, max_length=4096)
    units: tuple[CoverageUnit, ...] = Field(min_length=1, max_length=4096)
    discovery_candidates: tuple[DiscoveryCandidate, ...] = Field(default=(), max_length=100000)
    model_discovery_receipts: tuple[ModelDiscoveryReceipt, ...] = Field(default=(), max_length=128)
    candidate_interpretation_receipts: tuple[CandidateInterpretationReceipt, ...] = Field(
        default=(), max_length=100000
    )
    repair_requested_candidate_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=100000)
    coverage_complete: bool

    @model_validator(mode="after")
    def _validate_manifest(self) -> Self:
        expected_catalogue = ACCEPTED_STAGE_CATALOGUE_PIN
        actual_catalogue = (
            self.catalogue.component_id,
            self.catalogue.component_version,
            self.catalogue.content_sha256,
        )
        if actual_catalogue != expected_catalogue:
            raise ValueError("coverage requires the exact accepted stage catalogue pin")
        if len(self.required_unit_ids) != len(set(self.required_unit_ids)):
            raise ValueError("required_unit_ids must be unique")
        units_by_id = {unit.coverage_unit_id: unit for unit in self.units}
        if len(units_by_id) != len(self.units):
            raise ValueError("coverage_unit_id values must be unique")
        unknown_stages = {unit.stage_id for unit in self.units} - KNOWN_STAGE_IDS
        if unknown_stages:
            raise ValueError("coverage contains a stage unknown to the accepted catalogue")
        declared_required = {unit.coverage_unit_id for unit in self.units if unit.required}
        if set(self.required_unit_ids) != declared_required:
            raise ValueError("required_unit_ids must exactly enumerate every required unit")
        required_units = tuple(unit for unit in self.units if unit.required)
        if any(not unit.applicable for unit in required_units):
            raise ValueError("pinned scenario mandatory units must remain applicable")
        if self.scenario is CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE and not any(
            unit.stage_id == "deterministic_analysis"
            and unit.coverage_status is CoverageStatus.UNSUPPORTED
            for unit in required_units
        ):
            raise ValueError("unsupported-language scenario requires an UNSUPPORTED analysis unit")
        expected_keys = self._expected_required_unit_keys()
        actual_keys = {(unit.stage_id, unit.subject_id) for unit in required_units}
        if actual_keys != expected_keys or len(actual_keys) != len(required_units):
            raise ValueError("required units do not match the pinned catalogue scenario snapshot")
        structurally_complete = all(
            units_by_id[unit_id].satisfies_required_coverage for unit_id in self.required_unit_ids
        )
        receipt_complete = self._validate_receipts(units_by_id)
        complete = structurally_complete and receipt_complete
        if self.coverage_complete is not complete:
            raise ValueError("coverage_complete does not match mandatory unit evidence")
        return self

    def _expected_required_unit_keys(self) -> set[tuple[str, str | None]]:
        candidates = {candidate.candidate_id for candidate in self.discovery_candidates}
        repair_ids = set(self.repair_requested_candidate_ids)
        if len(repair_ids) != len(self.repair_requested_candidate_ids):
            raise ValueError("repair_requested_candidate_ids must be unique")
        if not repair_ids.issubset(candidates):
            raise ValueError("repair requests must reference current discovery candidates")
        candidate_scenarios = {
            CoverageScenario.DEMO_CWE89_SCAN,
            CoverageScenario.CONFIRMED_FINDING_WITHOUT_REPAIR,
            CoverageScenario.REPAIR_REQUESTED,
        }
        if self.scenario in candidate_scenarios and not candidates:
            raise ValueError("candidate scenario requires at least one current candidate")
        if self.scenario not in candidate_scenarios and candidates:
            raise ValueError("zero-candidate/unsupported scenario cannot contain candidates")
        if self.scenario is CoverageScenario.REPAIR_REQUESTED:
            if not repair_ids:
                raise ValueError("repair_requested scenario requires a repair request")
        elif repair_ids:
            raise ValueError("repair requests are valid only in the repair_requested scenario")

        expected: set[tuple[str, str | None]] = {
            (stage_id, None) for stage_id in SCENARIO_ATOMIC_REQUIRED_STAGE_IDS[self.scenario]
        }
        if self.scenario in candidate_scenarios:
            for candidate_id in candidates:
                expected.update(
                    {
                        ("auditor_investigation", candidate_id),
                        ("skeptic_review", candidate_id),
                        ("finding_gate", candidate_id),
                    }
                )
        if self.scenario is CoverageScenario.REPAIR_REQUESTED:
            for candidate_id in repair_ids:
                expected.update(
                    {
                        ("root_cause_localization", candidate_id),
                        ("security_test_generation", candidate_id),
                        ("architect", candidate_id),
                        ("validation_ladder", candidate_id),
                    }
                )
        return expected

    def _validate_receipts(self, units_by_id: dict[str, CoverageUnit]) -> bool:
        del units_by_id  # unit uniqueness and required completeness are checked by the caller
        if self.scenario is CoverageScenario.UNSUPPORTED_REQUIRED_LANGUAGE:
            if self.model_discovery_receipts or self.candidate_interpretation_receipts:
                raise ValueError("unsupported-language scenario cannot claim model receipts")
            return True
        candidate_keys = [
            (candidate.candidate_id, candidate.candidate_version)
            for candidate in self.discovery_candidates
        ]
        if len(candidate_keys) != len(set(candidate_keys)):
            raise ValueError("discovery candidate ID/version pairs must be unique")
        if len({candidate.candidate_id for candidate in self.discovery_candidates}) != len(
            self.discovery_candidates
        ):
            raise ValueError("manifest must contain only the current version of each candidate")

        discovery_by_id = {receipt.receipt_id: receipt for receipt in self.model_discovery_receipts}
        if len(discovery_by_id) != len(self.model_discovery_receipts):
            raise ValueError("model discovery receipt IDs must be unique")
        interpretation_keys = [
            (receipt.candidate_id, receipt.candidate_version)
            for receipt in self.candidate_interpretation_receipts
        ]
        if len(interpretation_keys) != len(set(interpretation_keys)):
            raise ValueError("each candidate version must have exactly one interpretation receipt")
        if set(interpretation_keys) != set(candidate_keys):
            raise ValueError("interpretation receipts must exactly cover current candidates")
        interpretation_by_id = {
            receipt.receipt_id: receipt for receipt in self.candidate_interpretation_receipts
        }
        if len(interpretation_by_id) != len(self.candidate_interpretation_receipts):
            raise ValueError("interpretation receipt IDs must be unique")

        model_native_units = [
            unit
            for unit in self.units
            if unit.stage_id == "model_native_discovery" and unit.applicable
        ]
        if len(model_native_units) != 1:
            raise ValueError("manifest requires exactly one applicable model-native coverage unit")
        model_native_receipt = discovery_by_id.get(model_native_units[0].receipt_id or "")
        if model_native_receipt is None:
            raise ValueError("model-native coverage unit must reference its discovery receipt")
        if (
            model_native_units[0].model_call_status is not model_native_receipt.model_call_status
            or model_native_units[0].schema_valid_result
            is not model_native_receipt.schema_valid_result
        ):
            raise ValueError("model-native coverage status must match its discovery receipt")

        model_candidate_ids = {
            candidate.candidate_id
            for candidate in self.discovery_candidates
            if candidate.candidate_origin in {CandidateOrigin.MODEL_NATIVE, CandidateOrigin.HYBRID}
        }
        receipt_candidate_ids = {
            candidate_id
            for receipt in self.model_discovery_receipts
            for candidate_id in receipt.candidate_ids
        }
        if receipt_candidate_ids != model_candidate_ids:
            raise ValueError("model discovery receipts must preserve all model-native candidates")

        candidate_ids = {candidate.candidate_id for candidate in self.discovery_candidates}
        for stage_id in ("auditor_investigation", "finding_gate"):
            stage_subjects = {
                unit.subject_id
                for unit in self.units
                if unit.stage_id == stage_id and unit.required and unit.applicable
            }
            if stage_subjects != candidate_ids:
                raise ValueError(f"{stage_id} coverage must exactly cover current candidates")
        for unit in self.units:
            if unit.stage_id != "auditor_investigation" or not unit.applicable:
                continue
            receipt = interpretation_by_id.get(unit.receipt_id or "")
            if receipt is None or receipt.candidate_id != unit.subject_id:
                raise ValueError("Auditor coverage must reference its candidate interpretation")
            if (
                unit.model_call_status is not receipt.model_call_status
                or unit.schema_valid_result is not receipt.schema_valid_result
            ):
                raise ValueError("Auditor coverage status must match its interpretation receipt")

        return (
            model_native_receipt.model_call_status is ModelCallStatus.SUCCEEDED
            and model_native_receipt.schema_valid_result
            and all(
                receipt.model_call_status is ModelCallStatus.SUCCEEDED
                and receipt.schema_valid_result
                for receipt in self.candidate_interpretation_receipts
            )
        )


class RawSignal(WireModel):
    """Untrusted deterministic fact; intentionally has no verdict field."""

    raw_signal_id: OpaqueId
    tenant_id: OpaqueId
    head_sha: CommitSha
    producer: ProducerRef
    rule_id: OpaqueId
    location: SourceLocation
    payload_classification: DataClass
    payload_ref: ArtifactRef | None = None
    signal_sha256: Sha256

    @model_validator(mode="after")
    def _require_sensitive_payload_reference(self) -> Self:
        if self.payload_classification in {
            DataClass.CONFIDENTIAL_SOURCE,
            DataClass.RESTRICTED,
        } and (
            self.payload_ref is None
            or self.payload_ref.data_class is not self.payload_classification
        ):
            raise ValueError("DC3/DC4 signal payload requires a same-class ArtifactRef")
        if self.payload_ref is not None and self.payload_ref.tenant_id != self.tenant_id:
            raise ValueError("signal and payload reference must belong to the same tenant")
        return self


class DiscoveryCandidate(WireModel):
    candidate_id: OpaqueId
    tenant_id: OpaqueId
    candidate_version: PositiveInt
    head_sha: CommitSha
    root_cause_fingerprint: Sha256
    candidate_origin: CandidateOrigin
    lineage: tuple[LineageRef, ...] = Field(min_length=1, max_length=4096)
    evidence_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=4096)

    @model_validator(mode="after")
    def _validate_origin_lineage(self) -> Self:
        _validate_origin(
            self.candidate_origin,
            self.root_cause_fingerprint,
            self.lineage,
        )
        lineage_ids = [item.lineage_id for item in self.lineage]
        if len(lineage_ids) != len(set(lineage_ids)):
            raise ValueError("candidate lineage IDs must be unique")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("candidate evidence IDs must be unique")
        lineage_evidence_ids = {
            evidence_id for item in self.lineage for evidence_id in item.evidence_ids
        }
        if not lineage_evidence_ids.issubset(self.evidence_ids):
            raise ValueError("candidate must retain every lineage evidence ID")
        return self


class ModelBudgetUsage(WireModel):
    token_limit: PositiveInt
    tokens_used: NonNegativeInt
    repository_call_limit: PositiveInt
    repository_calls_used: NonNegativeInt
    time_limit_ms: PositiveInt
    elapsed_ms: NonNegativeInt

    @model_validator(mode="after")
    def _validate_limits(self) -> Self:
        if self.tokens_used > self.token_limit:
            raise ValueError("tokens_used exceeds token_limit")
        if self.repository_calls_used > self.repository_call_limit:
            raise ValueError("repository_calls_used exceeds repository_call_limit")
        if self.elapsed_ms > self.time_limit_ms:
            raise ValueError("elapsed_ms exceeds time_limit_ms")
        return self


class ModelDiscoveryReceipt(WireModel):
    receipt_id: OpaqueId
    tenant_id: OpaqueId
    head_sha: CommitSha
    scope_sha256: Sha256
    model_profile: ComponentPin
    prompt: ComponentPin
    repository_view_call_hashes: tuple[Sha256, ...] = Field(default=(), max_length=4096)
    budget_usage: ModelBudgetUsage
    model_call_status: ModelCallStatus
    schema_valid_result: bool
    input_sha256: Sha256
    output_sha256: Sha256 | None = None
    candidate_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=4096)

    @model_validator(mode="after")
    def _validate_model_result(self) -> Self:
        if self.model_call_status is ModelCallStatus.SUCCEEDED:
            if not self.schema_valid_result or self.output_sha256 is None:
                raise ValueError("SUCCEEDED discovery requires schema-valid output and output hash")
        elif self.schema_valid_result or self.candidate_ids:
            raise ValueError("non-success discovery cannot claim valid candidates or coverage")
        if len(self.candidate_ids) != len(set(self.candidate_ids)):
            raise ValueError("candidate_ids must be unique")
        return self

    @property
    def is_completed_zero(self) -> bool:
        return (
            self.model_call_status is ModelCallStatus.SUCCEEDED
            and self.schema_valid_result
            and not self.candidate_ids
        )


class CandidateInterpretationReceipt(WireModel):
    receipt_id: OpaqueId
    tenant_id: OpaqueId
    candidate_id: OpaqueId
    candidate_version: PositiveInt
    head_sha: CommitSha
    auditor: ComponentPin
    model_profile: ComponentPin
    prompt: ComponentPin
    evidence_sha256: Sha256
    model_call_status: ModelCallStatus
    schema_valid_result: bool
    verdict_ref: OpaqueId | None = None
    input_sha256: Sha256
    output_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def _validate_terminal_interpretation(self) -> Self:
        if self.model_call_status is ModelCallStatus.SUCCEEDED:
            if (
                not self.schema_valid_result
                or self.verdict_ref is None
                or self.output_sha256 is None
            ):
                raise ValueError("SUCCEEDED interpretation requires schema-valid verdict output")
        elif self.schema_valid_result or self.verdict_ref is not None:
            raise ValueError("non-success interpretation cannot claim a valid verdict")
        return self


class Evidence(WireModel):
    evidence_id: OpaqueId
    tenant_id: OpaqueId
    head_sha: CommitSha
    evidence_kind: EvidenceKind
    producer: ProducerRef
    trust_label: TrustLabel
    data_class: DataClass
    evidence_sha256: Sha256
    location: SourceLocation | None = None
    artifact_ref: ArtifactRef | None = None

    @model_validator(mode="after")
    def _validate_sensitive_reference(self) -> Self:
        if self.data_class in {
            DataClass.CONFIDENTIAL_SOURCE,
            DataClass.RESTRICTED,
        } and (self.artifact_ref is None or self.artifact_ref.data_class is not self.data_class):
            raise ValueError("DC3/DC4 evidence requires a same-class ArtifactRef")
        if self.artifact_ref is not None and self.artifact_ref.tenant_id != self.tenant_id:
            raise ValueError("evidence and artifact reference must belong to the same tenant")
        _require_extension_tenant(self, self.tenant_id)
        return self


def _validate_origin(
    origin: CandidateOrigin,
    root_cause_fingerprint: str,
    lineage: tuple[LineageRef, ...],
) -> None:
    lanes = {item.lane for item in lineage}
    expected = {
        CandidateOrigin.DETERMINISTIC: {DiscoveryLane.DETERMINISTIC},
        CandidateOrigin.MODEL_NATIVE: {DiscoveryLane.MODEL_NATIVE},
        CandidateOrigin.HYBRID: {DiscoveryLane.DETERMINISTIC, DiscoveryLane.MODEL_NATIVE},
    }[origin]
    if lanes != expected:
        raise ValueError("candidate_origin does not match immutable discovery lineage")
    if any(item.root_cause_fingerprint != root_cause_fingerprint for item in lineage):
        raise ValueError("all merged lineage must resolve to the same root-cause fingerprint")


class FindingCase(WireModel):
    finding_id: OpaqueId
    candidate_id: OpaqueId
    candidate_version: PositiveInt
    repository_revision: RepositoryRevision
    root_cause_fingerprint: Sha256
    candidate_origin: CandidateOrigin
    producer_lineage: tuple[LineageRef, ...] = Field(min_length=1, max_length=4096)
    locations: tuple[SourceLocation, ...] = Field(min_length=1, max_length=4096)
    cwe_id: str = Field(pattern=r"^CWE-[1-9][0-9]{0,5}$", max_length=10)
    evidence_graph_ref: ArtifactRef
    evidence_ids: tuple[OpaqueId, ...] = Field(min_length=1, max_length=4096)
    interpretation_receipt_id: OpaqueId
    finding_verdict: FindingVerdict
    verdict_evidence_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=4096)
    blocking: bool

    @model_validator(mode="after")
    def _validate_finding(self) -> Self:
        _validate_origin(
            self.candidate_origin,
            self.root_cause_fingerprint,
            self.producer_lineage,
        )
        lineage_ids = [item.lineage_id for item in self.producer_lineage]
        if len(lineage_ids) != len(set(lineage_ids)):
            raise ValueError("finding producer lineage IDs must be unique")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("finding evidence_ids must be unique")
        if not set(self.verdict_evidence_ids).issubset(self.evidence_ids):
            raise ValueError("verdict evidence must reference finding evidence_ids")
        if (
            self.finding_verdict
            in {
                FindingVerdict.CONFIRMED,
                FindingVerdict.REJECTED_WITH_EVIDENCE,
            }
            and not self.verdict_evidence_ids
        ):
            raise ValueError("terminal positive/negative verdict requires cited evidence")
        if self.evidence_graph_ref.tenant_id != self.repository_revision.tenant_id:
            raise ValueError("finding and EvidenceGraph reference must belong to the same tenant")
        _require_extension_tenant(self, self.repository_revision.tenant_id)
        return self


class PatchCandidate(WireModel):
    patch_id: OpaqueId
    finding_id: OpaqueId
    repository_revision: RepositoryRevision
    unified_diff_sha256: Sha256
    diff_ref: ArtifactRef
    author: ProducerRef
    patch_status: PatchStatus
    parent_patch_id: OpaqueId | None = None

    @model_validator(mode="after")
    def _validate_diff_reference(self) -> Self:
        if self.diff_ref.content_sha256 != self.unified_diff_sha256:
            raise ValueError("diff_ref hash must match unified_diff_sha256")
        if self.diff_ref.data_class is not DataClass.CONFIDENTIAL_SOURCE:
            raise ValueError("diff bytes require a DC3_CONFIDENTIAL_SOURCE ArtifactRef")
        if self.diff_ref.tenant_id != self.repository_revision.tenant_id:
            raise ValueError("patch and diff reference must belong to the same tenant")
        _require_extension_tenant(self, self.repository_revision.tenant_id)
        return self


class ResourceUsage(WireModel):
    elapsed_ms: NonNegativeInt
    peak_memory_bytes: NonNegativeInt
    cpu_time_ms: NonNegativeInt


class ValidationGateResult(WireModel):
    ordinal: PositiveInt
    gate_id: OpaqueId
    gate_outcome: ValidationGateOutcome
    producer: ProducerRef
    input_hashes: tuple[Sha256, ...] = Field(min_length=1, max_length=4096)
    output_hashes: tuple[Sha256, ...] = Field(default=(), max_length=4096)
    reason_code: ReasonCode | None = None
    resource_usage: ResourceUsage

    @model_validator(mode="after")
    def _validate_gate(self) -> Self:
        if self.gate_outcome is ValidationGateOutcome.PASSED and not self.output_hashes:
            raise ValueError("PASSED validation gate requires output hashes")
        if self.gate_outcome is not ValidationGateOutcome.PASSED and self.reason_code is None:
            raise ValueError("non-passing validation gate requires reason_code")
        return self


class ValidationResult(WireModel):
    validation_id: OpaqueId
    tenant_id: OpaqueId
    patch_id: OpaqueId
    head_sha: CommitSha
    sandbox_profile: ComponentPin
    gates: tuple[ValidationGateResult, ...] = Field(min_length=1, max_length=128)
    validation_outcome: ValidationOutcome
    result_sha256: Sha256

    @model_validator(mode="after")
    def _validate_ordered_gates(self) -> Self:
        ordinals = [gate.ordinal for gate in self.gates]
        if ordinals != list(range(1, len(self.gates) + 1)):
            raise ValueError("validation gate ordinals must be contiguous and ordered")
        if self.validation_outcome is ValidationOutcome.VALIDATED and any(
            gate.gate_outcome is not ValidationGateOutcome.PASSED for gate in self.gates
        ):
            raise ValueError("VALIDATED requires every ordered gate to pass")
        _require_extension_tenant(self, self.tenant_id)
        return self


class Decision(WireModel):
    decision_id: OpaqueId
    actor_id: OpaqueId
    policy: ComponentPin
    decided_at: UtcTimestamp
    scope_sha256: Sha256
    head_sha: CommitSha
    decision_outcome: DecisionOutcome
    reason_code: ReasonCode


class AuditRun(WireModel):
    run_id: OpaqueId
    execution_identity: RunExecutionIdentity
    current_head_sha: CommitSha
    audit_outcome: AuditRunOutcome
    analysis_health: AnalysisHealth
    finding_gate_state: FindingGateState
    coverage_manifest: CoverageManifest
    finding_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=100000)
    blocking_finding_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=100000)
    unresolved_gate_ids: tuple[OpaqueId, ...] = Field(default=(), max_length=100000)
    publication_preconditions_met: bool
    cancelled: bool = False
    created_at: UtcTimestamp
    completed_at: UtcTimestamp

    @model_validator(mode="after")
    def _validate_run_outcome(self) -> Self:
        if len(self.finding_ids) != len(set(self.finding_ids)):
            raise ValueError("finding_ids must be unique")
        if len(self.blocking_finding_ids) != len(set(self.blocking_finding_ids)):
            raise ValueError("blocking_finding_ids must be unique")
        if not set(self.blocking_finding_ids).issubset(self.finding_ids):
            raise ValueError("blocking_finding_ids must reference finding_ids")
        if len(self.unresolved_gate_ids) != len(set(self.unresolved_gate_ids)):
            raise ValueError("unresolved_gate_ids must be unique")
        if self.completed_at < self.created_at:
            raise ValueError("completed_at cannot precede created_at")
        if self.coverage_manifest.catalogue != self.execution_identity.stage_catalogue:
            raise ValueError("coverage catalogue must equal the execution identity pin")
        if (
            self.coverage_manifest.execution_identity_hash
            != self.execution_identity.execution_identity_hash
        ):
            raise ValueError("coverage manifest must bind the exact execution identity hash")
        revision_head = self.execution_identity.repository_revision.head_sha
        revision_tenant = self.execution_identity.repository_revision.tenant_id
        if any(
            candidate.head_sha != revision_head
            for candidate in self.coverage_manifest.discovery_candidates
        ):
            raise ValueError("every discovery candidate must bind to the execution HEAD")
        if any(
            receipt.head_sha != revision_head
            for receipt in self.coverage_manifest.model_discovery_receipts
        ) or any(
            receipt.head_sha != revision_head
            for receipt in self.coverage_manifest.candidate_interpretation_receipts
        ):
            raise ValueError("every model receipt must bind to the execution HEAD")
        if (
            any(
                candidate.tenant_id != revision_tenant
                for candidate in self.coverage_manifest.discovery_candidates
            )
            or any(
                receipt.tenant_id != revision_tenant
                for receipt in self.coverage_manifest.model_discovery_receipts
            )
            or any(
                receipt.tenant_id != revision_tenant
                for receipt in self.coverage_manifest.candidate_interpretation_receipts
            )
        ):
            raise ValueError("every candidate and model receipt must bind to the execution tenant")

        has_blocking = bool(self.blocking_finding_ids)
        if has_blocking is not (self.finding_gate_state is FindingGateState.BLOCKING):
            raise ValueError("finding_gate_state must agree with blocking_finding_ids")

        if self.current_head_sha != revision_head:
            expected_outcome = AuditRunOutcome.SUPERSEDED
        elif self.cancelled:
            expected_outcome = AuditRunOutcome.CANCELLED
        elif has_blocking:
            expected_outcome = AuditRunOutcome.FAIL
        elif self.analysis_health is AnalysisHealth.UNAVAILABLE:
            expected_outcome = AuditRunOutcome.ERROR
        elif (
            self.analysis_health is not AnalysisHealth.HEALTHY
            or self.finding_gate_state is FindingGateState.INCONCLUSIVE
            or not self.coverage_manifest.coverage_complete
            or self.unresolved_gate_ids
            or not self.publication_preconditions_met
        ):
            expected_outcome = AuditRunOutcome.INDETERMINATE
        else:
            expected_outcome = AuditRunOutcome.PASS
        if self.audit_outcome is not expected_outcome:
            raise ValueError(
                f"audit_outcome must be {expected_outcome.value} for recorded evidence"
            )
        _require_extension_tenant(self, revision_tenant)
        return self


CoverageManifest.model_rebuild()
AuditRun.model_rebuild()


PUBLIC_ROOT_MODELS: dict[str, type[WireModel]] = {
    "audit-run": AuditRun,
    "evidence": Evidence,
    "finding-case": FindingCase,
    "patch-candidate": PatchCandidate,
    "validation-result": ValidationResult,
}

__all__ = [
    "PUBLIC_ROOT_MODELS",
    "AnalysisHealth",
    "ArtifactRef",
    "AuditRun",
    "AuditRunOutcome",
    "CandidateInterpretationReceipt",
    "CandidateOrigin",
    "ComponentPin",
    "CoverageManifest",
    "CoverageStatus",
    "CoverageUnit",
    "DataClass",
    "Decision",
    "DecisionOutcome",
    "DiscoveryCandidate",
    "DiscoveryLane",
    "Evidence",
    "EvidenceKind",
    "FindingCase",
    "FindingGateState",
    "FindingVerdict",
    "LineageRef",
    "ModelBudgetUsage",
    "ModelCallStatus",
    "ModelDiscoveryReceipt",
    "PatchCandidate",
    "PatchStatus",
    "ProducerRef",
    "RawSignal",
    "RepositoryRevision",
    "ResourceUsage",
    "RunExecutionIdentity",
    "SourceLocation",
    "SourcePosition",
    "TrustLabel",
    "ValidationGateOutcome",
    "ValidationGateResult",
    "ValidationOutcome",
    "ValidationResult",
]
