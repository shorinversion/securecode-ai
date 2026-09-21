"""Versioned, provider-neutral domain contracts for SecureCode AI."""

from __future__ import annotations

import unicodedata
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any, Self

from pydantic import Field, field_validator, model_validator

from .base import (
    CONTRACT_SCHEMA_VERSION,
    ContractExtension,
    DataClass,
    OpaqueId,
    ReasonCode,
    SemVer,
    Sha256,
    WireModel,
)
from .domain_primitives import (
    ACCEPTED_STAGE_CATALOGUE_PIN,
    KNOWN_STAGE_IDS,
    MODEL_STAGE_IDS,
    SCENARIO_ATOMIC_REQUIRED_STAGE_IDS,
    CandidateOrigin,
    ComponentPin,
    CoverageScenario,
    CoverageStatus,
    DiscoveryLane,
    ModelCallStatus,
    NonNegativeInt,
    PositiveInt,
    RepositoryRevision,
    UtcTimestamp,
    _canonical_sha256,
)

if TYPE_CHECKING:
    from .domain_discovery import (
        CandidateInterpretationReceipt,
        DiscoveryCandidate,
        ModelDiscoveryReceipt,
    )


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

        model_candidates = tuple(
            candidate
            for candidate in self.discovery_candidates
            if candidate.candidate_origin in {CandidateOrigin.MODEL_NATIVE, CandidateOrigin.HYBRID}
        )
        receipt_candidate_ids = {
            candidate_id
            for receipt in self.model_discovery_receipts
            for candidate_id in receipt.candidate_ids
        }
        # Normalization may assign a current candidate ID while retaining the
        # immutable model-native producer ID in lineage.  The receipt bytes are
        # therefore never rewritten.  Every original receipt ID maps to exactly
        # one current model-bearing candidate, and every such candidate retains
        # at least one original discovery ID.  This is deliberately an ID-only
        # relation: ModelDiscoveryReceipt has no fingerprint/version field.
        predecessors = {
            candidate.candidate_id: {
                candidate.candidate_id,
                *(
                    source_id
                    for lineage in candidate.lineage
                    if lineage.lane is DiscoveryLane.MODEL_NATIVE
                    for source_id in lineage.input_candidate_ids
                ),
            }
            for candidate in model_candidates
        }
        if any(
            sum(candidate_id in values for values in predecessors.values()) != 1
            for candidate_id in receipt_candidate_ids
        ) or any(
            not values.intersection(receipt_candidate_ids) for values in predecessors.values()
        ):
            raise ValueError("model discovery receipts must preserve current model-native lineage")

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
