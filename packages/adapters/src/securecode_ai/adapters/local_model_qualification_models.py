from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.core import (
    AuditRunOutcome,
    ComponentPin,
    ModelCallStatus,
    ModelRequest,
)
from securecode_ai.core.model_discovery import ModelDiscoveryReceipt, ModelPurpose, ModelRole
from securecode_ai.core.tool_policy import (
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryTool,
    RepositoryToolReceipt,
    RepositoryToolRequest,
    ToolOutcome,
)

from .openai_compatible_local import OpenAICompatibleLocalHttpConnector

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_LICENSE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_SAFE_INT: Final = 9_007_199_254_740_991
_TOOL_ARGUMENT_TYPES: Final = {
    RepositoryTool.LIST_PATHS: ListPathsArguments,
    RepositoryTool.LOOKUP_SYMBOL: LookupSymbolArguments,
    RepositoryTool.READ_RANGE: ReadRangeArguments,
    RepositoryTool.READ_EVIDENCE: ReadEvidenceArguments,
}
_LOCAL_CONNECTOR_TYPE: Final = (
    f"{OpenAICompatibleLocalHttpConnector.__module__}."
    f"{OpenAICompatibleLocalHttpConnector.__qualname__}"
)


class QualificationState(StrEnum):
    AWAITING_REAL_EVIDENCE = "AWAITING_REAL_EVIDENCE"
    REAL_EVIDENCE_RECORDED = "REAL_EVIDENCE_RECORDED"


class HardwareMemorySource(StrEnum):
    RUNTIME_REPORTED = "RUNTIME_REPORTED"
    PLATFORM_REPORTED = "PLATFORM_REPORTED"
    PLATFORM_UNRELIABLE = "PLATFORM_UNRELIABLE"
    UNAVAILABLE = "UNAVAILABLE"


class QualificationErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    EVIDENCE_INVALID = "EVIDENCE_INVALID"


class LocalModelQualificationError(ValueError):
    __slots__ = ("code",)

    def __init__(self, code: QualificationErrorCode) -> None:
        if type(code) is not QualificationErrorCode:
            raise TypeError("qualification error code is invalid")
        self.code = code
        super().__init__("local model qualification failed")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class LocalModelArtifact:
    model_tag: str
    manifest_sha256: str
    size_bytes: int
    artifact_format: str
    architecture: str
    parameter_size_label: str
    quantization: str
    license_spdx: str
    license_text_sha256: str
    license_source_id: str
    license_restrictions: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.model_tag,
                    self.artifact_format,
                    self.architecture,
                    self.parameter_size_label,
                    self.quantization,
                    self.license_source_id,
                )
            )
            or type(self.manifest_sha256) is not str
            or _SHA256.fullmatch(self.manifest_sha256) is None
            or type(self.size_bytes) is not int
            or not 1 <= self.size_bytes <= _MAX_SAFE_INT
            or type(self.license_spdx) is not str
            or _LICENSE.fullmatch(self.license_spdx) is None
            or type(self.license_text_sha256) is not str
            or _SHA256.fullmatch(self.license_text_sha256) is None
            or type(self.license_restrictions) is not tuple
            or any(
                type(item) is not str or _ID.fullmatch(item) is None
                for item in self.license_restrictions
            )
            or len(self.license_restrictions) != len(set(self.license_restrictions))
        ):
            raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
        object.__setattr__(self, "license_restrictions", tuple(sorted(self.license_restrictions)))


@dataclass(frozen=True, slots=True)
class LocalRuntimeSnapshot:
    runtime_id: str
    runtime_version: str
    runtime_sha256: str
    connector_type: str = _LOCAL_CONNECTOR_TYPE

    def __post_init__(self) -> None:
        if (
            type(self.runtime_id) is not str
            or _ID.fullmatch(self.runtime_id) is None
            or type(self.runtime_version) is not str
            or not re.fullmatch(
                r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", self.runtime_version
            )
            or type(self.runtime_sha256) is not str
            or _SHA256.fullmatch(self.runtime_sha256) is None
            or self.connector_type != _LOCAL_CONNECTOR_TYPE
        ):
            raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class GpuHardwareSnapshot:
    adapter_id: str
    reported_memory_bytes: int | None
    memory_source: HardwareMemorySource

    def __post_init__(self) -> None:
        if (
            type(self.adapter_id) is not str
            or _ID.fullmatch(self.adapter_id) is None
            or type(self.memory_source) is not HardwareMemorySource
            or (
                self.reported_memory_bytes is not None
                and (
                    type(self.reported_memory_bytes) is not int
                    or not 0 <= self.reported_memory_bytes <= _MAX_SAFE_INT
                )
            )
            or (
                self.memory_source is HardwareMemorySource.UNAVAILABLE
                and self.reported_memory_bytes is not None
            )
        ):
            raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class HardwareSnapshot:
    cpu_model: str
    cpu_physical_cores: int
    cpu_logical_cores: int
    physical_ram_bytes: int
    gpus: tuple[GpuHardwareSnapshot, ...]

    def __post_init__(self) -> None:
        if (
            type(self.cpu_model) is not str
            or not 1 <= len(self.cpu_model) <= 256
            or any(not character.isprintable() for character in self.cpu_model)
            or type(self.cpu_physical_cores) is not int
            or type(self.cpu_logical_cores) is not int
            or not 1 <= self.cpu_physical_cores <= self.cpu_logical_cores <= 65_536
            or type(self.physical_ram_bytes) is not int
            or not 1 <= self.physical_ram_bytes <= _MAX_SAFE_INT
            or type(self.gpus) is not tuple
            or any(type(item) is not GpuHardwareSnapshot for item in self.gpus)
            or len({item.adapter_id for item in self.gpus}) != len(self.gpus)
        ):
            raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
        object.__setattr__(self, "gpus", tuple(sorted(self.gpus, key=lambda item: item.adapter_id)))


@dataclass(frozen=True, slots=True)
class LocalModelQualificationRequest:
    """Trusted generic input to be filled from real closing-cycle observations."""

    qualification_id: str
    artifact: LocalModelArtifact
    runtime: LocalRuntimeSnapshot
    hardware: HardwareSnapshot
    provider_profile: ComponentPin
    connector: ComponentPin
    structured_request: ModelRequest
    repository_view_request: RepositoryToolRequest
    expected_repository_scope_sha256: str
    monetary_cost_usd_micros: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.qualification_id) is not str
            or _ID.fullmatch(self.qualification_id) is None
            or type(self.artifact) is not LocalModelArtifact
            or type(self.runtime) is not LocalRuntimeSnapshot
            or type(self.hardware) is not HardwareSnapshot
            or type(self.provider_profile) is not ComponentPin
            or type(self.connector) is not ComponentPin
            or type(self.structured_request) is not ModelRequest
            or type(self.repository_view_request) is not RepositoryToolRequest
            or type(self.expected_repository_scope_sha256) is not str
            or _SHA256.fullmatch(self.expected_repository_scope_sha256) is None
            or type(self.monetary_cost_usd_micros) is not int
            or self.monetary_cost_usd_micros != 0
        ):
            raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
        artifact = _copy_artifact(self.artifact)
        runtime = _copy_runtime(self.runtime)
        hardware = _copy_hardware(self.hardware)
        provider_profile = _copy_pin(self.provider_profile)
        connector = _copy_pin(self.connector)
        request = _copy_model_request(self.structured_request)
        repository_view_request = _copy_tool_request(self.repository_view_request)
        object.__setattr__(self, "artifact", artifact)
        object.__setattr__(self, "runtime", runtime)
        object.__setattr__(self, "hardware", hardware)
        object.__setattr__(self, "provider_profile", provider_profile)
        object.__setattr__(self, "connector", connector)
        object.__setattr__(self, "structured_request", request)
        object.__setattr__(self, "repository_view_request", repository_view_request)
        arguments = repository_view_request.arguments
        if (
            request.role is not ModelRole.DISCOVERY
            or request.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY
            or request.evidence
            or request.model_id != artifact.model_tag
            or request.provider_profile != provider_profile
            or type(repository_view_request.tool) is not RepositoryTool
            or type(arguments) is not _TOOL_ARGUMENT_TYPES[repository_view_request.tool]
            or arguments.head_sha != request.head_sha
        ):
            raise LocalModelQualificationError(QualificationErrorCode.IDENTITY_MISMATCH)

    @property
    def request_sha256(self) -> str:
        return _sha256(
            _canonical_bytes(
                {
                    "artifact": _artifact_material(self.artifact),
                    "connector": self.connector.model_dump(mode="json"),
                    "hardware": _hardware_material(self.hardware),
                    "monetary_cost_usd_micros": self.monetary_cost_usd_micros,
                    "expected_repository_scope_sha256": self.expected_repository_scope_sha256,
                    "provider_profile": self.provider_profile.model_dump(mode="json"),
                    "qualification_id": self.qualification_id,
                    "repository_view_request": _tool_request_material(self.repository_view_request),
                    "runtime": _runtime_material(self.runtime),
                    "structured_request": self.structured_request.model_dump(mode="json"),
                }
            )
        )


@dataclass(frozen=True, slots=True)
class LocalModelQualificationEvidence:
    """Four real P3.10 outcomes proving success, completed-zero and fault paths."""

    successful_discovery: ModelDiscoveryReceipt
    completed_zero_discovery: ModelDiscoveryReceipt
    provider_fault_discovery: ModelDiscoveryReceipt
    tool_fault_discovery: ModelDiscoveryReceipt
    repository_tool_receipt: RepositoryToolReceipt
    tool_fault_receipt: RepositoryToolReceipt

    def __post_init__(self) -> None:
        receipts = (
            self.successful_discovery,
            self.completed_zero_discovery,
            self.provider_fault_discovery,
            self.tool_fault_discovery,
        )
        if (
            any(type(item) is not ModelDiscoveryReceipt for item in receipts)
            or type(self.repository_tool_receipt) is not RepositoryToolReceipt
            or type(self.tool_fault_receipt) is not RepositoryToolReceipt
        ):
            raise LocalModelQualificationError(QualificationErrorCode.EVIDENCE_INVALID)
        copied_receipts = tuple(_copy_discovery_receipt(item) for item in receipts)
        repository_tool_receipt = _copy_tool_receipt(self.repository_tool_receipt)
        tool_fault_receipt = _copy_tool_receipt(self.tool_fault_receipt)
        object.__setattr__(self, "successful_discovery", copied_receipts[0])
        object.__setattr__(self, "completed_zero_discovery", copied_receipts[1])
        object.__setattr__(self, "provider_fault_discovery", copied_receipts[2])
        object.__setattr__(self, "tool_fault_discovery", copied_receipts[3])
        object.__setattr__(self, "repository_tool_receipt", repository_tool_receipt)
        object.__setattr__(self, "tool_fault_receipt", tool_fault_receipt)
        self._validate_semantics(copied_receipts, repository_tool_receipt, tool_fault_receipt)

    @staticmethod
    def _validate_semantics(
        receipts: tuple[ModelDiscoveryReceipt, ...],
        repository_tool_receipt: RepositoryToolReceipt,
        tool_fault_receipt: RepositoryToolReceipt,
    ) -> None:
        (
            successful_discovery,
            completed_zero_discovery,
            provider_fault_discovery,
            tool_fault_discovery,
        ) = receipts
        if (
            len({item.receipt_id for item in receipts}) != len(receipts)
            or not _same_discovery_identity(receipts)
            or successful_discovery.model_call_status is not ModelCallStatus.SUCCEEDED
            or not successful_discovery.schema_valid_result
            or not successful_discovery.candidate_ids
            or successful_discovery.output_sha256 is None
            or completed_zero_discovery.is_completed_zero is not True
            or completed_zero_discovery.output_sha256 is None
            or provider_fault_discovery.model_call_status is not ModelCallStatus.PROVIDER_ERROR
            or provider_fault_discovery.schema_valid_result
            or provider_fault_discovery.candidate_ids
            or provider_fault_discovery.output_sha256 is not None
            or tool_fault_discovery.model_call_status
            not in {ModelCallStatus.GUARDRAIL_BLOCKED, ModelCallStatus.BUDGET_EXHAUSTED}
            or tool_fault_discovery.schema_valid_result
            or tool_fault_discovery.candidate_ids
            or tool_fault_discovery.output_sha256 is not None
            or repository_tool_receipt.outcome is not ToolOutcome.SUCCEEDED
            or repository_tool_receipt.output_sha256 is None
            or tool_fault_receipt.outcome is not ToolOutcome.NON_SUCCESS
            or _tool_receipt_sha256(repository_tool_receipt)
            not in successful_discovery.repository_view_call_hashes
            or _tool_receipt_sha256(tool_fault_receipt)
            not in tool_fault_discovery.repository_view_call_hashes
        ):
            raise LocalModelQualificationError(QualificationErrorCode.EVIDENCE_INVALID)

    @property
    def receipt_hashes(self) -> tuple[str, ...]:
        return tuple(
            _sha256(_canonical_bytes(item.model_dump(mode="json")))
            for item in (
                self.successful_discovery,
                self.completed_zero_discovery,
                self.provider_fault_discovery,
                self.tool_fault_discovery,
            )
        )

    @property
    def tool_receipt_hashes(self) -> tuple[str, str]:
        return (
            _tool_receipt_sha256(self.repository_tool_receipt),
            _tool_receipt_sha256(self.tool_fault_receipt),
        )


@dataclass(frozen=True, slots=True)
class LocalModelQualificationRecord:
    """Safe output; evidence recorded here cannot upgrade the product outcome."""

    qualification_id: str
    request_sha256: str
    artifact: LocalModelArtifact
    runtime: LocalRuntimeSnapshot
    hardware: HardwareSnapshot
    provider_profile: ComponentPin
    connector: ComponentPin
    expected_repository_scope_sha256: str
    monetary_cost_usd_micros: int
    state: QualificationState
    required_terminal_outcome: AuditRunOutcome | None
    receipt_hashes: tuple[str, ...]
    tool_receipt_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.qualification_id) is not str
            or _ID.fullmatch(self.qualification_id) is None
            or type(self.request_sha256) is not str
            or _SHA256.fullmatch(self.request_sha256) is None
            or type(self.artifact) is not LocalModelArtifact
            or type(self.runtime) is not LocalRuntimeSnapshot
            or type(self.hardware) is not HardwareSnapshot
            or type(self.provider_profile) is not ComponentPin
            or type(self.connector) is not ComponentPin
            or type(self.expected_repository_scope_sha256) is not str
            or _SHA256.fullmatch(self.expected_repository_scope_sha256) is None
            or type(self.monetary_cost_usd_micros) is not int
            or self.monetary_cost_usd_micros != 0
            or type(self.state) is not QualificationState
            or type(self.receipt_hashes) is not tuple
            or any(
                type(item) is not str or _SHA256.fullmatch(item) is None
                for item in self.receipt_hashes
            )
            or len(self.receipt_hashes) != len(set(self.receipt_hashes))
            or type(self.tool_receipt_hashes) is not tuple
            or any(
                type(item) is not str or _SHA256.fullmatch(item) is None
                for item in self.tool_receipt_hashes
            )
            or len(self.tool_receipt_hashes) != len(set(self.tool_receipt_hashes))
            or (
                self.state is QualificationState.AWAITING_REAL_EVIDENCE
                and (
                    self.required_terminal_outcome is not AuditRunOutcome.INDETERMINATE
                    or self.receipt_hashes
                    or self.tool_receipt_hashes
                )
            )
            or (
                self.state is QualificationState.REAL_EVIDENCE_RECORDED
                and (
                    self.required_terminal_outcome is not None
                    or len(self.receipt_hashes) != 4
                    or len(self.tool_receipt_hashes) != 2
                )
            )
        ):
            raise LocalModelQualificationError(QualificationErrorCode.EVIDENCE_INVALID)
        object.__setattr__(self, "artifact", _copy_artifact(self.artifact))
        object.__setattr__(self, "runtime", _copy_runtime(self.runtime))
        object.__setattr__(self, "hardware", _copy_hardware(self.hardware))
        object.__setattr__(self, "provider_profile", _copy_pin(self.provider_profile))
        object.__setattr__(self, "connector", _copy_pin(self.connector))

    @property
    def payload(self) -> dict[str, object]:
        """Canonical source-free record material suitable for later attestation."""

        artifact = _copy_artifact(self.artifact)
        runtime = _copy_runtime(self.runtime)
        hardware = _copy_hardware(self.hardware)
        provider_profile = _copy_pin(self.provider_profile)
        connector = _copy_pin(self.connector)
        return {
            "artifact": _artifact_material(artifact),
            "connector": connector.model_dump(mode="json"),
            "expected_repository_scope_sha256": self.expected_repository_scope_sha256,
            "hardware": _hardware_material(hardware),
            "monetary_cost_usd_micros": self.monetary_cost_usd_micros,
            "provider_profile": provider_profile.model_dump(mode="json"),
            "qualification_id": self.qualification_id,
            "receipt_hashes": list(self.receipt_hashes),
            "request_sha256": self.request_sha256,
            "required_terminal_outcome": (
                self.required_terminal_outcome.value
                if self.required_terminal_outcome is not None
                else None
            ),
            "runtime": _runtime_material(runtime),
            "state": self.state.value,
            "tool_receipt_hashes": list(self.tool_receipt_hashes),
        }

    @property
    def canonical_bytes(self) -> bytes:
        return _canonical_bytes(self.payload)

    @property
    def record_sha256(self) -> str:
        return _sha256(self.canonical_bytes)


def _same_discovery_identity(receipts: tuple[ModelDiscoveryReceipt, ...]) -> bool:
    from .local_model_qualification_validation import _same_discovery_identity as validate

    return validate(receipts)


def _tool_receipt_sha256(receipt: RepositoryToolReceipt) -> str:
    from .local_model_qualification_validation import _tool_receipt_sha256 as digest

    return digest(receipt)


def _artifact_material(value: LocalModelArtifact) -> dict[str, object]:
    from .local_model_qualification_validation import _artifact_material as material

    return material(value)


def _runtime_material(value: LocalRuntimeSnapshot) -> dict[str, object]:
    from .local_model_qualification_validation import _runtime_material as material

    return material(value)


def _hardware_material(value: HardwareSnapshot) -> dict[str, object]:
    from .local_model_qualification_validation import _hardware_material as material

    return material(value)


def _tool_request_material(value: RepositoryToolRequest) -> dict[str, object]:
    from .local_model_qualification_validation import _tool_request_material as material

    return material(value)


def _canonical_bytes(value: object) -> bytes:
    from .local_model_qualification_validation import _canonical_bytes as serialize

    return serialize(value)


def _sha256(value: bytes) -> str:
    from .local_model_qualification_validation import _sha256 as digest

    return digest(value)


def _copy_artifact(value: object) -> LocalModelArtifact:
    from .local_model_qualification_validation import _copy_artifact as copy

    return copy(value)


def _copy_runtime(value: object) -> LocalRuntimeSnapshot:
    from .local_model_qualification_validation import _copy_runtime as copy

    return copy(value)


def _copy_hardware(value: object) -> HardwareSnapshot:
    from .local_model_qualification_validation import _copy_hardware as copy

    return copy(value)


def _copy_pin(value: object) -> ComponentPin:
    from .local_model_qualification_validation import _copy_pin as copy

    return copy(value)


def _copy_model_request(value: object) -> ModelRequest:
    from .local_model_qualification_validation import _copy_model_request as copy

    return copy(value)


def _copy_tool_request(value: object) -> RepositoryToolRequest:
    from .local_model_qualification_validation import _copy_tool_request as copy

    return copy(value)


def _copy_discovery_receipt(value: object) -> ModelDiscoveryReceipt:
    from .local_model_qualification_validation import _copy_discovery_receipt as copy

    return copy(value)


def _copy_tool_receipt(value: object) -> RepositoryToolReceipt:
    from .local_model_qualification_validation import _copy_tool_receipt as copy

    return copy(value)
