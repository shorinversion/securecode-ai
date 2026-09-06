from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import (
    AuditRunOutcome,
    ComponentPin,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    RepositoryTool,
)
from securecode_ai.core.tool_policy import (
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryToolArguments,
    RepositoryToolReceipt,
    RepositoryToolRequest,
    ToolDecision,
    ToolOutcome,
    ToolReason,
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


def record_local_model_qualification(
    request: LocalModelQualificationRequest,
    *,
    evidence: LocalModelQualificationEvidence | None = None,
) -> LocalModelQualificationRecord:
    """Record generic P3.13 evidence without performing I/O or returning PASS."""

    if type(request) is not LocalModelQualificationRequest:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    request = _copy_qualification_request(request)
    if evidence is None:
        return LocalModelQualificationRecord(
            qualification_id=request.qualification_id,
            request_sha256=request.request_sha256,
            artifact=request.artifact,
            runtime=request.runtime,
            hardware=request.hardware,
            provider_profile=request.provider_profile,
            connector=request.connector,
            expected_repository_scope_sha256=request.expected_repository_scope_sha256,
            monetary_cost_usd_micros=request.monetary_cost_usd_micros,
            state=QualificationState.AWAITING_REAL_EVIDENCE,
            required_terminal_outcome=AuditRunOutcome.INDETERMINATE,
            receipt_hashes=(),
            tool_receipt_hashes=(),
        )
    if type(evidence) is not LocalModelQualificationEvidence:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    evidence = _copy_qualification_evidence(evidence)
    _validate_evidence_binding(request, evidence)
    return LocalModelQualificationRecord(
        qualification_id=request.qualification_id,
        request_sha256=request.request_sha256,
        artifact=request.artifact,
        runtime=request.runtime,
        hardware=request.hardware,
        provider_profile=request.provider_profile,
        connector=request.connector,
        expected_repository_scope_sha256=request.expected_repository_scope_sha256,
        monetary_cost_usd_micros=request.monetary_cost_usd_micros,
        state=QualificationState.REAL_EVIDENCE_RECORDED,
        required_terminal_outcome=None,
        receipt_hashes=evidence.receipt_hashes,
        tool_receipt_hashes=evidence.tool_receipt_hashes,
    )


def _copy_artifact(value: object) -> LocalModelArtifact:
    if type(value) is not LocalModelArtifact:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    try:
        return LocalModelArtifact(
            model_tag=value.model_tag,
            manifest_sha256=value.manifest_sha256,
            size_bytes=value.size_bytes,
            artifact_format=value.artifact_format,
            architecture=value.architecture,
            parameter_size_label=value.parameter_size_label,
            quantization=value.quantization,
            license_spdx=value.license_spdx,
            license_text_sha256=value.license_text_sha256,
            license_source_id=value.license_source_id,
            license_restrictions=value.license_restrictions,
        )
    except (AttributeError, TypeError, ValueError):
        pass
    raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST) from None


def _copy_runtime(value: object) -> LocalRuntimeSnapshot:
    if type(value) is not LocalRuntimeSnapshot:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    try:
        return LocalRuntimeSnapshot(
            runtime_id=value.runtime_id,
            runtime_version=value.runtime_version,
            runtime_sha256=value.runtime_sha256,
            connector_type=value.connector_type,
        )
    except (AttributeError, TypeError, ValueError):
        pass
    raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST) from None


def _copy_hardware(value: object) -> HardwareSnapshot:
    if type(value) is not HardwareSnapshot:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    try:
        gpus = tuple(
            GpuHardwareSnapshot(
                adapter_id=item.adapter_id,
                reported_memory_bytes=item.reported_memory_bytes,
                memory_source=item.memory_source,
            )
            for item in value.gpus
        )
        return HardwareSnapshot(
            cpu_model=value.cpu_model,
            cpu_physical_cores=value.cpu_physical_cores,
            cpu_logical_cores=value.cpu_logical_cores,
            physical_ram_bytes=value.physical_ram_bytes,
            gpus=gpus,
        )
    except (AttributeError, TypeError, ValueError):
        pass
    raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST) from None


def _copy_pin(value: object) -> ComponentPin:
    if type(value) is not ComponentPin:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    try:
        return ComponentPin.model_validate(value.model_dump())
    except (AttributeError, TypeError, ValueError):
        pass
    raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST) from None


def _copy_model_request(value: object) -> ModelRequest:
    if type(value) is not ModelRequest:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    try:
        return ModelRequest.model_validate(value.model_dump())
    except (AttributeError, TypeError, ValueError):
        pass
    raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST) from None


def _copy_tool_request(value: object) -> RepositoryToolRequest:
    if type(value) is not RepositoryToolRequest:
        raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST)
    try:
        tool = value.tool
        arguments = value.arguments
        copied_arguments: RepositoryToolArguments
        if type(tool) is not RepositoryTool:
            raise TypeError("repository tool is invalid")
        if type(arguments) is ListPathsArguments:
            copied_arguments = ListPathsArguments(
                arguments.schema_version,
                arguments.head_sha,
                arguments.prefix,
                arguments.max_entries,
            )
        elif type(arguments) is LookupSymbolArguments:
            copied_arguments = LookupSymbolArguments(
                arguments.schema_version,
                arguments.head_sha,
                arguments.symbol,
                arguments.path,
            )
        elif type(arguments) is ReadRangeArguments:
            copied_arguments = ReadRangeArguments(
                arguments.schema_version,
                arguments.head_sha,
                arguments.path,
                arguments.start_line,
                arguments.end_line,
            )
        elif type(arguments) is ReadEvidenceArguments:
            copied_arguments = ReadEvidenceArguments(
                arguments.schema_version,
                arguments.head_sha,
                arguments.evidence_id,
            )
        else:
            raise TypeError("repository tool arguments are invalid")
        if type(copied_arguments) is not _TOOL_ARGUMENT_TYPES[tool]:
            raise TypeError("repository tool and arguments do not match")
    except (AttributeError, TypeError, ValueError):
        pass
    else:
        return RepositoryToolRequest(tool=tool, arguments=copied_arguments)
    raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST) from None


def _copy_discovery_receipt(value: object) -> ModelDiscoveryReceipt:
    if type(value) is not ModelDiscoveryReceipt:
        raise LocalModelQualificationError(QualificationErrorCode.EVIDENCE_INVALID)
    try:
        return ModelDiscoveryReceipt.model_validate(value.model_dump())
    except (AttributeError, TypeError, ValueError):
        pass
    raise LocalModelQualificationError(QualificationErrorCode.EVIDENCE_INVALID) from None


def _copy_tool_receipt(value: object) -> RepositoryToolReceipt:
    if type(value) is not RepositoryToolReceipt:
        raise LocalModelQualificationError(QualificationErrorCode.EVIDENCE_INVALID)
    try:
        fields = (
            value.sequence,
            value.tool,
            value.decision,
            value.outcome,
            value.reason,
            value.calls_used,
            value.bytes_used,
            value.tokens_used,
            value.output_sha256,
        )
    except AttributeError:
        pass
    else:
        if (
            type(fields[0]) is int
            and fields[0] >= 1
            and type(fields[1]) is str
            and _ID.fullmatch(fields[1]) is not None
            and type(fields[2]) is ToolDecision
            and type(fields[3]) is ToolOutcome
            and type(fields[4]) is ToolReason
            and all(type(item) is int and item >= 0 for item in fields[5:8])
            and (
                fields[8] is None
                or (type(fields[8]) is str and _SHA256.fullmatch(fields[8]) is not None)
            )
        ):
            return RepositoryToolReceipt(
                sequence=fields[0],
                tool=fields[1],
                decision=fields[2],
                outcome=fields[3],
                reason=fields[4],
                calls_used=fields[5],
                bytes_used=fields[6],
                tokens_used=fields[7],
                output_sha256=fields[8],
            )
    raise LocalModelQualificationError(QualificationErrorCode.EVIDENCE_INVALID) from None


def _copy_qualification_request(
    value: LocalModelQualificationRequest,
) -> LocalModelQualificationRequest:
    try:
        return LocalModelQualificationRequest(
            qualification_id=value.qualification_id,
            artifact=value.artifact,
            runtime=value.runtime,
            hardware=value.hardware,
            provider_profile=value.provider_profile,
            connector=value.connector,
            structured_request=value.structured_request,
            repository_view_request=value.repository_view_request,
            expected_repository_scope_sha256=value.expected_repository_scope_sha256,
            monetary_cost_usd_micros=value.monetary_cost_usd_micros,
        )
    except (AttributeError, TypeError, ValueError):
        pass
    raise LocalModelQualificationError(QualificationErrorCode.INVALID_REQUEST) from None


def _copy_qualification_evidence(
    value: LocalModelQualificationEvidence,
) -> LocalModelQualificationEvidence:
    try:
        return LocalModelQualificationEvidence(
            successful_discovery=value.successful_discovery,
            completed_zero_discovery=value.completed_zero_discovery,
            provider_fault_discovery=value.provider_fault_discovery,
            tool_fault_discovery=value.tool_fault_discovery,
            repository_tool_receipt=value.repository_tool_receipt,
            tool_fault_receipt=value.tool_fault_receipt,
        )
    except (AttributeError, TypeError, ValueError):
        pass
    raise LocalModelQualificationError(QualificationErrorCode.EVIDENCE_INVALID) from None


def _validate_evidence_binding(
    request: LocalModelQualificationRequest, evidence: LocalModelQualificationEvidence
) -> None:
    expected = request.structured_request
    for receipt in (
        evidence.successful_discovery,
        evidence.completed_zero_discovery,
        evidence.provider_fault_discovery,
        evidence.tool_fault_discovery,
    ):
        if (
            receipt.tenant_id != expected.tenant_id
            or receipt.head_sha != expected.head_sha
            or receipt.scope_sha256 != request.expected_repository_scope_sha256
            or receipt.model_profile != expected.provider_profile
            or receipt.prompt != expected.prompt
        ):
            raise LocalModelQualificationError(QualificationErrorCode.IDENTITY_MISMATCH)
    if (
        evidence.repository_tool_receipt.tool != request.repository_view_request.tool.value
        or evidence.tool_fault_receipt.tool != request.repository_view_request.tool.value
    ):
        raise LocalModelQualificationError(QualificationErrorCode.IDENTITY_MISMATCH)


def _same_discovery_identity(receipts: tuple[ModelDiscoveryReceipt, ...]) -> bool:
    first = receipts[0]
    return all(
        (
            item.tenant_id,
            item.head_sha,
            item.scope_sha256,
            item.model_profile,
            item.prompt,
        )
        == (
            first.tenant_id,
            first.head_sha,
            first.scope_sha256,
            first.model_profile,
            first.prompt,
        )
        for item in receipts[1:]
    )


def _tool_receipt_sha256(receipt: RepositoryToolReceipt) -> str:
    return _sha256(
        _canonical_bytes(
            {
                "bytes_used": receipt.bytes_used,
                "calls_used": receipt.calls_used,
                "decision": receipt.decision.value,
                "outcome": receipt.outcome.value,
                "output_sha256": receipt.output_sha256,
                "reason": receipt.reason.value,
                "sequence": receipt.sequence,
                "tokens_used": receipt.tokens_used,
                "tool": receipt.tool,
            }
        )
    )


def _artifact_material(value: LocalModelArtifact) -> dict[str, object]:
    return {
        "architecture": value.architecture,
        "artifact_format": value.artifact_format,
        "license_restrictions": list(value.license_restrictions),
        "license_source_id": value.license_source_id,
        "license_spdx": value.license_spdx,
        "license_text_sha256": value.license_text_sha256,
        "manifest_sha256": value.manifest_sha256,
        "model_tag": value.model_tag,
        "parameter_size_label": value.parameter_size_label,
        "quantization": value.quantization,
        "size_bytes": value.size_bytes,
    }


def _runtime_material(value: LocalRuntimeSnapshot) -> dict[str, object]:
    return {
        "connector_type": value.connector_type,
        "runtime_id": value.runtime_id,
        "runtime_sha256": value.runtime_sha256,
        "runtime_version": value.runtime_version,
    }


def _hardware_material(value: HardwareSnapshot) -> dict[str, object]:
    return {
        "cpu_logical_cores": value.cpu_logical_cores,
        "cpu_model": value.cpu_model,
        "cpu_physical_cores": value.cpu_physical_cores,
        "gpus": [
            {
                "adapter_id": item.adapter_id,
                "memory_source": item.memory_source.value,
                "reported_memory_bytes": item.reported_memory_bytes,
            }
            for item in value.gpus
        ],
        "physical_ram_bytes": value.physical_ram_bytes,
    }


def _tool_request_material(value: RepositoryToolRequest) -> dict[str, object]:
    arguments = value.arguments
    return {
        "arguments": {
            key: getattr(arguments, key) for key in sorted(arguments.__dataclass_fields__)
        },
        "tool": value.tool.value,
    }


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


__all__ = [
    "GpuHardwareSnapshot",
    "HardwareMemorySource",
    "HardwareSnapshot",
    "LocalModelArtifact",
    "LocalModelQualificationError",
    "LocalModelQualificationEvidence",
    "LocalModelQualificationRecord",
    "LocalModelQualificationRequest",
    "LocalRuntimeSnapshot",
    "QualificationErrorCode",
    "QualificationState",
    "record_local_model_qualification",
]
