from __future__ import annotations

import hashlib
import json

from securecode_ai.core import (
    ComponentPin,
    ModelRequest,
)
from securecode_ai.core.model_discovery import ModelDiscoveryReceipt
from securecode_ai.core.tool_policy import (
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryTool,
    RepositoryToolArguments,
    RepositoryToolReceipt,
    RepositoryToolRequest,
    ToolDecision,
    ToolOutcome,
    ToolReason,
)

from .local_model_qualification_models import (
    _ID,
    _SHA256,
    _TOOL_ARGUMENT_TYPES,
    GpuHardwareSnapshot,
    HardwareSnapshot,
    LocalModelArtifact,
    LocalModelQualificationError,
    LocalModelQualificationEvidence,
    LocalModelQualificationRequest,
    LocalRuntimeSnapshot,
    QualificationErrorCode,
)


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
