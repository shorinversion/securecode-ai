from __future__ import annotations

from dataclasses import replace

import pytest
from securecode_ai.adapters import local_model_qualification as qualification_module
from securecode_ai.adapters.local_model_qualification import (
    GpuHardwareSnapshot,
    HardwareMemorySource,
    HardwareSnapshot,
    LocalModelArtifact,
    LocalModelQualificationError,
    LocalModelQualificationEvidence,
    LocalModelQualificationRequest,
    LocalRuntimeSnapshot,
    QualificationState,
    record_local_model_qualification,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ApiDialect,
    AuditRunOutcome,
    ComponentPin,
    ModelBudgetUsage,
    ModelCallBudget,
    ModelCallStatus,
    ModelDiscoveryReceipt,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    RepositoryRevision,
    RepositoryTool,
    RunExecutionIdentity,
)
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ReadRangeArguments,
    RepositoryToolReceipt,
    RepositoryToolRequest,
    ToolDecision,
    ToolOutcome,
    ToolReason,
)

HEAD = "1" * 40
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
MODEL_TAG = "qwen2.5-coder:7b-instruct-q4_K_M"


def _pin(name: str, sha: str = SHA_A) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=sha,
    )


def _structured_request() -> ModelRequest:
    provider_profile = _pin("local-provider-profile", SHA_B)
    identity = RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-a",
            scm_provider="github",
            repository_id="repo-a",
            head_sha=HEAD,
        ),
        stage_catalogue=_pin("stages"),
        workflow=_pin("workflow"),
        policy=_pin("policy"),
        configuration=_pin("config"),
        provider_profile=provider_profile,
        capability_profile=_pin("capabilities"),
        egress_profile=_pin("egress"),
    )
    return ModelRequest(
        schema_version=CONTRACT_SCHEMA_VERSION,
        request_id="local-qualification-request",
        run_id="local-qualification-run",
        tenant_id="tenant-a",
        idempotency_key="local-qualification-idempotency",
        attempt=1,
        execution_identity=identity,
        head_sha=HEAD,
        role=ModelRole.DISCOVERY,
        mode=ModelPurpose.MODEL_NATIVE_DISCOVERY,
        provider_profile=provider_profile,
        api_dialect=ApiDialect.OPENAI_COMPATIBLE,
        model_id=MODEL_TAG,
        prompt=_pin("model-native-discovery-prompt"),
        output_schema=_pin("model-native-discovery-schema"),
        tool_policy=_pin("repository-tool-policy"),
        repository_scope=_pin("repository-scope"),
        repository_view_policy=_pin("repository-view-policy"),
        budget=ModelCallBudget(
            schema_version=CONTRACT_SCHEMA_VERSION,
            max_input_tokens=4096,
            max_output_tokens=1024,
            max_repository_calls=4,
            max_context_bytes=65_536,
            timeout_ms=30_000,
        ),
    )


def _request() -> LocalModelQualificationRequest:
    request = _structured_request()
    return LocalModelQualificationRequest(
        qualification_id="local-academic-demo-qualification",
        artifact=LocalModelArtifact(
            model_tag=MODEL_TAG,
            manifest_sha256=SHA_B,
            size_bytes=4_683_087_561,
            artifact_format="gguf",
            architecture="qwen2",
            parameter_size_label="7.6B",
            quantization="Q4_K_M",
            license_spdx="Apache-2.0",
            license_text_sha256=SHA_A,
            license_source_id="ollama-model-license",
            license_restrictions=("local-academic-demo", "review-license-terms"),
        ),
        runtime=LocalRuntimeSnapshot(
            runtime_id="ollama",
            runtime_version="0.16.2",
            runtime_sha256=SHA_C,
        ),
        hardware=HardwareSnapshot(
            cpu_model="AMD Ryzen 7 5800H",
            cpu_physical_cores=8,
            cpu_logical_cores=16,
            physical_ram_bytes=29_909_643_264,
            gpus=(
                GpuHardwareSnapshot(
                    adapter_id="amd-rx-6600m",
                    reported_memory_bytes=4 * 1024 * 1024 * 1024,
                    memory_source=HardwareMemorySource.PLATFORM_UNRELIABLE,
                ),
                GpuHardwareSnapshot(
                    adapter_id="amd-integrated",
                    reported_memory_bytes=4 * 1024 * 1024 * 1024,
                    memory_source=HardwareMemorySource.PLATFORM_UNRELIABLE,
                ),
            ),
        ),
        provider_profile=request.provider_profile,
        connector=_pin("openai-compatible-local-connector", SHA_D),
        structured_request=request,
        repository_view_request=RepositoryToolRequest(
            tool=RepositoryTool.READ_RANGE,
            arguments=ReadRangeArguments(
                TOOL_ARGUMENT_SCHEMA_VERSION,
                HEAD,
                "packages/core/example.py",
                1,
                2,
            ),
        ),
        expected_repository_scope_sha256=SHA_A,
    )


def _tool_receipt(*, success: bool) -> RepositoryToolReceipt:
    return RepositoryToolReceipt(
        sequence=1,
        tool=RepositoryTool.READ_RANGE.value,
        decision=ToolDecision.ALLOW,
        outcome=ToolOutcome.SUCCEEDED if success else ToolOutcome.NON_SUCCESS,
        reason=ToolReason.SUCCEEDED if success else ToolReason.BUDGET_EXHAUSTED,
        calls_used=1,
        bytes_used=24 if success else 0,
        tokens_used=4 if success else 0,
        output_sha256=SHA_D if success else None,
    )


def _discovery_receipt(
    request: LocalModelQualificationRequest,
    *,
    receipt_id: str,
    status: ModelCallStatus,
    candidate_ids: tuple[str, ...] = (),
    tool_hashes: tuple[str, ...] = (),
) -> ModelDiscoveryReceipt:
    succeeded = status is ModelCallStatus.SUCCEEDED
    return ModelDiscoveryReceipt(
        schema_version=CONTRACT_SCHEMA_VERSION,
        receipt_id=receipt_id,
        tenant_id=request.structured_request.tenant_id,
        head_sha=request.structured_request.head_sha,
        scope_sha256=request.expected_repository_scope_sha256,
        model_profile=request.structured_request.provider_profile,
        prompt=request.structured_request.prompt,
        repository_view_call_hashes=tool_hashes,
        budget_usage=ModelBudgetUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            token_limit=5120,
            tokens_used=28 if succeeded else 0,
            repository_call_limit=4,
            repository_calls_used=1 if tool_hashes else 0,
            time_limit_ms=30_000,
            elapsed_ms=25 if succeeded else 0,
        ),
        model_call_status=status,
        schema_valid_result=succeeded,
        input_sha256=SHA_B,
        output_sha256=SHA_C if succeeded else None,
        candidate_ids=candidate_ids,
    )


def _evidence(request: LocalModelQualificationRequest) -> LocalModelQualificationEvidence:
    tool_success = _tool_receipt(success=True)
    tool_fault = _tool_receipt(success=False)
    return LocalModelQualificationEvidence(
        successful_discovery=_discovery_receipt(
            request,
            receipt_id="successful-discovery",
            status=ModelCallStatus.SUCCEEDED,
            candidate_ids=("native-candidate-1",),
            tool_hashes=(qualification_module._tool_receipt_sha256(tool_success),),
        ),
        completed_zero_discovery=_discovery_receipt(
            request,
            receipt_id="completed-zero-discovery",
            status=ModelCallStatus.SUCCEEDED,
        ),
        provider_fault_discovery=_discovery_receipt(
            request,
            receipt_id="provider-fault-discovery",
            status=ModelCallStatus.PROVIDER_ERROR,
        ),
        tool_fault_discovery=_discovery_receipt(
            request,
            receipt_id="tool-fault-discovery",
            status=ModelCallStatus.BUDGET_EXHAUSTED,
            tool_hashes=(qualification_module._tool_receipt_sha256(tool_fault),),
        ),
        repository_tool_receipt=tool_success,
        tool_fault_receipt=tool_fault,
    )


def test_pending_qualification_is_indeterminate_without_live_model_evidence() -> None:
    record = record_local_model_qualification(_request())

    assert record.state is QualificationState.AWAITING_REAL_EVIDENCE
    assert record.required_terminal_outcome is AuditRunOutcome.INDETERMINATE
    assert record.receipt_hashes == ()
    assert record.tool_receipt_hashes == ()


def test_real_evidence_records_success_zero_and_fault_receipts_without_product_pass() -> None:
    request = _request()
    record = record_local_model_qualification(request, evidence=_evidence(request))

    assert record.state is QualificationState.REAL_EVIDENCE_RECORDED
    assert record.required_terminal_outcome is None
    assert len(record.receipt_hashes) == 4
    assert len(record.tool_receipt_hashes) == 2
    assert record.request_sha256 == request.request_sha256


def test_request_rejects_model_repository_and_nonzero_cost_identity_drift() -> None:
    request = _request()

    with pytest.raises(LocalModelQualificationError):
        LocalModelQualificationRequest(
            qualification_id=request.qualification_id,
            artifact=replace(request.artifact, model_tag="another-local-model"),
            runtime=request.runtime,
            hardware=request.hardware,
            provider_profile=request.provider_profile,
            connector=request.connector,
            structured_request=request.structured_request,
            repository_view_request=request.repository_view_request,
            expected_repository_scope_sha256=request.expected_repository_scope_sha256,
        )
    with pytest.raises(LocalModelQualificationError):
        LocalModelQualificationRequest(
            qualification_id=request.qualification_id,
            artifact=request.artifact,
            runtime=request.runtime,
            hardware=request.hardware,
            provider_profile=request.provider_profile,
            connector=request.connector,
            structured_request=request.structured_request,
            repository_view_request=RepositoryToolRequest(
                tool=RepositoryTool.READ_RANGE,
                arguments=ReadRangeArguments(
                    TOOL_ARGUMENT_SCHEMA_VERSION,
                    "2" * 40,
                    "packages/core/example.py",
                    1,
                    2,
                ),
            ),
            expected_repository_scope_sha256=request.expected_repository_scope_sha256,
        )
    with pytest.raises(LocalModelQualificationError):
        replace(request, monetary_cost_usd_micros=1)


def test_hardware_refuses_an_unavailable_gpu_memory_claim() -> None:
    with pytest.raises(LocalModelQualificationError):
        GpuHardwareSnapshot(
            adapter_id="unavailable-adapter",
            reported_memory_bytes=1,
            memory_source=HardwareMemorySource.UNAVAILABLE,
        )


def test_evidence_rejects_provider_and_tool_receipt_binding_drift() -> None:
    request = _request()
    evidence = _evidence(request)

    with pytest.raises(LocalModelQualificationError):
        LocalModelQualificationEvidence(
            successful_discovery=evidence.successful_discovery,
            completed_zero_discovery=evidence.completed_zero_discovery,
            provider_fault_discovery=evidence.provider_fault_discovery.model_copy(
                update={"model_call_status": ModelCallStatus.TIMEOUT}
            ),
            tool_fault_discovery=evidence.tool_fault_discovery,
            repository_tool_receipt=evidence.repository_tool_receipt,
            tool_fault_receipt=evidence.tool_fault_receipt,
        )
    with pytest.raises(LocalModelQualificationError):
        record_local_model_qualification(
            request,
            evidence=LocalModelQualificationEvidence(
                successful_discovery=evidence.successful_discovery,
                completed_zero_discovery=evidence.completed_zero_discovery,
                provider_fault_discovery=evidence.provider_fault_discovery,
                tool_fault_discovery=evidence.tool_fault_discovery.model_copy(
                    update={"scope_sha256": SHA_D}
                ),
                repository_tool_receipt=evidence.repository_tool_receipt,
                tool_fault_receipt=evidence.tool_fault_receipt,
            ),
        )
    with pytest.raises(LocalModelQualificationError):
        LocalModelQualificationEvidence(
            successful_discovery=evidence.successful_discovery.model_copy(
                update={"repository_view_call_hashes": ()}
            ),
            completed_zero_discovery=evidence.completed_zero_discovery,
            provider_fault_discovery=evidence.provider_fault_discovery,
            tool_fault_discovery=evidence.tool_fault_discovery,
            repository_tool_receipt=evidence.repository_tool_receipt,
            tool_fault_receipt=evidence.tool_fault_receipt,
        )


def test_request_and_evidence_revalidate_tampered_nested_values_before_hashing() -> None:
    request = _request()
    object.__setattr__(request.artifact, "size_bytes", 0)

    with pytest.raises(LocalModelQualificationError):
        record_local_model_qualification(request)

    request = _request()
    evidence = _evidence(request)
    object.__setattr__(evidence.repository_tool_receipt, "decision", "ALLOW")

    with pytest.raises(LocalModelQualificationError):
        record_local_model_qualification(request, evidence=evidence)


def test_nested_revalidation_failure_never_echoes_request_or_evidence_canaries() -> None:
    canary = "CANARY_NESTED_PRIVATE_VALUE"
    request = _request()
    object.__setattr__(request.structured_request, "provider_profile", canary)

    with pytest.raises(LocalModelQualificationError) as request_error:
        record_local_model_qualification(request)

    assert str(request_error.value) == "local model qualification failed"
    assert request_error.value.__cause__ is None
    assert request_error.value.__context__ is None
    assert canary not in repr(request_error.value)
    assert canary not in repr((request_error.value.__cause__, request_error.value.__context__))

    request = _request()
    evidence = _evidence(request)
    object.__setattr__(evidence.successful_discovery, "scope_sha256", canary)

    with pytest.raises(LocalModelQualificationError) as evidence_error:
        record_local_model_qualification(request, evidence=evidence)

    assert str(evidence_error.value) == "local model qualification failed"
    assert evidence_error.value.__cause__ is None
    assert evidence_error.value.__context__ is None
    assert canary not in repr(evidence_error.value)
    assert canary not in repr((evidence_error.value.__cause__, evidence_error.value.__context__))


def test_record_retains_deterministic_source_free_qualification_snapshot() -> None:
    request = _request()
    record = record_local_model_qualification(request)

    artifact_payload = record.payload["artifact"]
    runtime_payload = record.payload["runtime"]
    assert isinstance(artifact_payload, dict)
    assert isinstance(runtime_payload, dict)
    assert artifact_payload["model_tag"] == MODEL_TAG
    assert runtime_payload["runtime_id"] == "ollama"
    assert record.payload["monetary_cost_usd_micros"] == 0
    assert record.canonical_bytes == record.canonical_bytes
    assert len(record.record_sha256) == 64

    object.__setattr__(record.artifact, "size_bytes", 0)
    with pytest.raises(LocalModelQualificationError):
        _ = record.payload
