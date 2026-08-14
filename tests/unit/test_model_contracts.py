"""Public model-boundary contract tests for P1.8."""

from __future__ import annotations

import json
from copy import deepcopy

import pytest
from pydantic import ValidationError
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    DataClass,
    EvidenceInputRef,
    ModelCallBudget,
    ModelCallResult,
    ModelCallStatus,
    ModelRequest,
    ModelRole,
    ModelSchemaStatus,
    NativeOutcomeMetadata,
    OpaqueContentProvenance,
    RepositoryRevision,
    RunExecutionIdentity,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
HEAD = "1" * 40


def _pin(name: str, sha: str = SHA_A) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=sha,
    )


def _identity() -> RunExecutionIdentity:
    return RunExecutionIdentity.build(
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
        provider_profile=_pin("fake-hermetic", SHA_B),
        capability_profile=_pin("capabilities"),
        egress_profile=_pin("air-gap"),
    )


def valid_request_payload() -> dict[str, object]:
    identity = _identity()
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "request_id": "request-1",
        "run_id": "run-1",
        "tenant_id": "tenant-a",
        "idempotency_key": "idem-1",
        "attempt": 1,
        "execution_identity": identity.model_dump(mode="json"),
        "head_sha": HEAD,
        "role": "discovery",
        "mode": "model_native_discovery",
        "provider_profile": identity.provider_profile.model_dump(mode="json"),
        "api_dialect": "fake",
        "model_id": "fixture-model",
        "prompt": _pin("prompt").model_dump(mode="json"),
        "output_schema": _pin("discovery-output").model_dump(mode="json"),
        "tool_policy": _pin("repository-tools").model_dump(mode="json"),
        "repository_scope": _pin("repository-scope").model_dump(mode="json"),
        "repository_view_policy": _pin("repository-view-policy").model_dump(mode="json"),
        "evidence": [],
        "budget": {
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "max_input_tokens": 4096,
            "max_output_tokens": 1024,
            "max_repository_calls": 8,
            "max_context_bytes": 65536,
            "timeout_ms": 30000,
        },
    }


def _parse_request(payload: dict[str, object]) -> ModelRequest:
    return ModelRequest.model_validate_json(json.dumps(payload, sort_keys=True))


def _parse_result(payload: dict[str, object]) -> ModelCallResult:
    return ModelCallResult.model_validate_json(json.dumps(payload, sort_keys=True))


def test_model_request_round_trip_binds_execution_identity() -> None:
    request = _parse_request(valid_request_payload())
    assert request.execution_identity.repository_revision.head_sha == request.head_sha
    assert request.execution_identity.provider_profile == request.provider_profile
    assert request.tenant_id == request.execution_identity.repository_revision.tenant_id
    assert ModelRequest.model_validate_json(request.model_dump_json()) == request


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "tenant-b"),
        ("head_sha", "2" * 40),
        ("provider_profile", _pin("different", SHA_B).model_dump(mode="json")),
    ],
)
def test_model_request_rejects_duplicate_identity_drift(field: str, value: object) -> None:
    payload = valid_request_payload()
    payload[field] = value
    with pytest.raises(ValidationError):
        _parse_request(payload)


def test_only_model_native_discovery_may_start_without_evidence() -> None:
    payload = valid_request_payload()
    payload.update({"role": "auditor", "mode": "candidate_investigation"})
    with pytest.raises(ValidationError):
        _parse_request(payload)

    payload["evidence"] = [
        EvidenceInputRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            evidence_id="evidence-1",
            content_id="opaque-content-1",
            data_class=DataClass.CONFIDENTIAL_SECURITY,
        ).model_dump(mode="json")
    ]
    assert _parse_request(payload).role is ModelRole.AUDITOR


def valid_success_result_payload() -> dict[str, object]:
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "request_id": "request-1",
        "run_id": "run-1",
        "tenant_id": "tenant-a",
        "idempotency_key": "idem-1",
        "attempt": 1,
        "provider_profile": _pin("fake-hermetic", SHA_B).model_dump(mode="json"),
        "model_call_status": "SUCCEEDED",
        "native": {
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "request_code": "NATIVE_REQUEST_PRESENT",
            "finish_code": "COMPLETE",
            "refusal_code": None,
            "filter_code": None,
        },
        "schema_result": {
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "status": "VALID",
            "error_code": None,
            "validator": _pin("discovery-output").model_dump(mode="json"),
        },
        "usage": {
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "input_tokens": 10,
            "output_tokens": 5,
            "repository_calls": 0,
            "elapsed_ms": 20,
        },
        "retryable": False,
        "content_provenance": {
            "schema_version": CONTRACT_SCHEMA_VERSION,
            "content_id": "kid:opaque-keyed-1",
            "tenant_id": "tenant-a",
            "data_class": "DC2_CONFIDENTIAL_SECURITY",
            "validator": _pin("discovery-output").model_dump(mode="json"),
        },
        "safe_reason_code": None,
    }


def test_success_result_requires_schema_valid_content_provenance() -> None:
    result = _parse_result(valid_success_result_payload())
    assert result.status is ModelCallStatus.SUCCEEDED
    assert result.schema_result.status is ModelSchemaStatus.VALID
    assert result.content_provenance is not None
    assert ModelCallResult.model_validate_json(result.model_dump_json()) == result

    valid_payload = valid_success_result_payload()
    schema_result = valid_payload["schema_result"]
    native = valid_payload["native"]
    assert isinstance(schema_result, dict)
    assert isinstance(native, dict)
    mutations: tuple[dict[str, object], ...] = (
        {
            "schema_result": {
                **schema_result,
                "status": "INVALID",
                "error_code": "SCHEMA_INVALID",
            }
        },
        {"content_provenance": None},
        {"native": {**native, "refusal_code": "REFUSED"}},
    )
    for mutation in mutations:
        payload = valid_success_result_payload()
        payload.update(mutation)
        with pytest.raises(ValidationError):
            _parse_result(payload)


@pytest.mark.parametrize(
    "status", [item for item in ModelCallStatus if item is not ModelCallStatus.SUCCEEDED]
)
def test_non_success_result_cannot_carry_validated_content(status: ModelCallStatus) -> None:
    payload = valid_success_result_payload()
    payload.update(
        {
            "model_call_status": status.value,
            "schema_result": {
                "schema_version": CONTRACT_SCHEMA_VERSION,
                "status": "NOT_VALIDATED",
                "error_code": "MODEL_NON_SUCCESS",
                "validator": _pin("discovery-output").model_dump(mode="json"),
            },
            "content_provenance": None,
            "safe_reason_code": "MODEL_NON_SUCCESS",
        }
    )
    assert _parse_result(payload).status is status


def test_model_result_is_closed_and_never_accepts_raw_content_or_digest() -> None:
    for forbidden in ("content", "raw_response", "content_sha256", "credential"):
        payload = deepcopy(valid_success_result_payload())
        payload[forbidden] = "secret-canary"
        with pytest.raises(ValidationError) as raised:
            _parse_result(payload)
        assert raised.value.error_count() >= 1


def test_nested_model_types_are_closed_and_immutable() -> None:
    native = NativeOutcomeMetadata(
        schema_version=CONTRACT_SCHEMA_VERSION,
        request_code="REQUEST",
        finish_code="COMPLETE",
    )
    provenance = OpaqueContentProvenance(
        schema_version=CONTRACT_SCHEMA_VERSION,
        content_id="kid:opaque-1",
        tenant_id="tenant-a",
        data_class=DataClass.CONFIDENTIAL_SECURITY,
        validator=_pin("validator"),
    )
    budget = ModelCallBudget(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_input_tokens=10,
        max_output_tokens=5,
        max_repository_calls=1,
        max_context_bytes=100,
        timeout_ms=1000,
    )
    with pytest.raises(ValidationError):
        NativeOutcomeMetadata.model_validate({**native.model_dump(), "unknown": 1})
    with pytest.raises(ValidationError):
        provenance.tenant_id = "tenant-b"
    assert budget.max_output_tokens <= budget.max_input_tokens
