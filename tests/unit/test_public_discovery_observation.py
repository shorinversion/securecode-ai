"""Focused source-free native discovery observation checks."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TypeGuard

import pytest
from securecode_ai.adapters.product_runtime import (
    ProductDiscoveryInvocationObservation,
    _non_success_result,
)
from securecode_ai.adapters.public_discovery_observation import (
    PublicDiscoveryObservationError,
    PublicDiscoveryObservationRecorder,
    source_free_discovery_observation_document,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ModelCallResult,
    ModelCallStatus,
    ModelRequest,
    PreflightEligibility,
    ProducerRef,
)
from securecode_ai.core.model_discovery import (
    ModelNativeDiscoveryPayload,
    ModelNativeDiscoveryPlan,
    RepositoryToolSession,
    run_model_native_discovery,
)
from securecode_ai.core.tool_policy import RepositoryToolBudget, RepositoryToolScope


def _is_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _object_dict(value: object) -> dict[str, object]:
    assert _is_object_dict(value)
    return value


def _plan(request: ModelRequest) -> ModelNativeDiscoveryPlan:
    return ModelNativeDiscoveryPlan(
        receipt_id="public-discovery-receipt",
        request=request,
        preflight_eligibility=PreflightEligibility.ELIGIBLE,
        scope=RepositoryToolScope(
            request.tenant_id,
            request.execution_identity.repository_revision.repository_id,
            request.head_sha,
            ("a.py",),
            ("evidence-a",),
        ),
        tool_budget=RepositoryToolBudget(
            request.budget.max_repository_calls,
            request.budget.max_context_bytes,
            request.budget.max_input_tokens,
        ),
        producer=ProducerRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            producer_id="model-native-discovery",
            producer_version="1.0.0",
            producer_sha256="a" * 64,
        ),
    )


def _cycle_plan(request: ModelRequest, tools: RepositoryToolSession) -> ModelNativeDiscoveryPlan:
    scope = tools._guard._scope
    budget = tools._guard._budget
    return ModelNativeDiscoveryPlan(
        receipt_id="cycle-discovery-receipt",
        request=request,
        preflight_eligibility=PreflightEligibility.ELIGIBLE,
        scope=scope,
        tool_budget=budget,
        producer=ProducerRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            producer_id="model-native-discovery",
            producer_version="1.0.0",
            producer_sha256="a" * 64,
        ),
    )


class _ObservingBackend:
    def __init__(
        self,
        payload: ModelNativeDiscoveryPayload,
        recorder: PublicDiscoveryObservationRecorder,
    ) -> None:
        self._payload = payload
        self._recorder = recorder

    def discover(
        self, *, request: ModelRequest, tools: RepositoryToolSession
    ) -> ModelNativeDiscoveryPayload:
        result = self._payload.model_result
        self._recorder.observe(
            ProductDiscoveryInvocationObservation(
                request=request,
                model_result_before_collection=result,
                usage_before_collection=result.usage,
                model_call_status_before_collection=result.model_call_status,
                schema_valid_result_before_collection=result.schema_result.status.value == "VALID",
                repository_view_call_hashes=tools.call_hashes,
                elapsed_known=True,
                token_usage_known=result.native.request_code != "NO_NATIVE_RESPONSE",
            )
        )
        return self._payload


def _success_result(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ModelRequest, ModelCallResult]:
    from tests.integration.test_product_runtime_harness import _composition

    backend, tools, request, _, _ = _composition(monkeypatch)
    payload = backend.discover(request=request, tools=tools)
    assert payload.model_result.status is ModelCallStatus.SUCCEEDED
    return request, payload.model_result


def _with_usage(result: ModelCallResult, **changes: int) -> ModelCallResult:
    value = result.model_dump(mode="json")
    value["usage"].update(changes)
    return type(result).model_validate_json(json.dumps(value))


def test_recorder_reconciles_actual_core_success_and_whitelists_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.integration.test_product_runtime_harness import _composition

    request, result = _success_result(monkeypatch)
    plan = _plan(request)
    recorder = PublicDiscoveryObservationRecorder(plan)
    backend = _ObservingBackend(
        ModelNativeDiscoveryPayload(
            model_result=_with_usage(result, repository_calls=0), candidates=()
        ),
        recorder,
    )
    _, tools, _, _, _ = _composition(monkeypatch)
    outcome = run_model_native_discovery(plan, repository=tools._backend, backend=backend)

    evidence = recorder.finalize(outcome)
    assert evidence is not None
    document = source_free_discovery_observation_document(evidence)
    before = _object_dict(document["before_collection"])
    final = _object_dict(document["final_core_receipt"])
    assert before["token_usage_known"] is True
    assert final["model_call_status"] == "SUCCEEDED"
    encoded = json.dumps(document, sort_keys=True)
    assert "public source fixture" not in encoded and "model_request" not in encoded


def test_recorder_rejects_foreign_request_and_guard_hash_replay(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request, result = _success_result(monkeypatch)
    recorder = PublicDiscoveryObservationRecorder(_plan(request))
    request_data = request.model_dump(mode="json")
    request_data["run_id"] = "foreign-run"
    foreign = type(request).model_validate_json(json.dumps(request_data))
    with pytest.raises(PublicDiscoveryObservationError):
        recorder.observe(
            ProductDiscoveryInvocationObservation(
                request=foreign,
                model_result_before_collection=result,
                usage_before_collection=result.usage,
                model_call_status_before_collection=result.model_call_status,
                schema_valid_result_before_collection=True,
                repository_view_call_hashes=(),
                elapsed_known=True,
                token_usage_known=True,
            )
        )

    recorder = PublicDiscoveryObservationRecorder(_plan(request))
    observation = ProductDiscoveryInvocationObservation(
        request=request,
        model_result_before_collection=result,
        usage_before_collection=result.usage,
        model_call_status_before_collection=result.model_call_status,
        schema_valid_result_before_collection=True,
        repository_view_call_hashes=(),
        elapsed_known=True,
        token_usage_known=True,
    )
    recorder.observe(observation)
    with pytest.raises(PublicDiscoveryObservationError):
        recorder.observe(observation)


def test_recorder_rejects_foreign_final_receipt_id(monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.integration.test_product_runtime_harness import _composition

    request, result = _success_result(monkeypatch)
    plan = _plan(request)
    recorder = PublicDiscoveryObservationRecorder(plan)
    backend = _ObservingBackend(
        ModelNativeDiscoveryPayload(
            model_result=_with_usage(result, repository_calls=0), candidates=()
        ),
        recorder,
    )
    _, tools, _, _, _ = _composition(monkeypatch)
    outcome = run_model_native_discovery(plan, repository=tools._backend, backend=backend)
    value = outcome.receipt.model_dump(mode="json")
    value["receipt_id"] = "foreign-receipt"
    receipt = type(outcome.receipt).model_validate_json(json.dumps(value))

    with pytest.raises(PublicDiscoveryObservationError):
        recorder.finalize(replace(outcome, receipt=receipt))


def test_recorder_rejects_foreign_candidate_lineage_producer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.integration.test_native_repository_turns import _cycle_fixture

    backend, tools, request, _ = _cycle_fixture(monkeypatch, candidate=True)
    plan = _cycle_plan(request, tools)
    recorder = PublicDiscoveryObservationRecorder(plan)
    backend._observer = recorder.observe
    outcome = run_model_native_discovery(plan, repository=tools._backend, backend=backend)
    assert len(outcome.candidates) == 1
    value = outcome.candidates[0].model_dump(mode="json")
    value["lineage"][0]["producer"]["producer_sha256"] = "b" * 64
    candidate = type(outcome.candidates[0]).model_validate_json(json.dumps(value))

    assert recorder.finalize(outcome) is not None
    with pytest.raises(PublicDiscoveryObservationError):
        recorder.finalize(replace(outcome, candidates=(candidate,)))


def test_observed_overrun_survives_unchanged_core_invalid_schema_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.integration.test_product_runtime_harness import _composition

    request, result = _success_result(monkeypatch)
    overrun = _with_usage(result, repository_calls=0, elapsed_ms=request.budget.timeout_ms + 1)
    plan = _plan(request)
    recorder = PublicDiscoveryObservationRecorder(plan)
    backend = _ObservingBackend(
        ModelNativeDiscoveryPayload(model_result=overrun, candidates=()), recorder
    )
    _, tools, _, _, _ = _composition(monkeypatch)
    outcome = run_model_native_discovery(plan, repository=tools._backend, backend=backend)

    evidence = recorder.finalize(outcome)
    assert evidence is not None
    assert evidence.observed_elapsed_ms == request.budget.timeout_ms + 1
    assert evidence.observed_budget_exhausted
    assert outcome.receipt.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert outcome.receipt.budget_usage.elapsed_ms == 0


def test_unknown_provider_usage_remains_unknown_in_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.integration.test_product_runtime_harness import _composition

    request, _ = _success_result(monkeypatch)
    result = _non_success_result(request, ModelCallStatus.PROVIDER_ERROR, 0, 0, None)
    plan = _plan(request)
    recorder = PublicDiscoveryObservationRecorder(plan)

    class UnknownBackend:
        def discover(
            self, *, request: ModelRequest, tools: RepositoryToolSession
        ) -> ModelNativeDiscoveryPayload:
            recorder.observe(
                ProductDiscoveryInvocationObservation(
                    request=request,
                    model_result_before_collection=result,
                    usage_before_collection=result.usage,
                    model_call_status_before_collection=result.model_call_status,
                    schema_valid_result_before_collection=False,
                    repository_view_call_hashes=tools.call_hashes,
                    elapsed_known=False,
                    token_usage_known=False,
                )
            )
            return ModelNativeDiscoveryPayload(model_result=result, candidates=())

    _, tools, _, _, _ = _composition(monkeypatch)
    outcome = run_model_native_discovery(plan, repository=tools._backend, backend=UnknownBackend())
    evidence = recorder.finalize(outcome)
    assert evidence is not None
    document = source_free_discovery_observation_document(evidence)
    before = _object_dict(document["before_collection"])
    assert before["input_tokens"] is None
    assert before["output_tokens"] is None
    assert before["elapsed_ms"] is None


def test_schema_refusal_document_serializes_only_the_closed_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters.product_model import DiscoverySchemaRefusalCategory

    from tests.integration.test_product_runtime_harness import _composition

    request, _ = _success_result(monkeypatch)
    result = _non_success_result(request, ModelCallStatus.INVALID_SCHEMA, 0, 0, None)
    plan = _plan(request)
    recorder = PublicDiscoveryObservationRecorder(plan)

    class RefusalBackend:
        def discover(
            self, *, request: ModelRequest, tools: RepositoryToolSession
        ) -> ModelNativeDiscoveryPayload:
            recorder.observe(
                ProductDiscoveryInvocationObservation(
                    request=request,
                    model_result_before_collection=result,
                    usage_before_collection=result.usage,
                    model_call_status_before_collection=result.model_call_status,
                    schema_valid_result_before_collection=False,
                    repository_view_call_hashes=tools.call_hashes,
                    elapsed_known=True,
                    token_usage_known=True,
                    schema_refusal_category=DiscoverySchemaRefusalCategory.UNKNOWN_RULE,
                )
            )
            return ModelNativeDiscoveryPayload(model_result=result, candidates=())

    _, tools, _, _, _ = _composition(monkeypatch)
    outcome = run_model_native_discovery(plan, repository=tools._backend, backend=RefusalBackend())
    evidence = recorder.finalize(outcome)

    assert evidence is not None
    document = source_free_discovery_observation_document(evidence)
    before = _object_dict(document["before_collection"])
    assert before["schema_refusal_category"] == "UNKNOWN_RULE"
    assert "unregistered-rule" not in json.dumps(document, sort_keys=True)


def test_failed_capture_cannot_reconcile_to_successful_core_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from tests.integration.test_product_runtime_harness import _composition

    request, result = _success_result(monkeypatch)
    plan = _plan(request)
    success_recorder = PublicDiscoveryObservationRecorder(plan)
    _, tools, _, _, _ = _composition(monkeypatch)
    outcome = run_model_native_discovery(
        plan,
        repository=tools._backend,
        backend=_ObservingBackend(
            ModelNativeDiscoveryPayload(
                model_result=_with_usage(result, repository_calls=0), candidates=()
            ),
            success_recorder,
        ),
    )
    assert outcome.receipt.model_call_status is ModelCallStatus.SUCCEEDED
    recorder = PublicDiscoveryObservationRecorder(plan)
    failure = _non_success_result(request, ModelCallStatus.PROVIDER_ERROR, 0, 0, None)
    recorder.observe(
        ProductDiscoveryInvocationObservation(
            request=request,
            model_result_before_collection=failure,
            usage_before_collection=failure.usage,
            model_call_status_before_collection=ModelCallStatus.PROVIDER_ERROR,
            schema_valid_result_before_collection=False,
            repository_view_call_hashes=(),
            elapsed_known=False,
            token_usage_known=False,
        )
    )
    with pytest.raises(PublicDiscoveryObservationError):
        recorder.finalize(replace(outcome, candidates=()))
