"""Cross-dialect provider outcome normalization and fake-provider tests."""

from __future__ import annotations

import copy
import json
import pickle
import threading
import traceback
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import replace
from typing import Any

import pytest
from securecode_ai.adapters import (
    EphemeralStructuredPayload,
    HmacContentIdentifier,
    JsonObjectValidator,
    ModelBoundaryError,
    NormalizedModelAttempt,
    ProviderAttempt,
    ProviderAttemptBinding,
    ProviderStreamState,
    ScriptedFakeProvider,
    TransportFailure,
    normalize_provider_attempt,
    parse_model_call_result,
    parse_model_request,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ApiDialect,
    DataClass,
    EgressContentRef,
    EgressManifest,
    EgressPolicyDocument,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
)
from securecode_ai.core import (
    ComponentPin,
    ModelProvider,
    PayloadValidation,
    PreSendAuthorization,
    StructuredPayloadValidator,
    canonical_model_request_hash,
)

from .test_model_contracts import valid_request_payload, valid_success_result_payload
from .test_provider_preflight import (
    POLICIES,
    _issuer,
    _preflight_request,
    _profile,
    _semantic_cases,
)
from .test_provider_preflight import (
    _request as _scoped_request,
)

CANARY = "native-secret-canary-7a91"


def _request() -> ModelRequest:
    return ModelRequest.model_validate_json(json.dumps(valid_request_payload(), sort_keys=True))


def _validator(request: ModelRequest) -> JsonObjectValidator:
    return JsonObjectValidator(
        validator=request.output_schema,
        data_class=DataClass.CONFIDENTIAL_SECURITY,
        content_identifier=HmacContentIdentifier(b"k" * 32),
        required_keys=("candidates",),
    )


def _binding(request: ModelRequest) -> ProviderAttemptBinding:
    return ProviderAttemptBinding(
        request_hash=canonical_model_request_hash(request),
        profile_hash=request.provider_profile.content_sha256,
        policy_hash="c" * 64,
        manifest_hash="d" * 64,
        attempt=request.attempt,
    )


def _normalize(
    request: ModelRequest,
    attempt: ProviderAttempt,
    validator: StructuredPayloadValidator,
) -> NormalizedModelAttempt:
    return normalize_provider_attempt(
        request=request,
        attempt=attempt,
        expected_binding=attempt.binding,
        validator=validator,
    )


def _success_text() -> str:
    return json.dumps({"candidates": []}, separators=(",", ":"), sort_keys=True)


def _accept_model_provider(provider: ModelProvider) -> None:
    assert provider is not None


def _native_body(dialect: ApiDialect, status: ModelCallStatus) -> bytes:
    text: str | None = _success_text()
    finish = "COMPLETE"
    refusal = None
    filter_code = None
    if status is ModelCallStatus.REFUSED:
        refusal = "REFUSED"
    elif status is ModelCallStatus.CONTENT_FILTERED:
        filter_code = "CONTENT_FILTERED"
    elif status is ModelCallStatus.GUARDRAIL_BLOCKED:
        filter_code = "GUARDRAIL_BLOCKED"
    elif status is ModelCallStatus.INCOMPLETE:
        finish = "INCOMPLETE"
    elif status is ModelCallStatus.TRUNCATED:
        finish = "MAX_OUTPUT_TOKENS"
    elif status is ModelCallStatus.CONTEXT_EXHAUSTED:
        finish = "CONTEXT_EXHAUSTED"
    elif status is ModelCallStatus.INVALID_SCHEMA:
        text = "{not-json"
    elif status is ModelCallStatus.EMPTY_OUTPUT:
        text = "{}"
    elif status is ModelCallStatus.PROVIDER_ERROR:
        finish = "UNKNOWN_TERMINAL"

    document: dict[str, Any]
    if dialect is ApiDialect.FAKE:
        document = {
            "request_code": "FAKE_RESPONSE",
            "finish_code": finish,
            "refusal_code": refusal,
            "filter_code": filter_code,
            "content_text": text,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
    elif dialect is ApiDialect.OPENAI_RESPONSES:
        content: list[dict[str, Any]] = []
        if refusal is not None:
            content.append({"type": "refusal", "refusal": CANARY})
        if text is not None:
            content.append({"type": "output_text", "text": text})
        reason = {
            "INCOMPLETE": "provider_incomplete",
            "MAX_OUTPUT_TOKENS": "max_output_tokens",
            "CONTEXT_EXHAUSTED": "context_length",
            "UNKNOWN_TERMINAL": "unknown_terminal",
        }.get(finish)
        if filter_code is not None:
            reason = filter_code.lower()
        document = {
            "id": "resp_safe",
            "status": "completed" if finish == "COMPLETE" and filter_code is None else "incomplete",
            "incomplete_details": {"reason": reason} if reason else None,
            "output": [{"type": "message", "content": content}],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
    elif dialect is ApiDialect.ANTHROPIC_MESSAGES:
        stop = {
            "COMPLETE": "end_turn",
            "INCOMPLETE": "incomplete",
            "MAX_OUTPUT_TOKENS": "max_tokens",
            "CONTEXT_EXHAUSTED": "context_window_exceeded",
            "UNKNOWN_TERMINAL": "unknown_terminal",
        }[finish]
        if refusal is not None:
            stop = "refusal"
        elif filter_code == "CONTENT_FILTERED":
            stop = "content_filter"
        elif filter_code == "GUARDRAIL_BLOCKED":
            stop = "guardrail"
        document = {
            "id": "msg_safe",
            "stop_reason": stop,
            "content": [{"type": "text", "text": text}] if text is not None else [],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
    else:
        finish_reason = {
            "COMPLETE": "stop",
            "INCOMPLETE": "incomplete",
            "MAX_OUTPUT_TOKENS": "length",
            "CONTEXT_EXHAUSTED": "context_length",
            "UNKNOWN_TERMINAL": "unknown_terminal",
        }[finish]
        if filter_code == "CONTENT_FILTERED":
            finish_reason = "content_filter"
        elif filter_code == "GUARDRAIL_BLOCKED":
            finish_reason = "guardrail"
        document = {
            "id": "chatcmpl_safe",
            "choices": [
                {
                    "finish_reason": finish_reason,
                    "message": {"content": text, "refusal": CANARY if refusal else None},
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def _attempt(
    dialect: ApiDialect,
    status: ModelCallStatus,
    request: ModelRequest,
) -> ProviderAttempt:
    transport: TransportFailure | None = None
    http_status: int | None = 200
    if status is ModelCallStatus.TIMEOUT:
        transport = TransportFailure.TIMEOUT
        http_status = None
    elif status is ModelCallStatus.CANCELLED:
        transport = TransportFailure.CANCELLED
        http_status = None
    elif status is ModelCallStatus.BUDGET_EXHAUSTED:
        transport = TransportFailure.BUDGET_EXHAUSTED
        http_status = None
    elif status is ModelCallStatus.RATE_LIMITED:
        http_status = 429
    return ProviderAttempt(
        dialect=dialect,
        http_status=http_status,
        response_bytes=None if transport else _native_body(dialect, status),
        transport_failure=transport,
        stream_state=ProviderStreamState.COMPLETE,
        binding=_binding(request),
        elapsed_ms=20,
    )


@pytest.mark.parametrize("dialect", list(ApiDialect))
@pytest.mark.parametrize("status", list(ModelCallStatus))
def test_every_status_normalizes_identically_across_dialects(
    dialect: ApiDialect, status: ModelCallStatus
) -> None:
    request = _request().model_copy(update={"api_dialect": dialect})
    attempt = _attempt(dialect, status, request)
    normalized = _normalize(request, attempt, _validator(request))
    assert normalized.result.status is status
    assert (normalized.payload is not None) is (status is ModelCallStatus.SUCCEEDED)
    if status is not ModelCallStatus.SUCCEEDED:
        assert normalized.result.content_provenance is None
        assert normalized.result.safe_reason_code is not None


def test_provider_non_success_fail_open_matrix_has_zero_named_failures() -> None:
    non_success_to_pass_count = 0
    refusal_to_no_finding_count = 0
    for dialect in ApiDialect:
        request = _request().model_copy(update={"api_dialect": dialect})
        for status in ModelCallStatus:
            attempt = _attempt(dialect, status, request)
            normalized = _normalize(request, attempt, _validator(request))
            if status is not ModelCallStatus.SUCCEEDED:
                non_success_to_pass_count += int(
                    normalized.result.status is ModelCallStatus.SUCCEEDED
                )
            if status is ModelCallStatus.REFUSED:
                refusal_to_no_finding_count += int(normalized.payload is not None)
    assert non_success_to_pass_count == 0
    assert refusal_to_no_finding_count == 0


@pytest.mark.parametrize("dialect", list(ApiDialect))
def test_refusal_wins_over_success_shaped_content_and_never_leaks(dialect: ApiDialect) -> None:
    request = _request().model_copy(update={"api_dialect": dialect})
    attempt = _attempt(dialect, ModelCallStatus.REFUSED, request)
    normalized = _normalize(request, attempt, _validator(request))
    rendered = normalized.result.model_dump_json() + repr(normalized) + str(normalized)
    assert normalized.result.status is ModelCallStatus.REFUSED
    assert CANARY not in rendered
    assert normalized.payload is None


@pytest.mark.parametrize(
    "stream_state", [ProviderStreamState.INTERRUPTED, ProviderStreamState.DUPLICATED]
)
def test_interrupted_or_duplicated_stream_is_incomplete(
    stream_state: ProviderStreamState,
) -> None:
    request = _request().model_copy(update={"api_dialect": ApiDialect.OPENAI_RESPONSES})
    attempt = _attempt(ApiDialect.OPENAI_RESPONSES, ModelCallStatus.SUCCEEDED, request)
    attempt = ProviderAttempt(
        dialect=attempt.dialect,
        http_status=attempt.http_status,
        response_bytes=attempt.response_bytes,
        transport_failure=attempt.transport_failure,
        stream_state=stream_state,
        binding=attempt.binding,
        elapsed_ms=attempt.elapsed_ms,
    )
    assert (
        _normalize(request, attempt, _validator(request)).result.status
        is ModelCallStatus.INCOMPLETE
    )


def test_wrong_request_or_profile_and_malformed_envelope_are_typed_non_success() -> None:
    request = _request().model_copy(update={"api_dialect": ApiDialect.OPENAI_RESPONSES})
    base = _attempt(ApiDialect.OPENAI_RESPONSES, ModelCallStatus.SUCCEEDED, request)
    mutations = (
        replace(base, binding=replace(base.binding, request_hash="0" * 64)),
        replace(base, binding=replace(base.binding, profile_hash="0" * 64)),
        replace(base, binding=replace(base.binding, policy_hash="0" * 64)),
        replace(base, binding=replace(base.binding, manifest_hash="0" * 64)),
        replace(base, binding=replace(base.binding, attempt=request.attempt + 1)),
        replace(base, response_bytes=b'{"x":1,"x":2}'),
        replace(base, response_bytes=b"[[]"),
        replace(base, response_bytes=b"x" * (1024 * 1024 + 1)),
    )
    for attempt in mutations:
        result = normalize_provider_attempt(
            request=request,
            attempt=attempt,
            expected_binding=base.binding,
            validator=_validator(request),
        ).result
        assert result.status is ModelCallStatus.PROVIDER_ERROR


def test_dialect_is_bound_to_request_and_unknown_native_signals_fail_closed() -> None:
    request = _request()
    wrong_dialect = _attempt(
        ApiDialect.OPENAI_RESPONSES,
        ModelCallStatus.SUCCEEDED,
        request,
    )
    assert (
        _normalize(request, wrong_dialect, _validator(request)).result.status
        is ModelCallStatus.PROVIDER_ERROR
    )

    fake = _attempt(ApiDialect.FAKE, ModelCallStatus.SUCCEEDED, request)
    fake_document = json.loads(fake.response_bytes or b"{}")
    fake_document["filter_code"] = "UNKNOWN_FILTER"
    unknown_filter = replace(
        fake,
        response_bytes=json.dumps(fake_document, sort_keys=True).encode(),
    )
    assert (
        _normalize(request, unknown_filter, _validator(request)).result.status
        is ModelCallStatus.PROVIDER_ERROR
    )

    openai_request = request.model_copy(update={"api_dialect": ApiDialect.OPENAI_RESPONSES})
    openai = _attempt(
        ApiDialect.OPENAI_RESPONSES,
        ModelCallStatus.INCOMPLETE,
        openai_request,
    )
    openai_document = json.loads(openai.response_bytes or b"{}")
    openai_document["incomplete_details"] = None
    missing_reason = replace(
        openai,
        response_bytes=json.dumps(openai_document, sort_keys=True).encode(),
    )
    assert (
        _normalize(openai_request, missing_reason, _validator(openai_request)).result.status
        is ModelCallStatus.PROVIDER_ERROR
    )


def test_reported_usage_over_request_budget_is_typed_budget_exhaustion() -> None:
    request = _request()
    attempt = _attempt(ApiDialect.FAKE, ModelCallStatus.SUCCEEDED, request)
    document = json.loads(attempt.response_bytes or b"{}")
    document["usage"] = {
        "input_tokens": request.budget.max_input_tokens + 1,
        "output_tokens": request.budget.max_output_tokens + 1,
    }
    over_budget = replace(attempt, response_bytes=json.dumps(document, sort_keys=True).encode())
    assert (
        _normalize(request, over_budget, _validator(request)).result.status
        is ModelCallStatus.BUDGET_EXHAUSTED
    )


def test_unbounded_native_numbers_fail_closed_without_validation_exceptions() -> None:
    request = _request()
    attempt = _attempt(ApiDialect.FAKE, ModelCallStatus.SUCCEEDED, request)
    document = json.loads(attempt.response_bytes or b"{}")
    document["usage"]["input_tokens"] = 10**30
    oversized_usage = replace(attempt, response_bytes=json.dumps(document, sort_keys=True).encode())
    oversized_elapsed = replace(attempt, elapsed_ms=10**30)

    def corrupted(field: str, value: object) -> ProviderAttempt:
        candidate = replace(attempt)
        object.__setattr__(candidate, field, value)
        return candidate

    invalid_scalars = (
        replace(attempt, elapsed_ms=True),
        replace(attempt, elapsed_ms=1.5),  # type: ignore[arg-type]
        corrupted("http_status", True),
        corrupted("http_status", 200.5),
        corrupted("response_bytes", "{}"),
        corrupted("redirected", 0),
    )
    for candidate in (oversized_usage, oversized_elapsed, *invalid_scalars):
        normalized = _normalize(request, candidate, _validator(request))
        assert normalized.result.status is ModelCallStatus.PROVIDER_ERROR
        assert normalized.payload is None


def test_unknown_transport_and_openai_content_control_fail_closed() -> None:
    request = _request()
    base = _attempt(ApiDialect.FAKE, ModelCallStatus.SUCCEEDED, request)
    future_transport = replace(base, transport_failure="FUTURE_FAILURE")  # type: ignore[arg-type]
    assert (
        _normalize(request, future_transport, _validator(request)).result.status
        is ModelCallStatus.PROVIDER_ERROR
    )

    openai_request = request.model_copy(update={"api_dialect": ApiDialect.OPENAI_RESPONSES})
    attempt = _attempt(ApiDialect.OPENAI_RESPONSES, ModelCallStatus.SUCCEEDED, openai_request)
    document = json.loads(attempt.response_bytes or b"{}")
    document["output"][0]["content"].append({"type": "FUTURE_CONTROL", "text": _success_text()})
    future_content = replace(attempt, response_bytes=json.dumps(document, sort_keys=True).encode())
    assert (
        _normalize(openai_request, future_content, _validator(openai_request)).result.status
        is ModelCallStatus.PROVIDER_ERROR
    )

    anthropic_request = request.model_copy(update={"api_dialect": ApiDialect.ANTHROPIC_MESSAGES})
    attempt = _attempt(ApiDialect.ANTHROPIC_MESSAGES, ModelCallStatus.SUCCEEDED, anthropic_request)
    document = json.loads(attempt.response_bytes or b"{}")
    document["content"].append({"type": "FUTURE_CONTROL", "text": _success_text()})
    future_content = replace(attempt, response_bytes=json.dumps(document, sort_keys=True).encode())
    assert (
        _normalize(anthropic_request, future_content, _validator(anthropic_request)).result.status
        is ModelCallStatus.PROVIDER_ERROR
    )

    compatible_request = request.model_copy(update={"api_dialect": ApiDialect.OPENAI_COMPATIBLE})
    attempt = _attempt(ApiDialect.OPENAI_COMPATIBLE, ModelCallStatus.SUCCEEDED, compatible_request)
    document = json.loads(attempt.response_bytes or b"{}")
    document["choices"][0]["message"]["tool_calls"] = [{"id": "future-control"}]
    future_control = replace(attempt, response_bytes=json.dumps(document, sort_keys=True).encode())
    assert (
        _normalize(compatible_request, future_control, _validator(compatible_request)).result.status
        is ModelCallStatus.PROVIDER_ERROR
    )


@pytest.mark.parametrize(
    "dialect",
    [
        ApiDialect.OPENAI_RESPONSES,
        ApiDialect.ANTHROPIC_MESSAGES,
        ApiDialect.OPENAI_COMPATIBLE,
    ],
)
@pytest.mark.parametrize("mutation", ["provider_error", "unknown_top", "unknown_nested"])
def test_remote_provider_control_surfaces_are_closed(
    dialect: ApiDialect,
    mutation: str,
) -> None:
    request = _request().model_copy(update={"api_dialect": dialect})
    attempt = _attempt(dialect, ModelCallStatus.SUCCEEDED, request)
    document = json.loads(attempt.response_bytes or b"{}")
    control = {"type": "future_provider_error", "message": CANARY}
    if mutation == "provider_error":
        document["error"] = control
    elif mutation == "unknown_top":
        document["future_provider_control"] = control
    elif dialect is ApiDialect.OPENAI_RESPONSES:
        document["output"][0]["content"][0]["future_provider_control"] = control
    elif dialect is ApiDialect.ANTHROPIC_MESSAGES:
        document["content"][0]["future_provider_control"] = control
    else:
        document["choices"][0]["message"]["future_provider_control"] = control

    contradictory = replace(
        attempt,
        response_bytes=json.dumps(document, separators=(",", ":"), sort_keys=True).encode(),
    )
    normalized = _normalize(request, contradictory, _validator(request))
    assert normalized.result.status is ModelCallStatus.PROVIDER_ERROR
    assert normalized.payload is None
    assert CANARY not in repr(normalized.result)


@pytest.mark.parametrize(
    "restricted_value",
    ["sk-restricted-canary-123456", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"],
)
def test_restricted_output_canary_never_becomes_durable_success(
    restricted_value: str,
) -> None:
    request = _request()
    attempt = _attempt(ApiDialect.FAKE, ModelCallStatus.SUCCEEDED, request)
    document = json.loads(attempt.response_bytes or b"{}")
    document["content_text"] = json.dumps(
        {"candidates": [], "token": restricted_value},
        sort_keys=True,
    )
    restricted = replace(attempt, response_bytes=json.dumps(document, sort_keys=True).encode())
    normalized = _normalize(request, restricted, _validator(request))
    assert normalized.result.status is ModelCallStatus.INVALID_SCHEMA
    assert normalized.payload is None
    assert normalized.result.content_provenance is None
    assert restricted_value not in normalized.result.model_dump_json()


def test_normalization_boundary_rejects_permissive_or_malformed_validator_receipts() -> None:
    request = _request()
    attempt = _attempt(ApiDialect.FAKE, ModelCallStatus.SUCCEEDED, request)

    class PermissiveValidator:
        @property
        def validator(self) -> ComponentPin:
            return request.output_schema

        def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation:
            del payload
            return PayloadValidation(
                True,
                None,
                "kid:permissive-receipt",
                DataClass.CONFIDENTIAL_SECURITY,
                request.output_schema,
            )

    document = json.loads(attempt.response_bytes or b"{}")
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    document["content_text"] = json.dumps({"candidates": [], "token": secret})
    restricted = replace(attempt, response_bytes=json.dumps(document, sort_keys=True).encode())
    normalized = _normalize(request, restricted, PermissiveValidator())
    assert normalized.result.status is ModelCallStatus.INVALID_SCHEMA
    assert normalized.payload is None
    assert secret not in normalized.result.model_dump_json()

    class MalformedReceiptValidator(PermissiveValidator):
        def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation:
            del payload
            return PayloadValidation(
                True,
                None,
                "not-keyed",
                DataClass.CONFIDENTIAL_SECURITY,
                request.output_schema,
            )

    malformed = _normalize(request, attempt, MalformedReceiptValidator())
    assert malformed.result.status is ModelCallStatus.INVALID_SCHEMA
    assert malformed.payload is None


def test_ephemeral_payload_is_scoped_non_serializable_and_zeroizable() -> None:
    request = _request()
    attempt = _attempt(ApiDialect.FAKE, ModelCallStatus.SUCCEEDED, request)
    normalized = _normalize(request, attempt, _validator(request))
    payload = normalized.payload
    assert isinstance(payload, EphemeralStructuredPayload)
    assert payload.reveal_for(request.request_id) == {"candidates": []}
    with pytest.raises(ValueError):
        payload.reveal_for("other-request")
    with pytest.raises(TypeError):
        pickle.dumps(payload)
    with pytest.raises(TypeError):
        copy.deepcopy(payload)
    payload.close()
    with pytest.raises(ValueError):
        payload.reveal_for(request.request_id)


def test_scripted_fake_is_exact_idempotent_and_never_defaults_to_success() -> None:
    profile = _profile("valid.fake.json")
    policy_data = json.loads((POLICIES / "egress.valid.private-model-source.json").read_bytes())
    policy_data["policy_id"] = "private-fake-source"
    policy_data["rules"][0]["destinations"] = ["profile://fake-hermetic"]
    policy = EgressPolicyDocument.model_validate_json(json.dumps(policy_data, sort_keys=True))
    request = _scoped_request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    model_issuer = _issuer(profile, policy)

    def authorization_for(candidate: ModelRequest):  # type: ignore[no-untyped-def]
        case = dict(_semantic_cases()[0])
        case["required_execution_boundary"] = profile.execution_boundary.value
        pre = model_issuer.authorize_pre_context(
            _preflight_request(candidate, case), profile=profile, policy=policy
        )
        manifest = EgressManifest.build(
            model_request=candidate,
            policy=candidate.execution_identity.policy,
            destination="profile://fake-hermetic",
            payload_content_id="kid:fake-payload-1",
            content=(
                EgressContentRef(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    content_id="kid:fake-source-1",
                    data_class=DataClass.CONFIDENTIAL_SOURCE,
                ),
            ),
            applied_transforms=("bounded_repository_view",),
            byte_count=1024,
        )
        return model_issuer.authorize_pre_send(pre, manifest)

    attempt = _attempt(ApiDialect.FAKE, ModelCallStatus.SUCCEEDED, request)
    provider = ScriptedFakeProvider({canonical_model_request_hash(request): attempt})
    _accept_model_provider(provider)
    first = provider.invoke(
        request=request,
        authorization=authorization_for(request),
        model_issuer=model_issuer,
        validator=_validator(request),
    )
    duplicate = provider.invoke(
        request=request,
        authorization=authorization_for(request),
        model_issuer=model_issuer,
        validator=_validator(request),
    )
    assert first.result == duplicate.result
    assert provider.effect_count == 1

    conflicting = request.model_copy(update={"request_id": "conflicting-request"})
    conflict = provider.invoke(
        request=conflicting,
        authorization=authorization_for(conflicting),
        model_issuer=model_issuer,
        validator=_validator(conflicting),
    )
    assert conflict.result.status is ModelCallStatus.PROVIDER_ERROR
    assert provider.effect_count == 1

    unknown = request.model_copy(
        update={"request_id": "unknown-request", "idempotency_key": "idem-2"}
    )
    missing = provider.invoke(
        request=unknown,
        authorization=authorization_for(unknown),
        model_issuer=model_issuer,
        validator=_validator(unknown),
    )
    assert missing.result.status is ModelCallStatus.PROVIDER_ERROR
    assert provider.effect_count == 1


@pytest.mark.parametrize("force_wait_timeout", [False, True])
def test_scripted_fake_concurrent_duplicates_share_one_exact_effect(
    force_wait_timeout: bool,
) -> None:
    profile = _profile("valid.fake.json")
    policy_data = json.loads((POLICIES / "egress.valid.private-model-source.json").read_bytes())
    policy_data["policy_id"] = "private-fake-source"
    policy_data["rules"][0]["destinations"] = ["profile://fake-hermetic"]
    policy = EgressPolicyDocument.model_validate_json(json.dumps(policy_data, sort_keys=True))
    request = _scoped_request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    if force_wait_timeout:
        request = request.model_copy(
            update={"budget": request.budget.model_copy(update={"timeout_ms": 20})}
        )
    model_issuer = _issuer(profile, policy)

    def authorization() -> PreSendAuthorization:
        case = dict(_semantic_cases()[0])
        case["required_execution_boundary"] = profile.execution_boundary.value
        pre = model_issuer.authorize_pre_context(
            _preflight_request(request, case), profile=profile, policy=policy
        )
        manifest = EgressManifest.build(
            model_request=request,
            policy=request.execution_identity.policy,
            destination="profile://fake-hermetic",
            payload_content_id="kid:fake-race-payload",
            content=(
                EgressContentRef(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    content_id="kid:fake-race-source",
                    data_class=DataClass.CONFIDENTIAL_SOURCE,
                ),
            ),
            applied_transforms=("bounded_repository_view",),
            byte_count=1024,
        )
        return model_issuer.authorize_pre_send(pre, manifest)

    authorizations = (authorization(), authorization())
    entered = threading.Event()
    release = threading.Event()
    start = threading.Barrier(3)
    delegate = _validator(request)

    class BlockingValidator:
        @property
        def _content_identifier(self) -> HmacContentIdentifier:
            return delegate._content_identifier

        @property
        def validator(self) -> ComponentPin:
            return delegate.validator

        def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation:
            entered.set()
            assert release.wait(timeout=5), "test did not release fake normalization"
            return delegate.validate(payload, request=request)

    provider = ScriptedFakeProvider(
        {
            canonical_model_request_hash(request): _attempt(
                ApiDialect.FAKE, ModelCallStatus.SUCCEEDED, request
            )
        }
    )

    def invoke(index: int) -> NormalizedModelAttempt:
        start.wait(timeout=5)
        return provider.invoke(
            request=request,
            authorization=authorizations[index],
            model_issuer=model_issuer,
            validator=BlockingValidator(),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(invoke, 0)
        second_future = pool.submit(invoke, 1)
        start.wait(timeout=5)
        assert entered.wait(timeout=5)
        if force_wait_timeout:
            completed, _ = wait(
                (first_future, second_future), timeout=2, return_when=FIRST_COMPLETED
            )
            assert len(completed) == 1
        release.set()
        first = first_future.result(timeout=5)
        second = second_future.result(timeout=5)

    assert first is second
    expected = ModelCallStatus.PROVIDER_ERROR if force_wait_timeout else ModelCallStatus.SUCCEEDED
    assert first.result.status is expected
    assert provider.effect_count == 1


def test_keyed_content_identifier_is_tenant_scoped_not_raw_sha() -> None:
    identifier = HmacContentIdentifier(b"k" * 32)
    first = identifier.identify(tenant_id="tenant-a", payload=b"same")
    second = identifier.identify(tenant_id="tenant-b", payload=b"same")
    assert first.startswith("kid:")
    assert first != second
    assert first != "kid:" + __import__("hashlib").sha256(b"same").hexdigest()
    with pytest.raises(TypeError):
        copy.deepcopy(identifier)
    with pytest.raises(TypeError):
        pickle.dumps(identifier)
    with pytest.raises(AttributeError, match="immutable"):
        identifier._key = bytearray(b"x" * 32)
    with pytest.raises(AttributeError, match="immutable"):
        identifier._closed = True
    assert identifier.verify(tenant_id="tenant-a", payload=b"same", content_id=first)
    identifier.close()
    with pytest.raises(AttributeError, match="immutable"):
        identifier._closed = False
    with pytest.raises(ValueError, match="content identifier is closed"):
        identifier.identify(tenant_id="tenant-a", payload=b"same")

    tampered = HmacContentIdentifier(b"z" * 32)
    tampered._key[0] = 0
    with pytest.raises(ValueError, match="key integrity"):
        tampered.identify(tenant_id="tenant-a", payload=b"same")


@pytest.mark.parametrize(
    ("parser", "payload_factory", "code"),
    [
        (parse_model_request, valid_request_payload, "INVALID_MODEL_REQUEST"),
        (parse_model_call_result, valid_success_result_payload, "INVALID_MODEL_CALL_RESULT"),
    ],
)
def test_public_model_parsers_do_not_reflect_hostile_content(
    parser: Callable[[str | bytes | bytearray], object],
    payload_factory: Callable[[], dict[str, object]],
    code: str,
) -> None:
    payload = payload_factory()
    payload["raw_response"] = CANARY
    encoded = json.dumps(payload, sort_keys=True)
    with pytest.raises(ModelBoundaryError) as caught:
        parser(encoded)
    assert str(caught.value) == code
    assert CANARY not in "".join(traceback.format_exception(caught.value))


def test_public_model_parsers_round_trip_valid_json_enums_and_lists() -> None:
    request_bytes = json.dumps(valid_request_payload(), sort_keys=True).encode()
    result_bytes = json.dumps(valid_success_result_payload(), sort_keys=True).encode()
    assert parse_model_request(bytearray(request_bytes)) == _request()
    assert parse_model_call_result(result_bytes).status is ModelCallStatus.SUCCEEDED
