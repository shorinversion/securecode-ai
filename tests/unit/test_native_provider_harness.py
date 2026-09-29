"""Native selections pass the real issuers without becoming final success."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from typing import TypedDict, cast

import pytest
from securecode_ai.adapters import (
    AuthorizedProviderHarness,
    ConnectedChannel,
    CredentialLease,
    HmacContentIdentifier,
    JsonObjectValidator,
    PreparedModelContext,
    ProviderAttempt,
    ProviderAttemptBinding,
)
from securecode_ai.adapters.model import (
    NativeTurnBoundaryExecution,
    TransportFailure,
)
from securecode_ai.adapters.remote_provider_budget import RemoteProviderCallContext
from securecode_ai.contracts import (
    DataClass,
    EgressPolicyDocument,
    ModelCallStatus,
    ModelPreflightRequest,
    ModelPurpose,
    ModelRequest,
    ProviderProfile,
)
from securecode_ai.core import PreflightEligibility

from .test_endpoint_policy import (
    ScriptedResolver,
    SpyConnector,
    _endpoint_issuer,
    _remote_context,
    _success_attempt,
)
from .test_provider_preflight import (
    _issuer,
    _policy,
    _preflight_request,
    _profile,
    _request,
    _semantic_cases,
)


class _NativeArguments(TypedDict):
    preflight: ModelPreflightRequest
    profile: ProviderProfile
    policy: EgressPolicyDocument
    context_builder: Callable[[], PreparedModelContext]
    resolver: ScriptedResolver
    connector: SpyConnector
    credential_supplier: Callable[[ProviderProfile], CredentialLease | None]
    validator: JsonObjectValidator
    now: float


class _NativeFunction(TypedDict):
    name: str
    arguments: str


class _NativeToolCall(TypedDict):
    id: str
    type: str
    function: _NativeFunction


class _NativeMessage(TypedDict):
    role: str
    content: str | None
    refusal: str | None
    tool_calls: list[_NativeToolCall]


class _NativeChoice(TypedDict):
    finish_reason: str | None
    message: _NativeMessage


class _NativeUsage(TypedDict):
    prompt_tokens: int
    completion_tokens: int


class _NativeBody(TypedDict):
    id: str
    choices: list[_NativeChoice]
    usage: _NativeUsage


def _attempt(connector: SpyConnector) -> ProviderAttempt:
    assert connector.attempt is not None
    return connector.attempt


def _composition() -> tuple[
    AuthorizedProviderHarness,
    _NativeArguments,
    SpyConnector,
    PreparedModelContext,
    list[ProviderProfile],
]:
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    context = _remote_context(request)
    connector = SpyConnector(peer_ip="127.0.0.1", attempt=_success_attempt(request, profile))
    harness = AuthorizedProviderHarness(
        model_issuer=_issuer(profile, policy), endpoint_issuer=_endpoint_issuer(profile)
    )
    credentials: list[ProviderProfile] = []

    def credential_supplier(selected: ProviderProfile) -> CredentialLease | None:
        credentials.append(selected)
        raise AssertionError("local profile must not request a credential")

    arguments = _NativeArguments(
        preflight=_preflight_request(request, _semantic_cases()[0]),
        profile=profile,
        policy=policy,
        context_builder=lambda: context,
        resolver=ScriptedResolver(("127.0.0.1",), ("127.0.0.1",)),
        connector=connector,
        credential_supplier=credential_supplier,
        validator=JsonObjectValidator(
            validator=request.output_schema,
            data_class=DataClass.CONFIDENTIAL_SECURITY,
            content_identifier=HmacContentIdentifier(b"v" * 32),
            required_keys=("candidates",),
        ),
        now=100.0,
    )
    return harness, arguments, connector, context, credentials


def _calls(request: ModelRequest) -> list[_NativeToolCall]:
    common = {"schema_version": "0.1.0", "head_sha": request.head_sha}
    choices: list[tuple[str, dict[str, object]]] = [
        ("list_paths", {"prefix": "", "max_entries": 4}),
        ("lookup_symbol", {"symbol": "query", "path": "a.py"}),
        ("read_range", {"path": "a.py", "start_line": 1, "end_line": 2}),
        ("read_evidence", {"evidence_id": "source-alias"}),
    ]
    return [
        {
            "id": f"native-call-{index}",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(common | arguments)},
        }
        for index, (name, arguments) in enumerate(choices)
    ]


def _selection(arguments: _NativeArguments, connector: SpyConnector) -> _NativeBody:
    request = arguments["preflight"].model_request
    body: _NativeBody = {
        "id": "native-turn-1",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "refusal": None,
                    "tool_calls": _calls(request),
                },
            }
        ],
        "usage": {"prompt_tokens": 20, "completion_tokens": 10},
    }
    connector.attempt = replace(_attempt(connector), response_bytes=json.dumps(body).encode())
    return body


def _status(execution: NativeTurnBoundaryExecution) -> ModelCallStatus:
    assert execution.selection is None and execution.terminal is not None
    assert execution.terminal.result is not None
    return execution.terminal.result.status


def test_native_selection_is_nonterminal_metered_bound_and_replayed_once() -> None:
    harness, arguments, connector, context, credentials = _composition()
    _selection(arguments, connector)
    execution = harness.execute_native_turn(**arguments)
    assert type(execution) is NativeTurnBoundaryExecution
    assert execution.terminal is None and execution.selection is not None
    assert len(execution.selection) == 4
    assert [call.request.tool.value for call in execution.selection] == [
        "list_paths",
        "lookup_symbol",
        "read_range",
        "read_evidence",
    ]
    assert execution.usage is not None
    assert execution.usage.input_tokens == 20 and execution.usage.output_tokens == 10
    assert execution.usage.repository_calls == 0 and execution.elapsed_ms == 20
    assert harness.execute_native_turn(**arguments) is execution
    assert connector.events == ["connect", "send"] and not credentials
    with pytest.raises(ValueError):
        context.bytes_for(arguments["preflight"].model_request.request_id)
    assert "source-alias" not in repr(execution)


@pytest.mark.parametrize("native_first", [True, False])
def test_native_and_final_modes_cannot_reuse_an_idempotency_key(native_first: bool) -> None:
    harness, arguments, connector, _, _ = _composition()
    if native_first:
        _selection(arguments, connector)
        assert harness.execute_native_turn(**arguments).selection is not None
        conflict = harness.execute_remote(**arguments)
        assert conflict.result is not None
        assert conflict.result.status is ModelCallStatus.PROVIDER_ERROR
    else:
        final = harness.execute_remote(**arguments)
        assert final.result is not None
        assert final.result.status is ModelCallStatus.SUCCEEDED
        assert _status(harness.execute_native_turn(**arguments)) is ModelCallStatus.PROVIDER_ERROR
    assert connector.events == ["connect", "send"]


def test_native_terminal_uses_existing_validator_and_normalizer() -> None:
    harness, arguments, connector, _, _ = _composition()
    execution = harness.execute_native_turn(**arguments)
    assert _status(execution) is ModelCallStatus.SUCCEEDED
    assert execution.terminal is not None
    assert execution.terminal.payload is not None
    assert connector.events == ["connect", "send"]


def test_native_ineligible_preflight_has_zero_context_and_transport_effects() -> None:
    harness, arguments, connector, _, _ = _composition()
    arguments["preflight"] = arguments["preflight"].model_copy(
        update={"planned_transforms": ("secret_redaction",)}
    )

    def forbidden_context() -> PreparedModelContext:
        raise AssertionError("context was assembled")

    arguments["context_builder"] = forbidden_context
    execution = harness.execute_native_turn(**arguments)
    assert execution.selection is None and execution.terminal is not None
    assert execution.terminal.result is None
    assert execution.preflight.eligibility is PreflightEligibility.INELIGIBLE
    assert connector.events == [] and connector.application_bytes == 0


@pytest.mark.parametrize(
    "mutation",
    [
        "head",
        "duplicate-id",
        "unknown-tool",
        "mixed-content",
        "mixed-refusal",
        "extra-message",
        "extra-envelope",
        "duplicate-field",
        "invalid-usage",
        "invalid-response-id",
        "oversized-response-id",
    ],
)
def test_invalid_native_selection_never_exposes_calls(mutation: str) -> None:
    harness, arguments, connector, _, _ = _composition()
    body = _selection(arguments, connector)
    message = body["choices"][0]["message"]
    if mutation == "head":
        function = message["tool_calls"][0]["function"]
        fields = json.loads(function["arguments"])
        fields["head_sha"] = "2" * 40
        function["arguments"] = json.dumps(fields)
    elif mutation == "duplicate-id":
        message["tool_calls"][1]["id"] = message["tool_calls"][0]["id"]
    elif mutation == "unknown-tool":
        message["tool_calls"][0]["function"]["name"] = "shell"
    elif mutation == "mixed-content":
        message["content"] = '{"candidates":[]}'
    elif mutation == "mixed-refusal":
        message["refusal"] = "REFUSED"
    elif mutation == "extra-message":
        cast(dict[str, object], message)["future"] = True
    elif mutation == "extra-envelope":
        cast(dict[str, object], body)["future"] = True
    elif mutation == "invalid-usage":
        body["usage"]["prompt_tokens"] = True
    elif mutation == "invalid-response-id":
        body["id"] = "id\ncontrol"
    elif mutation == "oversized-response-id":
        body["id"] = "x" * 129
    encoded = json.dumps(body).encode()
    if mutation == "duplicate-field":
        encoded = encoded.replace(b'"id": "native-turn-1"', b'"id":"a","id":"b"')
    connector.attempt = replace(_attempt(connector), response_bytes=encoded)
    assert _status(harness.execute_native_turn(**arguments)) is ModelCallStatus.PROVIDER_ERROR
    assert connector.events == ["connect", "send"]


@pytest.mark.parametrize("field", ["prompt_tokens", "completion_tokens", "elapsed_ms"])
def test_native_actual_usage_limits_fail_closed(field: str) -> None:
    harness, arguments, connector, _, _ = _composition()
    body = _selection(arguments, connector)
    request = arguments["preflight"].model_request
    if field == "elapsed_ms":
        connector.attempt = replace(_attempt(connector), elapsed_ms=request.budget.timeout_ms + 1)
    else:
        if field == "prompt_tokens":
            body["usage"]["prompt_tokens"] = request.budget.max_input_tokens + 1
        else:
            body["usage"]["completion_tokens"] = request.budget.max_output_tokens + 1
        connector.attempt = replace(_attempt(connector), response_bytes=json.dumps(body).encode())
    execution = harness.execute_native_turn(**arguments)
    assert _status(execution) is ModelCallStatus.BUDGET_EXHAUSTED
    assert execution.terminal is not None and execution.terminal.result is not None
    assert execution.terminal.result.usage.input_tokens == body["usage"]["prompt_tokens"]


@pytest.mark.parametrize(
    "failure,status",
    [
        (TransportFailure.TIMEOUT, ModelCallStatus.TIMEOUT),
        (TransportFailure.CANCELLED, ModelCallStatus.CANCELLED),
        (TransportFailure.PROVIDER_ERROR, ModelCallStatus.PROVIDER_ERROR),
    ],
)
def test_native_transport_failures_remain_typed_terminal(
    failure: TransportFailure, status: ModelCallStatus
) -> None:
    harness, arguments, connector, _, _ = _composition()
    _selection(arguments, connector)
    connector.attempt = replace(_attempt(connector), transport_failure=failure)
    assert _status(harness.execute_native_turn(**arguments)) is status


def test_native_connector_cannot_forge_consumed_attempt_binding() -> None:
    harness, arguments, connector, _, _ = _composition()
    _selection(arguments, connector)
    original = connector.send

    def forged_send(
        channel: ConnectedChannel,
        *,
        credential: str | None,
        payload: bytes,
        model_id: str,
        timeout_ms: int,
        binding: ProviderAttemptBinding,
        call_budget: RemoteProviderCallContext,
    ) -> ProviderAttempt:
        attempt = original(
            channel,
            credential=credential,
            payload=payload,
            model_id=model_id,
            timeout_ms=timeout_ms,
            binding=binding,
            call_budget=call_budget,
        )
        return replace(attempt, binding=replace(attempt.binding, manifest_hash="f" * 64))

    connector.__dict__["send"] = forged_send
    assert _status(harness.execute_native_turn(**arguments)) is ModelCallStatus.PROVIDER_ERROR


def test_native_final_schema_failure_is_not_completed_zero() -> None:
    harness, arguments, connector, _, _ = _composition()
    response_bytes = _attempt(connector).response_bytes
    assert response_bytes is not None
    body = json.loads(response_bytes)
    body["choices"][0]["message"]["content"] = '{"other":true}'
    connector.attempt = replace(_attempt(connector), response_bytes=json.dumps(body).encode())
    assert _status(harness.execute_native_turn(**arguments)) is ModelCallStatus.INVALID_SCHEMA
