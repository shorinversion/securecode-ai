"""Native selections enter the actual Core repository guard, never a direct view."""

import json
from collections.abc import Callable
from typing import TypeGuard

import pytest
from securecode_ai.adapters.model import (
    ConnectedChannel,
    NativeTurnBoundaryExecution,
    PreparedModelContext,
    ProviderAttempt,
    ProviderAttemptBinding,
)
from securecode_ai.adapters.native_sources import build_native_source_catalogue
from securecode_ai.adapters.product_runtime import (
    ProductDiscoveryBackend,
    dispatch_native_repository_calls,
)
from securecode_ai.contracts import ModelRequest
from securecode_ai.core import StructuredPayloadValidator
from securecode_ai.core.model_discovery import RepositoryToolSession
from securecode_ai.core.tool_policy import (
    RepositoryToolBudget,
    RepositoryToolGuard,
    RepositoryToolScope,
)

from tests.unit.test_native_repository_tools import _call
from tests.unit.test_native_sources import repository


def _is_object_dict(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _object_dict(value: object) -> dict[str, object]:
    assert _is_object_dict(value)
    return value


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _object_list(value: object) -> list[object]:
    assert _is_object_list(value)
    return value


def _text(value: object) -> str:
    assert isinstance(value, str)
    return value


def composition() -> tuple[str, RepositoryToolSession, list[dict[str, object]]]:
    reader, head, _ = repository("a.py", b"def handler():\n    return 1\n")
    catalogue = build_native_source_catalogue(
        reader=reader,
        head_sha=head,
        tenant_id="tenant-a",
        repository_id="repo-a",
        content_key=b"p" * 32,
    )
    scope = RepositoryToolScope(
        "tenant-a",
        "repo-a",
        head,
        ("a.py",),
        tuple(sorted(anchor.evidence_id for anchor in catalogue.anchors)),
    )
    session = RepositoryToolSession(
        backend=catalogue.repository_view(),
        guard=RepositoryToolGuard(scope=scope, budget=RepositoryToolBudget(4, 65536, 65536)),
    )
    common = {"schema_version": "0.1.0", "head_sha": head}
    calls = [
        _call("list_paths", {**common, "prefix": "a.py", "max_entries": 4}, "call-1"),
        _call("lookup_symbol", {**common, "symbol": "handler", "path": "a.py"}, "call-2"),
        _call("read_range", {**common, "path": "a.py", "start_line": 1, "end_line": 2}, "call-3"),
        _call(
            "read_evidence", {**common, "evidence_id": catalogue.anchors[0].evidence_id}, "call-4"
        ),
    ]
    return head, session, calls


def test_all_native_tools_have_actual_guard_receipts() -> None:
    head, session, calls = composition()
    batch = dispatch_native_repository_calls(calls, head_sha=head, tools=session)
    assert batch.is_complete and session.calls_used == 4
    assert [result.receipt.sequence for result in batch.results] == [1, 2, 3, 4]
    assert all(result.receipt.output_sha256 for result in batch.results)
    assert "return 1" not in repr(batch)


def test_whole_native_batch_validated_before_first_read() -> None:
    head, session, calls = composition()
    function = _object_dict(calls[-1]["function"])
    arguments = json.loads(_text(function["arguments"]))
    arguments["head_sha"] = "b" * 40
    function["arguments"] = json.dumps(arguments)
    with pytest.raises(ValueError):
        dispatch_native_repository_calls(calls, head_sha=head, tools=session)
    assert session.calls_used == 0


def test_native_path_denial_keeps_nonterminal_incomplete_batch() -> None:
    head, session, calls = composition()
    function = _object_dict(calls[2]["function"])
    arguments = json.loads(_text(function["arguments"]))
    arguments["path"] = "other.py"
    function["arguments"] = json.dumps(arguments)
    batch = dispatch_native_repository_calls(calls, head_sha=head, tools=session)
    assert not batch.is_complete
    assert batch.results[2].output is None


def test_native_connector_sends_pinned_tools_and_preserves_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters.native_repository_tools import NATIVE_REPOSITORY_TOOLS_JSON
    from securecode_ai.adapters.openai_compatible_local import OpenAICompatibleLocalHttpConnector

    from tests.unit.test_local_provider_gateway import _native_call, _native_request
    from tests.unit.test_openai_compatible_local import _LocalEndpoint, _profile_for
    from tests.unit.test_provider_normalization import _binding, _request

    response = {
        "id": "native-turn-1",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "refusal": None,
                    "tool_calls": [_native_call()],
                },
            }
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
    }
    endpoint = _LocalEndpoint(status=200, body=json.dumps(response).encode())
    endpoint.install(monkeypatch)
    profile = _profile_for(endpoint.port)
    connector = OpenAICompatibleLocalHttpConnector(
        profile=profile, native_frames=True
    ).with_output_token_limit(32)
    native_request = _native_request()
    messages = _object_list(native_request["messages"])
    initial_message = _object_dict(messages[0])
    initial = json.loads(_text(initial_message["content"]))
    frame = json.dumps({"initial_context": initial, "tool_history": []}).encode()
    channel = connector.connect(
        ip_address="127.0.0.1", port=endpoint.port, server_name="127.0.0.1", timeout_ms=1000
    )
    attempt = connector.send(
        channel,
        credential=None,
        payload=frame,
        model_id=profile.model_id,
        timeout_ms=1000,
        binding=_binding(_request()),
    )
    assert attempt.http_status == 200 and attempt.response_bytes is not None
    assert json.loads(attempt.response_bytes)["choices"][0]["finish_reason"] == "tool_calls"
    sent = json.loads(endpoint.requests[0][2])
    assert sent["tools"] == json.loads(NATIVE_REPOSITORY_TOOLS_JSON)
    assert json.loads(sent["messages"][0]["content"]) == initial
    assert sent["max_tokens"] == 32


def test_guarded_native_result_history_is_quoted_and_paired() -> None:
    from securecode_ai.adapters.local_provider_gateway import _validate_native_transcript
    from securecode_ai.adapters.product_runtime import native_repository_history

    head, session, calls = composition()
    batch = dispatch_native_repository_calls(calls, head_sha=head, tools=session)
    history = native_repository_history(batch, head_sha=head)
    assert len(history) == 5
    assert not _validate_native_transcript([{}, *history], head_sha=head)
    for result in history[1:]:
        payload = json.loads(_text(result["content"]))
        assert (
            payload["instruction_authority"] == "NONE"
            and payload["data_class"] == "DC3_CONFIDENTIAL_SOURCE"
        )
    with pytest.raises(ValueError):
        native_repository_history(batch, head_sha="b" * 40)


def test_incomplete_native_batch_cannot_be_sent_as_successful_history() -> None:
    from securecode_ai.adapters.product_runtime import native_repository_history

    head, session, calls = composition()
    function = _object_dict(calls[2]["function"])
    arguments = json.loads(_text(function["arguments"]))
    arguments["path"] = "other.py"
    function["arguments"] = json.dumps(arguments)
    batch = dispatch_native_repository_calls(calls, head_sha=head, tools=session)
    with pytest.raises(ValueError):
        native_repository_history(batch, head_sha=head)


@pytest.mark.parametrize("configured_limit,request_limit", [(None, 8), (4, 8), (None, 4097)])
@pytest.mark.parametrize(
    "entry_point",
    ["harness", "product_executor", "product_executor_expired", "product_executor_connect_expired"],
)
def test_authorized_native_harness_and_real_connector_selection(
    monkeypatch: pytest.MonkeyPatch,
    configured_limit: int | None,
    request_limit: int,
    entry_point: str,
) -> None:
    from securecode_ai.adapters import (
        AuthorizedProviderHarness,
        EndpointAuthorizationIssuer,
        ProviderProfileRegistry,
    )
    from securecode_ai.adapters.model import HmacContentIdentifier, PreparedModelContext
    from securecode_ai.adapters.openai_compatible_local import OpenAICompatibleLocalHttpConnector
    from securecode_ai.contracts import ModelPurpose, PreflightEligibility

    from tests.unit.test_endpoint_policy import ScriptedResolver, _remote_context
    from tests.unit.test_local_provider_gateway import _native_call, _native_request
    from tests.unit.test_openai_compatible_local import _LocalEndpoint, _profile_for
    from tests.unit.test_provider_normalization import _validator
    from tests.unit.test_provider_preflight import (
        _issuer,
        _policy,
        _preflight_request,
        _request,
        _semantic_cases,
    )

    endpoint = _LocalEndpoint(status=200, body=b"{}")
    endpoint.install(monkeypatch)
    profile = _profile_for(endpoint.port)
    policy = _policy("egress.valid.private-model-source.json")
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    request_data = request.model_dump(mode="json")
    request_data["budget"]["max_output_tokens"] = request_limit
    request_data["budget"]["max_input_tokens"] = max(
        request_data["budget"]["max_input_tokens"], request_limit
    )
    request = type(request).model_validate_json(json.dumps(request_data))
    head = request.execution_identity.repository_revision.head_sha
    call = _native_call()
    call_function = _object_dict(call["function"])
    arguments = json.loads(_text(call_function["arguments"]))
    arguments["head_sha"] = head
    call_function["arguments"] = json.dumps(arguments)
    response = {
        "id": "native-turn-1",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "refusal": None,
                    "tool_calls": [call],
                },
            }
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1},
    }
    endpoint = _LocalEndpoint(status=200, body=json.dumps(response).encode())
    endpoint.install(monkeypatch)
    native_request = _native_request()
    messages = _object_list(native_request["messages"])
    initial_message = _object_dict(messages[0])
    initial = json.loads(_text(initial_message["content"]))
    initial["trusted_controls"]["source_revision"]["head_sha"] = head
    frame = json.dumps({"initial_context": initial, "tool_history": []}).encode()
    from securecode_ai.adapters.product_runtime import native_turn_request

    request = native_turn_request(
        request, ordinal=0, budget=request.budget, frame=frame, content_key=b"p" * 32
    )

    build_calls: list[bool] = []

    def build() -> PreparedModelContext:
        build_calls.append(True)
        old = _remote_context(request)
        content, transforms = old.content, old.applied_transforms
        old.close()
        return PreparedModelContext(
            payload=frame,
            content=content,
            applied_transforms=transforms,
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            content_identifier=HmacContentIdentifier(b"p" * 32),
        )

    harness = AuthorizedProviderHarness(
        model_issuer=_issuer(profile, policy),
        endpoint_issuer=EndpointAuthorizationIssuer(
            provider_registry=ProviderProfileRegistry((profile,))
        ),
    )
    connector = OpenAICompatibleLocalHttpConnector(
        profile=profile, native_frames=True, max_output_tokens=configured_limit
    )
    original_limit = connector._max_output_tokens
    if entry_point.startswith("product_executor"):
        from securecode_ai.adapters.product_runtime import AuthorizedLocalModelExecutor

        clock = [100.0]
        opened_channels = []
        if entry_point == "product_executor_connect_expired":
            original_connect = OpenAICompatibleLocalHttpConnector.connect

            def delayed_connect(
                selected: OpenAICompatibleLocalHttpConnector,
                *,
                ip_address: str,
                port: int,
                server_name: str,
                timeout_ms: int,
            ) -> ConnectedChannel:
                channel = original_connect(
                    selected,
                    ip_address=ip_address,
                    port=port,
                    server_name=server_name,
                    timeout_ms=timeout_ms,
                )
                opened_channels.append(channel)
                clock[0] = 100.0 + request.budget.timeout_ms / 1000 + 1
                return channel

            monkeypatch.setattr(OpenAICompatibleLocalHttpConnector, "connect", delayed_connect)
        executor = AuthorizedLocalModelExecutor(
            harness=harness,
            registry=ProviderProfileRegistry((profile,)),
            profile=profile,
            policy=policy,
            resolver=ScriptedResolver(),
            connector=connector,
            preflight=lambda selected: _preflight_request(selected, dict(_semantic_cases()[0])),
            now=lambda: clock[0],
        )
        if entry_point == "product_executor_expired":
            with pytest.raises(RuntimeError, match="authorized model execution failed"):
                executor.execute_native(
                    request=request,
                    context_builder=build,
                    validator=_validator(request),
                    started_at=0.0,
                )
            assert endpoint.requests == [] and build_calls == []
            return
        if (
            entry_point == "product_executor_connect_expired"
            and request_limit <= profile.capabilities.max_output_tokens
        ):
            with pytest.raises(RuntimeError, match="authorized model execution failed"):
                executor.execute_native(
                    request=request,
                    context_builder=build,
                    validator=_validator(request),
                    started_at=100.0,
                )
            assert endpoint.requests == []
            assert opened_channels and all(
                getattr(channel, "_closed", False) for channel in opened_channels
            )
            if request_limit <= profile.capabilities.max_output_tokens:
                assert build_calls == [True]
            return
        execution = executor.execute_native(
            request=request,
            context_builder=build,
            validator=_validator(request),
            started_at=100.0,
        )
    else:
        execution = harness.execute_native_turn(
            preflight=_preflight_request(request, dict(_semantic_cases()[0])),
            profile=profile,
            policy=policy,
            context_builder=build,
            resolver=ScriptedResolver(),
            connector=connector,
            credential_supplier=lambda selected: None,
            validator=_validator(request),
            now=100.0,
        )
    if request_limit > profile.capabilities.max_output_tokens:
        assert execution.selection is None and execution.terminal is not None
        assert execution.terminal.preflight.eligibility is PreflightEligibility.INELIGIBLE
        assert endpoint.requests == [] and build_calls == []
        return
    assert execution.terminal is None and execution.selection is not None
    assert execution.usage is not None
    assert execution.selection[0].call_id == "call-1"
    assert execution.usage.input_tokens == 2 and execution.usage.output_tokens == 1
    assert len(endpoint.requests) == 1
    assert json.loads(endpoint.requests[0][2])["max_tokens"] == min(8, original_limit)
    assert connector._max_output_tokens == original_limit


class _NativeSequenceEndpoint:
    """Script only sockets; authorization, connector and Core reads remain real."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, bodies: list[bytes]) -> None:
        from tests.unit.test_openai_compatible_local import _LocalEndpoint

        self.endpoint = _LocalEndpoint(status=200, body=bodies[0])
        self.bodies = bodies
        self.connections = 0
        original = self.endpoint._socket_factory

        def socket_factory(
            family: int,
            kind: int,
            proto: int = 0,
            fileno: int | None = None,
        ) -> object:
            if self.connections >= len(self.bodies):
                raise OSError("unexpected additional model turn")
            body = self.bodies[self.connections]
            self.connections += 1
            self.endpoint.response = (
                f"HTTP/1.1 200 scripted\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode() + body
            return original(family, kind, proto, fileno)

        monkeypatch.setattr("socket.socket", socket_factory)


def _cycle_fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    candidate: bool = False,
    second: str = "valid",
    call_budget: int = 8,
) -> tuple[ProductDiscoveryBackend, RepositoryToolSession, ModelRequest, _NativeSequenceEndpoint]:
    from securecode_ai.adapters.openai_compatible_local import OpenAICompatibleLocalHttpConnector
    from securecode_ai.adapters.product_runtime import ProductDiscoveryBackend

    from tests.integration.test_product_runtime_harness import _composition
    from tests.unit.test_openai_compatible_local import _success_body

    base, tools, request, _, _ = _composition(monkeypatch)
    value = request.model_dump(mode="json")
    value["budget"]["max_repository_calls"] = call_budget
    request = type(request).model_validate_json(json.dumps(value))
    anchor = base._catalogue[0]
    arguments = {
        "schema_version": "0.1.0",
        "head_sha": request.head_sha,
        "path": anchor.location.path,
        "start_line": 1,
        "end_line": 1,
    }

    def selection(call_id: str) -> dict[str, object]:
        return {
            "id": f"response-{call_id}",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "refusal": None,
                        "tool_calls": [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {
                                    "name": "read_range",
                                    "arguments": json.dumps(arguments),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1},
        }

    first = selection("call-1")
    middle = selection("call-2")
    if second == "duplicate":
        middle = selection("call-1")
    elif second == "wrong_head":
        broken = {**arguments, "head_sha": "f" * 40}
        choices = _object_list(middle["choices"])
        choice = _object_dict(choices[0])
        message = _object_dict(choice["message"])
        calls = _object_list(message["tool_calls"])
        selected_call = _object_dict(calls[0])
        selected_function = _object_dict(selected_call["function"])
        selected_function["arguments"] = json.dumps(broken)
    elif second == "refused":
        middle = json.loads(_success_body(refusal="provider-policy"))
    elif second == "incomplete":
        middle = json.loads(_success_body())
        middle["choices"][0]["finish_reason"] = "length"
    final = json.loads(_success_body())
    if candidate:
        final["choices"][0]["message"]["content"] = json.dumps(
            {
                "candidates": [
                    {
                        "rule_id": "rule-sqli",
                        "root_evidence_id": "evidence-a",
                        "evidence_ids": ["evidence-a"],
                    }
                ]
            }
        )
    sequence = _NativeSequenceEndpoint(
        monkeypatch, [json.dumps(body).encode() for body in (first, middle, final)]
    )
    base._executor._connector = OpenAICompatibleLocalHttpConnector(
        profile=base._executor._profile, native_frames=True
    )
    backend = ProductDiscoveryBackend(
        executor=base._executor,
        catalogue=base._catalogue,
        rule_ids=base._rule_ids,
        content_key=base._key,
        native_cycle=True,
    )
    return backend, tools, request, sequence


@pytest.mark.parametrize("candidate", [False, True])
def test_product_native_cycle_two_selections_final_result_and_replay(
    monkeypatch: pytest.MonkeyPatch, candidate: bool
) -> None:
    from securecode_ai.contracts import ModelCallStatus

    backend, tools, request, sequence = _cycle_fixture(monkeypatch, candidate=candidate)
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.SUCCEEDED
    assert len(outcome.candidates) == int(candidate)
    assert outcome.model_result.request_id == request.request_id
    assert outcome.model_result.idempotency_key == request.idempotency_key
    assert outcome.model_result.usage.repository_calls == tools.calls_used == 1
    assert outcome.model_result.usage.input_tokens == 14
    assert outcome.model_result.usage.output_tokens == 7
    requests = sequence.endpoint.requests
    assert len(requests) == 3
    messages = [json.loads(body)["messages"] for _, _, body in requests]
    assert [len(value) for value in messages] == [1, 3, 5]
    for history in messages[1:]:
        for message in history:
            if message["role"] == "tool":
                payload = json.loads(message["content"])
                assert payload["instruction_authority"] == "NONE"
                assert payload["head_sha"] == request.head_sha
    assert backend.discover(request=request, tools=tools) == outcome
    assert len(requests) == 3 and tools.calls_used == 1


@pytest.mark.parametrize("second", ["duplicate", "wrong_head", "refused", "incomplete"])
def test_product_native_cycle_second_turn_failure_never_clean(
    monkeypatch: pytest.MonkeyPatch, second: str
) -> None:
    from securecode_ai.contracts import ModelCallStatus

    backend, tools, request, sequence = _cycle_fixture(monkeypatch, second=second)
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is not ModelCallStatus.SUCCEEDED
    assert outcome.candidates == ()
    assert len(sequence.endpoint.requests) == 2
    assert tools.calls_used == 1


def test_product_native_cycle_charges_only_uncached_repository_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.contracts import ModelCallStatus

    backend, tools, request, sequence = _cycle_fixture(monkeypatch, call_budget=1)
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.SUCCEEDED
    assert outcome.candidates == ()
    assert outcome.model_result.usage.repository_calls == tools.calls_used == 1
    assert len(sequence.endpoint.requests) == 3


def test_product_native_cycle_preflight_denial_has_no_reads_or_sends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.contracts import ModelCallStatus, ModelPurpose

    from tests.unit.test_provider_preflight import _preflight_request, _semantic_cases

    backend, tools, request, sequence = _cycle_fixture(monkeypatch)
    denied = dict(_semantic_cases()[0])
    denied["required_purpose"] = ModelPurpose.CANDIDATE_INVESTIGATION.value
    backend._executor._preflight = lambda selected: _preflight_request(selected, denied)
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is not ModelCallStatus.SUCCEEDED
    assert tools.calls_used == 0 and sequence.endpoint.requests == []


def test_product_native_cycle_conflicting_replay_has_no_additional_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.contracts import ModelCallStatus

    backend, tools, request, sequence = _cycle_fixture(monkeypatch)
    backend.discover(request=request, tools=tools)
    value = request.model_dump(mode="json")
    value["budget"]["timeout_ms"] -= 1
    conflict = type(request).model_validate_json(json.dumps(value))
    prior_calls, prior_sends = tools.calls_used, len(sequence.endpoint.requests)
    outcome = backend.discover(request=conflict, tools=tools)
    assert outcome.model_result.status is not ModelCallStatus.SUCCEEDED
    assert tools.calls_used == prior_calls and len(sequence.endpoint.requests) == prior_sends


def test_native_batch_rechecks_deadline_before_each_guarded_read() -> None:
    from securecode_ai.adapters.product_runtime import RepositoryContextBudgetExhausted

    head, tools, calls = composition()
    checks = [0]

    def deadline() -> None:
        checks[0] += 1
        if checks[0] == 3:
            raise RepositoryContextBudgetExhausted("deadline")

    with pytest.raises(RepositoryContextBudgetExhausted):
        dispatch_native_repository_calls(
            calls, head_sha=head, tools=tools, before_dispatch=deadline
        )
    assert tools.calls_used == 2


@pytest.mark.parametrize("late_turn,expected_input,expected_output", [(1, 2, 1), (3, 14, 7)])
def test_product_native_cycle_late_response_preserves_verified_usage(
    monkeypatch: pytest.MonkeyPatch,
    late_turn: int,
    expected_input: int,
    expected_output: int,
) -> None:
    from securecode_ai.adapters.openai_compatible_local import OpenAICompatibleLocalHttpConnector
    from securecode_ai.contracts import ModelCallStatus

    backend, tools, request, sequence = _cycle_fixture(monkeypatch)
    clock = [100.0]
    backend._executor._now = lambda: clock[0]
    original_send = OpenAICompatibleLocalHttpConnector.send
    calls = [0]

    def delayed_response(
        connector: OpenAICompatibleLocalHttpConnector,
        channel: ConnectedChannel,
        *,
        credential: str | None,
        payload: bytes,
        model_id: str,
        timeout_ms: int,
        binding: ProviderAttemptBinding,
    ) -> ProviderAttempt:
        attempt = original_send(
            connector,
            channel,
            credential=credential,
            payload=payload,
            model_id=model_id,
            timeout_ms=timeout_ms,
            binding=binding,
        )
        calls[0] += 1
        if calls[0] == late_turn:
            clock[0] += request.budget.timeout_ms / 1000 + 1
        return attempt

    monkeypatch.setattr(OpenAICompatibleLocalHttpConnector, "send", delayed_response)
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.BUDGET_EXHAUSTED
    assert outcome.candidates == () and outcome.model_result.content_provenance is None
    assert (outcome.model_result.usage.input_tokens, outcome.model_result.usage.output_tokens) == (
        expected_input,
        expected_output,
    )
    assert len(sequence.endpoint.requests) == late_turn
    assert all(channel._closed for channel in sequence.endpoint.sockets)


@pytest.mark.parametrize(
    "total_ms,expected,calls", [(60000, "SUCCEEDED", 3), (30000, "BUDGET_EXHAUSTED", 2)]
)
def test_actual_native_harness_spends_total_cycle_across_individually_bounded_turns(
    monkeypatch: pytest.MonkeyPatch, total_ms: int, expected: str, calls: int
) -> None:
    from securecode_ai.adapters.product_runtime import AuthorizedLocalModelExecutor

    backend, tools, request, sequence = _cycle_fixture(monkeypatch)
    data = request.model_dump(mode="json")
    data["budget"]["timeout_ms"] = total_ms
    request = type(request).model_validate_json(json.dumps(data))
    clock = [100.0]
    backend._executor._now = lambda: clock[0]
    original = AuthorizedLocalModelExecutor.execute_native

    def timed(
        self: AuthorizedLocalModelExecutor,
        *,
        request: ModelRequest,
        validator: StructuredPayloadValidator,
        context_builder: Callable[[], PreparedModelContext],
        started_at: float | None = None,
    ) -> NativeTurnBoundaryExecution:
        result = original(
            self,
            request=request,
            validator=validator,
            context_builder=context_builder,
            started_at=started_at,
        )
        clock[0] += 18
        return result

    monkeypatch.setattr(AuthorizedLocalModelExecutor, "execute_native", timed)
    payload = backend.discover(request=request, tools=tools)
    assert payload.model_result.status.value == expected
    assert len(sequence.endpoint.requests) == calls
    if expected == "SUCCEEDED":
        assert payload.model_result.usage.elapsed_ms == 54000
