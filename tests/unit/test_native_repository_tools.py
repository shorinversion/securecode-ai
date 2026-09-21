from __future__ import annotations

import json

import pytest
from securecode_ai.adapters.native_repository_tools import (
    NativeToolCallError,
    NativeToolCallRejection,
    parse_native_tool_calls,
)

HEAD = "a" * 40


def _call(name: str, arguments: dict[str, object], call_id: str) -> dict[str, object]:
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments)},
    }


def test_all_four_closed_native_tools_parse() -> None:
    common = {"schema_version": "0.1.0", "head_sha": HEAD}
    calls = parse_native_tool_calls(
        [
            _call("list_paths", {**common, "prefix": "src", "max_entries": 2}, "call-1"),
            _call("lookup_symbol", {**common, "symbol": "handler", "path": None}, "call-2"),
            _call(
                "read_range",
                {**common, "path": "src/a.py", "start_line": 1, "end_line": 2},
                "call-3",
            ),
            _call("read_evidence", {**common, "evidence_id": "evidence-a"}, "call-4"),
        ],
        head_sha=HEAD,
    )
    assert tuple(item.request.tool.value for item in calls) == (
        "list_paths",
        "lookup_symbol",
        "read_range",
        "read_evidence",
    )


@pytest.mark.parametrize(
    "value",
    [
        [{"id": "call-1", "type": "function", "function": {"name": "unknown", "arguments": "{}"}}],
        [
            _call(
                "read_evidence",
                {"schema_version": "0.1.0", "head_sha": HEAD, "evidence_id": "a"},
                "same",
            ),
            _call(
                "read_evidence",
                {"schema_version": "0.1.0", "head_sha": HEAD, "evidence_id": "b"},
                "same",
            ),
        ],
        [
            _call(
                "read_evidence",
                {"schema_version": "0.1.0", "head_sha": "b" * 40, "evidence_id": "a"},
                "call-1",
            )
        ],
    ],
)
def test_native_calls_reject_unknown_duplicate_and_wrong_revision(value: object) -> None:
    with pytest.raises(NativeToolCallError):
        parse_native_tool_calls(value, head_sha=HEAD)


@pytest.mark.parametrize(
    "arguments",
    [
        '{"schema_version":"0.1.0","schema_version":"0.1.0","head_sha":"'
        + HEAD
        + '","evidence_id":"a"}',
        '{"schema_version":"0.1.0","head_sha":"' + HEAD + '","evidence_id":NaN}',
        '{"schema_version":"0.1.0","head_sha":"' + HEAD + '","evidence_id":"a","command":"run"}',
        "[" * 5000,
        "x" * 4097,
    ],
)
def test_native_argument_json_is_closed_and_bounded(arguments: str) -> None:
    value = [
        {
            "id": "call-1",
            "type": "function",
            "function": {"name": "read_evidence", "arguments": arguments},
        }
    ]
    with pytest.raises(NativeToolCallError):
        parse_native_tool_calls(value, head_sha=HEAD)


def test_empty_native_selection_cannot_be_completed_zero() -> None:
    with pytest.raises(NativeToolCallError):
        parse_native_tool_calls([], head_sha=HEAD)


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ("{", NativeToolCallRejection.JSON_MALFORMED),
        (
            '{"schema_version":"0.1.0","schema_version":"0.1.0",'
            f'"head_sha":"{HEAD}","evidence_id":"source-a"}}',
            NativeToolCallRejection.JSON_DUPLICATE,
        ),
        (
            f'{{"schema_version":"0.1.0","head_sha":"{HEAD}","evidence_id":NaN}}',
            NativeToolCallRejection.JSON_NONFINITE,
        ),
        ("x" * 4097, NativeToolCallRejection.ARGUMENT_TYPE_OR_BYTES),
        (
            json.dumps(
                {
                    "schema_version": "0.1.0",
                    "head_sha": HEAD,
                    "evidence_id": "source-a",
                    "unexpected": "field",
                }
            ),
            NativeToolCallRejection.ARGUMENT_SCHEMA,
        ),
    ],
)
def test_native_argument_rejection_is_closed_and_source_free(
    arguments: str, expected: object
) -> None:
    value = [
        {
            "id": "call-1",
            "type": "function",
            "function": {"name": "read_evidence", "arguments": arguments},
        }
    ]
    with pytest.raises(NativeToolCallError) as caught:
        parse_native_tool_calls(value, head_sha=HEAD)
    assert caught.value.rejection is expected
    assert arguments not in repr(caught.value)


def test_native_call_envelope_rejection_is_distinct_from_argument_rejection() -> None:
    with pytest.raises(NativeToolCallError) as caught:
        parse_native_tool_calls(
            [{"id": "call-1", "type": "function", "function": {}}], head_sha=HEAD
        )
    assert caught.value.rejection is NativeToolCallRejection.CALL_ENVELOPE


def test_native_cycle_remaining_limits_and_predispatch_reservation() -> None:
    from securecode_ai.adapters.product_runtime import (
        NativeCycleBudget,
        RepositoryContextBudgetExhausted,
    )
    from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ModelCallBudget, ModelUsage

    clock = [10.0]
    budget = ModelCallBudget(
        schema_version=CONTRACT_SCHEMA_VERSION,
        max_input_tokens=20,
        max_output_tokens=10,
        max_repository_calls=4,
        max_context_bytes=12,
        timeout_ms=1000,
    )
    cycle = NativeCycleBudget(budget, now=lambda: clock[0])
    assert cycle.begin_turn("turn-1").max_output_tokens == 10
    cycle.record_usage(
        "turn-1",
        ModelUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            input_tokens=8,
            output_tokens=3,
            repository_calls=0,
            elapsed_ms=100,
        ),
    )
    cycle.reserve_repository_calls(3)
    cycle.record_context_bytes(8)
    clock[0] = 10.5
    remaining = cycle.begin_turn("turn-2")
    assert (
        remaining.max_input_tokens,
        remaining.max_output_tokens,
        remaining.max_repository_calls,
        remaining.timeout_ms,
    ) == (12, 7, 1, 500)
    with pytest.raises(RepositoryContextBudgetExhausted):
        cycle.reserve_repository_calls(2)
    with pytest.raises(RepositoryContextBudgetExhausted):
        cycle.record_context_bytes(1)


@pytest.mark.parametrize(
    "failure", ["duplicate", "parallel", "deadline", "backward", "bytes", "usage"]
)
def test_native_cycle_stops_permanently_after_invalid_accounting(failure: str) -> None:
    from securecode_ai.adapters.product_runtime import (
        NativeCycleBudget,
        RepositoryContextBudgetExhausted,
    )
    from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ModelCallBudget, ModelUsage

    clock = [10.0]
    cycle = NativeCycleBudget(
        ModelCallBudget(
            schema_version=CONTRACT_SCHEMA_VERSION,
            max_input_tokens=20,
            max_output_tokens=10,
            max_repository_calls=4,
            max_context_bytes=12,
            timeout_ms=1000,
        ),
        now=lambda: clock[0],
    )
    cycle.begin_turn("first")
    usage = ModelUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        input_tokens=3,
        output_tokens=1,
        repository_calls=0,
        elapsed_ms=10,
    )
    if failure != "parallel":
        cycle.record_usage("first", usage)
    with pytest.raises(RepositoryContextBudgetExhausted):
        if failure == "duplicate":
            cycle.begin_turn("first")
        elif failure == "parallel":
            cycle.begin_turn("second")
        elif failure == "deadline":
            clock[0] = 11.0
            cycle.begin_turn("second")
        elif failure == "backward":
            clock[0] = 9.0
            cycle.begin_turn("second")
        elif failure == "bytes":
            cycle.record_context_bytes(13)
        else:
            cycle.record_usage("first", usage)
    with pytest.raises(RepositoryContextBudgetExhausted):
        cycle.begin_turn("third")


def test_native_cycle_rejects_usage_without_pending_turn() -> None:
    from securecode_ai.adapters.product_runtime import (
        NativeCycleBudget,
        RepositoryContextBudgetExhausted,
    )
    from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ModelCallBudget, ModelUsage

    cycle = NativeCycleBudget(
        ModelCallBudget(
            schema_version=CONTRACT_SCHEMA_VERSION,
            max_input_tokens=20,
            max_output_tokens=10,
            max_repository_calls=4,
            max_context_bytes=12,
            timeout_ms=1000,
        ),
        now=lambda: 10.0,
    )
    usage = ModelUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        input_tokens=1,
        output_tokens=1,
        repository_calls=0,
        elapsed_ms=1,
    )
    with pytest.raises(RepositoryContextBudgetExhausted):
        cycle.record_usage("missing", usage)
    with pytest.raises(RepositoryContextBudgetExhausted):
        cycle.begin_turn("later")


def test_native_cycle_enforces_issued_turn_cap_even_below_total() -> None:
    from securecode_ai.adapters.product_runtime import (
        NativeCycleBudget,
        RepositoryContextBudgetExhausted,
    )
    from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ModelCallBudget, ModelUsage

    cycle = NativeCycleBudget(
        ModelCallBudget(
            schema_version=CONTRACT_SCHEMA_VERSION,
            max_input_tokens=20,
            max_output_tokens=10,
            max_repository_calls=4,
            max_context_bytes=12,
            timeout_ms=1000,
        ),
        now=lambda: 10.0,
    )
    cycle.begin_turn("first")
    cycle.record_usage(
        "first",
        ModelUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            input_tokens=18,
            output_tokens=0,
            repository_calls=0,
            elapsed_ms=1,
        ),
    )
    assert cycle.begin_turn("second").max_output_tokens == 2
    with pytest.raises(RepositoryContextBudgetExhausted):
        cycle.record_usage(
            "second",
            ModelUsage(
                schema_version=CONTRACT_SCHEMA_VERSION,
                input_tokens=1,
                output_tokens=5,
                repository_calls=0,
                elapsed_ms=1,
            ),
        )
    with pytest.raises(RepositoryContextBudgetExhausted):
        cycle.begin_turn("later")


def test_native_turn_identity_binds_exact_frame_budget_and_ordinal() -> None:
    from securecode_ai.adapters.product_runtime import native_turn_request
    from securecode_ai.contracts import ModelPurpose

    from tests.unit.test_provider_preflight import _policy, _profile, _request

    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy("egress.valid.private-model-source.json")
    original = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    frame = b'{"initial_context":{},"tool_history":[]}'
    first = native_turn_request(
        original, ordinal=0, budget=original.budget, frame=frame, content_key=b"k" * 32
    )
    replay = native_turn_request(
        original, ordinal=0, budget=original.budget, frame=frame, content_key=b"k" * 32
    )
    assert first == replay and first.request_id != original.request_id
    assert first.idempotency_key != original.idempotency_key
    unchanged = original.model_dump(mode="json")
    changed = first.model_dump(mode="json")
    for name in ("request_id", "idempotency_key", "budget"):
        unchanged.pop(name)
        changed.pop(name)
    assert changed == unchanged
    for ordinal, payload, key in [
        (1, frame, b"k" * 32),
        (0, frame + b" ", b"k" * 32),
        (0, frame, b"l" * 32),
    ]:
        other = native_turn_request(
            original, ordinal=ordinal, budget=original.budget, frame=payload, content_key=key
        )
        assert (first.request_id, first.idempotency_key) != (
            other.request_id,
            other.idempotency_key,
        )
    value = original.budget.model_dump(mode="json")
    value["timeout_ms"] -= 1
    smaller = type(original.budget).model_validate_json(json.dumps(value))
    assert (
        native_turn_request(
            original, ordinal=0, budget=smaller, frame=frame, content_key=b"k" * 32
        ).request_id
        != first.request_id
    )


@pytest.mark.parametrize("invalid", ["ordinal", "bool", "empty", "oversize", "key", "budget"])
def test_native_turn_identity_rejects_invalid_or_expanded_bindings(invalid: str) -> None:
    from securecode_ai.adapters.product_runtime import native_turn_request
    from securecode_ai.contracts import ModelPurpose

    from tests.unit.test_provider_preflight import _policy, _profile, _request

    profile = _profile("valid.local-openai-compatible.json")
    original = _request(
        profile,
        _policy("egress.valid.private-model-source.json"),
        ModelPurpose.MODEL_NATIVE_DISCOVERY,
    )
    ordinal, frame, key, budget = 0, b"{}", b"k" * 32, original.budget
    if invalid == "ordinal":
        ordinal = 16
    elif invalid == "bool":
        ordinal = True
    elif invalid == "empty":
        frame = b""
    elif invalid == "oversize":
        frame = b"x" * (budget.max_context_bytes + 1)
    elif invalid == "key":
        key = b"short"
    else:
        value = budget.model_dump(mode="json")
        value["timeout_ms"] += 1
        budget = type(budget).model_validate_json(json.dumps(value))
    with pytest.raises(ValueError, match="native turn bindings are invalid"):
        native_turn_request(original, ordinal=ordinal, budget=budget, frame=frame, content_key=key)
