"""Local provider boundary with actual policy refusal and bounded backend I/O.

Refusal belongs to this gateway provider, not to the underlying model. No
capability registry is promoted by starting this service or handling a request.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import cast

from securecode_ai.contracts import DataClass

from .local_provider_gateway_types import (
    GatewayExchangeOperation,
    GatewayNativeArgumentsShape,
    GatewayNativeEnvelopeShape,
    GatewayReply,
    _decode,
    _NativeEnvelopeRejection,
    _valid_id,
)
from .native_repository_tools import (
    NATIVE_REPOSITORY_TOOLS_JSON,
    NativeToolCallError,
    parse_native_tool_calls,
)
from .openai_compatible_local_codec import _canonicalize_ollama_envelope


def _failure(status: int, *, dispatched: bool = False) -> GatewayReply:
    # Keep the public boundary closed even when an adapter hands us an
    # unexpected status value.  In particular, never let a bool, string, or
    # provider-specific status reach BaseHTTPRequestHandler.send_response.
    if type(status) is not int or status not in {
        400,
        408,
        413,
        429,
        500,
        502,
        503,
        504,
    }:
        status = 502
    if type(dispatched) is not bool:
        dispatched = True
    return GatewayReply(status, b'{"error":"gateway_request_unavailable"}', dispatched)


def _exchange_request_sha256(method: str, path: str, body: bytes | None) -> str:
    if body is not None:
        return hashlib.sha256(body).hexdigest()
    return hashlib.sha256(
        json.dumps(
            {"method": method, "path": path},
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()


_QWEN25_CODER_NO_THINK_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"
_NEMOTRON_MINI_NO_THINK_MODEL = "nemotron-mini:4b-instruct-q5_1"
_LLAMA31_NO_THINK_MODEL = "llama3.1:8b-instruct-q3_K_M"


def _ollama_native_request(body: bytes, *, expected_model_id: str) -> bytes:
    """Translate the closed internal request into Ollama's native tool dialect."""
    request = _decode(body)
    if set(request) - {
        "model",
        "messages",
        "max_tokens",
        "response_format",
        "tools",
        "temperature",
        "seed",
    }:
        raise ValueError("unsupported native request field")
    max_tokens = request.get("max_tokens")
    messages_value = request.get("messages")
    if (
        type(request.get("model")) is not str
        or request["model"] != expected_model_id
        or type(messages_value) is not list
        or not messages_value
        or type(max_tokens) is not int
        or isinstance(max_tokens, bool)
        or not 1 <= max_tokens <= 4096
    ):
        raise ValueError("invalid native request")
    messages_value = cast(list[object], messages_value)
    messages: list[dict[str, object]] = []
    for message in messages_value:
        if type(message) is not dict or type(message.get("role")) is not str:
            raise ValueError("invalid native message")
        converted = dict(message)
        calls = converted.get("tool_calls")
        if calls is not None:
            if type(calls) is not list:
                raise ValueError("invalid native tool history")
            native_calls = []
            for call in calls:
                if (
                    type(call) is not dict
                    or set(call) != {"id", "type", "function"}
                    or call["type"] != "function"
                    or type(call["function"]) is not dict
                    or set(call["function"]) != {"name", "arguments"}
                    or type(call["function"]["name"]) is not str
                    or type(call["function"]["arguments"]) is not str
                ):
                    raise ValueError("invalid native tool history")
                arguments = _decode(call["function"]["arguments"].encode())
                native_calls.append(
                    {"function": {"name": call["function"]["name"], "arguments": arguments}}
                )
            converted.pop("tool_calls")
            converted["tool_calls"] = native_calls
        if converted["role"] == "tool":
            converted.pop("tool_call_id", None)
        messages.append(converted)
    native: dict[str, object] = {
        "model": request["model"],
        "messages": messages,
        "stream": False,
        "think": request["model"]
        not in {
            _QWEN25_CODER_NO_THINK_MODEL,
            _NEMOTRON_MINI_NO_THINK_MODEL,
            _LLAMA31_NO_THINK_MODEL,
        },
        "options": {"num_predict": max_tokens},
    }
    options = cast(dict[str, object], native["options"])
    for option_name in ("temperature", "seed"):
        if option_name in request:
            value = request[option_name]
            if type(value) not in (int, float) or isinstance(value, bool):
                raise ValueError("invalid native option")
            numeric_value = cast(float | int, value)
            if not math.isfinite(numeric_value):
                raise ValueError("invalid native option")
            options[option_name] = numeric_value
    if "tools" in request:
        if (
            json.dumps(
                request["tools"], ensure_ascii=True, separators=(",", ":"), sort_keys=True
            ).encode()
            != NATIVE_REPOSITORY_TOOLS_JSON
        ):
            raise ValueError("invalid native tools")
        native["tools"] = request["tools"]
    if _validated_native_json_format_requested(request, messages_value):
        native["format"] = "json"
    return json.dumps(native, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def _canonicalize_ollama_native_chat(body: bytes, *, expected_model_id: str) -> bytes:
    """Accept bounded Ollama native chat replies and retain the closed dialect."""
    document = _decode(body)
    required = {
        "created_at",
        "done",
        "done_reason",
        "eval_count",
        "eval_duration",
        "load_duration",
        "message",
        "model",
        "prompt_eval_count",
        "prompt_eval_duration",
        "total_duration",
    }
    optional = {"prompt_eval_cached_count"}
    if (
        not set(document).issubset(required | optional)
        or not required.issubset(set(document))
        or document["model"] != expected_model_id
        or document["done"] is not True
    ):
        raise ValueError("invalid native chat envelope")
    if type(document["created_at"]) is not str or document["done_reason"] not in {"stop", "length"}:
        raise ValueError("invalid native chat completion")
    counters = (
        "eval_count",
        "eval_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_duration",
        "total_duration",
    )
    if any(
        type(document[key]) is not int
        or isinstance(document[key], bool)
        or cast(int, document[key]) < 0
        for key in counters
    ):
        raise ValueError("invalid native chat metrics")
    cached = document.get("prompt_eval_cached_count")
    if "prompt_eval_cached_count" in document and (
        type(cached) is not int or isinstance(cached, bool) or cached < 0
    ):
        raise ValueError("invalid native chat cache metrics")
    message = document["message"]
    if type(message) is not dict or set(message) not in (
        {"role", "content"},
        {"role", "content", "thinking"},
        {"role", "content", "tool_calls"},
        {"role", "content", "thinking", "tool_calls"},
    ):
        raise ValueError("invalid native chat message")
    if message["role"] != "assistant" or not isinstance(message["content"], str):
        raise ValueError("invalid native chat message")
    if "thinking" in message and not isinstance(message["thinking"], str):
        raise ValueError("invalid native chat thinking")
    response_hash = hashlib.sha256(body).hexdigest()
    canonical: dict[str, object] = {
        "id": "ollama-" + response_hash[:56],
        "usage": {
            "prompt_tokens": document["prompt_eval_count"],
            "completion_tokens": document["eval_count"],
        },
    }
    calls = message.get("tool_calls")
    if calls is None:
        canonical["choices"] = [
            {
                "finish_reason": document["done_reason"],
                "message": {"role": "assistant", "content": message["content"]},
            }
        ]
    else:
        if type(calls) is not list or not 1 <= len(calls) <= 4 or message["content"] != "":
            raise ValueError("invalid native tool calls")
        translated = []
        for index, call in enumerate(calls):
            if (
                type(call) is not dict
                or set(call) != {"id", "function"}
                or not _valid_id(call["id"])
                or type(call["function"]) is not dict
            ):
                raise ValueError("invalid native tool call")
            function = call["function"]
            if (
                set(function) != {"index", "name", "arguments"}
                or type(function["index"]) is not int
                or isinstance(function["index"], bool)
                or function["index"] != index
                or type(function["name"]) is not str
                or type(function["arguments"]) is not dict
            ):
                raise ValueError("invalid native tool call")
            translated.append(
                {
                    "id": f"ollama-{response_hash[:48]}-{index}",
                    "type": "function",
                    "function": {
                        "name": function["name"],
                        "arguments": json.dumps(
                            function["arguments"],
                            ensure_ascii=True,
                            allow_nan=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ),
                    },
                }
            )
        canonical["choices"] = [
            {
                "finish_reason": "tool_calls",
                "message": {"role": "assistant", "content": "", "tool_calls": translated},
            }
        ]
    return json.dumps(
        canonical, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _operation(method: str, path: str) -> GatewayExchangeOperation:
    if method == "GET" and path == "/api/version":
        return GatewayExchangeOperation.VERSION
    if method == "GET" and path == "/api/tags":
        return GatewayExchangeOperation.TAGS
    if method == "POST" and path in {"/api/chat", "/v1/chat/completions"}:
        return GatewayExchangeOperation.GENERATION
    raise ValueError("invalid gateway exchange operation")


def _validate_native_transcript(
    messages: list[object], *, head_sha: str, public_only: bool = False
) -> bool:
    """Validate quoted native history; this boundary never executes repository calls."""
    cursor = 1
    observed_ids: set[str] = set()
    restricted = False
    while cursor < len(messages):
        assistant = messages[cursor]
        if (
            not isinstance(assistant, dict)
            or set(assistant) != {"role", "content", "tool_calls"}
            or assistant["role"] != "assistant"
            or assistant["content"] not in (None, "")
        ):
            raise ValueError("invalid native assistant history")
        calls = parse_native_tool_calls(assistant["tool_calls"], head_sha=head_sha)
        ids = {call.call_id for call in calls}
        if observed_ids.intersection(ids) or len(observed_ids) + len(ids) > 16:
            raise ValueError("native transcript call budget exceeded")
        observed_ids.update(ids)
        cursor += 1
        for call in calls:
            if cursor >= len(messages):
                raise ValueError("native result missing")
            result = messages[cursor]
            if (
                not isinstance(result, dict)
                or set(result) != {"role", "tool_call_id", "content"}
                or result["role"] != "tool"
                or result["tool_call_id"] != call.call_id
                or not isinstance(result["content"], str)
            ):
                raise ValueError("invalid native result history")
            payload = _decode(result["content"].encode())
            if (
                set(payload) != {"instruction_authority", "data_class", "head_sha", "content"}
                or payload["instruction_authority"] != "NONE"
                or payload["head_sha"] != head_sha
                or payload["data_class"] not in tuple(value.value for value in DataClass)
                or not isinstance(payload["content"], str)
            ):
                raise ValueError("invalid native result metadata")
            if public_only and payload["data_class"] != DataClass.PUBLIC.value:
                raise ValueError("calibration requires public data")
            restricted = restricted or payload["data_class"] == DataClass.RESTRICTED.value
            cursor += 1
    return restricted


def _validated_native_json_format_requested(
    request: dict[str, object], messages: list[object]
) -> bool:
    """Allow Ollama JSON grammar for validated ordinary and post-tool turns only."""
    if request.get("response_format") != {"type": "json_object"}:
        return False
    first = messages[0]
    if (
        type(first) is not dict
        or set(first) != {"role", "content"}
        or first["role"] != "user"
        or not isinstance(first["content"], str)
    ):
        return False
    try:
        context = _decode(first["content"].encode())
        controls = context.get("trusted_controls")
        if type(controls) is not dict:
            return False
        revision = controls.get("source_revision")
        if (
            type(revision) is not dict
            or set(revision) != {"tenant_id", "head_sha"}
            or not isinstance(revision["head_sha"], str)
            or re.fullmatch(r"[0-9a-f]{40}", revision["head_sha"]) is None
        ):
            return False
        _validate_native_transcript(messages, head_sha=revision["head_sha"])
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return False
    if "tools" not in request:
        return len(messages) == 1
    return len(messages) > 1


def _native_arguments_shape(value: object) -> GatewayNativeArgumentsShape:
    if type(value) is not list:
        return GatewayNativeArgumentsShape.NOT_APPLICABLE
    observed: set[GatewayNativeArgumentsShape] = set()
    for item in value:
        function = item.get("function") if type(item) is dict else None
        if type(function) is not dict or "arguments" not in function:
            return GatewayNativeArgumentsShape.NOT_APPLICABLE
        argument = function["arguments"]
        observed.add(
            GatewayNativeArgumentsShape.STRING
            if type(argument) is str
            else GatewayNativeArgumentsShape.OBJECT
            if type(argument) is dict
            else GatewayNativeArgumentsShape.OTHER
        )
    if len(observed) != 1:
        return (
            GatewayNativeArgumentsShape.MIXED
            if observed
            else GatewayNativeArgumentsShape.NOT_APPLICABLE
        )
    return next(iter(observed))


def _canonicalize_native_reply(body: bytes, *, model_id: str, head_sha: str) -> bytes:
    try:
        document = _decode(body)
    except ValueError as error:
        raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.DECODE_REJECTED) from error
    choices = document.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.CHOICES_REJECTED)
    choice = choices[0]
    message = choice.get("message")
    if not isinstance(message, dict) or "tool_calls" not in message:
        try:
            return _canonicalize_ollama_envelope(body, expected_model_id=model_id)
        except ValueError as error:
            raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.NO_TOOL_CALLS) from error
    if (
        set(choice) not in ({"message", "finish_reason"}, {"index", "message", "finish_reason"})
        or ("index" in choice and (type(choice["index"]) is not int or choice["index"] != 0))
        or choice.get("finish_reason") != "tool_calls"
        or set(message)
        not in ({"role", "content", "tool_calls"}, {"role", "content", "tool_calls", "refusal"})
        or message.get("role") != "assistant"
        or message.get("content") not in (None, "")
        or message.get("refusal") is not None
    ):
        raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.CHOICE_REJECTED)
    raw_calls = message["tool_calls"]
    if type(raw_calls) is not list or not 1 <= len(raw_calls) <= 4:
        raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.CALL_LIST_REJECTED)
    ollama_envelope = set(document) == {
        "id",
        "object",
        "created",
        "model",
        "system_fingerprint",
        "choices",
        "usage",
    }
    calls = []
    for raw_call in raw_calls:
        if type(raw_call) is not dict:
            raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.CALL_ITEM_REJECTED)
        call = dict(raw_call)
        if "index" in call:
            if not ollama_envelope or type(call["index"]) is not int or not 0 <= call["index"] <= 3:
                raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.CALL_ITEM_REJECTED)
            # This is provider framing metadata, never repository authority.
            # The complete Ollama identity/control envelope is validated below.
            call.pop("index")
        calls.append(call)
    try:
        parse_native_tool_calls(calls, head_sha=head_sha)
    except NativeToolCallError as error:
        raise _NativeEnvelopeRejection(
            GatewayNativeEnvelopeShape.ARGUMENTS_REJECTED,
            _native_arguments_shape(calls),
            error.rejection,
        ) from None
    # Validate the complete backend envelope through the existing metadata codec.
    choice["finish_reason"] = "stop"
    choice["message"] = {"role": "assistant", "content": ""}
    if set(document) == {"id", "choices", "usage"}:
        choice["message"]["refusal"] = None
    try:
        canonical = _decode(
            _canonicalize_ollama_envelope(
                json.dumps(document, separators=(",", ":")).encode(),
                expected_model_id=model_id,
            )
        )
    except ValueError as error:
        raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.ENVELOPE_REJECTED) from error
    if not _valid_id(canonical.get("id")):
        raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.ENVELOPE_REJECTED)
    usage = canonical.get("usage")
    if (
        not isinstance(usage, dict)
        or set(usage) != {"prompt_tokens", "completion_tokens"}
        or any(type(value) is not int or not 0 <= value <= 2**31 - 1 for value in usage.values())
    ):
        raise _NativeEnvelopeRejection(GatewayNativeEnvelopeShape.ENVELOPE_REJECTED)
    canonical["choices"] = [
        {
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": None,
                "refusal": None,
                "tool_calls": calls,
            },
        }
    ]
    return json.dumps(canonical, separators=(",", ":")).encode()
