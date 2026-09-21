"""Hermetic provider adapter, native-dialect normalization and ephemeral payloads."""

from __future__ import annotations

import json
from typing import Any

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    ApiDialect,
    ModelCallResult,
    ModelCallStatus,
    ModelRequest,
    ModelSchemaResult,
    ModelSchemaStatus,
    ModelUsage,
    NativeOutcomeMetadata,
)

from .model_types import (
    _MAX_JSON_DEPTH,
    _MAX_NATIVE_BYTES,
    _MAX_WIRE_INT,
    ModelBoundaryError,
    NormalizedModelAttempt,
    ProviderAttempt,
    ProviderStreamState,
    TransportFailure,
    _NativeSignals,
)


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native response member")
        result[key] = value
    return result


def _depth(value: object, current: int = 0) -> int:
    if current > _MAX_JSON_DEPTH:
        raise ValueError("native response nesting exceeds limit")
    if isinstance(value, dict):
        return max((_depth(item, current + 1) for item in value.values()), default=current)
    if isinstance(value, list):
        return max((_depth(item, current + 1) for item in value), default=current)
    return current


def _parse_json(data: bytes) -> dict[str, Any]:
    if not data or len(data) > _MAX_NATIVE_BYTES or b"\0" in data:
        raise ValueError("native response envelope is invalid")
    value = json.loads(data, object_pairs_hook=_closed_object)
    _depth(value)
    if not isinstance(value, dict):
        raise ValueError("native response root must be an object")
    return value


def parse_model_request(payload: str | bytes | bytearray) -> ModelRequest:
    """Parse hostile public request bytes without reflecting source in diagnostics."""

    try:
        encoded = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        document = _parse_json(encoded)
        canonical = json.dumps(
            document, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode()
        return ModelRequest.model_validate_json(canonical)
    except Exception:
        raise ModelBoundaryError("INVALID_MODEL_REQUEST") from None


def parse_model_call_result(payload: str | bytes | bytearray) -> ModelCallResult:
    """Parse hostile public result bytes without reflecting provider content."""

    try:
        encoded = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        document = _parse_json(encoded)
        canonical = json.dumps(
            document, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode()
        return ModelCallResult.model_validate_json(canonical)
    except Exception:
        raise ModelBoundaryError("INVALID_MODEL_CALL_RESULT") from None


def _nonnegative_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > _MAX_WIRE_INT:
        raise ValueError("native usage is invalid")
    return value


def _fake_signals(document: dict[str, Any]) -> _NativeSignals:
    if set(document) != {
        "request_code",
        "finish_code",
        "refusal_code",
        "filter_code",
        "content_text",
        "usage",
    }:
        raise ValueError("fake response control surface is invalid")
    if document.get("request_code") != "FAKE_RESPONSE":
        raise ValueError("unknown fake request code")
    usage = document.get("usage")
    if not isinstance(usage, dict):
        raise ValueError("missing fake usage")
    finish = document.get("finish_code")
    if finish not in {
        "COMPLETE",
        "INCOMPLETE",
        "MAX_OUTPUT_TOKENS",
        "CONTEXT_EXHAUSTED",
        "UNKNOWN_TERMINAL",
    }:
        raise ValueError("unknown fake finish code")
    refusal = document.get("refusal_code")
    if refusal not in {None, "REFUSED"}:
        raise ValueError("unknown fake refusal code")
    filter_code = document.get("filter_code")
    if filter_code not in {None, "CONTENT_FILTERED", "GUARDRAIL_BLOCKED"}:
        raise ValueError("unknown fake filter code")
    content_text = document.get("content_text")
    if content_text is not None and not isinstance(content_text, str):
        raise ValueError("fake content is invalid")
    return _NativeSignals(
        "FAKE_RESPONSE",
        finish,
        refusal,
        filter_code,
        content_text,
        _nonnegative_int(usage.get("input_tokens")),
        _nonnegative_int(usage.get("output_tokens")),
    )


def _openai_signals(document: dict[str, Any]) -> _NativeSignals:
    if set(document) != {"id", "status", "incomplete_details", "output", "usage"}:
        raise ValueError("OpenAI response control surface is invalid")
    if not isinstance(document.get("id"), str):
        raise ValueError("OpenAI response id is invalid")
    status = document.get("status")
    if status not in {"completed", "incomplete"}:
        raise ValueError("unknown OpenAI response status")
    output = document.get("output")
    if not isinstance(output, list) or len(output) != 1 or not isinstance(output[0], dict):
        raise ValueError("OpenAI response output is invalid")
    if set(output[0]) != {"type", "content"} or output[0].get("type") != "message":
        raise ValueError("OpenAI response output type is invalid")
    content = output[0].get("content")
    if not isinstance(content, list):
        raise ValueError("OpenAI response content is invalid")
    for item in content:
        if not isinstance(item, dict):
            raise ValueError("OpenAI response content type is invalid")
        item_type = item.get("type")
        if item_type == "output_text":
            if set(item) != {"type", "text"} or not isinstance(item.get("text"), str):
                raise ValueError("OpenAI response text control surface is invalid")
        elif item_type == "refusal":
            if set(item) != {"type", "refusal"} or not isinstance(item.get("refusal"), str):
                raise ValueError("OpenAI refusal control surface is invalid")
        else:
            raise ValueError("OpenAI response content type is invalid")
    texts = [
        item.get("text")
        for item in content
        if isinstance(item, dict) and item.get("type") == "output_text"
    ]
    refused = any(isinstance(item, dict) and item.get("type") == "refusal" for item in content)
    if len(texts) > 1 or any(not isinstance(item, str) for item in texts):
        raise ValueError("OpenAI response text multiplicity is invalid")
    reason = None
    details = document.get("incomplete_details")
    if status == "incomplete":
        if (
            not isinstance(details, dict)
            or set(details) != {"reason"}
            or not isinstance(details.get("reason"), str)
        ):
            raise ValueError("OpenAI incomplete response requires a reason")
        reason = details.get("reason")
    elif details is not None:
        raise ValueError("OpenAI completed response cannot carry incomplete details")
    mapping = {
        "provider_incomplete": "INCOMPLETE",
        "max_output_tokens": "MAX_OUTPUT_TOKENS",
        "context_length": "CONTEXT_EXHAUSTED",
        "content_filtered": "COMPLETE",
        "guardrail_blocked": "COMPLETE",
        "unknown_terminal": "UNKNOWN_TERMINAL",
    }
    if status == "incomplete" and reason not in mapping:
        raise ValueError("unknown OpenAI incomplete reason")
    usage = document.get("usage")
    if not isinstance(usage, dict) or set(usage) != {"input_tokens", "output_tokens"}:
        raise ValueError("missing OpenAI usage")
    filter_code = None
    if reason == "content_filtered":
        filter_code = "CONTENT_FILTERED"
    elif reason == "guardrail_blocked":
        filter_code = "GUARDRAIL_BLOCKED"
    return _NativeSignals(
        "OPENAI_RESPONSE",
        "COMPLETE" if status == "completed" else mapping[str(reason)],
        "REFUSED" if refused else None,
        filter_code,
        texts[0] if texts else None,
        _nonnegative_int(usage.get("input_tokens")),
        _nonnegative_int(usage.get("output_tokens")),
    )


def _anthropic_signals(document: dict[str, Any]) -> _NativeSignals:
    if set(document) != {"id", "stop_reason", "content", "usage"}:
        raise ValueError("Anthropic response control surface is invalid")
    if not isinstance(document.get("id"), str):
        raise ValueError("Anthropic response id is invalid")
    stop = document.get("stop_reason")
    mapping = {
        "end_turn": ("COMPLETE", None, None),
        "incomplete": ("INCOMPLETE", None, None),
        "max_tokens": ("MAX_OUTPUT_TOKENS", None, None),
        "context_window_exceeded": ("CONTEXT_EXHAUSTED", None, None),
        "refusal": ("COMPLETE", "REFUSED", None),
        "content_filter": ("COMPLETE", None, "CONTENT_FILTERED"),
        "guardrail": ("COMPLETE", None, "GUARDRAIL_BLOCKED"),
        "unknown_terminal": ("UNKNOWN_TERMINAL", None, None),
    }
    if stop not in mapping:
        raise ValueError("unknown Anthropic stop reason")
    content = document.get("content")
    if not isinstance(content, list):
        raise ValueError("Anthropic content is invalid")
    if any(
        not isinstance(item, dict) or set(item) != {"type", "text"} or item.get("type") != "text"
        for item in content
    ):
        raise ValueError("Anthropic content control surface is invalid")
    texts = [
        item.get("text")
        for item in content
        if isinstance(item, dict) and item.get("type") == "text"
    ]
    if len(texts) > 1 or any(not isinstance(item, str) for item in texts):
        raise ValueError("Anthropic response text multiplicity is invalid")
    usage = document.get("usage")
    if not isinstance(usage, dict) or set(usage) != {"input_tokens", "output_tokens"}:
        raise ValueError("missing Anthropic usage")
    finish, refusal, filter_code = mapping[stop]
    return _NativeSignals(
        "ANTHROPIC_MESSAGE",
        finish,
        refusal,
        filter_code,
        texts[0] if texts else None,
        _nonnegative_int(usage.get("input_tokens")),
        _nonnegative_int(usage.get("output_tokens")),
    )


def _compatible_signals(document: dict[str, Any]) -> _NativeSignals:
    if set(document) != {"id", "choices", "usage"}:
        raise ValueError("compatible response control surface is invalid")
    if not isinstance(document.get("id"), str):
        raise ValueError("compatible response id is invalid")
    choices = document.get("choices")
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise ValueError("compatible choices are invalid")
    choice = choices[0]
    if set(choice) != {"finish_reason", "message"}:
        raise ValueError("compatible choice control surface is invalid")
    finish = choice.get("finish_reason")
    mapping = {
        "stop": ("COMPLETE", None),
        "incomplete": ("INCOMPLETE", None),
        "length": ("MAX_OUTPUT_TOKENS", None),
        "context_length": ("CONTEXT_EXHAUSTED", None),
        "content_filter": ("COMPLETE", "CONTENT_FILTERED"),
        "guardrail": ("COMPLETE", "GUARDRAIL_BLOCKED"),
        "unknown_terminal": ("UNKNOWN_TERMINAL", None),
    }
    if finish not in mapping:
        raise ValueError("unknown compatible finish reason")
    message = choice.get("message")
    if not isinstance(message, dict):
        raise ValueError("compatible message is invalid")
    if set(message) not in (
        {"content", "refusal"},
        {"content", "refusal", "role"},
    ):
        raise ValueError("compatible message control surface is invalid")
    if "role" in message and message["role"] != "assistant":
        raise ValueError("compatible message role is invalid")
    content = message.get("content")
    if content is not None and not isinstance(content, str):
        raise ValueError("compatible content is invalid")
    refusal = message.get("refusal")
    if refusal is not None and not isinstance(refusal, str):
        raise ValueError("compatible refusal is invalid")
    usage = document.get("usage")
    if not isinstance(usage, dict) or set(usage) != {
        "prompt_tokens",
        "completion_tokens",
    }:
        raise ValueError("missing compatible usage")
    finish_code, filter_code = mapping[finish]
    return _NativeSignals(
        "COMPATIBLE_RESPONSE",
        finish_code,
        "REFUSED" if refusal is not None else None,
        filter_code,
        content,
        _nonnegative_int(usage.get("prompt_tokens")),
        _nonnegative_int(usage.get("completion_tokens")),
    )


def _signals(dialect: ApiDialect, response: bytes) -> _NativeSignals:
    document = _parse_json(response)
    if dialect is ApiDialect.FAKE:
        return _fake_signals(document)
    if dialect is ApiDialect.OPENAI_RESPONSES:
        return _openai_signals(document)
    if dialect is ApiDialect.ANTHROPIC_MESSAGES:
        return _anthropic_signals(document)
    if dialect is ApiDialect.OPENAI_COMPATIBLE:
        return _compatible_signals(document)
    raise ValueError("unsupported provider dialect")


def _transport_status(attempt: ProviderAttempt) -> ModelCallStatus | None:
    transport_failure: object = attempt.transport_failure
    stream_state: object = attempt.stream_state
    if attempt.redirected:
        return ModelCallStatus.PROVIDER_ERROR
    if transport_failure is not None and not isinstance(transport_failure, TransportFailure):
        return ModelCallStatus.PROVIDER_ERROR
    if not isinstance(stream_state, ProviderStreamState):
        return ModelCallStatus.PROVIDER_ERROR
    if transport_failure is TransportFailure.TIMEOUT:
        return ModelCallStatus.TIMEOUT
    if transport_failure is TransportFailure.CANCELLED:
        return ModelCallStatus.CANCELLED
    if transport_failure is TransportFailure.BUDGET_EXHAUSTED:
        return ModelCallStatus.BUDGET_EXHAUSTED
    if transport_failure is TransportFailure.PROVIDER_ERROR:
        return ModelCallStatus.PROVIDER_ERROR
    if attempt.http_status == 429:
        return ModelCallStatus.RATE_LIMITED
    if attempt.http_status is None or not 200 <= attempt.http_status < 300:
        return ModelCallStatus.PROVIDER_ERROR
    if stream_state is not ProviderStreamState.COMPLETE:
        return ModelCallStatus.INCOMPLETE
    return None


def _status(signals: _NativeSignals) -> ModelCallStatus | None:
    if signals.refusal_code is not None:
        return ModelCallStatus.REFUSED
    if signals.filter_code == "CONTENT_FILTERED":
        return ModelCallStatus.CONTENT_FILTERED
    if signals.filter_code == "GUARDRAIL_BLOCKED":
        return ModelCallStatus.GUARDRAIL_BLOCKED
    return {
        "INCOMPLETE": ModelCallStatus.INCOMPLETE,
        "MAX_OUTPUT_TOKENS": ModelCallStatus.TRUNCATED,
        "CONTEXT_EXHAUSTED": ModelCallStatus.CONTEXT_EXHAUSTED,
        "UNKNOWN_TERMINAL": ModelCallStatus.PROVIDER_ERROR,
    }.get(signals.finish_code)


def _non_success(
    *,
    request: ModelRequest,
    status: ModelCallStatus,
    elapsed_ms: int,
    signals: _NativeSignals | None = None,
) -> NormalizedModelAttempt:
    native = signals or _NativeSignals(
        "NO_NATIVE_RESPONSE", "TRANSPORT_FAILURE", None, None, None, 0, 0
    )
    retryable = status in {
        ModelCallStatus.INCOMPLETE,
        ModelCallStatus.TIMEOUT,
        ModelCallStatus.RATE_LIMITED,
        ModelCallStatus.PROVIDER_ERROR,
    }
    result = ModelCallResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        request_id=request.request_id,
        run_id=request.run_id,
        tenant_id=request.tenant_id,
        idempotency_key=request.idempotency_key,
        attempt=request.attempt,
        provider_profile=request.provider_profile,
        model_call_status=status,
        native=NativeOutcomeMetadata(
            schema_version=CONTRACT_SCHEMA_VERSION,
            request_code=native.request_code,
            finish_code=native.finish_code,
            refusal_code=native.refusal_code,
            filter_code=native.filter_code,
        ),
        schema_result=ModelSchemaResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            status=ModelSchemaStatus.NOT_VALIDATED,
            error_code="MODEL_NON_SUCCESS",
            validator=request.output_schema,
        ),
        usage=ModelUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            input_tokens=native.input_tokens,
            output_tokens=native.output_tokens,
            repository_calls=0,
            elapsed_ms=elapsed_ms,
        ),
        retryable=retryable,
        safe_reason_code=status.value,
    )
    return NormalizedModelAttempt(result)
