"""Hermetic provider adapter, native-dialect normalization and ephemeral payloads."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Final, Protocol, Self, SupportsIndex

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    ApiDialect,
    AuditRunOutcome,
    AuthorizationError,
    ComponentPin,
    DataClass,
    EgressContentRef,
    EgressManifest,
    EgressPolicyDocument,
    ModelAuthorizationIssuer,
    ModelCallResult,
    ModelCallStatus,
    ModelPreflightRequest,
    ModelPreflightResult,
    ModelRequest,
    ModelSchemaResult,
    ModelSchemaStatus,
    ModelUsage,
    NativeOutcomeMetadata,
    OpaqueContentProvenance,
    PayloadValidation,
    PreflightEligibility,
    PreflightNextAction,
    PreSendAuthorization,
    ProviderProfile,
    StructuredPayloadValidator,
    canonical_model_request_hash,
)

from .config import CredentialLease
from .endpoint import EndpointAuthorizationIssuer, Resolver

_MAX_NATIVE_BYTES: Final = 1024 * 1024
_MAX_JSON_DEPTH: Final = 64
_MAX_WIRE_INT: Final = 9_007_199_254_740_991


class TransportFailure(StrEnum):
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class ProviderStreamState(StrEnum):
    COMPLETE = "COMPLETE"
    INTERRUPTED = "INTERRUPTED"
    DUPLICATED = "DUPLICATED"


@dataclass(frozen=True, slots=True, repr=False)
class ProviderAttemptBinding:
    """Exact issuer-owned authorization identity carried through one send."""

    request_hash: str
    profile_hash: str
    policy_hash: str
    manifest_hash: str
    attempt: int

    def __post_init__(self) -> None:
        if any(
            len(value) != 64 or any(char not in "0123456789abcdef" for char in value)
            for value in (
                self.request_hash,
                self.profile_hash,
                self.policy_hash,
                self.manifest_hash,
            )
        ):
            raise ValueError("provider attempt binding hashes are invalid")
        if self.attempt < 1:
            raise ValueError("provider attempt binding attempt is invalid")

    @classmethod
    def from_claim(cls, claim: dict[str, object]) -> ProviderAttemptBinding:
        try:
            attempt = claim["attempt"]
            if not isinstance(attempt, int) or isinstance(attempt, bool):
                raise ValueError("provider authorization attempt is invalid")
            return cls(
                request_hash=str(claim["request_hash"]),
                profile_hash=str(claim["profile_hash"]),
                policy_hash=str(claim["policy_hash"]),
                manifest_hash=str(claim["manifest_hash"]),
                attempt=attempt,
            )
        except (KeyError, TypeError, ValueError):
            raise ValueError("provider authorization claim is invalid") from None


@dataclass(frozen=True, slots=True, repr=False)
class ProviderAttempt:
    """Ephemeral transport envelope; repr deliberately hides provider bytes."""

    dialect: ApiDialect
    http_status: int | None
    response_bytes: bytes | None
    transport_failure: TransportFailure | None
    stream_state: ProviderStreamState
    binding: ProviderAttemptBinding
    elapsed_ms: int
    redirected: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.dialect, ApiDialect):
            raise TypeError("provider dialect must be typed")
        if self.http_status is not None and not 100 <= self.http_status <= 599:
            raise ValueError("provider HTTP status is invalid")
        if self.elapsed_ms < 0:
            raise ValueError("provider elapsed time is invalid")
        if not isinstance(self.binding, ProviderAttemptBinding):
            raise TypeError("provider attempt binding must be typed")

    def __repr__(self) -> str:
        return "ProviderAttempt(<redacted>)"


class HmacContentIdentifier:
    """Generate tenant-scoped opaque IDs without exposing a raw content digest."""

    __slots__ = ("_closed", "_key", "_key_check")

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("content identifier state is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("content identifier key must contain at least 32 bytes")
        self._key = bytearray(key)
        self._key_check = hashlib.sha256(key).digest()
        self._closed = False

    def __repr__(self) -> str:
        return "HmacContentIdentifier(<redacted>)"

    def __copy__(self) -> HmacContentIdentifier:
        raise TypeError("content identifiers cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> HmacContentIdentifier:
        del memo
        raise TypeError("content identifiers cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("content identifiers cannot be serialized")

    def identify(self, *, tenant_id: str, payload: bytes) -> str:
        if self._closed:
            raise ValueError("content identifier is closed")
        if not hmac.compare_digest(hashlib.sha256(bytes(self._key)).digest(), self._key_check):
            raise ValueError("content identifier key integrity failure")
        digest = hmac.new(bytes(self._key), tenant_id.encode() + b"\0" + payload, hashlib.sha256)
        return f"kid:{digest.hexdigest()}"

    def verify(self, *, tenant_id: str, payload: bytes, content_id: str) -> bool:
        expected = self.identify(tenant_id=tenant_id, payload=payload)
        return hmac.compare_digest(expected, content_id)

    def close(self) -> None:
        if self._closed:
            return
        for index in range(len(self._key)):
            self._key[index] = 0
        object.__setattr__(self, "_closed", True)


def _contains_restricted_material(value: object, *, depth: int = 0) -> bool:
    if depth > _MAX_JSON_DEPTH:
        return True
    if isinstance(value, dict):
        sensitive = {
            "api_key",
            "apikey",
            "authorization",
            "credential",
            "password",
            "private_key",
            "secret",
            "access_token",
            "refresh_token",
            "token",
        }
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in sensitive or _contains_restricted_material(item, depth=depth + 1):
                return True
        return False
    if isinstance(value, (list, tuple)):
        return any(_contains_restricted_material(item, depth=depth + 1) for item in value)
    if isinstance(value, str):
        upper = value.upper()
        return (
            value.startswith("sk-")
            or value.startswith("ghp_")
            or value.startswith("github_pat_")
            or value.startswith("glpat-")
            or value.startswith("xoxb-")
            or upper.startswith("AKIA")
            or "BEGIN PRIVATE KEY" in upper
            or "BEGIN RSA PRIVATE KEY" in upper
        )
    return False


class JsonObjectValidator:
    """Minimal schema-pin-aware validator used by the fake and contract harness."""

    __slots__ = ("_content_identifier", "_data_class", "_required_keys", "_validator")

    def __init__(
        self,
        *,
        validator: ComponentPin,
        data_class: DataClass,
        content_identifier: HmacContentIdentifier,
        required_keys: tuple[str, ...],
    ) -> None:
        if data_class is DataClass.RESTRICTED:
            raise ValueError("restricted payloads cannot be validated for model output")
        if not required_keys or len(set(required_keys)) != len(required_keys):
            raise ValueError("required output keys must be a nonempty set")
        self._validator = validator
        self._data_class = data_class
        self._content_identifier = content_identifier
        self._required_keys = tuple(sorted(required_keys))

    @property
    def validator(self) -> ComponentPin:
        return self._validator

    def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation:
        if self.validator != request.output_schema:
            return PayloadValidation(False, "VALIDATOR_PIN_MISMATCH", None, None, self.validator)
        if (
            not isinstance(payload, dict)
            or not payload
            or any(key not in payload for key in self._required_keys)
            or _contains_restricted_material(payload)
        ):
            code = (
                "RESTRICTED_OUTPUT" if _contains_restricted_material(payload) else "SCHEMA_INVALID"
            )
            return PayloadValidation(False, code, None, None, self.validator)
        try:
            encoded = json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        except (TypeError, ValueError):
            return PayloadValidation(False, "SCHEMA_INVALID", None, None, self.validator)
        return PayloadValidation(
            True,
            None,
            self._content_identifier.identify(tenant_id=request.tenant_id, payload=encoded),
            self._data_class,
            self.validator,
        )


class EphemeralStructuredPayload:
    """Request-scoped JSON bytes that can be explicitly zeroized and never serialized."""

    __slots__ = ("_buffer", "_closed", "_content_id", "_request_id")

    def __init__(self, *, payload: object, request_id: str, content_id: str) -> None:
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        self._buffer = bytearray(encoded)
        self._request_id = request_id
        self._content_id = content_id
        self._closed = False

    def __repr__(self) -> str:
        return "EphemeralStructuredPayload(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> EphemeralStructuredPayload:
        raise TypeError("ephemeral payloads cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> EphemeralStructuredPayload:
        del memo
        raise TypeError("ephemeral payloads cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("ephemeral payloads cannot be serialized")

    def reveal_for(self, request_id: str) -> object:
        if self._closed:
            raise ValueError("ephemeral payload is closed")
        if request_id != self._request_id:
            raise ValueError("ephemeral payload scope mismatch")
        return json.loads(bytes(self._buffer))

    def close(self) -> None:
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


@dataclass(frozen=True, slots=True, repr=False)
class NormalizedModelAttempt:
    result: ModelCallResult
    payload: EphemeralStructuredPayload | None = None

    def __repr__(self) -> str:
        return f"NormalizedModelAttempt(status={self.result.status.value})"


class PreparedModelContext:
    """Ephemeral bounded context bytes plus metadata needed for the egress manifest."""

    __slots__ = (
        "_buffer",
        "_closed",
        "_content",
        "_content_identifier",
        "_payload_content_id",
        "_request_id",
        "_tenant_id",
        "_transforms",
    )

    def __init__(
        self,
        *,
        payload: bytes,
        content: tuple[EgressContentRef, ...],
        applied_transforms: tuple[str, ...],
        request_id: str,
        tenant_id: str,
        content_identifier: HmacContentIdentifier,
    ) -> None:
        if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_NATIVE_BYTES:
            raise ValueError("prepared model context is invalid")
        if not content:
            raise ValueError("prepared model context requires content metadata")
        if len(applied_transforms) != len(set(applied_transforms)):
            raise ValueError("prepared model transforms must be unique")
        self._buffer = bytearray(payload)
        self._content = tuple(sorted(content, key=lambda item: item.content_id))
        self._transforms = tuple(sorted(applied_transforms))
        self._request_id = request_id
        self._tenant_id = tenant_id
        self._content_identifier = content_identifier
        self._payload_content_id = content_identifier.identify(tenant_id=tenant_id, payload=payload)
        self._closed = False

    def __repr__(self) -> str:
        return "PreparedModelContext(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> PreparedModelContext:
        raise TypeError("prepared model contexts cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> PreparedModelContext:
        del memo
        raise TypeError("prepared model contexts cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("prepared model contexts cannot be serialized")

    @property
    def byte_count(self) -> int:
        return len(self._buffer)

    @property
    def content(self) -> tuple[EgressContentRef, ...]:
        return self._content

    @property
    def applied_transforms(self) -> tuple[str, ...]:
        return self._transforms

    @property
    def payload_content_id(self) -> str:
        return self._payload_content_id

    def bytes_for(self, request_id: str) -> bytes:
        if self._closed:
            raise ValueError("prepared model context is closed")
        if request_id != self._request_id:
            raise ValueError("prepared model context scope mismatch")
        payload = bytes(self._buffer)
        if not self._content_identifier.verify(
            tenant_id=self._tenant_id,
            payload=payload,
            content_id=self._payload_content_id,
        ):
            raise ValueError("prepared model context content binding mismatch")
        return payload

    def close(self) -> None:
        for index in range(len(self._buffer)):
            self._buffer[index] = 0
        self._content_identifier.close()
        self._closed = True


class ConnectedChannel(Protocol):
    @property
    def peer_ip(self) -> str: ...


class _ProviderConnector(Protocol):
    def connect(
        self,
        *,
        ip_address: str,
        port: int,
        server_name: str,
        timeout_ms: int,
    ) -> ConnectedChannel: ...

    def send(
        self,
        channel: ConnectedChannel,
        *,
        credential: str | None,
        payload: bytes,
        model_id: str,
        timeout_ms: int,
        binding: ProviderAttemptBinding,
    ) -> ProviderAttempt: ...


@dataclass(frozen=True, slots=True, repr=False)
class ModelBoundaryExecution:
    preflight: ModelPreflightResult
    result: ModelCallResult | None
    payload: EphemeralStructuredPayload | None = None

    def __repr__(self) -> str:
        status = (
            self.result.status.value
            if self.result is not None
            else self.preflight.eligibility.value
        )
        return f"ModelBoundaryExecution(status={status})"


class ModelBoundaryError(ValueError):
    """Safe public-boundary parse failure with no untrusted validation detail."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class _NativeSignals:
    request_code: str
    finish_code: str
    refusal_code: str | None
    filter_code: str | None
    content_text: str | None
    input_tokens: int
    output_tokens: int


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


def normalize_provider_attempt(
    *,
    request: ModelRequest,
    attempt: ProviderAttempt,
    expected_binding: ProviderAttemptBinding,
    validator: StructuredPayloadValidator,
) -> NormalizedModelAttempt:
    """Normalize one bounded native response; every ambiguity fails closed."""

    try:
        expected_request_hash = canonical_model_request_hash(request)
    except ValueError:
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=0,
        )
    elapsed_ms: object = attempt.elapsed_ms
    http_status: object = attempt.http_status
    response_bytes: object = attempt.response_bytes
    redirected: object = attempt.redirected
    dialect: object = attempt.dialect
    if (
        not isinstance(elapsed_ms, int)
        or isinstance(elapsed_ms, bool)
        or not 0 <= elapsed_ms <= _MAX_WIRE_INT
        or (
            http_status is not None
            and (
                not isinstance(http_status, int)
                or isinstance(http_status, bool)
                or not 100 <= http_status <= 599
            )
        )
        or (response_bytes is not None and not isinstance(response_bytes, bytes))
        or not isinstance(redirected, bool)
        or not isinstance(dialect, ApiDialect)
    ):
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=0,
        )
    if (
        expected_binding.request_hash != expected_request_hash
        or expected_binding.profile_hash != request.provider_profile.content_sha256
        or expected_binding.attempt != request.attempt
        or attempt.binding != expected_binding
        or attempt.dialect is not request.api_dialect
    ):
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=attempt.elapsed_ms,
        )
    transport_status = _transport_status(attempt)
    if transport_status is not None:
        return _non_success(
            request=request,
            status=transport_status,
            elapsed_ms=attempt.elapsed_ms,
        )
    try:
        if attempt.response_bytes is None:
            raise ValueError("missing native response")
        signals = _signals(attempt.dialect, attempt.response_bytes)
    except Exception:
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=attempt.elapsed_ms,
        )
    if (
        signals.input_tokens > request.budget.max_input_tokens
        or signals.output_tokens > request.budget.max_output_tokens
        or signals.input_tokens + signals.output_tokens
        > request.budget.max_input_tokens + request.budget.max_output_tokens
        or attempt.elapsed_ms > request.budget.timeout_ms
    ):
        return _non_success(
            request=request,
            status=ModelCallStatus.BUDGET_EXHAUSTED,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    native_status = _status(signals)
    if native_status is not None:
        return _non_success(
            request=request,
            status=native_status,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    if signals.finish_code != "COMPLETE" or signals.content_text is None:
        return _non_success(
            request=request,
            status=ModelCallStatus.EMPTY_OUTPUT,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    try:
        payload = json.loads(signals.content_text, object_pairs_hook=_closed_object)
        _depth(payload)
    except Exception:
        return _non_success(
            request=request,
            status=ModelCallStatus.INVALID_SCHEMA,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    if payload in ({}, [], None, ""):
        return _non_success(
            request=request,
            status=ModelCallStatus.EMPTY_OUTPUT,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    if _contains_restricted_material(payload):
        return _non_success(
            request=request,
            status=ModelCallStatus.INVALID_SCHEMA,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    try:
        validation = validator.validate(payload, request=request)
        if (
            not isinstance(validation, PayloadValidation)
            or not validation.accepted
            or validation.error_code is not None
            or validation.content_id is None
            or validation.data_class is None
            or validation.data_class is DataClass.RESTRICTED
            or validation.validator != request.output_schema
        ):
            raise ValueError("model payload validation failed")
        result = ModelCallResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            request_id=request.request_id,
            run_id=request.run_id,
            tenant_id=request.tenant_id,
            idempotency_key=request.idempotency_key,
            attempt=request.attempt,
            provider_profile=request.provider_profile,
            model_call_status=ModelCallStatus.SUCCEEDED,
            native=NativeOutcomeMetadata(
                schema_version=CONTRACT_SCHEMA_VERSION,
                request_code=signals.request_code,
                finish_code="COMPLETE",
            ),
            schema_result=ModelSchemaResult(
                schema_version=CONTRACT_SCHEMA_VERSION,
                status=ModelSchemaStatus.VALID,
                validator=validation.validator,
            ),
            usage=ModelUsage(
                schema_version=CONTRACT_SCHEMA_VERSION,
                input_tokens=signals.input_tokens,
                output_tokens=signals.output_tokens,
                repository_calls=0,
                elapsed_ms=attempt.elapsed_ms,
            ),
            retryable=False,
            content_provenance=OpaqueContentProvenance(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id=validation.content_id,
                tenant_id=request.tenant_id,
                data_class=validation.data_class,
                validator=validation.validator,
            ),
        )
        structured_payload = EphemeralStructuredPayload(
            payload=payload,
            request_id=request.request_id,
            content_id=validation.content_id,
        )
    except Exception:
        return _non_success(
            request=request,
            status=ModelCallStatus.INVALID_SCHEMA,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    return NormalizedModelAttempt(result, structured_payload)


ContextBuilder = Callable[[], PreparedModelContext]
CredentialSupplier = Callable[[ProviderProfile], CredentialLease | None]


class _RemoteReservation:
    __slots__ = ("execution", "ready", "semantic_hash")

    def __init__(self, semantic_hash: str) -> None:
        self.semantic_hash = semantic_hash
        self.ready = threading.Event()
        self.execution: ModelBoundaryExecution | None = None


class _FakeReservation:
    __slots__ = ("ready", "result", "semantic_hash")

    def __init__(self, semantic_hash: str) -> None:
        self.semantic_hash = semantic_hash
        self.ready = threading.Event()
        self.result: NormalizedModelAttempt | None = None


def _remote_invocation_hash(
    preflight: ModelPreflightRequest,
    profile: ProviderProfile,
    policy: EgressPolicyDocument,
) -> str:
    material = {
        "preflight": preflight.model_dump(mode="json"),
        "profile_hash": profile.canonical_content_hash(),
        "policy_hash": policy.canonical_content_hash(),
    }
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _idempotency_stop(reason_code: str) -> ModelPreflightResult:
    return ModelPreflightResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        eligibility=PreflightEligibility.INELIGIBLE,
        preflight_context_bytes=0,
        preflight_network_bytes=0,
        next_action=PreflightNextAction.STOP_BEFORE_CONTEXT_OR_NETWORK,
        deterministic_only_fallback=False,
        required_terminal_outcome=AuditRunOutcome.INDETERMINATE,
        reason_codes=(reason_code,),
    )


class AuthorizedProviderHarness:
    """One bounded remote attempt with policy and peer checks before application bytes."""

    __slots__ = ("_endpoint_issuer", "_idempotency", "_idempotency_lock", "_model_issuer")

    def __init__(
        self,
        *,
        model_issuer: ModelAuthorizationIssuer,
        endpoint_issuer: EndpointAuthorizationIssuer,
    ) -> None:
        self._model_issuer = model_issuer
        self._endpoint_issuer = endpoint_issuer
        self._idempotency: dict[str, _RemoteReservation] = {}
        self._idempotency_lock = threading.Lock()

    def _failure(
        self,
        *,
        preflight: ModelPreflightResult,
        request: ModelRequest,
    ) -> ModelBoundaryExecution:
        normalized = _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=0,
        )
        return ModelBoundaryExecution(preflight, normalized.result)

    def _complete(
        self,
        reservation: _RemoteReservation,
        candidate: ModelBoundaryExecution,
    ) -> ModelBoundaryExecution:
        with self._idempotency_lock:
            if reservation.execution is None:
                reservation.execution = candidate
                reservation.ready.set()
            return reservation.execution

    def execute_remote(
        self,
        *,
        preflight: ModelPreflightRequest,
        profile: ProviderProfile,
        policy: EgressPolicyDocument,
        context_builder: ContextBuilder,
        resolver: Resolver,
        connector: _ProviderConnector,
        credential_supplier: CredentialSupplier,
        validator: StructuredPayloadValidator,
        now: float,
    ) -> ModelBoundaryExecution:
        request = preflight.model_request
        try:
            invocation_hash = _remote_invocation_hash(preflight, profile, policy)
        except (TypeError, ValueError):
            authorization = self._model_issuer.authorize_pre_context(
                preflight, profile=profile, policy=policy
            )
            return ModelBoundaryExecution(authorization.result, None)
        with self._idempotency_lock:
            reservation = self._idempotency.get(request.idempotency_key)
            owner = reservation is None
            if reservation is None:
                reservation = _RemoteReservation(invocation_hash)
                self._idempotency[request.idempotency_key] = reservation
        if not owner:
            if reservation.semantic_hash != invocation_hash:
                return self._failure(
                    preflight=_idempotency_stop("IDEMPOTENCY_SEMANTIC_CONFLICT"),
                    request=request,
                )
            if not reservation.ready.wait(timeout=request.budget.timeout_ms / 1000):
                return self._complete(
                    reservation,
                    self._failure(
                        preflight=_idempotency_stop("IDEMPOTENCY_WAIT_TIMEOUT"),
                        request=request,
                    ),
                )
            completed = reservation.execution
            if completed is None:
                raise RuntimeError("remote idempotency reservation completed without a result")
            return completed

        authorization = self._model_issuer.authorize_pre_context(
            preflight,
            profile=profile,
            policy=policy,
        )
        decision = authorization.result
        if decision.eligibility is not PreflightEligibility.ELIGIBLE:
            execution = ModelBoundaryExecution(decision, None)
            return self._complete(reservation, execution)

        context: PreparedModelContext | None = None
        credential_lease: CredentialLease | None = None
        try:
            context = context_builder()
            payload_bytes = context.bytes_for(request.request_id)
            manifest = EgressManifest.build(
                model_request=request,
                policy=request.execution_identity.policy,
                destination=f"profile://{profile.profile_id}",
                payload_content_id=context.payload_content_id,
                content=context.content,
                applied_transforms=context.applied_transforms,
                byte_count=len(payload_bytes),
            )
            pre_send = self._model_issuer.authorize_pre_send(authorization, manifest)
            endpoint = self._endpoint_issuer.authorize(
                pre_send,
                model_issuer=self._model_issuer,
                profile=profile,
                resolver=resolver,
                now=now,
            )
            channel = connector.connect(
                ip_address=endpoint.connect_addresses[0],
                port=endpoint.port,
                server_name=endpoint.authority,
                timeout_ms=request.budget.timeout_ms,
            )
            verified = self._endpoint_issuer.verify_peer(
                endpoint,
                connected_peer=channel.peer_ip,
                resolver=resolver,
                now=now,
            )
            binding = ProviderAttemptBinding.from_claim(
                self._endpoint_issuer.consume_verified(verified)
            )
            credential: str | None = None
            if profile.credential_ref is not None:
                credential_lease = credential_supplier(profile)
                if credential_lease is None:
                    raise ValueError("credential supplier did not return a lease")
                credential = credential_lease.reveal_for(
                    profile_selector=profile.selector,
                    authority=profile.endpoint.authority,
                )
            attempt = connector.send(
                channel,
                credential=credential,
                payload=payload_bytes,
                model_id=profile.model_id,
                timeout_ms=request.budget.timeout_ms,
                binding=binding,
            )
            normalized = normalize_provider_attempt(
                request=request,
                attempt=attempt,
                expected_binding=binding,
                validator=validator,
            )
            execution = ModelBoundaryExecution(decision, normalized.result, normalized.payload)
        except Exception:
            execution = self._failure(preflight=decision, request=request)
        finally:
            if credential_lease is not None:
                try:
                    credential_lease.close()
                except Exception:
                    execution = self._failure(preflight=decision, request=request)
            if context is not None:
                try:
                    context.close()
                except Exception:
                    execution = self._failure(preflight=decision, request=request)
        return self._complete(reservation, execution)


class ScriptedFakeProvider:
    """Hermetic exact-request fake: no default success, credential, DNS or network hooks."""

    __slots__ = (
        "_effects",
        "_idempotency",
        "_idempotency_lock",
        "_scripts",
        "effect_count",
    )

    def __init__(self, scripts: dict[str, ProviderAttempt]) -> None:
        self._scripts = dict(scripts)
        self._effects: set[str] = set()
        self._idempotency: dict[str, _FakeReservation] = {}
        self._idempotency_lock = threading.Lock()
        self.effect_count = 0

    def _provider_error(
        self, request: ModelRequest, validator: StructuredPayloadValidator
    ) -> NormalizedModelAttempt:
        del validator
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=0,
        )

    def _complete(
        self,
        reservation: _FakeReservation,
        candidate: NormalizedModelAttempt,
    ) -> NormalizedModelAttempt:
        with self._idempotency_lock:
            if reservation.result is None:
                reservation.result = candidate
                reservation.ready.set()
            return reservation.result

    def invoke(
        self,
        *,
        request: ModelRequest,
        authorization: PreSendAuthorization,
        model_issuer: ModelAuthorizationIssuer,
        validator: StructuredPayloadValidator,
    ) -> NormalizedModelAttempt:
        try:
            request_hash = canonical_model_request_hash(request)
        except ValueError:
            return self._provider_error(request, validator)
        try:
            claim = model_issuer.consume_pre_send(authorization)
        except AuthorizationError:
            return self._provider_error(request, validator)
        if (
            claim["request_hash"] != request_hash
            or claim["profile_hash"] != request.provider_profile.content_sha256
            or int(claim["attempt"]) != request.attempt
        ):
            return self._provider_error(request, validator)
        try:
            binding = ProviderAttemptBinding.from_claim(claim)
        except ValueError:
            return self._provider_error(request, validator)
        semantic_hash = hashlib.sha256(
            (
                request_hash
                + binding.profile_hash
                + binding.policy_hash
                + binding.manifest_hash
                + str(binding.attempt)
            ).encode()
        ).hexdigest()
        with self._idempotency_lock:
            reservation = self._idempotency.get(request.idempotency_key)
            owner = reservation is None
            if reservation is None:
                reservation = _FakeReservation(semantic_hash)
                self._idempotency[request.idempotency_key] = reservation
        if not owner:
            if reservation.semantic_hash != semantic_hash:
                return self._provider_error(request, validator)
            if not reservation.ready.wait(timeout=request.budget.timeout_ms / 1000):
                return self._complete(
                    reservation,
                    self._provider_error(request, validator),
                )
            if reservation.result is None:
                return self._provider_error(request, validator)
            return reservation.result
        attempt = self._scripts.get(request_hash)
        if attempt is None:
            normalized = self._provider_error(request, validator)
        else:
            try:
                with self._idempotency_lock:
                    if request_hash not in self._effects:
                        self._effects.add(request_hash)
                        self.effect_count += 1
                bound_attempt = replace(attempt, binding=binding)
                normalized = normalize_provider_attempt(
                    request=request,
                    attempt=bound_attempt,
                    expected_binding=binding,
                    validator=validator,
                )
            except Exception:
                normalized = self._provider_error(request, validator)
        return self._complete(reservation, normalized)


__all__ = [
    "AuthorizedProviderHarness",
    "ConnectedChannel",
    "ContextBuilder",
    "CredentialSupplier",
    "EphemeralStructuredPayload",
    "HmacContentIdentifier",
    "JsonObjectValidator",
    "ModelBoundaryError",
    "NormalizedModelAttempt",
    "PayloadValidation",
    "PreparedModelContext",
    "ProviderAttempt",
    "ProviderAttemptBinding",
    "ProviderStreamState",
    "ScriptedFakeProvider",
    "StructuredPayloadValidator",
    "TransportFailure",
    "normalize_provider_attempt",
    "parse_model_call_result",
    "parse_model_request",
]
