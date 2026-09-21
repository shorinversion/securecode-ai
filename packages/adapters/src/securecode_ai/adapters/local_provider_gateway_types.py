"""Local provider boundary with actual policy refusal and bounded backend I/O.

Refusal belongs to this gateway provider, not to the underlying model. No
capability registry is promoted by starting this service or handling a request.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from securecode_ai.contracts import DataClass

from .native_repository_tools import (
    NATIVE_REPOSITORY_TOOLS_JSON,
    NativeToolCallRejection,
)
from .product_model import AUDITOR_WIRE_SCHEMA_JSON, MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON

_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_OBSERVED_RESPONSE_BYTES = _MAX_RESPONSE_BYTES + 1
_MAX_REQUEST_BYTES = 128 * 1024
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and _ID.fullmatch(value) is not None


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate gateway field")
        result[key] = value
    return result


def _invalid_constant(value: str) -> object:
    raise ValueError("invalid gateway number")


def _decode(body: bytes) -> dict[str, object]:
    value = json.loads(body, object_pairs_hook=_closed_object, parse_constant=_invalid_constant)
    if not isinstance(value, dict):
        raise ValueError("invalid gateway root")
    return value


class GatewayBudgetMode(StrEnum):
    ORDINARY = "ORDINARY"
    PUBLIC_CPU_CALIBRATION = "PUBLIC_CPU_CALIBRATION"


@dataclass(frozen=True, slots=True)
class GatewayPolicy:
    model_id: str
    model_manifest_sha256: str
    backend_port: int = 11434
    max_output_tokens: int = 4096
    max_request_bytes: int = _MAX_REQUEST_BYTES
    timeout_seconds: float = 30.0
    backend_version: str = "0.16.2"
    budget_mode: GatewayBudgetMode = GatewayBudgetMode.ORDINARY

    def __post_init__(self) -> None:
        if (
            type(self.model_id) is not str
            or not 1 <= len(self.model_id) <= 128
            or any(ord(char) < 33 or ord(char) > 126 for char in self.model_id)
            or type(self.model_manifest_sha256) is not str
            or len(self.model_manifest_sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.model_manifest_sha256)
            or type(self.backend_port) is not int
            or not 1 <= self.backend_port <= 65535
            or type(self.max_output_tokens) is not int
            or not 1 <= self.max_output_tokens <= 4096
            or type(self.max_request_bytes) is not int
            or not 1 <= self.max_request_bytes <= _MAX_REQUEST_BYTES
            or type(self.timeout_seconds) not in (float, int)
            or type(self.budget_mode) is not GatewayBudgetMode
            or not 0
            < self.timeout_seconds
            <= (60 if self.budget_mode is GatewayBudgetMode.PUBLIC_CPU_CALIBRATION else 30)
            or not math.isfinite(self.timeout_seconds)
            or type(self.backend_version) is not str
            or re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", self.backend_version) is None
        ):
            raise ValueError("invalid gateway policy")

    @property
    def content_sha256(self) -> str:
        material = {
            "version": "1.7.0",
            "budget_mode": self.budget_mode.value,
            "native_upstream_format": "provider_native_json_for_validated_ordinary_or_post_tool",
            "ollama_native_tool_index_ceiling": 3,
            "native_tool_schema_sha256": hashlib.sha256(NATIVE_REPOSITORY_TOOLS_JSON).hexdigest(),
            "native_transcript_max_messages": 33,
            "native_transcript_max_calls": 16,
            "backend_version": self.backend_version,
            "model_id": self.model_id,
            "model_manifest_sha256": self.model_manifest_sha256,
            "backend_origin": f"http://127.0.0.1:{self.backend_port}",
            "max_output_tokens": self.max_output_tokens,
            "max_request_bytes": self.max_request_bytes,
            "timeout_seconds": self.timeout_seconds,
            "allowed_data_classes": [
                value.value for value in DataClass if value is not DataClass.RESTRICTED
            ],
            "restricted_data_outcome": "PROVIDER_NATIVE_REFUSAL",
            "allowed_roles": ["discovery", "auditor"],
            "role_schemas": [
                hashlib.sha256(schema).hexdigest()
                for schema in (
                    MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON,
                    AUDITOR_WIRE_SCHEMA_JSON,
                )
            ],
        }
        return hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class GatewayReply:
    status: int
    body: bytes = field(repr=False)
    backend_dispatched: bool = False
    native_policy_refusal: bool = False


class GatewayExchangeOperation(StrEnum):
    VERSION = "VERSION"
    TAGS = "TAGS"
    GENERATION = "GENERATION"


class GatewayExchangePhase(StrEnum):
    CONNECT = "CONNECT"
    REQUEST = "REQUEST"
    HEADERS = "HEADERS"
    BODY = "BODY"
    COMPLETE = "COMPLETE"


class GatewayExchangeFailure(StrEnum):
    NONE = "NONE"
    TIMEOUT = "TIMEOUT"
    TRANSPORT = "TRANSPORT"


class GatewayResponseNormalization(StrEnum):
    NOT_REACHED = "NOT_REACHED"
    STANDARD = "STANDARD"
    NATIVE = "NATIVE"
    REJECTED = "REJECTED"


class GatewayNativeEnvelopeShape(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    DECODE_REJECTED = "DECODE_REJECTED"
    CHOICES_REJECTED = "CHOICES_REJECTED"
    NO_TOOL_CALLS = "NO_TOOL_CALLS"
    CHOICE_REJECTED = "CHOICE_REJECTED"
    MESSAGE_REJECTED = "MESSAGE_REJECTED"
    CALL_LIST_REJECTED = "CALL_LIST_REJECTED"
    CALL_ITEM_REJECTED = "CALL_ITEM_REJECTED"
    ARGUMENTS_REJECTED = "ARGUMENTS_REJECTED"
    ENVELOPE_REJECTED = "ENVELOPE_REJECTED"


class GatewayNativeArgumentsShape(StrEnum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    STRING = "STRING"
    OBJECT = "OBJECT"
    OTHER = "OTHER"
    MIXED = "MIXED"


class _NativeEnvelopeRejection(ValueError):
    def __init__(
        self,
        shape: GatewayNativeEnvelopeShape,
        arguments_shape: GatewayNativeArgumentsShape = GatewayNativeArgumentsShape.NOT_APPLICABLE,
        arguments_rejection: NativeToolCallRejection = NativeToolCallRejection.NOT_APPLICABLE,
    ) -> None:
        super().__init__("native envelope rejected")
        self.shape = shape
        self.arguments_shape = arguments_shape
        self.arguments_rejection = arguments_rejection


@dataclass(frozen=True, slots=True)
class GatewayNormalizationObservation:
    """Closed gateway-only status after response normalization, without payloads."""

    policy_sha256: str
    request_sha256: str
    status: GatewayResponseNormalization
    native_shape: GatewayNativeEnvelopeShape = GatewayNativeEnvelopeShape.NOT_APPLICABLE
    native_arguments_shape: GatewayNativeArgumentsShape = GatewayNativeArgumentsShape.NOT_APPLICABLE
    native_arguments_rejection: NativeToolCallRejection = NativeToolCallRejection.NOT_APPLICABLE

    def __post_init__(self) -> None:
        if (
            not _sha256(self.policy_sha256)
            or not _sha256(self.request_sha256)
            or type(self.status) is not GatewayResponseNormalization
            or type(self.native_shape) is not GatewayNativeEnvelopeShape
            or type(self.native_arguments_shape) is not GatewayNativeArgumentsShape
            or type(self.native_arguments_rejection) is not NativeToolCallRejection
        ):
            raise ValueError("invalid gateway normalization observation")


@dataclass(frozen=True, slots=True)
class GatewayExchangeObservation:
    """Closed metadata for one cleaned-up backend HTTP exchange."""

    policy_sha256: str
    request_sha256: str
    operation: GatewayExchangeOperation
    phase: GatewayExchangePhase
    mapped_status: int
    observed_http_status: int | None
    elapsed_known: bool
    elapsed_ms: int | None
    deadline_expired: bool
    backend_dispatched: bool
    received_bytes: int
    response_overflow: bool
    failure: GatewayExchangeFailure

    def __post_init__(self) -> None:
        if (
            not _sha256(self.policy_sha256)
            or not _sha256(self.request_sha256)
            or type(self.operation) is not GatewayExchangeOperation
            or type(self.phase) is not GatewayExchangePhase
            or type(self.mapped_status) is not int
            or self.mapped_status not in (200, 408, 413, 429, 500, 502, 503, 504)
            or (
                self.observed_http_status is not None
                and (
                    type(self.observed_http_status) is not int
                    or not 100 <= self.observed_http_status <= 599
                )
            )
            or type(self.elapsed_known) is not bool
            or (self.elapsed_known != (self.elapsed_ms is not None))
            or (
                self.elapsed_ms is not None
                and (type(self.elapsed_ms) is not int or self.elapsed_ms < 0)
            )
            or type(self.deadline_expired) is not bool
            or type(self.backend_dispatched) is not bool
            or type(self.received_bytes) is not int
            or not 0 <= self.received_bytes <= _MAX_OBSERVED_RESPONSE_BYTES
            or type(self.response_overflow) is not bool
            or type(self.failure) is not GatewayExchangeFailure
        ):
            raise ValueError("invalid gateway exchange observation")


class GatewayBackend(Protocol):
    def dispatch(self, body: bytes, *, timeout_seconds: float) -> GatewayReply: ...


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
