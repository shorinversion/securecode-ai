"""Hermetic provider adapter, native-dialect normalization and ephemeral payloads."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Protocol, Self, SupportsIndex

from securecode_ai.core import (
    ApiDialect,
    ComponentPin,
    DataClass,
    EgressContentRef,
    ModelCallResult,
    ModelPreflightResult,
    ModelRequest,
    ModelUsage,
    PayloadValidation,
)

from .native_repository_tools import NativeRepositoryToolCall
from .remote_provider_budget import RemoteProviderCallContext

_MAX_NATIVE_BYTES: Final = 1024 * 1024
_MAX_JSON_DEPTH: Final = 64
_MAX_WIRE_INT: Final = 9_007_199_254_740_991
_NATIVE_RESPONSE_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


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
            or "BEGIN " + "PRIVATE KEY" in upper
            or "BEGIN RSA " + "PRIVATE KEY" in upper
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

    __slots__ = ("_buffer", "_closed", "_content_id", "_payload_sha256", "_request_id")

    def __init__(
        self,
        *,
        payload: bytes,
        request_id: str,
        tenant_id: str,
        content_id: str,
        content_identifier: HmacContentIdentifier,
    ) -> None:
        if (
            type(payload) is not bytes
            or not payload
            or len(payload) > _MAX_NATIVE_BYTES
            or type(request_id) is not str
            or not request_id
            or type(tenant_id) is not str
            or not tenant_id
            or type(content_id) is not str
            or not content_identifier.verify(
                tenant_id=tenant_id, payload=payload, content_id=content_id
            )
        ):
            raise ValueError("ephemeral payload content binding mismatch")
        self._buffer = bytearray(payload)
        self._request_id = request_id
        self._content_id = content_id
        self._payload_sha256 = hashlib.sha256(payload).digest()
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
        payload = bytes(self._buffer)
        if not hmac.compare_digest(hashlib.sha256(payload).digest(), self._payload_sha256):
            raise ValueError("ephemeral payload content binding mismatch")
        return json.loads(payload)

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
        call_budget: RemoteProviderCallContext,
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


@dataclass(frozen=True, slots=True, repr=False)
class NativeTurnBoundaryExecution:
    """A validated selection is nonterminal and never a successful model result."""

    preflight: ModelPreflightResult
    selection: tuple[NativeRepositoryToolCall, ...] | None = None
    usage: ModelUsage | None = None
    elapsed_ms: int = 0
    terminal: ModelBoundaryExecution | None = None

    def __post_init__(self) -> None:
        if (self.selection is None) == (self.terminal is None):
            raise ValueError("native turn must have exactly one outcome")
        if self.selection is not None and (not self.selection or self.usage is None):
            raise ValueError("native selection requires measured usage")

    def __repr__(self) -> str:
        return "NativeTurnBoundaryExecution(selection)" if self.selection else repr(self.terminal)


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
