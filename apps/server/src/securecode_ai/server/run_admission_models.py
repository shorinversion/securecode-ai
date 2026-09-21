"""Closed values and ports for durable run admission."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from securecode_ai.contracts import RunExecutionIdentity
from securecode_ai.core.resource_governor import (
    ResourceReservationReceipt,
    ResourceReservationRequest,
)

from .ports import VerifiedIdentity

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_SQLITE_INTEGER_MAX: Final = 9_223_372_036_854_775_807
_REQUEST_DOMAIN: Final = b"securecode-ai/run-admission/resource-request/v1\x00"


class AdmissionState(StrEnum):
    PERSISTED = "PERSISTED"
    RESERVED = "RESERVED"
    ADMITTED = "ADMITTED"
    FAILED = "FAILED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"


class AdmissionErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    FORBIDDEN = "FORBIDDEN"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    RUN_CONFLICT = "RUN_CONFLICT"
    RESOURCE_QUOTA_EXCEEDED = "RESOURCE_QUOTA_EXCEEDED"
    RESOURCE_RATE_LIMITED = "RESOURCE_RATE_LIMITED"
    RESOURCE_CONCURRENCY_EXCEEDED = "RESOURCE_CONCURRENCY_EXCEEDED"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"


class AdmissionError(Exception):
    """Safe coordinator failure that never carries rejected data."""

    __slots__ = ("code", "status")

    def __init__(self, code: AdmissionErrorCode, status: int) -> None:
        if type(code) is not AdmissionErrorCode or type(status) is not int:
            raise TypeError("admission error is invalid")
        self.code = code
        self.status = status
        super().__init__(safe_message(code))
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class RunResourceDefaults:
    """Host-owned default reservation, never selected by request JSON."""

    profile_sha256: str
    requested_tokens: int
    requested_cost_microunits: int
    requested_cpu_ms: int
    requested_memory_bytes: int
    requested_wall_ms: int
    lease_duration_ms: int

    def __post_init__(self) -> None:
        quantities = (
            self.requested_tokens,
            self.requested_cost_microunits,
            self.requested_cpu_ms,
            self.requested_memory_bytes,
            self.requested_wall_ms,
        )
        if (
            type(self.profile_sha256) is not str
            or _SHA256.fullmatch(self.profile_sha256) is None
            or any(not _bounded_nonnegative(value) for value in quantities)
            or not _bounded_positive(self.lease_duration_ms)
        ):
            raise ValueError("default resource request policy is invalid")


@dataclass(frozen=True, slots=True)
class AdmissionRecord:
    tenant_id: str
    idempotency_key: str
    request_sha256: str
    run_id: str
    repository_id: str
    execution_identity_hash: str
    identity_json: str
    resource_request: ResourceReservationRequest
    state: AdmissionState
    reservation_id: str | None = None
    reservation_version: int | None = None
    failure_code: AdmissionErrorCode | None = None


class RunAdmissionStore(Protocol):
    def find(
        self, *, tenant_id: str, idempotency_key: str, request_sha256: str
    ) -> AdmissionRecord | None: ...

    def begin(
        self,
        *,
        tenant_id: str,
        idempotency_key: str,
        request_sha256: str,
        run_id: str,
        execution_identity: RunExecutionIdentity,
        resource_request: ResourceReservationRequest,
        metadata: Mapping[str, object],
        now_ms: int,
    ) -> AdmissionRecord: ...

    def reserved(
        self, record: AdmissionRecord, receipt: ResourceReservationReceipt, *, now_ms: int
    ) -> AdmissionRecord: ...

    def admitted(self, record: AdmissionRecord, *, now_ms: int) -> AdmissionRecord: ...

    def failed(
        self,
        record: AdmissionRecord,
        *,
        code: AdmissionErrorCode,
        recovery_required: bool,
        now_ms: int,
    ) -> AdmissionRecord: ...

    def run_document(self, record: AdmissionRecord) -> dict[str, object]: ...


class ResourceReservationPort(Protocol):
    def reserve(self, request: ResourceReservationRequest) -> ResourceReservationReceipt: ...

    def release(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        reservation_id: str,
        expected_version: int,
        now_ms: int,
        cancelled: bool = False,
    ) -> ResourceReservationReceipt: ...


class WorkerQueuePort(Protocol):
    def enqueue(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity: RunExecutionIdentity,
    ) -> None: ...


class AuthorizationPort(Protocol):
    def allows(
        self,
        identity: VerifiedIdentity,
        *,
        action: str,
        repository_id: str | None,
    ) -> bool: ...


class ResourceRequestPolicy(Protocol):
    def build(
        self,
        *,
        idempotency_key: str,
        run_id: str,
        execution_identity: RunExecutionIdentity,
        now_ms: int,
    ) -> ResourceReservationRequest: ...


class DefaultResourceRequestPolicy:
    """Build a deterministic, host-configured request for the first admission attempt."""

    __slots__ = ("_defaults",)

    def __init__(self, defaults: RunResourceDefaults) -> None:
        if type(defaults) is not RunResourceDefaults:
            raise TypeError("defaults must be RunResourceDefaults")
        self._defaults = defaults

    def build(
        self,
        *,
        idempotency_key: str,
        run_id: str,
        execution_identity: RunExecutionIdentity,
        now_ms: int,
    ) -> ResourceReservationRequest:
        if not _identifier(idempotency_key) or not _identifier(run_id):
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400)
        if type(execution_identity) is not RunExecutionIdentity or not _bounded_nonnegative(now_ms):
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400)
        revision = execution_identity.repository_revision
        lease_expires_at_ms = now_ms + self._defaults.lease_duration_ms
        if lease_expires_at_ms > _SQLITE_INTEGER_MAX:
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400)
        request_id = (
            "admission-"
            + hashlib.sha256(
                _REQUEST_DOMAIN
                + revision.tenant_id.encode("utf-8")
                + b"\x00"
                + idempotency_key.encode("utf-8")
            ).hexdigest()[:40]
        )
        return ResourceReservationRequest(
            request_id=request_id,
            tenant_id=revision.tenant_id,
            repository_id=revision.repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity.execution_identity_hash,
            profile_sha256=self._defaults.profile_sha256,
            requested_tokens=self._defaults.requested_tokens,
            requested_cost_microunits=self._defaults.requested_cost_microunits,
            requested_cpu_ms=self._defaults.requested_cpu_ms,
            requested_memory_bytes=self._defaults.requested_memory_bytes,
            requested_wall_ms=self._defaults.requested_wall_ms,
            now_ms=now_ms,
            lease_expires_at_ms=lease_expires_at_ms,
        )


AdmissionClock = Callable[[], int]


def request_sha256(method: str, route: str, raw_body: bytes) -> str:
    if type(method) is not str or type(route) is not str or type(raw_body) is not bytes:
        raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400)
    try:
        method_bytes = method.encode("ascii")
    except UnicodeEncodeError:
        raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400) from None
    return hashlib.sha256(
        method_bytes + b"\x00" + route.encode("utf-8") + b"\x00" + raw_body
    ).hexdigest()


def canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def safe_message(code: AdmissionErrorCode) -> str:
    messages = {
        AdmissionErrorCode.INVALID_REQUEST: "run admission request is invalid",
        AdmissionErrorCode.FORBIDDEN: "request is not authorized",
        AdmissionErrorCode.IDEMPOTENCY_CONFLICT: "idempotency key conflicts with a prior request",
        AdmissionErrorCode.RUN_CONFLICT: "run conflicts with current state",
        AdmissionErrorCode.RESOURCE_QUOTA_EXCEEDED: "tenant resource quota was exceeded",
        AdmissionErrorCode.RESOURCE_RATE_LIMITED: "tenant admission rate was exceeded",
        AdmissionErrorCode.RESOURCE_CONCURRENCY_EXCEEDED: "tenant run concurrency was exceeded",
        AdmissionErrorCode.RESOURCE_CONFLICT: "resource reservation conflicts with current state",
        AdmissionErrorCode.SERVICE_UNAVAILABLE: "run admission is unavailable",
    }
    return messages[code]


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _bounded_nonnegative(value: object) -> bool:
    return type(value) is int and 0 <= value <= _SQLITE_INTEGER_MAX


def _bounded_positive(value: object) -> bool:
    return type(value) is int and 0 < value <= _SQLITE_INTEGER_MAX


__all__ = [
    "AdmissionClock",
    "AdmissionError",
    "AdmissionErrorCode",
    "AdmissionRecord",
    "AdmissionState",
    "AuthorizationPort",
    "DefaultResourceRequestPolicy",
    "ResourceRequestPolicy",
    "ResourceReservationPort",
    "RunAdmissionStore",
    "RunResourceDefaults",
    "WorkerQueuePort",
    "canonical",
    "request_sha256",
    "safe_message",
]
