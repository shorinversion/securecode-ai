"""Tenant resource admission, quota reservation, and spend accounting."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_HASH_DOMAIN: Final = b"securecode-ai/resource-governor/v1\x00"


class ResourceGovernorErrorCode(StrEnum):
    INVALID_REQUEST = "INVALID_REQUEST"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    CONCURRENCY_EXCEEDED = "CONCURRENCY_EXCEEDED"
    CONFLICT = "CONFLICT"
    RESERVATION_UNKNOWN = "RESERVATION_UNKNOWN"
    RESERVATION_TERMINAL = "RESERVATION_TERMINAL"


class ResourceGovernorError(ValueError):
    __slots__ = ("code", "safe_message")

    def __init__(self, code: ResourceGovernorErrorCode) -> None:
        if type(code) is not ResourceGovernorErrorCode:
            raise TypeError("resource governor error code is invalid")
        self.code = code
        self.safe_message = "resource request was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


class ReservationState(StrEnum):
    RESERVED = "RESERVED"
    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class TenantResourceLimits:
    tenant_id: str
    profile_id: str
    profile_sha256: str
    max_concurrent_runs: int
    max_admissions_per_window: int
    admission_window_ms: int
    max_tokens_per_window: int
    max_cost_microunits_per_window: int
    max_cpu_ms_per_run: int
    max_memory_bytes_per_run: int
    max_wall_ms_per_run: int

    def __post_init__(self) -> None:
        if (
            not _identifier(self.tenant_id)
            or not _identifier(self.profile_id)
            or not _sha256(self.profile_sha256)
            or any(
                type(value) is not int or value < 1
                for value in (
                    self.max_concurrent_runs,
                    self.max_admissions_per_window,
                    self.admission_window_ms,
                    self.max_tokens_per_window,
                    self.max_cost_microunits_per_window,
                    self.max_cpu_ms_per_run,
                    self.max_memory_bytes_per_run,
                    self.max_wall_ms_per_run,
                )
            )
        ):
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class ResourceReservationRequest:
    request_id: str
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    profile_sha256: str
    requested_tokens: int
    requested_cost_microunits: int
    requested_cpu_ms: int
    requested_memory_bytes: int
    requested_wall_ms: int
    now_ms: int
    lease_expires_at_ms: int

    def __post_init__(self) -> None:
        if (
            any(
                not _identifier(value)
                for value in (self.request_id, self.tenant_id, self.repository_id, self.run_id)
            )
            or not _sha256(self.execution_identity_hash)
            or not _sha256(self.profile_sha256)
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.requested_tokens,
                    self.requested_cost_microunits,
                    self.requested_cpu_ms,
                    self.requested_memory_bytes,
                    self.requested_wall_ms,
                    self.now_ms,
                )
            )
            or type(self.lease_expires_at_ms) is not int
            or self.lease_expires_at_ms <= self.now_ms
        ):
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class ResourceUsage:
    tokens: int
    cost_microunits: int
    cpu_ms: int
    peak_memory_bytes: int
    wall_ms: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (
                self.tokens,
                self.cost_microunits,
                self.cpu_ms,
                self.peak_memory_bytes,
                self.wall_ms,
            )
        ):
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)


@dataclass(frozen=True, slots=True)
class ResourceReservationReceipt:
    reservation_id: str
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    profile_sha256: str
    state: ReservationState
    reserved: ResourceUsage
    actual: ResourceUsage | None
    lease_expires_at_ms: int
    state_version: int
    idempotent: bool


@dataclass(slots=True)
class _Reservation:
    request_hash: str
    request: ResourceReservationRequest
    reserved: ResourceUsage
    actual: ResourceUsage | None
    state: ReservationState
    state_version: int


class TenantResourceGovernor:
    """Process-local governor suitable for a durable transactional adapter."""

    __slots__ = ("_admissions", "_limits", "_lock", "_requests", "_reservations")

    def __init__(self) -> None:
        self._lock = RLock()
        self._limits: dict[str, TenantResourceLimits] = {}
        self._requests: dict[str, str] = {}
        self._reservations: dict[str, _Reservation] = {}
        self._admissions: dict[str, list[tuple[int, int, int]]] = {}

    def configure(self, limits: TenantResourceLimits) -> None:
        if type(limits) is not TenantResourceLimits:
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)
        with self._lock:
            current = self._limits.get(limits.tenant_id)
            if current is not None and current.profile_sha256 == limits.profile_sha256:
                if current != limits:
                    raise ResourceGovernorError(ResourceGovernorErrorCode.CONFLICT)
                return
            self._limits[limits.tenant_id] = limits

    def reserve(self, request: ResourceReservationRequest) -> ResourceReservationReceipt:
        if type(request) is not ResourceReservationRequest:
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)
        request_hash = _request_hash(request)
        reservation_id = "reservation-" + request_hash[:40]
        with self._lock:
            existing_id = self._requests.get(request.request_id)
            if existing_id is not None:
                record = self._reservations[existing_id]
                if record.request_hash != request_hash:
                    raise ResourceGovernorError(ResourceGovernorErrorCode.CONFLICT)
                return _receipt(existing_id, record, idempotent=True)
            limits = self._limits.get(request.tenant_id)
            if limits is None or limits.profile_sha256 != request.profile_sha256:
                raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)
            self._expire(request.now_ms)
            active = tuple(
                item
                for item in self._reservations.values()
                if item.request.tenant_id == request.tenant_id
                and item.state is ReservationState.RESERVED
            )
            if len(active) >= limits.max_concurrent_runs:
                raise ResourceGovernorError(ResourceGovernorErrorCode.CONCURRENCY_EXCEEDED)
            events = self._window_events(request.tenant_id, request.now_ms, limits)
            if len(events) >= limits.max_admissions_per_window:
                raise ResourceGovernorError(ResourceGovernorErrorCode.RATE_LIMITED)
            window_tokens = sum(item[1] for item in events)
            window_cost = sum(item[2] for item in events)
            reserved = ResourceUsage(
                tokens=request.requested_tokens,
                cost_microunits=request.requested_cost_microunits,
                cpu_ms=request.requested_cpu_ms,
                peak_memory_bytes=request.requested_memory_bytes,
                wall_ms=request.requested_wall_ms,
            )
            if (
                window_tokens + reserved.tokens > limits.max_tokens_per_window
                or window_cost + reserved.cost_microunits > limits.max_cost_microunits_per_window
                or reserved.cpu_ms > limits.max_cpu_ms_per_run
                or reserved.peak_memory_bytes > limits.max_memory_bytes_per_run
                or reserved.wall_ms > limits.max_wall_ms_per_run
            ):
                raise ResourceGovernorError(ResourceGovernorErrorCode.QUOTA_EXCEEDED)
            record = _Reservation(
                request_hash=request_hash,
                request=request,
                reserved=reserved,
                actual=None,
                state=ReservationState.RESERVED,
                state_version=1,
            )
            self._requests[request.request_id] = reservation_id
            self._reservations[reservation_id] = record
            self._admissions.setdefault(request.tenant_id, []).append(
                (request.now_ms, reserved.tokens, reserved.cost_microunits)
            )
            return _receipt(reservation_id, record, idempotent=False)

    def commit(
        self,
        reservation_id: str,
        usage: ResourceUsage,
        *,
        expected_version: int,
        now_ms: int,
    ) -> ResourceReservationReceipt:
        if type(usage) is not ResourceUsage:
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)
        with self._lock:
            record = self._record(reservation_id)
            if record.state is ReservationState.COMMITTED:
                if record.actual != usage:
                    raise ResourceGovernorError(ResourceGovernorErrorCode.CONFLICT)
                return _receipt(reservation_id, record, idempotent=True)
            self._require_active(record, expected_version, now_ms)
            if (
                usage.tokens > record.reserved.tokens
                or usage.cost_microunits > record.reserved.cost_microunits
                or usage.cpu_ms > record.reserved.cpu_ms
                or usage.peak_memory_bytes > record.reserved.peak_memory_bytes
                or usage.wall_ms > record.reserved.wall_ms
            ):
                raise ResourceGovernorError(ResourceGovernorErrorCode.QUOTA_EXCEEDED)
            record.actual = usage
            record.state = ReservationState.COMMITTED
            record.state_version += 1
            return _receipt(reservation_id, record, idempotent=False)

    def release(
        self,
        reservation_id: str,
        *,
        expected_version: int,
        now_ms: int,
        cancelled: bool = False,
    ) -> ResourceReservationReceipt:
        if type(cancelled) is not bool:
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)
        with self._lock:
            record = self._record(reservation_id)
            target = ReservationState.CANCELLED if cancelled else ReservationState.RELEASED
            if record.state is target:
                return _receipt(reservation_id, record, idempotent=True)
            self._require_active(record, expected_version, now_ms)
            record.state = target
            record.state_version += 1
            return _receipt(reservation_id, record, idempotent=False)

    def create_run_enforcer(
        self,
        reservation_id: str,
        terminate: Callable[[], object],
        *,
        expected_version: int,
        now_ms: int,
    ) -> PerRunResourceEnforcer:
        """Bind live enforcement to an active, versioned reservation."""
        with self._lock:
            record = self._record(reservation_id)
            self._require_active(record, expected_version, now_ms)
            return PerRunResourceEnforcer(record.reserved, terminate)

    def _record(self, reservation_id: str) -> _Reservation:
        if not _identifier(reservation_id):
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)
        try:
            return self._reservations[reservation_id]
        except KeyError as error:
            raise ResourceGovernorError(ResourceGovernorErrorCode.RESERVATION_UNKNOWN) from error

    def _require_active(self, record: _Reservation, expected_version: int, now_ms: int) -> None:
        if (
            type(expected_version) is not int
            or type(now_ms) is not int
            or now_ms < 0
            or record.state_version != expected_version
        ):
            raise ResourceGovernorError(ResourceGovernorErrorCode.CONFLICT)
        if (
            record.state is not ReservationState.RESERVED
            or now_ms < record.request.now_ms
            or now_ms >= record.request.lease_expires_at_ms
        ):
            raise ResourceGovernorError(ResourceGovernorErrorCode.RESERVATION_TERMINAL)

    def _expire(self, now_ms: int) -> None:
        for record in self._reservations.values():
            if (
                record.state is ReservationState.RESERVED
                and now_ms >= record.request.lease_expires_at_ms
            ):
                record.state = ReservationState.RELEASED
                record.state_version += 1

    def _window_events(
        self,
        tenant_id: str,
        now_ms: int,
        limits: TenantResourceLimits,
    ) -> list[tuple[int, int, int]]:
        lower = now_ms - limits.admission_window_ms
        events = [item for item in self._admissions.get(tenant_id, []) if item[0] > lower]
        self._admissions[tenant_id] = events
        return events


class PerRunResourceEnforcer:
    """Enforce a reservation's ceilings while a run is still executing.

    The execution owner supplies cumulative usage snapshots and a callback that
    terminates the active work. The callback is invoked exactly once, on the
    first snapshot that crosses any reserved per-run ceiling.
    """

    __slots__ = ("_lock", "_reserved", "_stopped", "_terminate")

    def __init__(
        self,
        reserved: ResourceUsage,
        terminate: Callable[[], object],
    ) -> None:
        if type(reserved) is not ResourceUsage or not callable(terminate):
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)
        self._lock = RLock()
        self._reserved = reserved
        self._terminate = terminate
        self._stopped = False

    @property
    def stopped(self) -> bool:
        with self._lock:
            return self._stopped

    def observe(self, usage: ResourceUsage) -> None:
        """Accept a cumulative snapshot or terminate and reject the run."""
        if type(usage) is not ResourceUsage:
            raise ResourceGovernorError(ResourceGovernorErrorCode.INVALID_REQUEST)
        with self._lock:
            if self._stopped:
                raise ResourceGovernorError(ResourceGovernorErrorCode.QUOTA_EXCEEDED)
            exceeded = (
                usage.tokens > self._reserved.tokens
                or usage.cost_microunits > self._reserved.cost_microunits
                or usage.cpu_ms > self._reserved.cpu_ms
                or usage.peak_memory_bytes > self._reserved.peak_memory_bytes
                or usage.wall_ms > self._reserved.wall_ms
            )
            if not exceeded:
                return
            self._stopped = True
        # A failed cancellation request must not turn a limit breach into
        # an accepted snapshot or leak the callback's error to callers.
        with suppress(Exception):
            self._terminate()
        raise ResourceGovernorError(ResourceGovernorErrorCode.QUOTA_EXCEEDED)


def _request_hash(request: ResourceReservationRequest) -> str:
    return _hash(
        {
            "execution_identity_hash": request.execution_identity_hash,
            "lease_expires_at_ms": request.lease_expires_at_ms,
            "now_ms": request.now_ms,
            "profile_sha256": request.profile_sha256,
            "repository_id": request.repository_id,
            "requested_cost_microunits": request.requested_cost_microunits,
            "requested_cpu_ms": request.requested_cpu_ms,
            "requested_memory_bytes": request.requested_memory_bytes,
            "requested_tokens": request.requested_tokens,
            "requested_wall_ms": request.requested_wall_ms,
            "run_id": request.run_id,
            "tenant_id": request.tenant_id,
        }
    )


def _hash(material: dict[str, object]) -> str:
    payload = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(_HASH_DOMAIN + payload).hexdigest()


def _receipt(
    reservation_id: str,
    record: _Reservation,
    *,
    idempotent: bool,
) -> ResourceReservationReceipt:
    request = record.request
    return ResourceReservationReceipt(
        reservation_id=reservation_id,
        tenant_id=request.tenant_id,
        repository_id=request.repository_id,
        run_id=request.run_id,
        execution_identity_hash=request.execution_identity_hash,
        profile_sha256=request.profile_sha256,
        state=record.state,
        reserved=record.reserved,
        actual=record.actual,
        lease_expires_at_ms=request.lease_expires_at_ms,
        state_version=record.state_version,
        idempotent=idempotent,
    )


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


__all__ = [
    "PerRunResourceEnforcer",
    "ReservationState",
    "ResourceGovernorError",
    "ResourceGovernorErrorCode",
    "ResourceReservationReceipt",
    "ResourceReservationRequest",
    "ResourceUsage",
    "TenantResourceGovernor",
    "TenantResourceLimits",
]
