"""Bounded tenant/model spend budget port for remote provider calls."""

from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Protocol

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_MAX_WINDOW_MS = 86_400_000
_MAX_CALLS = 100_000
_MAX_TOKENS = 1_000_000_000
_MAX_COST_MICROUNITS = 1_000_000_000_000_000
_MAX_RATE_MICROUNITS_PER_MILLION = 1_000_000_000_000
_MAX_POLICIES = 256
_MAX_RECORDS = 65_536
_MAX_TOTAL_EVENTS = 100_000
_MICRO = 1_000_000


class RemoteProviderBudgetError(RuntimeError):
    __slots__ = ("code", "safe_message")

    def __init__(self, code: str) -> None:
        if code not in {"NOT_CONFIGURED", "LIMIT_EXCEEDED", "INVALID_STATE"}:
            code = "INVALID_STATE"
        self.code = code
        self.safe_message = "remote provider budget rejected the call"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class RemoteProviderCallContext:
    tenant_id: str
    request_id: str
    attempt: int
    max_input_tokens: int
    max_output_tokens: int

    def __post_init__(self) -> None:
        if (
            not _identifier(self.tenant_id)
            or not _identifier(self.request_id)
            or type(self.attempt) is not int
            or not 1 <= self.attempt <= 10
            or type(self.max_input_tokens) is not int
            or not 1 <= self.max_input_tokens <= _MAX_TOKENS
            or type(self.max_output_tokens) is not int
            or not 1 <= self.max_output_tokens <= _MAX_TOKENS
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")


@dataclass(frozen=True, slots=True)
class RemoteProviderSpendRequest:
    tenant_id: str
    model_id: str
    request_id: str
    attempt: int
    max_input_tokens: int
    max_output_tokens: int

    def __post_init__(self) -> None:
        if (
            not _identifier(self.tenant_id)
            or not _model_id(self.model_id)
            or not _identifier(self.request_id)
            or type(self.attempt) is not int
            or not 1 <= self.attempt <= 10
            or type(self.max_input_tokens) is not int
            or not 1 <= self.max_input_tokens <= _MAX_TOKENS
            or type(self.max_output_tokens) is not int
            or not 1 <= self.max_output_tokens <= _MAX_TOKENS
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")


@dataclass(frozen=True, slots=True)
class RemoteProviderSpendUsage:
    input_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or not 0 <= value <= _MAX_TOKENS
            for value in (self.input_tokens, self.output_tokens)
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")


@dataclass(frozen=True, slots=True, repr=False)
class RemoteProviderSpendLease:
    lease_id: str
    tenant_id: str
    model_id: str
    request_id: str
    attempt: int
    max_input_tokens: int
    max_output_tokens: int
    reserved_cost_microunits: int

    def __repr__(self) -> str:
        return "RemoteProviderSpendLease(<redacted>)"


class RemoteProviderBudgetPort(Protocol):
    """Transactional admission and settlement boundary for one remote send."""

    def reserve(self, request: RemoteProviderSpendRequest) -> RemoteProviderSpendLease: ...

    def settle(
        self, lease: RemoteProviderSpendLease, usage: RemoteProviderSpendUsage
    ) -> None: ...

    def charge_maximum(self, lease: RemoteProviderSpendLease) -> None: ...

    def release(self, lease: RemoteProviderSpendLease) -> None: ...


@dataclass(frozen=True, slots=True)
class RemoteProviderSpendPolicy:
    tenant_id: str
    model_id: str
    window_ms: int
    max_calls_per_window: int
    max_concurrent_calls: int
    max_tokens_per_window: int
    max_cost_microunits_per_window: int
    input_cost_microunits_per_million_tokens: int
    output_cost_microunits_per_million_tokens: int

    def __post_init__(self) -> None:
        if (
            not _identifier(self.tenant_id)
            or not _model_id(self.model_id)
            or type(self.window_ms) is not int
            or not 1 <= self.window_ms <= _MAX_WINDOW_MS
            or type(self.max_calls_per_window) is not int
            or not 1 <= self.max_calls_per_window <= _MAX_CALLS
            or type(self.max_concurrent_calls) is not int
            or not 1 <= self.max_concurrent_calls <= min(1024, self.max_calls_per_window)
            or type(self.max_tokens_per_window) is not int
            or not 1 <= self.max_tokens_per_window <= _MAX_TOKENS
            or type(self.max_cost_microunits_per_window) is not int
            or not 1 <= self.max_cost_microunits_per_window <= _MAX_COST_MICROUNITS
            or type(self.input_cost_microunits_per_million_tokens) is not int
            or not 0 <= self.input_cost_microunits_per_million_tokens
            <= _MAX_RATE_MICROUNITS_PER_MILLION
            or type(self.output_cost_microunits_per_million_tokens) is not int
            or not 0 <= self.output_cost_microunits_per_million_tokens
            <= _MAX_RATE_MICROUNITS_PER_MILLION
            or self.input_cost_microunits_per_million_tokens
            + self.output_cost_microunits_per_million_tokens
            == 0
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")


@dataclass(slots=True)
class _Event:
    lease_id: str
    request_key: tuple[str, str, str, int]
    timestamp_ms: int
    tokens: int
    cost_microunits: int
    reserved: bool


class InMemoryRemoteProviderBudget:
    """Bounded process-local guard; durable deployments can implement the port."""

    __slots__ = (
        "_event_count",
        "_events",
        "_leases",
        "_lock",
        "_policies",
        "_request_leases",
    )

    def __init__(self, policies: tuple[RemoteProviderSpendPolicy, ...]) -> None:
        if type(policies) is not tuple or not policies or len(policies) > _MAX_POLICIES:
            raise RemoteProviderBudgetError("INVALID_STATE")
        configured: dict[tuple[str, str], RemoteProviderSpendPolicy] = {}
        for policy in policies:
            if type(policy) is not RemoteProviderSpendPolicy:
                raise RemoteProviderBudgetError("INVALID_STATE")
            key = (policy.tenant_id, policy.model_id)
            if key in configured:
                raise RemoteProviderBudgetError("INVALID_STATE")
            configured[key] = policy
        self._lock = threading.RLock()
        self._policies = configured
        self._events: dict[tuple[str, str], list[_Event]] = {key: [] for key in configured}
        self._leases: dict[str, _Event] = {}
        self._request_leases: dict[tuple[str, str, str, int], str] = {}
        self._event_count = 0

    def reserve(self, request: RemoteProviderSpendRequest) -> RemoteProviderSpendLease:
        if type(request) is not RemoteProviderSpendRequest:
            raise RemoteProviderBudgetError("INVALID_STATE")
        key = (request.tenant_id, request.model_id)
        request_key = (request.tenant_id, request.model_id, request.request_id, request.attempt)
        now_ms = time.monotonic_ns() // 1_000_000
        with self._lock:
            policy = self._policies.get(key)
            events = self._events.get(key)
            if policy is None or events is None:
                raise RemoteProviderBudgetError("NOT_CONFIGURED")
            self._prune(key, now_ms, policy)
            events = self._events[key]
            if request_key in self._request_leases or len(self._leases) >= _MAX_RECORDS:
                raise RemoteProviderBudgetError("INVALID_STATE")
            if self._event_count >= _MAX_TOTAL_EVENTS:
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
            active = sum(event.reserved for event in events)
            if active >= policy.max_concurrent_calls:
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
            reserved_tokens = request.max_input_tokens + request.max_output_tokens
            reserved_cost = _cost_microunits(
                request.max_input_tokens,
                policy.input_cost_microunits_per_million_tokens,
            ) + _cost_microunits(
                request.max_output_tokens,
                policy.output_cost_microunits_per_million_tokens,
            )
            if (
                len(events) >= policy.max_calls_per_window
                or sum(event.tokens for event in events) + reserved_tokens
                > policy.max_tokens_per_window
                or sum(event.cost_microunits for event in events) + reserved_cost
                > policy.max_cost_microunits_per_window
            ):
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")
            lease_id = secrets.token_hex(24)
            event = _Event(
                lease_id=lease_id,
                request_key=request_key,
                timestamp_ms=now_ms,
                tokens=reserved_tokens,
                cost_microunits=reserved_cost,
                reserved=True,
            )
            events.append(event)
            self._event_count += 1
            self._leases[lease_id] = event
            self._request_leases[request_key] = lease_id
            return RemoteProviderSpendLease(
                lease_id=lease_id,
                tenant_id=request.tenant_id,
                model_id=request.model_id,
                request_id=request.request_id,
                attempt=request.attempt,
                max_input_tokens=request.max_input_tokens,
                max_output_tokens=request.max_output_tokens,
                reserved_cost_microunits=reserved_cost,
            )

    def settle(
        self, lease: RemoteProviderSpendLease, usage: RemoteProviderSpendUsage
    ) -> None:
        if type(usage) is not RemoteProviderSpendUsage:
            raise RemoteProviderBudgetError("INVALID_STATE")
        with self._lock:
            event, policy = self._active_lease(lease)
            actual_tokens = usage.input_tokens + usage.output_tokens
            actual_cost = _cost_microunits(
                usage.input_tokens, policy.input_cost_microunits_per_million_tokens
            ) + _cost_microunits(
                usage.output_tokens, policy.output_cost_microunits_per_million_tokens
            )
            event.tokens = actual_tokens
            event.cost_microunits = actual_cost
            event.reserved = False
            self._leases.pop(event.lease_id, None)
            if (
                usage.input_tokens > lease.max_input_tokens
                or usage.output_tokens > lease.max_output_tokens
                or actual_cost > lease.reserved_cost_microunits
            ):
                raise RemoteProviderBudgetError("LIMIT_EXCEEDED")

    def charge_maximum(self, lease: RemoteProviderSpendLease) -> None:
        with self._lock:
            event, _ = self._active_lease(lease)
            self._settle_maximum(event)

    def release(self, lease: RemoteProviderSpendLease) -> None:
        with self._lock:
            event, _ = self._active_lease(lease)
            events = self._events[(lease.tenant_id, lease.model_id)]
            events.remove(event)
            self._event_count -= 1
            self._leases.pop(event.lease_id, None)
            self._request_leases.pop(event.request_key, None)

    def _active_lease(
        self, lease: RemoteProviderSpendLease
    ) -> tuple[_Event, RemoteProviderSpendPolicy]:
        if type(lease) is not RemoteProviderSpendLease:
            raise RemoteProviderBudgetError("INVALID_STATE")
        event = self._leases.get(lease.lease_id)
        policy = self._policies.get((lease.tenant_id, lease.model_id))
        if (
            event is None
            or policy is None
            or event.request_key
            != (lease.tenant_id, lease.model_id, lease.request_id, lease.attempt)
            or event.tokens != lease.max_input_tokens + lease.max_output_tokens
            or event.cost_microunits != lease.reserved_cost_microunits
            or not event.reserved
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")
        return event, policy

    def _settle_maximum(self, event: _Event) -> None:
        event.reserved = False
        self._leases.pop(event.lease_id, None)

    def _prune(
        self, key: tuple[str, str], now_ms: int, policy: RemoteProviderSpendPolicy
    ) -> None:
        threshold = now_ms - policy.window_ms
        old_events = tuple(event for event in self._events[key] if event.timestamp_ms <= threshold)
        if not old_events:
            return
        retained = [event for event in self._events[key] if event.timestamp_ms > threshold]
        self._events[key] = retained
        self._event_count -= len(old_events)
        for event in old_events:
            if event.reserved:
                # Expired in-flight calls remain charged at their reserved maximum.
                event.reserved = False
                self._leases.pop(event.lease_id, None)
            self._request_leases.pop(event.request_key, None)


def _cost_microunits(tokens: int, rate_per_million: int) -> int:
    if tokens == 0 or rate_per_million == 0:
        return 0
    return (tokens * rate_per_million + _MICRO - 1) // _MICRO


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _model_id(value: object) -> bool:
    return type(value) is str and _MODEL.fullmatch(value) is not None


__all__ = [
    "InMemoryRemoteProviderBudget",
    "RemoteProviderBudgetError",
    "RemoteProviderBudgetPort",
    "RemoteProviderCallContext",
    "RemoteProviderSpendLease",
    "RemoteProviderSpendPolicy",
    "RemoteProviderSpendRequest",
    "RemoteProviderSpendUsage",
]
