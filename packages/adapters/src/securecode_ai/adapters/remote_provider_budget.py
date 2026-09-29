"""Bounded tenant/model spend budget port for remote provider calls."""

from __future__ import annotations

import hashlib
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
_MAX_INPUT_TOKEN_UPPER_BOUND = _MAX_TOKENS * 2
# A configured rolling-window ceiling is intentionally lower than the maximum
# representable observed charge.  A provider may return usage above the
# admitted request maximum; that call must be rejected while its real charge
# remains representable in the settlement receipt and worker telemetry.
_MAX_POLICY_COST_MICROUNITS = 1_000_000_000_000_000
_MAX_OBSERVED_COST_MICROUNITS = 2_000_000_000_000_000
_MAX_RATE_MICROUNITS_PER_MILLION = 1_000_000_000_000
_PRICING_VERSION = "v1"
_MAX_POLICIES = 256
_MAX_RECORDS = 65_536
_MAX_TOTAL_EVENTS = 100_000
_MAX_SLOT_TIMEOUT_MS = 86_400_000
_DEFAULT_SLOT_TIMEOUT_MS = 300_000
_MICRO = 1_000_000


class RemoteProviderBudgetError(RuntimeError):
    __slots__ = ("code", "cost_receipt", "safe_message")

    def __init__(
        self,
        code: str,
        *,
        cost_receipt: RemoteProviderCostReceipt | None = None,
    ) -> None:
        if code not in {"NOT_CONFIGURED", "LIMIT_EXCEEDED", "INVALID_STATE"}:
            code = "INVALID_STATE"
        self.code = code
        self.cost_receipt = cost_receipt
        self.safe_message = "remote provider budget rejected the call"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class RemoteProviderCallContext:
    run_id: str
    tenant_id: str
    request_id: str
    attempt: int
    max_input_tokens: int
    max_output_tokens: int
    input_token_upper_bound: int | None = None

    def __post_init__(self) -> None:
        if (
            not _identifier(self.run_id)
            or not _identifier(self.tenant_id)
            or not _identifier(self.request_id)
            or type(self.attempt) is not int
            or not 1 <= self.attempt <= 10
            or type(self.max_input_tokens) is not int
            or not 1 <= self.max_input_tokens <= _MAX_TOKENS
            or type(self.max_output_tokens) is not int
            or not 1 <= self.max_output_tokens <= _MAX_TOKENS
            or (
                self.input_token_upper_bound is not None
                and (
                    type(self.input_token_upper_bound) is not int
                    or not 1 <= self.input_token_upper_bound <= _MAX_INPUT_TOKEN_UPPER_BOUND
                )
            )
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")


@dataclass(frozen=True, slots=True)
class RemoteProviderSpendRequest:
    run_id: str
    tenant_id: str
    model_id: str
    request_id: str
    attempt: int
    max_input_tokens: int
    max_output_tokens: int
    slot_timeout_ms: int | None = None

    def __post_init__(self) -> None:
        if (
            not _identifier(self.run_id)
            or not _identifier(self.tenant_id)
            or not _model_id(self.model_id)
            or not _identifier(self.request_id)
            or type(self.attempt) is not int
            or not 1 <= self.attempt <= 10
            or type(self.max_input_tokens) is not int
            or not 1 <= self.max_input_tokens <= _MAX_TOKENS
            or type(self.max_output_tokens) is not int
            or not 1 <= self.max_output_tokens <= _MAX_TOKENS
            or (
                self.slot_timeout_ms is not None
                and (
                    type(self.slot_timeout_ms) is not int
                    or not 1 <= self.slot_timeout_ms <= _MAX_SLOT_TIMEOUT_MS
                )
            )
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
    run_id: str
    tenant_id: str
    model_id: str
    request_id: str
    attempt: int
    max_input_tokens: int
    max_output_tokens: int
    reserved_cost_microunits: int

    def __repr__(self) -> str:
        return "RemoteProviderSpendLease(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class RemoteProviderCostReceipt:
    """Source-free settlement proof for one admitted remote call."""

    run_id: str
    tenant_id: str
    model_id: str
    request_id: str
    attempt: int
    cost_microunits: int
    maximum_charged: bool

    def __post_init__(self) -> None:
        if (
            not _identifier(self.run_id)
            or not _identifier(self.tenant_id)
            or not _model_id(self.model_id)
            or not _identifier(self.request_id)
            or type(self.attempt) is not int
            or not 1 <= self.attempt <= 10
            or type(self.cost_microunits) is not int
            or not 0 <= self.cost_microunits <= _MAX_OBSERVED_COST_MICROUNITS
            or type(self.maximum_charged) is not bool
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")

    def __repr__(self) -> str:
        return "RemoteProviderCostReceipt(<redacted>)"


class RemoteProviderBudgetPort(Protocol):
    """Transactional admission and settlement boundary for one remote send."""

    def reserve(self, request: RemoteProviderSpendRequest) -> RemoteProviderSpendLease: ...

    def settle(
        self, lease: RemoteProviderSpendLease, usage: RemoteProviderSpendUsage
    ) -> RemoteProviderCostReceipt: ...

    def charge_maximum(self, lease: RemoteProviderSpendLease) -> RemoteProviderCostReceipt:
        """Commit the conservative maximum charge, idempotently for one lease."""
        ...

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
            or not 1 <= self.max_cost_microunits_per_window <= _MAX_POLICY_COST_MICROUNITS
            or type(self.input_cost_microunits_per_million_tokens) is not int
            or not 0
            <= self.input_cost_microunits_per_million_tokens
            <= _MAX_RATE_MICROUNITS_PER_MILLION
            or type(self.output_cost_microunits_per_million_tokens) is not int
            or not 0
            <= self.output_cost_microunits_per_million_tokens
            <= _MAX_RATE_MICROUNITS_PER_MILLION
            or self.input_cost_microunits_per_million_tokens
            + self.output_cost_microunits_per_million_tokens
            == 0
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")

    @property
    def pricing_pin(self) -> str:
        """Return the canonical identity of this tenant/model rate card."""

        return remote_provider_pricing_pin(
            tenant_id=self.tenant_id,
            model_id=self.model_id,
            input_cost_microunits_per_million_tokens=self.input_cost_microunits_per_million_tokens,
            output_cost_microunits_per_million_tokens=self.output_cost_microunits_per_million_tokens,
            pricing_version=self.pricing_version,
        )

    @property
    def pricing_version(self) -> str:
        return _PRICING_VERSION


def remote_provider_pricing_pin(
    *,
    tenant_id: str,
    model_id: str,
    input_cost_microunits_per_million_tokens: int,
    output_cost_microunits_per_million_tokens: int,
    pricing_version: str,
) -> str:
    if (
        not _identifier(tenant_id)
        or not _model_id(model_id)
        or pricing_version != _PRICING_VERSION
        or type(input_cost_microunits_per_million_tokens) is not int
        or not 0 <= input_cost_microunits_per_million_tokens <= _MAX_RATE_MICROUNITS_PER_MILLION
        or type(output_cost_microunits_per_million_tokens) is not int
        or not 0 <= output_cost_microunits_per_million_tokens <= _MAX_RATE_MICROUNITS_PER_MILLION
        or input_cost_microunits_per_million_tokens + output_cost_microunits_per_million_tokens == 0
    ):
        raise RemoteProviderBudgetError("INVALID_STATE")
    canonical = b"\x00".join(
        (
            f"securecode.remote-pricing.{pricing_version}".encode("ascii"),
            tenant_id.encode("ascii"),
            model_id.encode("ascii"),
            str(input_cost_microunits_per_million_tokens).encode("ascii"),
            str(output_cost_microunits_per_million_tokens).encode("ascii"),
        )
    )
    return hashlib.sha256(canonical).hexdigest()


@dataclass(slots=True)
class _Event:
    lease_id: str
    request_key: tuple[str, str, str, int]
    timestamp_ms: int
    tokens: int
    cost_microunits: int
    reserved: bool
    slot_active: bool
    slot_expires_at_ms: int
    replay_blocked: bool = False
    in_window: bool = True


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
        request_key = (
            request.tenant_id,
            request.model_id,
            request.request_id,
            request.attempt,
        )
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
            active = sum(
                event.slot_active for event in self._leases.values() if event.request_key[:2] == key
            )
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
                sum(event.in_window for event in events) >= policy.max_calls_per_window
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
                slot_active=True,
                slot_expires_at_ms=now_ms
                + (
                    request.slot_timeout_ms
                    if request.slot_timeout_ms is not None
                    else _DEFAULT_SLOT_TIMEOUT_MS
                ),
            )
            events.append(event)
            self._event_count += 1
            self._leases[lease_id] = event
            self._request_leases[request_key] = lease_id
            return RemoteProviderSpendLease(
                lease_id=lease_id,
                run_id=request.run_id,
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
    ) -> RemoteProviderCostReceipt:
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
            event.timestamp_ms = time.monotonic_ns() // 1_000_000
            event.in_window = True
            event.tokens = actual_tokens
            event.cost_microunits = actual_cost
            event.reserved = False
            event.slot_active = False
            event.slot_expires_at_ms = 0
            self._leases.pop(event.lease_id, None)
            if (
                usage.input_tokens > lease.max_input_tokens
                or usage.output_tokens > lease.max_output_tokens
                or actual_cost > lease.reserved_cost_microunits
            ):
                raise RemoteProviderBudgetError(
                    "LIMIT_EXCEEDED",
                    cost_receipt=_cost_receipt(lease, actual_cost, maximum_charged=False),
                )
            return _cost_receipt(lease, actual_cost, maximum_charged=False)

    def charge_maximum(self, lease: RemoteProviderSpendLease) -> RemoteProviderCostReceipt:
        with self._lock:
            event, _ = self._lease_event(lease)
            if event.reserved or event.slot_active:
                self._settle_maximum(event, replay_blocked=True)
            elif (
                event.tokens != lease.max_input_tokens + lease.max_output_tokens
                or event.cost_microunits != lease.reserved_cost_microunits
            ):
                raise RemoteProviderBudgetError("INVALID_STATE")
            return _cost_receipt(lease, event.cost_microunits, maximum_charged=True)

    def release(self, lease: RemoteProviderSpendLease) -> None:
        with self._lock:
            event, _ = self._active_lease(lease)
            events = self._events[(lease.tenant_id, lease.model_id)]
            try:
                events.remove(event)
            except ValueError:
                raise RemoteProviderBudgetError("INVALID_STATE") from None
            self._event_count -= 1
            self._leases.pop(event.lease_id, None)
            self._request_leases.pop(event.request_key, None)

    def _active_lease(
        self, lease: RemoteProviderSpendLease
    ) -> tuple[_Event, RemoteProviderSpendPolicy]:
        event, policy = self._lease_event(lease)
        if not event.reserved or not event.slot_active:
            raise RemoteProviderBudgetError("INVALID_STATE")
        return event, policy

    def _lease_event(
        self, lease: RemoteProviderSpendLease
    ) -> tuple[_Event, RemoteProviderSpendPolicy]:
        if type(lease) is not RemoteProviderSpendLease:
            raise RemoteProviderBudgetError("INVALID_STATE")
        event = self._leases.get(lease.lease_id)
        policy = self._policies.get((lease.tenant_id, lease.model_id))
        if event is None:
            event = next(
                (
                    candidate
                    for candidate in self._events.get((lease.tenant_id, lease.model_id), ())
                    if candidate.lease_id == lease.lease_id
                ),
                None,
            )
        if (
            event is None
            or policy is None
            or event.request_key
            != (
                lease.tenant_id,
                lease.model_id,
                lease.request_id,
                lease.attempt,
            )
            or event.tokens != lease.max_input_tokens + lease.max_output_tokens
            or event.cost_microunits != lease.reserved_cost_microunits
            or type(event.slot_active) is not bool
            or type(event.slot_expires_at_ms) is not int
            or event.slot_expires_at_ms < 0
            or type(event.replay_blocked) is not bool
            or (event.reserved and not event.slot_active)
        ):
            raise RemoteProviderBudgetError("INVALID_STATE")
        return event, policy

    def _settle_maximum(self, event: _Event, *, replay_blocked: bool = False) -> None:
        event.timestamp_ms = time.monotonic_ns() // 1_000_000
        event.in_window = True
        event.reserved = False
        event.slot_active = False
        event.slot_expires_at_ms = 0
        event.replay_blocked = replay_blocked
        self._leases.pop(event.lease_id, None)

    def _prune(self, key: tuple[str, str], now_ms: int, policy: RemoteProviderSpendPolicy) -> None:
        for event in self._events[key]:
            if event.slot_active and event.slot_expires_at_ms <= now_ms:
                self._settle_maximum(event, replay_blocked=True)
        threshold = now_ms - policy.window_ms
        old_events = tuple(event for event in self._events[key] if event.timestamp_ms <= threshold)
        if not old_events:
            return
        retained = [
            event
            for event in self._events[key]
            if (
                event.timestamp_ms > threshold
                or event.reserved
                or event.slot_active
                or event.replay_blocked
            )
        ]
        self._events[key] = retained
        removed_events = tuple(event for event in old_events if event not in retained)
        self._event_count -= len(removed_events)
        for event in removed_events:
            event.in_window = False
            self._request_leases.pop(event.request_key, None)


def _cost_microunits(tokens: int, rate_per_million: int) -> int:
    if tokens == 0 or rate_per_million == 0:
        return 0
    return (tokens * rate_per_million + _MICRO - 1) // _MICRO


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _model_id(value: object) -> bool:
    return type(value) is str and _MODEL.fullmatch(value) is not None


def _cost_receipt(
    lease: RemoteProviderSpendLease,
    cost_microunits: int,
    *,
    maximum_charged: bool,
) -> RemoteProviderCostReceipt:
    return RemoteProviderCostReceipt(
        run_id=lease.run_id,
        tenant_id=lease.tenant_id,
        model_id=lease.model_id,
        request_id=lease.request_id,
        attempt=lease.attempt,
        cost_microunits=cost_microunits,
        maximum_charged=maximum_charged,
    )


__all__ = [
    "InMemoryRemoteProviderBudget",
    "RemoteProviderBudgetError",
    "RemoteProviderBudgetPort",
    "RemoteProviderCallContext",
    "RemoteProviderCostReceipt",
    "RemoteProviderSpendLease",
    "RemoteProviderSpendPolicy",
    "RemoteProviderSpendRequest",
    "RemoteProviderSpendUsage",
    "remote_provider_pricing_pin",
]
