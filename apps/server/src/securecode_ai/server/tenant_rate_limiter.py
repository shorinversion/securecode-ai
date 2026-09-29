"""Bounded process-local per-tenant token bucket for authenticated requests."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Final, Protocol, TypeGuard

_TOKEN_UNIT: Final = 1_000_000_000
_MAX_TENANTS: Final = 100_000
_MAX_CAPACITY: Final = 10_000
_MAX_REFILL_PER_SECOND: Final = 10_000
_MAX_CLOCK_NS: Final = (1 << 63) - 1
_MAX_TENANT_ID_LENGTH: Final = 128


class RateLimitErrorCode(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    STATE_FULL = "STATE_FULL"
    CLOCK_INVALID = "CLOCK_INVALID"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"


class RateLimitError(RuntimeError):
    """A safe, non-echoing rate limiter failure."""

    __slots__ = ("code",)

    def __init__(self, code: RateLimitErrorCode) -> None:
        if type(code) is not RateLimitErrorCode:
            raise TypeError("rate limit error code is invalid")
        self.code = code
        super().__init__("tenant rate limiter unavailable")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int


class TenantRateLimiter(Protocol):
    """Admission port shared by process-local and durable implementations."""

    def allow(self, *, tenant_id: object, now_ns: object = None) -> RateLimitDecision: ...


@dataclass(slots=True)
class _Bucket:
    tokens: int
    updated_ns: int
    last_seen_ns: int


class TenantTokenBucketRateLimiter:
    """Atomically charge requests against a fixed, bounded per-tenant bucket."""

    __slots__ = (
        "_buckets",
        "_capacity",
        "_idle_timeout_ns",
        "_last_now_ns",
        "_lock",
        "_max_tenants",
        "_refill_per_second",
    )

    def __init__(
        self,
        *,
        capacity: int = 120,
        refill_per_second: int = 2,
        max_tenants: int = 10_000,
        idle_timeout_seconds: int = 300,
    ) -> None:
        if (
            type(capacity) is not int
            or not 1 <= capacity <= _MAX_CAPACITY
            or type(refill_per_second) is not int
            or not 1 <= refill_per_second <= _MAX_REFILL_PER_SECOND
            or type(max_tenants) is not int
            or not 1 <= max_tenants <= _MAX_TENANTS
            or type(idle_timeout_seconds) is not int
            or not 1 <= idle_timeout_seconds <= 86_400
        ):
            raise RateLimitError(RateLimitErrorCode.INVALID_INPUT)
        self._capacity = capacity * _TOKEN_UNIT
        self._refill_per_second = refill_per_second
        self._max_tenants = max_tenants
        self._idle_timeout_ns = idle_timeout_seconds * _TOKEN_UNIT
        self._buckets: dict[str, _Bucket] = {}
        self._last_now_ns: int | None = None
        self._lock = Lock()

    @property
    def tracked_tenants(self) -> int:
        with self._lock:
            return len(self._buckets)

    def allow(
        self,
        *,
        tenant_id: object,
        now_ns: object = None,
    ) -> RateLimitDecision:
        if not _valid_tenant_id(tenant_id):
            raise RateLimitError(RateLimitErrorCode.INVALID_INPUT)

        with self._lock:
            if now_ns is None:
                current_ns = time.monotonic_ns()
            elif type(now_ns) is int:
                current_ns = now_ns
            else:
                raise RateLimitError(RateLimitErrorCode.INVALID_INPUT)
            if not 0 <= current_ns <= _MAX_CLOCK_NS:
                raise RateLimitError(RateLimitErrorCode.CLOCK_INVALID)
            if self._last_now_ns is not None and current_ns < self._last_now_ns:
                raise RateLimitError(RateLimitErrorCode.CLOCK_INVALID)
            self._last_now_ns = current_ns
            bucket = self._buckets.get(tenant_id)
            if bucket is None:
                if len(self._buckets) >= self._max_tenants:
                    self._discard_idle(current_ns)
                if len(self._buckets) >= self._max_tenants:
                    raise RateLimitError(RateLimitErrorCode.STATE_FULL)
                bucket = _Bucket(
                    tokens=self._capacity,
                    updated_ns=current_ns,
                    last_seen_ns=current_ns,
                )
                self._buckets[tenant_id] = bucket

            elapsed_ns = current_ns - bucket.updated_ns
            replenished = min(
                self._capacity,
                bucket.tokens + elapsed_ns * self._refill_per_second,
            )
            bucket.updated_ns = current_ns
            bucket.last_seen_ns = current_ns
            if replenished >= _TOKEN_UNIT:
                bucket.tokens = replenished - _TOKEN_UNIT
                return RateLimitDecision(True, 0)

            bucket.tokens = replenished
            deficit = _TOKEN_UNIT - replenished
            retry_numerator = deficit
            retry_denominator = self._refill_per_second * _TOKEN_UNIT
            retry_after = max(
                1,
                (retry_numerator + retry_denominator - 1) // retry_denominator,
            )
            return RateLimitDecision(False, retry_after)

    def _discard_idle(self, now_ns: int) -> None:
        expired = tuple(
            tenant_id
            for tenant_id, bucket in self._buckets.items()
            if now_ns - bucket.last_seen_ns >= self._idle_timeout_ns
        )
        for tenant_id in expired:
            del self._buckets[tenant_id]


def _valid_tenant_id(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and 1 <= len(value) <= _MAX_TENANT_ID_LENGTH
        and value[0].isascii()
        and value[0].isalnum()
        and all(
            character.isascii() and (character.isalnum() or character in "._:-")
            for character in value
        )
    )


__all__ = [
    "RateLimitDecision",
    "RateLimitError",
    "RateLimitErrorCode",
    "TenantRateLimiter",
    "TenantTokenBucketRateLimiter",
]
