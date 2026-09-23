"""P8.7 bounded per-tenant request quota and spend ceiling.

One tenant may not exceed a request rate or a spend ceiling inside a sliding
window. The ledger is process-local and bounded: it keeps at most one entry per
tenant and a hard cap on tracked tenants, so abuse degrades to a refusal instead
of unbounded memory. Decisions are metadata-only — a quota never inspects a body.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Final, Protocol, TypeGuard

MAX_TENANTS: Final = 10_000
MAX_WINDOW_SECONDS: Final = 86_400
MAX_REQUESTS_PER_WINDOW: Final = 1_000_000
MAX_SPEND_MICROUNITS: Final = 1_000_000_000_000


class QuotaErrorCode(StrEnum):
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    STORE_UNAVAILABLE = "STORE_UNAVAILABLE"


class QuotaError(ValueError):
    """Bounded quota configuration failure."""

    __slots__ = ("code",)

    def __init__(self, code: QuotaErrorCode) -> None:
        self.code = code
        super().__init__("quota configuration is invalid")


@dataclass(frozen=True, slots=True)
class QuotaPolicy:
    """Declared ceiling for one tenant inside one window."""

    tenant_id: str
    window_seconds: int
    max_requests: int
    max_spend_microunits: int = 0

    def __post_init__(self) -> None:
        if (
            not _valid_tenant_id(self.tenant_id)
            or type(self.window_seconds) is not int
            or not 1 <= self.window_seconds <= MAX_WINDOW_SECONDS
            or type(self.max_requests) is not int
            or not 1 <= self.max_requests <= MAX_REQUESTS_PER_WINDOW
            or type(self.max_spend_microunits) is not int
            or not 0 <= self.max_spend_microunits <= MAX_SPEND_MICROUNITS
        ):
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)


@dataclass(frozen=True, slots=True)
class QuotaDecision:
    """Outcome of one admission check; `allowed` false carries the retry hint."""

    allowed: bool
    remaining_requests: int
    remaining_spend_microunits: int
    retry_after_seconds: int

    def document(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "remaining_requests": self.remaining_requests,
            "remaining_spend_microunits": self.remaining_spend_microunits,
            "retry_after_seconds": self.retry_after_seconds,
        }


class RequestQuota(Protocol):
    def check(
        self,
        *,
        tenant_id: object,
        now_ms: object,
        cost_microunits: int = 0,
    ) -> QuotaDecision: ...


@dataclass(slots=True)
class _Window:
    started_ms: int
    requests: int
    spend_microunits: int


class QuotaLedger:
    """Sliding-window counters for a bounded set of tenants."""

    __slots__ = ("_lock", "_policies", "_windows")

    def __init__(self, policies: tuple[QuotaPolicy, ...] = ()) -> None:
        if type(policies) is not tuple or any(type(item) is not QuotaPolicy for item in policies):
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)
        if len({policy.tenant_id for policy in policies}) != len(policies):
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)
        if len(policies) > MAX_TENANTS:
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)
        self._policies = {policy.tenant_id: policy for policy in policies}
        self._windows: dict[str, _Window] = {}
        self._lock = Lock()

    @property
    def tenants(self) -> int:
        return len(self._policies)

    def check(
        self,
        *,
        tenant_id: object,
        now_ms: object,
        cost_microunits: int = 0,
    ) -> QuotaDecision:
        """Charge one request against the tenant's window, or refuse it.

        A tenant without a declared policy is admitted: this ledger is a ceiling
        for opted-in tenants, never an implicit global limit.
        """

        if (
            not _valid_tenant_id(tenant_id)
            or type(now_ms) is not int
            or now_ms < 0
            or type(cost_microunits) is not int
            or not 0 <= cost_microunits <= MAX_SPEND_MICROUNITS
        ):
            raise QuotaError(QuotaErrorCode.INVALID_CONFIGURATION)
        policy = self._policies.get(tenant_id)
        if policy is None:
            return QuotaDecision(True, MAX_REQUESTS_PER_WINDOW, MAX_SPEND_MICROUNITS, 0)
        window_ms = policy.window_seconds * 1000
        with self._lock:
            window = self._windows.get(tenant_id)
            if window is None or now_ms - window.started_ms >= window_ms:
                window = _Window(started_ms=now_ms, requests=0, spend_microunits=0)
                self._windows[tenant_id] = window
            if (
                window.requests + 1 > policy.max_requests
                or window.spend_microunits + cost_microunits > policy.max_spend_microunits
            ):
                retry_ms = window.started_ms + window_ms - now_ms
                retry_seconds = max(1, (retry_ms + 999) // 1000)
                return QuotaDecision(
                    False,
                    max(0, policy.max_requests - window.requests),
                    max(0, policy.max_spend_microunits - window.spend_microunits),
                    retry_seconds,
                )
            window.requests += 1
            window.spend_microunits += cost_microunits
            return QuotaDecision(
                True,
                policy.max_requests - window.requests,
                max(0, policy.max_spend_microunits - window.spend_microunits),
                0,
            )


def _valid_tenant_id(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and value[0].isascii()
        and value[0].isalnum()
        and all(
            character.isascii() and (character.isalnum() or character in "._:-")
            for character in value
        )
    )


__all__ = [
    "MAX_REQUESTS_PER_WINDOW",
    "MAX_SPEND_MICROUNITS",
    "MAX_TENANTS",
    "MAX_WINDOW_SECONDS",
    "QuotaDecision",
    "QuotaError",
    "QuotaErrorCode",
    "QuotaLedger",
    "QuotaPolicy",
    "RequestQuota",
]
