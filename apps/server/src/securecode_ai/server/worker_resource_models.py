"""Source-free values and ports for worker terminal resource accounting."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from securecode_ai.core.resource_governor import (
    ReservationState,
    ResourceReservationReceipt,
    ResourceUsage,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_INTEGER: Final = 9_223_372_036_854_775_807
USAGE_KEYS: Final = frozenset(
    {"tokens", "cost_microunits", "cpu_ms", "peak_memory_bytes", "wall_ms"}
)
COMMIT_OUTCOMES: Final = frozenset({"PASS", "FAIL", "INDETERMINATE"})
RELEASE_OUTCOMES: Final = frozenset({"CANCELLED", "SUPERSEDED"})
TERMINAL_OUTCOMES: Final = COMMIT_OUTCOMES | RELEASE_OUTCOMES


class WorkerResourceErrorCode(StrEnum):
    INVALID_USAGE = "WORKER_RESOURCE_USAGE_INVALID"
    BINDING_UNAVAILABLE = "WORKER_RESOURCE_BINDING_UNAVAILABLE"
    ACCOUNTING_UNAVAILABLE = "WORKER_RESOURCE_ACCOUNTING_UNAVAILABLE"


class WorkerResourceError(Exception):
    """Safe accounting failure that never includes worker or source content."""

    __slots__ = ("code", "status")

    def __init__(self, code: WorkerResourceErrorCode, status: int) -> None:
        if type(code) is not WorkerResourceErrorCode or type(status) is not int:
            raise TypeError("worker resource error is invalid")
        self.code = code
        self.status = status
        super().__init__(safe_message(code))
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class WorkerReservationBinding:
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    profile_sha256: str
    reservation_id: str
    reservation_version: int
    reserved: ResourceUsage
    state: ReservationState
    actual: ResourceUsage | None

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _ID.fullmatch(value) is None
                for value in (
                    self.tenant_id,
                    self.repository_id,
                    self.run_id,
                    self.reservation_id,
                )
            )
            or type(self.execution_identity_hash) is not str
            or _SHA256.fullmatch(self.execution_identity_hash) is None
            or type(self.profile_sha256) is not str
            or _SHA256.fullmatch(self.profile_sha256) is None
            or type(self.reservation_version) is not int
            or self.reservation_version < 1
            or type(self.reserved) is not ResourceUsage
            or type(self.state) is not ReservationState
            or (self.actual is not None and type(self.actual) is not ResourceUsage)
            or (
                self.state is ReservationState.RESERVED
                and self.actual is not None
            )
            or (
                self.state is ReservationState.COMMITTED
                and self.actual is None
            )
            or (
                self.state in {ReservationState.RELEASED, ReservationState.CANCELLED}
                and self.actual is not None
            )
            or (
                self.actual is not None
                and any(
                    actual > reserved
                    for actual, reserved in zip(
                        (
                            self.actual.tokens,
                            self.actual.cost_microunits,
                            self.actual.cpu_ms,
                            self.actual.peak_memory_bytes,
                            self.actual.wall_ms,
                        ),
                        (
                            self.reserved.tokens,
                            self.reserved.cost_microunits,
                            self.reserved.cpu_ms,
                            self.reserved.peak_memory_bytes,
                            self.reserved.wall_ms,
                        ),
                        strict=True,
                    )
                )
            )
        ):
            raise WorkerResourceError(WorkerResourceErrorCode.BINDING_UNAVAILABLE, 503)


@dataclass(frozen=True, slots=True)
class WorkerResourceSettlement:
    binding: WorkerReservationBinding
    outcome: str
    usage: ResourceUsage | None

    def __post_init__(self) -> None:
        if (
            type(self.binding) is not WorkerReservationBinding
            or type(self.outcome) is not str
            or self.outcome not in TERMINAL_OUTCOMES
            or (self.outcome in COMMIT_OUTCOMES and type(self.usage) is not ResourceUsage)
            or (
                self.usage is not None
                and any(
                    actual > reserved
                    for actual, reserved in zip(
                        (
                            self.usage.tokens,
                            self.usage.cost_microunits,
                            self.usage.cpu_ms,
                            self.usage.peak_memory_bytes,
                            self.usage.wall_ms,
                        ),
                        (
                            self.binding.reserved.tokens,
                            self.binding.reserved.cost_microunits,
                            self.binding.reserved.cpu_ms,
                            self.binding.reserved.peak_memory_bytes,
                            self.binding.reserved.wall_ms,
                        ),
                        strict=True,
                    )
                )
            )
            or (
                self.binding.actual is not None
                and self.usage is not None
                and self.binding.actual != self.usage
            )
        ):
            raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)


class WorkerReservationBindingStore(Protocol):
    def load(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
    ) -> WorkerReservationBinding: ...


class WorkerResourcePort(Protocol):
    def commit(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        reservation_id: str,
        usage: ResourceUsage,
        expected_version: int,
        now_ms: int,
    ) -> ResourceReservationReceipt: ...

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


WorkerResourceClock = Callable[[], int]


def resolve_usage(
    value: object,
    *,
    supplied: bool,
    reserved: ResourceUsage,
    recorded: ResourceUsage | None,
) -> ResourceUsage:
    """Validate worker counters or charge the stable reserved upper bounds."""

    if not supplied:
        return recorded if recorded is not None else reserved
    if not isinstance(value, Mapping) or set(value) != USAGE_KEYS:
        raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
    try:
        usage = ResourceUsage(
            tokens=_quantity(value, "tokens"),
            cost_microunits=_quantity(value, "cost_microunits"),
            cpu_ms=_quantity(value, "cpu_ms"),
            peak_memory_bytes=_quantity(value, "peak_memory_bytes"),
            wall_ms=_quantity(value, "wall_ms"),
        )
    except WorkerResourceError:
        raise
    except Exception:
        raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409) from None
    if (
        usage.tokens > reserved.tokens
        or usage.cost_microunits > reserved.cost_microunits
        or usage.cpu_ms > reserved.cpu_ms
        or usage.peak_memory_bytes > reserved.peak_memory_bytes
        or usage.wall_ms > reserved.wall_ms
        or (recorded is not None and usage != recorded)
    ):
        raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
    return usage


def _quantity(value: Mapping[object, object], key: str) -> int:
    quantity = value[key]
    if type(quantity) is not int or not 0 <= quantity <= _MAX_INTEGER:
        raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
    return quantity


def safe_message(code: WorkerResourceErrorCode) -> str:
    return {
        WorkerResourceErrorCode.INVALID_USAGE: "worker resource usage is invalid",
        WorkerResourceErrorCode.BINDING_UNAVAILABLE: ("worker resource reservation is unavailable"),
        WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE: (
            "worker resource accounting is unavailable"
        ),
    }[code]


__all__ = [
    "COMMIT_OUTCOMES",
    "RELEASE_OUTCOMES",
    "TERMINAL_OUTCOMES",
    "WorkerReservationBinding",
    "WorkerReservationBindingStore",
    "WorkerResourceClock",
    "WorkerResourceError",
    "WorkerResourceErrorCode",
    "WorkerResourcePort",
    "WorkerResourceSettlement",
    "resolve_usage",
    "safe_message",
]
