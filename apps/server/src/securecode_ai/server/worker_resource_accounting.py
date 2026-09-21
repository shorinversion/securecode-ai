"""Fail-closed terminal accounting wrapper for the connected worker queue."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from typing import cast

from securecode_ai.core.resource_governor import (
    ReservationState,
    ResourceGovernorError,
    ResourceReservationReceipt,
    ResourceUsage,
)

from .ports import (
    ControlPlaneService,
    ServiceRequest,
    ServiceResponse,
    ServiceUnavailableError,
)
from .worker_resource_models import (
    COMMIT_OUTCOMES,
    TERMINAL_OUTCOMES,
    WorkerReservationBinding,
    WorkerReservationBindingStore,
    WorkerResourceClock,
    WorkerResourceError,
    WorkerResourceErrorCode,
    WorkerResourcePort,
    WorkerResourceSettlement,
    resolve_usage,
    safe_message,
)


class WorkerResourceAccountingService:
    """Prepare and settle one terminal reservation transition."""

    __slots__ = ("_bindings", "_clock", "_resources")

    def __init__(
        self,
        *,
        bindings: WorkerReservationBindingStore,
        resources: WorkerResourcePort,
        clock: WorkerResourceClock,
    ) -> None:
        if bindings is None or resources is None or clock is None:
            raise TypeError("worker resource accounting dependency is missing")
        self._bindings = bindings
        self._resources = resources
        self._clock = clock

    def prepare(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
        outcome: str,
        usage_document: object,
        usage_supplied: bool,
    ) -> WorkerResourceSettlement:
        if outcome not in TERMINAL_OUTCOMES:
            raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
        try:
            binding = self._bindings.load(
                tenant_id=tenant_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
            )
        except WorkerResourceError:
            raise
        except Exception:
            raise WorkerResourceError(WorkerResourceErrorCode.BINDING_UNAVAILABLE, 503) from None
        if outcome in COMMIT_OUTCOMES:
            if binding.state not in {
                ReservationState.RESERVED,
                ReservationState.COMMITTED,
            }:
                raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
            usage = resolve_usage(
                usage_document,
                supplied=usage_supplied,
                reserved=binding.reserved,
                recorded=binding.actual,
            )
        else:
            if usage_supplied:
                raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
            expected_state = (
                ReservationState.CANCELLED if outcome == "CANCELLED" else ReservationState.RELEASED
            )
            if binding.state not in {ReservationState.RESERVED, expected_state}:
                raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
            usage = None
        return WorkerResourceSettlement(binding, outcome, usage)

    def settle(self, settlement: WorkerResourceSettlement) -> None:
        if type(settlement) is not WorkerResourceSettlement:
            raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
        binding = settlement.binding
        now_ms = self._now_ms()
        try:
            if settlement.outcome in COMMIT_OUTCOMES:
                if settlement.usage is None:
                    raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
                receipt = self._resources.commit(
                    tenant_id=binding.tenant_id,
                    repository_id=binding.repository_id,
                    run_id=binding.run_id,
                    execution_identity_hash=binding.execution_identity_hash,
                    reservation_id=binding.reservation_id,
                    usage=settlement.usage,
                    expected_version=binding.reservation_version,
                    now_ms=now_ms,
                )
                _require_receipt(
                    binding,
                    receipt,
                    state=ReservationState.COMMITTED,
                    actual=settlement.usage,
                )
            else:
                cancelled = settlement.outcome == "CANCELLED"
                target = ReservationState.CANCELLED if cancelled else ReservationState.RELEASED
                receipt = self._resources.release(
                    tenant_id=binding.tenant_id,
                    repository_id=binding.repository_id,
                    run_id=binding.run_id,
                    execution_identity_hash=binding.execution_identity_hash,
                    reservation_id=binding.reservation_id,
                    expected_version=binding.reservation_version,
                    now_ms=now_ms,
                    cancelled=cancelled,
                )
                _require_receipt(binding, receipt, state=target, actual=None)
        except WorkerResourceError:
            raise
        except ResourceGovernorError:
            raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503) from None
        except Exception:
            raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503) from None

    def _now_ms(self) -> int:
        try:
            value = self._clock()
        except Exception:
            raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503) from None
        if type(value) is not int or not 0 <= value <= 9_223_372_036_854_775_807:
            raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
        return value

    def now_ms(self) -> int:
        """Return one validated timestamp for an atomic completion transaction."""

        return self._now_ms()


class WorkerResourceAccountingHandler:
    """Settle resources before exposing an idempotent terminal queue state."""

    __slots__ = ("_accounting", "_fallback")

    def __init__(
        self,
        *,
        accounting: WorkerResourceAccountingService,
        fallback: ControlPlaneService,
    ) -> None:
        if not isinstance(accounting, WorkerResourceAccountingService) or not hasattr(
            fallback, "dispatch"
        ):
            raise TypeError("worker resource handler dependencies are invalid")
        self._accounting = accounting
        self._fallback = fallback

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action != "worker_sessions.complete":
            return await self._fallback.dispatch(request)
        terminal = _terminal_request(request)
        if terminal is None:
            return await self._fallback.dispatch(request)
        run_id, identity_hash, outcome, document = terminal
        try:
            settlement = self._accounting.prepare(
                tenant_id=request.identity.tenant_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                outcome=outcome,
                usage_document=document.get("resource_usage"),
                usage_supplied="resource_usage" in document,
            )
        except WorkerResourceError as error:
            if error.status >= 500:
                raise ServiceUnavailableError() from None
            return _error_response(error)
        except Exception:
            raise ServiceUnavailableError() from None

        completion = getattr(self._fallback, "dispatch_accounted_completion", None)
        if not callable(completion):
            raise ServiceUnavailableError()
        try:
            response = cast(
                ServiceResponse,
                await completion(
                    request,
                    settlement=settlement,
                    resource_clock=self._accounting.now_ms,
                ),
            )
        except WorkerResourceError:
            raise ServiceUnavailableError() from None
        except Exception as error:
            if isinstance(error, ServiceUnavailableError):
                raise
            raise ServiceUnavailableError() from None
        if response.status != 200:
            return response
        if (
            response.document.get("terminal") is not True
            or response.document.get("run_id") != run_id
        ):
            raise ServiceUnavailableError()
        return response


def _terminal_request(
    request: ServiceRequest,
) -> tuple[str, str, str, Mapping[str, object]] | None:
    document = request.document
    if not isinstance(document, Mapping):
        return None
    run_id = document.get("run_id")
    identity_hash = document.get("execution_identity_hash")
    outcome = document.get("outcome")
    if (
        type(run_id) is not str
        or type(identity_hash) is not str
        or type(outcome) is not str
        or outcome not in TERMINAL_OUTCOMES
    ):
        return None
    return run_id, identity_hash, outcome, document


def settle_worker_resources(
    cursor: sqlite3.Cursor,
    settlement: WorkerResourceSettlement,
    *,
    now_ms: int,
) -> None:
    """Apply or replay one resource transition inside the queue transaction."""

    if (
        not isinstance(cursor, sqlite3.Cursor)
        or type(settlement) is not WorkerResourceSettlement
        or type(now_ms) is not int
        or not 0 <= now_ms <= 9_223_372_036_854_775_807
    ):
        raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
    binding = settlement.binding
    row = cursor.execute(
        """SELECT * FROM resource_reservations
           WHERE tenant_id=? AND reservation_id=?""",
        (binding.tenant_id, binding.reservation_id),
    ).fetchone()
    if row is None or not _resource_binding_matches(row, binding):
        raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
    target = (
        ReservationState.COMMITTED
        if settlement.outcome in COMMIT_OUTCOMES
        else ReservationState.CANCELLED
        if settlement.outcome == "CANCELLED"
        else ReservationState.RELEASED
    )
    state = ReservationState(row["state"])
    if state is target:
        if (
            row["state_version"] != binding.reservation_version + 1
            or (target is ReservationState.COMMITTED) is not (settlement.usage is not None)
            or (settlement.usage is not None and _actual_resource_usage(row) != settlement.usage)
        ):
            raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
        return
    if (
        state is not ReservationState.RESERVED
        or row["state_version"] != binding.reservation_version
        or now_ms >= row["lease_expires_at_ms"]
    ):
        raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
    if settlement.usage is not None:
        usage = settlement.usage
        if any(
            actual > reserved
            for actual, reserved in zip(
                _usage_values(usage),
                _reserved_values(row),
                strict=True,
            )
        ):
            raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
        cursor.execute(
            """UPDATE resource_reservations
               SET state=?, actual_tokens=?, actual_cost_microunits=?,
                   actual_cpu_ms=?, actual_peak_memory_bytes=?, actual_wall_ms=?,
                   state_version=state_version+1, terminal_at_ms=?
               WHERE tenant_id=? AND reservation_id=? AND state=? AND state_version=?""",
            (
                target.value,
                *_usage_values(usage),
                now_ms,
                binding.tenant_id,
                binding.reservation_id,
                ReservationState.RESERVED.value,
                binding.reservation_version,
            ),
        )
    else:
        cursor.execute(
            """UPDATE resource_reservations
               SET state=?, state_version=state_version+1, terminal_at_ms=?
               WHERE tenant_id=? AND reservation_id=? AND state=? AND state_version=?""",
            (
                target.value,
                now_ms,
                binding.tenant_id,
                binding.reservation_id,
                ReservationState.RESERVED.value,
                binding.reservation_version,
            ),
        )
    if cursor.rowcount != 1:
        raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)


def _resource_binding_matches(row: sqlite3.Row, binding: WorkerReservationBinding) -> bool:
    return (
        row["repository_id"] == binding.repository_id
        and row["run_id"] == binding.run_id
        and row["execution_identity_hash"] == binding.execution_identity_hash
        and row["profile_sha256"] == binding.profile_sha256
        and _reserved_values(row) == _usage_values(binding.reserved)
    )


def _reserved_values(row: sqlite3.Row) -> tuple[int, int, int, int, int]:
    return (
        row["requested_tokens"],
        row["requested_cost_microunits"],
        row["requested_cpu_ms"],
        row["requested_memory_bytes"],
        row["requested_wall_ms"],
    )


def _actual_resource_usage(row: sqlite3.Row) -> ResourceUsage:
    return ResourceUsage(
        tokens=row["actual_tokens"],
        cost_microunits=row["actual_cost_microunits"],
        cpu_ms=row["actual_cpu_ms"],
        peak_memory_bytes=row["actual_peak_memory_bytes"],
        wall_ms=row["actual_wall_ms"],
    )


def _usage_values(value: ResourceUsage) -> tuple[int, int, int, int, int]:
    return (
        value.tokens,
        value.cost_microunits,
        value.cpu_ms,
        value.peak_memory_bytes,
        value.wall_ms,
    )


def _require_receipt(
    binding: WorkerReservationBinding,
    receipt: ResourceReservationReceipt,
    *,
    state: ReservationState,
    actual: object,
) -> None:
    if (
        type(receipt) is not ResourceReservationReceipt
        or receipt.tenant_id != binding.tenant_id
        or receipt.repository_id != binding.repository_id
        or receipt.run_id != binding.run_id
        or receipt.execution_identity_hash != binding.execution_identity_hash
        or receipt.profile_sha256 != binding.profile_sha256
        or receipt.reservation_id != binding.reservation_id
        or receipt.reserved != binding.reserved
        or receipt.state is not state
        or receipt.actual != actual
        or receipt.state_version != binding.reservation_version + 1
    ):
        raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)


def _error_response(error: WorkerResourceError) -> ServiceResponse:
    return ServiceResponse(
        error.status,
        {"error": {"code": error.code.value, "message": safe_message(error.code)}},
    )


__all__ = [
    "WorkerResourceAccountingHandler",
    "WorkerResourceAccountingService",
    "settle_worker_resources",
]
