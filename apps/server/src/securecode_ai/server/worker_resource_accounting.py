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
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard
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
        if type(outcome) is not str or outcome not in TERMINAL_OUTCOMES:
            raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
        if outcome in COMMIT_OUTCOMES and usage_supplied is not True:
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
            expected_state = (
                ReservationState.CANCELLED if outcome == "CANCELLED" else ReservationState.RELEASED
            )
            if usage_supplied:
                if binding.state not in {
                    ReservationState.RESERVED,
                    ReservationState.COMMITTED,
                }:
                    raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
                usage = resolve_usage(
                    usage_document,
                    supplied=True,
                    reserved=binding.reserved,
                    recorded=binding.actual,
                )
            else:
                if binding.state not in {ReservationState.RESERVED, expected_state}:
                    raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
                usage = None
        return WorkerResourceSettlement(binding, outcome, usage)

    def settle(self, settlement: WorkerResourceSettlement) -> None:
        if type(settlement) is not WorkerResourceSettlement:
            raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
        requested_binding = settlement.binding
        try:
            binding = self._bindings.load(
                tenant_id=requested_binding.tenant_id,
                run_id=requested_binding.run_id,
                execution_identity_hash=requested_binding.execution_identity_hash,
            )
        except WorkerResourceError:
            raise
        except Exception:
            raise WorkerResourceError(WorkerResourceErrorCode.BINDING_UNAVAILABLE, 503) from None
        if not _binding_scope_matches(binding, requested_binding):
            raise WorkerResourceError(WorkerResourceErrorCode.BINDING_UNAVAILABLE, 503)
        target = (
            ReservationState.COMMITTED
            if settlement.outcome in COMMIT_OUTCOMES or settlement.usage is not None
            else ReservationState.CANCELLED
            if settlement.outcome == "CANCELLED"
            else ReservationState.RELEASED
        )
        # A worker retry may load the already-terminal binding after the first
        # settlement committed.  The durable resource adapter treats that
        # transition as an idempotent replay, so the service must do the same
        # instead of issuing a stale-version mutation and then expecting a
        # state-version increment that cannot occur.
        if binding.state is target:
            if target is ReservationState.COMMITTED:
                if binding.actual is None or settlement.usage != binding.actual:
                    raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
            elif binding.actual is not None or settlement.usage is not None:
                raise WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409)
            return
        if binding.state is not ReservationState.RESERVED:
            raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
        now_ms = self._now_ms()
        try:
            if settlement.outcome in COMMIT_OUTCOMES or settlement.usage is not None:
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
            if _terminal_settlement_matches(self._bindings, settlement, target):
                return
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

    __slots__ = ("_accounting", "_fallback", "_residency_guard", "_residency_region")

    def __init__(
        self,
        *,
        accounting: WorkerResourceAccountingService,
        fallback: ControlPlaneService,
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
    ) -> None:
        if not isinstance(accounting, WorkerResourceAccountingService) or not hasattr(
            fallback, "dispatch"
        ):
            raise TypeError("worker resource handler dependencies are invalid")
        if (residency_guard is None) != (residency_region is None):
            raise ValueError("worker residency configuration is incomplete")
        if residency_guard is not None and not callable(
            getattr(residency_guard, "require_region", None)
        ):
            raise ValueError("worker residency guard is invalid")
        self._accounting = accounting
        self._fallback = fallback
        self._residency_guard = residency_guard
        self._residency_region = residency_region

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        residency_response = self._residency_response(request.identity.tenant_id)
        if residency_response is not None:
            return residency_response
        if request.action != "worker_sessions.complete":
            return await self._fallback.dispatch(request)
        terminal = _terminal_request(request)
        if terminal is None:
            # The queue handler deliberately does not process completion
            # requests by itself.  Returning its generic 503 here used to
            # turn malformed worker payloads into transient failures and
            # left the caller retrying a request that could never settle a
            # reservation.  Keep non-completion actions on the fallback,
            # while reporting an invalid completion contract directly.
            return (
                _error_response(WorkerResourceError(WorkerResourceErrorCode.INVALID_USAGE, 409))
                if request.action == "worker_sessions.complete"
                else await self._fallback.dispatch(request)
            )
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
        except WorkerResourceError as error:
            if error.status >= 500:
                raise ServiceUnavailableError() from None
            return _error_response(error)
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

    def _residency_response(self, tenant_id: str) -> ServiceResponse | None:
        guard = self._residency_guard
        if guard is None:
            return None
        region = self._residency_region
        if type(region) is not str or not region:
            raise ServiceUnavailableError()
        try:
            decision = guard.require_region(tenant_id=tenant_id, region=region)
        except ResidencyConflict:
            return ServiceResponse(
                403,
                {
                    "error": {
                        "code": "RESIDENCY_DENIED",
                        "message": "worker residency policy denied the request",
                    }
                },
            )
        except Exception:
            raise ServiceUnavailableError() from None
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != tenant_id
            or decision.source_region != region
            or decision.destination_region != region
            or not decision.same_region
        ):
            raise ServiceUnavailableError()
        return None


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
        """SELECT r.*, a.state AS admission_state,
                  a.reservation_id AS admission_reservation_id,
                  a.reservation_version AS admission_reservation_version
           FROM resource_reservations AS r
           LEFT JOIN run_admissions AS a
             ON a.tenant_id=r.tenant_id AND a.run_id=r.run_id
           WHERE r.tenant_id=? AND r.reservation_id=?""",
        (binding.tenant_id, binding.reservation_id),
    ).fetchone()
    if (
        row is None
        or not _resource_binding_matches(row, binding)
        or row["admission_state"] != "ADMITTED"
        or row["admission_reservation_id"] != binding.reservation_id
        or row["admission_reservation_version"] != binding.reservation_version
    ):
        raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
    target = (
        ReservationState.COMMITTED
        if settlement.outcome in COMMIT_OUTCOMES or settlement.usage is not None
        else ReservationState.CANCELLED
        if settlement.outcome == "CANCELLED"
        else ReservationState.RELEASED
    )
    try:
        state = ReservationState(row["state"])
    except (TypeError, ValueError):
        raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503) from None
    if state is target:
        # The binding may have been read just before another identical
        # completion committed the reservation.  It is safe to replay that
        # transition only when this binding is the original RESERVED version
        # and the durable terminal row still represents the same transition.
        stale_reserved_binding = (
            binding.state is ReservationState.RESERVED and binding.actual is None
        )
        current_terminal_binding = binding.state is target
        if (
            (not stale_reserved_binding and not current_terminal_binding)
            or row["state_version"] != binding.reservation_version + 1
            or (target is ReservationState.COMMITTED) is not (settlement.usage is not None)
            or (
                target is ReservationState.COMMITTED
                and settlement.usage is not None
                and _actual_resource_usage(row) != settlement.usage
            )
            or (
                target is not ReservationState.COMMITTED
                and (settlement.usage is not None or binding.actual is not None)
            )
            or (
                current_terminal_binding
                and target is ReservationState.COMMITTED
                and binding.actual != settlement.usage
            )
        ):
            raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503)
        return
    if (
        state is not ReservationState.RESERVED
        or binding.state is not ReservationState.RESERVED
        or binding.actual is not None
        or row["state_version"] != binding.reservation_version
        or now_ms < row["admitted_at_ms"]
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


def _binding_scope_matches(
    current: WorkerReservationBinding,
    requested: WorkerReservationBinding,
) -> bool:
    return (
        current.tenant_id == requested.tenant_id
        and current.repository_id == requested.repository_id
        and current.run_id == requested.run_id
        and current.execution_identity_hash == requested.execution_identity_hash
        and current.profile_sha256 == requested.profile_sha256
        and current.reservation_id == requested.reservation_id
        and current.reserved == requested.reserved
    )


def _terminal_settlement_matches(
    bindings: WorkerReservationBindingStore,
    settlement: WorkerResourceSettlement,
    target: ReservationState,
) -> bool:
    requested = settlement.binding
    try:
        current = bindings.load(
            tenant_id=requested.tenant_id,
            run_id=requested.run_id,
            execution_identity_hash=requested.execution_identity_hash,
        )
    except Exception:
        return False
    if not _binding_scope_matches(current, requested) or current.state is not target:
        return False
    if target is ReservationState.COMMITTED:
        return current.actual is not None and current.actual == settlement.usage
    return current.actual is None and settlement.usage is None


def _reserved_values(row: sqlite3.Row) -> tuple[int, int, int, int, int]:
    return (
        row["requested_tokens"],
        row["requested_cost_microunits"],
        row["requested_cpu_ms"],
        row["requested_memory_bytes"],
        row["requested_wall_ms"],
    )


def _actual_resource_usage(row: sqlite3.Row) -> ResourceUsage:
    try:
        return ResourceUsage(
            tokens=row["actual_tokens"],
            cost_microunits=row["actual_cost_microunits"],
            cpu_ms=row["actual_cpu_ms"],
            peak_memory_bytes=row["actual_peak_memory_bytes"],
            wall_ms=row["actual_wall_ms"],
        )
    except Exception:
        raise WorkerResourceError(WorkerResourceErrorCode.ACCOUNTING_UNAVAILABLE, 503) from None


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
