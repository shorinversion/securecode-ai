"""Wire immutable per-run audit exports and low-cardinality service telemetry."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from time import perf_counter_ns

from .audit_export import export_audit
from .audit_log import AuditConflict, AuditLog
from .operations_telemetry import OperationsTelemetry
from .persistence import DevelopmentRepository, NotFoundError
from .ports import ControlPlaneService, ServiceRequest, ServiceResponse, ServiceUnavailableError

_MAX_EXPORT_EVENTS = 500
_AUDITED_ACTIONS = frozenset(
    {
        "runs.create",
        "runs.cancel",
        "findings.decide",
        "approvals.create",
        "approvals.decide",
        "artifacts.authorize",
        "artifacts.upload",
        "feedback.submit",
        "assurance.append",
        "webhooks.github",
        "webhooks.gitlab",
        "worker_sessions.create",
        "worker_sessions.heartbeat",
        "worker_sessions.events.append",
        "worker_sessions.artifacts.commit",
        "worker_sessions.complete",
    }
)
_AUDIT_OUTCOMES = frozenset(
    {
        "success",
        "error",
        "cancelled",
        "superseded",
        "pass",
        "fail",
        "indeterminate",
        "approved",
        "rejected",
    }
)


class AuditTelemetryControlPlane:
    """Observe durable service actions without retaining request or source data."""

    def __init__(
        self,
        *,
        fallback: ControlPlaneService,
        audit_log: AuditLog,
        telemetry: OperationsTelemetry,
        runs: DevelopmentRepository,
        clock_ns: Callable[[], int] = perf_counter_ns,
    ) -> None:
        self._fallback = fallback
        self._audit_log = audit_log
        self._telemetry = telemetry
        self._runs = runs
        self._clock_ns = clock_ns

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action == "operations.metrics.read":
            if "admin" not in request.identity.roles:
                return _error(403, "FORBIDDEN")
            return ServiceResponse(200, self._telemetry.snapshot())
        if request.action == "runs.audit.read":
            started = self._clock_ns()
            audit_response: ServiceResponse | None = None
            try:
                audit_response = self._export_run_audit(request)
                return audit_response
            finally:
                elapsed_ms = max(0, (self._clock_ns() - started) // 1_000_000)
                self._telemetry.record(
                    operation="export",
                    outcome=_outcome(audit_response),
                    elapsed_ms=elapsed_ms,
                )

        started = self._clock_ns()
        response: ServiceResponse | None = None
        try:
            response = await self._fallback.dispatch(request)
            if request.action in _AUDITED_ACTIONS:
                self._record_run_action(request, response)
            return response
        finally:
            operation = _operation_for(request.action)
            if operation is not None:
                elapsed_ms = max(0, (self._clock_ns() - started) // 1_000_000)
                outcome = _outcome(response)
                self._telemetry.record(
                    operation=operation,
                    outcome=outcome,
                    elapsed_ms=elapsed_ms,
                )

    def _export_run_audit(self, request: ServiceRequest) -> ServiceResponse:
        run_id = request.path_params.get("run_id")
        if run_id is None:
            return _error(400, "INVALID_AUDIT_RANGE")
        try:
            run = self._runs.get_run(request.identity.tenant_id, run_id)
        except NotFoundError:
            return _error(404, "NOT_FOUND")
        repository_id = run.get("repository_id")
        if "admin" not in request.identity.roles and (
            "auditor" not in request.identity.roles
            or repository_id not in request.identity.repository_ids
        ):
            return _error(403, "FORBIDDEN")
        try:
            head = self._audit_log.head_sequence(
                tenant_id=request.identity.tenant_id,
                run_id=run_id,
            )
            start, end = _audit_range(request.query, head)
        except AuditConflict:
            return _error(400, "INVALID_AUDIT_RANGE")
        try:
            self._audit_log.require_valid(tenant_id=request.identity.tenant_id, run_id=run_id)
            result = export_audit(
                self._audit_log,
                tenant_id=request.identity.tenant_id,
                run_id=run_id,
                start=start,
                end=end,
            )
        except AuditConflict as error:
            raise ServiceUnavailableError() from error
        except Exception as error:
            raise ServiceUnavailableError() from error
        return ServiceResponse(200, result)

    def _record_run_action(self, request: ServiceRequest, response: ServiceResponse) -> None:
        if response.status >= 500:
            return
        run_id = _action_run_id(request, response)
        if run_id is None:
            run_id = self._identity_bound_run_id(request)
        if run_id is None:
            # A successful mutating route must identify the exact run whose
            # durable state it changed.  A worker claim returning 204 is an
            # explicit no-op and has no run to record; malformed success
            # responses fail closed instead of silently losing the audit event.
            if 200 <= response.status < 300 and response.status != 204:
                raise ServiceUnavailableError()
            return
        try:
            run = self._runs.get_run(request.identity.tenant_id, run_id)
        except NotFoundError:
            if response.status < 400:
                raise ServiceUnavailableError() from None
            return
        except Exception as error:
            raise ServiceUnavailableError() from error
        repository_id = run.get("repository_id")
        identity_hash = run.get("execution_identity_hash")
        if type(repository_id) is not str or type(identity_hash) is not str:
            raise ServiceUnavailableError()
        key_material = "\x00".join(
            (
                request.identity.tenant_id,
                run_id,
                identity_hash,
                request.identity.subject_id,
                request.action,
                request.idempotency_key or "",
            )
        )
        idempotency_key = "audit-" + hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        outcome = _audit_outcome(request, response)
        try:
            self._audit_log.append(
                tenant_id=request.identity.tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                actor_id=request.identity.subject_id,
                action=request.action,
                identity_hash=identity_hash,
                expected_sequence=self._audit_log.head_sequence(
                    tenant_id=request.identity.tenant_id,
                    run_id=run_id,
                ),
                attributes={"outcome": outcome},
                idempotency_key=idempotency_key,
            )
        except Exception as error:
            raise ServiceUnavailableError() from error

    def _identity_bound_run_id(self, request: ServiceRequest) -> str | None:
        """Resolve evidence writes through their already admitted identity hash."""

        if request.action != "assurance.append" or not isinstance(request.document, Mapping):
            return None
        repository_id = request.document.get("repository_id")
        identity_hash = request.document.get("execution_identity_hash")
        if (
            not _safe_identifier(repository_id)
            or not _sha256(identity_hash)
        ):
            return None
        lookup = getattr(self._runs, "get_run_by_identity", None)
        if not callable(lookup):
            return None
        try:
            run = lookup(request.identity.tenant_id, repository_id, identity_hash)
        except NotFoundError:
            return None
        except Exception as error:
            raise ServiceUnavailableError() from error
        if not isinstance(run, Mapping):
            return None
        run_id = run.get("run_id")
        return run_id if _safe_identifier(run_id) else None


def _action_run_id(request: ServiceRequest, response: ServiceResponse) -> str | None:
    candidates: list[object] = [request.path_params.get("run_id")]
    if request.action == "artifacts.upload":
        candidates.append(request.headers.get("x-securecode-run-id"))
    candidates.extend(
        (
            response.document.get("run_id"),
            request.document.get("run_id") if isinstance(request.document, Mapping) else None,
        )
    )
    for document in (response.document, request.document):
        if not isinstance(document, Mapping):
            continue
        for name in ("run", "admission"):
            nested = document.get(name)
            if isinstance(nested, Mapping):
                candidates.append(nested.get("run_id"))
    for run_id in candidates:
        if type(run_id) is str and _safe_identifier(run_id):
            return run_id
    return None


def _safe_identifier(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 256
        and "\x00" not in value
        and all(ord(character) >= 0x20 for character in value)
    )


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _operation_for(action: str) -> str | None:
    if action.startswith(("runs.", "findings.", "feedback.", "assurance.", "webhooks.")):
        return "run"
    if action.startswith("worker_sessions."):
        return "worker"
    if action.startswith("artifacts."):
        return "artifact"
    if action.startswith("approvals."):
        return "approval"
    if action == "runs.audit.read":
        return "export"
    return None


def _outcome(response: ServiceResponse | None) -> str:
    if response is None or response.status >= 400:
        return "error"
    state = response.document.get("state")
    if state == "CANCELLED":
        return "cancelled"
    if state == "SUPERSEDED":
        return "superseded"
    return "success"


def _audit_outcome(request: ServiceRequest, response: ServiceResponse) -> str:
    if request.action == "worker_sessions.complete" and isinstance(request.document, Mapping):
        value = request.document.get("outcome")
        if type(value) is str and value in {"PASS", "FAIL", "INDETERMINATE"}:
            return value.lower()
    if request.action == "approvals.decide":
        decision = response.document.get("decision")
        if isinstance(decision, Mapping):
            state = decision.get("state")
            if type(state) is str and state in {"APPROVED", "REJECTED"}:
                return state.lower()
    outcome = _outcome(response)
    return outcome if outcome in _AUDIT_OUTCOMES else "error"


def _audit_range(query: Mapping[str, tuple[str, ...]], head: int) -> tuple[int, int | None]:
    if set(query) - {"start", "end"}:
        raise AuditConflict("audit range query is invalid")
    start_value = _query_integer(query, "start", default=1)
    end = _query_integer(query, "end", default=None)
    if start_value is None:
        raise AuditConflict("audit range start is invalid")
    start = start_value
    if start < 1 or (end is not None and (end < start or end > head)):
        raise AuditConflict("audit range is invalid")
    effective_end = head if end is None else end
    if effective_end >= start and effective_end - start + 1 > _MAX_EXPORT_EVENTS:
        raise AuditConflict("audit range exceeds the export limit")
    return start, end if end is not None else (effective_end if effective_end >= start else None)


def _query_integer(
    query: Mapping[str, tuple[str, ...]], name: str, *, default: int | None
) -> int | None:
    values = query.get(name)
    if values is None:
        if default is None:
            return None
        return default
    if (
        len(values) != 1
        or not values[0].isascii()
        or not values[0].isdecimal()
        or len(values[0]) > 19
    ):
        raise AuditConflict("audit range query is invalid")
    parsed = int(values[0])
    if parsed > 9_223_372_036_854_775_807:
        raise AuditConflict("audit range query is invalid")
    return parsed


def _error(status: int, code: str) -> ServiceResponse:
    return ServiceResponse(status, {"error": {"code": code}})


__all__ = ["AuditTelemetryControlPlane"]
