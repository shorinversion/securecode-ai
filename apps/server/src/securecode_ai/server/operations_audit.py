"""Wire immutable per-run audit exports and low-cardinality service telemetry."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from time import perf_counter_ns

from .audit_export import export_audit, export_resource_audit
from .audit_log import AuditConflict, AuditLog
from .operations_telemetry import OperationsTelemetry
from .persistence import DevelopmentRepository, NotFoundError
from .ports import ControlPlaneService, ServiceRequest, ServiceResponse, ServiceUnavailableError

_MAX_EXPORT_EVENTS = 500
_RESOURCE_AUDIT_TYPES = frozenset({"backup", "secret-grant"})
_RESOURCE_AUDIT_ACTIONS = {
    "backups.create": "backup",
    "backups.read": "backup",
    "backups.execute": "backup",
    "backups.restore": "backup",
    "secrets.grant": "secret-grant",
    "secrets.read": "secret-grant",
    "secrets.rotate": "secret-grant",
    "secrets.revoke": "secret-grant",
}
_RESOURCE_AUDIT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}\Z")
_AUDITED_ACTIONS = frozenset(
    {
        "runs.create",
        "runs.cancel",
        "findings.decide",
        "approvals.create",
        "approvals.decide",
        "waivers.create",
        "waivers.revoke",
        "artifacts.authorize",
        "artifacts.upload",
        "feedback.submit",
        "assurance.append",
        "lifecycle.deletions.create",
        "lifecycle.deletions.approve",
        "lifecycle.deletions.legal_hold",
        "lifecycle.deletions.execute",
        *_RESOURCE_AUDIT_ACTIONS,
        "webhooks.github",
        "webhooks.gitlab",
        "worker_sessions.create",
        "worker_sessions.heartbeat",
        "worker_sessions.events.append",
        "worker_sessions.artifacts.commit",
        "worker_sessions.complete",
        "worker_sessions.osv.query",
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
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


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
                if request.path_params.get("resource_type") is not None:
                    audit_response = self._export_resource_audit(request)
                else:
                    audit_response = self._export_run_audit(request)
                return audit_response
            finally:
                elapsed_ms = max(0, (self._clock_ns() - started) // 1_000_000)
                _record_telemetry_safely(
                    self._telemetry,
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
        except Exception:
            # A successful domain response that cannot be durably audited is
            # exposed as a service failure.  Keep the operational outcome in
            # sync with that externally visible failure.
            response = None
            raise
        finally:
            operation = _operation_for(request.action)
            if operation is not None:
                elapsed_ms = max(0, (self._clock_ns() - started) // 1_000_000)
                outcome = _outcome(response)
                resource_usage = None
                if request.action == "worker_sessions.complete":
                    outcome = _worker_terminal_outcome(request, response)
                    resource_usage = _worker_resource_usage(request, response, outcome)
                _record_telemetry_safely(
                    self._telemetry,
                    operation=operation,
                    outcome=outcome,
                    elapsed_ms=elapsed_ms,
                    resource_usage=resource_usage,
                )

    def preflight_artifact_upload(self, request: ServiceRequest) -> str:
        preflight = getattr(self._fallback, "preflight_artifact_upload", None)
        if not callable(preflight):
            raise ServiceUnavailableError()
        artifact_id: str = preflight(request)
        return artifact_id

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

    def _export_resource_audit(self, request: ServiceRequest) -> ServiceResponse:
        resource_type = request.path_params.get("resource_type")
        resource_id = request.path_params.get("resource_id")
        if (
            type(resource_type) is not str
            or resource_type not in _RESOURCE_AUDIT_TYPES
            or (
                resource_id is not None
                and (
                    type(resource_id) is not str
                    or _RESOURCE_AUDIT_ID.fullmatch(resource_id) is None
                )
            )
        ):
            return _error(400, "INVALID_AUDIT_RANGE")
        if "admin" not in request.identity.roles:
            return _error(403, "FORBIDDEN")
        try:
            key_hash = self._audit_log.resource_key_sha256(
                tenant_id=request.identity.tenant_id,
                resource_type=resource_type,
                resource_id=resource_id,
            )
            head = self._audit_log.resource_head_sequence(
                tenant_id=request.identity.tenant_id,
                resource_type=resource_type,
                resource_key_sha256=key_hash,
            )
            if head == 0:
                return _error(404, "NOT_FOUND")
            start, end = _audit_range(request.query, head)
            result = export_resource_audit(
                self._audit_log,
                tenant_id=request.identity.tenant_id,
                resource_type=resource_type,
                resource_key_sha256=key_hash,
                resource_scope="tenant" if resource_id is None else "resource",
                start=start,
                end=end,
                maximum_events=_MAX_EXPORT_EVENTS,
            )
        except AuditConflict:
            return _error(400, "INVALID_AUDIT_RANGE")
        except Exception as error:
            raise ServiceUnavailableError() from error
        return ServiceResponse(200, result)

    def _record_run_action(self, request: ServiceRequest, response: ServiceResponse) -> None:
        if response.status >= 500:
            return
        resource_target = _resource_audit_target(request, response)
        if resource_target is not None:
            resource_type, resource_id = resource_target
            if resource_id is None:
                if response.status < 400 and request.action in {"backups.create", "secrets.grant"}:
                    raise ServiceUnavailableError()
                return
            raw_body_sha = hashlib.sha256(request.raw_body).hexdigest()
            material = "\x00".join(
                (
                    request.identity.tenant_id,
                    resource_type,
                    resource_id,
                    request.identity.subject_id,
                    request.action,
                    request.idempotency_key or "",
                    request.precondition or "",
                    raw_body_sha,
                )
            )
            idempotency_key = (
                "resource-audit-" + hashlib.sha256(material.encode("utf-8")).hexdigest()
            )
            try:
                self._audit_log.append_resource(
                    tenant_id=request.identity.tenant_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    actor_id=request.identity.subject_id,
                    action=request.action,
                    expected_sequence=None,
                    attributes={"outcome": _audit_outcome(request, response)},
                    idempotency_key=idempotency_key,
                )
            except Exception as error:
                raise ServiceUnavailableError() from error
            return
        if _is_audit_retention_execution(request, response):
            # The lifecycle row is the durable deletion receipt.  The target
            # audit chain is retired before this wrapper regains control, so
            # appending another event would resurrect the retired chain.
            return
        run_id = _action_run_id(request, response)
        if run_id is None:
            run_id = self._identity_bound_run_id(request, response)
        if run_id is None:
            # A successful mutating route must identify the exact run whose
            # durable state it changed.  A worker claim returning 204 is an
            # explicit no-op and has no run to record; malformed success
            # responses fail closed instead of silently losing the audit event.
            if 200 <= response.status < 300 and response.status != 204:
                raise ServiceUnavailableError()
            return
        audit_tenant_id = _action_tenant_id(request, response)
        try:
            run = self._runs.get_run(audit_tenant_id, run_id)
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
                audit_tenant_id,
                run_id,
                identity_hash,
                request.identity.subject_id,
                request.action,
                request.idempotency_key or "",
                request.precondition or "",
                hashlib.sha256(request.raw_body).hexdigest(),
                _request_scope_hash(request),
            )
        )
        idempotency_key = "audit-" + hashlib.sha256(key_material.encode("utf-8")).hexdigest()
        outcome = _audit_outcome(request, response)
        attributes = _audit_attributes(request, response, outcome)
        try:
            self._audit_log.append(
                tenant_id=audit_tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                actor_id=request.identity.subject_id,
                action=request.action,
                identity_hash=identity_hash,
                expected_sequence=self._audit_log.head_sequence(
                    tenant_id=audit_tenant_id,
                    run_id=run_id,
                ),
                attributes=attributes,
                idempotency_key=idempotency_key,
            )
        except Exception as error:
            raise ServiceUnavailableError() from error

    def _identity_bound_run_id(
        self,
        request: ServiceRequest,
        response: ServiceResponse,
    ) -> str | None:
        """Resolve run-scoped writes through their already admitted identity hash."""

        identity_bound_actions = {
            "assurance.append",
            "lifecycle.deletions.create",
            "lifecycle.deletions.approve",
            "lifecycle.deletions.legal_hold",
            "lifecycle.deletions.execute",
        }
        if request.action not in identity_bound_actions:
            return None
        documents = (response.document, request.document)
        repository_id: object = None
        identity_hash: object = None
        for document in documents:
            if not isinstance(document, Mapping):
                continue
            repository_id = document.get("repository_id", repository_id)
            identity_hash = document.get(
                "execution_identity_hash",
                document.get("identity_hash", identity_hash),
            )
        if not _safe_identifier(repository_id) or not _sha256(identity_hash):
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


def _record_telemetry_safely(
    telemetry: OperationsTelemetry,
    *,
    operation: str,
    outcome: str,
    elapsed_ms: int,
    resource_usage: Mapping[str, int] | None = None,
) -> None:
    try:
        telemetry.record(
            operation=operation,
            outcome=outcome,
            elapsed_ms=elapsed_ms,
            resource_usage=resource_usage,
        )
    except Exception:
        return


def _resource_audit_target(
    request: ServiceRequest,
    response: ServiceResponse,
) -> tuple[str, str | None] | None:
    resource_type = _RESOURCE_AUDIT_ACTIONS.get(request.action)
    if resource_type is None:
        return None
    path_name = "backup_id" if resource_type == "backup" else "grant_id"
    response_name = "backup_id" if resource_type == "backup" else "grant_id"
    resource_id: object = request.path_params.get(path_name)
    if resource_id is None and request.action == "backups.create":
        request_document = request.document
        candidate = (
            request_document.get("backup_id") if isinstance(request_document, Mapping) else None
        )
        if type(candidate) is str and _RESOURCE_AUDIT_ID.fullmatch(candidate) is not None:
            resource_id = candidate
    if resource_id is None and isinstance(response.document, Mapping):
        resource_id = response.document.get(response_name)
    if type(resource_id) is not str or _RESOURCE_AUDIT_ID.fullmatch(resource_id) is None:
        return (resource_type, None)
    return resource_type, resource_id


def _action_tenant_id(request: ServiceRequest, response: ServiceResponse) -> str:
    """Resolve the durable tenant for routes with a transport identity."""

    if request.action != "artifacts.upload" or not 200 <= response.status < 300:
        return request.identity.tenant_id
    if not isinstance(response.document, Mapping):
        raise ServiceUnavailableError()
    receipt_tenant = response.document.get("tenant_id")
    receipt_run = response.document.get("run_id")
    header_tenant = request.headers.get("x-securecode-tenant-id")
    header_run = request.headers.get("x-securecode-run-id")
    if (
        not _safe_identifier(receipt_tenant)
        or not request.identity.workload
        or "artifact_uploader" not in request.identity.roles
        or type(header_tenant) is not str
        or receipt_tenant != header_tenant
        or not _safe_identifier(receipt_run)
        or type(header_run) is not str
        or receipt_run != header_run
    ):
        raise ServiceUnavailableError()
    return receipt_tenant


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


def _request_scope_hash(request: ServiceRequest) -> str:
    """Hash routing metadata so keyless transitions cannot collide by run."""

    parts = [request.method, request.route]
    parts.extend(f"path:{key}={value}" for key, value in sorted(request.path_params.items()))
    parts.extend(f"query:{key}={'/'.join(values)}" for key, values in sorted(request.query.items()))
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _operation_for(action: str) -> str | None:
    if action == "runs.audit.read":
        return "export"
    if action.startswith(
        (
            "runs.",
            "findings.",
            "feedback.",
            "assurance.",
            "webhooks.",
            "scm.",
            "policies.",
        )
    ):
        return "run"
    if action.startswith("worker_sessions."):
        return "worker"
    if action.startswith(("artifacts.", "backups.", "secrets.", "lifecycle.deletions.")):
        return "artifact"
    if action.startswith(("approvals.", "waivers.")):
        return "approval"
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


def _worker_terminal_outcome(request: ServiceRequest, response: ServiceResponse | None) -> str:
    """Use a worker terminal result only after the server accepted completion."""

    if response is None or response.status < 200 or response.status >= 300:
        return "error"
    document = request.document
    value = document.get("outcome") if isinstance(document, Mapping) else None
    if type(value) is str and value in {
        "PASS",
        "FAIL",
        "INDETERMINATE",
        "CANCELLED",
        "SUPERSEDED",
    }:
        return value.lower()
    return _outcome(response)


def _worker_resource_usage(
    request: ServiceRequest, response: ServiceResponse | None, outcome: str
) -> Mapping[str, int] | None:
    """Project accepted numeric counters without retaining worker payload data."""

    if (
        response is None
        or response.status < 200
        or response.status >= 300
        or outcome not in {"pass", "fail", "indeterminate"}
        or not isinstance(request.document, Mapping)
    ):
        return None
    value = request.document.get("resource_usage")
    if not isinstance(value, Mapping):
        return None
    fields = {"tokens", "cost_microunits", "cpu_ms", "peak_memory_bytes", "wall_ms"}
    if set(value) != fields or any(type(item) is not int or item < 0 for item in value.values()):
        return None
    return {name: value[name] for name in fields}


def _audit_outcome(request: ServiceRequest, response: ServiceResponse) -> str:
    if (
        request.action == "worker_sessions.complete"
        and 200 <= response.status < 300
        and isinstance(request.document, Mapping)
    ):
        value = request.document.get("outcome")
        if type(value) is str and value in {"PASS", "FAIL", "INDETERMINATE"}:
            return value.lower()
    if request.action == "approvals.decide":
        states: tuple[object, ...] = (response.document.get("state"),)
        decision = response.document.get("decision")
        if isinstance(decision, Mapping):
            states += (decision.get("state"),)
        for state in states:
            if type(state) is str and state in {"APPROVED", "REJECTED"}:
                return state.lower()
    outcome = _outcome(response)
    return outcome if outcome in _AUDIT_OUTCOMES else "error"


def _audit_attributes(
    request: ServiceRequest,
    response: ServiceResponse,
    outcome: str,
) -> dict[str, object]:
    attributes: dict[str, object] = {"outcome": outcome}
    request_document = request.document
    response_document = response.document
    if request.action in {"findings.decide", "approvals.decide"}:
        reason_code = (
            request_document.get("reason_code") if isinstance(request_document, Mapping) else None
        )
        if type(reason_code) is str and _REASON_CODE.fullmatch(reason_code) is not None:
            attributes["reason_code"] = reason_code
    if request.action.startswith("lifecycle.deletions."):
        for document in (response_document, request_document):
            if not isinstance(document, Mapping):
                continue
            resource_type = document.get("data_class")
            if (
                type(resource_type) is str
                and 1 <= len(resource_type) <= 128
                and all(ord(character) >= 32 for character in resource_type)
            ):
                attributes["resource_type"] = resource_type
                break
        if request.action == "lifecycle.deletions.legal_hold":
            retention_marked = (
                request_document.get("enabled") if isinstance(request_document, Mapping) else None
            )
            if type(retention_marked) is bool:
                attributes["retention_marked"] = retention_marked
    return attributes


def _is_audit_retention_execution(
    request: ServiceRequest,
    response: ServiceResponse,
) -> bool:
    if request.action != "lifecycle.deletions.execute" or not 200 <= response.status < 300:
        return False
    for document in (response.document, request.document):
        if isinstance(document, Mapping) and document.get("data_class") == "audit":
            return True
    return False


def _audit_range(query: Mapping[str, tuple[str, ...]], head: int) -> tuple[int, int | None]:
    if set(query) - {"start", "end"}:
        raise AuditConflict("audit range query is invalid")
    start_value = _query_integer(query, "start", default=1)
    end = _query_integer(query, "end", default=None)
    if start_value is None:
        raise AuditConflict("audit range start is invalid")
    start = start_value
    if head == 0 and start == 1 and end is None:
        return 1, None
    if start < 1 or start > head or (end is not None and (end < start or end > head)):
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
