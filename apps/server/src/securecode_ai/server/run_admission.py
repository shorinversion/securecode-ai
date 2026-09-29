"""Production-readable coordinator and handler for ``runs.create``."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from pydantic import ValidationError
from securecode_ai.contracts import RunExecutionIdentity
from securecode_ai.core.resource_governor import (
    ResourceGovernorError,
    ResourceGovernorErrorCode,
    ResourceReservationReceipt,
)

from .ports import (
    ControlPlaneService,
    ServiceRequest,
    ServiceResponse,
    ServiceUnavailableError,
)
from .profiles import ProfileConflict
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard
from .run_admission_models import (
    AdmissionClock,
    AdmissionError,
    AdmissionErrorCode,
    AdmissionRecord,
    AdmissionState,
    AuthorizationPort,
    ResourceRequestPolicy,
    ResourceReservationPort,
    RunAdmissionStore,
    RunIdentityResolver,
    RunOperation,
    RunPolicyPinValidator,
    WorkerQueuePort,
    canonical,
    request_sha256,
    safe_message,
)
from .scm_webhooks import SCMWebhookError, SCMWebhookErrorCode


class RunAdmissionService:
    """Coordinate durable persistence, tenant quota, and exact-identity enqueue."""

    __slots__ = (
        "_authorization",
        "_clock",
        "_identity_resolver",
        "_policy_pin_validator",
        "_queue",
        "_residency_guard",
        "_residency_region",
        "_resource_policy",
        "_resources",
        "_store",
    )

    def __init__(
        self,
        *,
        store: RunAdmissionStore,
        resources: ResourceReservationPort,
        queue: WorkerQueuePort,
        authorization: AuthorizationPort,
        clock: AdmissionClock,
        default_resource_policy: ResourceRequestPolicy,
        identity_resolver: RunIdentityResolver | None = None,
        policy_pin_validator: RunPolicyPinValidator | None = None,
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
    ) -> None:
        for dependency in (
            store,
            resources,
            queue,
            authorization,
            clock,
            default_resource_policy,
        ):
            if dependency is None:
                raise TypeError("run admission dependency is missing")
        if (residency_guard is None) != (residency_region is None):
            raise TypeError("run admission residency configuration is incomplete")
        if policy_pin_validator is not None and not callable(policy_pin_validator):
            raise TypeError("run admission policy validator is invalid")
        if residency_guard is not None and not callable(
            getattr(residency_guard, "require_region", None)
        ):
            raise TypeError("run admission residency guard is invalid")
        self._store = store
        self._resources = resources
        self._queue = queue
        self._authorization = authorization
        self._clock = clock
        self._resource_policy = default_resource_policy
        self._identity_resolver = identity_resolver
        self._policy_pin_validator = policy_pin_validator
        self._residency_guard = residency_guard
        self._residency_region = residency_region

    def create(self, request: ServiceRequest) -> ServiceResponse:
        request = self._resolve_shorthand(request)
        identity, run_id, idempotency_key = self._validate_request(request)
        revision = identity.repository_revision
        self._validate_policy_pin(identity)
        try:
            allowed = self._authorization.allows(
                request.identity,
                action="runs.create",
                repository_id=revision.repository_id,
            )
        except Exception:
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503) from None
        if revision.tenant_id != request.identity.tenant_id or not allowed:
            raise AdmissionError(AdmissionErrorCode.FORBIDDEN, 403)
        if self._residency_guard is not None:
            region = self._residency_region
            if region is None:
                raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)
            try:
                decision = self._residency_guard.require_region(
                    tenant_id=revision.tenant_id,
                    region=region,
                )
            except ResidencyConflict:
                raise AdmissionError(AdmissionErrorCode.FORBIDDEN, 403) from None
            except Exception:
                raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503) from None
            if (
                type(decision) is not ResidencyDecision
                or decision.tenant_id != revision.tenant_id
                or decision.source_region != region
                or decision.destination_region != region
                or not decision.same_region
            ):
                raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)

        digest = request_sha256(request.method, request.route, request.raw_body)
        record = self._store.find(
            tenant_id=revision.tenant_id,
            idempotency_key=idempotency_key,
            request_sha256=digest,
        )
        if record is None:
            now_ms = self._now_ms()
            resource_request = self._resource_policy.build(
                idempotency_key=idempotency_key,
                run_id=run_id,
                execution_identity=identity,
                now_ms=now_ms,
            )
            record = self._store.begin(
                tenant_id=revision.tenant_id,
                idempotency_key=idempotency_key,
                request_sha256=digest,
                run_id=run_id,
                execution_identity=identity,
                resource_request=resource_request,
                metadata={
                    **_safe_metadata(request.document),
                    **_safe_server_context(request.server_context),
                },
                now_ms=now_ms,
            )
        _require_exact_record(record, identity, run_id)
        return self._resume(record, identity, request.document)

    def _validate_policy_pin(self, identity: RunExecutionIdentity) -> None:
        validator = self._policy_pin_validator
        if validator is None:
            return
        try:
            validator(identity)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except ProfileConflict:
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503) from None
        except (TypeError, ValueError):
            raise AdmissionError(AdmissionErrorCode.RUN_CONFLICT, 409) from None
        except Exception:
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503) from None

    def _bind_publication(
        self,
        document: Mapping[str, object] | None,
        identity: RunExecutionIdentity,
        run_id: str,
    ) -> None:
        binder = getattr(self._identity_resolver, "bind_publication", None)
        if binder is None:
            return
        if not callable(binder):
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)
        try:
            binder(run_id=run_id, identity=identity, document=document)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except AdmissionError:
            raise
        except Exception:
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503) from None

    def _resume(
        self,
        record: AdmissionRecord,
        identity: RunExecutionIdentity,
        document: Mapping[str, object] | None,
    ) -> ServiceResponse:
        if record.state is AdmissionState.ADMITTED:
            run_document = self._store.run_document(record)
            if run_document.get("state") not in {
                "SUCCEEDED",
                "FAILED",
                "INDETERMINATE",
                "CANCELLED",
                "SUPERSEDED",
            } and not self._admitted_reservation_is_active(record):
                recovered = self._recover_expired_admitted(record)
                run_document = self._store.run_document(recovered)
            self._bind_publication(document, identity, record.run_id)
            return ServiceResponse(201, run_document)
        if record.state in {AdmissionState.FAILED, AdmissionState.RECOVERY_REQUIRED}:
            code = record.failure_code or AdmissionErrorCode.SERVICE_UNAVAILABLE
            raise AdmissionError(code, _status_for(code, record.state))

        if record.state is AdmissionState.PERSISTED:
            if self._now_ms() >= record.resource_request.lease_expires_at_ms:
                self._fail_closed(
                    record,
                    AdmissionErrorCode.SERVICE_UNAVAILABLE,
                    recovery_required=True,
                )
            receipt = self._reserve(record)
            try:
                record = self._store.reserved(record, receipt, now_ms=self._now_ms())
            except Exception:
                released = self._release(record, receipt)
                self._fail_closed(
                    record,
                    AdmissionErrorCode.SERVICE_UNAVAILABLE,
                    recovery_required=not released,
                )

        if record.state is not AdmissionState.RESERVED:
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)
        if self._now_ms() >= record.resource_request.lease_expires_at_ms:
            released = self._release_record(record)
            self._fail_closed(
                record,
                AdmissionErrorCode.SERVICE_UNAVAILABLE,
                recovery_required=not released,
            )
        try:
            self._queue.enqueue(
                tenant_id=record.tenant_id,
                run_id=record.run_id,
                execution_identity=identity,
            )
        except Exception:
            released = self._release_record(record)
            self._fail_closed(
                record,
                AdmissionErrorCode.SERVICE_UNAVAILABLE,
                recovery_required=not released,
            )
        try:
            self._bind_publication(document, identity, record.run_id)
        except Exception:
            released = self._release_record(record)
            self._fail_closed(
                record,
                AdmissionErrorCode.SERVICE_UNAVAILABLE,
                recovery_required=not released,
            )
        try:
            admitted = self._store.admitted(record, now_ms=self._now_ms())
        except Exception:
            released = self._release_record(record)
            self._fail_closed(
                record,
                AdmissionErrorCode.SERVICE_UNAVAILABLE,
                recovery_required=not released,
            )
        return ServiceResponse(201, self._store.run_document(admitted))

    def _admitted_reservation_is_active(self, record: AdmissionRecord) -> bool:
        if record.reservation_id is None or record.reservation_version is None:
            return False
        checker = getattr(self._resources, "is_active", None)
        if not callable(checker):
            return False
        try:
            return bool(
                checker(
                    tenant_id=record.tenant_id,
                    repository_id=record.repository_id,
                    run_id=record.run_id,
                    execution_identity_hash=record.execution_identity_hash,
                    reservation_id=record.reservation_id,
                    expected_version=record.reservation_version,
                    now_ms=self._now_ms(),
                )
            )
        except Exception:
            return False

    def _recover_expired_admitted(self, record: AdmissionRecord) -> AdmissionRecord:
        try:
            recovered = self._store.recover_admitted(
                record,
                code=AdmissionErrorCode.SERVICE_UNAVAILABLE,
                now_ms=self._now_ms(),
            )
            document = self._store.run_document(recovered)
        except AdmissionError:
            raise
        except Exception:
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503) from None
        if document.get("state") in {
            "SUCCEEDED",
            "FAILED",
            "INDETERMINATE",
            "CANCELLED",
            "SUPERSEDED",
        }:
            return recovered
        raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)

    def _resolve_shorthand(self, request: ServiceRequest) -> ServiceRequest:
        resolver = self._identity_resolver
        document = request.document
        if (
            resolver is None
            or document is None
            or not isinstance(document, Mapping)
            or request.action != "runs.create"
            or request.method != "POST"
            or request.route != "/api/v1/runs"
            or request.idempotency_key is None
        ):
            return request
        if "execution_identity" in document or "execution_identity_hash" in document:
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400)
        try:
            resolved = resolver.resolve(
                authenticated_tenant_id=request.identity.tenant_id,
                document=document,
            )
        except SCMWebhookError as error:
            if error.code in {
                SCMWebhookErrorCode.HEAD_UNAVAILABLE,
                SCMWebhookErrorCode.INVALID_CONFIGURATION,
            }:
                raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503) from None
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400) from None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400) from None
        if resolved is None:
            return request
        identity, run_id = resolved
        if type(identity) is not RunExecutionIdentity or not _identifier(run_id):
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400)
        expanded = dict(document)
        expanded["run_id"] = run_id
        expanded["execution_identity"] = identity.model_dump(mode="json")
        expanded["execution_identity_hash"] = identity.execution_identity_hash
        return replace(request, document=expanded)

    def _reserve(self, record: AdmissionRecord) -> ResourceReservationReceipt:
        try:
            return self._resources.reserve(record.resource_request)
        except ResourceGovernorError as error:
            code, status = _resource_error(error.code)
            self._fail_closed(record, code, recovery_required=False, status=status)
        except Exception:
            self._fail_closed(
                record,
                AdmissionErrorCode.SERVICE_UNAVAILABLE,
                recovery_required=True,
            )
        raise AssertionError("unreachable")

    def _release(self, record: AdmissionRecord, receipt: ResourceReservationReceipt) -> bool:
        try:
            self._resources.release(
                tenant_id=record.tenant_id,
                repository_id=record.repository_id,
                run_id=record.run_id,
                execution_identity_hash=record.execution_identity_hash,
                reservation_id=receipt.reservation_id,
                expected_version=receipt.state_version,
                now_ms=self._now_ms(),
                cancelled=True,
            )
        except Exception:
            return False
        return True

    def _release_record(self, record: AdmissionRecord) -> bool:
        if record.reservation_id is None or record.reservation_version is None:
            return False
        try:
            self._resources.release(
                tenant_id=record.tenant_id,
                repository_id=record.repository_id,
                run_id=record.run_id,
                execution_identity_hash=record.execution_identity_hash,
                reservation_id=record.reservation_id,
                expected_version=record.reservation_version,
                now_ms=self._now_ms(),
                cancelled=True,
            )
        except Exception:
            return False
        return True

    def _fail_closed(
        self,
        record: AdmissionRecord,
        code: AdmissionErrorCode,
        *,
        recovery_required: bool,
        status: int = 503,
    ) -> None:
        try:
            failed = self._store.failed(
                record,
                code=code,
                recovery_required=recovery_required,
                now_ms=self._now_ms(),
            )
        except Exception:
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503) from None
        terminal_code = failed.failure_code or AdmissionErrorCode.SERVICE_UNAVAILABLE
        terminal_status = _status_for(terminal_code, failed.state)
        if not recovery_required and terminal_code is code:
            terminal_status = status
        raise AdmissionError(terminal_code, terminal_status)

    def _now_ms(self) -> int:
        try:
            value = self._clock()
        except Exception:
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503) from None
        if type(value) is not int or not 0 <= value <= 9_223_372_036_854_775_807:
            raise AdmissionError(AdmissionErrorCode.SERVICE_UNAVAILABLE, 503)
        return value

    @staticmethod
    def _validate_request(
        request: ServiceRequest,
    ) -> tuple[RunExecutionIdentity, str, str]:
        if (
            request.action != "runs.create"
            or request.method != "POST"
            or request.route != "/api/v1/runs"
            or request.document is None
            or request.idempotency_key is None
        ):
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400)
        run_id = request.document.get("run_id")
        identity_document = request.document.get("execution_identity")
        identity_hash = request.document.get("execution_identity_hash")
        operation_value = request.document.get("operation", RunOperation.SCAN.value)
        if (
            type(run_id) is not str
            or not _identifier(run_id)
            or type(request.idempotency_key) is not str
            or not _identifier(request.idempotency_key)
            or type(identity_document) is not dict
            or type(identity_hash) is not str
        ):
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400)
        try:
            if not isinstance(operation_value, str):
                raise TypeError("run operation must be text")
            RunOperation(operation_value)
        except (TypeError, ValueError):
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400) from None
        try:
            identity = RunExecutionIdentity.model_validate(identity_document)
        except (TypeError, ValueError, ValidationError):
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400) from None
        if identity_hash != identity.execution_identity_hash:
            raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400)
        return identity, run_id, request.idempotency_key


class RunAdmissionHandler:
    """Handler-compatible safe boundary for ``CompositeService.optional``."""

    __slots__ = ("_service",)

    def __init__(self, service: RunAdmissionService) -> None:
        if not isinstance(service, RunAdmissionService):
            raise TypeError("service must be a RunAdmissionService")
        self._service = service

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action != "runs.create":
            raise ServiceUnavailableError()
        try:
            return self._service.create(request)
        except AdmissionError as error:
            return ServiceResponse(
                error.status,
                {"error": {"code": error.code.value, "message": safe_message(error.code)}},
            )
        except Exception:
            return ServiceResponse(
                503,
                {
                    "error": {
                        "code": AdmissionErrorCode.SERVICE_UNAVAILABLE.value,
                        "message": safe_message(AdmissionErrorCode.SERVICE_UNAVAILABLE),
                    }
                },
            )


class RunAdmissionRoutingService:
    """Install admission for one route while preserving the existing core handler."""

    __slots__ = ("_admission", "_fallback")

    def __init__(
        self,
        *,
        admission: RunAdmissionHandler,
        fallback: ControlPlaneService,
    ) -> None:
        if not isinstance(admission, RunAdmissionHandler) or not hasattr(fallback, "dispatch"):
            raise TypeError("run admission routing dependencies are invalid")
        self._admission = admission
        self._fallback = fallback

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action == "runs.create":
            return await self._admission.dispatch(request)
        response = await self._fallback.dispatch(request)
        if not isinstance(response, ServiceResponse):
            raise ServiceUnavailableError()
        return response

    def preflight_artifact_upload(self, request: ServiceRequest) -> str:
        preflight = getattr(self._fallback, "preflight_artifact_upload", None)
        if not callable(preflight):
            raise ServiceUnavailableError()
        artifact_id: str = preflight(request)
        return artifact_id


def _require_exact_record(
    record: AdmissionRecord, identity: RunExecutionIdentity, run_id: str
) -> None:
    revision = identity.repository_revision
    if (
        record.run_id != run_id
        or record.tenant_id != revision.tenant_id
        or record.repository_id != revision.repository_id
        or record.execution_identity_hash != identity.execution_identity_hash
        or record.identity_json != canonical(identity.model_dump(mode="json"))
    ):
        raise AdmissionError(AdmissionErrorCode.RUN_CONFLICT, 409)


def _safe_metadata(document: Mapping[str, object] | None) -> dict[str, object]:
    if document is None:
        return {}
    metadata: dict[str, object] = {
        key: value
        for key in ("request_id", "policy_id", "workflow_id")
        if type(value := document.get(key)) is str and _identifier(value)
    }
    try:
        operation = document.get("operation", RunOperation.SCAN.value)
        if not isinstance(operation, str):
            raise TypeError("run operation must be text")
        metadata["operation"] = RunOperation(operation).value
    except (TypeError, ValueError):
        raise AdmissionError(AdmissionErrorCode.INVALID_REQUEST, 400) from None
    return metadata


def _safe_server_context(context: Mapping[str, object]) -> dict[str, object]:
    trust = context.get("contribution_trust")
    if type(trust) is str and trust in {
        "TRUSTED_SAME_REPOSITORY",
        "UNTRUSTED_FORK",
        "UNTRUSTED_SAME_REPOSITORY",
        "UNKNOWN",
    }:
        return {"contribution_trust": trust}
    return {}


def _resource_error(
    code: ResourceGovernorErrorCode,
) -> tuple[AdmissionErrorCode, int]:
    mapping = {
        ResourceGovernorErrorCode.QUOTA_EXCEEDED: (
            AdmissionErrorCode.RESOURCE_QUOTA_EXCEEDED,
            429,
        ),
        ResourceGovernorErrorCode.RATE_LIMITED: (
            AdmissionErrorCode.RESOURCE_RATE_LIMITED,
            429,
        ),
        ResourceGovernorErrorCode.CONCURRENCY_EXCEEDED: (
            AdmissionErrorCode.RESOURCE_CONCURRENCY_EXCEEDED,
            429,
        ),
        ResourceGovernorErrorCode.CONFLICT: (
            AdmissionErrorCode.RESOURCE_CONFLICT,
            409,
        ),
    }
    return mapping.get(code, (AdmissionErrorCode.SERVICE_UNAVAILABLE, 503))


def _status_for(code: AdmissionErrorCode, state: AdmissionState) -> int:
    if state is AdmissionState.RECOVERY_REQUIRED:
        return 503
    if code in {
        AdmissionErrorCode.RESOURCE_QUOTA_EXCEEDED,
        AdmissionErrorCode.RESOURCE_RATE_LIMITED,
        AdmissionErrorCode.RESOURCE_CONCURRENCY_EXCEEDED,
    }:
        return 429
    if code in {
        AdmissionErrorCode.IDEMPOTENCY_CONFLICT,
        AdmissionErrorCode.RUN_CONFLICT,
        AdmissionErrorCode.RESOURCE_CONFLICT,
    }:
        return 409
    if code is AdmissionErrorCode.FORBIDDEN:
        return 403
    if code is AdmissionErrorCode.INVALID_REQUEST:
        return 400
    return 503


def _identifier(value: object) -> bool:
    if type(value) is not str or not 1 <= len(value) <= 128:
        return False
    return value[0].isalnum() and all(
        character.isascii() and (character.isalnum() or character in "._:-") for character in value
    )


__all__ = [
    "RunAdmissionHandler",
    "RunAdmissionRoutingService",
    "RunAdmissionService",
]
