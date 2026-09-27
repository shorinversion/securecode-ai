"""Small ASGI control-plane boundary with closed admission and safe failures."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Final, Protocol
from urllib.parse import parse_qs

from .http_boundary import (
    _IDEMPOTENCY,
    _MAX_BODY_BYTES,
    _MAX_QUERY_FIELDS,
    _MUTATING,
    _headers,
    _idempotency_key,
    _json_object,
    _login_transport_allowed,
    _match_route,
    _query,
    _read_body,
    _Route,
    _safe_message,
    _supports_version,
    _valid_precondition,
)
from .idempotency import ClaimState, InMemoryRequestReplayStore, RequestReplayStore
from .json_boundary import JsonBoundaryError, load_json_object
from .oidc_login import OidcLoginError, OidcLoginErrorCode, OidcLoginService
from .openapi import API_VERSION, CAPABILITIES, build_openapi_document
from .ports import (
    AuthorizationPort,
    ControlPlaneService,
    DenyAuthorization,
    DenyIdentityVerifier,
    IdentityVerifier,
    ReadinessPort,
    ServiceRequest,
    ServiceResponse,
    ServiceUnavailableError,
    StaticReadiness,
    UnavailableControlPlaneService,
    VerifiedIdentity,
)
from .request_quota import MAX_SPEND_MICROUNITS, QuotaError, QuotaErrorCode, RequestQuota
from .run_admission_models import request_sha256 as _run_request_sha256
from .request_scope import repository_id as _repository_id
from .sessions import SessionError, SessionStore
from .tenant_rate_limiter import TenantRateLimiter, TenantTokenBucketRateLimiter
from .telemetry import TelemetryRecorder


class RequestTelemetry(Protocol):
    def record(self, *, action: str, status: int, duration_ms: int) -> None: ...


_QUERY_ALLOWED: Final[dict[str, frozenset[str]]] = {
    "runs.list": frozenset({"cursor", "limit"}),
    "runs.events.read": frozenset({"cursor", "limit"}),
    "runs.findings.read": frozenset({"cursor", "limit"}),
    "runs.artifacts.read": frozenset({"cursor", "limit", "content_sha256"}),
    "runs.repair_patches.content": frozenset({"patch_sha256"}),
    "runs.audit.read": frozenset({"start", "end"}),
    "policies.read": frozenset({"cursor", "limit"}),
    "feedback.metrics.read": frozenset({"repository_id"}),
    "assurance.read": frozenset({"repository_id", "execution_identity_hash", "view"}),
}
_QUERY_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,1024}\Z")
_QUERY_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_QUERY_IDENTIFIER = re.compile(r"[\x21-\x7e]{1,256}\Z")
_QUERY_INTEGER_MAX = 9_223_372_036_854_775_807
_SCM_RECONCILE_INTERVAL_SECONDS: Final[float] = 15.0


class ServerApp:
    def __init__(
        self,
        *,
        identities: IdentityVerifier | None = None,
        authorization: AuthorizationPort | None = None,
        service: ControlPlaneService | None = None,
        readiness: ReadinessPort | None = None,
        replay_store: RequestReplayStore | None = None,
        webhook_identity: VerifiedIdentity | None = None,
        artifact_upload_identity: VerifiedIdentity | None = None,
        telemetry: RequestTelemetry | None = None,
        oidc_login: OidcLoginService | None = None,
        sessions: SessionStore | None = None,
        quota: RequestQuota | None = None,
        quota_run_cost_microunits: int | None = None,
        rate_limiter: TenantRateLimiter | None = None,
        capabilities: tuple[str, ...] = CAPABILITIES,
        max_body_bytes: int = _MAX_BODY_BYTES,
        background_reconcile: Callable[[], object] | None = None,
        shutdown_callback: Callable[[], object] | None = None,
    ) -> None:
        if (
            type(max_body_bytes) is not int
            or not 1 <= max_body_bytes <= _MAX_BODY_BYTES
            or type(capabilities) is not tuple
            or len(set(capabilities)) != len(capabilities)
            or any(type(value) is not str or not value for value in capabilities)
            or (oidc_login is not None and type(oidc_login) is not OidcLoginService)
            or (sessions is not None and type(sessions) is not SessionStore)
            or (oidc_login is not None and type(sessions) is not SessionStore)
            or (
                quota_run_cost_microunits is not None
                and (
                    type(quota_run_cost_microunits) is not int
                    or not 0 <= quota_run_cost_microunits <= MAX_SPEND_MICROUNITS
                )
            )
            or (rate_limiter is not None and not callable(getattr(rate_limiter, "allow", None)))
            or (background_reconcile is not None and not callable(background_reconcile))
            or (shutdown_callback is not None and not callable(shutdown_callback))
        ):
            raise ValueError("server application settings are invalid")
        self._telemetry = telemetry if telemetry is not None else TelemetryRecorder()
        self._oidc_login = oidc_login
        self._sessions = sessions
        self._quota = quota
        self._quota_run_cost_microunits = quota_run_cost_microunits
        self._rate_limiter = (
            rate_limiter if rate_limiter is not None else TenantTokenBucketRateLimiter()
        )
        self._identities = identities or DenyIdentityVerifier()
        self._authorization = authorization or DenyAuthorization()
        self._service = service or UnavailableControlPlaneService()
        self._readiness = readiness or StaticReadiness()
        self._replay_store = replay_store or InMemoryRequestReplayStore()
        self._webhook_identity = webhook_identity
        self._artifact_upload_identity = artifact_upload_identity
        self._capabilities = capabilities
        self._max_body_bytes = max_body_bytes
        self._background_reconcile = background_reconcile
        self._background_task: asyncio.Task[None] | None = None
        self._shutdown_callback = shutdown_callback
        self._shutdown_complete = False
        self._shutdown_task: asyncio.Task[None] | None = None

    async def __call__(
        self,
        scope: Mapping[str, object],
        receive: Callable[[], Awaitable[Mapping[str, object]]],
        send: Callable[[Mapping[str, object]], Awaitable[None]],
    ) -> None:
        if self._shutdown_task is not None or self._shutdown_complete:
            await self._send_error(send, 503, "SERVICE_SHUTTING_DOWN", secrets.token_hex(16))
            return
        self._start_background_reconciler()
        started_at = time.monotonic()
        status = 500

        async def observe_send(message: Mapping[str, object]) -> None:
            nonlocal status
            if message.get("type") == "http.response.start":
                candidate = message.get("status")
                if type(candidate) is int and 100 <= candidate <= 599:
                    status = candidate
            await send(message)

        try:
            await self._handle_request(scope, receive, observe_send)
        finally:
            self._record_observation(_telemetry_action(scope), status, started_at)

    def _start_background_reconciler(self) -> None:
        if self._background_reconcile is None or self._background_task is not None:
            return
        self._background_task = asyncio.create_task(self._run_background_reconciler())

    async def startup(self) -> None:
        """Start application-owned recovery work before accepting requests."""

        if self._shutdown_complete:
            raise RuntimeError("server application is already shut down")
        self._start_background_reconciler()

    async def shutdown(self) -> None:
        """Stop application-owned background work during server shutdown."""

        if self._shutdown_complete:
            return
        task = self._shutdown_task
        if task is None:
            task = asyncio.create_task(self._finish_shutdown())
            self._shutdown_task = task
        await asyncio.shield(task)

    async def _finish_shutdown(self) -> None:
        self._shutdown_complete = True
        task = self._background_task
        self._background_task = None
        try:
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
        finally:
            if self._shutdown_callback is not None:
                self._shutdown_callback()

    async def _run_background_reconciler(self) -> None:
        while True:
            try:
                callback = self._background_reconcile
                if callback is not None:
                    callback()
            except asyncio.CancelledError:
                raise
            except Exception:
                await asyncio.sleep(_SCM_RECONCILE_INTERVAL_SECONDS)
                continue
            await asyncio.sleep(_SCM_RECONCILE_INTERVAL_SECONDS)

    async def _handle_request(
        self,
        scope: Mapping[str, object],
        receive: Callable[[], Awaitable[Mapping[str, object]]],
        send: Callable[[Mapping[str, object]], Awaitable[None]],
    ) -> None:
        correlation_id = secrets.token_hex(16)
        if scope.get("type") != "http":
            await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
            return
        method = scope.get("method")
        path = scope.get("path")
        if type(method) is not str or type(path) is not str:
            await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
            return
        query_string = _query(scope.get("query_string"))
        if query_string is None:
            await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
            return
        if path in {
            "/api/v1/auth/login",
            "/api/v1/auth/callback",
            "/api/v1/auth/logout",
            "/api/v1/capabilities",
            "/api/v1/health/live",
            "/api/v1/health/ready",
            "/api/v1/openapi.json",
        } and query_string:
            await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
            return
        headers = _headers(scope.get("headers"))
        if not _supports_version(headers):
            await self._send_error(send, 422, "UNSUPPORTED_VERSION", correlation_id)
            return
        if path in {
            "/api/v1/auth/login",
            "/api/v1/auth/callback",
            "/api/v1/auth/logout",
        } and not _login_transport_allowed(scope):
            await self._send_error(send, 403, "INSECURE_TRANSPORT", correlation_id)
            return
        if path == "/api/v1/health/live" and method == "GET":
            await self._send_json(send, 200, {"status": "live", "api_version": API_VERSION})
            return
        if path == "/api/v1/health/ready" and method == "GET":
            status = 200 if self._readiness.ready() else 503
            await self._send_json(
                send, status, {"status": "ready" if status == 200 else "not_ready"}
            )
            return
        if path == "/api/v1/capabilities" and method == "GET":
            await self._send_json(
                send,
                200,
                {"api_version": API_VERSION, "capabilities": self._capabilities},
            )
            return
        if path == "/api/v1/auth/login" and method == "POST":
            login_body = await _read_body(receive, self._max_body_bytes)
            if login_body is None:
                await self._send_error(send, 413, "BODY_TOO_LARGE", correlation_id)
                return
            if login_body:
                await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
                return
            await self._send_login_start(
                send,
                correlation_id,
                rate_limit_key=_login_rate_limit_key(scope),
            )
            return
        if path == "/api/v1/openapi.json" and method == "GET":
            await self._send_json(send, 200, build_openapi_document())
            return
        if path == "/api/v1/auth/callback" and method == "POST":
            callback_body = await _read_body(receive, self._max_body_bytes)
            if callback_body is None:
                await self._send_error(send, 413, "BODY_TOO_LARGE", correlation_id)
                return
            await self._send_login_callback(
                send,
                callback_body,
                correlation_id,
                rate_limit_key=_login_rate_limit_key(scope),
            )
            return
        if path == "/api/v1/auth/logout" and method == "POST":
            logout_body = await _read_body(receive, self._max_body_bytes)
            if logout_body is None:
                await self._send_error(send, 413, "BODY_TOO_LARGE", correlation_id)
                return
            if logout_body:
                await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
                return
            await self._send_logout(send, headers, correlation_id)
            return
        route, params = _match_route(method, path)
        if route is None:
            await self._send_error(send, 404, "NOT_FOUND", correlation_id)
            return
        identity = (
            self._self_authenticated_identity(route)
            if route.self_authenticated
            else self._identity(headers)
        )
        if identity is None:
            await self._send_error(send, 401, "UNAUTHENTICATED", correlation_id)
            return
        try:
            rate_decision = self._rate_limiter.allow(
                tenant_id=identity.tenant_id,
            )
        except Exception:
            await self._send_error(send, 503, "SERVICE_UNAVAILABLE", correlation_id)
            return
        if not rate_decision.allowed:
            await self._send_json(
                send,
                429,
                {"error": {"code": "RATE_LIMIT_EXCEEDED", "correlation_id": correlation_id}},
                {"Retry-After": str(rate_decision.retry_after_seconds)},
            )
            return
        body = await _read_body(receive, self._max_body_bytes)
        if body is None:
            await self._send_error(send, 413, "BODY_TOO_LARGE", correlation_id)
            return
        if route.workload_only and not identity.workload:
            await self._send_error(send, 403, "FORBIDDEN", correlation_id)
            return
        document = (
            None
            if route.raw_body
            else {}
            if not body and method not in _MUTATING
            else _json_object(body)
        )
        if not route.raw_body and document is None:
            await self._send_error(send, 400, "INVALID_JSON", correlation_id)
            return
        if route.action.startswith("worker_sessions.") and (
            type(document) is not dict or document.get("worker_id") != identity.subject_id
        ):
            await self._send_error(send, 403, "FORBIDDEN", correlation_id)
            return
        try:
            query = _parse_query(route.action, query_string)
        except (UnicodeDecodeError, ValueError):
            query = None
        if query is None:
            await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
            return
        repository_id = params.get("repository_id") or _repository_id(document, query)
        if not self._authorization.allows(
            identity, action=route.action, repository_id=repository_id
        ):
            await self._send_error(send, 403, "FORBIDDEN", correlation_id)
            return
        key = _idempotency_key(route, method, headers)
        if method in _MUTATING and (key is None or _IDEMPOTENCY.fullmatch(key) is None):
            await self._send_error(send, 400, "IDEMPOTENCY_KEY_REQUIRED", correlation_id)
            return
        precondition = headers.get("if-match")
        if route.needs_precondition and not _valid_precondition(precondition):
            await self._send_error(send, 412, "PRECONDITION_REQUIRED", correlation_id)
            return
        # Run admission, worker claims, and SCM webhooks own replay in their
        # domain stores. Admission must resume its persisted saga, worker claims
        # must revalidate the lease and reservation, and webhooks must verify
        # provider authentication before a duplicate delivery can be returned.
        domain_owned_replay = route.action in {
            "runs.create",
            "worker_sessions.create",
        } or route.action.startswith("webhooks.")
        if key is not None and not domain_owned_replay:
            try:
                claim = self._replay_store.claim(
                    tenant_id=identity.tenant_id,
                    key=key,
                    method=method,
                    path=path,
                    body=body,
                    precondition=precondition,
                )
            except Exception:
                await self._send_error(send, 503, "SERVICE_UNAVAILABLE", correlation_id)
                return
            if claim.state is ClaimState.CONFLICT:
                await self._send_error(send, 409, "IDEMPOTENCY_CONFLICT", correlation_id)
                return
            if claim.state is ClaimState.IN_FLIGHT:
                await self._send_error(send, 409, "IDEMPOTENCY_IN_FLIGHT", correlation_id)
                return
            if claim.state is ClaimState.REPLAY and claim.response is not None:
                await self._send_json(
                    send,
                    200 if claim.response.status == 201 else claim.response.status,
                    dict(claim.response.document),
                    claim.response.headers,
                )
                return
        service_request = ServiceRequest(
            method=method,
            route=route.pattern,
            action=route.action,
            identity=identity,
            idempotency_key=key,
            precondition=precondition,
            path_params=params,
            query=query,
            document=document,
            raw_body=body,
            headers=headers,
        )
        target_tenant = identity.tenant_id
        if route.action == "artifacts.upload":
            try:
                target_tenant = _preflight_artifact_upload(
                    self._service,
                    service_request,
                )
            except ServiceUnavailableError:
                self._release_idempotency(identity, key)
                await self._send_error(send, 503, "SERVICE_UNAVAILABLE", correlation_id)
                return
            except Exception:
                self._release_idempotency(identity, key)
                await self._send_error(send, 403, "FORBIDDEN", correlation_id)
                return
            if target_tenant != identity.tenant_id:
                try:
                    target_rate = self._rate_limiter.allow(tenant_id=target_tenant)
                except Exception:
                    self._release_idempotency(identity, key)
                    await self._send_error(send, 503, "SERVICE_UNAVAILABLE", correlation_id)
                    return
                if not target_rate.allowed:
                    self._release_idempotency(identity, key)
                    await self._send_json(
                        send,
                        429,
                        {"error": {"code": "RATE_LIMIT_EXCEEDED", "correlation_id": correlation_id}},
                        {"Retry-After": str(target_rate.retry_after_seconds)},
                    )
                    return
        # Charge routed API work only after replay resolution and, for artifact
        # uploads, after preflight binds the signed tenant. This prevents a
        # worker credential tenant from being charged in addition to the
        # artifact owner tenant.
        if self._quota is not None:
            try:
                quota_now_ms = time.time_ns() // 1_000_000
                quota_cost = _quota_cost_microunits(
                    route.action,
                    run_cost_microunits=self._quota_run_cost_microunits,
                )
                idempotent_run_charge = getattr(
                    self._quota,
                    "check_idempotent_run",
                    None,
                )
                if route.action == "runs.create" and key is not None and callable(
                    idempotent_run_charge
                ):
                    decision = idempotent_run_charge(
                        tenant_id=target_tenant,
                        now_ms=quota_now_ms,
                        cost_microunits=quota_cost,
                        idempotency_key=key,
                        request_sha256=_run_request_sha256(method, route.pattern, body),
                    )
                else:
                    decision = self._quota.check(
                        tenant_id=target_tenant,
                        now_ms=quota_now_ms,
                        cost_microunits=quota_cost,
                    )
            except QuotaError as error:
                self._release_idempotency(identity, key)
                if error.code is QuotaErrorCode.IDEMPOTENCY_CONFLICT:
                    await self._send_error(send, 409, error.code.value, correlation_id)
                    return
                await self._send_error(send, 503, "QUOTA_UNAVAILABLE", correlation_id)
                return
            if not decision.allowed:
                self._release_idempotency(identity, key)
                await self._send_json(
                    send,
                    429,
                    {"error": {"code": "QUOTA_EXCEEDED", "correlation_id": correlation_id}},
                    {"Retry-After": str(decision.retry_after_seconds)},
                )
                return
        try:
            response = await self._service.dispatch(service_request)
        except ServiceUnavailableError:
            self._release_idempotency(identity, key)
            await self._send_error(send, 503, "SERVICE_UNAVAILABLE", correlation_id)
            return
        except Exception:
            self._release_idempotency(identity, key)
            await self._send_error(send, 500, "OPERATION_FAILED", correlation_id)
            return
        if not domain_owned_replay:
            try:
                self._complete_idempotency(identity, key, response)
            except Exception:
                await self._send_error(send, 503, "SERVICE_UNAVAILABLE", correlation_id)
                return
        if response.raw_body is None:
            await self._send_json(send, response.status, dict(response.document), response.headers)
        else:
            await self._send_bytes(
                send,
                response.status,
                response.raw_body,
                response.headers,
                correlation_id=correlation_id,
            )

    def _identity(self, headers: Mapping[str, str]) -> VerifiedIdentity | None:
        value = headers.get("authorization")
        if value is None or not value.startswith("Bearer "):
            return None
        token = value.removeprefix("Bearer ")
        if not token or len(token) > 8192:
            return None
        try:
            identity = self._identities.verify_bearer(token)
        except Exception:
            return None
        return identity if type(identity) is VerifiedIdentity else None

    def _self_authenticated_identity(self, route: _Route) -> VerifiedIdentity | None:
        if route.action.startswith("webhooks."):
            return self._webhook_identity
        if route.action == "artifacts.upload":
            return self._artifact_upload_identity
        return None

    def _complete_idempotency(
        self, identity: VerifiedIdentity, key: str | None, response: ServiceResponse
    ) -> None:
        if key is None:
            return
        self._replay_store.complete(
            tenant_id=identity.tenant_id,
            key=key,
            response=response,
        )

    def _record_observation(self, action: str, status: int, started_at: float) -> None:
        """Record one redacted observation; telemetry never breaks a request."""

        try:
            elapsed_ms = int(max(0.0, (time.monotonic() - started_at) * 1000.0))
            self._telemetry.record(action=action, status=status, duration_ms=elapsed_ms)
        except Exception:
            return

    def _release_idempotency(self, identity: VerifiedIdentity, key: str | None) -> None:
        if key is not None:
            try:
                self._replay_store.release(tenant_id=identity.tenant_id, key=key)
            except Exception:
                return

    async def _send_login_start(
        self,
        send: Callable[[Mapping[str, object]], Awaitable[None]],
        correlation_id: str,
        *,
        rate_limit_key: str,
    ) -> None:
        """Hand out one login attempt handle; unconfigured servers fail closed."""

        if self._oidc_login is None:
            await self._send_error(send, 503, "AUTH_NOT_CONFIGURED", correlation_id)
            return
        try:
            start = self._oidc_login.start(rate_limit_key=rate_limit_key)
        except OidcLoginError as error:
            if error.code is OidcLoginErrorCode.RATE_LIMITED:
                await self._send_json(
                    send,
                    429,
                    {"error": {"code": error.code.value, "correlation_id": correlation_id}},
                    {
                        "Retry-After": str(error.retry_after_seconds),
                        "Cache-Control": "no-store",
                        "Pragma": "no-cache",
                    },
                )
            else:
                await self._send_error(send, 503, "AUTH_UNAVAILABLE", correlation_id)
            return
        except Exception:
            await self._send_error(send, 503, "AUTH_UNAVAILABLE", correlation_id)
            return
        await self._send_json(
            send,
            200,
            start.document(),
            {"cache-control": "no-store", "pragma": "no-cache"},
        )

    async def _send_login_callback(
        self,
        send: Callable[[Mapping[str, object]], Awaitable[None]],
        body: bytes,
        correlation_id: str,
        *,
        rate_limit_key: str,
    ) -> None:
        """Exchange a callback token for a verified principal, or fail closed."""

        if self._oidc_login is None:
            await self._send_error(send, 503, "AUTH_NOT_CONFIGURED", correlation_id)
            return
        try:
            document = load_json_object(body)
        except JsonBoundaryError:
            await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
            return
        token = document.get("token")
        nonce = document.get("nonce")
        state = document.get("state")
        if type(token) is not str or type(nonce) is not str or type(state) is not str:
            await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
            return
        try:
            receipt = self._oidc_login.callback(
                token=token,
                nonce=nonce,
                state=state,
                rate_limit_key=rate_limit_key,
            )
        except OidcLoginError as error:
            if error.code is OidcLoginErrorCode.RATE_LIMITED:
                await self._send_json(
                    send,
                    429,
                    {"error": {"code": error.code.value, "correlation_id": correlation_id}},
                    {
                        "Retry-After": str(error.retry_after_seconds),
                        "Cache-Control": "no-store",
                        "Pragma": "no-cache",
                    },
                )
                return
            await self._send_error(send, 401, error.code.value, correlation_id)
            return
        except Exception:
            await self._send_error(send, 401, "TOKEN_REJECTED", correlation_id)
            return
        await self._send_json(
            send,
            200,
            receipt.document(),
            {"cache-control": "no-store", "pragma": "no-cache"},
        )

    async def _send_logout(
        self,
        send: Callable[[Mapping[str, object]], Awaitable[None]],
        headers: Mapping[str, str],
        correlation_id: str,
    ) -> None:
        if self._sessions is None:
            await self._send_error(send, 503, "AUTH_NOT_CONFIGURED", correlation_id)
            return
        value = headers.get("authorization")
        if value is None or not value.startswith("Bearer "):
            await self._send_error(send, 401, "SESSION_REJECTED", correlation_id)
            return
        if self._identity(headers) is None:
            await self._send_error(send, 401, "SESSION_REJECTED", correlation_id)
            return
        try:
            self._sessions.revoke_session(value.removeprefix("Bearer "))
        except SessionError:
            await self._send_error(send, 401, "SESSION_REJECTED", correlation_id)
            return
        await self._send_json(
            send,
            200,
            {"status": "logged_out"},
            {"cache-control": "no-store", "pragma": "no-cache"},
        )

    async def _send_error(
        self,
        send: Callable[[Mapping[str, object]], Awaitable[None]],
        status: int,
        code: str,
        correlation_id: str,
    ) -> None:
        await self._send_json(
            send,
            status,
            {
                "error": {
                    "code": code,
                    "message": _safe_message(code),
                    "correlation_id": correlation_id,
                }
            },
        )

    async def _send_json(
        self,
        send: Callable[[Mapping[str, object]], Awaitable[None]],
        status: int,
        document: Mapping[str, object],
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        payload = json.dumps(
            document, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(payload)).encode("ascii")),
            (b"x-content-type-options", b"nosniff"),
        ]
        if extra_headers is not None:
            headers.extend(
                (key.lower().encode("ascii"), value.encode("ascii"))
                for key, value in extra_headers.items()
            )
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})

    async def _send_bytes(
        self,
        send: Callable[[Mapping[str, object]], Awaitable[None]],
        status: int,
        payload: bytes,
        extra_headers: Mapping[str, str] | None = None,
        *,
        correlation_id: str,
    ) -> None:
        if type(payload) is not bytes or len(payload) > _MAX_BODY_BYTES:
            await self._send_error(send, 503, "SERVICE_UNAVAILABLE", correlation_id)
            return
        headers = [
            (b"content-type", b"application/octet-stream"),
            (b"content-length", str(len(payload)).encode("ascii")),
            (b"x-content-type-options", b"nosniff"),
        ]
        if extra_headers is not None:
            headers.extend(
                (key.lower().encode("ascii"), value.encode("ascii"))
                for key, value in extra_headers.items()
                if key.lower() != "content-type"
            )
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": payload})


def create_app(**kwargs: object) -> ServerApp:
    return ServerApp(**kwargs)  # type: ignore[arg-type]


def _quota_cost_microunits(action: str, *, run_cost_microunits: int | None) -> int | None:
    """Return the admission cost for a routed API operation.

    Run creation has a durable resource reservation whose configured cost is
    known before dispatch. Other HTTP operations do not invoke a model and
    therefore have an explicit zero cost. A missing run estimate stays unknown
    so an active spend ceiling rejects the request instead of charging zero.
    """

    if action == "runs.create":
        return run_cost_microunits
    return 0


def _login_rate_limit_key(scope: Mapping[str, object]) -> str:
    """Hash the socket peer address without trusting forwarded headers."""
    client = scope.get("client")
    if type(client) is not tuple or len(client) < 1 or type(client[0]) is not str:
        return "default"
    try:
        address = ipaddress.ip_address(client[0])
    except ValueError:
        return "default"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return hashlib.sha256(b"securecode.oidc.login-source.v1\0" + address.packed).hexdigest()


def _telemetry_action(scope: Mapping[str, object]) -> str:
    """Resolve a source-free action label from a static route, never raw paths."""
    if scope.get("type") != "http":
        return "http.invalid"
    method = scope.get("method")
    path = scope.get("path")
    if type(method) is not str or type(path) is not str:
        return "http.invalid"
    action = {
        ("POST", "/api/v1/auth/login"): "auth.login",
        ("POST", "/api/v1/auth/callback"): "auth.callback",
        ("POST", "/api/v1/auth/logout"): "auth.logout",
        ("GET", "/api/v1/capabilities"): "capabilities.read",
        ("GET", "/api/v1/health/live"): "health.live",
        ("GET", "/api/v1/health/ready"): "health.ready",
        ("GET", "/api/v1/openapi.json"): "openapi.read",
    }.get((method, path))
    if action is not None:
        return action
    try:
        route, _ = _match_route(method, path)
    except Exception:
        return "http.invalid"
    return route.action if route is not None else "http.not_found"


def _preflight_artifact_upload(
    service: ControlPlaneService,
    request: ServiceRequest,
) -> str:
    preflight = getattr(service, "preflight_artifact_upload", None)
    if not callable(preflight):
        raise ServiceUnavailableError()
    tenant_id = preflight(request)
    if (
        type(tenant_id) is not str
        or not tenant_id
        or tenant_id != request.path_params.get("tenant_id")
        or tenant_id != request.headers.get("x-securecode-tenant-id")
    ):
        raise ValueError("artifact upload tenant binding is invalid")
    return tenant_id


def _parse_query(action: str, query_string: str) -> dict[str, tuple[str, ...]] | None:
    parsed = parse_qs(
        query_string,
        keep_blank_values=True,
        encoding="utf-8",
        errors="strict",
        max_num_fields=_MAX_QUERY_FIELDS,
    )
    allowed = _QUERY_ALLOWED.get(action, frozenset())
    if set(parsed) - allowed:
        return None
    query = {name: tuple(values) for name, values in parsed.items()}
    if any(len(values) != 1 for values in query.values()):
        return None
    if any(
        not _valid_query_value(name, values[0])
        for name, values in query.items()
    ):
        return None
    if action == "runs.artifacts.read" and "content_sha256" in query and (
        "cursor" in query or "limit" in query
    ):
        return None
    return query


def _valid_query_value(name: str, value: str) -> bool:
    if name in {"repository_id", "execution_identity_hash"}:
        if name == "execution_identity_hash":
            return _QUERY_SHA256.fullmatch(value) is not None
        return _QUERY_IDENTIFIER.fullmatch(value) is not None
    if name == "view":
        return value == "report"
    if name in {"content_sha256", "patch_sha256"}:
        return _QUERY_SHA256.fullmatch(value) is not None
    if name == "cursor":
        return _QUERY_CURSOR.fullmatch(value) is not None
    if name == "limit":
        if not value.isascii() or not value.isdecimal() or len(value) > 3:
            return False
        return 1 <= int(value) <= 100
    if name in {"start", "end"}:
        if not value.isascii() or not value.isdecimal() or len(value) > 19:
            return False
        return int(value) <= _QUERY_INTEGER_MAX
    return False
