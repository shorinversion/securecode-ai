"""Small ASGI control-plane boundary with closed admission and safe failures."""

from __future__ import annotations

import json
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from urllib.parse import parse_qs

from .http_boundary import (
    _IDEMPOTENCY,
    _MAX_BODY_BYTES,
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
from .request_quota import QuotaError, RequestQuota
from .request_scope import repository_id as _repository_id
from .sessions import SessionError, SessionStore
from .telemetry import TelemetryRecorder


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
        telemetry: TelemetryRecorder | None = None,
        oidc_login: OidcLoginService | None = None,
        sessions: SessionStore | None = None,
        quota: RequestQuota | None = None,
        capabilities: tuple[str, ...] = CAPABILITIES,
        max_body_bytes: int = _MAX_BODY_BYTES,
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
        ):
            raise ValueError("server application settings are invalid")
        self._telemetry = telemetry if telemetry is not None else TelemetryRecorder()
        self._oidc_login = oidc_login
        self._sessions = sessions
        self._quota = quota
        self._identities = identities or DenyIdentityVerifier()
        self._authorization = authorization or DenyAuthorization()
        self._service = service or UnavailableControlPlaneService()
        self._readiness = readiness or StaticReadiness()
        self._replay_store = replay_store or InMemoryRequestReplayStore()
        self._webhook_identity = webhook_identity
        self._artifact_upload_identity = artifact_upload_identity
        self._capabilities = capabilities
        self._max_body_bytes = max_body_bytes

    async def __call__(
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
            await self._send_login_start(send, correlation_id)
            return
        if path == "/api/v1/openapi.json" and method == "GET":
            await self._send_json(send, 200, build_openapi_document())
            return
        if path == "/api/v1/auth/callback" and method == "POST":
            callback_body = await _read_body(receive, self._max_body_bytes)
            if callback_body is None:
                await self._send_error(send, 413, "BODY_TOO_LARGE", correlation_id)
                return
            await self._send_login_callback(send, callback_body, correlation_id)
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
        body = await _read_body(receive, self._max_body_bytes)
        if body is None:
            await self._send_error(send, 413, "BODY_TOO_LARGE", correlation_id)
            return
        identity = (
            self._self_authenticated_identity(route)
            if route.self_authenticated
            else self._identity(headers)
        )
        if identity is None:
            await self._send_error(send, 401, "UNAUTHENTICATED", correlation_id)
            return
        # Scope note: the quota charges routed API work, after the tenant is
        # known. Early unauthenticated routes (login, health, capabilities)
        # are not charged here; a login brute-force ceiling belongs with the
        # login flow itself, not with tenant accounting.
        if self._quota is not None:
            try:
                decision = self._quota.check(
                    tenant_id=identity.tenant_id,
                    now_ms=time.time_ns() // 1_000_000,
                )
            except QuotaError:
                await self._send_error(send, 503, "QUOTA_UNAVAILABLE", correlation_id)
                return
            if not decision.allowed:
                await self._send_json(
                    send,
                    429,
                    {"error": {"code": "QUOTA_EXCEEDED", "correlation_id": correlation_id}},
                    {"Retry-After": str(decision.retry_after_seconds)},
                )
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
        query = {
            name: tuple(values)
            for name, values in parse_qs(
                _query(scope.get("query_string")),
                keep_blank_values=True,
            ).items()
        }
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
        if key is not None:
            try:
                claim = self._replay_store.claim(
                    tenant_id=identity.tenant_id,
                    key=key,
                    method=method,
                    path=path,
                    body=body,
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
        started_at = time.monotonic()
        try:
            response = await self._service.dispatch(
                ServiceRequest(
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
            )
            self._record_observation(route.action, response.status, started_at)
        except ServiceUnavailableError:
            self._release_idempotency(identity, key)
            await self._send_error(send, 503, "SERVICE_UNAVAILABLE", correlation_id)
            return
        except Exception:
            self._release_idempotency(identity, key)
            await self._send_error(send, 500, "OPERATION_FAILED", correlation_id)
            return
        try:
            self._complete_idempotency(identity, key, response)
        except Exception:
            await self._send_error(send, 503, "SERVICE_UNAVAILABLE", correlation_id)
            return
        await self._send_json(send, response.status, dict(response.document), response.headers)

    def _identity(self, headers: Mapping[str, str]) -> VerifiedIdentity | None:
        value = headers.get("authorization")
        if value is None or not value.startswith("Bearer "):
            return None
        token = value.removeprefix("Bearer ")
        if not token or len(token) > 8192:
            return None
        return self._identities.verify_bearer(token)

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

        elapsed_ms = int(max(0.0, (time.monotonic() - started_at) * 1000.0))
        try:
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
        self, send: Callable[[Mapping[str, object]], Awaitable[None]], correlation_id: str
    ) -> None:
        """Hand out one login attempt handle; unconfigured servers fail closed."""

        if self._oidc_login is None:
            await self._send_error(send, 503, "AUTH_NOT_CONFIGURED", correlation_id)
            return
        try:
            start = self._oidc_login.start()
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
            receipt = self._oidc_login.callback(token=token, nonce=nonce, state=state)
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


def create_app(**kwargs: object) -> ServerApp:
    return ServerApp(**kwargs)  # type: ignore[arg-type]
