"""Small ASGI control-plane boundary with closed admission and safe failures."""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import parse_qs

from .idempotency import ClaimState, InMemoryRequestReplayStore, RequestReplayStore
from .json_boundary import JsonBoundaryError, load_json_object
from .oidc_login import OidcLoginError, OidcLoginService
from .openapi import API_VERSION, CAPABILITIES, SUPPORTED_MAJOR, build_openapi_document
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
from .request_quota import QuotaLedger
from .request_scope import repository_id as _repository_id
from .telemetry import TelemetryRecorder

_MAX_BODY_BYTES: Final = 16_777_216
_IDEMPOTENCY: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
_PATH_PARAMETER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_VERSION_HEADER: Final = "x-securecode-api-version"
_MUTATING: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True, slots=True)
class _Route:
    method: str
    pattern: str
    action: str
    workload_only: bool = False
    needs_precondition: bool = False
    raw_body: bool = False
    self_authenticated: bool = False


_ROUTES: Final = (
    _Route("POST", "/api/v1/runs", "runs.create"),
    _Route("POST", "/api/v1/scm/runs:resolve", "scm.runs.resolve", workload_only=True),
    _Route("GET", "/api/v1/runs/{run_id}", "runs.read"),
    _Route("POST", "/api/v1/runs/{run_id}:cancel", "runs.cancel", needs_precondition=True),
    _Route("GET", "/api/v1/runs/{run_id}/events", "runs.events.read"),
    _Route("GET", "/api/v1/runs/{run_id}/findings", "runs.findings.read"),
    _Route("GET", "/api/v1/runs/{run_id}/artifacts", "runs.artifacts.read"),
    _Route("GET", "/api/v1/runs/{run_id}/audit", "runs.audit.read"),
    _Route("GET", "/api/v1/operations/metrics", "operations.metrics.read"),
    _Route("GET", "/api/v1/findings/{finding_id}", "findings.read"),
    _Route(
        "POST",
        "/api/v1/findings/{finding_id}/decisions",
        "findings.decide",
        needs_precondition=True,
    ),
    _Route("POST", "/api/v1/artifacts:authorize", "artifacts.authorize"),
    _Route(
        "PUT",
        "/api/v1/artifact-uploads/{tenant_id}/{content_sha256}/{authorization_id}",
        "artifacts.upload",
        raw_body=True,
        self_authenticated=True,
    ),
    _Route("GET", "/api/v1/policies", "policies.read"),
    _Route("POST", "/api/v1/approvals", "approvals.create"),
    _Route("GET", "/api/v1/approvals/{approval_id}", "approvals.read"),
    _Route(
        "POST",
        "/api/v1/approvals/{approval_id}:decide",
        "approvals.decide",
        needs_precondition=True,
    ),
    _Route("POST", "/api/v1/secret-grants", "secrets.grant"),
    _Route("GET", "/api/v1/secret-grants/{grant_id}", "secrets.read"),
    _Route(
        "POST",
        "/api/v1/secret-grants/{grant_id}:rotate",
        "secrets.rotate",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/secret-grants/{grant_id}:revoke",
        "secrets.revoke",
        needs_precondition=True,
    ),
    _Route("POST", "/api/v1/backups", "backups.create"),
    _Route("GET", "/api/v1/backups/{backup_id}", "backups.read"),
    _Route(
        "POST",
        "/api/v1/backups/{backup_id}:execute",
        "backups.execute",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/backups/{backup_id}:restore",
        "backups.restore",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/lifecycle/deletions",
        "lifecycle.deletions.create",
    ),
    _Route(
        "GET",
        "/api/v1/lifecycle/deletions/{deletion_id}",
        "lifecycle.deletions.read",
    ),
    _Route(
        "POST",
        "/api/v1/lifecycle/deletions/{deletion_id}:approve",
        "lifecycle.deletions.approve",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/lifecycle/deletions/{deletion_id}:legal-hold",
        "lifecycle.deletions.legal_hold",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/lifecycle/deletions/{deletion_id}:execute",
        "lifecycle.deletions.execute",
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/feedback",
        "feedback.submit",
        needs_precondition=True,
    ),
    _Route("GET", "/api/v1/feedback/metrics", "feedback.metrics.read"),
    _Route(
        "POST",
        "/api/v1/assurance",
        "assurance.append",
        needs_precondition=True,
    ),
    _Route("GET", "/api/v1/assurance", "assurance.read"),
    _Route(
        "POST",
        "/api/v1/integrations/github/webhook",
        "webhooks.github",
        raw_body=True,
        self_authenticated=True,
    ),
    _Route(
        "POST",
        "/api/v1/integrations/gitlab/webhook",
        "webhooks.gitlab",
        raw_body=True,
        self_authenticated=True,
    ),
    _Route("POST", "/api/v1/worker-sessions", "worker_sessions.create", workload_only=True),
    _Route(
        "POST",
        "/api/v1/worker-sessions/{session_id}:heartbeat",
        "worker_sessions.heartbeat",
        workload_only=True,
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/worker-sessions/{session_id}/events:append",
        "worker_sessions.events.append",
        workload_only=True,
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/worker-sessions/{session_id}/artifacts:commit",
        "worker_sessions.artifacts.commit",
        workload_only=True,
        needs_precondition=True,
    ),
    _Route(
        "POST",
        "/api/v1/worker-sessions/{session_id}:complete",
        "worker_sessions.complete",
        workload_only=True,
        needs_precondition=True,
    ),
)


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
        quota: QuotaLedger | None = None,
        capabilities: tuple[str, ...] = CAPABILITIES,
        max_body_bytes: int = _MAX_BODY_BYTES,
    ) -> None:
        if (
            type(max_body_bytes) is not int
            or not 1 <= max_body_bytes <= _MAX_BODY_BYTES
            or type(capabilities) is not tuple
            or len(set(capabilities)) != len(capabilities)
            or any(type(value) is not str or not value for value in capabilities)
        ):
            raise ValueError("server application settings are invalid")
        self._telemetry = telemetry if telemetry is not None else TelemetryRecorder()
        self._oidc_login = oidc_login
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
            decision = self._quota.check(
                tenant_id=identity.tenant_id,
                now_ms=int(time.monotonic() * 1000),
            )
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
        repository_id = _repository_id(document, query)
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
        await self._send_json(send, 200, self._oidc_login.start().document())

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
        if type(token) is not str or type(nonce) is not str:
            await self._send_error(send, 400, "INVALID_REQUEST", correlation_id)
            return
        try:
            receipt = self._oidc_login.callback(token=token, nonce=nonce)
        except OidcLoginError as error:
            await self._send_error(send, 401, error.code.value, correlation_id)
            return
        except Exception:
            await self._send_error(send, 401, "TOKEN_REJECTED", correlation_id)
            return
        await self._send_json(send, 200, receipt.document())

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


def _headers(value: object) -> dict[str, str]:
    if not isinstance(value, (list, tuple)):
        return {}
    output: dict[str, str] = {}
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(part, bytes) for part in item)
        ):
            return {}
        try:
            name, item_value = item[0].decode("ascii").lower(), item[1].decode("latin-1")
        except UnicodeDecodeError:
            return {}
        if name in output:
            return {}
        output[name] = item_value
    return output


async def _read_body(
    receive: Callable[[], Awaitable[Mapping[str, object]]], limit: int
) -> bytes | None:
    chunks: list[bytes] = []
    size = 0
    while True:
        event = await receive()
        if event.get("type") != "http.request":
            return None
        chunk = event.get("body", b"")
        if not isinstance(chunk, bytes):
            return None
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
        if not event.get("more_body", False):
            return b"".join(chunks)


def _json_object(body: bytes) -> dict[str, object] | None:
    try:
        return load_json_object(body)
    except JsonBoundaryError:
        return None


def _match_route(method: str, path: str) -> tuple[_Route | None, dict[str, str]]:
    parts = path.strip("/").split("/")
    for route in _ROUTES:
        template = route.pattern.strip("/").split("/")
        if route.method != method or len(template) != len(parts):
            continue
        parameters: dict[str, str] = {}
        for expected, actual in zip(template, parts, strict=True):
            parameter = _match_path_segment(expected, actual)
            if parameter is not None:
                name, value = parameter
                parameters[name] = value
            elif expected != actual:
                break
        else:
            return route, parameters
    return None, {}


def _match_path_segment(expected: str, actual: str) -> tuple[str, str] | None:
    opening = expected.find("{")
    closing = expected.find("}", opening + 1)
    if opening < 0 or closing < 0:
        return None
    name = expected[opening + 1 : closing]
    prefix = expected[:opening]
    suffix = expected[closing + 1 :]
    if not name or not actual.startswith(prefix) or not actual.endswith(suffix):
        return None
    end = len(actual) - len(suffix) if suffix else len(actual)
    value = actual[len(prefix) : end]
    if _PATH_PARAMETER.fullmatch(value) is None:
        return None
    return name, value


def _idempotency_key(
    route: _Route,
    method: str,
    headers: Mapping[str, str],
) -> str | None:
    if method not in _MUTATING:
        return None
    if route.action == "webhooks.github":
        return headers.get("x-github-delivery")
    if route.action == "webhooks.gitlab":
        return headers.get("x-gitlab-event-uuid")
    if route.action == "artifacts.upload":
        return headers.get("x-securecode-authorization-id")
    return headers.get("idempotency-key")


def _supports_version(headers: Mapping[str, str]) -> bool:
    value = headers.get(_VERSION_HEADER)
    if value is None:
        return True
    major = value.split(".", 1)[0]
    return major == str(SUPPORTED_MAJOR)


def _valid_precondition(value: str | None) -> bool:
    return value is not None and 1 <= len(value) <= 256 and "\r" not in value and "\n" not in value


def _query(value: object) -> str:
    return value.decode("ascii") if isinstance(value, bytes) else ""


def _safe_message(code: str) -> str:
    return {
        "INVALID_REQUEST": "request is invalid",
        "INVALID_JSON": "request JSON is invalid",
        "BODY_TOO_LARGE": "request body exceeds the allowed limit",
        "UNSUPPORTED_VERSION": "API version is unsupported",
        "UNAUTHENTICATED": "authentication is required",
        "FORBIDDEN": "request is not authorized",
        "NOT_FOUND": "resource was not found",
        "IDEMPOTENCY_KEY_REQUIRED": "a valid idempotency key is required",
        "IDEMPOTENCY_CONFLICT": "idempotency key conflicts with a prior request",
        "PRECONDITION_REQUIRED": "a current resource precondition is required",
        "SERVICE_UNAVAILABLE": "requested service is unavailable",
        "OPERATION_FAILED": "operation could not be completed",
    }.get(code, "request could not be completed")
