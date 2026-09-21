"""Route adapters for authenticated webhooks and worker sessions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .evidence_egress import EgressDenied, EgressPolicy, authorize
from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError
from .scm_webhooks import SCMWebhookError, SCMWebhookErrorCode
from .worker_sessions import WorkerDenied, WorkerSession, WorkerSessionStore


class RawWebhookAdapter(Protocol):
    async def handle_raw(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str],
        delivery_key: str | None,
    ) -> dict[str, object]: ...


class WebhookHandler:
    def __init__(self, adapter: RawWebhookAdapter) -> None:
        self._adapter = adapter

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.document is not None:
            raise ServiceUnavailableError()
        try:
            result = await self._adapter.handle_raw(
                request.raw_body,
                headers=request.headers,
                delivery_key=request.idempotency_key,
            )
        except SCMWebhookError as error:
            status = 401 if error.code is SCMWebhookErrorCode.AUTHENTICATION_FAILED else 409
            if error.code in {
                SCMWebhookErrorCode.INVALID_HEADERS,
                SCMWebhookErrorCode.PAYLOAD_INVALID,
                SCMWebhookErrorCode.IDENTITY_MISMATCH,
            }:
                status = 400
            elif error.code in {
                SCMWebhookErrorCode.HEAD_UNAVAILABLE,
                SCMWebhookErrorCode.INVALID_CONFIGURATION,
            }:
                status = 503
            return ServiceResponse(
                status,
                {
                    "error": {
                        "code": error.code.value,
                        "message": error.safe_message,
                    }
                },
            )
        return ServiceResponse(202, result)


class WorkerHandler:
    """Translate the versioned worker HTTP contract to the session store."""

    def __init__(self, sessions: WorkerSessionStore) -> None:
        self._sessions = sessions

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        try:
            session = self._dispatch(request)
        except WorkerDenied:
            return ServiceResponse(
                409,
                {
                    "error": {
                        "code": "WORKER_CONFLICT",
                        "message": "worker lease conflicts with current state",
                    }
                },
            )
        status = 201 if request.action == "worker_sessions.create" else 200
        return ServiceResponse(
            status,
            _session_document(session),
            {"etag": f'"{session.version}"'},
        )

    def _dispatch(self, request: ServiceRequest) -> WorkerSession:
        document = _document(request)
        worker_id = _required_string(document, "worker_id")
        identity_hash = _required_string(document, "execution_identity_hash")
        if request.action == "worker_sessions.create":
            return self._sessions.create(
                tenant_id=request.identity.tenant_id,
                run_id=_required_string(document, "run_id"),
                worker_id=worker_id,
                identity_hash=identity_hash,
                idempotency_key=_idempotency_key(request),
            )
        session_id = request.path_params.get("session_id")
        if not session_id:
            raise WorkerDenied()
        tenant_id = request.identity.tenant_id
        expected_version = _expected_version(request)
        if request.action == "worker_sessions.heartbeat":
            return self._sessions.heartbeat(
                session_id=session_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                identity_hash=identity_hash,
                expected_version=expected_version,
            )
        if request.action == "worker_sessions.events.append":
            raw_events = document.get("events")
            if not isinstance(raw_events, list) or not raw_events:
                raise WorkerDenied()
            events: list[dict[str, object]] = []
            for event in raw_events:
                if not isinstance(event, dict):
                    raise WorkerDenied()
                events.append(dict(event))
            return self._sessions.append(
                session_id=session_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                identity_hash=identity_hash,
                expected_version=expected_version,
                events=tuple(events),
            )
        if request.action == "worker_sessions.artifacts.commit":
            return self._sessions.artifact(
                session_id=session_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                identity_hash=identity_hash,
                expected_version=expected_version,
                content_sha256=_required_string(document, "content_sha256"),
            )
        if request.action == "worker_sessions.complete":
            return self._sessions.complete(
                session_id=session_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                identity_hash=identity_hash,
                expected_version=expected_version,
                outcome=_required_string(document, "outcome"),
            )
        raise ServiceUnavailableError()


class ArtifactAuthorizationHandler:
    """Issue a metadata-only egress authorization under one pinned policy."""

    def __init__(self, policy: EgressPolicy) -> None:
        self._policy = policy

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        document = request.document
        if document is None:
            return _artifact_denied()
        tenant_id = request.identity.tenant_id
        declared_tenant = document.get("tenant_id")
        if declared_tenant is not None and declared_tenant != tenant_id:
            return _artifact_denied()
        values = {
            name: document.get(name)
            for name in (
                "repository_id",
                "run_id",
                "execution_identity_hash",
                "destination_id",
                "profile_id",
                "capability_id",
            )
        }
        if any(not isinstance(value, str) or not value for value in values.values()):
            return _artifact_denied()
        try:
            receipt = authorize(
                self._policy,
                tenant_id=tenant_id,
                repository_id=str(values["repository_id"]),
                run_id=str(values["run_id"]),
                execution_identity_hash=str(values["execution_identity_hash"]),
                destination_id=str(values["destination_id"]),
                profile_id=str(values["profile_id"]),
                capability_id=str(values["capability_id"]),
            )
        except EgressDenied:
            return _artifact_denied()
        return ServiceResponse(
            201,
            {
                "tenant_id": receipt.tenant_id,
                "repository_id": receipt.repository_id,
                "run_id": receipt.run_id,
                "execution_identity_hash": receipt.execution_identity_hash,
                "destination_id": receipt.destination_id,
                "profile_id": receipt.profile_id,
                "capability_id": receipt.capability_id,
                "authority": "ARTIFACT_EGRESS_ONLY",
            },
        )


def _document(request: ServiceRequest) -> Mapping[str, object]:
    if request.document is None:
        raise WorkerDenied()
    return request.document


def _required_string(document: Mapping[str, object], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise WorkerDenied()
    return value


def _idempotency_key(request: ServiceRequest) -> str:
    if request.idempotency_key is None:
        raise WorkerDenied()
    return request.idempotency_key


def _expected_version(request: ServiceRequest) -> int:
    if request.precondition is None:
        raise WorkerDenied()
    value = request.precondition.strip('"')
    if not value.isdigit() or int(value) < 1:
        raise WorkerDenied()
    return int(value)


def _session_document(session: WorkerSession) -> dict[str, object]:
    document: dict[str, object] = {
        "session_id": session.session_id,
        "run_id": session.run_id,
        "worker_id": session.worker_id,
        "execution_identity_hash": session.identity_hash,
        "version": session.version,
        "terminal": session.terminal,
        "command": session.command.value,
    }
    if session.outcome is not None:
        document["outcome"] = session.outcome
    return document


def _artifact_denied() -> ServiceResponse:
    return ServiceResponse(
        403,
        {"error": {"code": "EGRESS_DENIED", "message": "artifact egress is not authorized"}},
    )


__all__ = [
    "ArtifactAuthorizationHandler",
    "RawWebhookAdapter",
    "WebhookHandler",
    "WorkerHandler",
]
