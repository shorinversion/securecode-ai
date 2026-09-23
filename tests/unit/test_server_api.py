"""Focused P6.1 ASGI boundary contracts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import cast
from urllib.parse import parse_qs, urlsplit

from securecode_ai.server import (
    ServerApp,
    ServiceRequest,
    ServiceResponse,
    VerifiedIdentity,
    create_app,
)
from securecode_ai.server.bootstrap import RoleAuthorization
from securecode_ai.server.oidc_login import (
    OidcAuthorizationClient,
    OidcLoginService,
)
from securecode_ai.server.oidc_sessions import NonceReplayLedger
from securecode_ai.server.persistence import DevelopmentRepository
from securecode_ai.server.service import DurableControlPlaneService
from securecode_ai.server.sessions import SessionStore
from securecode_ai.server.sqlite_request_quota import (
    SQLITE_REQUEST_QUOTA_SCHEMA_STATEMENTS,
    SqliteQuotaLedger,
)


@dataclass
class _IdentityVerifier:
    identity: VerifiedIdentity | None

    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        return self.identity if token == "token" else None


class _AllowAuthorization:
    def allows(self, identity: VerifiedIdentity, *, action: str, repository_id: str | None) -> bool:
        return identity.tenant_id == "tenant-a" and action.startswith(
            ("runs.", "findings.", "worker_sessions.")
        )


class _ArtifactAuthorization:
    def allows(self, identity: VerifiedIdentity, *, action: str, repository_id: str | None) -> bool:
        return action == "artifacts.authorize" and repository_id == "repo-1"


@dataclass
class _Service:
    requests: list[ServiceRequest] = field(default_factory=list)

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        self.requests.append(request)
        return ServiceResponse(201, {"run_id": "run-1", "tenant": request.identity.tenant_id})


async def _request(
    app: ServerApp,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    document: object | None = None,
) -> tuple[int, dict[str, object]]:
    body = b"" if document is None else json.dumps(document).encode("utf-8")
    events: list[Mapping[str, object]] = []
    received = False

    async def receive() -> Mapping[str, object]:
        nonlocal received
        if received:
            return {"type": "http.request", "body": b"", "more_body": False}
        received = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(event: Mapping[str, object]) -> None:
        events.append(event)

    encoded_headers = [
        (key.encode("ascii"), value.encode("latin-1")) for key, value in (headers or {}).items()
    ]
    await app(
        {
            "type": "http",
            "scheme": "https",
            "client": ("127.0.0.1", 43120),
            "method": method,
            "path": path,
            "headers": encoded_headers,
            "query_string": b"",
        },
        receive,
        send,
    )
    status = events[0].get("status")
    response_body = events[1].get("body")
    assert type(status) is int
    assert isinstance(response_body, str | bytes | bytearray)
    decoded: object = json.loads(response_body)
    assert isinstance(decoded, dict)
    assert all(isinstance(key, str) for key in decoded)
    return status, {str(key): value for key, value in decoded.items()}


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return value


def test_liveness_is_unauthenticated_and_safe() -> None:
    status, payload = asyncio.run(_request(create_app(), "GET", "/api/v1/health/live"))

    assert status == 200
    assert payload == {"api_version": "1.0.0", "status": "live"}


def test_openapi_advertises_the_accepted_worker_and_run_routes() -> None:
    status, payload = asyncio.run(_request(create_app(), "GET", "/api/v1/openapi.json"))

    assert status == 200
    paths = _mapping(payload["paths"])
    assert "/api/v1/runs" in paths
    assert "/api/v1/repositories/{repository_id}/runs" in paths
    assert "/api/v1/worker-sessions/{session_id}:complete" in paths
    assert "/api/v1/findings/{finding_id}/evidence" in paths


def test_finding_evidence_route_passes_authenticated_identity_to_service() -> None:
    identity = VerifiedIdentity("user-1", "tenant-a", frozenset({"viewer"}))
    service = _Service()
    app = create_app(
        identities=_IdentityVerifier(identity),
        authorization=RoleAuthorization(),
        service=service,
    )

    status, payload = asyncio.run(
        _request(
            app,
            "GET",
            "/api/v1/findings/finding-1/evidence",
            headers={"authorization": "Bearer token"},
        )
    )

    assert status == 201
    assert payload["run_id"] == "run-1"
    assert len(service.requests) == 1
    assert service.requests[0].action == "findings.evidence.read"
    assert service.requests[0].path_params == {"finding_id": "finding-1"}


def test_authenticated_viewer_can_list_only_granted_repository_runs() -> None:
    tenant_id = "tenant-a"
    repository_id = "repo-1"
    identity = VerifiedIdentity(
        "user-1",
        tenant_id,
        frozenset({"viewer"}),
        repository_ids=frozenset({repository_id}),
    )
    repository = DevelopmentRepository.in_memory()
    for run_id in ("run-a", "run-b"):
        repository.create_run(
            tenant_id=tenant_id,
            run_id=run_id,
            repository_id=repository_id,
            execution_identity_hash=hashlib.sha256(run_id.encode()).hexdigest(),
            base_sha="a" * 40,
            head_sha="b" * 40,
            metadata={},
            idempotency_key=f"key-{run_id}",
            request_sha256=hashlib.sha256(("request-" + run_id).encode()).hexdigest(),
        )
    repository.create_run(
        tenant_id="tenant-b",
        run_id="run-private",
        repository_id=repository_id,
        execution_identity_hash=hashlib.sha256(b"private").hexdigest(),
        base_sha="a" * 40,
        head_sha="b" * 40,
        metadata={},
        idempotency_key="key-private",
        request_sha256=hashlib.sha256(b"request-private").hexdigest(),
    )
    app = create_app(
        identities=_IdentityVerifier(identity),
        authorization=RoleAuthorization(),
        service=DurableControlPlaneService(repository),
    )

    status, payload = asyncio.run(
        _request(
            app,
            "GET",
            f"/api/v1/repositories/{repository_id}/runs",
            headers={"authorization": "Bearer token"},
        )
    )

    assert status == 200
    listed = cast(list[dict[str, object]], payload["items"])
    assert [item["run_id"] for item in listed] == ["run-a", "run-b"]
    assert all(item["tenant_id"] == tenant_id for item in listed)
    assert payload["next_cursor"] is None


def test_run_listing_rejects_invalid_and_repeated_pagination_parameters() -> None:
    repository = DevelopmentRepository.in_memory()
    service = DurableControlPlaneService(repository)
    identity = VerifiedIdentity(
        "user-1",
        "tenant-a",
        frozenset({"viewer"}),
        repository_ids=frozenset({"repo-1"}),
    )
    invalid_queries = (
        {"limit": ("0",)},
        {"limit": ("101",)},
        {"limit": ("invalid",)},
        {"limit": ("\u0661",)},
        {"limit": ("10", "20")},
        {"cursor": ("a", "b")},
    )

    for query in invalid_queries:
        request = ServiceRequest(
            method="GET",
            route="/api/v1/repositories/repo-1/runs",
            action="runs.list",
            identity=identity,
            idempotency_key=None,
            precondition=None,
            path_params={"repository_id": "repo-1"},
            query=query,
            document=None,
            raw_body=b"",
        )
        response = asyncio.run(service.dispatch(request))
        assert response.status == 409
        assert _mapping(response.document["error"])["code"] == "CONFLICT"


def test_mutation_requires_verified_identity_and_idempotency_key() -> None:
    identity = VerifiedIdentity("user-1", "tenant-a", frozenset({"operator"}))
    app = create_app(
        identities=_IdentityVerifier(identity),
        authorization=_AllowAuthorization(),
        service=_Service(),
    )
    status, payload = asyncio.run(
        _request(
            app,
            "POST",
            "/api/v1/runs",
            headers={"authorization": "Bearer token"},
            document={"repository_id": "repo-1"},
        )
    )

    assert status == 400
    assert _mapping(payload["error"])["code"] == "IDEMPOTENCY_KEY_REQUIRED"


def test_identical_mutation_replays_without_a_second_service_effect() -> None:
    identity = VerifiedIdentity("user-1", "tenant-a", frozenset({"operator"}))
    service = _Service()
    app = create_app(
        identities=_IdentityVerifier(identity), authorization=_AllowAuthorization(), service=service
    )
    headers = {"authorization": "Bearer token", "idempotency-key": "key-0001"}
    first = asyncio.run(
        _request(app, "POST", "/api/v1/runs", headers=headers, document={"repository_id": "repo-1"})
    )
    second = asyncio.run(
        _request(app, "POST", "/api/v1/runs", headers=headers, document={"repository_id": "repo-1"})
    )

    assert first[0] == 201
    assert second[0] == 200
    assert len(service.requests) == 1


def test_workload_route_requires_a_workload_identity_and_precondition() -> None:
    identity = VerifiedIdentity("worker-1", "tenant-a", frozenset({"worker"}), workload=True)
    app = create_app(
        identities=_IdentityVerifier(identity),
        authorization=_AllowAuthorization(),
        service=_Service(),
    )
    status, payload = asyncio.run(
        _request(
            app,
            "POST",
            "/api/v1/worker-sessions/session-1:heartbeat",
            headers={"authorization": "Bearer token", "idempotency-key": "key-0002"},
            document={"repository_id": "repo-1"},
        )
    )

    assert status == 412
    assert _mapping(payload["error"])["code"] == "PRECONDITION_REQUIRED"


def test_artifact_authorization_requires_a_workload_identity() -> None:
    service = _Service()
    headers = {"authorization": "Bearer token", "idempotency-key": "key-0003"}
    document = {"repository_id": "repo-1"}
    interactive = create_app(
        identities=_IdentityVerifier(
            VerifiedIdentity("auditor-1", "tenant-a", frozenset({"auditor"}))
        ),
        authorization=_ArtifactAuthorization(),
        service=service,
    )

    denied, payload = asyncio.run(
        _request(
            interactive,
            "POST",
            "/api/v1/artifacts:authorize",
            headers=headers,
            document=document,
        )
    )

    assert denied == 403
    assert _mapping(payload["error"])["code"] == "FORBIDDEN"
    assert not service.requests

    worker = create_app(
        identities=_IdentityVerifier(
            VerifiedIdentity("worker-1", "tenant-a", frozenset({"worker"}), workload=True)
        ),
        authorization=_ArtifactAuthorization(),
        service=service,
    )
    allowed, _ = asyncio.run(
        _request(
            worker,
            "POST",
            "/api/v1/artifacts:authorize",
            headers=headers,
            document=document,
        )
    )

    assert allowed == 201
    assert [request.action for request in service.requests] == ["artifacts.authorize"]


def test_unsupported_major_version_is_rejected_before_service_dispatch() -> None:
    status, payload = asyncio.run(
        _request(
            create_app(), "GET", "/api/v1/capabilities", headers={"x-securecode-api-version": "2.0"}
        )
    )

    assert status == 422
    assert _mapping(payload["error"])["code"] == "UNSUPPORTED_VERSION"


def test_persistent_quota_returns_retry_after_and_fails_closed() -> None:
    identity = VerifiedIdentity("user-1", "tenant-a", frozenset({"operator"}))
    connection = sqlite3.connect(":memory:")
    for statement in SQLITE_REQUEST_QUOTA_SCHEMA_STATEMENTS:
        connection.execute(statement)
    ledger = SqliteQuotaLedger(
        connection,
        window_seconds=60,
        max_requests=1,
    )
    app = create_app(
        identities=_IdentityVerifier(identity),
        authorization=_AllowAuthorization(),
        service=_Service(),
        quota=ledger,
    )
    headers = {
        "authorization": "Bearer token",
        "x-securecode-api-version": "1.0.0",
    }
    first = asyncio.run(_request(app, "GET", "/api/v1/runs/run-1", headers=headers))
    second = asyncio.run(_request(app, "GET", "/api/v1/runs/run-1", headers=headers))

    assert first[0] == 201
    assert second[0] == 429
    assert _mapping(second[1]["error"])["code"] == "QUOTA_EXCEEDED"

    unavailable = create_app(
        identities=_IdentityVerifier(identity),
        authorization=_AllowAuthorization(),
        service=_Service(),
        quota=SqliteQuotaLedger(
            sqlite3.connect(":memory:"),
            window_seconds=60,
            max_requests=1,
        ),
    )
    failed = asyncio.run(_request(unavailable, "GET", "/api/v1/runs/run-1", headers=headers))
    assert failed[0] == 503
    assert _mapping(failed[1]["error"])["code"] == "QUOTA_UNAVAILABLE"


def test_oidc_login_start_returns_state_nonce_and_pkce_authorization_url() -> None:
    class Admission:
        def admit(self, token: str, *, nonce: str) -> object:
            raise AssertionError("login start must not admit a token")

    login = OidcLoginService(
        admission=Admission(),  # type: ignore[arg-type]
        ledger=NonceReplayLedger(),
        authorization_client=OidcAuthorizationClient(
            authorization_endpoint="https://idp.example/authorize",
            client_id="securecode-client",
            redirect_uri="https://securecode.example/auth/callback",
        ),
    )
    app = create_app(oidc_login=login, sessions=SessionStore())
    status, payload = asyncio.run(_request(app, "POST", "/api/v1/auth/login"))

    assert status == 200
    assert type(payload.get("state")) is str and payload["state"]
    assert type(payload.get("nonce")) is str and payload["nonce"]
    assert type(payload.get("code_verifier")) is str and payload["code_verifier"]
    assert payload["code_challenge_method"] == "S256"
    authorization_url = payload.get("authorization_url")
    assert type(authorization_url) is str
    query = parse_qs(urlsplit(authorization_url).query)
    assert query["state"] == [payload["state"]]
    assert query["nonce"] == [payload["nonce"]]
    assert query["code_challenge_method"] == ["S256"]
    assert query["response_type"] == ["code"]


def test_oidc_login_start_fails_closed_when_authentication_is_unconfigured() -> None:
    status, payload = asyncio.run(_request(create_app(), "POST", "/api/v1/auth/login"))

    assert status == 503
    assert _mapping(payload["error"])["code"] == "AUTH_NOT_CONFIGURED"
