"""P6.10 connected audit export and operational telemetry contracts."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field

import pytest
from securecode_ai.server.application import ServerApp
from securecode_ai.server.audit_log import AuditLog
from securecode_ai.server.bootstrap import RoleAuthorization
from securecode_ai.server.operations_audit import AuditTelemetryControlPlane
from securecode_ai.server.operations_telemetry import OperationsTelemetry
from securecode_ai.server.persistence import DevelopmentRepository
from securecode_ai.server.ports import (
    ServiceRequest,
    ServiceResponse,
    ServiceUnavailableError,
    VerifiedIdentity,
)


@dataclass
class _IdentityVerifier:
    identity: VerifiedIdentity

    def verify_bearer(self, token: str) -> VerifiedIdentity | None:
        return self.identity if token == "token" else None


@dataclass
class _Fallback:
    response: ServiceResponse = field(
        default_factory=lambda: ServiceResponse(200, {"state": "CANCELLED", "run_id": "run-1"})
    )

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        return self.response


def _run_store() -> tuple[sqlite3.Connection, DevelopmentRepository]:
    connection = sqlite3.connect(":memory:")
    repository = DevelopmentRepository(connection)
    repository.create_run(
        tenant_id="tenant-a",
        run_id="run-1",
        repository_id="repo-a",
        execution_identity_hash="a" * 64,
        base_sha=None,
        head_sha="b" * 40,
        metadata={},
        idempotency_key="create-0001",
        request_sha256="c" * 64,
    )
    return connection, repository


def _service(
    repository: DevelopmentRepository,
    *,
    audit: AuditLog | None = None,
    telemetry: OperationsTelemetry | None = None,
) -> AuditTelemetryControlPlane:
    return AuditTelemetryControlPlane(
        fallback=_Fallback(),
        audit_log=audit or AuditLog(),
        telemetry=telemetry or OperationsTelemetry(),
        runs=repository,
        clock_ns=iter((0, 10_000_000) * 20).__next__,
    )


def _request(
    action: str,
    identity: VerifiedIdentity,
    *,
    run_id: str = "run-1",
    query: Mapping[str, tuple[str, ...]] | None = None,
    document: Mapping[str, object] | None = None,
    idempotency_key: str | None = "cancel-0001",
) -> ServiceRequest:
    return ServiceRequest(
        method="GET" if action.endswith(".read") else "POST",
        route="/api/v1/runs/{run_id}",
        action=action,
        identity=identity,
        idempotency_key=idempotency_key,
        precondition='"1"',
        path_params={"run_id": run_id},
        query=query or {},
        document={} if document is None else document,
        raw_body=b"{}",
    )


def test_cancel_writes_one_immutable_event_and_retry_replays_it() -> None:
    connection, repository = _run_store()
    audit = AuditLog(connection)
    telemetry = OperationsTelemetry()
    service = _service(repository, audit=audit, telemetry=telemetry)
    identity = VerifiedIdentity(
        "alice", "tenant-a", frozenset({"auditor"}), repository_ids=frozenset({"repo-a"})
    )
    request = _request("runs.cancel", identity)

    first = asyncio.run(service.dispatch(request))
    replay = asyncio.run(service.dispatch(request))

    assert first == replay
    assert audit.head_sequence(tenant_id="tenant-a", run_id="run-1") == 1
    event = audit.range("tenant-a", "run-1")[0]
    assert event.actor_id == "alice"
    assert event.action == "runs.cancel"
    assert event.attributes == {"outcome": "cancelled"}
    assert audit.verify(tenant_id="tenant-a", run_id="run-1")
    assert telemetry.snapshot() == {
        "counters": ({"operation": "run", "outcome": "cancelled", "count": 2},),
        "latency_ms": ({"operation": "run", "total": 20, "count": 2},),
        "latency_percentiles_ms": ({"operation": "run", "p50": 10, "p95": 10},),
    }


def test_audit_export_is_repo_scoped_bounded_and_source_free() -> None:
    connection, repository = _run_store()
    audit = AuditLog(connection)
    audit.append(
        tenant_id="tenant-a",
        repository_id="repo-a",
        run_id="run-1",
        actor_id="alice",
        action="runs.cancel",
        identity_hash="a" * 64,
        expected_sequence=0,
        attributes={"outcome": "success"},
        idempotency_key="audit-event-1",
    )
    service = _service(repository, audit=audit)
    authorized = VerifiedIdentity(
        "alice", "tenant-a", frozenset({"auditor"}), repository_ids=frozenset({"repo-a"})
    )
    response = asyncio.run(service.dispatch(_request("runs.audit.read", authorized)))

    assert response.status == 200
    exported = response.document["document"]
    assert isinstance(exported, dict)
    assert exported["authority"] == "NONE"
    assert "source" not in json.dumps(response.document).casefold()
    assert isinstance(response.document["manifest_sha256"], str)

    other_repository = VerifiedIdentity(
        "alice", "tenant-a", frozenset({"auditor"}), repository_ids=frozenset({"repo-b"})
    )
    denied = asyncio.run(service.dispatch(_request("runs.audit.read", other_repository)))
    assert denied.status == 403
    invalid_range = asyncio.run(
        service.dispatch(_request("runs.audit.read", authorized, query={"end": ("501",)}))
    )
    assert invalid_range.status == 400
    assert invalid_range.document == {"error": {"code": "INVALID_AUDIT_RANGE"}}
    unicode_range = asyncio.run(
        service.dispatch(_request("runs.audit.read", authorized, query={"start": (chr(0x0661),)}))
    )
    assert unicode_range.status == 400
    oversized_range = asyncio.run(
        service.dispatch(_request("runs.audit.read", authorized, query={"start": ("9" * 5000,)}))
    )
    assert oversized_range.status == 400


def test_approval_transition_is_bound_to_the_run_audit_chain() -> None:
    connection, repository = _run_store()
    audit = AuditLog(connection)
    fallback = _Fallback(
        ServiceResponse(
            200,
            {"run_id": "run-1", "state": "PENDING", "decision": {"state": "APPROVED"}},
        )
    )
    service = AuditTelemetryControlPlane(
        fallback=fallback,
        audit_log=audit,
        telemetry=OperationsTelemetry(),
        runs=repository,
        clock_ns=iter((0, 10_000_000) * 2).__next__,
    )
    identity = VerifiedIdentity(
        "approver-1", "tenant-a", frozenset({"approver"}), repository_ids=frozenset({"repo-a"})
    )

    result = asyncio.run(service.dispatch(_request("approvals.decide", identity)))

    assert result.status == 200
    event = audit.range("tenant-a", "run-1")[0]
    assert event.action == "approvals.decide"
    assert event.actor_id == "approver-1"
    assert event.attributes == {"outcome": "approved"}


def test_worker_terminal_outcome_is_audited_without_worker_payload() -> None:
    connection, repository = _run_store()
    audit = AuditLog(connection)
    service = _service(repository, audit=audit)
    identity = VerifiedIdentity("worker-1", "tenant-a", frozenset({"worker"}), workload=True)

    asyncio.run(
        service.dispatch(
            _request(
                "worker_sessions.complete",
                identity,
                document={"run_id": "run-1", "outcome": "FAIL", "findings": ["private"]},
            )
        )
    )

    event = audit.range("tenant-a", "run-1")[0]
    assert event.attributes == {"outcome": "fail"}
    assert "findings" not in str(event.attributes)


def test_corrupt_audit_chain_fails_closed_and_metrics_have_fixed_labels() -> None:
    connection, repository = _run_store()
    audit = AuditLog(connection)
    audit.append(
        tenant_id="tenant-a",
        repository_id="repo-a",
        run_id="run-1",
        actor_id="alice",
        action="runs.cancel",
        identity_hash="a" * 64,
        expected_sequence=0,
        attributes={"outcome": "success"},
        idempotency_key="audit-event-1",
    )
    connection.execute(
        "UPDATE audit_chain_events SET event_hash = ? WHERE tenant_id = ? AND run_id = ?",
        ("f" * 64, "tenant-a", "run-1"),
    )
    connection.commit()
    metrics = OperationsTelemetry()
    service = _service(repository, audit=audit, telemetry=metrics)
    identity = VerifiedIdentity(
        "root", "tenant-a", frozenset({"admin"}), repository_ids=frozenset({"repo-a"})
    )

    with pytest.raises(ServiceUnavailableError):
        asyncio.run(service.dispatch(_request("runs.audit.read", identity)))
    denied = asyncio.run(
        service.dispatch(
            _request(
                "operations.metrics.read",
                VerifiedIdentity("viewer", "tenant-a", frozenset({"viewer"})),
            )
        )
    )
    assert denied.status == 403
    snapshot = asyncio.run(service.dispatch(_request("operations.metrics.read", identity)))
    assert snapshot.status == 200
    assert "tenant-a" not in json.dumps(snapshot.document)
    assert "repo-a" not in json.dumps(snapshot.document)
    assert snapshot.document == {
        "counters": ({"operation": "export", "outcome": "error", "count": 1},),
        "latency_ms": ({"operation": "export", "total": 10, "count": 1},),
        "latency_percentiles_ms": ({"operation": "export", "p50": 10, "p95": 10},),
    }


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ({"start": ("0",)}, 400),
        ({"start": ("1", "2")}, 400),
        ({"start": ("1",), "end": ("501",)}, 400),
        ({"unknown": ("1",)}, 400),
    ],
)
def test_audit_api_route_rejects_invalid_ranges(
    query: dict[str, tuple[str, ...]], expected: int
) -> None:
    connection, repository = _run_store()
    identity = VerifiedIdentity(
        "alice", "tenant-a", frozenset({"auditor"}), repository_ids=frozenset({"repo-a"})
    )
    service = _service(repository, audit=AuditLog(connection))
    app = ServerApp(
        identities=_IdentityVerifier(identity),
        authorization=RoleAuthorization(),
        service=service,
    )
    status, _ = asyncio.run(_asgi_request(app, "/api/v1/runs/run-1/audit", query=query))
    assert status == expected


async def _asgi_request(
    app: ServerApp,
    path: str,
    *,
    query: Mapping[str, tuple[str, ...]],
) -> tuple[int, dict[str, object]]:
    events: list[Mapping[str, object]] = []
    received = False

    async def receive() -> Mapping[str, object]:
        nonlocal received
        if received:
            return {"type": "http.request", "body": b"", "more_body": False}
        received = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(event: Mapping[str, object]) -> None:
        events.append(event)

    query_string = "&".join(
        f"{name}={value}" for name, values in query.items() for value in values
    ).encode("ascii")
    await app(
        {
            "type": "http",
            "method": "GET",
            "path": path,
            "query_string": query_string,
            "headers": [(b"authorization", b"Bearer token")],
        },
        receive,
        send,
    )
    status = events[0].get("status")
    body = events[1].get("body")
    assert type(status) is int and isinstance(body, bytes)
    payload = json.loads(body)
    assert isinstance(payload, dict)
    return status, payload
