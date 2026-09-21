"""Connected-worker HTTP handler backed by the durable run queue."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Final, cast

from securecode_ai.contracts import ArtifactRef

from .artifact_upload_verifier import LocalArtifactUploadVerifier
from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError
from .worker_artifact_authorization import (
    ArtifactAuthorizationDenied,
    SqliteArtifactAuthorizationStore,
)
from .worker_completion_evidence import verify_terminal_evidence
from .worker_findings import WorkerFindingRecord, parse_worker_findings
from .worker_findings_store import complete_worker_run
from .worker_queue import SqliteWorkerQueue, WorkerQueueClaimHandler, WorkerQueueConflict
from .worker_queue_models import WorkerQueueLease
from .worker_resource_models import WorkerResourceSettlement

_EVENT_KINDS: Final = frozenset(
    {
        "RUN_STARTED",
        "RUN_COMPLETED",
        "RUN_CANCELLED",
        "RUN_SUPERSEDED",
        "RUN_FAILED",
    }
)
_COMMIT_OUTCOMES: Final = frozenset({"PASS", "FAIL", "INDETERMINATE"})
_COMPLETION_KEYS: Final = frozenset(
    {
        "execution_identity_hash",
        "outcome",
        "run_id",
        "schema_version",
        "worker_id",
    }
)


class WorkerQueueHandler:
    """Serve claims, lease changes, evidence commits, and terminal outcomes."""

    def __init__(
        self,
        *,
        queue: SqliteWorkerQueue,
        artifact_authorizations: SqliteArtifactAuthorizationStore,
        uploaded_artifacts: LocalArtifactUploadVerifier,
    ) -> None:
        self._queue = queue
        self._claims = WorkerQueueClaimHandler(queue)
        self._artifact_authorizations = artifact_authorizations
        self._uploaded_artifacts = uploaded_artifacts

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action == "worker_sessions.create":
            return await self._claims.dispatch(request)
        try:
            return self._dispatch_session(request)
        except ArtifactAuthorizationDenied:
            return _denied(
                403,
                "ARTIFACT_AUTHORIZATION_DENIED",
                "artifact upload is not authorized",
            )
        except (WorkerQueueConflict, KeyError, TypeError, ValueError):
            return _denied(
                409,
                "WORKER_CONFLICT",
                "worker lease conflicts with current state",
            )

    async def dispatch_accounted_completion(
        self,
        request: ServiceRequest,
        *,
        settlement: WorkerResourceSettlement,
        resource_clock: Callable[[], int],
    ) -> ServiceResponse:
        """Atomically settle resources and complete one validated worker run."""

        try:
            document = _document(request)
            session_id = request.path_params.get("session_id")
            worker_id = _required_text(document, "worker_id")
            run_id = _required_text(document, "run_id")
            identity_hash = _required_text(document, "execution_identity_hash")
            if request.action != "worker_sessions.complete" or not session_id:
                raise WorkerQueueConflict()
            expected_version = _version(request.precondition)
            outcome = _required_text(document, "outcome")
            findings = _completion_findings(document, outcome)
            connection = _queue_connection(self._queue)
            verify_terminal_evidence(
                connection=connection,
                artifact_root=_artifact_root(self._uploaded_artifacts),
                tenant_id=request.identity.tenant_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                outcome=outcome,
                findings=findings,
            )
            lease = complete_worker_run(
                connection,
                lease_seconds=_queue_lease_seconds(self._queue),
                now=_queue_clock(self._queue),
                tenant_id=request.identity.tenant_id,
                session_id=session_id,
                worker_id=worker_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                expected_version=expected_version,
                outcome=outcome,
                findings=findings,
                resource_settlement=settlement,
                resource_clock=resource_clock,
            )
            return _lease_response(lease)
        except (WorkerQueueConflict, KeyError, TypeError, ValueError):
            return _denied(
                409,
                "WORKER_CONFLICT",
                "worker lease conflicts with current state",
            )

    def _dispatch_session(self, request: ServiceRequest) -> ServiceResponse:
        document = _document(request)
        session_id = request.path_params.get("session_id")
        worker_id = _required_text(document, "worker_id")
        run_id = _required_text(document, "run_id")
        identity_hash = _required_text(document, "execution_identity_hash")
        if not session_id:
            raise WorkerQueueConflict()
        tenant_id = request.identity.tenant_id
        expected_version = _version(request.precondition)
        if request.action == "worker_sessions.heartbeat":
            lease = self._queue.heartbeat(
                tenant_id=tenant_id,
                session_id=session_id,
                worker_id=worker_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                expected_version=expected_version,
            )
        elif request.action == "worker_sessions.events.append":
            events = _events(document.get("events"), run_id, identity_hash)
            lease = self._queue.advance(
                tenant_id=tenant_id,
                session_id=session_id,
                worker_id=worker_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                expected_version=expected_version,
                events=events,
            )
        elif request.action == "worker_sessions.artifacts.commit":
            artifact = _artifact(document)
            authorization = self._artifact_authorizations.require(
                tenant_id=request.identity.tenant_id,
                authorization_id=_required_text(document, "authorization_id"),
                run_id=run_id,
                execution_identity_hash=identity_hash,
                content_sha256=artifact.content_sha256,
                size_bytes=artifact.size_bytes,
                purpose=_required_text(document, "purpose"),
            )
            if (
                authorization.worker_id != worker_id
                or authorization.content_id != artifact.content_id
                or authorization.data_class != artifact.data_class.value
            ):
                raise ArtifactAuthorizationDenied()
            self._uploaded_artifacts.require(
                tenant_id=request.identity.tenant_id,
                authorization_id=authorization.authorization_id,
                worker_id=worker_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                content_sha256=artifact.content_sha256,
                size_bytes=artifact.size_bytes,
                purpose=authorization.purpose,
            )
            lease = self._queue.advance(
                tenant_id=tenant_id,
                session_id=session_id,
                worker_id=worker_id,
                run_id=run_id,
                execution_identity_hash=identity_hash,
                expected_version=expected_version,
                artifact={
                    "authorization_id": authorization.authorization_id,
                    "content_id": artifact.content_id,
                    "content_sha256": artifact.content_sha256,
                    "data_class": artifact.data_class.value,
                    "purpose": authorization.purpose,
                    "size_bytes": artifact.size_bytes,
                },
            )
        elif request.action == "worker_sessions.complete":
            raise ServiceUnavailableError()
        else:
            raise ServiceUnavailableError()
        return _lease_response(lease)


def _events(
    value: object,
    run_id: str,
    execution_identity_hash: str,
) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 64:
        raise WorkerQueueConflict()
    admitted: list[Mapping[str, object]] = []
    previous_sequence = 0
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
            "event_hash",
            "event_id",
            "kind",
            "sequence",
        }:
            raise WorkerQueueConflict()
        sequence = item["sequence"]
        kind = item["kind"]
        if (
            type(sequence) is not int
            or sequence <= previous_sequence
            or type(kind) is not str
            or kind not in _EVENT_KINDS
        ):
            raise WorkerQueueConflict()
        digest = _event_hash(run_id, execution_identity_hash, sequence, kind)
        if item["event_hash"] != digest or item["event_id"] != f"worker-{sequence}-{digest[:32]}":
            raise WorkerQueueConflict()
        admitted.append(dict(item))
        previous_sequence = sequence
    return tuple(admitted)


def _event_hash(run_id: str, identity_hash: str, sequence: int, kind: str) -> str:
    value = {
        "execution_identity_hash": identity_hash,
        "kind": kind,
        "run_id": run_id,
        "sequence": sequence,
    }
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _artifact(document: Mapping[str, object]) -> ArtifactRef:
    value = document.get("artifact_ref")
    if not isinstance(value, Mapping):
        raise ArtifactAuthorizationDenied()
    try:
        return ArtifactRef.model_validate(dict(value))
    except (TypeError, ValueError):
        raise ArtifactAuthorizationDenied() from None


def _completion_findings(
    document: Mapping[str, object], outcome: str
) -> tuple[WorkerFindingRecord, ...]:
    commits = outcome in _COMMIT_OUTCOMES
    keys = set(document)
    expected = _COMPLETION_KEYS | ({"findings"} if commits else set())
    allowed = {frozenset(expected)}
    if commits:
        allowed.add(frozenset(expected | {"resource_usage"}))
    if frozenset(keys) not in allowed or document.get("schema_version") != "0.2.0":
        raise WorkerQueueConflict()
    return parse_worker_findings(
        document.get("findings"),
        required=commits,
        supplied="findings" in document,
    )


def _document(request: ServiceRequest) -> Mapping[str, object]:
    if request.document is None:
        raise WorkerQueueConflict()
    return request.document


def _required_text(document: Mapping[str, object], name: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value:
        raise WorkerQueueConflict()
    return value


def _version(value: str | None) -> int:
    if value is None:
        raise WorkerQueueConflict()
    unquoted = value.strip('"')
    if not unquoted.isdigit() or int(unquoted) < 1:
        raise WorkerQueueConflict()
    return int(unquoted)


def _queue_connection(queue: SqliteWorkerQueue) -> sqlite3.Connection:
    connection = getattr(queue, "_connection", None)
    if not isinstance(connection, sqlite3.Connection):
        raise WorkerQueueConflict()
    return connection


def _artifact_root(verifier: LocalArtifactUploadVerifier) -> Path:
    root = getattr(verifier, "_root", None)
    if not isinstance(root, Path) or not root.is_absolute():
        raise WorkerQueueConflict()
    return root


def _queue_lease_seconds(queue: SqliteWorkerQueue) -> int:
    value = getattr(queue, "_lease_seconds", None)
    if type(value) is not int or not 5 <= value <= 3600:
        raise WorkerQueueConflict()
    return value


def _queue_clock(queue: SqliteWorkerQueue) -> Callable[[], datetime]:
    value = getattr(queue, "_now", None)
    if not callable(value):
        raise WorkerQueueConflict()
    return cast(Callable[[], datetime], value)


def _lease_response(lease: WorkerQueueLease) -> ServiceResponse:
    return ServiceResponse(
        200,
        {
            "command": lease.command,
            "run_id": lease.run_id,
            "session_id": lease.session_id,
            "terminal": lease.terminal,
            "version": lease.version,
        },
        {"etag": f'"{lease.version}"'},
    )


def _denied(status: int, code: str, message: str) -> ServiceResponse:
    return ServiceResponse(status, {"error": {"code": code, "message": message}})


__all__ = ["WorkerQueueHandler"]
