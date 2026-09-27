"""Least-privilege HTTP client for connected worker sessions."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from http import HTTPStatus
from http.client import HTTPMessage, IncompleteRead
from typing import IO, Final
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, quote, urljoin, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from securecode_ai.adapters.dependency_scanning import (
    OsvAdvisoryRecord,
    OsvBatchRequest,
    OsvBatchResponse,
    OsvPackageResult,
)

from .protocol import (
    ProtocolError,
    WorkerArtifact,
    WorkerCommand,
    WorkerEvent,
    WorkerFinding,
    WorkerJob,
    WorkerResourceUsage,
)

_MAX_RESPONSE_BYTES: Final = 1_048_576
_MAX_OSV_RESPONSE_BYTES: Final = 16 * 1024 * 1024
_MAX_OSV_REQUEST_BYTES: Final = 2 * 1024 * 1024
_MAX_OSV_TRANSPORT_SECONDS: Final = 15.0
_MAX_OSV_QUERIES: Final = 10_000
_MAX_OSV_ADVISORIES: Final = 10_000
_MAX_OSV_ALIASES: Final = 64
_MAX_REQUEST_BYTES: Final = 16_777_216
_MAX_SESSION_VERSION: Final = 2_147_483_647
_MAX_COMPLETION_RECONCILIATION_SECONDS: Final = 30.0
_API_VERSION: Final = "1.0.0"
_ARTIFACT_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_UPLOAD_AUTHORIZATION_FIELDS: Final = frozenset(
    {
        "authorization_id",
        "upload_url",
        "headers",
        "expires_at",
        "receipt_signature",
        "signer_key_id",
        "tenant_id",
        "repository_id",
        "run_id",
        "execution_identity_hash",
        "content_sha256",
        "size_bytes",
        "purpose",
        "method",
    }
)
_UPLOAD_RECEIPT_FIELDS: Final = frozenset(
    {
        "schema_version",
        "authorization_id",
        "tenant_id",
        "worker_id",
        "repository_id",
        "run_id",
        "execution_identity_hash",
        "content_id",
        "content_sha256",
        "size_bytes",
        "data_class",
        "purpose",
        "signer_key_id",
        "authorization_signature",
        "authorized_at",
        "authorization_expires_at",
        "stored_at",
        "object_key",
    }
)


class ControlPlaneError(RuntimeError):
    """Safe base class for transport and remote protocol failures."""


class RetryableControlPlaneError(ControlPlaneError):
    pass


class IdempotencyInFlight(RetryableControlPlaneError):
    """The same mutating request is still executing on the control plane."""


class ControlPlaneRejected(ControlPlaneError):
    pass


class LeaseLost(ControlPlaneError):
    pass


class NoWork(ControlPlaneError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> Request | None:
        return None


@dataclass(frozen=True, slots=True)
class SessionUpdate:
    version: int
    command: WorkerCommand
    terminal: bool = False
    outcome: str | None = None


class ControlPlaneClient:
    """Perform bounded JSON requests without forwarding credentials elsewhere."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        worker_id: str,
        timeout_seconds: float,
        artifact_hosts: frozenset[str],
    ) -> None:
        parsed_base_url = _validated_endpoint(base_url)
        if parsed_base_url.path not in {"", "/"} or parsed_base_url.query:
            raise ValueError("control-plane settings are invalid")
        if (
            type(token) is not str
            or len(token) < 32
            or type(worker_id) is not str
            or not worker_id
            or type(timeout_seconds) is not float
            or not 1.0 <= timeout_seconds <= 120.0
            or not artifact_hosts
            or any(type(host) is not str or not host for host in artifact_hosts)
        ):
            raise ValueError("control-plane settings are invalid")
        self._base_url = base_url.rstrip("/") + "/"
        self._token = token
        self._worker_id = worker_id
        self._timeout = timeout_seconds
        self._artifact_hosts = artifact_hosts
        self._opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl.create_default_context()),
            _NoRedirect(),
        )

    def open_session(self, *, attempt: int, requested_run_id: str | None) -> WorkerJob:
        if (
            type(attempt) is not int
            or not 0 <= attempt <= _MAX_SESSION_VERSION
            or (requested_run_id is not None and type(requested_run_id) is not str)
        ):
            raise ValueError("worker claim request is invalid")
        body: dict[str, object] = {
            "schema_version": "0.2.0",
            "worker_id": self._worker_id,
        }
        if requested_run_id is not None:
            body["run_id"] = requested_run_id
        key = _idempotency_key("claim", self._worker_id, str(attempt), requested_run_id or "queue")
        status, document = self._request_json(
            "POST", "api/v1/worker-sessions", body, idempotency_key=key
        )
        if status == HTTPStatus.NO_CONTENT or (
            status == HTTPStatus.NOT_FOUND and requested_run_id is None
        ):
            raise NoWork("no worker job is available")
        if status not in {HTTPStatus.OK, HTTPStatus.CREATED}:
            self._raise_status(status)
        try:
            return WorkerJob.from_document(document)
        except ProtocolError:
            raise ControlPlaneRejected("control-plane response is invalid") from None

    def resolve_scm_run(
        self,
        *,
        provider: str,
        repository_id: str,
        change_id: str,
        head_sha: str,
    ) -> str:
        """Resolve the pending run for one exact CI revision before claiming work."""

        body = {
            "change_id": change_id,
            "head_sha": head_sha,
            "provider": provider,
            "repository_id": repository_id,
        }
        key = _idempotency_key("resolve", provider, repository_id, change_id, head_sha)
        status, document = self._request_json(
            "POST", "api/v1/scm/runs:resolve", body, idempotency_key=key
        )
        if status == HTTPStatus.NOT_FOUND:
            raise NoWork("SCM run is not admitted")
        if status != HTTPStatus.OK:
            self._raise_status(status)
        run_id = document.get("run_id")
        returned_head = document.get("head_sha")
        returned_repository = document.get("repository_id")
        if (
            type(run_id) is not str
            or not run_id
            or returned_head != head_sha
            or returned_repository != repository_id
        ):
            raise ControlPlaneRejected("control-plane response is invalid")
        return run_id

    def heartbeat(self, job: WorkerJob, *, attempt: int) -> SessionUpdate:
        if (
            type(job) is not WorkerJob
            or type(attempt) is not int
            or not 0 <= attempt <= _MAX_SESSION_VERSION
        ):
            raise ValueError("worker heartbeat request is invalid")
        body = self._session_body(job)
        key = _idempotency_key("heartbeat", job.session_id, str(attempt))
        status, document = self._request_json(
            "POST",
            f"api/v1/worker-sessions/{quote(job.session_id, safe='')}:heartbeat",
            body,
            idempotency_key=key,
            version=job.version,
        )
        if status in {HTTPStatus.CONFLICT, HTTPStatus.PRECONDITION_FAILED, HTTPStatus.GONE}:
            raise LeaseLost("worker lease is no longer current")
        if status != HTTPStatus.OK:
            self._raise_status(status)
        return _session_update(document, job.version)

    def append_events(self, job: WorkerJob, events: tuple[WorkerEvent, ...]) -> SessionUpdate:
        if (
            type(job) is not WorkerJob
            or type(events) is not tuple
            or not events
            or len(events) > 64
            or any(type(item) is not WorkerEvent for item in events)
        ):
            raise ValueError("worker event batch is invalid")
        body = self._session_body(job)
        body["events"] = [event.document() for event in events]
        batch_hash = hashlib.sha256(
            json.dumps(body["events"], sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        status, document = self._request_json(
            "POST",
            f"api/v1/worker-sessions/{quote(job.session_id, safe='')}/events:append",
            body,
            idempotency_key=_idempotency_key("events", job.session_id, batch_hash),
            version=job.version,
        )
        if status == HTTPStatus.CONFLICT and _error_code(document) == "WORKER_CONFLICT":
            raise ControlPlaneRejected("worker event conflicts with current command")
        if status in {HTTPStatus.CONFLICT, HTTPStatus.PRECONDITION_FAILED, HTTPStatus.GONE}:
            raise LeaseLost("worker event append lost its lease")
        if status != HTTPStatus.OK:
            self._raise_status(status)
        return _session_update(document, job.version)

    def publish_artifact(
        self,
        job: WorkerJob,
        artifact: WorkerArtifact,
        *,
        deadline: Callable[[], float] | None = None,
    ) -> SessionUpdate:
        if type(job) is not WorkerJob or type(artifact) is not WorkerArtifact:
            raise ValueError("worker artifact request is invalid")
        reference = artifact.reference.model_dump(mode="json")
        authorize_body = {
            "artifact_ref": reference,
            "execution_identity_hash": job.execution_identity.execution_identity_hash,
            "method": "PUT",
            "purpose": artifact.purpose,
            "repository_id": job.execution_identity.repository_revision.repository_id,
            "run_id": job.run_id,
            "schema_version": "0.2.0",
            "session_id": job.session_id,
            "worker_id": self._worker_id,
        }
        authorize_key = _idempotency_key(
            "authorize", job.session_id, artifact.reference.content_sha256, artifact.purpose
        )
        status, authorization = self._request_json(
            "POST",
            "api/v1/artifacts:authorize",
            authorize_body,
            idempotency_key=authorize_key,
            timeout_seconds=self._request_timeout(deadline),
        )
        if status not in {HTTPStatus.OK, HTTPStatus.CREATED}:
            self._raise_status(status)
        upload_url = authorization.get("upload_url")
        authorization_id = authorization.get("authorization_id")
        upload_headers = authorization.get("headers", {})
        if (
            type(upload_url) is not str
            or not upload_url
            or type(authorization_id) is not str
            or not authorization_id
            or not isinstance(upload_headers, Mapping)
        ):
            raise ControlPlaneRejected("artifact authorization is invalid")
        authorization_expires_at = _validate_artifact_authorization(
            authorization,
            job=job,
            artifact=artifact,
            worker_id=self._worker_id,
        )
        receipt = self._upload(
            upload_url,
            artifact.content,
            # The PUT is a mutating control-plane route too. Reusing this key
            # lets a lost response replay the stored receipt safely.
            upload_headers,
            idempotency_key=_idempotency_key(
                "upload", job.session_id, artifact.reference.content_sha256, artifact.purpose
            ),
            timeout_seconds=self._request_timeout(deadline),
        )
        _validate_artifact_upload_receipt(
            receipt,
            authorization=authorization,
            authorization_expires_at=authorization_expires_at,
            job=job,
            artifact=artifact,
            worker_id=self._worker_id,
        )

        commit_body = self._session_body(job)
        commit_body.update(
            {
                "artifact_ref": reference,
                "authorization_id": authorization_id,
                "purpose": artifact.purpose,
            }
        )
        if artifact.binding is not None:
            commit_body["binding"] = artifact.binding.document()
        status, document = self._request_json(
            "POST",
            f"api/v1/worker-sessions/{quote(job.session_id, safe='')}/artifacts:commit",
            commit_body,
            idempotency_key=_idempotency_key(
                "artifact", job.session_id, artifact.reference.content_sha256, artifact.purpose
            ),
            version=job.version,
            timeout_seconds=self._request_timeout(deadline),
        )
        if status in {HTTPStatus.CONFLICT, HTTPStatus.PRECONDITION_FAILED, HTTPStatus.GONE}:
            raise LeaseLost("worker artifact commit lost its lease")
        if status != HTTPStatus.OK:
            self._raise_status(status)
        return _session_update(document, job.version)

    def complete(
        self,
        job: WorkerJob,
        *,
        outcome: str,
        resource_usage: WorkerResourceUsage | None = None,
        findings: tuple[WorkerFinding, ...] = (),
        deadline: Callable[[], float] | None = None,
    ) -> SessionUpdate:
        if type(job) is not WorkerJob:
            raise ValueError("worker completion request is invalid")
        if outcome not in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}:
            raise ValueError("worker outcome is invalid")
        commits_result = outcome in {"PASS", "FAIL", "INDETERMINATE"}
        requires_measured_usage = commits_result
        if (
            (requires_measured_usage and type(resource_usage) is not WorkerResourceUsage)
            or (resource_usage is not None and type(resource_usage) is not WorkerResourceUsage)
            or type(findings) is not tuple
            or any(type(item) is not WorkerFinding for item in findings)
            or len(findings) > 100_000
            or (not commits_result and findings)
        ):
            raise ValueError("worker completion is invalid")
        revision = job.execution_identity.repository_revision
        finding_ids = tuple(item.finding_id for item in findings)
        if (
            finding_ids != tuple(sorted(finding_ids))
            or len(finding_ids) != len(set(finding_ids))
            or any(
                item.revision_sha != revision.head_sha
                or item.evidence_graph_ref.tenant_id != revision.tenant_id
                for item in findings
            )
            or any(
                item.blocking and item.verdict not in {"CONFIRMED", "CONFLICTING"}
                for item in findings
            )
            or (
                commits_result
                and (outcome == "FAIL") is not any(item.blocking for item in findings)
            )
        ):
            raise ValueError("worker completion is invalid")
        body = self._session_body(job)
        body["outcome"] = outcome
        finding_documents = [item.document() for item in findings]
        if commits_result:
            body["findings"] = finding_documents
        if resource_usage is not None:
            body["resource_usage"] = resource_usage.document()
        usage_key = (
            hashlib.sha256(
                json.dumps(
                    resource_usage.document(),
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ).hexdigest()
            if resource_usage is not None
            else "reserved"
            if outcome == "INDETERMINATE"
            else "released"
        )
        findings_key = hashlib.sha256(
            json.dumps(
                finding_documents,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        ).hexdigest()
        status, document = self._request_json_reconciled(
            "POST",
            f"api/v1/worker-sessions/{quote(job.session_id, safe='')}:complete",
            body,
            idempotency_key=_idempotency_key(
                "complete", job.session_id, outcome, usage_key, findings_key
            ),
            version=job.version,
            deadline=deadline,
            timeout_seconds=self._request_timeout(deadline),
        )
        if status in {HTTPStatus.CONFLICT, HTTPStatus.PRECONDITION_FAILED, HTTPStatus.GONE}:
            raise LeaseLost("worker completion lost its lease")
        if status != HTTPStatus.OK:
            self._raise_status(status)
        update = _session_update(document, job.version)
        if (
            update.terminal is not True
            or update.outcome != outcome
            or document.get("run_id") != job.run_id
            or document.get("session_id") != job.session_id
            or update.version <= job.version
        ):
            raise ControlPlaneRejected("worker completion response is invalid")
        return update

    def osv_scanner(self, job: WorkerJob) -> ControlPlaneOsvScanner:
        if type(job) is not WorkerJob:
            raise ValueError("worker OSV session is invalid")
        return ControlPlaneOsvScanner(self, job)

    def query_osv(self, job: WorkerJob, request: OsvBatchRequest) -> OsvBatchResponse:
        if type(job) is not WorkerJob or type(request) is not OsvBatchRequest:
            raise ValueError("worker OSV request is invalid")
        if len(request.purls) > _MAX_OSV_QUERIES:
            raise ControlPlaneRejected("OSV request is too large")
        body = self._session_body(job)
        body["purls"] = list(request.purls)
        payload = json.dumps(
            body,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if len(payload) > _MAX_OSV_REQUEST_BYTES:
            raise ControlPlaneRejected("OSV request is too large")
        digest = hashlib.sha256(payload).hexdigest()
        status, document = self._request_json(
            "POST",
            f"api/v1/worker-sessions/{quote(job.session_id, safe='')}/osv:query",
            body,
            idempotency_key=_idempotency_key("osv", job.session_id, digest),
            timeout_seconds=min(self._timeout, _MAX_OSV_TRANSPORT_SECONDS),
            max_response_bytes=_MAX_OSV_RESPONSE_BYTES,
        )
        if status in {HTTPStatus.CONFLICT, HTTPStatus.PRECONDITION_FAILED, HTTPStatus.GONE}:
            raise LeaseLost("worker OSV request lost its lease")
        if status != HTTPStatus.OK:
            self._raise_status(status)
        return _osv_batch_response(document, request)

    def _session_body(self, job: WorkerJob) -> dict[str, object]:
        return {
            "execution_identity_hash": job.execution_identity.execution_identity_hash,
            "run_id": job.run_id,
            "schema_version": "0.2.0",
            "worker_id": self._worker_id,
        }

    def _request_json(
        self,
        method: str,
        path: str,
        document: Mapping[str, object],
        *,
        idempotency_key: str,
        version: int | None = None,
        timeout_seconds: float | None = None,
        max_response_bytes: int = _MAX_RESPONSE_BYTES,
    ) -> tuple[int, dict[str, object]]:
        if (
            type(max_response_bytes) is not int
            or not 1 <= max_response_bytes <= _MAX_OSV_RESPONSE_BYTES
        ):
            raise ValueError("control-plane response limit is invalid")
        payload = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if len(payload) > _MAX_REQUEST_BYTES:
            raise ControlPlaneRejected("control-plane request is too large")
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self._token,
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency_key,
            "X-SecureCode-Api-Version": _API_VERSION,
        }
        if version is not None:
            headers["If-Match"] = str(version)
        request = Request(
            urljoin(self._base_url, path),
            data=payload,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(
                request,
                timeout=self._timeout if timeout_seconds is None else timeout_seconds,
            ) as response:
                status = int(response.status)
                raw = response.read(max_response_bytes + 1)
        except HTTPError as error:
            status = int(error.code)
            try:
                raw = error.read(max_response_bytes + 1)
            except (IncompleteRead, OSError, TimeoutError, URLError):
                raise RetryableControlPlaneError(
                    "control-plane transport is unavailable"
                ) from None
        except (IncompleteRead, OSError, TimeoutError, URLError):
            raise RetryableControlPlaneError("control-plane transport is unavailable") from None
        if len(raw) > max_response_bytes:
            raise ControlPlaneRejected("control-plane response is too large")
        if not raw:
            return status, {}
        try:
            decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_closed_object)
        except (
            OverflowError,
            RecursionError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ):
            raise ControlPlaneRejected("control-plane response is invalid") from None
        if type(decoded) is not dict:
            raise ControlPlaneRejected("control-plane response is invalid")
        if (
            status == HTTPStatus.CONFLICT
            and _error_code(decoded) == "IDEMPOTENCY_IN_FLIGHT"
        ):
            raise IdempotencyInFlight("control-plane request is still in flight")
        return status, decoded

    def _request_json_reconciled(
        self,
        method: str,
        path: str,
        document: Mapping[str, object],
        *,
        idempotency_key: str,
        version: int | None = None,
        deadline: Callable[[], float] | None = None,
        timeout_seconds: float | None = None,
    ) -> tuple[int, dict[str, object]]:
        """Replay one mutating request until its original result is durable."""

        try:
            return self._request_json(
                method,
                path,
                document,
                idempotency_key=idempotency_key,
                version=version,
                timeout_seconds=timeout_seconds,
            )
        except IdempotencyInFlight:
            reconciliation_deadline = time.monotonic() + _MAX_COMPLETION_RECONCILIATION_SECONDS
            delay = 0.1
            while True:
                remaining = reconciliation_deadline - time.monotonic()
                if remaining <= 0:
                    raise RetryableControlPlaneError(
                        "control-plane completion reconciliation timed out"
                    ) from None
                time.sleep(min(delay, remaining))
                try:
                    return self._request_json(
                        method,
                        path,
                        document,
                        idempotency_key=idempotency_key,
                        version=version,
                        timeout_seconds=self._request_timeout(deadline),
                    )
                except IdempotencyInFlight:
                    delay = min(1.0, delay * 2.0)
                except RetryableControlPlaneError:
                    delay = min(1.0, delay * 2.0)

    def _upload(
        self,
        url: str,
        content: bytes,
        headers: Mapping[object, object],
        *,
        idempotency_key: str,
        timeout_seconds: float | None = None,
    ) -> dict[str, object]:
        try:
            parsed = _validated_endpoint(url)
        except ValueError:
            raise ControlPlaneRejected("artifact upload destination is invalid") from None
        if parsed.hostname not in self._artifact_hosts:
            raise ControlPlaneRejected("artifact upload destination is not allowed")
        if type(idempotency_key) is not str or not idempotency_key:
            raise ControlPlaneRejected("artifact upload idempotency key is invalid")
        upload_headers = {
            "Content-Length": str(len(content)),
            "Idempotency-Key": idempotency_key,
        }
        seen_headers = {"content-length", "idempotency-key"}
        for name, value in headers.items():
            if type(name) is not str or type(value) is not str:
                raise ControlPlaneRejected("artifact upload headers are invalid")
            if not _is_http_header_name(name):
                raise ControlPlaneRejected("artifact upload headers are invalid")
            lowered = name.lower()
            if lowered in {
                "authorization",
                "proxy-authorization",
                "cookie",
                "host",
                "idempotency-key",
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
            }:
                raise ControlPlaneRejected("artifact upload headers are invalid")
            if "\r" in value or "\n" in value:
                raise ControlPlaneRejected("artifact upload headers are invalid")
            if lowered == "content-length":
                if value != str(len(content)):
                    raise ControlPlaneRejected("artifact upload headers are invalid")
                continue
            if lowered in seen_headers:
                raise ControlPlaneRejected("artifact upload headers are invalid")
            seen_headers.add(lowered)
            upload_headers[name] = value
        request = Request(url, data=content, headers=upload_headers, method="PUT")
        try:
            with self._opener.open(
                request,
                timeout=self._timeout if timeout_seconds is None else timeout_seconds,
            ) as response:
                status = int(response.status)
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            status = int(error.code)
            try:
                raw = error.read(_MAX_RESPONSE_BYTES + 1)
            except (IncompleteRead, OSError, TimeoutError, URLError):
                raise RetryableControlPlaneError("artifact upload is unavailable") from None
        except (IncompleteRead, OSError, TimeoutError, URLError):
            raise RetryableControlPlaneError("artifact upload is unavailable") from None
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ControlPlaneRejected("artifact upload response is too large")
        # The server returns 201 for the first durable write and 200 when the
        # same authorization-bound idempotency key replays the stored receipt.
        # Both responses continue through the identical strict receipt and
        # execution binding validation in publish_artifact().
        if status not in {HTTPStatus.OK, HTTPStatus.CREATED}:
            if (
                status == HTTPStatus.CONFLICT
                and _response_error_code(raw) == "IDEMPOTENCY_IN_FLIGHT"
            ):
                raise RetryableControlPlaneError("artifact upload is still in flight")
            self._raise_status(status)
        try:
            decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_closed_object)
        except (
            OverflowError,
            RecursionError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ):
            raise ControlPlaneRejected("artifact upload receipt is invalid") from None
        if type(decoded) is not dict:
            raise ControlPlaneRejected("artifact upload receipt is invalid")
        return decoded

    def _request_timeout(self, deadline: Callable[[], float] | None) -> float | None:
        if deadline is None:
            return None
        remaining = deadline() - time.monotonic()
        if remaining < 0.1:
            raise RetryableControlPlaneError("worker lease time is exhausted")
        return min(self._timeout, remaining)

    @staticmethod
    def _raise_status(status: int) -> None:
        if status in {HTTPStatus.REQUEST_TIMEOUT, HTTPStatus.TOO_MANY_REQUESTS} or status >= 500:
            raise RetryableControlPlaneError("control-plane request can be retried")
        raise ControlPlaneRejected("control-plane request was rejected")


def _validate_artifact_authorization(
    authorization: Mapping[str, object],
    *,
    job: WorkerJob,
    artifact: WorkerArtifact,
    worker_id: str,
) -> str:
    reference = artifact.reference
    tenant_id = job.execution_identity.repository_revision.tenant_id
    if (
        type(authorization) is not dict
        or set(authorization) != _UPLOAD_AUTHORIZATION_FIELDS
        or reference.tenant_id != tenant_id
        or type(artifact.content) is not bytes
        or len(artifact.content) != reference.size_bytes
        or hashlib.sha256(artifact.content).hexdigest() != reference.content_sha256
    ):
        raise ControlPlaneRejected("artifact authorization is invalid")

    authorization_id = authorization.get("authorization_id")
    upload_url = authorization.get("upload_url")
    signer_key_id = authorization.get("signer_key_id")
    receipt_signature = authorization.get("receipt_signature")
    expires_at = authorization.get("expires_at")
    headers = authorization.get("headers")
    expected_text = {
        "tenant_id": tenant_id,
        "repository_id": job.execution_identity.repository_revision.repository_id,
        "run_id": job.run_id,
        "execution_identity_hash": job.execution_identity.execution_identity_hash,
        "content_sha256": reference.content_sha256,
        "purpose": artifact.purpose,
        "method": "PUT",
    }
    if (
        type(authorization_id) is not str
        or _ARTIFACT_ID.fullmatch(authorization_id) is None
        or type(upload_url) is not str
        or not upload_url
        or type(signer_key_id) is not str
        or not 1 <= len(signer_key_id) <= 128
        or any(not 0x21 <= ord(character) <= 0x7E for character in signer_key_id)
        or type(receipt_signature) is not str
        or not 1 <= len(receipt_signature) <= 2048
        or any(not 0x21 <= ord(character) <= 0x7E for character in receipt_signature)
        or type(authorization.get("size_bytes")) is not int
        or authorization["size_bytes"] != reference.size_bytes
        or any(
            type(authorization.get(name)) is not str
            or authorization[name] != value
            for name, value in expected_text.items()
        )
        or type(headers) is not dict
        or type(expires_at) is not str
        or _parse_artifact_timestamp(expires_at) is None
    ):
        raise ControlPlaneRejected("artifact authorization is invalid")

    expected_headers = {
        "content-length": str(reference.size_bytes),
        "x-securecode-authorization-id": authorization_id,
        "x-securecode-content-sha256": reference.content_sha256,
        "x-securecode-execution-identity-hash": job.execution_identity.execution_identity_hash,
        "x-securecode-purpose": artifact.purpose,
        "x-securecode-repository-id": job.execution_identity.repository_revision.repository_id,
        "x-securecode-receipt-signature": receipt_signature,
        "x-securecode-run-id": job.run_id,
        "x-securecode-tenant-id": reference.tenant_id,
        "x-securecode-worker-id": worker_id,
    }
    if headers != expected_headers:
        raise ControlPlaneRejected("artifact authorization is invalid")
    return expires_at


def _validate_artifact_upload_receipt(
    receipt: Mapping[str, object],
    *,
    authorization: Mapping[str, object],
    authorization_expires_at: str,
    job: WorkerJob,
    artifact: WorkerArtifact,
    worker_id: str,
) -> None:
    if (
        type(receipt) is not dict
        or set(receipt) != _UPLOAD_RECEIPT_FIELDS
        or type(receipt.get("schema_version")) is not int
        or receipt["schema_version"] != 1
        or type(receipt.get("size_bytes")) is not int
        or receipt["size_bytes"] != artifact.reference.size_bytes
    ):
        raise ControlPlaneRejected("artifact upload receipt is invalid")

    expected = {
        "authorization_id": authorization["authorization_id"],
        "tenant_id": job.execution_identity.repository_revision.tenant_id,
        "worker_id": worker_id,
        "repository_id": job.execution_identity.repository_revision.repository_id,
        "run_id": job.run_id,
        "execution_identity_hash": job.execution_identity.execution_identity_hash,
        "content_id": artifact.reference.content_id,
        "content_sha256": artifact.reference.content_sha256,
        "data_class": artifact.reference.data_class.value,
        "purpose": artifact.purpose,
        "signer_key_id": authorization["signer_key_id"],
        "authorization_signature": authorization["receipt_signature"],
        "object_key": "/".join(
            (
                artifact.reference.tenant_id,
                artifact.reference.content_sha256[:2],
                artifact.reference.content_sha256,
            )
        ),
        "authorization_expires_at": authorization_expires_at,
    }
    if any(
        type(receipt.get(name)) is not str or receipt[name] != value
        for name, value in expected.items()
    ):
        raise ControlPlaneRejected("artifact upload receipt is invalid")

    authorized_at = _parse_artifact_timestamp(receipt.get("authorized_at"))
    expires_at = _parse_artifact_timestamp(receipt.get("authorization_expires_at"))
    stored_at = _parse_artifact_timestamp(receipt.get("stored_at"))
    if authorized_at is None or expires_at is None or stored_at is None:
        raise ControlPlaneRejected("artifact upload receipt is invalid")
    if not authorized_at < expires_at or not authorized_at <= stored_at < expires_at:
        raise ControlPlaneRejected("artifact upload receipt is invalid")


def _parse_artifact_timestamp(value: object) -> datetime | None:
    if type(value) is not str:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (OverflowError, ValueError):
        return None
    if parsed.utcoffset() != timedelta(0) or parsed.isoformat() != value:
        return None
    return parsed


def _session_update(document: Mapping[str, object], current_version: int) -> SessionUpdate:
    version = document.get("version")
    command_value = document.get("command")
    terminal = document.get("terminal", False)
    outcome = document.get("outcome")
    try:
        if type(command_value) is not str:
            raise ValueError("worker command is invalid")
        command = WorkerCommand(command_value)
    except (TypeError, ValueError):
        raise ControlPlaneRejected("worker session response is invalid") from None
    if (
        type(version) is not int
        or not 1 <= version <= _MAX_SESSION_VERSION
        or version < current_version
        or (version == current_version and command is WorkerCommand.CONTINUE)
    ):
        raise ControlPlaneRejected("worker session response is invalid")
    if (
        type(terminal) is not bool
        or (outcome is not None and type(outcome) is not str)
        or (
            terminal
            and outcome
            not in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}
        )
        or (not terminal and outcome is not None)
    ):
        raise ControlPlaneRejected("worker session response is invalid")
    return SessionUpdate(version, command, terminal, outcome)


class ControlPlaneOsvScanner:
    """Use the authenticated control plane as the OSV metadata transport."""

    scanner_id = "osv.dev"
    scanner_version = "v1"

    def __init__(self, client: ControlPlaneClient, job: WorkerJob) -> None:
        if type(client) is not ControlPlaneClient or type(job) is not WorkerJob:
            raise ValueError("worker OSV scanner settings are invalid")
        self._client = client
        self._job = job

    def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse:
        return self._client.query_osv(self._job, request)


def _osv_batch_response(
    document: Mapping[str, object], request: OsvBatchRequest
) -> OsvBatchResponse:
    if (
        type(document) is not dict
        or set(document) != {"results", "scanner", "schema_version"}
        or document.get("schema_version") != "0.2.0"
    ):
        raise ControlPlaneRejected("OSV response is invalid")
    scanner = document.get("scanner")
    results = document.get("results")
    if (
        type(scanner) is not dict
        or set(scanner) != {"id", "version"}
        or scanner.get("id") != "osv.dev"
        or scanner.get("version") != "v1"
        or type(results) is not list
        or len(results) != len(request.purls)
    ):
        raise ControlPlaneRejected("OSV response is invalid")
    output: list[OsvPackageResult] = []
    total_advisories = 0
    for expected_purl, item in zip(request.purls, results, strict=True):
        if type(item) is not dict or set(item) != {"advisories", "purl"}:
            raise ControlPlaneRejected("OSV response is invalid")
        if item.get("purl") != expected_purl:
            raise ControlPlaneRejected("OSV response is invalid")
        values = item.get("advisories")
        if type(values) is not list:
            raise ControlPlaneRejected("OSV response is invalid")
        total_advisories += len(values)
        if total_advisories > _MAX_OSV_ADVISORIES:
            raise ControlPlaneRejected("OSV response is too large")
        advisories: list[OsvAdvisoryRecord] = []
        for value in values:
            if type(value) is not dict or set(value) != {"aliases", "id"}:
                raise ControlPlaneRejected("OSV response is invalid")
            aliases = value.get("aliases")
            advisory_id = value.get("id")
            if type(advisory_id) is not str:
                raise ControlPlaneRejected("OSV response is invalid")
            if type(aliases) is not list or len(aliases) > _MAX_OSV_ALIASES:
                raise ControlPlaneRejected("OSV response is invalid")
            alias_values: list[str] = []
            for alias in aliases:
                if type(alias) is not str:
                    raise ControlPlaneRejected("OSV response is invalid")
                alias_values.append(alias)
            try:
                advisory = OsvAdvisoryRecord(advisory_id, tuple(alias_values))
            except (TypeError, ValueError):
                raise ControlPlaneRejected("OSV response is invalid") from None
            advisories.append(advisory)
        try:
            output.append(OsvPackageResult(expected_purl, tuple(advisories)))
        except (TypeError, ValueError):
            raise ControlPlaneRejected("OSV response is invalid") from None
    try:
        return OsvBatchResponse(tuple(output))
    except (TypeError, ValueError):
        raise ControlPlaneRejected("OSV response is invalid") from None


def _error_code(document: Mapping[str, object]) -> str | None:
    error = document.get("error")
    if not isinstance(error, Mapping):
        return None
    code = error.get("code")
    return code if type(code) is str else None


def _response_error_code(raw: bytes) -> str | None:
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_closed_object)
    except (OverflowError, RecursionError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    return _error_code(document) if type(document) is dict else None


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, item in pairs:
        if key in document:
            raise ValueError("duplicate control-plane field")
        document[key] = item
    return document


def _idempotency_key(*parts: str) -> str:
    digest = hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()
    return "worker-" + digest


def _is_http_header_name(name: str) -> bool:
    return bool(name) and all(
        character.isascii()
        and (character.isalnum() or character in "!#$%&'*+-.^_`|~")
        for character in name
    )


def _validated_endpoint(url: str) -> SplitResult:
    if (
        type(url) is not str
        or not url
        or len(url) > 4096
        or url != url.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in url)
    ):
        raise ValueError("endpoint is invalid")
    parsed = urlsplit(url)
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("endpoint is invalid") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or (port is not None and not 1 <= port <= 65535)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("endpoint is invalid")
    if parsed.scheme == "http":
        try:
            if not ipaddress.ip_address(parsed.hostname).is_loopback:
                raise ValueError("endpoint is invalid")
        except ValueError:
            raise ValueError("endpoint is invalid") from None
    return parsed


__all__ = [
    "ControlPlaneClient",
    "ControlPlaneError",
    "ControlPlaneOsvScanner",
    "ControlPlaneRejected",
    "IdempotencyInFlight",
    "LeaseLost",
    "NoWork",
    "RetryableControlPlaneError",
    "SessionUpdate",
]
