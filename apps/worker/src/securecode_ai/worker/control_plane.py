"""Least-privilege HTTP client for connected worker sessions."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http import HTTPStatus
from http.client import HTTPMessage
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
_API_VERSION: Final = "1.0.0"


class ControlPlaneError(RuntimeError):
    """Safe base class for transport and remote protocol failures."""


class RetryableControlPlaneError(ControlPlaneError):
    pass


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
        _validated_endpoint(base_url)
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
        if not events:
            raise ValueError("worker event batch is empty")
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
        self._upload(
            upload_url,
            artifact.content,
            upload_headers,
            timeout_seconds=self._request_timeout(deadline),
        )

        commit_body = self._session_body(job)
        commit_body.update(
            {
                "artifact_ref": reference,
                "authorization_id": authorization_id,
                "purpose": artifact.purpose,
            }
        )
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
    ) -> SessionUpdate:
        if outcome not in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}:
            raise ValueError("worker outcome is invalid")
        commits_result = outcome in {"PASS", "FAIL", "INDETERMINATE"}
        requires_measured_usage = outcome in {"PASS", "FAIL"}
        if (
            (requires_measured_usage and type(resource_usage) is not WorkerResourceUsage)
            or (resource_usage is not None and type(resource_usage) is not WorkerResourceUsage)
            or (not commits_result and resource_usage is not None)
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
        status, document = self._request_json(
            "POST",
            f"api/v1/worker-sessions/{quote(job.session_id, safe='')}:complete",
            body,
            idempotency_key=_idempotency_key(
                "complete", job.session_id, outcome, usage_key, findings_key
            ),
            version=job.version,
        )
        if status in {HTTPStatus.CONFLICT, HTTPStatus.PRECONDITION_FAILED, HTTPStatus.GONE}:
            raise LeaseLost("worker completion lost its lease")
        if status != HTTPStatus.OK:
            self._raise_status(status)
        update = _session_update(document, job.version)
        if (
            document.get("terminal") is not True
            or document.get("run_id") != job.run_id
            or document.get("session_id") != job.session_id
            or update.version <= job.version
        ):
            raise ControlPlaneRejected("worker completion response is invalid")
        return update

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
    ) -> tuple[int, dict[str, object]]:
        payload = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
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
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            status = int(error.code)
            try:
                raw = error.read(_MAX_RESPONSE_BYTES + 1)
            except (OSError, TimeoutError, URLError):
                raise RetryableControlPlaneError(
                    "control-plane transport is unavailable"
                ) from None
        except (OSError, TimeoutError, URLError):
            raise RetryableControlPlaneError("control-plane transport is unavailable") from None
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ControlPlaneRejected("control-plane response is too large")
        if not raw:
            return status, {}
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ControlPlaneRejected("control-plane response is invalid") from None
        if type(decoded) is not dict:
            raise ControlPlaneRejected("control-plane response is invalid")
        if (
            status == HTTPStatus.CONFLICT
            and _error_code(decoded) == "IDEMPOTENCY_IN_FLIGHT"
        ):
            raise RetryableControlPlaneError("control-plane request is still in flight")
        return status, decoded

    def _upload(
        self,
        url: str,
        content: bytes,
        headers: Mapping[object, object],
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        try:
            parsed = _validated_endpoint(url)
        except ValueError:
            raise ControlPlaneRejected("artifact upload destination is invalid") from None
        if parsed.hostname not in self._artifact_hosts:
            raise ControlPlaneRejected("artifact upload destination is not allowed")
        upload_headers = {"Content-Length": str(len(content))}
        for name, value in headers.items():
            if type(name) is not str or type(value) is not str:
                raise ControlPlaneRejected("artifact upload headers are invalid")
            if not _is_http_header_name(name):
                raise ControlPlaneRejected("artifact upload headers are invalid")
            lowered = name.lower()
            if lowered in {"authorization", "proxy-authorization", "cookie", "host"}:
                raise ControlPlaneRejected("artifact upload headers are invalid")
            if "\r" in value or "\n" in value:
                raise ControlPlaneRejected("artifact upload headers are invalid")
            if lowered == "content-length":
                if value != str(len(content)):
                    raise ControlPlaneRejected("artifact upload headers are invalid")
                continue
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
            except (OSError, TimeoutError, URLError):
                raise RetryableControlPlaneError("artifact upload is unavailable") from None
        except (OSError, TimeoutError, URLError):
            raise RetryableControlPlaneError("artifact upload is unavailable") from None
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise ControlPlaneRejected("artifact upload response is too large")
        if status not in {HTTPStatus.OK, HTTPStatus.CREATED, HTTPStatus.NO_CONTENT}:
            if (
                status == HTTPStatus.CONFLICT
                and _response_error_code(raw) == "IDEMPOTENCY_IN_FLIGHT"
            ):
                raise RetryableControlPlaneError("artifact upload is still in flight")
            self._raise_status(status)

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


def _session_update(document: Mapping[str, object], current_version: int) -> SessionUpdate:
    version = document.get("version", current_version)
    command_value = document.get("command", WorkerCommand.CONTINUE.value)
    try:
        if type(command_value) is not str:
            raise ValueError("worker command is invalid")
        command = WorkerCommand(command_value)
    except (TypeError, ValueError):
        raise ControlPlaneRejected("worker session response is invalid") from None
    if type(version) is not int or version < current_version:
        raise ControlPlaneRejected("worker session response is invalid")
    return SessionUpdate(version, command)


def _error_code(document: Mapping[str, object]) -> str | None:
    error = document.get("error")
    if not isinstance(error, Mapping):
        return None
    code = error.get("code")
    return code if type(code) is str else None


def _response_error_code(raw: bytes) -> str | None:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return _error_code(document) if type(document) is dict else None


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
    if type(url) is not str or len(url) > 4096:
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
    "ControlPlaneRejected",
    "LeaseLost",
    "NoWork",
    "RetryableControlPlaneError",
    "SessionUpdate",
]
