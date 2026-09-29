"""Metadata-only OSV relay for isolated connected workers."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping

from securecode_ai.adapters.dependency_scanning import (
    ApprovedOsvScanner,
    OsvBatchRequest,
    OsvBatchResponse,
)
from securecode_ai.adapters.dependency_scanning_osv import BoundedOsvScanner

from .ports import ServiceRequest, ServiceResponse
from .worker_queue import SqliteWorkerQueue

_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_QUERIES = 10_000
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_MAX_ADVISORIES = 10_000
_MAX_ALIASES = 64
_REQUEST_FIELDS = frozenset(
    {"execution_identity_hash", "purls", "run_id", "schema_version", "worker_id"}
)


class OsvMetadataRelay:
    """Authorize one worker lease and proxy only bounded package coordinates."""

    def __init__(
        self,
        *,
        queue: SqliteWorkerQueue,
        scanner: ApprovedOsvScanner | None = None,
    ) -> None:
        if type(queue) is not SqliteWorkerQueue:
            raise ValueError("OSV relay queue is invalid")
        selected = scanner or BoundedOsvScanner()
        if (
            type(getattr(selected, "scanner_id", None)) is not str
            or selected.scanner_id != "osv.dev"
            or type(getattr(selected, "scanner_version", None)) is not str
            or selected.scanner_version != "v1"
            or not callable(getattr(selected, "query_batch", None))
        ):
            raise ValueError("OSV relay scanner is invalid")
        self._queue = queue
        self._scanner = selected

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        parsed = self._request(request)
        if isinstance(parsed, ServiceResponse):
            return parsed
        session_id, worker_id, run_id, identity_hash, batch = parsed
        self._queue.authorize_session(
            tenant_id=request.identity.tenant_id,
            session_id=session_id,
            worker_id=worker_id,
            execution_identity_hash=identity_hash,
            run_id=run_id,
        )
        try:
            response = await asyncio.to_thread(self._scanner.query_batch, batch)
        except Exception:
            return _error(503, "OSV_UNAVAILABLE", "dependency metadata is unavailable")
        if type(response) is not OsvBatchResponse:
            return _error(503, "OSV_RESPONSE_INVALID", "dependency metadata is unavailable")
        try:
            document = _response_document(response, batch)
        except (TypeError, ValueError, OverflowError):
            return _error(503, "OSV_RESPONSE_INVALID", "dependency metadata is unavailable")
        if len(_encoded_size(document)) > _MAX_RESPONSE_BYTES:
            return _error(503, "OSV_RESPONSE_TOO_LARGE", "dependency metadata is unavailable")
        return ServiceResponse(200, document)

    @staticmethod
    def _request(
        request: ServiceRequest,
    ) -> tuple[str, str, str, str, OsvBatchRequest] | ServiceResponse:
        document = request.document
        session_id = request.path_params.get("session_id")
        if (
            request.action != "worker_sessions.osv.query"
            or not request.identity.workload
            or type(document) is not dict
            or set(document) != _REQUEST_FIELDS
            or type(request.raw_body) is not bytes
            or len(request.raw_body) > _MAX_REQUEST_BYTES
            or type(session_id) is not str
            or not session_id
        ):
            return _error(400, "OSV_REQUEST_INVALID", "dependency metadata request is invalid")
        worker_id = document.get("worker_id")
        run_id = document.get("run_id")
        identity_hash = document.get("execution_identity_hash")
        purls = document.get("purls")
        if (
            type(worker_id) is not str
            or worker_id != request.identity.subject_id
            or type(run_id) is not str
            or type(identity_hash) is not str
            or type(purls) is not list
            or len(purls) < 1
            or len(purls) > _MAX_TOTAL_QUERIES
            or any(type(item) is not str for item in purls)
        ):
            return _error(400, "OSV_REQUEST_INVALID", "dependency metadata request is invalid")
        try:
            batch = OsvBatchRequest(tuple(purls))
        except (TypeError, ValueError):
            return _error(400, "OSV_REQUEST_INVALID", "dependency metadata request is invalid")
        return session_id, worker_id, run_id, identity_hash, batch


def _response_document(response: OsvBatchResponse, request: OsvBatchRequest) -> dict[str, object]:
    if (
        len(response.results) != len(request.purls)
        or tuple(item.purl for item in response.results) != request.purls
    ):
        raise ValueError("OSV response does not match request")
    advisories = sum(len(item.advisories) for item in response.results)
    if advisories > _MAX_ADVISORIES:
        raise ValueError("OSV response is too large")
    for item in response.results:
        item.__post_init__()
        for advisory in item.advisories:
            advisory.__post_init__()
            if len(advisory.aliases) > _MAX_ALIASES:
                raise ValueError("OSV response is too large")
    return {
        "results": [
            {
                "advisories": [
                    {"aliases": list(advisory.aliases), "id": advisory.advisory_id}
                    for advisory in item.advisories
                ],
                "purl": item.purl,
            }
            for item in response.results
        ],
        "scanner": {"id": "osv.dev", "version": "v1"},
        "schema_version": "0.2.0",
    }


def _encoded_size(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _error(status: int, code: str, message: str) -> ServiceResponse:
    return ServiceResponse(status, {"error": {"code": code, "message": message}})


__all__ = ["OsvMetadataRelay"]
