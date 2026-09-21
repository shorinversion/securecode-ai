"""HTTP adapter for signed, bearer-free artifact PUT requests."""

from __future__ import annotations

from .artifact_upload import (
    ArtifactPutRequest,
    ArtifactUploadConflict,
    ArtifactUploadRejected,
    ArtifactUploadService,
    ArtifactUploadUnavailable,
)
from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError


class ArtifactUploadHandler:
    """Authenticate an upload through its signed short-lived authorization."""

    def __init__(self, service: ArtifactUploadService) -> None:
        self._service = service

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action != "artifacts.upload" or request.document is not None:
            raise ServiceUnavailableError()
        try:
            upload = ArtifactPutRequest(
                authorization_id=_header(request, "x-securecode-authorization-id"),
                tenant_id=_header(request, "x-securecode-tenant-id"),
                worker_id=_header(request, "x-securecode-worker-id"),
                run_id=_header(request, "x-securecode-run-id"),
                execution_identity_hash=_header(request, "x-securecode-execution-identity-hash"),
                content_sha256=_header(request, "x-securecode-content-sha256"),
                size_bytes=_size(request),
                purpose=_header(request, "x-securecode-purpose"),
                receipt_signature=_header(request, "x-securecode-receipt-signature"),
                content=request.raw_body,
            )
            if (
                request.path_params.get("tenant_id") != upload.tenant_id
                or request.path_params.get("content_sha256") != upload.content_sha256
                or request.path_params.get("authorization_id") != upload.authorization_id
            ):
                raise ArtifactUploadRejected()
            receipt = await self._service.put(upload)
        except (ArtifactUploadRejected, KeyError, TypeError, ValueError):
            return _error(403, "ARTIFACT_UPLOAD_DENIED", "artifact upload is not authorized")
        except ArtifactUploadConflict:
            return _error(
                409, "ARTIFACT_UPLOAD_CONFLICT", "artifact upload conflicts with stored content"
            )
        except ArtifactUploadUnavailable:
            return _error(
                503, "ARTIFACT_UPLOAD_UNAVAILABLE", "artifact upload store is unavailable"
            )
        return ServiceResponse(201, receipt.document())


def _header(request: ServiceRequest, name: str) -> str:
    value = request.headers.get(name)
    if not isinstance(value, str) or not value:
        raise ArtifactUploadRejected()
    return value


def _size(request: ServiceRequest) -> int:
    value = _header(request, "content-length")
    if not value.isdigit():
        raise ArtifactUploadRejected()
    size = int(value)
    if size != len(request.raw_body):
        raise ArtifactUploadRejected()
    return size


def _error(status: int, code: str, message: str) -> ServiceResponse:
    return ServiceResponse(status, {"error": {"code": code, "message": message}})


__all__ = ["ArtifactUploadHandler"]
