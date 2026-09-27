"""HTTP adapter for signed, bearer-free artifact PUT requests."""

from __future__ import annotations

from .artifact_upload import (
    ArtifactPutRequest,
    ArtifactUploadConflict,
    ArtifactUploadReceipt,
    ArtifactUploadRejected,
    ArtifactUploadService,
    ArtifactUploadUnavailable,
)
from .ports import ServiceRequest, ServiceResponse, ServiceUnavailableError


class ArtifactUploadHandler:
    """Authenticate an upload through its signed short-lived authorization."""

    def __init__(self, service: ArtifactUploadService) -> None:
        if not callable(getattr(service, "put", None)):
            raise TypeError("artifact upload service is invalid")
        self._service = service

    def preflight_artifact_upload(self, request: ServiceRequest) -> str:
        """Validate the signed upload before tenant admission is charged."""

        upload = _artifact_put_request(request)
        if (
            request.path_params.get("tenant_id") != upload.tenant_id
            or request.path_params.get("content_sha256") != upload.content_sha256
            or request.path_params.get("authorization_id") != upload.authorization_id
        ):
            raise ArtifactUploadRejected()
        preflight = getattr(self._service, "preflight", None)
        if not callable(preflight):
            raise ArtifactUploadRejected()
        tenant_id = preflight(upload)
        if type(tenant_id) is not str or tenant_id != upload.tenant_id:
            raise ArtifactUploadRejected()
        return tenant_id

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action != "artifacts.upload" or request.document is not None:
            raise ServiceUnavailableError()
        try:
            upload = _artifact_put_request(request)
            if (
                request.path_params.get("tenant_id") != upload.tenant_id
                or request.path_params.get("content_sha256") != upload.content_sha256
                or request.path_params.get("authorization_id") != upload.authorization_id
            ):
                raise ArtifactUploadRejected()
            receipt = await self._service.put(upload)
            if not _receipt_matches_request(receipt, upload):
                raise ArtifactUploadRejected()
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


def _artifact_put_request(request: ServiceRequest) -> ArtifactPutRequest:
    if request.action != "artifacts.upload" or request.document is not None:
        raise ArtifactUploadRejected()
    return ArtifactPutRequest(
        authorization_id=_header(request, "x-securecode-authorization-id"),
        tenant_id=_header(request, "x-securecode-tenant-id"),
        worker_id=_header(request, "x-securecode-worker-id"),
        repository_id=_header(request, "x-securecode-repository-id"),
        run_id=_header(request, "x-securecode-run-id"),
        execution_identity_hash=_header(request, "x-securecode-execution-identity-hash"),
        content_sha256=_header(request, "x-securecode-content-sha256"),
        size_bytes=_size(request),
        purpose=_header(request, "x-securecode-purpose"),
        receipt_signature=_header(request, "x-securecode-receipt-signature"),
        content=request.raw_body,
    )


def _size(request: ServiceRequest) -> int:
    value = _header(request, "content-length")
    if not value.isdigit():
        raise ArtifactUploadRejected()
    size = int(value)
    if size != len(request.raw_body):
        raise ArtifactUploadRejected()
    return size


def _receipt_matches_request(
    receipt: object,
    request: ArtifactPutRequest,
) -> bool:
    """Keep a faulty upload port from returning another tenant's receipt."""

    return (
        type(receipt) is ArtifactUploadReceipt
        and receipt.authorization_id == request.authorization_id
        and receipt.tenant_id == request.tenant_id
        and receipt.worker_id == request.worker_id
        and receipt.repository_id == request.repository_id
        and receipt.run_id == request.run_id
        and receipt.execution_identity_hash == request.execution_identity_hash
        and receipt.content_sha256 == request.content_sha256
        and receipt.size_bytes == request.size_bytes
        and receipt.purpose == request.purpose
    )


def _error(status: int, code: str, message: str) -> ServiceResponse:
    return ServiceResponse(status, {"error": {"code": code, "message": message}})


__all__ = ["ArtifactUploadHandler"]
