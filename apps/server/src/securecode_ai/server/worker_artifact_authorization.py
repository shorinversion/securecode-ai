"""Signed short-lived artifact upload authorization receipts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol
from urllib.parse import quote, urljoin, urlsplit

from securecode_ai.contracts import ArtifactRef

from .ports import ServiceRequest, ServiceResponse

_PURPOSES: Final = frozenset({"audit-report", "audit-run", "evidence-graph", "sarif-report"})


class ArtifactAuthorizationDenied(Exception):
    """The requested artifact transfer is not bound to the active run."""


class ArtifactReceiptSigner(Protocol):
    @property
    def key_id(self) -> str: ...

    def sign(self, material: bytes) -> str: ...

    def verify(self, material: bytes, signature: str) -> bool: ...


class ArtifactUploadUrlFactory(Protocol):
    def build(
        self,
        *,
        authorization_id: str,
        tenant_id: str,
        content_sha256: str,
        expires_at: datetime,
    ) -> str: ...


class HmacSha256ArtifactReceiptSigner:
    """Injected symmetric signer for metadata-only authorization receipts."""

    def __init__(self, secret: bytes, *, key_id: str) -> None:
        if (
            type(secret) is not bytes
            or len(secret) < 32
            or type(key_id) is not str
            or not key_id
            or len(key_id) > 128
        ):
            raise ValueError("artifact receipt signer settings are invalid")
        self._secret = secret
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, material: bytes) -> str:
        if type(material) is not bytes or not material:
            raise ValueError("artifact receipt material is invalid")
        digest = hmac.new(self._secret, material, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def verify(self, material: bytes, signature: str) -> bool:
        if type(material) is not bytes or type(signature) is not str:
            return False
        return hmac.compare_digest(self.sign(material), signature)


class StaticArtifactUploadUrlFactory:
    """Build opaque content-addressed URLs for an injected upload service."""

    def __init__(self, base_url: str) -> None:
        parsed = urlsplit(base_url)
        if (
            type(base_url) is not str
            or parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("artifact upload base URL is invalid")
        if parsed.scheme == "http" and not _loopback(parsed.hostname):
            raise ValueError("artifact upload base URL is invalid")
        self._base_url = base_url.rstrip("/") + "/"

    def build(
        self,
        *,
        authorization_id: str,
        tenant_id: str,
        content_sha256: str,
        expires_at: datetime,
    ) -> str:
        del expires_at
        path = "/".join(
            (
                quote(tenant_id, safe=""),
                quote(content_sha256, safe=""),
                quote(authorization_id, safe=""),
            )
        )
        return urljoin(self._base_url, path)


@dataclass(frozen=True, slots=True)
class ArtifactUploadAuthorization:
    authorization_id: str
    tenant_id: str
    worker_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    content_id: str
    content_sha256: str
    size_bytes: int
    data_class: str
    purpose: str
    method: str
    upload_url: str
    headers: Mapping[str, str]
    issued_at: datetime
    expires_at: datetime
    signer_key_id: str
    receipt_signature: str

    def response_document(self) -> dict[str, object]:
        return {
            "authorization_id": self.authorization_id,
            "upload_url": self.upload_url,
            "headers": dict(self.headers),
            "expires_at": self.expires_at.isoformat(),
            "receipt_signature": self.receipt_signature,
            "signer_key_id": self.signer_key_id,
            "tenant_id": self.tenant_id,
            "repository_id": self.repository_id,
            "run_id": self.run_id,
            "execution_identity_hash": self.execution_identity_hash,
            "content_sha256": self.content_sha256,
            "size_bytes": self.size_bytes,
            "purpose": self.purpose,
            "method": self.method,
        }

    def signing_document(self) -> dict[str, object]:
        return {
            "authorization_id": self.authorization_id,
            "tenant_id": self.tenant_id,
            "worker_id": self.worker_id,
            "repository_id": self.repository_id,
            "run_id": self.run_id,
            "execution_identity_hash": self.execution_identity_hash,
            "content_id": self.content_id,
            "content_sha256": self.content_sha256,
            "size_bytes": self.size_bytes,
            "data_class": self.data_class,
            "purpose": self.purpose,
            "method": self.method,
            "upload_url": self.upload_url,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "signer_key_id": self.signer_key_id,
        }


class SqliteArtifactAuthorizationStore:
    """Issue and restore tenant-bound signed upload authorizations."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        signer: ArtifactReceiptSigner,
        upload_urls: ArtifactUploadUrlFactory,
        ttl_seconds: int = 300,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if type(ttl_seconds) is not int or not 30 <= ttl_seconds <= 900:
            raise ValueError("artifact authorization lifetime is invalid")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._signer = signer
        self._upload_urls = upload_urls
        self._ttl_seconds = ttl_seconds
        self._now = now

    def issue(
        self,
        *,
        tenant_id: str,
        worker_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        artifact_ref: ArtifactRef,
        purpose: str,
        method: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> ArtifactUploadAuthorization:
        if (
            artifact_ref.tenant_id != tenant_id
            or purpose not in _PURPOSES
            or method != "PUT"
            or artifact_ref.size_bytes < 1
            or len(request_sha256) != 64
        ):
            raise ArtifactAuthorizationDenied()
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            replay = cursor.execute(
                """SELECT * FROM artifact_upload_authorizations
                   WHERE tenant_id=? AND idempotency_key=?""",
                (tenant_id, idempotency_key),
            ).fetchone()
            if replay is not None:
                if replay["request_sha256"] != request_sha256:
                    raise ArtifactAuthorizationDenied()
                authorization = _row_authorization(replay)
                self._verify(authorization)
                self._connection.commit()
                return authorization

            now = _utc(self._now())
            if artifact_ref.expires_at is not None and artifact_ref.expires_at <= now:
                raise ArtifactAuthorizationDenied()
            queue = cursor.execute(
                """SELECT r.repository_id, r.execution_identity_hash, r.state,
                          q.lease_owner, q.lease_expires_at, q.terminal
                   FROM audit_runs AS r
                   JOIN worker_run_queue AS q
                     ON q.tenant_id=r.tenant_id AND q.run_id=r.run_id
                   WHERE r.tenant_id=? AND r.run_id=?""",
                (tenant_id, run_id),
            ).fetchone()
            if (
                queue is None
                or queue["repository_id"] != repository_id
                or queue["execution_identity_hash"] != execution_identity_hash
                or queue["state"] != "RUNNING"
                or queue["lease_owner"] != worker_id
                or bool(queue["terminal"])
                or _timestamp(queue["lease_expires_at"]) <= now
            ):
                raise ArtifactAuthorizationDenied()
            authorization_id = (
                "upload-"
                + hashlib.sha256(
                    "\x00".join(
                        (
                            tenant_id,
                            run_id,
                            artifact_ref.content_sha256,
                            idempotency_key,
                            request_sha256,
                        )
                    ).encode("utf-8")
                ).hexdigest()[:48]
            )
            expires = now + timedelta(seconds=self._ttl_seconds)
            upload_url = self._upload_urls.build(
                authorization_id=authorization_id,
                tenant_id=tenant_id,
                content_sha256=artifact_ref.content_sha256,
                expires_at=expires,
            )
            _upload_url(upload_url)
            unsigned = ArtifactUploadAuthorization(
                authorization_id=authorization_id,
                tenant_id=tenant_id,
                worker_id=worker_id,
                repository_id=repository_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                content_id=artifact_ref.content_id,
                content_sha256=artifact_ref.content_sha256,
                size_bytes=artifact_ref.size_bytes,
                data_class=artifact_ref.data_class.value,
                purpose=purpose,
                method=method,
                upload_url=upload_url,
                headers={},
                issued_at=now,
                expires_at=expires,
                signer_key_id=self._signer.key_id,
                receipt_signature="",
            )
            signature = self._signer.sign(_signing_bytes(unsigned))
            headers = {
                "content-length": str(artifact_ref.size_bytes),
                "x-securecode-authorization-id": authorization_id,
                "x-securecode-content-sha256": artifact_ref.content_sha256,
                "x-securecode-execution-identity-hash": execution_identity_hash,
                "x-securecode-purpose": purpose,
                "x-securecode-receipt-signature": signature,
                "x-securecode-run-id": run_id,
                "x-securecode-tenant-id": tenant_id,
                "x-securecode-worker-id": worker_id,
            }
            authorization = replace(
                unsigned,
                headers=headers,
                receipt_signature=signature,
            )
            cursor.execute(
                """INSERT INTO artifact_upload_authorizations
                   (tenant_id, authorization_id, idempotency_key, request_sha256,
                    worker_id, repository_id, run_id, execution_identity_hash,
                    content_id, content_sha256, size_bytes, data_class, purpose,
                    method, upload_url, headers_json, issued_at, expires_at,
                    signer_key_id, receipt_signature)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    tenant_id,
                    authorization_id,
                    idempotency_key,
                    request_sha256,
                    worker_id,
                    repository_id,
                    run_id,
                    execution_identity_hash,
                    artifact_ref.content_id,
                    artifact_ref.content_sha256,
                    artifact_ref.size_bytes,
                    artifact_ref.data_class.value,
                    purpose,
                    method,
                    upload_url,
                    _canonical(headers),
                    now.isoformat(),
                    expires.isoformat(),
                    self._signer.key_id,
                    signature,
                ),
            )
            self._connection.commit()
            return authorization
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    def require(
        self,
        *,
        tenant_id: str,
        authorization_id: str,
        run_id: str,
        execution_identity_hash: str,
        content_sha256: str,
        size_bytes: int,
        purpose: str,
    ) -> ArtifactUploadAuthorization:
        row = self._connection.execute(
            """SELECT * FROM artifact_upload_authorizations
               WHERE tenant_id=? AND authorization_id=?""",
            (tenant_id, authorization_id),
        ).fetchone()
        if row is None:
            raise ArtifactAuthorizationDenied()
        authorization = _row_authorization(row)
        if (
            authorization.run_id,
            authorization.execution_identity_hash,
            authorization.content_sha256,
            authorization.size_bytes,
            authorization.purpose,
        ) != (run_id, execution_identity_hash, content_sha256, size_bytes, purpose):
            raise ArtifactAuthorizationDenied()
        self._verify(authorization)
        if authorization.expires_at <= _utc(self._now()):
            raise ArtifactAuthorizationDenied()
        return authorization

    def _verify(self, authorization: ArtifactUploadAuthorization) -> None:
        if authorization.signer_key_id != self._signer.key_id or not self._signer.verify(
            _signing_bytes(authorization), authorization.receipt_signature
        ):
            raise ArtifactAuthorizationDenied()


class SignedArtifactAuthorizationHandler:
    """Handler-compatible adapter for the worker artifact authorization route."""

    def __init__(self, store: SqliteArtifactAuthorizationStore) -> None:
        self._store = store

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action != "artifacts.authorize":
            return _denied_response()
        document = request.document
        if document is None or request.idempotency_key is None:
            return _denied_response()
        artifact_document = document.get("artifact_ref")
        try:
            if not isinstance(artifact_document, Mapping):
                raise ArtifactAuthorizationDenied()
            artifact = ArtifactRef.model_validate(dict(artifact_document))
            values = tuple(
                document.get(name)
                for name in (
                    "worker_id",
                    "repository_id",
                    "run_id",
                    "execution_identity_hash",
                    "purpose",
                    "method",
                )
            )
            if not all(isinstance(value, str) and value for value in values):
                raise ArtifactAuthorizationDenied()
            authorization = self._store.issue(
                tenant_id=request.identity.tenant_id,
                worker_id=str(values[0]),
                repository_id=str(values[1]),
                run_id=str(values[2]),
                execution_identity_hash=str(values[3]),
                artifact_ref=artifact,
                purpose=str(values[4]),
                method=str(values[5]),
                idempotency_key=request.idempotency_key,
                request_sha256=hashlib.sha256(request.raw_body).hexdigest(),
            )
        except (ArtifactAuthorizationDenied, TypeError, ValueError):
            return _denied_response()
        return ServiceResponse(201, authorization.response_document())


def _row_authorization(row: sqlite3.Row) -> ArtifactUploadAuthorization:
    try:
        headers = json.loads(row["headers_json"])
        if not isinstance(headers, dict) or not all(
            isinstance(name, str) and isinstance(value, str) for name, value in headers.items()
        ):
            raise ArtifactAuthorizationDenied()
        return ArtifactUploadAuthorization(
            authorization_id=row["authorization_id"],
            tenant_id=row["tenant_id"],
            worker_id=row["worker_id"],
            repository_id=row["repository_id"],
            run_id=row["run_id"],
            execution_identity_hash=row["execution_identity_hash"],
            content_id=row["content_id"],
            content_sha256=row["content_sha256"],
            size_bytes=row["size_bytes"],
            data_class=row["data_class"],
            purpose=row["purpose"],
            method=row["method"],
            upload_url=row["upload_url"],
            headers=headers,
            issued_at=_timestamp(row["issued_at"]),
            expires_at=_timestamp(row["expires_at"]),
            signer_key_id=row["signer_key_id"],
            receipt_signature=row["receipt_signature"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ArtifactAuthorizationDenied() from None


def _signing_bytes(authorization: ArtifactUploadAuthorization) -> bytes:
    return _canonical(authorization.signing_document()).encode("ascii")


def _upload_url(value: str) -> None:
    parsed = urlsplit(value)
    if (
        type(value) is not str
        or len(value) > 4096
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ArtifactAuthorizationDenied()
    if parsed.scheme == "http" and not _loopback(parsed.hostname):
        raise ArtifactAuthorizationDenied()


def _loopback(hostname: str) -> bool:
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ArtifactAuthorizationDenied()
    try:
        return _utc(datetime.fromisoformat(value))
    except ValueError:
        raise ArtifactAuthorizationDenied() from None


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise ArtifactAuthorizationDenied()
    return value


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _denied_response() -> ServiceResponse:
    return ServiceResponse(
        403,
        {
            "error": {
                "code": "ARTIFACT_AUTHORIZATION_DENIED",
                "message": "artifact upload is not authorized",
            }
        },
    )


__all__ = [
    "ArtifactAuthorizationDenied",
    "ArtifactReceiptSigner",
    "ArtifactUploadAuthorization",
    "ArtifactUploadUrlFactory",
    "HmacSha256ArtifactReceiptSigner",
    "SignedArtifactAuthorizationHandler",
    "SqliteArtifactAuthorizationStore",
    "StaticArtifactUploadUrlFactory",
]
