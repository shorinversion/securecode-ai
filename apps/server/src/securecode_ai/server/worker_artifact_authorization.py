"""Signed short-lived artifact upload authorization receipts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol
from urllib.parse import quote, urljoin, urlsplit

from securecode_ai.contracts import ArtifactRef

from .ports import ServiceRequest, ServiceResponse

_PURPOSES: Final = frozenset(
    {
        "audit-report",
        "audit-run",
        "evidence-graph",
        "repair-patch",
        "repair-report",
        "sarif-report",
    }
)
_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_IDEMPOTENCY_KEY: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_ARTIFACT_AUTHORIZATION_PURGE_SAVEPOINT: Final = "securecode_artifact_authorization_purge"
_MAX_PURGE_ITEMS: Final = 256


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
        session_id: str,
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
            not _valid_identifier(tenant_id)
            or not _valid_identifier(worker_id)
            or not _valid_identifier(session_id)
            or not _valid_identifier(repository_id)
            or not _valid_identifier(run_id)
            or not _valid_digest(execution_identity_hash)
            or not isinstance(artifact_ref, ArtifactRef)
            or artifact_ref.tenant_id != tenant_id
            or type(purpose) is not str
            or purpose not in _PURPOSES
            or (
                purpose == "repair-patch"
                and artifact_ref.data_class.value != "DC3_CONFIDENTIAL_SOURCE"
            )
            or (
                purpose != "repair-patch"
                and artifact_ref.data_class.value == "DC3_CONFIDENTIAL_SOURCE"
            )
            or type(method) is not str
            or method != "PUT"
            or type(artifact_ref.size_bytes) is not int
            or artifact_ref.size_bytes < 1
            or type(idempotency_key) is not str
            or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
            or not _valid_digest(request_sha256)
        ):
            raise ArtifactAuthorizationDenied()
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            now = _utc(self._now())
            queue = cursor.execute(
                """SELECT r.repository_id, r.execution_identity_hash, r.state,
                          q.lease_owner, q.lease_expires_at, q.session_id, q.terminal
                   FROM audit_runs AS r
                   JOIN worker_run_queue AS q
                     ON q.tenant_id=r.tenant_id AND q.run_id=r.run_id
                   WHERE r.tenant_id=? AND r.run_id=?""",
                (tenant_id, run_id),
            ).fetchone()
            if not _active_session_matches(
                queue,
                worker_id=worker_id,
                session_id=session_id,
                repository_id=repository_id,
                execution_identity_hash=execution_identity_hash,
                now=now,
            ):
                raise ArtifactAuthorizationDenied()
            _require_artifact_not_tombstoned(
                cursor, tenant_id=tenant_id, content_sha256=artifact_ref.content_sha256
            )
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
                if authorization.expires_at <= _utc(self._now()):
                    raise ArtifactAuthorizationDenied()
                if replay["idempotency_key"] != _session_authorization_key(
                    session_id, artifact_ref.content_sha256, purpose
                ):
                    raise ArtifactAuthorizationDenied()
                self._connection.commit()
                return authorization

            if artifact_ref.expires_at is not None and artifact_ref.expires_at <= now:
                raise ArtifactAuthorizationDenied()
            if idempotency_key != _session_authorization_key(
                session_id, artifact_ref.content_sha256, purpose
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
            if artifact_ref.expires_at is not None:
                expires = min(expires, _utc(artifact_ref.expires_at))
            if expires <= now:
                raise ArtifactAuthorizationDenied()
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
            authorization = replace(
                unsigned,
                receipt_signature=signature,
            )
            authorization = replace(
                authorization,
                headers=_authorization_headers(authorization),
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
                    _canonical(dict(authorization.headers)),
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
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        content_sha256: str,
        size_bytes: int,
        purpose: str,
        request_sha256: str,
    ) -> ArtifactUploadAuthorization:
        return self._require(
            tenant_id=tenant_id,
            authorization_id=authorization_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
            purpose=purpose,
            request_sha256=request_sha256,
        )

    def require_upload(
        self,
        *,
        tenant_id: str,
        authorization_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        content_sha256: str,
        size_bytes: int,
        purpose: str,
    ) -> ArtifactUploadAuthorization:
        """Validate the signed upload capability without the original request body.

        The original body hash is checked again when the worker commits the
        artifact.  The PUT boundary has only the issued receipt fields, so its
        binding is the signed authorization plus the live lease and payload.
        """
        return self._require(
            tenant_id=tenant_id,
            authorization_id=authorization_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
            purpose=purpose,
            request_sha256=None,
        )

    def require_not_tombstoned(
        self,
        *,
        tenant_id: str,
        content_sha256: str,
    ) -> None:
        """Re-check the immutable deletion barrier after filesystem I/O."""

        _require_artifact_not_tombstoned(
            self._connection,
            tenant_id=tenant_id,
            content_sha256=content_sha256,
        )

    def _require(
        self,
        *,
        tenant_id: str,
        authorization_id: str,
        repository_id: str,
        run_id: str,
        execution_identity_hash: str,
        content_sha256: str,
        size_bytes: int,
        purpose: str,
        request_sha256: str | None,
    ) -> ArtifactUploadAuthorization:
        if not _valid_identifier(repository_id) or (
            request_sha256 is not None and not _valid_digest(request_sha256)
        ):
            raise ArtifactAuthorizationDenied()
        row = self._connection.execute(
            """SELECT a.*, r.state, q.lease_owner, q.lease_expires_at,
                      q.session_id AS active_session_id, q.terminal
               FROM artifact_upload_authorizations AS a
               JOIN audit_runs AS r ON r.tenant_id=a.tenant_id AND r.run_id=a.run_id
               JOIN worker_run_queue AS q ON q.tenant_id=a.tenant_id AND q.run_id=a.run_id
               WHERE a.tenant_id=? AND a.authorization_id=?""",
            (tenant_id, authorization_id),
        ).fetchone()
        if row is None:
            raise ArtifactAuthorizationDenied()
        authorization = _row_authorization(row)
        _require_artifact_not_tombstoned(
            self._connection,
            tenant_id=tenant_id,
            content_sha256=content_sha256,
        )
        if (
            authorization.run_id,
            authorization.repository_id,
            authorization.execution_identity_hash,
            authorization.content_sha256,
            authorization.size_bytes,
            authorization.purpose,
        ) != (
            run_id,
            repository_id,
            execution_identity_hash,
            content_sha256,
            size_bytes,
            purpose,
        ):
            raise ArtifactAuthorizationDenied()
        stored_request_sha256 = row["request_sha256"]
        if not _valid_digest(stored_request_sha256) or (
            request_sha256 is not None and stored_request_sha256 != request_sha256
        ):
            raise ArtifactAuthorizationDenied()
        self._verify(authorization)
        now = _utc(self._now())
        if (
            authorization.expires_at <= now
            or row["state"] != "RUNNING"
            or bool(row["terminal"])
            or row["lease_owner"] != authorization.worker_id
            or not isinstance(row["active_session_id"], str)
            or row["lease_expires_at"] is None
            or _timestamp(row["lease_expires_at"]) <= now
            or row["idempotency_key"]
            != _session_authorization_key(
                row["active_session_id"], authorization.content_sha256, authorization.purpose
            )
        ):
            raise ArtifactAuthorizationDenied()
        return authorization

    def _verify(self, authorization: ArtifactUploadAuthorization) -> None:
        if authorization.signer_key_id != self._signer.key_id or not self._signer.verify(
            _signing_bytes(authorization), authorization.receipt_signature
        ):
            raise ArtifactAuthorizationDenied()


def purge_expired_artifact_authorizations(
    connection: sqlite3.Connection,
    *,
    tenant_id: str,
    now: datetime,
    max_items: int = _MAX_PURGE_ITEMS,
) -> int:
    """Bounded cleanup for expired, uncommitted authorizations of terminal runs."""

    current = _validate_purge_arguments(tenant_id, now, max_items)
    cursor = connection.cursor()
    active = False
    try:
        cursor.execute(f"SAVEPOINT {_ARTIFACT_AUTHORIZATION_PURGE_SAVEPOINT}")
        active = True
        changed = cursor.execute(
            """DELETE FROM artifact_upload_authorizations
               WHERE rowid IN (
                   SELECT z.rowid
                   FROM artifact_upload_authorizations AS z
                   WHERE z.tenant_id=? AND z.expires_at<=?
                     AND NOT EXISTS (
                         SELECT 1 FROM run_artifacts AS a
                         WHERE a.tenant_id=z.tenant_id
                           AND a.authorization_id=z.authorization_id
                     )
                     AND EXISTS (
                         SELECT 1 FROM audit_runs AS r
                         WHERE r.tenant_id=z.tenant_id AND r.run_id=z.run_id
                           AND r.repository_id=z.repository_id
                           AND r.execution_identity_hash=z.execution_identity_hash
                     )
                     AND EXISTS (
                         SELECT 1
                         FROM audit_runs AS r
                         JOIN worker_run_queue AS q
                           ON q.tenant_id=r.tenant_id AND q.run_id=r.run_id
                         WHERE r.tenant_id=z.tenant_id AND r.run_id=z.run_id
                           AND r.repository_id=z.repository_id
                           AND r.execution_identity_hash=z.execution_identity_hash
                           AND r.state IN ('CANCELLED', 'FAILED', 'INDETERMINATE',
                                           'SUCCEEDED', 'SUPERSEDED')
                           AND q.terminal=1
                     )
                   ORDER BY z.expires_at, z.authorization_id LIMIT ?
               )""",
            (tenant_id, current.isoformat(), max_items),
        ).rowcount
        cursor.execute(f"RELEASE SAVEPOINT {_ARTIFACT_AUTHORIZATION_PURGE_SAVEPOINT}")
        active = False
        return changed
    except sqlite3.Error as error:
        if active:
            _rollback_savepoint(cursor, _ARTIFACT_AUTHORIZATION_PURGE_SAVEPOINT)
        raise ValueError("artifact authorization cleanup is unavailable") from error
    finally:
        cursor.close()


def has_expired_artifact_authorizations(
    connection: sqlite3.Connection,
    *,
    tenant_id: str,
    now: datetime,
) -> bool:
    current = _validate_purge_arguments(tenant_id, now, 1)
    row = connection.execute(
        """SELECT 1
           FROM artifact_upload_authorizations AS z
           WHERE z.tenant_id=? AND z.expires_at<=?
             AND NOT EXISTS (
                 SELECT 1 FROM run_artifacts AS a
                 WHERE a.tenant_id=z.tenant_id
                   AND a.authorization_id=z.authorization_id
             )
             AND EXISTS (
                 SELECT 1 FROM audit_runs AS r
                 WHERE r.tenant_id=z.tenant_id AND r.run_id=z.run_id
                   AND r.repository_id=z.repository_id
                   AND r.execution_identity_hash=z.execution_identity_hash
             )
             AND EXISTS (
                 SELECT 1
                 FROM audit_runs AS r
                 JOIN worker_run_queue AS q
                   ON q.tenant_id=r.tenant_id AND q.run_id=r.run_id
                 WHERE r.tenant_id=z.tenant_id AND r.run_id=z.run_id
                   AND r.repository_id=z.repository_id
                   AND r.execution_identity_hash=z.execution_identity_hash
                   AND r.state IN ('CANCELLED', 'FAILED', 'INDETERMINATE',
                                   'SUCCEEDED', 'SUPERSEDED')
                   AND q.terminal=1
             )
           LIMIT 1""",
        (tenant_id, current.isoformat()),
    ).fetchone()
    return row is not None


def _validate_purge_arguments(tenant_id: str, now: datetime, max_items: int) -> datetime:
    if not _valid_identifier(tenant_id):
        raise ValueError("artifact authorization tenant is invalid")
    if type(max_items) is not int or not 1 <= max_items <= _MAX_PURGE_ITEMS:
        raise ValueError("artifact authorization cleanup batch is invalid")
    try:
        return _utc(now)
    except ArtifactAuthorizationDenied:
        raise ValueError("artifact authorization cleanup clock is invalid") from None


def _rollback_savepoint(cursor: sqlite3.Cursor, name: str) -> None:
    try:
        cursor.execute(f"ROLLBACK TO SAVEPOINT {name}")
        cursor.execute(f"RELEASE SAVEPOINT {name}")
    except sqlite3.Error:
        pass


def _require_artifact_not_tombstoned(
    connection: sqlite3.Connection | sqlite3.Cursor,
    *,
    tenant_id: str,
    content_sha256: str,
) -> None:
    """Prevent lifecycle-deleted tenant content from being reintroduced."""

    try:
        row = connection.execute(
            """SELECT 1 FROM lifecycle_storage_tombstones
               WHERE tenant_id=? AND content_sha256=?""",
            (tenant_id, content_sha256),
        ).fetchone()
    except sqlite3.Error:
        raise ArtifactAuthorizationDenied() from None
    if row is not None:
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
                    "session_id",
                    "repository_id",
                    "run_id",
                    "execution_identity_hash",
                    "purpose",
                    "method",
                )
            )
            if not all(isinstance(value, str) and value for value in values):
                raise ArtifactAuthorizationDenied()
            if values[0] != request.identity.subject_id:
                raise ArtifactAuthorizationDenied()
            authorization = self._store.issue(
                tenant_id=request.identity.tenant_id,
                worker_id=str(values[0]),
                session_id=str(values[1]),
                repository_id=str(values[2]),
                run_id=str(values[3]),
                execution_identity_hash=str(values[4]),
                artifact_ref=artifact,
                purpose=str(values[5]),
                method=str(values[6]),
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
        authorization = ArtifactUploadAuthorization(
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
        if dict(authorization.headers) != _authorization_headers(authorization):
            raise ArtifactAuthorizationDenied()
        return authorization
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ArtifactAuthorizationDenied() from None


def _signing_bytes(authorization: ArtifactUploadAuthorization) -> bytes:
    return _canonical(authorization.signing_document()).encode("ascii")


def _authorization_headers(
    authorization: ArtifactUploadAuthorization,
) -> dict[str, str]:
    return {
        "content-length": str(authorization.size_bytes),
        "x-securecode-authorization-id": authorization.authorization_id,
        "x-securecode-content-sha256": authorization.content_sha256,
        "x-securecode-execution-identity-hash": authorization.execution_identity_hash,
        "x-securecode-purpose": authorization.purpose,
        "x-securecode-repository-id": authorization.repository_id,
        "x-securecode-receipt-signature": authorization.receipt_signature,
        "x-securecode-run-id": authorization.run_id,
        "x-securecode-tenant-id": authorization.tenant_id,
        "x-securecode-worker-id": authorization.worker_id,
    }


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


def _valid_identifier(value: object) -> bool:
    return type(value) is str and _IDENTIFIER.fullmatch(value) is not None


def _valid_digest(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _active_session_matches(
    queue: sqlite3.Row | None,
    *,
    worker_id: str,
    session_id: str,
    repository_id: str,
    execution_identity_hash: str,
    now: datetime,
) -> bool:
    if queue is None:
        return False
    try:
        return (
            queue["repository_id"] == repository_id
            and queue["execution_identity_hash"] == execution_identity_hash
            and queue["state"] == "RUNNING"
            and queue["lease_owner"] == worker_id
            and queue["session_id"] == session_id
            and not bool(queue["terminal"])
            and _timestamp(queue["lease_expires_at"]) > now
        )
    except (KeyError, TypeError, ValueError):
        return False


def _session_authorization_key(session_id: str, content_sha256: str, purpose: str) -> str:
    material = "\x00".join(("authorize", session_id, content_sha256, purpose)).encode("utf-8")
    return "worker-" + hashlib.sha256(material).hexdigest()


__all__ = [
    "ArtifactAuthorizationDenied",
    "ArtifactReceiptSigner",
    "ArtifactUploadAuthorization",
    "ArtifactUploadUrlFactory",
    "HmacSha256ArtifactReceiptSigner",
    "SignedArtifactAuthorizationHandler",
    "SqliteArtifactAuthorizationStore",
    "StaticArtifactUploadUrlFactory",
    "has_expired_artifact_authorizations",
    "purge_expired_artifact_authorizations",
]
