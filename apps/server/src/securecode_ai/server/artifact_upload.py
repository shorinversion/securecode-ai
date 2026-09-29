"""Authorized, immutable local artifact uploads for the connected server."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Protocol, cast

from .artifact_tenant_namespace import (
    ArtifactTenantNamespaceError,
    artifact_tenant_path_component,
)
from .filesystem_paths import lexical_absolute_path
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard
from .worker_artifact_authorization import (
    ArtifactAuthorizationDenied,
    ArtifactUploadAuthorization,
    SqliteArtifactAuthorizationStore,
)

_IDENTIFIER_CHARS: Final = frozenset(
    "".join(
        (
            "abcdefghijklmnop",
            "qrstuvwxyzABCDEF",
            "GHIJKLMNOPQRSTUV",
            "WXYZ0123456789_-",
        )
    )
)
_HEX_CHARS: Final = frozenset("0123456789abcdef")
_REPARSE_POINT: Final = 0x400
_RECEIPT_LIMIT: Final = 65_536
_SCHEMA_VERSION: Final = 1
_ORPHAN_PURGE_MAX: Final = 256
_ORPHAN_PURGE_GRACE: Final = timedelta(hours=1)
_ORPHAN_STAGE_PREFIXES: Final = (".upload-", ".receipt-")
_RECEIPT_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_OPAQUE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DATA_CLASSES: Final = frozenset(
    {
        "DC0_PUBLIC",
        "DC1_INTERNAL_METADATA",
        "DC2_CONFIDENTIAL_SECURITY",
        "DC3_CONFIDENTIAL_SOURCE",
        "DC4_RESTRICTED",
    }
)
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


class ArtifactUploadRejected(Exception):
    """The request is not exactly bound to a live signed authorization."""


class ArtifactUploadConflict(Exception):
    """The content-addressed object exists with different or unsafe state."""


class ArtifactUploadUnavailable(Exception):
    """The configured local object store could not durably accept the upload."""


@dataclass(frozen=True, slots=True)
class ArtifactPutRequest:
    """Trusted transport fields and the exact bytes from one signed PUT."""

    authorization_id: str
    tenant_id: str
    worker_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    content_sha256: str
    size_bytes: int
    purpose: str
    receipt_signature: str
    content: bytes

    def __post_init__(self) -> None:
        strings = (
            self.authorization_id,
            self.tenant_id,
            self.worker_id,
            self.repository_id,
            self.run_id,
            self.execution_identity_hash,
            self.content_sha256,
            self.purpose,
            self.receipt_signature,
        )
        if (
            not all(type(value) is str and value and "\x00" not in value for value in strings)
            or type(self.size_bytes) is not int
            or self.size_bytes < 1
            or type(self.content) is not bytes
            or not _valid_tenant_id(self.tenant_id)
            or not _RECEIPT_IDENTIFIER.fullmatch(self.repository_id)
            or not _sha256(self.execution_identity_hash)
            or not _sha256(self.content_sha256)
            or self.purpose not in _PURPOSES
        ):
            raise ValueError("artifact PUT request is invalid")


@dataclass(frozen=True, slots=True)
class ArtifactUploadReceipt:
    """Source-free durable metadata returned for a completed upload."""

    schema_version: int
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
    signer_key_id: str
    authorization_signature: str
    authorized_at: datetime
    authorization_expires_at: datetime
    stored_at: datetime
    object_key: str

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
            or type(self.authorization_id) is not str
            or type(self.tenant_id) is not str
            or type(self.worker_id) is not str
            or type(self.repository_id) is not str
            or type(self.run_id) is not str
            or not _RECEIPT_IDENTIFIER.fullmatch(self.authorization_id)
            or not _RECEIPT_IDENTIFIER.fullmatch(self.tenant_id)
            or not _RECEIPT_IDENTIFIER.fullmatch(self.worker_id)
            or not _RECEIPT_IDENTIFIER.fullmatch(self.repository_id)
            or not _RECEIPT_IDENTIFIER.fullmatch(self.run_id)
            or not _sha256(self.execution_identity_hash)
            or type(self.content_id) is not str
            or not _OPAQUE_IDENTIFIER.fullmatch(self.content_id)
            or not _sha256(self.content_sha256)
            or type(self.size_bytes) is not int
            or not 1 <= self.size_bytes <= 1_073_741_824
            or type(self.data_class) is not str
            or self.data_class not in _DATA_CLASSES
            or type(self.purpose) is not str
            or self.purpose not in _PURPOSES
            or not _safe_text(self.signer_key_id, maximum=128)
            or not _safe_text(self.authorization_signature, maximum=2048)
            or not isinstance(self.authorized_at, datetime)
            or not isinstance(self.authorization_expires_at, datetime)
            or not isinstance(self.stored_at, datetime)
            or type(self.object_key) is not str
            or not self.object_key
        ):
            raise ValueError("artifact upload receipt is invalid")
        authorized_at = _utc(self.authorized_at, rejected=False)
        expires_at = _utc(self.authorization_expires_at, rejected=False)
        stored_at = _utc(self.stored_at, rejected=False)
        if not authorized_at < expires_at or not authorized_at <= stored_at < expires_at:
            raise ValueError("artifact upload receipt interval is invalid")
        expected_key = "/".join((self.tenant_id, self.content_sha256[:2], self.content_sha256))
        if self.object_key != expected_key:
            raise ValueError("artifact upload receipt object key is invalid")

    def document(self) -> dict[str, object]:
        value = asdict(self)
        value["authorized_at"] = self.authorized_at.isoformat()
        value["authorization_expires_at"] = self.authorization_expires_at.isoformat()
        value["stored_at"] = self.stored_at.isoformat()
        return value


class ArtifactUploadService(Protocol):
    def preflight(self, request: ArtifactPutRequest) -> str: ...

    async def put(self, request: ArtifactPutRequest) -> ArtifactUploadReceipt: ...


class AuthorizedLocalArtifactUploadService:
    """Validate signed metadata before storing exact content bytes locally."""

    def __init__(
        self,
        root: Path,
        *,
        authorizations: SqliteArtifactAuthorizationStore,
        max_bytes: int = 16_777_216,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
    ) -> None:
        if (
            not isinstance(root, Path)
            or type(max_bytes) is not int
            or not 1 <= max_bytes <= 1_073_741_824
        ):
            raise ValueError("artifact upload store settings are invalid")
        self._authorizations = authorizations
        self._objects = _AtomicContentAddressedStore(root, max_bytes=max_bytes)
        self._max_bytes = max_bytes
        self._now = now
        if (residency_guard is None) != (residency_region is None):
            raise ValueError("artifact upload residency configuration is incomplete")
        if residency_guard is not None and not callable(
            getattr(residency_guard, "require_region", None)
        ):
            raise ValueError("artifact upload residency guard is invalid")
        self._residency_guard = residency_guard
        self._residency_region = residency_region

    def preflight(self, request: ArtifactPutRequest) -> str:
        """Authenticate an upload without mutating the object store.

        The HTTP boundary uses this hook after the aggregate transport bucket
        is charged and before charging the signed tenant's quota.  Every
        tenant field comes from the authorization row and its receipt HMAC,
        never from the URL alone.
        """

        authorization, _ = self._authorize(request)
        return authorization.tenant_id

    async def put(self, request: ArtifactPutRequest) -> ArtifactUploadReceipt:
        authorization, stored_at = self._authorize(request)
        receipt = _receipt(authorization, stored_at=stored_at)
        try:
            stored = await asyncio.to_thread(
                self._objects.put,
                receipt=receipt,
                content=request.content,
            )
            try:
                self._authorizations.require_not_tombstoned(
                    tenant_id=receipt.tenant_id,
                    content_sha256=receipt.content_sha256,
                )
            except ArtifactAuthorizationDenied:
                try:
                    await asyncio.to_thread(self._objects.remove, receipt=receipt)
                except (ArtifactUploadConflict, OSError, ValueError):
                    raise ArtifactUploadUnavailable() from None
                raise ArtifactUploadRejected() from None
            return stored
        except ArtifactUploadConflict:
            raise
        except (OSError, UnicodeError, ValueError):
            raise ArtifactUploadUnavailable() from None

    def _authorize(
        self,
        request: ArtifactPutRequest,
    ) -> tuple[ArtifactUploadAuthorization, datetime]:
        if not isinstance(request, ArtifactPutRequest):
            raise ArtifactUploadRejected()
        if request.size_bytes > self._max_bytes or len(request.content) != request.size_bytes:
            raise ArtifactUploadRejected()
        actual_digest = hashlib.sha256(request.content).hexdigest()
        if not hmac.compare_digest(
            actual_digest.encode("ascii"), request.content_sha256.encode("ascii")
        ):
            raise ArtifactUploadRejected()
        try:
            authorization = self._authorizations.require_upload(
                tenant_id=request.tenant_id,
                authorization_id=request.authorization_id,
                repository_id=request.repository_id,
                run_id=request.run_id,
                execution_identity_hash=request.execution_identity_hash,
                content_sha256=request.content_sha256,
                size_bytes=request.size_bytes,
                purpose=request.purpose,
            )
        except (ArtifactAuthorizationDenied, TypeError, ValueError):
            raise ArtifactUploadRejected() from None
        if (
            authorization.method != "PUT"
            or authorization.worker_id != request.worker_id
            or not hmac.compare_digest(
                authorization.receipt_signature.encode("utf-8"),
                request.receipt_signature.encode("utf-8"),
            )
        ):
            raise ArtifactUploadRejected()
        stored_at = _utc(self._now(), rejected=True)
        if stored_at < authorization.issued_at or stored_at >= authorization.expires_at:
            raise ArtifactUploadRejected()
        self._require_residency(request.tenant_id)
        return authorization, stored_at

    def _require_residency(self, tenant_id: str) -> None:
        guard = self._residency_guard
        if guard is None:
            return
        region = self._residency_region
        if type(region) is not str or not region:
            raise ArtifactUploadRejected()
        try:
            decision = guard.require_region(tenant_id=tenant_id, region=region)
        except (ResidencyConflict, TypeError, ValueError):
            raise ArtifactUploadRejected() from None
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != tenant_id
            or decision.source_region != region
            or decision.destination_region != region
            or not decision.same_region
        ):
            raise ArtifactUploadRejected()


def purge_orphaned_artifact_objects(
    connection: sqlite3.Connection,
    root: Path,
    *,
    tenant_id: str,
    max_items: int = _ORPHAN_PURGE_MAX,
) -> int:
    """Remove uploaded objects that never reached the durable commit row.

    Upload publication is intentionally two phase: the payload and receipt are
    committed to the object store before the worker records ``run_artifacts``.
    A crashed worker can therefore leave a complete object with an expired
    authorization but no database reference.  Authorization row cleanup alone
    cannot reclaim those bytes.  Hold the SQLite write lock while checking
    references so a new authorization or commit cannot race the filesystem
    removal.  The next maintenance run can safely finish an interrupted
    cleanup because the object is selected only while no durable references
    exist.
    """

    if (
        not isinstance(connection, sqlite3.Connection)
        or not isinstance(root, Path)
        or type(max_items) is not int
        or not 1 <= max_items <= _ORPHAN_PURGE_MAX
        or not _valid_tenant_id(tenant_id)
    ):
        raise ValueError("artifact orphan cleanup settings are invalid")
    root = lexical_absolute_path(root)
    try:
        _assert_directory_chain(root)
    except (OSError, ValueError):
        raise ValueError("artifact orphan cleanup root is unsafe") from None
    try:
        tenant_root = root / artifact_tenant_path_component(tenant_id)
        tenant_details = tenant_root.lstat()
    except FileNotFoundError:
        return 0
    except (ArtifactTenantNamespaceError, OSError, ValueError):
        raise ArtifactUploadConflict() from None
    if _link_like(tenant_details) or not stat.S_ISDIR(tenant_details.st_mode):
        raise ArtifactUploadConflict()

    cursor = connection.cursor()
    transaction_started = False
    removed = 0
    try:
        if connection.in_transaction:
            raise ValueError("artifact orphan cleanup requires an idle connection")
        cursor.execute("BEGIN IMMEDIATE")
        transaction_started = True
        cleanup_now = datetime.now(UTC)
        for shard in tenant_root.iterdir():
            if removed >= max_items:
                break
            if shard.name.startswith("."):
                continue
            if len(shard.name) != 2 or any(character not in _HEX_CHARS for character in shard.name):
                raise ArtifactUploadConflict()
            _assert_plain_directory(shard)
            for target in shard.iterdir():
                if removed >= max_items:
                    break
                if target.name.startswith("."):
                    if target.name.startswith(_ORPHAN_STAGE_PREFIXES) and _orphan_stage_past_grace(
                        target, now=cleanup_now
                    ):
                        _remove_orphan_stage(target)
                        removed += 1
                    continue
                if (
                    len(target.name) != 64
                    or any(character not in _HEX_CHARS for character in target.name)
                    or target.name[:2] != shard.name
                ):
                    raise ArtifactUploadConflict()
                if not _orphan_without_references(cursor, tenant_id, target.name):
                    continue
                if not _orphan_past_grace(
                    target,
                    tenant_id=tenant_id,
                    content_sha256=target.name,
                    now=cleanup_now,
                ):
                    continue
                _remove_orphan_object(target)
                removed += 1
        connection.commit()
        transaction_started = False
        return removed
    except Exception:
        if transaction_started:
            connection.rollback()
        raise
    finally:
        cursor.close()


def _orphan_stage_past_grace(target: Path, *, now: datetime) -> bool:
    try:
        details = target.lstat()
        _assert_plain_directory(target)
        modified = datetime.fromtimestamp(details.st_mtime, tz=UTC)
        current = _utc(now, rejected=False)
    except (OSError, OverflowError, TypeError, ValueError):
        raise ArtifactUploadConflict() from None
    return modified + _ORPHAN_PURGE_GRACE <= current


def _remove_orphan_stage(target: Path) -> None:
    if not target.name.startswith(_ORPHAN_STAGE_PREFIXES):
        raise ArtifactUploadConflict()
    try:
        _assert_plain_directory(target)
    except (OSError, ValueError):
        raise ArtifactUploadConflict() from None
    entries = {entry.name: entry for entry in target.iterdir()}
    if not set(entries).issubset({"payload", "receipt.json"}):
        raise ArtifactUploadConflict()
    for entry in entries.values():
        _assert_regular_file(entry)
    for entry in entries.values():
        entry.unlink()
    _sync_directory(target)
    target.rmdir()
    _sync_directory(target.parent)


def _orphan_past_grace(
    target: Path,
    *,
    tenant_id: str,
    content_sha256: str,
    now: datetime,
) -> bool:
    receipt_raw = _read_regular(target / "receipt.json", _RECEIPT_LIMIT)
    try:
        document = json.loads(receipt_raw.decode("ascii"), object_pairs_hook=_unique_object_pairs)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise ArtifactUploadConflict() from None
    if type(document) is not dict:
        raise ArtifactUploadConflict()
    receipt = _parse_receipt(document)
    current = _utc(now, rejected=False)
    return (
        receipt.tenant_id == tenant_id
        and receipt.content_sha256 == content_sha256
        and receipt.authorization_expires_at + _ORPHAN_PURGE_GRACE <= current
    )


def _orphan_without_references(
    cursor: sqlite3.Cursor,
    tenant_id: str,
    content_sha256: str,
) -> bool:
    row = cursor.execute(
        """SELECT 1
           FROM artifact_upload_authorizations
           WHERE tenant_id=? AND content_sha256=?
           UNION ALL
           SELECT 1
           FROM run_artifacts
           WHERE tenant_id=? AND content_sha256=?
           LIMIT 1""",
        (tenant_id, content_sha256, tenant_id, content_sha256),
    ).fetchone()
    return row is None


def _remove_orphan_object(target: Path) -> None:
    _assert_plain_directory(target)
    entries = {entry.name: entry for entry in target.iterdir()}
    if not entries.keys() <= {"payload", "receipt.json", "authorizations"}:
        raise ArtifactUploadConflict()
    authorizations = entries.get("authorizations")
    authorization_receipts: list[tuple[Path, Path]] = []
    if authorizations is not None:
        _assert_plain_directory(authorizations)
        for authorization in authorizations.iterdir():
            details = authorization.lstat()
            if (
                _link_like(details)
                or not stat.S_ISDIR(details.st_mode)
                or not _OPAQUE_IDENTIFIER.fullmatch(authorization.name)
            ):
                raise ArtifactUploadConflict()
            child_entries = {entry.name: entry for entry in authorization.iterdir()}
            if set(child_entries) != {"receipt.json"}:
                raise ArtifactUploadConflict()
            receipt = child_entries["receipt.json"]
            _assert_regular_file(receipt)
            authorization_receipts.append((authorization, receipt))
    for name in ("payload", "receipt.json"):
        entry = entries.get(name)
        if entry is None:
            continue
        _assert_regular_file(entry)
        entry.unlink()
    if authorizations is not None:
        for authorization, receipt in authorization_receipts:
            receipt.unlink()
            authorization.rmdir()
        authorizations.rmdir()
    _sync_directory(target)
    target.rmdir()
    _sync_directory(target.parent)


class _AtomicContentAddressedStore:
    """Commit payload and receipt together under a tenant-scoped digest key."""

    def __init__(self, root: Path, *, max_bytes: int) -> None:
        self._root = lexical_absolute_path(root)
        self._max_bytes = max_bytes
        try:
            _create_plain_directory_chain(self._root)
        except (OSError, ValueError):
            raise ValueError("artifact upload root is unsafe") from None

    def put(self, *, receipt: ArtifactUploadReceipt, content: bytes) -> ArtifactUploadReceipt:
        target = self._object_directory(receipt.tenant_id, receipt.content_sha256)
        parent = target.parent
        try:
            self._create_owned_directories(parent)
            self._assert_owned_directory(parent)
        except ArtifactUploadConflict:
            raise
        except OSError:
            raise ArtifactUploadUnavailable() from None
        if _lexists(target):
            return self._existing_or_conflict(target, receipt)

        stage = Path(tempfile.mkdtemp(prefix=".upload-", dir=parent))
        committed = False
        try:
            self._assert_owned_directory(stage)
            _write_new(stage / "payload", content)
            receipt_bytes = _canonical(receipt.document()).encode("ascii")
            _write_new(stage / "receipt.json", receipt_bytes)
            _sync_directory(stage)
            self._assert_owned_directory(parent)
            try:
                stage.rename(target)
                committed = True
            except OSError:
                if not _lexists(target):
                    raise
                return self._existing_or_conflict(target, receipt)
            self._assert_owned_directory(target)
            _sync_directory(parent)
            return receipt
        finally:
            if not committed:
                _discard_stage(stage)

    def _existing_or_conflict(
        self, target: Path, expected: ArtifactUploadReceipt
    ) -> ArtifactUploadReceipt:
        try:
            self._assert_owned_directory(target)
            receipt_raw = _read_regular(target / "receipt.json", _RECEIPT_LIMIT)
            decoded = json.loads(
                receipt_raw.decode("ascii"), object_pairs_hook=_unique_object_pairs
            )
            if type(decoded) is not dict:
                raise ArtifactUploadConflict()
            primary = _parse_receipt(decoded)
            if (
                primary.tenant_id != expected.tenant_id
                or primary.content_sha256 != expected.content_sha256
                or primary.size_bytes != expected.size_bytes
                or primary.object_key != expected.object_key
            ):
                raise ArtifactUploadConflict()
            payload_digest, payload_size = _digest_regular(
                target / "payload", max_bytes=self._max_bytes
            )
            if payload_size != expected.size_bytes or not hmac.compare_digest(
                payload_digest, expected.content_sha256
            ):
                raise ArtifactUploadConflict()
            if _same_authorization(primary, expected):
                return primary
            return self._authorization_receipt(target, expected)
        except ArtifactUploadConflict:
            raise
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            raise ArtifactUploadConflict() from None

    def remove(self, *, receipt: ArtifactUploadReceipt) -> None:
        target = self._object_directory(receipt.tenant_id, receipt.content_sha256)
        if not _lexists(target):
            return
        try:
            _remove_orphan_object(target)
        except ValueError:
            raise ArtifactUploadConflict() from None

    def _authorization_receipt(
        self, target: Path, expected: ArtifactUploadReceipt
    ) -> ArtifactUploadReceipt:
        if not _safe_identifier(expected.authorization_id):
            raise ArtifactUploadConflict()
        root = target / "authorizations"
        self._create_owned_directories(root)
        authorization_directory = root / expected.authorization_id
        if _lexists(authorization_directory):
            return self._read_authorization_receipt(authorization_directory, expected)

        stage = Path(tempfile.mkdtemp(prefix=".receipt-", dir=target.parent))
        committed = False
        try:
            self._assert_owned_directory(stage)
            _write_new(
                stage / "receipt.json",
                _canonical(expected.document()).encode("ascii"),
            )
            _sync_directory(stage)
            self._assert_owned_directory(root)
            try:
                stage.rename(authorization_directory)
                committed = True
            except OSError:
                if not _lexists(authorization_directory):
                    raise
                return self._read_authorization_receipt(authorization_directory, expected)
            _sync_directory(root)
            return expected
        finally:
            if not committed:
                _discard_receipt_stage(stage)

    def _read_authorization_receipt(
        self, directory: Path, expected: ArtifactUploadReceipt
    ) -> ArtifactUploadReceipt:
        self._assert_owned_directory(directory)
        raw = _read_regular(directory / "receipt.json", _RECEIPT_LIMIT)
        decoded = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object_pairs)
        if type(decoded) is not dict:
            raise ArtifactUploadConflict()
        receipt = _parse_receipt(decoded)
        if not _same_authorization(receipt, expected):
            raise ArtifactUploadConflict()
        return receipt

    def _object_directory(self, tenant_id: str, digest: str) -> Path:
        if not _sha256(digest):
            raise ArtifactUploadRejected()
        try:
            tenant_component = artifact_tenant_path_component(tenant_id)
        except ArtifactTenantNamespaceError:
            raise ArtifactUploadRejected() from None
        target = self._root / tenant_component / digest[:2] / digest
        try:
            target.relative_to(self._root)
        except ValueError:
            raise ArtifactUploadRejected() from None
        return target

    def _assert_owned_directory(self, path: Path) -> None:
        try:
            path.relative_to(self._root)
            _assert_directory_chain(self._root)
            current = self._root
            for part in path.relative_to(self._root).parts:
                current /= part
                _assert_plain_directory(current)
        except (OSError, ValueError):
            raise ArtifactUploadConflict() from None

    def _create_owned_directories(self, path: Path) -> None:
        try:
            relative = path.relative_to(self._root)
        except ValueError:
            raise ArtifactUploadConflict() from None
        _assert_directory_chain(self._root)
        current = self._root
        for part in relative.parts:
            current /= part
            _mkdir_durable(current)
            _assert_plain_directory(current)


def _receipt(
    authorization: ArtifactUploadAuthorization, *, stored_at: datetime
) -> ArtifactUploadReceipt:
    object_key = "/".join(
        (
            authorization.tenant_id,
            authorization.content_sha256[:2],
            authorization.content_sha256,
        )
    )
    return ArtifactUploadReceipt(
        schema_version=_SCHEMA_VERSION,
        authorization_id=authorization.authorization_id,
        tenant_id=authorization.tenant_id,
        worker_id=authorization.worker_id,
        repository_id=authorization.repository_id,
        run_id=authorization.run_id,
        execution_identity_hash=authorization.execution_identity_hash,
        content_id=authorization.content_id,
        content_sha256=authorization.content_sha256,
        size_bytes=authorization.size_bytes,
        data_class=authorization.data_class,
        purpose=authorization.purpose,
        signer_key_id=authorization.signer_key_id,
        authorization_signature=authorization.receipt_signature,
        authorized_at=authorization.issued_at,
        authorization_expires_at=authorization.expires_at,
        stored_at=stored_at,
        object_key=object_key,
    )


def _parse_receipt(document: Mapping[str, object]) -> ArtifactUploadReceipt:
    expected = {item.name for item in fields(ArtifactUploadReceipt)}
    if set(document) != expected:
        raise ArtifactUploadConflict()
    strings = expected - {"schema_version", "size_bytes"}
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != _SCHEMA_VERSION
        or type(document["size_bytes"]) is not int
        or not all(type(document[name]) is str and document[name] for name in strings)
    ):
        raise ArtifactUploadConflict()
    try:
        return ArtifactUploadReceipt(
            schema_version=document["schema_version"],
            authorization_id=cast(str, document["authorization_id"]),
            tenant_id=cast(str, document["tenant_id"]),
            worker_id=cast(str, document["worker_id"]),
            repository_id=cast(str, document["repository_id"]),
            run_id=cast(str, document["run_id"]),
            execution_identity_hash=cast(str, document["execution_identity_hash"]),
            content_id=cast(str, document["content_id"]),
            content_sha256=cast(str, document["content_sha256"]),
            size_bytes=document["size_bytes"],
            data_class=cast(str, document["data_class"]),
            purpose=cast(str, document["purpose"]),
            signer_key_id=cast(str, document["signer_key_id"]),
            authorization_signature=cast(str, document["authorization_signature"]),
            authorized_at=_timestamp(document["authorized_at"]),
            authorization_expires_at=_timestamp(document["authorization_expires_at"]),
            stored_at=_timestamp(document["stored_at"]),
            object_key=cast(str, document["object_key"]),
        )
    except (TypeError, ValueError):
        raise ArtifactUploadConflict() from None


def _same_authorization(actual: ArtifactUploadReceipt, expected: ArtifactUploadReceipt) -> bool:
    actual_values = actual.document()
    expected_values = expected.document()
    actual_values.pop("stored_at")
    expected_values.pop("stored_at")
    return hmac.compare_digest(_canonical(actual_values), _canonical(expected_values))


def _assert_directory_chain(path: Path) -> None:
    if not path.is_absolute() or not path.anchor:
        raise ValueError("artifact directory must be absolute")
    current = Path(path.anchor)
    _assert_plain_directory(current)
    for part in path.parts[1:]:
        current /= part
        _assert_plain_directory(current)


def _create_plain_directory_chain(path: Path) -> None:
    if not path.is_absolute() or not path.anchor:
        raise ValueError("artifact directory must be absolute")
    current = Path(path.anchor)
    _assert_plain_directory(current)
    for part in path.parts[1:]:
        current /= part
        _mkdir_durable(current)
        _assert_plain_directory(current)


def _assert_plain_directory(path: Path) -> None:
    details = path.lstat()
    if _link_like(details) or not stat.S_ISDIR(details.st_mode):
        raise ValueError("artifact directory is unsafe")


def _assert_regular_file(path: Path) -> None:
    details = path.lstat()
    if _link_like(details) or not stat.S_ISREG(details.st_mode):
        raise ArtifactUploadConflict()


def _read_regular(path: Path, limit: int) -> bytes:
    descriptor = _open_regular(path)
    try:
        chunks: list[bytes] = []
        size = 0
        while True:
            value = os.read(descriptor, min(65_536, limit + 1 - size))
            if not value:
                break
            size += len(value)
            if size > limit:
                raise ArtifactUploadConflict()
            chunks.append(value)
        _assert_open_path_unchanged(path, descriptor)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _digest_regular(path: Path, *, max_bytes: int) -> tuple[str, int]:
    descriptor = _open_regular(path)
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            value = os.read(descriptor, 65_536)
            if not value:
                break
            size += len(value)
            if size > max_bytes:
                raise ArtifactUploadConflict()
            digest.update(value)
        _assert_open_path_unchanged(path, descriptor)
        return digest.hexdigest(), size
    finally:
        os.close(descriptor)


def _open_regular(path: Path) -> int:
    before = path.lstat()
    if _link_like(before) or not stat.S_ISREG(before.st_mode):
        raise ArtifactUploadConflict()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
        opened.st_dev,
        opened.st_ino,
    ):
        os.close(descriptor)
        raise ArtifactUploadConflict()
    return descriptor


def _assert_open_path_unchanged(path: Path, descriptor: int) -> None:
    current = path.lstat()
    opened = os.fstat(descriptor)
    if (
        _link_like(current)
        or not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        raise ArtifactUploadConflict()


def _write_new(path: Path, content: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise OSError("artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        _assert_open_path_unchanged(path, descriptor)
    finally:
        os.close(descriptor)


def _discard_stage(stage: Path) -> None:
    try:
        details = stage.lstat()
        if _link_like(details) or not stat.S_ISDIR(details.st_mode):
            return
        for name in ("payload", "receipt.json"):
            candidate = stage / name
            if _lexists(candidate):
                candidate.unlink()
        stage.rmdir()
    except OSError:
        return


def _discard_receipt_stage(stage: Path) -> None:
    try:
        details = stage.lstat()
        if _link_like(details) or not stat.S_ISDIR(details.st_mode):
            return
        receipt = stage / "receipt.json"
        if _lexists(receipt):
            receipt.unlink()
        stage.rmdir()
    except OSError:
        return


def _sync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _mkdir_durable(path: Path) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        return
    _sync_directory(path.parent)


def _link_like(details: os.stat_result) -> bool:
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(attributes & _REPARSE_POINT)


def _lexists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _safe_identifier(value: str) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character in _IDENTIFIER_CHARS for character in value)
    )


def _valid_tenant_id(value: str) -> bool:
    try:
        artifact_tenant_path_component(value)
    except ArtifactTenantNamespaceError:
        return False
    return True


def _safe_text(value: object, *, maximum: int) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= maximum
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _sha256(value: str) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _HEX_CHARS for character in value)
    )


def _timestamp(value: object) -> datetime:
    if type(value) is not str:
        raise ArtifactUploadConflict()
    return _utc(datetime.fromisoformat(value), rejected=False)


def _utc(value: datetime, *, rejected: bool) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        if rejected:
            raise ArtifactUploadRejected()
        raise ArtifactUploadConflict()
    return value


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactUploadConflict()
        value[key] = item
    return value


__all__ = [
    "ArtifactPutRequest",
    "ArtifactUploadConflict",
    "ArtifactUploadReceipt",
    "ArtifactUploadRejected",
    "ArtifactUploadService",
    "ArtifactUploadUnavailable",
    "AuthorizedLocalArtifactUploadService",
    "purge_orphaned_artifact_objects",
]
