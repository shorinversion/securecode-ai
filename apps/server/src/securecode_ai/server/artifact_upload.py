"""Authorized, immutable local artifact uploads for the connected server."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import stat
import tempfile
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final, Protocol

from .filesystem_paths import lexical_absolute_path
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
            or not _safe_identifier(self.tenant_id)
            or not _sha256(self.execution_identity_hash)
            or not _sha256(self.content_sha256)
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

    def document(self) -> dict[str, object]:
        value = asdict(self)
        value["authorized_at"] = self.authorized_at.isoformat()
        value["authorization_expires_at"] = self.authorization_expires_at.isoformat()
        value["stored_at"] = self.stored_at.isoformat()
        return value


class ArtifactUploadService(Protocol):
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

    async def put(self, request: ArtifactPutRequest) -> ArtifactUploadReceipt:
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
            authorization = self._authorizations.require(
                tenant_id=request.tenant_id,
                authorization_id=request.authorization_id,
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
        if stored_at >= authorization.expires_at:
            raise ArtifactUploadRejected()
        receipt = _receipt(authorization, stored_at=stored_at)
        try:
            return await asyncio.to_thread(
                self._objects.put,
                receipt=receipt,
                content=request.content,
            )
        except ArtifactUploadConflict:
            raise
        except (OSError, UnicodeError, ValueError):
            raise ArtifactUploadUnavailable() from None


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
            decoded = json.loads(receipt_raw.decode("ascii"))
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
        decoded = json.loads(raw.decode("ascii"))
        if type(decoded) is not dict:
            raise ArtifactUploadConflict()
        receipt = _parse_receipt(decoded)
        if not _same_authorization(receipt, expected):
            raise ArtifactUploadConflict()
        return receipt

    def _object_directory(self, tenant_id: str, digest: str) -> Path:
        if not _safe_identifier(tenant_id) or not _sha256(digest):
            raise ArtifactUploadRejected()
        target = self._root / tenant_id / digest[:2] / digest
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
            with suppress(FileExistsError):
                current.mkdir(mode=0o700)
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
        document["schema_version"] != _SCHEMA_VERSION
        or type(document["size_bytes"]) is not int
        or not all(type(document[name]) is str and document[name] for name in strings)
    ):
        raise ArtifactUploadConflict()
    try:
        return ArtifactUploadReceipt(
            schema_version=_SCHEMA_VERSION,
            authorization_id=str(document["authorization_id"]),
            tenant_id=str(document["tenant_id"]),
            worker_id=str(document["worker_id"]),
            repository_id=str(document["repository_id"]),
            run_id=str(document["run_id"]),
            execution_identity_hash=str(document["execution_identity_hash"]),
            content_id=str(document["content_id"]),
            content_sha256=str(document["content_sha256"]),
            size_bytes=int(document["size_bytes"]),
            data_class=str(document["data_class"]),
            purpose=str(document["purpose"]),
            signer_key_id=str(document["signer_key_id"]),
            authorization_signature=str(document["authorization_signature"]),
            authorized_at=_timestamp(document["authorized_at"]),
            authorization_expires_at=_timestamp(document["authorization_expires_at"]),
            stored_at=_timestamp(document["stored_at"]),
            object_key=str(document["object_key"]),
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
        with suppress(FileExistsError):
            current.mkdir(mode=0o700)
        _assert_plain_directory(current)


def _assert_plain_directory(path: Path) -> None:
    details = path.lstat()
    if _link_like(details) or not stat.S_ISDIR(details.st_mode):
        raise ValueError("artifact directory is unsafe")


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


__all__ = [
    "ArtifactPutRequest",
    "ArtifactUploadConflict",
    "ArtifactUploadReceipt",
    "ArtifactUploadRejected",
    "ArtifactUploadService",
    "ArtifactUploadUnavailable",
    "AuthorizedLocalArtifactUploadService",
]
