"""Exclusive immutable local development blob store with read-time integrity checks."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path

from .artifact_tenant_namespace import (
    ArtifactTenantNamespaceError,
    artifact_tenant_path_component,
)
from .artifacts import ArtifactConflict, ArtifactMetadata

_METADATA_LIMIT = 65_536
_MAX_ARTIFACT_ENTRIES = 10_000


class LocalArtifactStore:
    def __init__(self, root: Path, *, max_bytes: int = 16_777_216) -> None:
        if type(max_bytes) is not int or not 1 <= max_bytes <= 1_073_741_824:
            raise ValueError("artifact store size limit is invalid")
        self._root = _lexical_root(root)
        self._max_bytes = max_bytes
        try:
            _ensure_plain_directory(self._root)
        except OSError:
            raise ValueError("artifact root is unsafe") from None

    def put(
        self, metadata: ArtifactMetadata, chunks: Iterable[bytes], idempotency_key: str
    ) -> ArtifactMetadata:
        untrusted_chunks: object = chunks
        if (
            type(metadata) is not ArtifactMetadata
            or not isinstance(untrusted_chunks, Iterable)
            or type(untrusted_chunks) is str
            or type(untrusted_chunks) is bytes
            or type(untrusted_chunks) is bytearray
            or type(idempotency_key) is not str
            or not 1 <= len(idempotency_key) <= 128
            or any(ord(character) < 0x21 or ord(character) > 0x7E for character in idempotency_key)
        ):
            raise ArtifactConflict()
        _require_unexpired(metadata)
        if metadata.size_bytes > self._max_bytes:
            raise ArtifactConflict()
        target = self._object_path(metadata.tenant_id, metadata.content_sha256)
        meta = target.with_suffix(".json")
        try:
            _ensure_plain_directory(target.parent)
        except OSError:
            raise ArtifactConflict() from None
        if target.exists() or meta.exists():
            if target.exists() and not meta.exists():
                self._publish_orphan_metadata(target, meta, metadata)
            existing, _ = self.get(
                tenant_id=metadata.tenant_id, content_sha256=metadata.content_sha256
            )
            if existing == metadata:
                return existing
            raise ArtifactConflict()
        digest, size, temporary = self._stream_temp(target.parent, chunks)
        try:
            if digest != metadata.content_sha256 or size != metadata.size_bytes:
                raise ArtifactConflict()
            try:
                os.link(temporary, target)
            except FileExistsError:
                self._publish_orphan_metadata(target, meta, metadata)
                existing, _ = self.get(
                    tenant_id=metadata.tenant_id, content_sha256=metadata.content_sha256
                )
                if existing != metadata:
                    raise ArtifactConflict() from None
                return existing
            _sync_directory(target.parent)
            try:
                self._write_metadata(meta, metadata)
            except FileExistsError:
                existing, _ = self.get(
                    tenant_id=metadata.tenant_id, content_sha256=metadata.content_sha256
                )
                if existing != metadata:
                    raise ArtifactConflict() from None
                return existing
            return metadata
        finally:
            Path(temporary).unlink(missing_ok=True)

    def _publish_orphan_metadata(
        self, target: Path, meta: Path, metadata: ArtifactMetadata
    ) -> None:
        if meta.exists():
            return
        _require_unexpired(metadata)
        if (
            _path_is_link_like(target)
            or not target.is_file()
            or metadata.size_bytes > self._max_bytes
            or target.stat().st_size != metadata.size_bytes
            or _digest(target) != metadata.content_sha256
        ):
            raise ArtifactConflict()
        try:
            self._write_metadata(meta, metadata)
        except FileExistsError:
            return

    def get(
        self, *, tenant_id: str, content_sha256: str
    ) -> tuple[ArtifactMetadata, Iterator[bytes]]:
        target = self._object_path(tenant_id, content_sha256)
        meta_path = target.with_suffix(".json")
        try:
            _assert_plain_directory_chain(target.parent)
            unsafe = (
                not target.is_file()
                or _path_is_link_like(target)
                or not meta_path.is_file()
                or _path_is_link_like(meta_path)
                or meta_path.stat().st_size > _METADATA_LIMIT
            )
        except OSError:
            raise ArtifactConflict() from None
        if unsafe:
            raise ArtifactConflict()
        try:
            document = json.loads(
                meta_path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_object_pairs,
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise ArtifactConflict() from None
        if type(document) is not dict:
            raise ArtifactConflict()
        metadata = _metadata(document)
        if metadata.tenant_id != tenant_id or metadata.content_sha256 != content_sha256:
            raise ArtifactConflict()
        _require_unexpired(metadata)
        content = _read_verified_content(
            target,
            expected_sha256=content_sha256,
            expected_size=metadata.size_bytes,
            max_bytes=self._max_bytes,
        )
        return metadata, iter((content,))

    def list(self, *, tenant_id: str, run_id: str) -> tuple[ArtifactMetadata, ...]:
        directory = self._tenant_dir(tenant_id)
        try:
            details = directory.lstat()
        except FileNotFoundError:
            return ()
        except OSError:
            raise ArtifactConflict() from None
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise ArtifactConflict()
        values = []
        now = datetime.now(tz=UTC)
        for seen_entries, path in enumerate(directory.rglob("*.json"), start=1):
            if seen_entries > _MAX_ARTIFACT_ENTRIES:
                raise ArtifactConflict()
            if path.is_symlink():
                raise ArtifactConflict()
            try:
                _assert_plain_directory_chain(path.parent)
                if path.stat().st_size > _METADATA_LIMIT:
                    raise ArtifactConflict()
            except OSError:
                raise ArtifactConflict() from None
            try:
                document = json.loads(
                    path.read_text(encoding="utf-8"),
                    object_pairs_hook=_unique_object_pairs,
                )
            except (OSError, UnicodeError, json.JSONDecodeError):
                raise ArtifactConflict() from None
            if type(document) is not dict:
                raise ArtifactConflict()
            metadata = _metadata(document)
            _require_unexpired(metadata, now=now)
            if metadata.size_bytes > self._max_bytes:
                raise ArtifactConflict()
            if metadata.tenant_id != tenant_id:
                raise ArtifactConflict()
            if metadata.run_id == run_id:
                _read_verified_content(
                    self._object_path(tenant_id, metadata.content_sha256),
                    expected_sha256=metadata.content_sha256,
                    expected_size=metadata.size_bytes,
                    max_bytes=self._max_bytes,
                )
                values.append(metadata)
                if len(values) > _MAX_ARTIFACT_ENTRIES:
                    raise ArtifactConflict()
        return tuple(sorted(values, key=lambda item: item.content_sha256))

    def _stream_temp(self, directory: Path, chunks: Iterable[bytes]) -> tuple[str, int, str]:
        descriptor, name = tempfile.mkstemp(dir=directory, prefix=".upload-", suffix=".tmp")
        digest, size = hashlib.sha256(), 0
        try:
            with os.fdopen(descriptor, "wb") as stream:
                for chunk in chunks:
                    if not isinstance(chunk, bytes):
                        raise ArtifactConflict()
                    size += len(chunk)
                    if size > self._max_bytes:
                        raise ArtifactConflict()
                    digest.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            return digest.hexdigest(), size, name
        except Exception:
            Path(name).unlink(missing_ok=True)
            raise

    def _object_path(self, tenant_id: str, digest: str) -> Path:
        if not _sha(digest):
            raise ArtifactConflict()
        path = self._tenant_dir(tenant_id) / digest[:2] / digest
        try:
            path.relative_to(self._root)
        except ValueError:
            raise ArtifactConflict() from None
        return path

    def _tenant_dir(self, tenant_id: str) -> Path:
        try:
            tenant_component = artifact_tenant_path_component(tenant_id)
        except ArtifactTenantNamespaceError:
            raise ArtifactConflict() from None
        return self._root / tenant_component

    def _write_metadata(self, path: Path, metadata: ArtifactMetadata) -> None:
        _require_unexpired(metadata)
        value = {
            **asdict(metadata),
            "created_at": metadata.created_at.isoformat(),
            "expires_at": None if metadata.expires_at is None else metadata.expires_at.isoformat(),
        }
        descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".metadata-", suffix=".tmp")
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(json.dumps(value, ensure_ascii=True, sort_keys=True))
                stream.flush()
                os.fsync(stream.fileno())
            os.link(name, path)
            _sync_directory(path.parent)
        finally:
            Path(name).unlink(missing_ok=True)


class TenantNamespacedArtifactStore:
    """Keep arbitrary tenant identifiers out of local filesystem paths."""

    def __init__(self, store: LocalArtifactStore) -> None:
        if not isinstance(store, LocalArtifactStore):
            raise TypeError("store must be a LocalArtifactStore")
        self._store = store

    def put(
        self, metadata: ArtifactMetadata, chunks: Iterable[bytes], idempotency_key: str
    ) -> ArtifactMetadata:
        stored = replace(metadata, tenant_id=_tenant_namespace(metadata.tenant_id))
        self._store.put(stored, chunks, idempotency_key)
        return metadata

    def get(
        self, *, tenant_id: str, content_sha256: str
    ) -> tuple[ArtifactMetadata, Iterator[bytes]]:
        metadata, chunks = self._store.get(
            tenant_id=_tenant_namespace(tenant_id), content_sha256=content_sha256
        )
        return replace(metadata, tenant_id=tenant_id), chunks

    def list(self, *, tenant_id: str, run_id: str) -> tuple[ArtifactMetadata, ...]:
        return tuple(
            replace(metadata, tenant_id=tenant_id)
            for metadata in self._store.list(tenant_id=_tenant_namespace(tenant_id), run_id=run_id)
        )


def _tenant_namespace(tenant_id: str) -> str:
    if type(tenant_id) is not str or not tenant_id:
        raise ArtifactConflict()
    return "t-" + hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()


def _chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as stream:
        while value := stream.read(65536):
            yield value


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    for chunk in _chunks(path):
        digest.update(chunk)
    return digest.hexdigest()


def _read_verified_content(
    path: Path, *, expected_sha256: str, expected_size: int, max_bytes: int
) -> bytes:
    if expected_size > max_bytes:
        raise ArtifactConflict()
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        raise ArtifactConflict() from None
    try:
        before = os.fstat(descriptor)
        if (
            _link_like(before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_size != expected_size
        ):
            raise ArtifactConflict()
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, min(65_536, max_bytes + 1 - size)):
            size += len(chunk)
            if size > max_bytes:
                raise ArtifactConflict()
            chunks.append(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            _link_like(current)
            or not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or size != expected_size
            or digest.hexdigest() != expected_sha256
        ):
            raise ArtifactConflict()
        return b"".join(chunks)
    except OSError:
        raise ArtifactConflict() from None
    finally:
        os.close(descriptor)


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
    return stat.S_ISLNK(details.st_mode) or bool(attributes & 0x400)


def _path_is_link_like(path: Path) -> bool:
    try:
        return _link_like(path.lstat())
    except OSError:
        return True


def _safe(value: str) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(
            ("A" <= character <= "Z")
            or ("a" <= character <= "z")
            or ("0" <= character <= "9")
            or character in "_-"
            for character in value
        )
    )


def _ensure_plain_directory(path: Path) -> None:
    """Create a directory chain without ever following a reparse point."""

    if not path.is_absolute() or not path.anchor:
        raise OSError("artifact directory must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        with contextlib.suppress(FileExistsError):
            current.mkdir()
        details = current.lstat()
        if _link_like(details) or not stat.S_ISDIR(details.st_mode):
            raise OSError("artifact directory is unsafe")


def _assert_plain_directory_chain(path: Path) -> None:
    """Reject reparse points in every directory used for a read."""

    if not path.is_absolute() or not path.anchor:
        raise OSError("artifact directory must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        details = current.lstat()
        if _link_like(details) or not stat.S_ISDIR(details.st_mode):
            raise OSError("artifact directory is unsafe")


def _lexical_root(root: Path) -> Path:
    """Return an absolute root without following a symlink in its path."""

    if not isinstance(root, Path):
        raise ValueError("artifact root is unsafe")
    absolute = root.absolute()
    current = absolute
    while True:
        try:
            details = current.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            raise ValueError("artifact root is unsafe") from None
        else:
            if stat.S_ISLNK(details.st_mode) or bool(
                getattr(details, "st_file_attributes", 0) & 0x400
            ):
                raise ValueError("artifact root is unsafe")
        if current == Path(current.anchor):
            break
        current = current.parent
    return absolute


def _sha(value: str) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _metadata(value: dict[str, object]) -> ArtifactMetadata:
    if type(value) is not dict:
        raise ArtifactConflict()
    expected = {
        "tenant_id",
        "repository_id",
        "run_id",
        "execution_identity_hash",
        "content_sha256",
        "size_bytes",
        "content_class",
        "purpose",
        "created_at",
        "expires_at",
        "retention_marked",
    }
    if set(value) != expected:
        raise ArtifactConflict()
    tenant_id = _metadata_text(value["tenant_id"])
    repository_id = _metadata_text(value["repository_id"])
    run_id = _metadata_text(value["run_id"])
    execution_identity_hash = _metadata_text(value["execution_identity_hash"])
    content_sha256 = _metadata_text(value["content_sha256"])
    size_bytes = value["size_bytes"]
    content_class = _metadata_text(value["content_class"])
    purpose = _metadata_text(value["purpose"])
    created = _metadata_text(value["created_at"])
    expires = value["expires_at"]
    retention_marked = value["retention_marked"]
    if (
        type(size_bytes) is not int
        or (expires is not None and not isinstance(expires, str))
        or type(retention_marked) is not bool
    ):
        raise ArtifactConflict()
    try:
        return ArtifactMetadata(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
            content_class=content_class,
            purpose=purpose,
            created_at=datetime.fromisoformat(created),
            expires_at=None if expires is None else datetime.fromisoformat(expires),
            retention_marked=retention_marked,
        )
    except (TypeError, ValueError):
        raise ArtifactConflict() from None


def _metadata_text(value: object) -> str:
    if not isinstance(value, str):
        raise ArtifactConflict()
    return value


def _require_unexpired(metadata: ArtifactMetadata, *, now: datetime | None = None) -> None:
    if type(metadata) is not ArtifactMetadata:
        raise ArtifactConflict()
    if metadata.expires_at is not None and metadata.expires_at <= (
        datetime.now(tz=UTC) if now is None else now
    ):
        raise ArtifactConflict()


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ArtifactConflict()
        value[key] = item
    return value
