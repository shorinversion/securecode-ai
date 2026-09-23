"""Exclusive immutable local development blob store with read-time integrity checks."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .artifacts import ArtifactConflict, ArtifactMetadata


class LocalArtifactStore:
    def __init__(self, root: Path, *, max_bytes: int = 16_777_216) -> None:
        self._root = _lexical_root(root)
        self._max_bytes = max_bytes
        self._root.mkdir(parents=True, exist_ok=True)

    def put(
        self, metadata: ArtifactMetadata, chunks: Iterable[bytes], idempotency_key: str
    ) -> ArtifactMetadata:
        if not isinstance(idempotency_key, str) or not idempotency_key:
            raise ArtifactConflict()
        target = self._object_path(metadata.tenant_id, metadata.content_sha256)
        meta = target.with_suffix(".json")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() or meta.exists():
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
                existing, _ = self.get(
                    tenant_id=metadata.tenant_id, content_sha256=metadata.content_sha256
                )
                if existing != metadata:
                    raise ArtifactConflict() from None
                return existing
            self._write_metadata(meta, metadata)
            return metadata
        finally:
            Path(temporary).unlink(missing_ok=True)

    def get(
        self, *, tenant_id: str, content_sha256: str
    ) -> tuple[ArtifactMetadata, Iterator[bytes]]:
        target = self._object_path(tenant_id, content_sha256)
        meta_path = target.with_suffix(".json")
        if (
            not target.is_file()
            or target.is_symlink()
            or not meta_path.is_file()
            or meta_path.is_symlink()
        ):
            raise ArtifactConflict()
        metadata = _metadata(json.loads(meta_path.read_text(encoding="utf-8")))
        if (
            metadata.tenant_id != tenant_id
            or metadata.content_sha256 != content_sha256
            or target.stat().st_size != metadata.size_bytes
            or _digest(target) != content_sha256
        ):
            raise ArtifactConflict()
        return metadata, _chunks(target)

    def list(self, *, tenant_id: str, run_id: str) -> tuple[ArtifactMetadata, ...]:
        directory = self._tenant_dir(tenant_id)
        if not directory.exists():
            return ()
        values = []
        for path in directory.rglob("*.json"):
            if path.is_symlink():
                raise ArtifactConflict()
            metadata = _metadata(json.loads(path.read_text(encoding="utf-8")))
            if metadata.tenant_id == tenant_id and metadata.run_id == run_id:
                values.append(metadata)
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
        if not _safe(tenant_id) or not _sha(digest):
            raise ArtifactConflict()
        path = self._tenant_dir(tenant_id) / digest[:2] / digest
        if self._root not in path.resolve().parents:
            raise ArtifactConflict()
        return path

    def _tenant_dir(self, tenant_id: str) -> Path:
        if not _safe(tenant_id):
            raise ArtifactConflict()
        return self._root / tenant_id

    def _write_metadata(self, path: Path, metadata: ArtifactMetadata) -> None:
        value = {
            **asdict(metadata),
            "created_at": metadata.created_at.isoformat(),
            "expires_at": None if metadata.expires_at is None else metadata.expires_at.isoformat(),
        }
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True), encoding="utf-8")
        temporary.replace(path)


def _chunks(path: Path) -> Iterator[bytes]:
    with path.open("rb") as stream:
        while value := stream.read(65536):
            yield value


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    for chunk in _chunks(path):
        digest.update(chunk)
    return digest.hexdigest()


def _safe(value: str) -> bool:
    return bool(value) and value.replace("_", "").replace("-", "").isalnum()


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
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _metadata(value: dict[str, object]) -> ArtifactMetadata:
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
