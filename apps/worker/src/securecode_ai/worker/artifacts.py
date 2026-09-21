"""Linux-only atomic storage for canonical CI worker result metadata."""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
import sys
from contextlib import suppress
from pathlib import Path
from typing import Final

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    AuditRun,
    DataClass,
)

from .runner import CiWorkerRequest, CiWorkerResult, canonical_ci_worker_result_json, run_ci_worker

_CONTENT_DOMAIN: Final = b"securecode.ci-worker-artifact.v1"
_TENANT_DOMAIN: Final = b"securecode.ci-worker-artifact-tenant.v1"
_CONCRETE_PATH_TYPE: Final = type(Path())
_MAX_RESULT_BYTES: Final = 1_048_576
_O_NOFOLLOW: Final[int] = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY: Final[int] = getattr(os, "O_DIRECTORY", 0)
_O_CLOEXEC: Final[int] = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK: Final[int] = getattr(os, "O_NONBLOCK", 0)


class CiWorkerArtifactError(ValueError):
    """Safe failure for all local worker-artifact boundary violations."""

    def __init__(self) -> None:
        super().__init__("CI worker artifact operation failed")


def write_ci_worker_artifact(
    artifact_root: Path,
    request: CiWorkerRequest,
    result: CiWorkerResult,
) -> ArtifactRef:
    """Persist a revalidated canonical worker result with exclusive publication.

    The writer deliberately supports only Linux descriptor-relative filesystem
    operations.  A result cannot select its tenant or be persisted unless it
    exactly equals a fresh closed worker result for the supplied request.
    """

    root_fd = tenants_fd = tenant_fd = -1
    temporary_name: str | None = None
    temporary_identity: tuple[int, int] | None = None
    try:
        _require_linux()
        audit_run = _revalidate_request(request)
        result_bytes = _matching_result_bytes(CiWorkerRequest(audit_run=audit_run), result)
        tenant_id = audit_run.execution_identity.repository_revision.tenant_id
        content_sha256 = hashlib.sha256(result_bytes).hexdigest()
        content_id = "ciwr-" + _content_digest(tenant_id, result_bytes)
        tenant_directory = _tenant_digest(tenant_id)

        root_fd, root_identity = _open_root(artifact_root)
        tenants_fd, tenants_identity = _open_or_create_directory(root_fd, "tenants")
        tenant_fd, tenant_identity = _open_or_create_directory(tenants_fd, tenant_directory)
        leaf_name = f"{content_id}.json"

        try:
            _verify_existing(tenant_fd, leaf_name, result_bytes)
        except FileNotFoundError:
            temporary_name, temporary_identity = _write_temporary(
                tenant_fd, content_id, result_bytes
            )
            try:
                os.link(
                    temporary_name,
                    leaf_name,
                    src_dir_fd=tenant_fd,
                    dst_dir_fd=tenant_fd,
                    follow_symlinks=False,
                )
            except FileExistsError:
                _verify_existing(tenant_fd, leaf_name, result_bytes)
            else:
                _verify_existing(tenant_fd, leaf_name, result_bytes)
                os.fsync(tenant_fd)
            finally:
                _unlink_owned(tenant_fd, temporary_name, temporary_identity)
                temporary_name = None
                temporary_identity = None

        _assert_root_binding(artifact_root, root_identity)
        _assert_directory_binding(root_fd, "tenants", tenants_identity)
        _assert_directory_binding(tenants_fd, tenant_directory, tenant_identity)
        leaf_identity = _verify_existing(tenant_fd, leaf_name, result_bytes)
        _assert_root_binding(artifact_root, root_identity)
        _assert_directory_binding(root_fd, "tenants", tenants_identity)
        _assert_directory_binding(tenants_fd, tenant_directory, tenant_identity)
        _assert_leaf_binding(tenant_fd, leaf_name, leaf_identity)
        return ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=tenant_id,
            content_id=content_id,
            content_sha256=content_sha256,
            size_bytes=len(result_bytes),
            data_class=DataClass.INTERNAL_METADATA,
        )
    except CiWorkerArtifactError:
        raise
    except Exception:
        raise CiWorkerArtifactError() from None
    finally:
        if temporary_name is not None and temporary_identity is not None and tenant_fd >= 0:
            _unlink_owned(tenant_fd, temporary_name, temporary_identity)
        for descriptor in (tenant_fd, tenants_fd, root_fd):
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)


def _require_linux() -> None:
    if (
        sys.platform != "linux"
        or os.name != "posix"
        or _O_NOFOLLOW == 0
        or _O_DIRECTORY == 0
        or _O_NONBLOCK == 0
    ):
        raise CiWorkerArtifactError()


def _revalidate_request(request: CiWorkerRequest) -> AuditRun:
    if type(request) is not CiWorkerRequest:
        raise CiWorkerArtifactError()
    audit_run = request.audit_run
    if type(audit_run) is not AuditRun:
        raise CiWorkerArtifactError()
    return AuditRun.model_validate_json(audit_run.model_dump_json())


def _matching_result_bytes(request: CiWorkerRequest, result: CiWorkerResult) -> bytes:
    if type(result) is not CiWorkerResult:
        raise CiWorkerArtifactError()
    expected = canonical_ci_worker_result_json(run_ci_worker(request))
    supplied = canonical_ci_worker_result_json(result)
    if expected != supplied:
        raise CiWorkerArtifactError()
    payload = supplied.encode("ascii")
    if len(payload) > _MAX_RESULT_BYTES:
        raise CiWorkerArtifactError()
    return payload


def _content_digest(tenant_id: str, result_bytes: bytes) -> str:
    return hashlib.sha256(
        _CONTENT_DOMAIN + b"\0" + tenant_id.encode("utf-8") + b"\0" + result_bytes
    ).hexdigest()


def _tenant_digest(tenant_id: str) -> str:
    return hashlib.sha256(_TENANT_DOMAIN + b"\0" + tenant_id.encode("utf-8")).hexdigest()


def _open_root(root: Path) -> tuple[int, tuple[int, int]]:
    if (
        type(root) is not _CONCRETE_PATH_TYPE
        or not root.is_absolute()
        or any(part in {".", ".."} for part in root.parts)
    ):
        raise CiWorkerArtifactError()
    descriptor = os.open("/", _directory_flags())
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISDIR(details.st_mode):
            raise CiWorkerArtifactError()
        for component in root.parts[1:]:
            child, _ = _open_existing_directory(descriptor, component)
            os.close(descriptor)
            descriptor = child
        return descriptor, _identity(os.fstat(descriptor))
    except Exception:
        with suppress(OSError):
            os.close(descriptor)
        raise


def _open_existing_directory(parent_fd: int, name: str) -> tuple[int, tuple[int, int]]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if _is_link_like(before) or not stat.S_ISDIR(before.st_mode):
        raise CiWorkerArtifactError()
    descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or _identity(before) != _identity(opened):
        os.close(descriptor)
        raise CiWorkerArtifactError()
    return descriptor, _identity(opened)


def _open_or_create_directory(parent_fd: int, name: str) -> tuple[int, tuple[int, int]]:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        with suppress(FileExistsError):
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if _is_link_like(before) or not stat.S_ISDIR(before.st_mode):
        raise CiWorkerArtifactError()
    descriptor = os.open(name, _directory_flags(), dir_fd=parent_fd)
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or _identity(before) != _identity(opened):
        os.close(descriptor)
        raise CiWorkerArtifactError()
    return descriptor, _identity(opened)


def _write_temporary(
    directory_fd: int, content_id: str, result_bytes: bytes
) -> tuple[str, tuple[int, int]]:
    name = f".{content_id}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    identity: tuple[int, int] | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW | _O_CLOEXEC
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise CiWorkerArtifactError()
        identity = _identity(opened)
        _write_all(descriptor, result_bytes)
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if identity != _identity(after) or after.st_size != len(result_bytes):
            raise CiWorkerArtifactError()
        return name, identity
    except Exception:
        if identity is not None:
            _unlink_owned(directory_fd, name, identity)
        raise
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _verify_existing(directory_fd: int, name: str, expected: bytes) -> tuple[int, int]:
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if _is_link_like(before) or not stat.S_ISREG(before.st_mode) or before.st_size != len(expected):
        raise CiWorkerArtifactError()
    descriptor = -1
    try:
        descriptor = os.open(name, _read_flags(), dir_fd=directory_fd)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(before) != _identity(opened):
            raise CiWorkerArtifactError()
        data = _read_bounded(descriptor, len(expected))
        after = os.fstat(descriptor)
        if _identity(opened) != _identity(after) or data != expected:
            raise CiWorkerArtifactError()
        return _identity(after)
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _assert_root_binding(root: Path, identity: tuple[int, int]) -> None:
    descriptor = -1
    try:
        descriptor, current = _open_root(root)
        if current != identity:
            raise CiWorkerArtifactError()
    finally:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)


def _assert_directory_binding(parent_fd: int, name: str, identity: tuple[int, int]) -> None:
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (
        _is_link_like(current)
        or not stat.S_ISDIR(current.st_mode)
        or _identity(current) != identity
    ):
        raise CiWorkerArtifactError()


def _assert_leaf_binding(directory_fd: int, name: str, identity: tuple[int, int]) -> None:
    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (
        _is_link_like(current)
        or not stat.S_ISREG(current.st_mode)
        or _identity(current) != identity
    ):
        raise CiWorkerArtifactError()


def _unlink_owned(directory_fd: int, name: str, identity: tuple[int, int]) -> None:
    with suppress(OSError):
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            stat.S_ISREG(current.st_mode)
            and not _is_link_like(current)
            and _identity(current) == identity
        ):
            os.unlink(name, dir_fd=directory_fd)


def _read_bounded(descriptor: int, expected_size: int) -> bytes:
    remaining = expected_size + 1
    chunks: list[bytes] = []
    while remaining > 0:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise CiWorkerArtifactError()
        offset += written


def _directory_flags() -> int:
    return os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW | _O_CLOEXEC


def _read_flags() -> int:
    return os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK


def _is_link_like(details: os.stat_result) -> bool:
    return stat.S_ISLNK(details.st_mode) or bool(
        getattr(details, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _identity(details: os.stat_result) -> tuple[int, int]:
    return (details.st_dev, details.st_ino)


__all__ = ["CiWorkerArtifactError", "write_ci_worker_artifact"]
