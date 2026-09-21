from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Final, cast

from securecode_ai.core.release_candidate import ReleaseArtifact, ReleaseCandidate
from securecode_ai.core.release_publisher import (
    AuthorizedPublishRequest,
    PublishAuthorization,
    RemoteRelease,
)

from .release_authorization import HmacReleaseAuthority as HmacReleaseAuthority

_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TAG: Final = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+\Z")
_PATH_PART: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_CHUNK_BYTES: Final = 1024 * 1024
_MAX_TAG_BYTES: Final = 16 * 1024
_MAX_MANIFEST_BYTES: Final = 8 * 1024 * 1024
_SCHEMA_VERSION: Final = 2


class LocalReleaseProviderError(ValueError):
    def __init__(self) -> None:
        super().__init__("Local release publication was rejected")
        self.__cause__ = None
        self.__context__ = None


def _manifest_bytes(
    request: AuthorizedPublishRequest,
    objects: tuple[dict[str, object], ...],
    evidence: tuple[dict[str, object], ...],
) -> bytes:
    candidate = request.plan.candidate
    authorization = request.authorization
    return _canonical_json(
        {
            "authorization": {
                "action": authorization.action,
                "approver_id": authorization.approver_id,
                "authorization_id": authorization.authorization_id,
                "candidate_sha256": authorization.candidate_sha256,
                "expires_at": authorization.expires_at,
                "key_id": authorization.key_id,
                "nonce": authorization.nonce,
                "store_identity_sha256": authorization.store_identity_sha256,
                "signature_sha256": authorization.signature_sha256,
            },
            "candidate": {
                "artifacts": [
                    {
                        "artifact_id": item.artifact_id,
                        "checksum_sha256": item.checksum_sha256,
                        "signature_sha256": item.signature_sha256,
                    }
                    for item in candidate.artifacts
                ],
                "candidate_sha256": candidate.candidate_sha256,
                "checksums_sha256": candidate.checksums_sha256,
                "closure_activation_sha256": candidate.closure_activation_sha256,
                "provenance_sha256": candidate.provenance_sha256,
                "release_signature_sha256": candidate.release_signature_sha256,
                "sbom_sha256": candidate.sbom_sha256,
                "server_image_digest": candidate.server_image_digest,
                "source_tree_sha256": candidate.source_tree_sha256,
                "version": candidate.version,
                "worker_image_digest": candidate.worker_image_digest,
            },
            "evidence": list(evidence),
            "objects": list(objects),
            "schema_version": _SCHEMA_VERSION,
        }
    )


def _candidate_from_manifest(manifest: dict[str, object]) -> ReleaseCandidate:
    if (
        set(manifest)
        != {
            "authorization",
            "candidate",
            "evidence",
            "objects",
            "schema_version",
        }
        or manifest["schema_version"] != _SCHEMA_VERSION
    ):
        raise LocalReleaseProviderError()
    authorization = manifest["authorization"]
    value = manifest["candidate"]
    if (
        type(authorization) is not dict
        or set(authorization)
        != {
            "action",
            "approver_id",
            "authorization_id",
            "candidate_sha256",
            "expires_at",
            "key_id",
            "nonce",
            "signature_sha256",
            "store_identity_sha256",
        }
        or type(value) is not dict
        or set(value)
        != {
            "artifacts",
            "candidate_sha256",
            "checksums_sha256",
            "closure_activation_sha256",
            "provenance_sha256",
            "release_signature_sha256",
            "sbom_sha256",
            "server_image_digest",
            "source_tree_sha256",
            "version",
            "worker_image_digest",
        }
    ):
        raise LocalReleaseProviderError()
    artifacts = value["artifacts"]
    if type(artifacts) is not list:
        raise LocalReleaseProviderError()
    parsed: list[ReleaseArtifact] = []
    for item in artifacts:
        if type(item) is not dict or set(item) != {
            "artifact_id",
            "checksum_sha256",
            "signature_sha256",
        }:
            raise LocalReleaseProviderError()
        artifact_id = _required_string(item["artifact_id"])
        checksum_sha256 = _required_string(item["checksum_sha256"])
        signature_sha256 = _required_string(item["signature_sha256"])
        parsed.append(ReleaseArtifact(artifact_id, checksum_sha256, signature_sha256))
    scalar_names = (
        "version",
        "source_tree_sha256",
        "closure_activation_sha256",
        "sbom_sha256",
        "provenance_sha256",
        "checksums_sha256",
        "server_image_digest",
        "worker_image_digest",
        "release_signature_sha256",
        "candidate_sha256",
    )
    scalars = tuple(_required_string(value[name]) for name in scalar_names)
    return ReleaseCandidate(
        scalars[0],
        scalars[1],
        scalars[2],
        scalars[3],
        scalars[4],
        scalars[5],
        scalars[6],
        scalars[7],
        tuple(parsed),
        scalars[8],
        scalars[9],
    )


def _authorization_from_manifest(manifest: dict[str, object]) -> PublishAuthorization:
    value = manifest.get("authorization")
    keys = {
        "action",
        "approver_id",
        "authorization_id",
        "candidate_sha256",
        "expires_at",
        "key_id",
        "nonce",
        "signature_sha256",
        "store_identity_sha256",
    }
    if type(value) is not dict or set(value) != keys:
        raise LocalReleaseProviderError()
    expires_at = value["expires_at"]
    if type(expires_at) is not int:
        raise LocalReleaseProviderError()
    return PublishAuthorization(
        _required_string(value["authorization_id"]),
        _required_string(value["action"]),
        _required_string(value["approver_id"]),
        _required_string(value["candidate_sha256"]),
        expires_at,
        _required_string(value["key_id"]),
        _required_string(value["nonce"]),
        _required_string(value["store_identity_sha256"]),
        _required_string(value["signature_sha256"]),
    )


def _remote_matches(remote: RemoteRelease, request: AuthorizedPublishRequest) -> bool:
    plan = request.plan
    return (
        remote.complete
        and remote.tag == plan.tag
        and remote.candidate_sha256 == plan.candidate_sha256
        and remote.artifact_checksums == plan.artifact_checksums
    )


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _json_object(value: bytes) -> dict[str, object]:
    parsed = json.loads(value.decode("ascii"))
    if type(parsed) is not dict:
        raise LocalReleaseProviderError()
    return parsed


def _verify_canonical_json(path: Path, maximum_bytes: int) -> None:
    value = _read_verified_file(path, maximum_bytes)
    parsed = json.loads(value.decode("ascii"))
    if not isinstance(parsed, (dict, list)) or not parsed or value != _canonical_json(parsed):
        raise LocalReleaseProviderError()


def _required_string(value: object) -> str:
    if type(value) is not str:
        raise LocalReleaseProviderError()
    return value


def _object_relative_path(digest: str) -> str:
    if type(digest) is not str or _HASH.fullmatch(digest) is None:
        raise LocalReleaseProviderError()
    return f"objects/sha256/{digest[:2]}/{digest}.blob"


def _manifest_relative_path(digest: str) -> str:
    if type(digest) is not str or _HASH.fullmatch(digest) is None:
        raise LocalReleaseProviderError()
    return f"releases/sha256/{digest[:2]}/{digest}.json"


def _tag_relative_path(tag: str) -> str:
    if type(tag) is not str or _TAG.fullmatch(tag) is None:
        raise LocalReleaseProviderError()
    return f"tags/{tag}.json"


def _safe_relative_path(value: object) -> bool:
    if type(value) is not str or not value or "\\" in value or "//" in value or "\x00" in value:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and str(path) == value
        and all(part not in {"", ".", ".."} and _PATH_PART.fullmatch(part) for part in path.parts)
    )


def _existing_root(value: str | os.PathLike[str]) -> Path:
    path = _path_argument(value)
    _require_directory(path)
    resolved = path.resolve(strict=True)
    _require_safe_ancestors(resolved)
    return resolved


def _destination_root(value: str | os.PathLike[str]) -> Path:
    if os.name != "posix":
        raise LocalReleaseProviderError()
    original = _path_argument(value)
    if original.exists():
        _require_directory(original)
    resolved = original.resolve(strict=False)
    resolved.mkdir(parents=True, mode=0o700, exist_ok=True)
    _require_safe_ancestors(resolved)
    _require_directory(resolved)
    _require_private_directory(resolved)
    return resolved


def _path_argument(value: str | os.PathLike[str]) -> Path:
    raw = os.fspath(value)
    if type(raw) is not str or not raw or "\x00" in raw:
        raise LocalReleaseProviderError()
    return Path(raw).absolute()


def _store_identity(path: Path) -> str:
    return hashlib.sha256(
        b"securecode-ai/release-store/v1\x00" + str(path.resolve(strict=False)).encode("utf-8")
    ).hexdigest()


def _require_directory(path: Path) -> None:
    state = path.lstat()
    if not stat.S_ISDIR(state.st_mode) or _is_reparse(state):
        raise LocalReleaseProviderError()


def _ensure_directory(root: Path, directory: Path) -> None:
    if directory != root and root not in directory.parents:
        raise LocalReleaseProviderError()
    current = root
    _require_directory(current)
    _require_private_directory(current)
    for part in directory.relative_to(root).parts:
        current /= part
        with suppress(FileExistsError):
            current.mkdir(mode=0o700)
        _require_directory(current)
        _require_private_directory(current)


def _ensure_directory_beneath(root_fd: int, relative_path: PurePosixPath) -> None:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = os.dup(root_fd)
    try:
        for part in relative_path.parts:
            try:
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            except FileNotFoundError:
                os.mkdir(part, 0o700, dir_fd=directory_fd)
                next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            state = os.fstat(next_fd)
            current_uid = cast(Callable[[], int], vars(os)["geteuid"])()
            if state.st_uid not in {0, current_uid} or state.st_mode & 0o077:
                os.close(next_fd)
                raise LocalReleaseProviderError()
            os.close(directory_fd)
            directory_fd = next_fd
    finally:
        os.close(directory_fd)


def _require_private_directory(path: Path) -> None:
    state = path.stat(follow_symlinks=False)
    current_uid = cast(Callable[[], int], vars(os)["geteuid"])()
    if state.st_uid not in {0, current_uid} or state.st_mode & 0o077:
        raise LocalReleaseProviderError()


def _require_safe_ancestors(path: Path) -> None:
    if os.name != "posix":
        return
    current_uid = cast(Callable[[], int], vars(os)["geteuid"])()
    for directory in (path, *path.parents):
        state = directory.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(state.st_mode)
            or state.st_uid not in {0, current_uid}
            or (state.st_mode & 0o022 and not state.st_mode & stat.S_ISVTX)
        ):
            raise LocalReleaseProviderError()


def _reject_unsafe_ancestors(root: Path, path: Path) -> None:
    if path != root and root not in path.parents:
        raise LocalReleaseProviderError()
    _require_directory(root)
    current = root
    for part in path.relative_to(root).parts[:-1]:
        current /= part
        _require_directory(current)


def _open_regular_file(path: Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    state = os.fstat(descriptor)
    if not stat.S_ISREG(state.st_mode) or _is_reparse(state):
        os.close(descriptor)
        raise LocalReleaseProviderError()
    return descriptor


def _open_regular_beneath(root: Path, relative_path: str) -> int:
    """Open a regular file through fixed no-follow directory descriptors."""

    if os.name != "posix" or not _safe_relative_path(relative_path):
        raise LocalReleaseProviderError()
    parts = PurePosixPath(relative_path).parts
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = os.open(root, directory_flags)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(parts[-1], flags, dir_fd=directory_fd)
        state = os.fstat(descriptor)
        if not stat.S_ISREG(state.st_mode):
            os.close(descriptor)
            raise LocalReleaseProviderError()
        return descriptor
    finally:
        os.close(directory_fd)


def _read_verified_file(path: Path, maximum_bytes: int) -> bytes:
    descriptor = _open_regular_file(path)
    try:
        before = os.fstat(descriptor)
        if before.st_size > maximum_bytes:
            raise LocalReleaseProviderError()
        chunks: list[bytes] = []
        total = 0
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            while chunk := stream.read(min(_CHUNK_BYTES, maximum_bytes + 1 - total)):
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum_bytes:
                    raise LocalReleaseProviderError()
            after = os.fstat(stream.fileno())
        if total != before.st_size or not _same_file_state(before, after):
            raise LocalReleaseProviderError()
        return b"".join(chunks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_digest_and_size(path: Path, digest: str, size: int) -> None:
    descriptor = _open_regular_file(path)
    try:
        before = os.fstat(descriptor)
        if (
            before.st_size != size
            or before.st_nlink != 1
            or (os.name == "posix" and before.st_mode & 0o222)
        ):
            raise LocalReleaseProviderError()
        actual = hashlib.sha256()
        total = 0
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            while chunk := stream.read(_CHUNK_BYTES):
                actual.update(chunk)
                total += len(chunk)
            after = os.fstat(stream.fileno())
        if total != size or actual.hexdigest() != digest or not _same_file_state(before, after):
            raise LocalReleaseProviderError()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _stage_bytes(directory: Path, value: bytes) -> tuple[Path, Path]:
    stage_directory = Path(tempfile.mkdtemp(prefix=".release-", dir=directory))
    temporary = stage_directory / "content.tmp"
    ready = stage_directory / "content.ready"
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(ready)
        _fsync_directory(stage_directory)
        return ready, stage_directory
    except Exception:
        temporary.unlink(missing_ok=True)
        ready.unlink(missing_ok=True)
        with suppress(OSError):
            stage_directory.rmdir()
        raise


def _link_create_if_absent(source: Path, root_fd: int, relative_path: str) -> bool:
    relative = PurePosixPath(relative_path)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    destination_fd = _open_directory_beneath(root_fd, relative.parent)
    source_fd = os.open(source.parent, directory_flags)
    try:
        try:
            os.link(
                source.name,
                relative.name,
                src_dir_fd=source_fd,
                dst_dir_fd=destination_fd,
                follow_symlinks=False,
            )
            os.chmod(relative.name, 0o400, dir_fd=destination_fd, follow_symlinks=False)
            os.fsync(destination_fd)
            return True
        except FileExistsError:
            return False
    finally:
        os.close(source_fd)
        os.close(destination_fd)


def _open_directory_beneath(root_fd: int, relative_path: PurePosixPath) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.dup(root_fd)
    try:
        for part in relative_path.parts:
            next_fd = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_fd
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _is_reparse(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(getattr(value, "st_reparse_tag", 0))


def _fsync_directory(directory: Path) -> None:
    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "LocalReleaseProviderError",
]
