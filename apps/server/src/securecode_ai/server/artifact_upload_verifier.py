"""Read-side verification for immutable locally uploaded artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from .artifact_upload import ArtifactUploadRejected
from .filesystem_paths import lexical_absolute_path

_AUTHORIZATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class LocalArtifactUploadVerifier:
    """Require an intact payload and receipt before worker artifact commit."""

    def __init__(self, root: Path, *, max_bytes: int = 16_777_216) -> None:
        if not isinstance(root, Path) or not 1 <= max_bytes <= 1_073_741_824:
            raise ValueError("artifact verifier settings are invalid")
        self._root = lexical_absolute_path(root)
        self._max_bytes = max_bytes

    def require(
        self,
        *,
        tenant_id: str,
        authorization_id: str,
        worker_id: str,
        run_id: str,
        execution_identity_hash: str,
        content_sha256: str,
        size_bytes: int,
        purpose: str,
    ) -> None:
        if type(authorization_id) is not str or _AUTHORIZATION_ID.fullmatch(authorization_id) is None:
            raise ArtifactUploadRejected()
        target = self._root / tenant_id / content_sha256[:2] / content_sha256
        _plain_chain(self._root, target)
        primary = _json(_read_regular(target / "receipt.json", 65_536))
        if primary.get("authorization_id") == authorization_id:
            receipt = primary
        else:
            authorization_directory = target / "authorizations" / authorization_id
            _plain_chain(self._root, authorization_directory)
            receipt = _json(_read_regular(authorization_directory / "receipt.json", 65_536))
        expected = {
            "authorization_id": authorization_id,
            "tenant_id": tenant_id,
            "worker_id": worker_id,
            "run_id": run_id,
            "execution_identity_hash": execution_identity_hash,
            "content_sha256": content_sha256,
            "size_bytes": size_bytes,
            "purpose": purpose,
        }
        if any(receipt.get(name) != value for name, value in expected.items()):
            raise ArtifactUploadRejected()
        digest, size = _digest(target / "payload", self._max_bytes)
        if digest != content_sha256 or size != size_bytes:
            raise ArtifactUploadRejected()


def _plain_chain(root: Path, target: Path) -> None:
    try:
        resolved_root = root.resolve(strict=True)
        if target != resolved_root and resolved_root not in target.parents:
            raise ArtifactUploadRejected()
        current = resolved_root
        _plain_directory(current)
        for part in target.relative_to(resolved_root).parts:
            current /= part
            _plain_directory(current)
    except (OSError, ValueError):
        raise ArtifactUploadRejected() from None


def _plain_directory(path: Path) -> None:
    details = path.lstat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or bool(getattr(details, "st_reparse_tag", 0))
    ):
        raise ArtifactUploadRejected()


def _read_regular(path: Path, limit: int) -> bytes:
    descriptor = _open_regular(path)
    try:
        details = os.fstat(descriptor)
        if details.st_size > limit:
            raise ArtifactUploadRejected()
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            value = stream.read(limit + 1)
        if len(value) > limit:
            raise ArtifactUploadRejected()
        return value
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _digest(path: Path, limit: int) -> tuple[str, int]:
    descriptor = _open_regular(path)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise ArtifactUploadRejected()
                digest.update(chunk)
        return digest.hexdigest(), size
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _open_regular(path: Path) -> int:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or bool(getattr(details, "st_reparse_tag", 0))
        ):
            os.close(descriptor)
            raise ArtifactUploadRejected()
        return descriptor
    except OSError:
        raise ArtifactUploadRejected() from None


def _json(value: bytes) -> dict[str, object]:
    try:
        document = json.loads(value.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ArtifactUploadRejected() from None
    if type(document) is not dict:
        raise ArtifactUploadRejected()
    return document


__all__ = ["LocalArtifactUploadVerifier"]
