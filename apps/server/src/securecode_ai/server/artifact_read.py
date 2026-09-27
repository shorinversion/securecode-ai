"""Tenant-scoped reads of committed, source-free artifact content."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from .artifact_tenant_namespace import (
    ArtifactTenantNamespaceError,
    artifact_tenant_path_component,
)
from .filesystem_paths import lexical_absolute_path
from .persistence import NotFoundError, RepositoryError
from .ports import VerifiedIdentity
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard

_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_PURPOSES: Final = frozenset(
    {"audit-report", "audit-run", "evidence-graph", "repair-report", "sarif-report"}
)
_SOURCE_FREE_CLASSES: Final = frozenset(
    {"DC0_PUBLIC", "DC1_INTERNAL_METADATA", "DC2_CONFIDENTIAL_SECURITY"}
)
_READ_ROLES: Final = frozenset({"admin", "viewer", "auditor", "approver"})
# JSON responses leave room for base64 expansion and the source-free metadata
# envelope. Binary downloads use the same bound as the upload object store.
_MAX_CONTENT_BYTES: Final = 700_000
_MAX_BINARY_CONTENT_BYTES: Final = 16_777_216
_COMMITTED_ARTIFACT_KEYS: Final = frozenset(
    {
        "authorization_id",
        "content_id",
        "content_sha256",
        "data_class",
        "purpose",
        "size_bytes",
    }
)
_EXPIRING_COMMITTED_ARTIFACT_KEYS: Final = _COMMITTED_ARTIFACT_KEYS | frozenset(
    {"expires_at"}
)


@dataclass(frozen=True, slots=True)
class CommittedArtifactContent:
    """A bounded source-free content response for one committed artifact."""

    content_id: str
    content_sha256: str
    size_bytes: int
    data_class: str
    purpose: str
    committed_at: str
    content: bytes

    def document(self) -> dict[str, object]:
        return {
            "committed_at": self.committed_at,
            "content_base64": base64.b64encode(self.content).decode("ascii"),
            "content_encoding": "base64",
            "content_id": self.content_id,
            "content_sha256": self.content_sha256,
            "data_class": self.data_class,
            "purpose": self.purpose,
            "size_bytes": self.size_bytes,
        }


class LocalCommittedArtifactReader:
    """Read only committed, non-source artifacts from the upload object store."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        root: Path,
        *,
        now: Callable[[], datetime] | None = None,
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection) or not isinstance(root, Path):
            raise TypeError("artifact reader dependencies are invalid")
        if now is not None and not callable(now):
            raise TypeError("artifact reader clock is invalid")
        if (residency_guard is None) != (residency_region is None):
            raise TypeError("artifact reader residency configuration is incomplete")
        if residency_guard is not None and not callable(
            getattr(residency_guard, "require_region", None)
        ):
            raise TypeError("artifact reader residency guard is invalid")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._root = lexical_absolute_path(root)
        self._now = now or (lambda: datetime.now(UTC))
        self._residency_guard = residency_guard
        self._residency_region = residency_region

    def require_tenant_access(self, tenant_id: str) -> None:
        """Apply residency policy before exposing artifact metadata."""

        try:
            artifact_tenant_path_component(tenant_id)
        except ArtifactTenantNamespaceError:
            raise NotFoundError() from None
        self._require_residency(tenant_id)

    def read(
        self, *, tenant_id: str, run_id: str, content_sha256: str
    ) -> dict[str, object]:
        """Read one bounded artifact as a source-free JSON document."""

        return self._read_committed(
            tenant_id=tenant_id,
            run_id=run_id,
            content_sha256=content_sha256,
            max_bytes=_MAX_CONTENT_BYTES,
        ).document()

    def read_for_principal(
        self,
        *,
        principal: VerifiedIdentity,
        run_id: str,
        content_sha256: str,
    ) -> dict[str, object]:
        """Read metadata only after checking the caller's repository grant."""

        if type(principal) is not VerifiedIdentity:
            raise NotFoundError()
        return self._read_committed(
            tenant_id=principal.tenant_id,
            run_id=run_id,
            content_sha256=content_sha256,
            max_bytes=_MAX_CONTENT_BYTES,
            principal=principal,
        ).document()

    def read_binary(
        self, *, tenant_id: str, run_id: str, content_sha256: str
    ) -> CommittedArtifactContent:
        """Read one committed artifact as verified binary content.

        The caller remains responsible for selecting a response transport. All
        authorization, lifecycle, residency, path and digest checks are shared
        with the JSON read path.
        """

        return self._read_committed(
            tenant_id=tenant_id,
            run_id=run_id,
            content_sha256=content_sha256,
            max_bytes=_MAX_BINARY_CONTENT_BYTES,
        )

    def read_binary_for_principal(
        self,
        *,
        principal: VerifiedIdentity,
        run_id: str,
        content_sha256: str,
    ) -> CommittedArtifactContent:
        """Read bytes only for a verified principal bound to the run repository."""

        if type(principal) is not VerifiedIdentity:
            raise NotFoundError()
        return self._read_committed(
            tenant_id=principal.tenant_id,
            run_id=run_id,
            content_sha256=content_sha256,
            max_bytes=_MAX_BINARY_CONTENT_BYTES,
            principal=principal,
        )

    def read_repair_patch_for_principal(
        self,
        *,
        principal: VerifiedIdentity,
        run_id: str,
        finding_id: str,
        patch_sha256: str,
    ) -> CommittedArtifactContent:
        """Read one validated source-bearing patch through its exact binding."""

        if (
            type(principal) is not VerifiedIdentity
            or type(run_id) is not str
            or _IDENTIFIER.fullmatch(run_id) is None
            or type(finding_id) is not str
            or _IDENTIFIER.fullmatch(finding_id) is None
            or type(patch_sha256) is not str
            or _SHA256.fullmatch(patch_sha256) is None
        ):
            raise NotFoundError()
        tenant_id = principal.tenant_id
        self.require_tenant_access(tenant_id)
        try:
            rows = self._connection.execute(
                """SELECT a.authorization_id, a.content_sha256, a.purpose, a.committed_at,
                          a.metadata_json, r.repository_id, r.head_sha,
                          r.execution_identity_hash, z.content_id, z.size_bytes,
                          z.data_class, z.issued_at, z.expires_at
                   FROM run_artifacts AS a
                   JOIN artifact_upload_authorizations AS z
                     ON z.tenant_id=a.tenant_id
                    AND z.authorization_id=a.authorization_id
                    AND z.run_id=a.run_id
                    AND z.content_sha256=a.content_sha256
                    AND z.purpose=a.purpose
                   JOIN audit_runs AS r
                     ON r.tenant_id=a.tenant_id
                    AND r.run_id=a.run_id
                    AND r.repository_id=z.repository_id
                    AND r.execution_identity_hash=z.execution_identity_hash
                   WHERE a.tenant_id=? AND a.run_id=?
                     AND a.purpose='repair-patch'
                     AND z.data_class='DC3_CONFIDENTIAL_SOURCE'
                     AND NOT EXISTS (
                         SELECT 1 FROM lifecycle_storage_tombstones AS t
                         WHERE t.tenant_id=a.tenant_id
                           AND t.content_sha256=a.content_sha256
                     )
                   ORDER BY a.rowid DESC
                   LIMIT 257""",
                (tenant_id, run_id),
            ).fetchall()
        except sqlite3.Error as error:
            raise RepositoryError("repair patch lookup failed") from error
        if len(rows) > 256:
            raise RepositoryError("repair patch inventory is too large")
        selected: tuple[sqlite3.Row, dict[str, object]] | None = None
        for row in rows:
            binding = _repair_patch_binding_metadata(
                row,
                tenant_id=tenant_id,
                run_id=run_id,
            )
            if (
                binding is None
                or binding.get("finding_id") != finding_id
                or binding.get("patch_sha256") != patch_sha256
            ):
                continue
            finding_row = self._connection.execute(
                """SELECT revision_sha FROM finding_occurrences
                   WHERE tenant_id=? AND run_id=? AND finding_id=?""",
                (tenant_id, run_id, finding_id),
            ).fetchone()
            if finding_row is None or finding_row["revision_sha"] != binding.get("head_sha"):
                raise RepositoryError("repair patch finding binding is invalid")
            if not _principal_can_read(
                principal,
                tenant_id=tenant_id,
                repository_id=str(row["repository_id"]),
            ):
                raise NotFoundError()
            if selected is not None:
                raise RepositoryError("repair patch binding is ambiguous")
            selected = (row, binding)
        if selected is None:
            raise NotFoundError()
        row, binding = selected
        content_sha256 = row["content_sha256"]
        size_bytes = row["size_bytes"]
        if (
            type(content_sha256) is not str
            or _SHA256.fullmatch(content_sha256) is None
            or type(size_bytes) is not int
            or not 1 <= size_bytes <= _MAX_BINARY_CONTENT_BYTES
        ):
            raise RepositoryError("repair patch metadata is invalid")
        content = _read_verified_payload(
            self._object_path(tenant_id, content_sha256) / "payload",
            root=self._root,
            expected_sha256=content_sha256,
            expected_size=size_bytes,
        )
        _validate_repair_patch_bundle(content, binding)
        return CommittedArtifactContent(
            content_id=str(row["content_id"]),
            content_sha256=content_sha256,
            size_bytes=size_bytes,
            data_class="DC3_CONFIDENTIAL_SOURCE",
            purpose="repair-patch",
            committed_at=str(row["committed_at"]),
            content=content,
        )

    def _read_committed(
        self,
        *,
        tenant_id: str,
        run_id: str,
        content_sha256: str,
        max_bytes: int,
        principal: VerifiedIdentity | None = None,
    ) -> CommittedArtifactContent:
        self.require_tenant_access(tenant_id)
        if (
            principal is not None
            and (
                type(principal) is not VerifiedIdentity
                or principal.tenant_id != tenant_id
            )
        ):
            raise NotFoundError()
        if (
            type(run_id) is not str
            or not run_id
            or type(content_sha256) is not str
            or _SHA256.fullmatch(content_sha256) is None
            or type(max_bytes) is not int
            or max_bytes < _MAX_CONTENT_BYTES
            or max_bytes > _MAX_BINARY_CONTENT_BYTES
        ):
            raise NotFoundError()
        try:
            current = _utc(self._now())
        except (TypeError, ValueError):
            raise RepositoryError("artifact content clock is invalid") from None
        try:
            rows = self._connection.execute(
                """SELECT a.authorization_id, a.content_sha256, a.purpose, a.committed_at,
                          r.repository_id,
                          z.content_id, z.size_bytes, z.data_class,
                          z.issued_at, z.expires_at, a.metadata_json
                   FROM run_artifacts AS a
                   JOIN artifact_upload_authorizations AS z
                     ON z.tenant_id=a.tenant_id
                    AND z.authorization_id=a.authorization_id
                    AND z.run_id=a.run_id
                    AND z.content_sha256=a.content_sha256
                    AND z.purpose=a.purpose
                   JOIN audit_runs AS r
                     ON r.tenant_id=a.tenant_id
                    AND r.run_id=a.run_id
                    AND r.repository_id=z.repository_id
                    AND r.execution_identity_hash=z.execution_identity_hash
                   WHERE a.tenant_id=? AND a.run_id=?
                     AND a.content_sha256=?
                     AND a.purpose IN ('audit-report', 'audit-run',
                                       'evidence-graph', 'repair-report', 'sarif-report')
                     AND z.data_class IN ('DC0_PUBLIC', 'DC1_INTERNAL_METADATA',
                                          'DC2_CONFIDENTIAL_SECURITY')
                     AND NOT EXISTS (
                         SELECT 1 FROM lifecycle_storage_tombstones AS t
                         WHERE t.tenant_id=a.tenant_id
                           AND t.content_sha256=a.content_sha256
                     )""",
                (tenant_id, run_id, content_sha256),
            ).fetchmany(2)
        except sqlite3.Error as error:
            raise RepositoryError("artifact content lookup failed") from error
        if not rows:
            raise NotFoundError()
        if len(rows) != 1:
            raise NotFoundError()
        row = rows[0]
        authorization_id = row["authorization_id"]
        repository_id = row["repository_id"]
        content_id = row["content_id"]
        size_bytes = row["size_bytes"]
        data_class = row["data_class"]
        purpose = row["purpose"]
        committed_at = row["committed_at"]
        issued_at = row["issued_at"]
        expires_at = row["expires_at"]
        metadata_json = row["metadata_json"]
        if (
            type(authorization_id) is not str
            or _IDENTIFIER.fullmatch(authorization_id) is None
            or type(repository_id) is not str
            or _IDENTIFIER.fullmatch(repository_id) is None
            or type(content_id) is not str
            or _IDENTIFIER.fullmatch(content_id) is None
            or type(size_bytes) is not int
            or not 1 <= size_bytes <= max_bytes
            or type(data_class) is not str
            or data_class not in _SOURCE_FREE_CLASSES
            or type(purpose) is not str
            or purpose not in _PURPOSES
            or type(committed_at) is not str
            or not committed_at
            or type(issued_at) is not str
            or not issued_at
            or type(expires_at) is not str
            or not expires_at
            or type(metadata_json) is not str
            or not metadata_json
        ):
            raise RepositoryError("artifact content metadata is invalid")
        if principal is not None and not _principal_can_read(
            principal,
            tenant_id=tenant_id,
            repository_id=repository_id,
        ):
            raise NotFoundError()
        try:
            issued = _utc(datetime.fromisoformat(issued_at))
            committed = _utc(datetime.fromisoformat(committed_at))
            expires = _utc(datetime.fromisoformat(expires_at))
        except (TypeError, ValueError):
            raise RepositoryError("artifact content metadata is invalid") from None
        # The upload authorization is a short lived capability.  It must
        # bound the time at which the object was committed, but it must not
        # turn into the retention deadline for an already committed artifact.
        # The artifact's own optional expires_at metadata is checked below.
        if not issued <= committed < expires:
            raise RepositoryError("artifact content metadata is invalid")
        artifact_expires = _committed_artifact_metadata(
            metadata_json,
            authorization_id=authorization_id,
            content_id=content_id,
            content_sha256=content_sha256,
            data_class=data_class,
            purpose=purpose,
            size_bytes=size_bytes,
        )
        if artifact_expires is not None:
            if artifact_expires <= committed:
                raise RepositoryError("artifact content metadata is invalid")
            if current >= artifact_expires:
                raise NotFoundError()
        target = self._object_path(tenant_id, content_sha256)
        try:
            content = _read_verified_payload(
                target / "payload",
                root=self._root,
                expected_sha256=content_sha256,
                expected_size=size_bytes,
            )
        except (OSError, ValueError, ArtifactReadError):
            raise RepositoryError("artifact content is unavailable") from None
        return CommittedArtifactContent(
            content_id=content_id,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
            data_class=data_class,
            purpose=purpose,
            committed_at=committed_at,
            content=content,
        )

    def _require_residency(self, tenant_id: str) -> None:
        guard = self._residency_guard
        if guard is None:
            return
        region = self._residency_region
        if type(region) is not str or not region:
            raise RepositoryError("artifact reader residency configuration is invalid")
        try:
            decision = guard.require_region(tenant_id=tenant_id, region=region)
        except ResidencyConflict:
            raise NotFoundError() from None
        except Exception:
            raise RepositoryError("artifact reader residency check failed") from None
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != tenant_id
            or decision.source_region != region
            or decision.destination_region != region
            or not decision.same_region
        ):
            raise RepositoryError("artifact reader residency decision is invalid")

    def _object_path(self, tenant_id: str, content_sha256: str) -> Path:
        try:
            tenant_component = artifact_tenant_path_component(tenant_id)
        except ArtifactTenantNamespaceError:
            raise ArtifactReadError() from None
        target = self._root / tenant_component / content_sha256[:2] / content_sha256
        try:
            target.relative_to(self._root)
        except ValueError:
            raise ArtifactReadError() from None
        return target


class ArtifactReadError(Exception):
    """The on-disk artifact object is missing, unsafe, or corrupt."""


def _principal_can_read(
    principal: VerifiedIdentity,
    *,
    tenant_id: str,
    repository_id: str,
) -> bool:
    if (
        type(principal) is not VerifiedIdentity
        or principal.tenant_id != tenant_id
        or principal.workload
        or not principal.roles
        or not principal.roles.issubset(_READ_ROLES)
    ):
        return False
    if "admin" in principal.roles:
        return True
    return repository_id in principal.repository_ids


def _utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise ValueError("artifact timestamp is not UTC")
    return value.astimezone(UTC)


def _committed_artifact_metadata(
    metadata_json: str,
    *,
    authorization_id: str,
    content_id: str,
    content_sha256: str,
    data_class: str,
    purpose: str,
    size_bytes: int,
) -> datetime | None:
    """Reject a read when durable commit metadata drifts from authorization."""

    try:
        document = json.loads(
            metadata_json,
            object_pairs_hook=_unique_object_pairs,
        )
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise RepositoryError("artifact content metadata is invalid") from None
    if type(document) is not dict:
        raise RepositoryError("artifact content metadata is invalid")
    keys = frozenset(document)
    if keys not in {_COMMITTED_ARTIFACT_KEYS, _EXPIRING_COMMITTED_ARTIFACT_KEYS}:
        raise RepositoryError("artifact content metadata is invalid")
    expected = {
        "authorization_id": authorization_id,
        "content_id": content_id,
        "content_sha256": content_sha256,
        "data_class": data_class,
        "purpose": purpose,
        "size_bytes": size_bytes,
    }
    if document != expected:
        expires_at = document.get("expires_at")
        if keys != _EXPIRING_COMMITTED_ARTIFACT_KEYS:
            raise RepositoryError("artifact content metadata is invalid")
        if type(expires_at) is not str or not expires_at:
            raise RepositoryError("artifact content metadata is invalid")
        try:
            expiry = _utc(datetime.fromisoformat(expires_at))
        except (TypeError, ValueError):
            raise RepositoryError("artifact content metadata is invalid") from None
        if document != {**expected, "expires_at": expires_at}:
            raise RepositoryError("artifact content metadata is invalid")
        return expiry
    if keys != _COMMITTED_ARTIFACT_KEYS:
        raise RepositoryError("artifact content metadata is invalid")
    return None


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate artifact metadata field")
        value[key] = item
    return value


def _read_verified_payload(
    path: Path,
    *,
    root: Path,
    expected_sha256: str,
    expected_size: int,
) -> bytes:
    _plain_chain(root, path.parent)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            raise ArtifactReadError()
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, min(65_536, expected_size + 1 - size)):
            size += len(chunk)
            if size > expected_size:
                raise ArtifactReadError()
            digest.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or bool(getattr(current, "st_reparse_tag", 0))
            or bool(getattr(current, "st_file_attributes", 0) & 0x400)
            or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or size != expected_size
            or digest.hexdigest() != expected_sha256
        ):
            raise ArtifactReadError()
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _repair_patch_binding_metadata(
    row: sqlite3.Row,
    *,
    tenant_id: str,
    run_id: str,
) -> dict[str, object] | None:
    try:
        document = json.loads(
            row["metadata_json"].encode("utf-8").decode("utf-8"),
            object_pairs_hook=_unique_object_pairs,
        )
    except (AttributeError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        raise RepositoryError("repair patch metadata is invalid") from None
    if type(document) is not dict:
        raise RepositoryError("repair patch metadata is invalid")
    binding = document.get("binding")
    expected_keys = _COMMITTED_ARTIFACT_KEYS | frozenset({"binding"})
    if set(document) not in {expected_keys, expected_keys | frozenset({"expires_at"})}:
        raise RepositoryError("repair patch metadata is invalid")
    if (
        document.get("authorization_id") != row["authorization_id"]
        or document.get("content_id") != row["content_id"]
        or document.get("content_sha256") != row["content_sha256"]
        or document.get("purpose") != "repair-patch"
        or document.get("size_bytes") != row["size_bytes"]
        or document.get("data_class") != "DC3_CONFIDENTIAL_SOURCE"
        or not isinstance(binding, dict)
    ):
        raise RepositoryError("repair patch metadata is invalid")
    required = {
        "execution_identity_hash",
        "finding_id",
        "head_sha",
        "manifest_sha256",
        "patch_size_bytes",
        "patch_sha256",
        "patch_status_sha256",
        "repository_id",
        "run_id",
        "tenant_id",
        "validation_result_sha256",
    }
    if set(binding) != required:
        raise RepositoryError("repair patch metadata is invalid")
    if (
        binding.get("tenant_id") != tenant_id
        or binding.get("run_id") != run_id
        or binding.get("repository_id") != row["repository_id"]
        or binding.get("head_sha") != row["head_sha"]
        or binding.get("execution_identity_hash") != row["execution_identity_hash"]
    ):
        raise RepositoryError("repair patch metadata is invalid")
    for name in ("tenant_id", "repository_id", "run_id", "finding_id"):
        if _IDENTIFIER.fullmatch(str(binding.get(name))) is None:
            raise RepositoryError("repair patch metadata is invalid")
    if re.fullmatch(r"[0-9a-f]{40}", str(binding.get("head_sha"))) is None:
        raise RepositoryError("repair patch metadata is invalid")
    for name in (
        "execution_identity_hash",
        "manifest_sha256",
        "patch_sha256",
        "patch_status_sha256",
        "validation_result_sha256",
    ):
        if _SHA256.fullmatch(str(binding.get(name))) is None:
            raise RepositoryError("repair patch metadata is invalid")
    patch_size = binding.get("patch_size_bytes")
    if type(patch_size) is not int or not 1 <= patch_size <= 131_072:
        raise RepositoryError("repair patch metadata is invalid")
    if "expires_at" in document:
        expiry = document.get("expires_at")
        if type(expiry) is not str or not expiry:
            raise RepositoryError("repair patch metadata is invalid")
        try:
            if _utc(datetime.fromisoformat(expiry)) <= _utc(datetime.fromisoformat(str(row["committed_at"]))):
                raise RepositoryError("repair patch metadata is invalid")
            if _utc(datetime.now(UTC)) >= _utc(datetime.fromisoformat(expiry)):
                raise NotFoundError()
        except (TypeError, ValueError):
            raise RepositoryError("repair patch metadata is invalid") from None
    return dict(binding)


def _validate_repair_patch_bundle(
    content: bytes,
    binding: Mapping[str, object],
) -> None:
    try:
        document = json.loads(
            content.decode("ascii"),
            object_pairs_hook=_unique_object_pairs,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise RepositoryError("repair patch content is invalid") from None
    if (
        type(document) is not dict
        or set(document) != {"binding", "manifest_base64", "patch_base64", "schema_version"}
        or document.get("schema_version") != "securecode.repair-patch.v1"
        or document.get("binding") != dict(binding)
        or type(document.get("manifest_base64")) is not str
        or type(document.get("patch_base64")) is not str
    ):
        raise RepositoryError("repair patch content is invalid")
    try:
        manifest = base64.b64decode(document["manifest_base64"], validate=True)
        patch = base64.b64decode(document["patch_base64"], validate=True)
    except (TypeError, ValueError):
        raise RepositoryError("repair patch content is invalid") from None
    if (
        not patch
        or len(patch) != binding["patch_size_bytes"]
        or hashlib.sha256(patch).hexdigest() != binding["patch_sha256"]
        or not manifest
        or hashlib.sha256(manifest).hexdigest() != binding["manifest_sha256"]
    ):
        raise RepositoryError("repair patch content is invalid")
def _plain_chain(root: Path, target: Path) -> None:
    resolved_root = root.absolute()
    current = resolved_root
    try:
        _plain_directory(current)
        for part in target.relative_to(resolved_root).parts:
            current /= part
            _plain_directory(current)
    except (OSError, ValueError):
        raise ArtifactReadError() from None


def _plain_directory(path: Path) -> None:
    details = path.lstat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or bool(getattr(details, "st_reparse_tag", 0))
        or bool(getattr(details, "st_file_attributes", 0) & 0x400)
    ):
        raise ArtifactReadError()


__all__ = ["CommittedArtifactContent", "LocalCommittedArtifactReader"]
