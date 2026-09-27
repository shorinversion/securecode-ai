"""Retention planning and tombstoning for the private backup artifact store."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from .artifacts import ArtifactMetadata
from .backup_repository import (
    BackupConflict,
    BackupRecord,
    deserialize_backup_record,
    validate_backup_record,
)
from .backup_service import manifest_sha256
from .data_lifecycle_models import (
    DeletionRequest,
    LifecycleConflict,
    RetentionProfile,
    StorageExecutor,
    require_identifier,
    require_sha256,
)
from .filesystem_paths import lexical_absolute_path
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard

BACKUP_RETENTION_DELETION_PREFIX: Final = "backup-retention-"
BACKUP_RETENTION_PURPOSES: Final = frozenset({"backup-record", "backup-snapshot"})
BACKUP_TOMBSTONE_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS lifecycle_storage_tombstones (
        tenant_id TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        deletion_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL,
        tombstoned_at TEXT NOT NULL,
        binding_sha256 TEXT NOT NULL,
        PRIMARY KEY (tenant_id, content_sha256),
        UNIQUE (tenant_id, deletion_id)
    )""",
)

_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_SHARD: Final = re.compile(r"[0-9a-f]{2}\Z")
_MAX_METADATA_BYTES: Final = 65_536
_MAX_STORE_ENTRIES: Final = 10_000
_BACKUP_RETENTION_SCHEMA_VERSION: Final = 1


@dataclass(frozen=True, slots=True)
class BackupRetentionCandidate:
    """Source-free lifecycle request created for one expired backup object."""

    deletion_id: str
    tenant_id: str
    backup_id: str
    repository_id: str
    content_sha256: str
    execution_identity_hash: str
    purpose: str
    profile_sha256: str
    eligible_at: str
    requested_at: str


@dataclass(frozen=True, slots=True)
class _BackupBinding:
    backup: BackupRecord
    repository_id: str
    execution_identity_hash: str


@dataclass(frozen=True, slots=True)
class _TombstoneBinding:
    deletion_id: str
    tenant_id: str
    repository_id: str
    content_sha256: str
    execution_identity_hash: str
    executed: bool = False


class BackupLifecycleAdapter:
    """Bridge backup store objects into the existing lifecycle deletion port.

    The adapter deliberately keeps backup control rows immutable. Planning adds
    ordinary unapproved lifecycle requests, so the existing two-person approval
    and scheduler path remains authoritative. Execution removes only an object
    whose store metadata, backup record, repository scope and identity hash all
    agree with the lifecycle request.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        root: Path,
        *,
        requested_by: str = "backup-retention-planner",
        clock: Callable[[], datetime] | None = None,
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
        fallback: StorageExecutor | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        if not isinstance(root, Path):
            raise TypeError("backup root must be a path")
        require_identifier(requested_by, "requested_by")
        if (residency_guard is None) != (residency_region is None):
            raise TypeError("backup lifecycle residency configuration is incomplete")
        if residency_guard is not None and not callable(
            getattr(residency_guard, "require_region", None)
        ):
            raise TypeError("backup lifecycle residency guard is invalid")
        if fallback is not None and not callable(
            getattr(fallback, "execute_tombstone", None)
        ):
            raise TypeError("backup lifecycle fallback is invalid")
        self._db = connection
        self._root = lexical_absolute_path(root)
        _require_directory(self._root)
        self._requested_by = requested_by
        self._clock = clock or (lambda: datetime.now(UTC))
        self._residency_guard = residency_guard
        self._residency_region = residency_region
        self._fallback = fallback
        self._initialize_schema()

    def plan_once(
        self,
        *,
        profile: RetentionProfile,
        max_items: int = 32,
    ) -> tuple[BackupRetentionCandidate, ...]:
        """Create bounded, unapproved lifecycle requests for expired objects."""

        if type(profile) is not RetentionProfile:
            raise TypeError("profile must be a RetentionProfile")
        if type(max_items) is not int or not 1 <= max_items <= 256:
            raise ValueError("backup retention batch size is invalid")
        self._require_residency(profile.tenant_id)
        now = _utc(self._clock())
        profile_sha256 = _profile_hash(profile)
        candidates: list[BackupRetentionCandidate] = []
        for metadata, path in self._metadata_files(profile.tenant_id):
            if metadata.purpose not in BACKUP_RETENTION_PURPOSES:
                raise LifecycleConflict("backup retention object purpose is invalid")
            binding = self._binding_for_metadata(profile.tenant_id, metadata)
            # Backup executors stamp the retention deadline on each object.
            # Do not silently replace that explicit policy with the generic
            # artifact period, and reject legacy records without a deadline.
            if metadata.expires_at is None:
                raise LifecycleConflict("backup retention expiration is unavailable")
            eligible_at = metadata.expires_at
            if eligible_at > now:
                continue
            if len(candidates) >= max_items:
                break
            self._verify_payload(path, metadata)
            candidate = self._candidate(
                profile=profile,
                metadata=metadata,
                binding=binding,
                profile_sha256=profile_sha256,
                eligible_at=eligible_at,
                requested_at=now,
            )
            if self._insert_request(candidate, now=now):
                candidates.append(candidate)
        return tuple(candidates)

    def execute_tombstone(
        self,
        *,
        tenant_id: str,
        content_sha256: str,
        deletion_id: str,
        repository_id: str,
        identity_hash: str,
    ) -> None:
        """Apply one approved backup deletion, or delegate normal artifacts."""

        require_identifier(tenant_id, "tenant_id")
        require_sha256(content_sha256, "content_sha256")
        require_identifier(deletion_id, "deletion_id")
        require_identifier(repository_id, "repository_id")
        require_sha256(identity_hash, "identity_hash")
        self._require_residency(tenant_id)
        binding = self._deletion_binding(
            tenant_id=tenant_id,
            content_sha256=content_sha256,
            deletion_id=deletion_id,
            repository_id=repository_id,
            identity_hash=identity_hash,
        )
        if binding is None:
            if deletion_id.startswith(BACKUP_RETENTION_DELETION_PREFIX):
                raise LifecycleConflict("backup deletion binding is unavailable")
            if self._object_present(tenant_id, content_sha256):
                raise LifecycleConflict("backup deletion binding is unavailable")
            self._delegate(
                tenant_id=tenant_id,
                content_sha256=content_sha256,
                deletion_id=deletion_id,
                repository_id=repository_id,
                identity_hash=identity_hash,
            )
            return
        if not binding.deletion_id.startswith(BACKUP_RETENTION_DELETION_PREFIX):
            if self._object_present(tenant_id, content_sha256):
                raise LifecycleConflict("backup deletion binding is unavailable")
            self._delegate(
                tenant_id=tenant_id,
                content_sha256=content_sha256,
                deletion_id=deletion_id,
                repository_id=repository_id,
                identity_hash=identity_hash,
            )
            return
        marker_path = self._marker_path(tenant_id, content_sha256)
        stored = self._stored_tombstone(tenant_id, content_sha256)
        marker = self._read_marker(marker_path) if marker_path.exists() else None
        if binding.executed and stored is None:
            raise LifecycleConflict("completed backup tombstone is unavailable")
        if stored is not None:
            self._require_exact(stored, binding)
            if marker is None:
                raise LifecycleConflict("backup tombstone marker is unavailable")
            self._require_exact(marker, binding)
            self._require_object_absent(tenant_id, content_sha256)
            return
        if marker is not None:
            self._require_exact(marker, binding)
        else:
            metadata, path = self._metadata_for_content(tenant_id, content_sha256)
            backup_binding = self._binding_for_metadata(tenant_id, metadata)
            if (
                metadata.repository_id != binding.repository_id
                or metadata.execution_identity_hash != binding.execution_identity_hash
                or backup_binding.repository_id != binding.repository_id
                or backup_binding.execution_identity_hash != binding.execution_identity_hash
            ):
                raise LifecycleConflict("backup tombstone scope conflicts")
            self._verify_payload(path, metadata)
            marker = self._new_tombstone(binding)
            self._write_marker(marker_path, marker)
        self._remove_object(tenant_id, content_sha256)
        self._insert_tombstone(marker)

    def _delegate(
        self,
        *,
        tenant_id: str,
        content_sha256: str,
        deletion_id: str,
        repository_id: str,
        identity_hash: str,
    ) -> None:
        if self._fallback is None:
            raise LifecycleConflict("backup lifecycle storage executor is unavailable")
        try:
            self._fallback.execute_tombstone(
                tenant_id=tenant_id,
                content_sha256=content_sha256,
                deletion_id=deletion_id,
                repository_id=repository_id,
                identity_hash=identity_hash,
            )
        except LifecycleConflict:
            raise
        except Exception as error:
            raise LifecycleConflict("artifact tombstone execution failed") from error

    def _candidate(
        self,
        *,
        profile: RetentionProfile,
        metadata: ArtifactMetadata,
        binding: _BackupBinding,
        profile_sha256: str,
        eligible_at: datetime,
        requested_at: datetime,
    ) -> BackupRetentionCandidate:
        deletion_id = _deletion_id(
            tenant_id=profile.tenant_id,
            content_sha256=metadata.content_sha256,
            identity_hash=binding.execution_identity_hash,
            purpose=metadata.purpose,
        )
        return BackupRetentionCandidate(
            deletion_id=deletion_id,
            tenant_id=profile.tenant_id,
            backup_id=metadata.run_id,
            repository_id=binding.repository_id,
            content_sha256=metadata.content_sha256,
            execution_identity_hash=binding.execution_identity_hash,
            purpose=metadata.purpose,
            profile_sha256=profile_sha256,
            eligible_at=eligible_at.isoformat(),
            requested_at=requested_at.isoformat(),
        )

    def _insert_request(
        self,
        candidate: BackupRetentionCandidate,
        *,
        now: datetime,
    ) -> bool:
        request = DeletionRequest(
            deletion_id=candidate.deletion_id,
            tenant_id=candidate.tenant_id,
            content_sha256=candidate.content_sha256,
            data_class="artifact",
            identity_hash=candidate.execution_identity_hash,
            requested_by=self._requested_by,
            version=1,
        )
        idempotency_key = f"{BACKUP_RETENTION_DELETION_PREFIX}{candidate.content_sha256}"
        request_sha256 = _deletion_request_hash(request)
        cursor = self._db.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            # Re-check placement after the filesystem scan and while the
            # lifecycle rows are locked.  A profile update during planning
            # must not leave an approved request for a denied tenant.
            self._require_residency(candidate.tenant_id)
            existing = cursor.execute(
                """SELECT deletion_id, content_sha256, data_class,
                                  identity_hash, requested_by, version,
                                  approved_by, executed, legal_hold
                           FROM lifecycle_deletions
                          WHERE tenant_id=? AND content_sha256=?""",
                (candidate.tenant_id, candidate.content_sha256),
            ).fetchall()
            if existing:
                if len(existing) != 1:
                    raise LifecycleConflict("backup retention target is ambiguous")
                row = existing[0]
                if (
                    row[0] != candidate.deletion_id
                    or row[1] != candidate.content_sha256
                    or row[2] != "artifact"
                    or row[3] != candidate.execution_identity_hash
                ):
                    raise LifecycleConflict("backup retention target conflicts")
                self._validate_scope(cursor, candidate)
                self._db.commit()
                return False
            planned = cursor.execute(
                """SELECT deletion_id, repository_id, execution_identity_hash,
                                  profile_sha256
                           FROM lifecycle_retention_plans
                          WHERE tenant_id=? AND content_sha256=?""",
                (candidate.tenant_id, candidate.content_sha256),
            ).fetchone()
            if planned is not None:
                if (
                    planned[0] != candidate.deletion_id
                    or planned[1] != candidate.repository_id
                    or planned[2] != candidate.execution_identity_hash
                ):
                    raise LifecycleConflict("backup retention plan conflicts")
                self._db.commit()
                return False
            cursor.execute(
                """INSERT INTO lifecycle_deletions (
                       deletion_id, tenant_id, content_sha256, data_class,
                       identity_hash, requested_by, version, approved_by,
                       executed, legal_hold, created_at
                   ) VALUES (?, ?, ?, 'artifact', ?, ?, 1, NULL, 0, 0, ?)""",
                (
                    request.deletion_id,
                    request.tenant_id,
                    request.content_sha256,
                    request.identity_hash,
                    request.requested_by,
                    now.isoformat(),
                ),
            )
            cursor.execute(
                """INSERT INTO lifecycle_repository_scopes (
                       deletion_id, tenant_id, repository_id
                   ) VALUES (?, ?, ?)""",
                (
                    candidate.deletion_id,
                    candidate.tenant_id,
                    candidate.repository_id,
                ),
            )
            cursor.execute(
                """INSERT INTO lifecycle_retention_plans (
                       tenant_id, content_sha256, deletion_id, repository_id,
                       execution_identity_hash, profile_sha256, eligible_at,
                       requested_at, schema_version
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    candidate.tenant_id,
                    candidate.content_sha256,
                    candidate.deletion_id,
                    candidate.repository_id,
                    candidate.execution_identity_hash,
                    candidate.profile_sha256,
                    candidate.eligible_at,
                    candidate.requested_at,
                    _BACKUP_RETENTION_SCHEMA_VERSION,
                ),
            )
            cursor.execute(
                """INSERT INTO lifecycle_idempotency (
                       tenant_id, idempotency_key, operation, request_sha256,
                       deletion_id, resulting_version
                   ) VALUES (?, ?, 'request', ?, ?, 1)""",
                (
                    candidate.tenant_id,
                    idempotency_key,
                    request_sha256,
                    candidate.deletion_id,
                ),
            )
            self._db.commit()
            return True
        except sqlite3.IntegrityError as error:
            self._db.rollback()
            raise LifecycleConflict("backup retention request conflicts") from error
        except Exception:
            self._db.rollback()
            raise
        finally:
            cursor.close()

    @staticmethod
    def _validate_scope(cursor: sqlite3.Cursor, candidate: BackupRetentionCandidate) -> None:
        row = cursor.execute(
            """SELECT repository_id FROM lifecycle_repository_scopes
                      WHERE tenant_id=? AND deletion_id=?""",
            (candidate.tenant_id, candidate.deletion_id),
        ).fetchone()
        if row is None or row[0] != candidate.repository_id:
            raise LifecycleConflict("backup retention scope is unavailable")

    def _metadata_files(
        self, tenant_id: str
    ) -> tuple[tuple[ArtifactMetadata, Path], ...]:
        namespace = _tenant_namespace(tenant_id)
        directory = self._root / namespace
        if not directory.exists():
            return ()
        _require_directory(directory)
        values: list[tuple[ArtifactMetadata, Path]] = []
        seen = 0
        try:
            paths = tuple(directory.rglob("*.json"))
        except OSError as error:
            raise LifecycleConflict("backup retention store is unavailable") from error
        for path in paths:
            seen += 1
            if seen > _MAX_STORE_ENTRIES:
                raise LifecycleConflict("backup retention store exceeds its limit")
            relative = path.relative_to(directory)
            if (
                len(relative.parts) != 2
                or _SHARD.fullmatch(relative.parts[0]) is None
                or _SHA256.fullmatch(relative.stem) is None
                or relative.name != f"{relative.stem}.json"
            ):
                raise LifecycleConflict("backup retention metadata path is invalid")
            _require_directory(directory / relative.parts[0])
            metadata = _read_metadata(path)
            if metadata.tenant_id != namespace or metadata.content_sha256 != relative.stem:
                raise LifecycleConflict("backup retention metadata scope is invalid")
            values.append((metadata, path))
        return tuple(sorted(values, key=lambda item: item[0].content_sha256))

    def _metadata_for_content(
        self, tenant_id: str, content_sha256: str
    ) -> tuple[ArtifactMetadata, Path]:
        namespace = _tenant_namespace(tenant_id)
        _require_directory(self._root / namespace)
        _require_directory(self._root / namespace / content_sha256[:2])
        path = self._root / namespace / content_sha256[:2] / f"{content_sha256}.json"
        if not path.exists() or path.is_symlink():
            raise LifecycleConflict("backup retention object is unavailable")
        metadata = _read_metadata(path)
        if metadata.tenant_id != namespace or metadata.content_sha256 != content_sha256:
            raise LifecycleConflict("backup retention metadata scope is invalid")
        return metadata, path

    def _object_present(self, tenant_id: str, content_sha256: str) -> bool:
        namespace = _tenant_namespace(tenant_id)
        namespace_path = self._root / namespace
        if not namespace_path.exists():
            return False
        _require_directory(namespace_path)
        shard = namespace_path / content_sha256[:2]
        if not shard.exists():
            return False
        _require_directory(shard)
        payload = shard / content_sha256
        metadata = payload.with_suffix(".json")
        return any(path.exists() or path.is_symlink() for path in (payload, metadata))

    def _binding_for_metadata(
        self, tenant_id: str, metadata: ArtifactMetadata
    ) -> _BackupBinding:
        if (
            metadata.purpose not in BACKUP_RETENTION_PURPOSES
            or metadata.content_class != "DC2_CONFIDENTIAL_SECURITY"
        ):
            raise LifecycleConflict("backup retention binding is invalid")
        row = self._db.execute(
            """SELECT b.body_json, s.repository_id
                 FROM backups AS b
                 JOIN backup_repository_scopes AS s
                   ON s.tenant_id=b.tenant_id AND s.backup_id=b.backup_id
                WHERE b.tenant_id=? AND b.backup_id=?""",
            (tenant_id, metadata.run_id),
        ).fetchone()
        if row is None or type(row[0]) is not str or type(row[1]) is not str:
            raise LifecycleConflict("backup retention binding is unavailable")
        try:
            backup = deserialize_backup_record(row[0])
            validate_backup_record(backup)
        except (BackupConflict, TypeError, ValueError):
            raise LifecycleConflict("backup retention binding is invalid") from None
        if (
            backup.tenant_id != tenant_id
            or backup.backup_id != metadata.run_id
            or backup.state not in {"BACKED_UP", "RESTORED"}
            or backup.completed_at is None
            or type(row[1]) is not str
            or not row[1]
        ):
            raise LifecycleConflict("backup retention binding is invalid")
        identity_hash = _record_identity(backup)
        if (
            metadata.repository_id != row[1]
            or metadata.execution_identity_hash != identity_hash
        ):
            raise LifecycleConflict("backup retention binding conflicts")
        if metadata.purpose == "backup-record":
            path = self._object_path(tenant_id, metadata.content_sha256)
            payload = self._read_payload(path, metadata)
            try:
                stored = deserialize_backup_record(payload.decode("utf-8"))
                validate_backup_record(stored)
            except (BackupConflict, UnicodeError, TypeError, ValueError):
                raise LifecycleConflict("backup record artifact is invalid") from None
            if (
                stored.tenant_id != tenant_id
                or stored.backup_id != metadata.run_id
                or stored.state not in {"BACKED_UP", "RESTORED"}
                or stored.completed_at is None
                or _record_identity(stored) != identity_hash
                or metadata.created_at
                != datetime.fromtimestamp(stored.completed_at, tz=UTC)
                or metadata.expires_at
                != datetime.fromtimestamp(stored.completed_at, tz=UTC)
                + timedelta(days=90)
            ):
                raise LifecycleConflict("backup record artifact conflicts")
        elif (
            metadata.created_at < datetime.fromtimestamp(backup.created_at, tz=UTC)
            or metadata.expires_at is None
            or metadata.expires_at != metadata.created_at + timedelta(days=90)
        ):
            raise LifecycleConflict("backup snapshot retention metadata conflicts")
        return _BackupBinding(
            backup=backup,
            repository_id=row[1],
            execution_identity_hash=identity_hash,
        )

    def _deletion_binding(
        self,
        *,
        tenant_id: str,
        content_sha256: str,
        deletion_id: str,
        repository_id: str,
        identity_hash: str,
    ) -> _TombstoneBinding | None:
        row = self._db.execute(
            """SELECT d.deletion_id, d.tenant_id, d.content_sha256,
                      d.data_class, d.identity_hash, s.repository_id,
                      d.approved_by, d.executed, d.legal_hold
                 FROM lifecycle_deletions AS d
                 JOIN lifecycle_repository_scopes AS s
                   ON s.tenant_id=d.tenant_id AND s.deletion_id=d.deletion_id
                WHERE d.tenant_id=? AND d.deletion_id=?
                  AND d.content_sha256=? AND d.identity_hash=?
                  AND s.repository_id=?""",
            (tenant_id, deletion_id, content_sha256, identity_hash, repository_id),
        ).fetchall()
        if not row:
            return None
        if len(row) != 1:
            raise LifecycleConflict("backup deletion binding is ambiguous")
        value = row[0]
        if value[3] != "artifact":
            return None
        approved_by = value[6]
        legal_hold = value[8]
        if type(approved_by) is not str or not approved_by:
            raise LifecycleConflict("backup deletion binding is not executable")
        if type(legal_hold) is not int or legal_hold not in (0, 1):
            raise LifecycleConflict("backup deletion binding is invalid")
        if legal_hold:
            raise LifecycleConflict("backup deletion binding is not executable")
        executed = value[7]
        if type(executed) is not int or executed not in (0, 1):
            raise LifecycleConflict("backup deletion binding is invalid")
        require_identifier(value[0], "deletion_id")
        require_identifier(value[1], "tenant_id")
        require_sha256(value[2], "content_sha256")
        require_sha256(value[4], "identity_hash")
        require_identifier(value[5], "repository_id")
        return _TombstoneBinding(
            deletion_id=value[0],
            tenant_id=value[1],
            repository_id=value[5],
            content_sha256=value[2],
            execution_identity_hash=value[4],
            executed=bool(executed),
        )

    def _initialize_schema(self) -> None:
        try:
            for statement in BACKUP_TOMBSTONE_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _require_residency(self, tenant_id: str) -> None:
        guard = self._residency_guard
        if guard is None:
            return
        region = self._residency_region
        if region is None:
            raise LifecycleConflict("backup lifecycle residency is incomplete")
        try:
            decision = guard.require_region(tenant_id=tenant_id, region=region)
        except ResidencyConflict as error:
            raise LifecycleConflict("backup lifecycle residency denied") from error
        except Exception as error:
            raise LifecycleConflict("backup lifecycle residency check failed") from error
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != tenant_id
            or decision.source_region != region
            or decision.destination_region != region
            or not decision.same_region
        ):
            raise LifecycleConflict("backup lifecycle residency decision is invalid")

    def _marker_path(self, tenant_id: str, content_sha256: str) -> Path:
        tombstone_root = self._root / ".tombstones"
        if tombstone_root.exists():
            _require_directory(tombstone_root)
        else:
            try:
                tombstone_root.mkdir(mode=0o700)
            except OSError as error:
                raise LifecycleConflict("backup tombstone directory is unavailable") from error
        markers = tombstone_root / _tenant_namespace(tenant_id)
        try:
            markers.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise LifecycleConflict("backup tombstone directory is unavailable") from error
        _require_directory(markers)
        return markers / f"{content_sha256}.json"

    def _new_tombstone(self, binding: _TombstoneBinding) -> dict[str, object]:
        occurred_at = _utc(self._clock()).isoformat()
        value = {
            "content_sha256": binding.content_sha256,
            "deletion_id": binding.deletion_id,
            "execution_identity_hash": binding.execution_identity_hash,
            "repository_id": binding.repository_id,
            "tenant_id": binding.tenant_id,
            "tombstoned_at": occurred_at,
        }
        return {
            **value,
            "binding_sha256": _digest(value),
            "schema_version": 1,
        }

    def _write_marker(self, path: Path, value: Mapping[str, object]) -> None:
        encoded = _canonical(value).encode("ascii")
        if path.exists():
            self._require_exact(_read_marker(path), _binding_from_marker(value))
            return
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=".tombstone-",
            suffix=".tmp",
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                self._require_exact(_read_marker(path), _binding_from_marker(value))
            _sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _read_marker(self, path: Path) -> dict[str, object]:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_METADATA_BYTES:
            raise LifecycleConflict("backup tombstone marker is invalid")
        try:
            document = json.loads(
                path.read_text(encoding="ascii"),
                object_pairs_hook=_unique_object_pairs,
            )
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            raise LifecycleConflict("backup tombstone marker is invalid") from None
        if not isinstance(document, dict) or set(document) != {
            "binding_sha256",
            "content_sha256",
            "deletion_id",
            "execution_identity_hash",
            "repository_id",
            "schema_version",
            "tenant_id",
            "tombstoned_at",
        }:
            raise LifecycleConflict("backup tombstone marker is invalid")
        _validate_marker(document)
        return document

    def _stored_tombstone(
        self, tenant_id: str, content_sha256: str
    ) -> _TombstoneBinding | None:
        row = self._db.execute(
            """SELECT deletion_id, tenant_id, repository_id,
                              content_sha256, execution_identity_hash,
                              tombstoned_at, binding_sha256
                         FROM lifecycle_storage_tombstones
                        WHERE tenant_id=? AND content_sha256=?""",
            (tenant_id, content_sha256),
        ).fetchone()
        if row is None:
            return None
        value = {
            "content_sha256": row[3],
            "deletion_id": row[0],
            "execution_identity_hash": row[4],
            "repository_id": row[2],
            "tenant_id": row[1],
            "tombstoned_at": row[5],
            "binding_sha256": row[6],
            "schema_version": 1,
        }
        _validate_marker(value)
        return _binding_from_marker(value)

    def _insert_tombstone(self, value: Mapping[str, object]) -> None:
        _validate_marker(value)
        try:
            self._db.execute(
                """INSERT INTO lifecycle_storage_tombstones (
                       tenant_id, content_sha256, deletion_id, repository_id,
                       execution_identity_hash, tombstoned_at, binding_sha256
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    value["tenant_id"],
                    value["content_sha256"],
                    value["deletion_id"],
                    value["repository_id"],
                    value["execution_identity_hash"],
                    value["tombstoned_at"],
                    value["binding_sha256"],
                ),
            )
        except sqlite3.IntegrityError as error:
            existing = self._stored_tombstone(
                str(value["tenant_id"]), str(value["content_sha256"])
            )
            if existing is None or existing != _binding_from_marker(value):
                raise LifecycleConflict("backup tombstone conflicts") from error

    @staticmethod
    def _require_exact(
        value: _TombstoneBinding | Mapping[str, object],
        binding: _TombstoneBinding,
    ) -> None:
        actual = (
            value.deletion_id if isinstance(value, _TombstoneBinding) else value["deletion_id"],
            value.tenant_id if isinstance(value, _TombstoneBinding) else value["tenant_id"],
            value.repository_id if isinstance(value, _TombstoneBinding) else value["repository_id"],
            value.content_sha256
            if isinstance(value, _TombstoneBinding)
            else value["content_sha256"],
            value.execution_identity_hash
            if isinstance(value, _TombstoneBinding)
            else value["execution_identity_hash"],
        )
        expected = (
            binding.deletion_id,
            binding.tenant_id,
            binding.repository_id,
            binding.content_sha256,
            binding.execution_identity_hash,
        )
        if actual != expected:
            raise LifecycleConflict("backup tombstone scope conflicts")

    def _remove_object(self, tenant_id: str, content_sha256: str) -> None:
        payload = self._object_path(tenant_id, content_sha256)
        metadata = payload.with_suffix(".json")
        _require_directory(payload.parent.parent)
        _require_directory(payload.parent)
        for path in (payload, metadata):
            # The tombstone is written before either file is removed.  A
            # process crash can therefore leave only one half of the object.
            # Treat an already absent half as completed work, while still
            # rejecting reparse points and non-regular files that could hide
            # a different object under the same digest.
            if path.is_symlink():
                raise LifecycleConflict("backup object is unsafe")
            if path.exists():
                _require_regular_file(path)
        for path in (payload, metadata):
            if not path.exists():
                continue
            try:
                path.unlink()
            except OSError as error:
                raise LifecycleConflict("backup object removal failed") from error
        _sync_directory(payload.parent)

    def _require_object_absent(self, tenant_id: str, content_sha256: str) -> None:
        path = self._object_path(tenant_id, content_sha256)
        _require_directory(path.parent.parent)
        _require_directory(path.parent)
        metadata = path.with_suffix(".json")
        if path.exists() or path.is_symlink() or metadata.exists() or metadata.is_symlink():
            raise LifecycleConflict("backup tombstoned object still exists")

    def _object_path(self, tenant_id: str, content_sha256: str) -> Path:
        namespace = _tenant_namespace(tenant_id)
        path = self._root / namespace / content_sha256[:2] / content_sha256
        try:
            path.relative_to(self._root)
        except ValueError:
            raise LifecycleConflict("backup object path is unsafe") from None
        return path

    def _read_payload(self, path: Path, metadata: ArtifactMetadata) -> bytes:
        payload_path = path.with_suffix("")
        if payload_path.is_symlink() or not payload_path.is_file():
            raise LifecycleConflict("backup object payload is unavailable")
        if metadata.size_bytes > 1_073_741_824:
            raise LifecycleConflict("backup object payload is too large")
        try:
            with payload_path.open("rb") as stream:
                payload = stream.read(metadata.size_bytes + 1)
        except OSError as error:
            raise LifecycleConflict("backup object payload is unavailable") from error
        if len(payload) != metadata.size_bytes or _sha256(payload) != metadata.content_sha256:
            raise LifecycleConflict("backup object payload integrity failed")
        return payload

    def _verify_payload(self, metadata_path: Path, metadata: ArtifactMetadata) -> None:
        self._read_payload(metadata_path, metadata)


def _read_metadata(path: Path) -> ArtifactMetadata:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_METADATA_BYTES:
        raise LifecycleConflict("backup retention metadata is invalid")
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object_pairs,
        )
        if not isinstance(document, Mapping):
            raise ValueError
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
        if set(document) != expected:
            raise ValueError
        value = ArtifactMetadata(
            tenant_id=document["tenant_id"],
            repository_id=document["repository_id"],
            run_id=document["run_id"],
            execution_identity_hash=document["execution_identity_hash"],
            content_sha256=document["content_sha256"],
            size_bytes=document["size_bytes"],
            content_class=document["content_class"],
            purpose=document["purpose"],
            created_at=datetime.fromisoformat(document["created_at"]),
            expires_at=(
                None
                if document["expires_at"] is None
                else datetime.fromisoformat(document["expires_at"])
            ),
            retention_marked=document["retention_marked"],
        )
    except (OSError, UnicodeError, TypeError, ValueError, json.JSONDecodeError):
        raise LifecycleConflict("backup retention metadata is invalid") from None
    return value


def _binding_from_marker(value: Mapping[str, object]) -> _TombstoneBinding:
    return _TombstoneBinding(
        deletion_id=str(value["deletion_id"]),
        tenant_id=str(value["tenant_id"]),
        repository_id=str(value["repository_id"]),
        content_sha256=str(value["content_sha256"]),
        execution_identity_hash=str(value["execution_identity_hash"]),
    )


def _validate_marker(value: Mapping[str, object]) -> None:
    if value.get("schema_version") != 1:
        raise LifecycleConflict("backup tombstone marker is invalid")
    binding = _binding_from_marker(value)
    require_identifier(binding.deletion_id, "deletion_id")
    require_identifier(binding.tenant_id, "tenant_id")
    require_identifier(binding.repository_id, "repository_id")
    require_sha256(binding.content_sha256, "content_sha256")
    require_sha256(binding.execution_identity_hash, "execution_identity_hash")
    occurred = value.get("tombstoned_at")
    if type(occurred) is not str:
        raise LifecycleConflict("backup tombstone marker is invalid")
    try:
        occurred_at = datetime.fromisoformat(occurred)
    except (TypeError, ValueError):
        raise LifecycleConflict("backup tombstone marker is invalid") from None
    _utc(occurred_at)
    expected = {
        "content_sha256": binding.content_sha256,
        "deletion_id": binding.deletion_id,
        "execution_identity_hash": binding.execution_identity_hash,
        "repository_id": binding.repository_id,
        "tenant_id": binding.tenant_id,
        "tombstoned_at": occurred,
    }
    if value.get("binding_sha256") != _digest(expected):
        raise LifecycleConflict("backup tombstone binding is invalid")


def _record_identity(record: BackupRecord) -> str:
    validate_backup_record(record)
    if record.manifest_sha256 is None or record.manifest_sha256 != manifest_sha256(record):
        raise LifecycleConflict("backup record manifest is invalid")
    material = f"backup-record-v1\0{record.tenant_id}\0{record.backup_id}\0{record.manifest_sha256}"
    return _sha256(material.encode("utf-8"))


def _deletion_id(
    *, tenant_id: str, content_sha256: str, identity_hash: str, purpose: str
) -> str:
    return BACKUP_RETENTION_DELETION_PREFIX + _digest(
        {
            "content_sha256": content_sha256,
            "identity_hash": identity_hash,
            "purpose": purpose,
            "tenant_id": tenant_id,
            "version": 1,
        }
    )


def _deletion_request_hash(value: DeletionRequest) -> str:
    return _digest(
        [
            value.deletion_id,
            value.tenant_id,
            value.content_sha256,
            value.data_class,
            value.identity_hash,
            value.requested_by,
            value.version,
            value.approved_by,
            value.executed,
            value.legal_hold,
        ]
    )


def _profile_hash(profile: RetentionProfile) -> str:
    return _digest(
        {
            "artifact_days": profile.artifact_days,
            "audit_days": profile.audit_days,
            "metadata_days": profile.metadata_days,
            "tenant_id": profile.tenant_id,
        }
    )


def _tenant_namespace(tenant_id: str) -> str:
    require_identifier(tenant_id, "tenant_id")
    return "t-" + _sha256(tenant_id.encode("utf-8"))


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise LifecycleConflict("backup lifecycle document is invalid") from error


def _digest(value: object) -> str:
    return _sha256(_canonical(value).encode("ascii"))


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise LifecycleConflict("backup lifecycle clock returned an invalid timestamp")
    result = value.astimezone(UTC)
    if result.utcoffset() != timedelta(0):
        raise LifecycleConflict("backup lifecycle clock returned an invalid timestamp")
    return result


def _require_directory(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise LifecycleConflict("backup retention directory is unavailable") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
        raise LifecycleConflict("backup retention directory is unsafe")


def _require_regular_file(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise LifecycleConflict("backup object file is unavailable") from error
    if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
        raise LifecycleConflict("backup object file is unsafe")


def _sync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "BACKUP_RETENTION_DELETION_PREFIX",
    "BACKUP_RETENTION_PURPOSES",
    "BACKUP_TOMBSTONE_SCHEMA_STATEMENTS",
    "BackupLifecycleAdapter",
    "BackupRetentionCandidate",
]
