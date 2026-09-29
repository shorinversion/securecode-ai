"""Durable, tenant-scoped deletion of locally stored artifact bytes."""

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
from typing import BinaryIO, Final

from .artifact_tenant_namespace import (
    ArtifactTenantNamespaceError,
    artifact_tenant_path_component,
)
from .artifact_upload import (
    ArtifactUploadConflict,
    _parse_receipt,
    _unique_object_pairs,
)
from .data_lifecycle_models import LifecycleConflict, require_identifier, require_sha256
from .filesystem_paths import lexical_absolute_path
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard

_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_REPARSE_POINT: Final = 0x400
_MAX_RECEIPT_BYTES: Final = 65_536
_TOMBSTONE_SCHEMA_VERSION: Final = 1

STORAGE_TOMBSTONE_SCHEMA_STATEMENTS: Final = (
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


@dataclass(frozen=True, slots=True)
class ArtifactTombstone:
    """Source-free proof that one exact tenant artifact was removed."""

    schema_version: int
    deletion_id: str
    tenant_id: str
    repository_id: str
    content_sha256: str
    execution_identity_hash: str
    tombstoned_at: str
    binding_sha256: str

    def document(self) -> dict[str, object]:
        return {
            "binding_sha256": self.binding_sha256,
            "content_sha256": self.content_sha256,
            "deletion_id": self.deletion_id,
            "execution_identity_hash": self.execution_identity_hash,
            "repository_id": self.repository_id,
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "tombstoned_at": self.tombstoned_at,
        }


@dataclass(frozen=True, slots=True)
class _DeletionBinding:
    deletion_id: str
    tenant_id: str
    repository_id: str
    content_sha256: str
    execution_identity_hash: str
    approved: bool
    executed: bool
    legal_hold: bool


class LocalArtifactStorageExecutor:
    """Idempotently tombstone an authorized local artifact.

    The lifecycle ledger invokes this boundary inside its SQLite transaction.
    This implementation therefore participates in the caller's transaction and
    never commits it. A durable filesystem marker bridges process failure
    between byte removal and the database commit.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        artifact_root: Path,
        *,
        clock: Callable[[], datetime] | None = None,
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        if not isinstance(artifact_root, Path):
            raise TypeError("artifact_root must be a path")
        self._db = connection
        self._root = lexical_absolute_path(artifact_root)
        self._clock = clock or (lambda: datetime.now(UTC))
        if (residency_guard is None) != (residency_region is None):
            raise TypeError("storage residency configuration is incomplete")
        if residency_guard is not None and not callable(
            getattr(residency_guard, "require_region", None)
        ):
            raise TypeError("storage residency guard is invalid")
        self._residency_guard = residency_guard
        self._residency_region = residency_region
        _require_directory_chain(self._root)
        self._markers = self._root / ".tombstones"
        _create_private_directory(self._markers)
        self._initialize_schema()

    def execute_tombstone(
        self,
        *,
        tenant_id: str,
        content_sha256: str,
        deletion_id: str,
        repository_id: str,
        identity_hash: str,
    ) -> None:
        _require_tenant(tenant_id)
        _require_sha256(content_sha256)
        require_identifier(deletion_id, "deletion_id")
        require_identifier(repository_id, "repository_id")
        require_sha256(identity_hash, "identity_hash")
        self._require_residency(tenant_id)
        binding = self._binding(
            tenant_id=tenant_id,
            content_sha256=content_sha256,
            deletion_id=deletion_id,
            repository_id=repository_id,
            identity_hash=identity_hash,
        )
        marker_path = self._marker_path(tenant_id, content_sha256)
        stored = self._stored_tombstone(tenant_id, content_sha256)
        marker = self._read_marker(marker_path) if marker_path.exists() else None

        if stored is not None:
            self._require_exact(stored, binding)
            if not binding.approved or not binding.executed or binding.legal_hold:
                raise LifecycleConflict("artifact deletion is not in a completed state")
            if marker is None:
                raise LifecycleConflict("artifact tombstone marker is unavailable")
            self._require_exact(marker, binding)
            self._require_object_absent(tenant_id, content_sha256)
            return

        if not binding.approved or binding.executed or binding.legal_hold:
            raise LifecycleConflict("artifact deletion is not approved for execution")

        target = self._object_path(tenant_id, content_sha256)
        if marker is None:
            receipt = self._validated_receipt(target, binding)
            self._require_receipt_binding(receipt, binding)
            marker = self._new_tombstone(binding)
            self._write_marker(marker_path, marker)
        else:
            self._require_exact(marker, binding)

        self._remove_object(target, marker_exists=True)
        self._insert_tombstone(marker)

    def _require_residency(self, tenant_id: str) -> None:
        guard = self._residency_guard
        if guard is None:
            return
        region = self._residency_region
        if region is None:
            raise LifecycleConflict("storage residency configuration is incomplete")
        try:
            decision = guard.require_region(tenant_id=tenant_id, region=region)
        except ResidencyConflict as error:
            raise LifecycleConflict("storage residency policy denied") from error
        except Exception as error:
            raise LifecycleConflict("storage residency check failed") from error
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != tenant_id
            or decision.source_region != region
            or decision.destination_region != region
            or not decision.same_region
        ):
            raise LifecycleConflict("storage residency decision is invalid")

    def _initialize_schema(self) -> None:
        try:
            for statement in STORAGE_TOMBSTONE_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _binding(
        self,
        *,
        tenant_id: str,
        content_sha256: str,
        deletion_id: str,
        repository_id: str,
        identity_hash: str,
    ) -> _DeletionBinding:
        rows = self._db.execute(
            """SELECT d.deletion_id, d.tenant_id, d.content_sha256,
                      d.data_class, d.identity_hash, s.repository_id,
                      d.approved_by, d.approved_at, d.executed, d.legal_hold
               FROM lifecycle_deletions AS d
               JOIN lifecycle_repository_scopes AS s
                 ON s.deletion_id=d.deletion_id AND s.tenant_id=d.tenant_id
               WHERE d.tenant_id=? AND d.deletion_id=?
                 AND d.content_sha256=? AND d.identity_hash=?
                 AND s.repository_id=?""",
            (tenant_id, deletion_id, content_sha256, identity_hash, repository_id),
        ).fetchall()
        if len(rows) != 1 or str(rows[0]["data_class"]) != "artifact":
            raise LifecycleConflict("artifact deletion binding is unavailable")
        row = rows[0]
        approved_by = row["approved_by"]
        approved_at = row["approved_at"]
        executed = row["executed"]
        legal_hold = row["legal_hold"]
        if (
            (approved_by is None) != (approved_at is None)
            or (approved_by is not None and type(approved_by) is not str)
            or (approved_at is not None and type(approved_at) is not str)
            or type(executed) is not int
            or executed not in (0, 1)
            or type(legal_hold) is not int
            or legal_hold not in (0, 1)
        ):
            raise LifecycleConflict("artifact deletion state is invalid")
        if approved_by is not None:
            require_identifier(approved_by, "approved_by")
        return _DeletionBinding(
            deletion_id=str(row["deletion_id"]),
            tenant_id=str(row["tenant_id"]),
            repository_id=str(row["repository_id"]),
            content_sha256=str(row["content_sha256"]),
            execution_identity_hash=str(row["identity_hash"]),
            approved=approved_by is not None,
            executed=executed == 1,
            legal_hold=legal_hold == 1,
        )

    def _validated_receipt(self, target: Path, binding: _DeletionBinding) -> Mapping[str, object]:
        _require_plain_directory(target)
        entries = {entry.name for entry in target.iterdir()}
        if not {"payload", "receipt.json"}.issubset(entries) or not entries.issubset(
            {"payload", "receipt.json", "authorizations"}
        ):
            raise LifecycleConflict("artifact object layout is invalid")
        payload = target / "payload"
        receipt_path = target / "receipt.json"
        _require_regular_file(payload)
        _require_regular_file(receipt_path)
        receipt_bytes = _read_bounded(receipt_path, _MAX_RECEIPT_BYTES)
        try:
            value = json.loads(
                receipt_bytes.decode("ascii"), object_pairs_hook=_unique_object_pairs
            )
        except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
            raise LifecycleConflict("artifact receipt is invalid") from None
        if not isinstance(value, Mapping):
            raise LifecycleConflict("artifact receipt is invalid")
        expected_hash = value.get("content_sha256")
        expected_size = value.get("size_bytes")
        if type(expected_hash) is not str or type(expected_size) is not int:
            raise LifecycleConflict("artifact receipt is invalid")
        digest, size = _digest_file(payload)
        if digest != expected_hash or size != expected_size:
            raise LifecycleConflict("artifact payload integrity check failed")
        try:
            primary = _parse_receipt(value)
        except (ArtifactUploadConflict, TypeError, ValueError):
            raise LifecycleConflict("artifact receipt is invalid") from None
        candidates: list[Mapping[str, object]] = [primary.document()]
        if "authorizations" in entries:
            authorization_root = target / "authorizations"
            _require_plain_directory(authorization_root)
            for authorization_directory in authorization_root.iterdir():
                if not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", authorization_directory.name
                ):
                    raise LifecycleConflict("artifact authorization receipt path is invalid")
                _require_plain_directory(authorization_directory)
                if {entry.name for entry in authorization_directory.iterdir()} != {"receipt.json"}:
                    raise LifecycleConflict("artifact authorization receipt layout is invalid")
                receipt_path = authorization_directory / "receipt.json"
                _require_regular_file(receipt_path)
                try:
                    candidate = json.loads(
                        _read_bounded(receipt_path, _MAX_RECEIPT_BYTES).decode("ascii"),
                        object_pairs_hook=_unique_object_pairs,
                    )
                except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
                    raise LifecycleConflict("artifact authorization receipt is invalid") from None
                if not isinstance(candidate, Mapping):
                    raise LifecycleConflict("artifact authorization receipt scope conflicts")
                try:
                    parsed_candidate = _parse_receipt(candidate)
                except (ArtifactUploadConflict, TypeError, ValueError):
                    raise LifecycleConflict("artifact authorization receipt is invalid") from None
                if (
                    parsed_candidate.authorization_id != authorization_directory.name
                    or parsed_candidate.tenant_id != binding.tenant_id
                    or parsed_candidate.content_sha256 != binding.content_sha256
                    or parsed_candidate.size_bytes != size
                ):
                    raise LifecycleConflict("artifact authorization receipt scope conflicts")
                candidates.append(parsed_candidate.document())
        selected = next(
            (
                receipt
                for receipt in candidates
                if receipt.get("tenant_id") == binding.tenant_id
                and receipt.get("repository_id") == binding.repository_id
                and receipt.get("content_sha256") == binding.content_sha256
                and receipt.get("execution_identity_hash") == binding.execution_identity_hash
            ),
            None,
        )
        if selected is None:
            raise LifecycleConflict("artifact authorization receipt is unavailable")
        return selected

    def _require_receipt_binding(
        self,
        receipt: Mapping[str, object],
        binding: _DeletionBinding,
    ) -> None:
        authorization_id = receipt.get("authorization_id")
        exact = (
            receipt.get("tenant_id"),
            receipt.get("repository_id"),
            receipt.get("content_sha256"),
            receipt.get("execution_identity_hash"),
        )
        expected = (
            binding.tenant_id,
            binding.repository_id,
            binding.content_sha256,
            binding.execution_identity_hash,
        )
        if type(authorization_id) is not str or exact != expected:
            raise LifecycleConflict("artifact receipt scope conflicts")
        row = self._db.execute(
            """SELECT tenant_id, repository_id, content_sha256,
                      execution_identity_hash, worker_id, run_id, content_id,
                      size_bytes, data_class, purpose, signer_key_id,
                      receipt_signature, issued_at, expires_at
               FROM artifact_upload_authorizations
               WHERE tenant_id=? AND authorization_id=?""",
            (binding.tenant_id, authorization_id),
        ).fetchone()
        if row is None or tuple(str(row[index]) for index in range(4)) != expected:
            raise LifecycleConflict("artifact authorization scope conflicts")
        if (
            any(
                receipt.get(name) != row[name]
                for name in (
                    "worker_id",
                    "repository_id",
                    "run_id",
                    "execution_identity_hash",
                    "content_id",
                    "content_sha256",
                    "size_bytes",
                    "data_class",
                    "purpose",
                    "signer_key_id",
                    "authorization_signature",
                )
            )
            or receipt.get("authorized_at") != row["issued_at"]
            or receipt.get("authorization_expires_at") != row["expires_at"]
        ):
            raise LifecycleConflict("artifact authorization receipt conflicts")
        foreign = self._db.execute(
            """SELECT 1 FROM artifact_upload_authorizations
               WHERE tenant_id=? AND content_sha256=? AND repository_id<>?
               LIMIT 1""",
            (
                binding.tenant_id,
                binding.content_sha256,
                binding.repository_id,
            ),
        ).fetchone()
        if foreign is not None:
            raise LifecycleConflict("artifact has cross-repository references")

    def _new_tombstone(self, binding: _DeletionBinding) -> ArtifactTombstone:
        occurred_at = _utc_text(self._clock())
        material = {
            "content_sha256": binding.content_sha256,
            "deletion_id": binding.deletion_id,
            "execution_identity_hash": binding.execution_identity_hash,
            "repository_id": binding.repository_id,
            "tenant_id": binding.tenant_id,
            "tombstoned_at": occurred_at,
        }
        return ArtifactTombstone(
            schema_version=_TOMBSTONE_SCHEMA_VERSION,
            deletion_id=binding.deletion_id,
            tenant_id=binding.tenant_id,
            repository_id=binding.repository_id,
            content_sha256=binding.content_sha256,
            execution_identity_hash=binding.execution_identity_hash,
            tombstoned_at=occurred_at,
            binding_sha256=_hash_document(material),
        )

    def _insert_tombstone(self, value: ArtifactTombstone) -> None:
        try:
            self._db.execute(
                """INSERT INTO lifecycle_storage_tombstones (
                       tenant_id, content_sha256, deletion_id, repository_id,
                       execution_identity_hash, tombstoned_at, binding_sha256
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    value.tenant_id,
                    value.content_sha256,
                    value.deletion_id,
                    value.repository_id,
                    value.execution_identity_hash,
                    value.tombstoned_at,
                    value.binding_sha256,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise LifecycleConflict("artifact tombstone conflicts") from error

    def _stored_tombstone(self, tenant_id: str, content_sha256: str) -> ArtifactTombstone | None:
        row = self._db.execute(
            """SELECT deletion_id, tenant_id, repository_id, content_sha256,
                      execution_identity_hash, tombstoned_at, binding_sha256
               FROM lifecycle_storage_tombstones
               WHERE tenant_id=? AND content_sha256=?""",
            (tenant_id, content_sha256),
        ).fetchone()
        if row is None:
            return None
        return ArtifactTombstone(
            schema_version=_TOMBSTONE_SCHEMA_VERSION,
            deletion_id=str(row["deletion_id"]),
            tenant_id=str(row["tenant_id"]),
            repository_id=str(row["repository_id"]),
            content_sha256=str(row["content_sha256"]),
            execution_identity_hash=str(row["execution_identity_hash"]),
            tombstoned_at=str(row["tombstoned_at"]),
            binding_sha256=str(row["binding_sha256"]),
        )

    def _marker_path(self, tenant_id: str, content_sha256: str) -> Path:
        tenant_dir = self._markers / _tenant_component(tenant_id)
        _create_private_directory(tenant_dir)
        return tenant_dir / f"{content_sha256}.json"

    def _read_marker(self, path: Path) -> ArtifactTombstone:
        _require_regular_file(path)
        try:
            value = json.loads(_read_bounded(path, _MAX_RECEIPT_BYTES).decode("ascii"))
        except (UnicodeError, json.JSONDecodeError):
            raise LifecycleConflict("artifact tombstone marker is invalid") from None
        if not isinstance(value, dict) or set(value) != {
            "binding_sha256",
            "content_sha256",
            "deletion_id",
            "execution_identity_hash",
            "repository_id",
            "schema_version",
            "tenant_id",
            "tombstoned_at",
        }:
            raise LifecycleConflict("artifact tombstone marker is invalid")
        try:
            marker = ArtifactTombstone(**value)
        except TypeError:
            raise LifecycleConflict("artifact tombstone marker is invalid") from None
        _validate_tombstone(marker)
        return marker

    def _write_marker(self, path: Path, value: ArtifactTombstone) -> None:
        if path.exists():
            self._require_exact(self._read_marker(path), _binding_from(value))
            _sync_directory(path.parent)
            return
        encoded = _canonical(value.document()).encode("ascii")
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
                self._require_exact(self._read_marker(path), _binding_from(value))
            _require_regular_file(path)
            _sync_directory(path.parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _remove_object(self, target: Path, *, marker_exists: bool) -> None:
        if not marker_exists:
            raise LifecycleConflict("artifact tombstone marker is unavailable")
        if not target.exists():
            if target.is_symlink():
                raise LifecycleConflict("artifact object path is unsafe")
            return
        _require_plain_directory(target)
        entries = {entry.name: entry for entry in target.iterdir()}
        if not set(entries).issubset({"payload", "receipt.json", "authorizations"}):
            raise LifecycleConflict("artifact object layout is invalid")
        for name in ("payload", "receipt.json"):
            path = entries.get(name)
            if path is None:
                continue
            _require_regular_file(path)
            try:
                path.unlink()
            except OSError as error:
                raise LifecycleConflict("artifact byte removal failed") from error
        _sync_directory(target)
        authorizations = entries.get("authorizations")
        if authorizations is not None:
            _require_plain_directory(authorizations)
            for authorization_directory in authorizations.iterdir():
                if not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", authorization_directory.name
                ):
                    raise LifecycleConflict("artifact authorization receipt path is invalid")
                _require_plain_directory(authorization_directory)
                contents = {entry.name for entry in authorization_directory.iterdir()}
                if not contents.issubset({"receipt.json"}):
                    raise LifecycleConflict("artifact authorization receipt layout is invalid")
                receipt = authorization_directory / "receipt.json"
                if "receipt.json" in contents:
                    _require_regular_file(receipt)
                    try:
                        receipt.unlink()
                    except OSError as error:
                        raise LifecycleConflict(
                            "artifact authorization receipt removal failed"
                        ) from error
                    _sync_directory(authorization_directory)
                try:
                    authorization_directory.rmdir()
                except OSError as error:
                    raise LifecycleConflict(
                        "artifact authorization receipt removal failed"
                    ) from error
            try:
                authorizations.rmdir()
            except OSError as error:
                raise LifecycleConflict(
                    "artifact authorization directory removal failed"
                ) from error
            _sync_directory(target)
        try:
            target.rmdir()
        except OSError as error:
            raise LifecycleConflict("artifact object removal failed") from error
        _sync_directory(target.parent)

    def _require_object_absent(self, tenant_id: str, content_sha256: str) -> None:
        target = self._object_path(tenant_id, content_sha256)
        if target.exists() or target.is_symlink():
            raise LifecycleConflict("tombstoned artifact bytes still exist")

    def _object_path(self, tenant_id: str, content_sha256: str) -> Path:
        target = self._root / _tenant_component(tenant_id) / content_sha256[:2] / content_sha256
        try:
            target.relative_to(self._root)
        except ValueError:
            raise LifecycleConflict("artifact object path is unsafe") from None
        try:
            _require_directory_chain(target.parent)
        except (OSError, ValueError) as error:
            raise LifecycleConflict("artifact object path is unsafe") from error
        return target

    @staticmethod
    def _require_exact(value: ArtifactTombstone, binding: _DeletionBinding) -> None:
        expected = (
            binding.deletion_id,
            binding.tenant_id,
            binding.repository_id,
            binding.content_sha256,
            binding.execution_identity_hash,
        )
        actual = (
            value.deletion_id,
            value.tenant_id,
            value.repository_id,
            value.content_sha256,
            value.execution_identity_hash,
        )
        if actual != expected:
            raise LifecycleConflict("artifact tombstone scope conflicts")
        _validate_tombstone(value)


def _binding_from(value: ArtifactTombstone) -> _DeletionBinding:
    return _DeletionBinding(
        deletion_id=value.deletion_id,
        tenant_id=value.tenant_id,
        repository_id=value.repository_id,
        content_sha256=value.content_sha256,
        execution_identity_hash=value.execution_identity_hash,
        approved=True,
        executed=False,
        legal_hold=False,
    )


def _validate_tombstone(value: ArtifactTombstone) -> None:
    if value.schema_version != _TOMBSTONE_SCHEMA_VERSION:
        raise LifecycleConflict("artifact tombstone version is invalid")
    _require_tenant(value.tenant_id)
    _require_sha256(value.content_sha256)
    _require_sha256(value.execution_identity_hash)
    _require_sha256(value.binding_sha256)
    for identifier in (value.deletion_id, value.repository_id):
        if type(identifier) is not str or not identifier or "\x00" in identifier:
            raise LifecycleConflict("artifact tombstone identifier is invalid")
    occurred = _parse_utc(value.tombstoned_at)
    material = {
        "content_sha256": value.content_sha256,
        "deletion_id": value.deletion_id,
        "execution_identity_hash": value.execution_identity_hash,
        "repository_id": value.repository_id,
        "tenant_id": value.tenant_id,
        "tombstoned_at": occurred.isoformat(),
    }
    if _hash_document(material) != value.binding_sha256:
        raise LifecycleConflict("artifact tombstone binding is invalid")


def _require_directory_chain(path: Path) -> None:
    if not path.is_absolute() or not path.anchor:
        raise ValueError("artifact root must be absolute")
    current = Path(path.anchor)
    _require_plain_directory(current, value_error=True)
    for part in path.parts[1:]:
        current /= part
        _require_plain_directory(current, value_error=True)


def _create_private_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
    except FileNotFoundError:
        _create_private_directory(path.parent)
        path.mkdir(mode=0o700, exist_ok=True)
        _sync_directory(path.parent)
    else:
        _sync_directory(path.parent)
    _require_plain_directory(path, value_error=True)


def _sync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_plain_directory(path: Path, *, value_error: bool = False) -> None:
    error_type = ValueError if value_error else LifecycleConflict
    try:
        details = path.lstat()
    except OSError as error:
        raise error_type("artifact directory is unavailable") from error
    if _link_like(details) or not stat.S_ISDIR(details.st_mode):
        raise error_type("artifact directory is unsafe")


def _require_regular_file(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise LifecycleConflict("artifact file is unavailable") from error
    if _link_like(details) or not stat.S_ISREG(details.st_mode):
        raise LifecycleConflict("artifact file is unsafe")


def _link_like(details: os.stat_result) -> bool:
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(attributes & _REPARSE_POINT)


def _open_regular_file(path: Path) -> BinaryIO:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(current.st_mode)
            or not os.path.samestat(opened, current)
        ):
            raise LifecycleConflict("artifact file is unsafe")
        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        return stream
    except LifecycleConflict:
        raise
    except OSError as error:
        raise LifecycleConflict("artifact file cannot be opened safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _read_bounded(path: Path, limit: int) -> bytes:
    try:
        with _open_regular_file(path) as stream:
            value = stream.read(limit + 1)
    except OSError as error:
        raise LifecycleConflict("artifact file cannot be read") from error
    if len(value) > limit:
        raise LifecycleConflict("artifact file exceeds its limit")
    return value


def _digest_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    try:
        with _open_regular_file(path) as stream:
            while chunk := stream.read(65_536):
                digest.update(chunk)
                size += len(chunk)
    except OSError as error:
        raise LifecycleConflict("artifact payload cannot be read") from error
    return digest.hexdigest(), size


def _require_tenant(value: object) -> str:
    if type(value) is not str:
        raise LifecycleConflict("tenant_id is invalid")
    _tenant_component(value)
    return value


def _tenant_component(tenant_id: str) -> str:
    try:
        return artifact_tenant_path_component(tenant_id)
    except ArtifactTenantNamespaceError:
        raise LifecycleConflict("tenant_id is invalid") from None


def _require_sha256(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise LifecycleConflict("SHA-256 value is invalid")
    return value


def _utc_text(source: datetime) -> str:
    if not isinstance(source, datetime) or source.tzinfo is None:
        raise LifecycleConflict("clock returned an invalid timestamp")
    value = source.astimezone(UTC)
    if value.utcoffset() != timedelta(0):
        raise LifecycleConflict("clock returned an invalid timestamp")
    return value.isoformat()


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise LifecycleConflict("tombstone timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise LifecycleConflict("tombstone timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise LifecycleConflict("tombstone timestamp is invalid")
    return parsed


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
        raise LifecycleConflict("tombstone metadata is invalid") from error


def _hash_document(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


__all__ = [
    "STORAGE_TOMBSTONE_SCHEMA_STATEMENTS",
    "ArtifactTombstone",
    "LocalArtifactStorageExecutor",
]
