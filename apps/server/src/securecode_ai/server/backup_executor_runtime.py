"""Local backup and restore executors with a verified SQLite fallback."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Final, Protocol

from .artifacts import ArtifactConflict, ArtifactMetadata
from .backup_repository import (
    BackupConflict,
    BackupRecord,
    deserialize_backup_record,
    serialize_backup_record,
    validate_backup_record,
)
from .backup_service import BackupExecutionResult, BackupExecutor, manifest_sha256
from .subprocess_protocol import (
    PinnedJsonProcess,
    SubprocessProtocolError,
    configured_process,
)

_MAX_SNAPSHOT_BYTES: Final = 67_108_864
_MAX_ENCRYPTION_CHUNK_BYTES: Final = 32_768
_MAX_ENCRYPTION_BLOCK_BYTES: Final = 47_000
_MAX_ENCRYPTION_OUTPUT_BYTES: Final = _MAX_ENCRYPTION_BLOCK_BYTES
_MAX_ENCRYPTION_OUTPUT_B64: Final = ((_MAX_ENCRYPTION_BLOCK_BYTES + 2) // 3) * 4
_MAX_ENCRYPTION_CHUNKS: Final = (
    (_MAX_SNAPSHOT_BYTES + _MAX_ENCRYPTION_CHUNK_BYTES - 1)
    // _MAX_ENCRYPTION_CHUNK_BYTES
)
_SNAPSHOT_RETENTION_DAYS: Final = 90
_SNAPSHOT_PURPOSE: Final = "backup-snapshot"
_CONTROL_TABLES: Final = frozenset(
    {
        "backup_idempotency",
        "backup_repository_scopes",
        "backup_transition_journal",
        "backup_restore_phases",
        "backup_restore_recovery_audit",
        "backups",
    }
)
# Tables without tenant data are safe to carry in a scoped snapshot only when
# they are immutable schema bookkeeping.  Any populated operational table
# without a tenant key makes the scope unverifiable and therefore fails closed.
_GLOBAL_SCOPE_TABLES: Final = frozenset({"schema_metadata"})
# OIDC login state is deliberately kept outside tenant snapshots.  These
# tables are process-wide security state and have no tenant key in the schema.
# Their rows must never be copied into an artifact addressed to one tenant.
_OIDC_SYSTEM_TABLE_SHAPES: Final = (
    (
        "oidc_login_states",
        ("state_hash", "nonce_hash", "expires_at"),
    ),
    (
        "oidc_nonce_replays",
        ("subject_hash", "nonce_hash", "expires_at"),
    ),
    (
        "oidc_login_rate_limit",
        ("bucket", "window_started_at", "attempts"),
    ),
    (
        "oidc_login_source_rate_limit",
        ("bucket", "source_hash", "window_started_at", "window_seconds", "attempts"),
    ),
)
_OIDC_SYSTEM_TABLES: Final = frozenset(
    table for table, _ in _OIDC_SYSTEM_TABLE_SHAPES
)
_ENCRYPTED_CHUNKS_MAGIC: Final = b"SECURECODE-BACKUP-ENC-1\0"


@dataclass(frozen=True, slots=True)
class _RestorePhase:
    """Durable proof of the phase reached by one restore intent."""

    phase: str
    rpo_seconds: int
    rto_seconds: int | None
    applied_at: int | None


class BackupEncryptionProvider(Protocol):
    """Host-owned authenticated encryption boundary for local snapshots."""

    def encrypt(self, payload: bytes, key_ref: str) -> bytes: ...

    def decrypt(self, payload: bytes, key_ref: str) -> bytes: ...


class SubprocessBackupEncryptionProvider:
    """Use one hash-pinned process for authenticated snapshot encryption."""

    def __init__(self, process: PinnedJsonProcess) -> None:
        if not isinstance(process, PinnedJsonProcess):
            raise TypeError("encryption process must be a PinnedJsonProcess")
        self._process = process

    def encrypt(self, payload: bytes, key_ref: str) -> bytes:
        if type(payload) is not bytes or not payload:
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_REQUEST_INVALID")
        chunks = [
            payload[offset : offset + _MAX_ENCRYPTION_CHUNK_BYTES]
            for offset in range(0, len(payload), _MAX_ENCRYPTION_CHUNK_BYTES)
        ]
        if len(chunks) > _MAX_ENCRYPTION_CHUNKS:
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_REQUEST_TOO_LARGE")
        encrypted = [self._execute("encrypt", chunk, key_ref) for chunk in chunks]
        return _pack_encrypted_chunks(encrypted)

    def decrypt(self, payload: bytes, key_ref: str) -> bytes:
        chunks = _unpack_encrypted_chunks(payload)
        decrypted = [self._execute("decrypt", chunk, key_ref) for chunk in chunks]
        result = b"".join(decrypted)
        if len(result) > _MAX_SNAPSHOT_BYTES:
            raise SubprocessProtocolError("BACKUP_DECRYPTION_INVALID")
        return result

    def _execute(self, operation: str, payload: bytes, key_ref: str) -> bytes:
        if (
            operation not in {"encrypt", "decrypt"}
            or type(payload) is not bytes
            or not payload
            or len(payload) > _MAX_ENCRYPTION_BLOCK_BYTES
            or type(key_ref) is not str
            or not 1 <= len(key_ref) <= 512
            or any(ord(character) < 0x20 or ord(character) > 0x7E for character in key_ref)
        ):
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_REQUEST_INVALID")
        encoded = base64.b64encode(payload).decode("ascii")
        response = self._process.request(
            {
                "key_ref": key_ref,
                "operation": operation,
                "payload_b64": encoded,
                "schema_version": 1,
            }
        )
        if set(response) != {"payload_b64", "schema_version", "status"}:
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_RESPONSE_INVALID")
        if (
            type(response.get("schema_version")) is not int
            or response.get("schema_version") != 1
            or response.get("status") != "ok"
            or type(response.get("payload_b64")) is not str
            or not response["payload_b64"]
        ):
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_RESPONSE_INVALID")
        encoded_response = response["payload_b64"]
        if len(encoded_response) > _MAX_ENCRYPTION_OUTPUT_B64:
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_RESPONSE_TOO_LARGE")
        try:
            decoded = base64.b64decode(encoded_response.encode("ascii"), validate=True)
        except (UnicodeError, ValueError, binascii.Error):
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_RESPONSE_INVALID") from None
        if not decoded or len(decoded) > _MAX_ENCRYPTION_OUTPUT_BYTES:
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_RESPONSE_INVALID")
        if operation == "encrypt" and decoded == payload:
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_RESPONSE_PLAINTEXT")
        return decoded


def _pack_encrypted_chunks(chunks: list[bytes]) -> bytes:
    if not 1 <= len(chunks) <= _MAX_ENCRYPTION_CHUNKS:
        raise SubprocessProtocolError("BACKUP_ENCRYPTION_RESPONSE_INVALID")
    packed = bytearray(_ENCRYPTED_CHUNKS_MAGIC)
    packed.extend(len(chunks).to_bytes(4, "big"))
    for chunk in chunks:
        if not 1 <= len(chunk) <= _MAX_ENCRYPTION_BLOCK_BYTES:
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_RESPONSE_INVALID")
        packed.extend(len(chunk).to_bytes(4, "big"))
        packed.extend(chunk)
    if len(packed) > _MAX_SNAPSHOT_BYTES * 2:
        raise SubprocessProtocolError("BACKUP_ENCRYPTION_RESPONSE_TOO_LARGE")
    return bytes(packed)


def _unpack_encrypted_chunks(payload: bytes) -> tuple[bytes, ...]:
    if (
        type(payload) is not bytes
        or not payload.startswith(_ENCRYPTED_CHUNKS_MAGIC)
        or len(payload) > _MAX_SNAPSHOT_BYTES * 2
    ):
        raise SubprocessProtocolError("BACKUP_DECRYPTION_INVALID")
    offset = len(_ENCRYPTED_CHUNKS_MAGIC)
    if len(payload) < offset + 4:
        raise SubprocessProtocolError("BACKUP_DECRYPTION_INVALID")
    count = int.from_bytes(payload[offset : offset + 4], "big")
    offset += 4
    if not 1 <= count <= _MAX_ENCRYPTION_CHUNKS:
        raise SubprocessProtocolError("BACKUP_DECRYPTION_INVALID")
    chunks: list[bytes] = []
    for _ in range(count):
        if offset + 4 > len(payload):
            raise SubprocessProtocolError("BACKUP_DECRYPTION_INVALID")
        size = int.from_bytes(payload[offset : offset + 4], "big")
        offset += 4
        if (
            not 1 <= size <= _MAX_ENCRYPTION_BLOCK_BYTES
            or offset + size > len(payload)
        ):
            raise SubprocessProtocolError("BACKUP_DECRYPTION_INVALID")
        chunks.append(payload[offset : offset + size])
        offset += size
    if offset != len(payload):
        raise SubprocessProtocolError("BACKUP_DECRYPTION_INVALID")
    return tuple(chunks)


class SubprocessBackupExecutor:
    """Execute backup operations through one hash-pinned local process."""

    def __init__(self, process: PinnedJsonProcess) -> None:
        if not isinstance(process, PinnedJsonProcess):
            raise TypeError("process must be a PinnedJsonProcess")
        self._process = process

    def backup(self, record: BackupRecord) -> BackupExecutionResult:
        return self._execute("backup", record)

    def restore(self, record: BackupRecord) -> BackupExecutionResult:
        return self._execute("restore", record)

    def _execute(self, operation: str, record: BackupRecord) -> BackupExecutionResult:
        if operation not in {"backup", "restore"} or not isinstance(record, BackupRecord):
            raise SubprocessProtocolError("BACKUP_REQUEST_INVALID")
        try:
            validate_backup_record(record)
        except (BackupConflict, TypeError, ValueError):
            raise SubprocessProtocolError("BACKUP_REQUEST_INVALID") from None
        if operation == "backup" and record.state != "PLANNED":
            raise SubprocessProtocolError("BACKUP_REQUEST_INVALID")
        if operation == "restore" and (
            record.state != "BACKED_UP" or not record.backup_verified
        ):
            raise SubprocessProtocolError("BACKUP_REQUEST_INVALID")
        if record.manifest_sha256 is None:
            raise SubprocessProtocolError("BACKUP_MANIFEST_MISSING")
        response = self._process.request(
            {
                "backup_id": record.backup_id,
                "component_hashes": list(record.component_hashes),
                "encryption_key_ref": record.encryption_key_ref,
                "manifest_sha256": record.manifest_sha256,
                "operation": operation,
                "region": record.region,
                "schema_version": 1,
                "tenant_id": record.tenant_id,
            }
        )
        expected = {
            "component_hashes",
            "manifest_sha256",
            "rpo_seconds",
            "rto_seconds",
            "schema_version",
            "status",
        }
        if set(response) != expected:
            raise SubprocessProtocolError("BACKUP_RESPONSE_INVALID")
        if (
            type(response.get("schema_version")) is not int
            or response.get("schema_version") != 1
            or type(response.get("status")) is not str
            or response.get("status") != "ok"
        ):
            raise SubprocessProtocolError("BACKUP_RESPONSE_INVALID")
        components = response.get("component_hashes")
        manifest = response.get("manifest_sha256")
        rpo = response.get("rpo_seconds")
        rto = response.get("rto_seconds")
        if (
            type(components) is not list
            or len(components) > 10_000
            or not all(type(value) is str for value in components)
            or tuple(components) != record.component_hashes
            or type(manifest) is not str
            or manifest != record.manifest_sha256
            or type(rpo) is not int
            or not 0 <= rpo <= 315_360_000
            or type(rto) is not int
            or not 0 <= rto <= 315_360_000
        ):
            raise SubprocessProtocolError("BACKUP_RESPONSE_INVALID")
        return BackupExecutionResult(
            rpo_seconds=rpo,
            rto_seconds=rto,
            manifest_sha256=manifest,
            component_hashes=tuple(components),
        )


class UnavailableBackupExecutor:
    """Reject backup and restore instead of manufacturing verification evidence."""

    def backup(self, record: BackupRecord) -> BackupExecutionResult:
        del record
        raise RuntimeError("backup executor is unavailable")

    def restore(self, record: BackupRecord) -> BackupExecutionResult:
        del record
        raise RuntimeError("backup executor is unavailable")


class ArtifactStoreBackupExecutor:
    """Persist verified backup record snapshots through the artifact port."""

    def __init__(self, process: PinnedJsonProcess, store: object, scopes: object) -> None:
        self._executor = SubprocessBackupExecutor(process)
        if not all(callable(getattr(store, name, None)) for name in ("put", "get", "list")):
            raise TypeError("backup artifact store is invalid")
        if not callable(getattr(scopes, "repository", None)):
            raise TypeError("backup scope repository is invalid")
        self._store = store
        self._scopes = scopes

    def backup(self, record: BackupRecord) -> BackupExecutionResult:
        return self._executor.backup(record)

    def restore(self, record: BackupRecord) -> BackupExecutionResult:
        self.load_backed_up_record(record)
        return self._executor.restore(record)

    def recover_transition(
        self, expected: BackupRecord, *, operation: str
    ) -> BackupRecord | None:
        validate_backup_record(expected)
        if operation not in {"backup", "restore"}:
            raise SubprocessProtocolError("BACKUP_TRANSITION_INVALID")
        repository_id = self._repository_id(expected)
        target_state = "BACKED_UP" if operation == "backup" else "RESTORED"
        target_version = expected.version + 1
        now = datetime.now(tz=timezone.utc)
        recovered: BackupRecord | None = None
        for metadata in self._store.list(
            tenant_id=expected.tenant_id, run_id=expected.backup_id
        ):
            if metadata.purpose == _SNAPSHOT_PURPOSE:
                continue
            if (
                metadata.tenant_id != expected.tenant_id
                or metadata.repository_id != repository_id
                or metadata.run_id != expected.backup_id
                or metadata.content_class != "DC2_CONFIDENTIAL_SECURITY"
                or metadata.purpose != "backup-record"
                or metadata.execution_identity_hash != _record_identity(expected)
                or metadata.size_bytes > 1_048_576
                or metadata.created_at > now
                or metadata.expires_at is None
                or metadata.expires_at <= now
            ):
                raise SubprocessProtocolError("BACKUP_RECORD_SCOPE_INVALID")
            stored_metadata, chunks = self._store.get(
                tenant_id=expected.tenant_id,
                content_sha256=metadata.content_sha256,
            )
            if stored_metadata != metadata:
                raise SubprocessProtocolError("BACKUP_RECORD_INVALID")
            payload = b"".join(chunks)
            if len(payload) > 1_048_576 or len(payload) != metadata.size_bytes:
                raise SubprocessProtocolError("BACKUP_RECORD_INVALID")
            text = payload.decode("utf-8")
            stored = deserialize_backup_record(text)
            if (
                stored.tenant_id != expected.tenant_id
                or stored.backup_id != expected.backup_id
                or stored.state not in {"BACKED_UP", "RESTORED"}
                or stored.completed_at is None
                or _record_identity(stored) != metadata.execution_identity_hash
                or metadata.created_at
                != datetime.fromtimestamp(stored.completed_at, tz=timezone.utc)
                or metadata.expires_at
                != datetime.fromtimestamp(stored.completed_at, tz=timezone.utc)
                + timedelta(days=90)
                or serialize_backup_record(stored) != text
            ):
                raise SubprocessProtocolError("BACKUP_RECORD_INVALID")
            if stored.state != target_state or stored.version != target_version:
                continue
            if (
                stored.component_hashes != expected.component_hashes
                or stored.region != expected.region
                or stored.encryption_key_ref != expected.encryption_key_ref
                or stored.manifest_sha256 != expected.manifest_sha256
                or not stored.backup_verified
                or (operation == "backup" and stored.rto_seconds is not None)
                or (operation == "restore" and not stored.restore_verified)
            ):
                raise SubprocessProtocolError("BACKUP_RECORD_CONFLICT")
            if recovered is not None and recovered != stored:
                raise SubprocessProtocolError("BACKUP_RECORD_CONFLICT")
            recovered = stored
        return recovered

    def persist_record(self, record: BackupRecord) -> None:
        validate_backup_record(record)
        if record.state not in {"BACKED_UP", "RESTORED"} or record.completed_at is None:
            raise SubprocessProtocolError("BACKUP_RECORD_INVALID")
        repository_id = self._repository_id(record)
        payload = serialize_backup_record(record).encode("utf-8")
        digest = hashlib.sha256(payload).hexdigest()
        created_at = datetime.fromtimestamp(record.completed_at, tz=timezone.utc)
        metadata = ArtifactMetadata(
            tenant_id=record.tenant_id,
            repository_id=repository_id,
            run_id=record.backup_id,
            execution_identity_hash=_record_identity(record),
            content_sha256=digest,
            size_bytes=len(payload),
            content_class="DC2_CONFIDENTIAL_SECURITY",
            purpose="backup-record",
            created_at=created_at,
            expires_at=created_at + timedelta(days=90),
        )
        try:
            self._store.put(
                metadata,
                (payload,),
                hashlib.sha256(
                    f"backup-record:{record.tenant_id}:{record.backup_id}:{record.version}".encode(
                        "utf-8"
                    )
                ).hexdigest(),
            )
        except (ArtifactConflict, OSError, ValueError) as error:
            raise SubprocessProtocolError("BACKUP_RECORD_STORAGE_FAILED") from error

    def load_backed_up_record(self, expected: BackupRecord) -> BackupRecord:
        validate_backup_record(expected)
        if expected.state != "BACKED_UP":
            raise SubprocessProtocolError("BACKUP_RECORD_INVALID")
        try:
            candidates = self._store.list(
                tenant_id=expected.tenant_id, run_id=expected.backup_id
            )
            if not candidates:
                raise SubprocessProtocolError("BACKUP_RECORD_MISSING")
            repository_id = self._repository_id(expected)
            expected_payload = serialize_backup_record(expected)
            matched = False
            for metadata in candidates:
                if metadata.purpose == _SNAPSHOT_PURPOSE:
                    continue
                if (
                    metadata.tenant_id != expected.tenant_id
                    or metadata.repository_id != repository_id
                    or metadata.run_id != expected.backup_id
                    or metadata.content_class != "DC2_CONFIDENTIAL_SECURITY"
                    or metadata.purpose != "backup-record"
                    or metadata.execution_identity_hash != _record_identity(expected)
                ):
                    raise SubprocessProtocolError("BACKUP_RECORD_SCOPE_INVALID")
                now = datetime.now(tz=timezone.utc)
                if (
                    metadata.size_bytes > 1_048_576
                    or metadata.created_at > now
                    or metadata.expires_at is None
                    or metadata.expires_at <= now
                ):
                    raise SubprocessProtocolError("BACKUP_RECORD_INVALID")
                stored_metadata, chunks = self._store.get(
                    tenant_id=expected.tenant_id,
                    content_sha256=metadata.content_sha256,
                )
                if stored_metadata != metadata:
                    raise SubprocessProtocolError("BACKUP_RECORD_INVALID")
                payload = b"".join(chunks)
                if len(payload) > 1_048_576 or len(payload) != metadata.size_bytes:
                    raise SubprocessProtocolError("BACKUP_RECORD_INVALID")
                stored = deserialize_backup_record(payload.decode("utf-8"))
                if (
                    stored.state not in {"BACKED_UP", "RESTORED"}
                    or stored.tenant_id != expected.tenant_id
                    or stored.backup_id != expected.backup_id
                    or _record_identity(stored) != metadata.execution_identity_hash
                    or stored.completed_at is None
                    or metadata.created_at
                    != datetime.fromtimestamp(stored.completed_at, tz=timezone.utc)
                    or metadata.expires_at
                    != datetime.fromtimestamp(stored.completed_at, tz=timezone.utc)
                    + timedelta(days=90)
                    or serialize_backup_record(stored) != payload.decode("utf-8")
                ):
                    raise SubprocessProtocolError("BACKUP_RECORD_INVALID")
                matched = matched or serialize_backup_record(stored) == expected_payload
            if not matched:
                raise SubprocessProtocolError("BACKUP_RECORD_CONFLICT")
        except (ArtifactConflict, BackupConflict, OSError, UnicodeError, ValueError) as error:
            raise SubprocessProtocolError("BACKUP_RECORD_INVALID") from error
        return expected

    def _repository_id(self, record: BackupRecord) -> str:
        repository_id = self._scopes.repository(
            tenant_id=record.tenant_id, backup_id=record.backup_id
        )
        if type(repository_id) is not str or not repository_id:
            raise SubprocessProtocolError("BACKUP_RECORD_SCOPE_MISSING")
        return repository_id


class SqliteBackupExecutor(ArtifactStoreBackupExecutor):
    """Create and verify local SQLite snapshots without a helper process.

    The snapshot is kept in the already tenant-namespaced backup artifact
    store. Restore writes only application tables from the verified snapshot;
    the backup control tables remain live so the in-flight restore can commit
    its durable state transition and idempotency record. The fallback supports
    exactly one component, whose digest must be the actual plaintext SQLite
    snapshot digest in the requested record. Other component topologies fail
    closed and require the pinned external executor.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        store: object,
        scopes: object,
        encryption: object,
    ) -> None:
        if type(connection) is not sqlite3.Connection:
            raise TypeError("backup database is invalid")
        if not all(callable(getattr(store, name, None)) for name in ("put", "get", "list")):
            raise TypeError("backup artifact store is invalid")
        if not callable(getattr(scopes, "repository", None)):
            raise TypeError("backup scope repository is invalid")
        if not all(
            callable(getattr(encryption, name, None)) for name in ("encrypt", "decrypt")
        ):
            raise TypeError("backup encryption provider is unavailable")
        self._db = connection
        self._store = store
        self._scopes = scopes
        self._encryption = encryption

    def recover_transition(
        self, expected: BackupRecord, *, operation: str
    ) -> BackupRecord | None:
        """Recover only a transition whose durable evidence is sufficient.

        A backup snapshot proves that the backup artifact exists.  It does not
        prove that a restore changed the target database.  Restore recovery is
        therefore driven by the phase row written atomically with the target
        tables, rather than by inspecting the snapshot or a record artifact.
        An ``IN_PROGRESS`` or missing phase remains indeterminate and is
        intentionally not replayed after restart.
        """

        if operation == "restore":
            self._require_operation(expected, operation)
            phase = self._read_restore_phase(expected)
            if phase is None:
                return None
            if phase.phase != "APPLIED":
                raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_IN_PROGRESS")
            assert phase.rto_seconds is not None
            assert phase.applied_at is not None
            return replace(
                expected,
                version=expected.version + 1,
                state="RESTORED",
                rpo_seconds=phase.rpo_seconds,
                rto_seconds=phase.rto_seconds,
                backup_verified=True,
                restore_verified=True,
                completed_at=phase.applied_at,
            )
        if operation != "backup":
            return super().recover_transition(expected, operation=operation)
        self._require_operation(expected, "backup")
        _require_database_scope(
            self._db,
            expected,
            self._repository_id(expected),
            excluded_tables=_OIDC_SYSTEM_TABLES,
        )
        payload = self._load_snapshot(expected)
        self._verified_components(expected, payload)
        completed_at = max(expected.created_at, int(time.time()))
        return replace(
            expected,
            version=expected.version + 1,
            state="BACKED_UP",
            rpo_seconds=0,
            rto_seconds=None,
            backup_verified=True,
            restore_verified=False,
            completed_at=completed_at,
        )

    def backup(self, record: BackupRecord) -> BackupExecutionResult:
        started = time.monotonic_ns()
        self._require_operation(record, "backup")
        payload = self._snapshot(record)
        component_hashes = self._verified_components(record, payload)
        self._persist_snapshot(record, payload)
        return self._result(record, component_hashes, started)

    def restore(self, record: BackupRecord) -> BackupExecutionResult:
        started = time.monotonic_ns()
        self._require_operation(record, "restore")
        self.load_backed_up_record(record)
        phase = self._read_restore_phase(record)
        if phase is not None:
            if phase.phase == "APPLIED":
                return self._result_from_phase(record, phase)
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_IN_PROGRESS")
        payload = self._load_snapshot(record)
        component_hashes = self._verified_components(record, payload)
        self._restore(payload, record, started)
        phase = self._read_restore_phase(record)
        if phase is None or phase.phase != "APPLIED":
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")
        if phase.rpo_seconds != 0 or phase.rto_seconds is None:
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")
        if component_hashes != record.component_hashes:
            raise SubprocessProtocolError("BACKUP_COMPONENTS_UNVERIFIED")
        return self._result_from_phase(record, phase)

    def _require_operation(self, record: BackupRecord, operation: str) -> None:
        if not isinstance(record, BackupRecord) or operation not in {"backup", "restore"}:
            raise SubprocessProtocolError("BACKUP_REQUEST_INVALID")
        try:
            validate_backup_record(record)
        except (BackupConflict, TypeError, ValueError):
            raise SubprocessProtocolError("BACKUP_REQUEST_INVALID") from None
        if record.manifest_sha256 is None:
            raise SubprocessProtocolError("BACKUP_MANIFEST_MISSING")
        if operation == "backup" and record.state != "PLANNED":
            raise SubprocessProtocolError("BACKUP_REQUEST_INVALID")
        if operation == "restore" and (
            record.state != "BACKED_UP" or not record.backup_verified
        ):
            raise SubprocessProtocolError("BACKUP_REQUEST_INVALID")

    def _snapshot(self, record: BackupRecord) -> bytes:
        if self._db.in_transaction:
            raise SubprocessProtocolError("BACKUP_SNAPSHOT_BUSY")
        _require_database_scope(
            self._db,
            record,
            self._repository_id(record),
            excluded_tables=_OIDC_SYSTEM_TABLES,
        )
        source = sqlite3.connect(":memory:")
        try:
            self._db.backup(source)
            _strip_oidc_system_state(source)
            _require_database_scope(
                source,
                record,
                self._repository_id(record),
                excluded_tables=_OIDC_SYSTEM_TABLES,
                require_excluded_empty=True,
            )
            payload = ("\n".join(source.iterdump()) + "\n").encode("utf-8")
        except (sqlite3.Error, UnicodeError, ValueError) as error:
            raise SubprocessProtocolError("BACKUP_SNAPSHOT_FAILED") from error
        finally:
            source.close()
        if not payload or len(payload) > _MAX_SNAPSHOT_BYTES:
            raise SubprocessProtocolError("BACKUP_SNAPSHOT_TOO_LARGE")
        return payload

    def _persist_snapshot(self, record: BackupRecord, payload: bytes) -> None:
        repository_id = self._repository_id(record)
        encrypted = self._encrypt(payload, record.encryption_key_ref)
        digest = hashlib.sha256(encrypted).hexdigest()
        now = datetime.now(tz=timezone.utc)
        metadata = ArtifactMetadata(
            tenant_id=record.tenant_id,
            repository_id=repository_id,
            run_id=record.backup_id,
            execution_identity_hash=_record_identity(record),
            content_sha256=digest,
            size_bytes=len(encrypted),
            content_class="DC2_CONFIDENTIAL_SECURITY",
            purpose=_SNAPSHOT_PURPOSE,
            created_at=now,
            expires_at=now + timedelta(days=_SNAPSHOT_RETENTION_DAYS),
        )
        existing = self._snapshot_metadata(record)
        if existing is not None:
            stored_metadata, chunks = self._store.get(
                tenant_id=record.tenant_id,
                content_sha256=existing.content_sha256,
            )
            stored = b"".join(chunks)
            if stored_metadata != existing or stored != encrypted:
                raise SubprocessProtocolError("BACKUP_SNAPSHOT_CONFLICT")
            return
        try:
            self._store.put(
                metadata,
                (encrypted,),
                hashlib.sha256(
                    f"backup-snapshot:{record.tenant_id}:{record.backup_id}:{digest}".encode(
                        "utf-8"
                    )
                ).hexdigest(),
            )
        except (ArtifactConflict, OSError, ValueError) as error:
            raise SubprocessProtocolError("BACKUP_SNAPSHOT_STORAGE_FAILED") from error

    def _load_snapshot(self, record: BackupRecord) -> bytes:
        metadata = self._snapshot_metadata(record)
        if metadata is None:
            raise SubprocessProtocolError("BACKUP_SNAPSHOT_MISSING")
        try:
            stored_metadata, chunks = self._store.get(
                tenant_id=record.tenant_id,
                content_sha256=metadata.content_sha256,
            )
            payload = b"".join(chunks)
        except (ArtifactConflict, OSError, ValueError) as error:
            raise SubprocessProtocolError("BACKUP_SNAPSHOT_INVALID") from error
        if (
            stored_metadata != metadata
            or len(payload) != metadata.size_bytes
            or len(payload) > _MAX_SNAPSHOT_BYTES * 2
            or hashlib.sha256(payload).hexdigest() != metadata.content_sha256
        ):
            raise SubprocessProtocolError("BACKUP_SNAPSHOT_INVALID")
        return self._decrypt(payload, record.encryption_key_ref)

    def _encrypt(self, payload: bytes, key_ref: str) -> bytes:
        try:
            encrypted = self._encryption.encrypt(payload, key_ref)
        except Exception as error:
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_FAILED") from error
        if (
            type(encrypted) is not bytes
            or not encrypted
            or len(encrypted) > _MAX_SNAPSHOT_BYTES * 2
            or encrypted == payload
        ):
            raise SubprocessProtocolError("BACKUP_ENCRYPTION_INVALID")
        return encrypted

    def _decrypt(self, payload: bytes, key_ref: str) -> bytes:
        try:
            decrypted = self._encryption.decrypt(payload, key_ref)
        except Exception as error:
            raise SubprocessProtocolError("BACKUP_DECRYPTION_FAILED") from error
        if type(decrypted) is not bytes or not decrypted or len(decrypted) > _MAX_SNAPSHOT_BYTES:
            raise SubprocessProtocolError("BACKUP_DECRYPTION_INVALID")
        return decrypted

    def _snapshot_metadata(self, record: BackupRecord) -> ArtifactMetadata | None:
        repository_id = self._repository_id(record)
        now = datetime.now(tz=timezone.utc)
        found: ArtifactMetadata | None = None
        try:
            candidates = self._store.list(
                tenant_id=record.tenant_id, run_id=record.backup_id
            )
            for metadata in candidates:
                if metadata.purpose != _SNAPSHOT_PURPOSE:
                    continue
                if (
                    metadata.tenant_id != record.tenant_id
                    or metadata.repository_id != repository_id
                    or metadata.run_id != record.backup_id
                    or metadata.content_class != "DC2_CONFIDENTIAL_SECURITY"
                    or metadata.execution_identity_hash != _record_identity(record)
                    or metadata.size_bytes > _MAX_SNAPSHOT_BYTES * 2
                    or metadata.created_at
                    < datetime.fromtimestamp(record.created_at, tz=timezone.utc)
                    or metadata.created_at > now
                    or metadata.expires_at is None
                    or metadata.expires_at
                    != metadata.created_at + timedelta(days=_SNAPSHOT_RETENTION_DAYS)
                    or metadata.expires_at <= now
                ):
                    raise SubprocessProtocolError("BACKUP_SNAPSHOT_SCOPE_INVALID")
                if found is not None and found != metadata:
                    raise SubprocessProtocolError("BACKUP_SNAPSHOT_CONFLICT")
                found = metadata
        except (ArtifactConflict, OSError, ValueError) as error:
            raise SubprocessProtocolError("BACKUP_SNAPSHOT_INVALID") from error
        return found

    def _restore(
        self, payload: bytes, record: BackupRecord, started: int
    ) -> int:
        source = sqlite3.connect(":memory:")
        try:
            source.executescript(payload.decode("utf-8"))
            if source.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise SubprocessProtocolError("BACKUP_SNAPSHOT_INVALID")
            return self._restore_tables(source, record, started)
        except (sqlite3.Error, UnicodeError, ValueError) as error:
            if isinstance(error, SubprocessProtocolError):
                raise
            raise SubprocessProtocolError("BACKUP_RESTORE_FAILED") from error
        finally:
            source.close()

    def _restore_tables(
        self, source: sqlite3.Connection, record: BackupRecord, started: int
    ) -> int:
        if self._db.in_transaction:
            raise SubprocessProtocolError("BACKUP_RESTORE_BUSY")
        source_tables = _table_names(source)
        target_tables = _table_names(self._db)
        repository_id = self._repository_id(record)
        _require_database_scope(
            source,
            record,
            repository_id,
            excluded_tables=_OIDC_SYSTEM_TABLES,
            require_excluded_empty=True,
        )
        _require_database_scope(
            self._db,
            record,
            repository_id,
            excluded_tables=_OIDC_SYSTEM_TABLES,
        )
        source_application_tables = source_tables - _CONTROL_TABLES
        target_application_tables = target_tables - _CONTROL_TABLES
        if source_application_tables != target_application_tables:
            raise SubprocessProtocolError("BACKUP_SCHEMA_CONFLICT")
        tables = sorted(target_application_tables)
        for table in tables:
            if table not in source_tables:
                continue
            if _table_shape(source, table) != _table_shape(self._db, table):
                raise SubprocessProtocolError("BACKUP_SCHEMA_CONFLICT")
            if _table_columns(source, table) != _table_columns(self._db, table):
                raise SubprocessProtocolError("BACKUP_SCHEMA_CONFLICT")
        phase, created = self._begin_restore_phase(record)
        if phase.phase == "APPLIED":
            assert phase.rto_seconds is not None
            return phase.rto_seconds
        if not created:
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_IN_PROGRESS")
        try:
            self._db.execute("PRAGMA foreign_keys=OFF")
            self._db.execute("BEGIN EXCLUSIVE")
            _require_database_scope(
                self._db,
                record,
                repository_id,
                excluded_tables=_OIDC_SYSTEM_TABLES,
            )
            locked_target_tables = _table_names(self._db)
            if locked_target_tables - _CONTROL_TABLES != target_application_tables:
                raise SubprocessProtocolError("BACKUP_SCHEMA_CONFLICT")
            for table in tables:
                if table in _OIDC_SYSTEM_TABLES:
                    # Global OIDC state belongs to the running control plane.
                    # A tenant restore must not delete or import it.
                    continue
                self._db.execute(f"DELETE FROM {_quote_identifier(table)}")
                if table not in source_tables:
                    continue
                if _table_shape(source, table) != _table_shape(self._db, table):
                    raise SubprocessProtocolError("BACKUP_SCHEMA_CONFLICT")
                source_columns = _table_columns(source, table)
                target_columns = _table_columns(self._db, table)
                if source_columns != target_columns:
                    raise SubprocessProtocolError("BACKUP_SCHEMA_CONFLICT")
                rows = source.execute(f"SELECT * FROM {_quote_identifier(table)}")
                placeholders = ",".join("?" for _ in target_columns)
                self._db.executemany(
                    f"INSERT INTO {_quote_identifier(table)} VALUES ({placeholders})",
                    (tuple(row) for row in rows),
                )
            if self._db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise SubprocessProtocolError("BACKUP_RESTORE_INTEGRITY_FAILED")
            if self._db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise SubprocessProtocolError("BACKUP_RESTORE_FOREIGN_KEY_FAILED")
            elapsed = time.monotonic_ns() - started
            if type(elapsed) is not int or elapsed < 0:
                raise SubprocessProtocolError("BACKUP_CLOCK_INVALID")
            rto_seconds = elapsed // 1_000_000_000
            try:
                applied_at = max(record.created_at, int(time.time()))
            except (OverflowError, TypeError, ValueError):
                raise SubprocessProtocolError("BACKUP_CLOCK_INVALID") from None
            self._mark_restore_applied(record, rto_seconds, applied_at)
            self._db.commit()
            return rto_seconds
        except Exception:
            self._db.rollback()
            raise
        finally:
            self._db.execute("PRAGMA foreign_keys=ON")

    def _begin_restore_phase(
        self, record: BackupRecord
    ) -> tuple[_RestorePhase, bool]:
        """Durably mark a restore before any application table is changed."""

        self._validate_restore_phase_record(record)
        if self._db.in_transaction:
            raise SubprocessProtocolError("BACKUP_RESTORE_BUSY")
        try:
            self._db.execute("BEGIN IMMEDIATE")
            existing = self._read_restore_phase(record)
            if existing is not None:
                self._db.commit()
                return existing, False
            self._db.execute(
                """INSERT INTO backup_restore_phases (
                       tenant_id, backup_id, expected_version, request_sha256,
                       phase, manifest_sha256, component_hashes_json,
                       rpo_seconds, rto_seconds, applied_at
                   ) VALUES (?, ?, ?, ?, 'IN_PROGRESS', ?, ?, 0, NULL, NULL)""",
                (
                    record.tenant_id,
                    record.backup_id,
                    record.version,
                    _restore_request_hash(record),
                    record.manifest_sha256,
                    _component_hashes_json(record),
                ),
            )
            self._db.commit()
            return _RestorePhase("IN_PROGRESS", 0, None, None), True
        except SubprocessProtocolError:
            self._db.rollback()
            raise
        except (sqlite3.Error, TypeError, ValueError) as error:
            self._db.rollback()
            raise SubprocessProtocolError(
                "BACKUP_RESTORE_PHASE_STORAGE_FAILED"
            ) from error

    def _mark_restore_applied(
        self, record: BackupRecord, rto_seconds: int, applied_at: int
    ) -> None:
        if (
            type(rto_seconds) is not int
            or not 0 <= rto_seconds <= 315_360_000
            or type(applied_at) is not int
            or applied_at < record.created_at
        ):
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")
        phase = self._read_restore_phase(record)
        if phase is None or phase.phase != "IN_PROGRESS":
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")
        cursor = self._db.execute(
            """UPDATE backup_restore_phases
               SET phase='APPLIED', rto_seconds=?, applied_at=?
               WHERE tenant_id=? AND backup_id=? AND expected_version=?
                 AND request_sha256=? AND phase='IN_PROGRESS'""",
            (
                rto_seconds,
                applied_at,
                record.tenant_id,
                record.backup_id,
                record.version,
                _restore_request_hash(record),
            ),
        )
        if cursor.rowcount != 1:
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")

    def _read_restore_phase(self, record: BackupRecord) -> _RestorePhase | None:
        self._validate_restore_phase_record(record)
        try:
            row = self._db.execute(
                """SELECT request_sha256, phase, manifest_sha256,
                          component_hashes_json, rpo_seconds, rto_seconds,
                          applied_at
                   FROM backup_restore_phases
                   WHERE tenant_id=? AND backup_id=? AND expected_version=?""",
                (record.tenant_id, record.backup_id, record.version),
            ).fetchone()
        except sqlite3.Error as error:
            raise SubprocessProtocolError(
                "BACKUP_RESTORE_PHASE_STORAGE_FAILED"
            ) from error
        if row is None:
            return None
        request_sha256, phase, manifest, components_json, rpo, rto, applied_at = row
        if (
            request_sha256 != _restore_request_hash(record)
            or phase not in {"IN_PROGRESS", "APPLIED"}
            or manifest != record.manifest_sha256
            or type(components_json) is not str
            or components_json != _component_hashes_json(record)
            or type(rpo) is not int
            or rpo != 0
        ):
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")
        try:
            components = json.loads(components_json)
        except (TypeError, ValueError):
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID") from None
        if type(components) is not list or tuple(components) != record.component_hashes:
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")
        if phase == "IN_PROGRESS":
            if rto is not None or applied_at is not None:
                raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")
            return _RestorePhase(phase, rpo, None, None)
        if (
            type(rto) is not int
            or not 0 <= rto <= 315_360_000
            or type(applied_at) is not int
            or applied_at < record.created_at
        ):
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")
        return _RestorePhase(phase, rpo, rto, applied_at)

    @staticmethod
    def _validate_restore_phase_record(record: BackupRecord) -> None:
        if (
            record.manifest_sha256 is None
            or record.manifest_sha256 != manifest_sha256(record)
        ):
            raise SubprocessProtocolError("BACKUP_MANIFEST_INVALID")

    @staticmethod
    def _result_from_phase(
        record: BackupRecord, phase: _RestorePhase
    ) -> BackupExecutionResult:
        if phase.phase != "APPLIED" or phase.rto_seconds is None:
            raise SubprocessProtocolError("BACKUP_RESTORE_PHASE_INVALID")
        assert record.manifest_sha256 is not None
        return BackupExecutionResult(
            rpo_seconds=phase.rpo_seconds,
            rto_seconds=phase.rto_seconds,
            manifest_sha256=record.manifest_sha256,
            component_hashes=record.component_hashes,
        )

    @staticmethod
    def _verified_components(
        record: BackupRecord, payload: bytes
    ) -> tuple[str, ...]:
        if record.manifest_sha256 is None or manifest_sha256(record) != record.manifest_sha256:
            raise SubprocessProtocolError("BACKUP_MANIFEST_INVALID")
        digest = hashlib.sha256(payload).hexdigest()
        components = (digest,)
        if record.component_hashes != components:
            raise SubprocessProtocolError("BACKUP_COMPONENTS_UNVERIFIED")
        return components

    @staticmethod
    def _result(
        record: BackupRecord,
        component_hashes: tuple[str, ...],
        started: int,
    ) -> BackupExecutionResult:
        assert record.manifest_sha256 is not None
        elapsed = time.monotonic_ns() - started
        if type(elapsed) is not int or elapsed < 0:
            raise SubprocessProtocolError("BACKUP_CLOCK_INVALID")
        rto = elapsed // 1_000_000_000
        return BackupExecutionResult(
            rpo_seconds=0,
            rto_seconds=rto,
            manifest_sha256=record.manifest_sha256,
            component_hashes=component_hashes,
        )


def _table_names(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    names = {row[0] for row in rows}
    if any(type(name) is not str or not name for name in names):
        raise SubprocessProtocolError("BACKUP_SCHEMA_INVALID")
    return names


def _table_columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    rows = connection.execute(f"PRAGMA table_info({_quote_identifier(table)})").fetchall()
    columns = tuple(row[1] for row in rows)
    if not columns or any(type(name) is not str or not name for name in columns):
        raise SubprocessProtocolError("BACKUP_SCHEMA_INVALID")
    return columns


def _require_database_scope(
    connection: sqlite3.Connection,
    record: BackupRecord,
    repository_id: str,
    *,
    excluded_tables: frozenset[str] = frozenset(),
    require_excluded_empty: bool = False,
) -> None:
    """Refuse a full-database backup unless its contents have one scope.

    ``SqliteBackupExecutor`` currently serializes the whole SQLite database,
    while its control-plane contract binds a backup to one tenant and one
    repository.  Restoring such a snapshot into a shared database would
    delete or replace another tenant's rows.  Until a row-filtered snapshot
    format exists, a populated database is accepted only when every persisted
    row is tenant-bound to the requested tenant and every repository-bearing
    row names the requested repository.  Unknown global tables fail closed.
    """

    if type(connection) is not sqlite3.Connection:
        raise SubprocessProtocolError("BACKUP_SCOPE_INVALID")
    if not isinstance(record, BackupRecord):
        raise SubprocessProtocolError("BACKUP_SCOPE_INVALID")
    if type(repository_id) is not str or not repository_id:
        raise SubprocessProtocolError("BACKUP_SCOPE_INVALID")
    if type(excluded_tables) is not frozenset or not excluded_tables.issubset(
        _OIDC_SYSTEM_TABLES
    ):
        raise SubprocessProtocolError("BACKUP_SCOPE_INVALID")
    if type(require_excluded_empty) is not bool:
        raise SubprocessProtocolError("BACKUP_SCOPE_INVALID")
    tables = _table_names(connection) - _CONTROL_TABLES
    for table, expected_columns in _OIDC_SYSTEM_TABLE_SHAPES:
        if table not in excluded_tables:
            continue
        if table not in tables or _table_columns(connection, table) != expected_columns:
            raise SubprocessProtocolError("BACKUP_SCHEMA_INVALID")
        if (
            require_excluded_empty
            and connection.execute(f"SELECT 1 FROM {_quote_identifier(table)} LIMIT 1").fetchone()
            is not None
        ):
            raise SubprocessProtocolError("BACKUP_SCOPE_UNVERIFIABLE")
    observed_repositories: set[str] = set()
    has_tenant_rows = False
    for table in sorted(tables - excluded_tables):
        columns = _table_columns(connection, table)
        quoted = _quote_identifier(table)
        if "tenant_id" not in columns:
            if table in _GLOBAL_SCOPE_TABLES:
                continue
            if connection.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone() is not None:
                raise SubprocessProtocolError("BACKUP_SCOPE_UNVERIFIABLE")
            continue
        tenants = _distinct_scope_values(connection, table, "tenant_id")
        if not tenants:
            continue
        has_tenant_rows = True
        if tenants != {record.tenant_id}:
            raise SubprocessProtocolError("BACKUP_SCOPE_CONFLICT")
        if "repository_id" not in columns:
            continue
        repositories = _distinct_scope_values(connection, table, "repository_id")
        if repositories != {repository_id}:
            raise SubprocessProtocolError("BACKUP_SCOPE_CONFLICT")
        observed_repositories.update(repositories)
    if has_tenant_rows and observed_repositories != {repository_id}:
        raise SubprocessProtocolError("BACKUP_SCOPE_UNVERIFIABLE")


def _strip_oidc_system_state(connection: sqlite3.Connection) -> None:
    """Remove process-wide OIDC rows from a tenant snapshot staging database.

    The source database is an isolated in-memory copy.  The live control-plane
    connection is never modified.  Table names and shapes are checked before
    deletion so a future schema drift cannot turn this into an arbitrary table
    filter.  A separate system-scoped backup contract is required to restore
    these rows; tenant backup artifacts intentionally do not contain them.
    """

    if type(connection) is not sqlite3.Connection:
        raise SubprocessProtocolError("BACKUP_SCOPE_INVALID")
    tables = _table_names(connection)
    for table, expected_columns in _OIDC_SYSTEM_TABLE_SHAPES:
        if table not in tables or _table_columns(connection, table) != expected_columns:
            raise SubprocessProtocolError("BACKUP_SCHEMA_INVALID")
    try:
        for table in sorted(_OIDC_SYSTEM_TABLES):
            connection.execute(f"DELETE FROM {_quote_identifier(table)}")
        connection.commit()
    except sqlite3.Error as error:
        raise SubprocessProtocolError("BACKUP_SCOPE_UNVERIFIABLE") from error


def _distinct_scope_values(
    connection: sqlite3.Connection,
    table: str,
    column: str,
) -> set[str]:
    quoted_table = _quote_identifier(table)
    quoted_column = _quote_identifier(column)
    row = connection.execute(
        f"SELECT COUNT(*), COUNT({quoted_column}), "
        f"COUNT(DISTINCT {quoted_column}), MIN({quoted_column}) "
        f"FROM {quoted_table}"
    ).fetchone()
    if row is None or any(type(row[index]) is not int for index in range(3)):
        raise SubprocessProtocolError("BACKUP_SCOPE_INVALID")
    total, non_null, distinct, minimum = row
    if total == 0:
        return set()
    if non_null != total or distinct != 1 or type(minimum) is not str or not minimum:
        raise SubprocessProtocolError("BACKUP_SCOPE_INVALID")
    return {minimum}


def _table_shape(
    connection: sqlite3.Connection, table: str
) -> tuple[tuple[object, ...], ...]:
    rows = connection.execute(f"PRAGMA table_info({_quote_identifier(table)})").fetchall()
    shape = tuple(tuple(row[index] for index in range(1, 6)) for row in rows)
    if not shape or any(
        type(row[0]) is not str
        or not row[0]
        or type(row[1]) is not str
        or type(row[2]) is not int
        or type(row[3]) is not int
        or type(row[4]) not in {str, type(None)}
        or type(row[5]) is not int
        for row in shape
    ):
        raise SubprocessProtocolError("BACKUP_SCHEMA_INVALID")
    return shape


def _quote_identifier(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise SubprocessProtocolError("BACKUP_SCHEMA_INVALID")
    return '"' + value.replace('"', '""') + '"'


def _record_identity(record: BackupRecord) -> str:
    if record.manifest_sha256 is None:
        raise SubprocessProtocolError("BACKUP_MANIFEST_MISSING")
    identity = f"backup-record-v1\0{record.tenant_id}\0{record.backup_id}\0{record.manifest_sha256}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _component_hashes_json(record: BackupRecord) -> str:
    return json.dumps(
        list(record.component_hashes),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    )


def _restore_request_hash(record: BackupRecord) -> str:
    return hashlib.sha256(
        f"restore\0{record.tenant_id}\0{record.backup_id}\0{record.version}".encode(
            "utf-8"
        )
    ).hexdigest()


def build_backup_executor(
    values: object, *, connection: sqlite3.Connection | None = None
) -> tuple[BackupExecutor, bool]:
    process = configured_process(values, prefix="SECURECODE_BACKUP_EXECUTOR")
    if isinstance(values, dict):
        store = values.get("_SECURECODE_INTERNAL_BACKUP_ARTIFACT_STORE")
        scopes = values.get("_SECURECODE_INTERNAL_BACKUP_SCOPE_REPOSITORY")
        encryption = values.get("_SECURECODE_INTERNAL_BACKUP_ENCRYPTION_PROVIDER")
        if process is not None and store is not None and scopes is not None:
            try:
                return ArtifactStoreBackupExecutor(process, store, scopes), True
            except TypeError:
                pass
        if process is None and encryption is None:
            encryption_process = configured_process(
                values, prefix="SECURECODE_BACKUP_ENCRYPTION"
            )
            if encryption_process is not None:
                encryption = SubprocessBackupEncryptionProvider(encryption_process)
        if (
            process is None
            and connection is not None
            and store is not None
            and scopes is not None
            and encryption is not None
        ):
            try:
                return SqliteBackupExecutor(connection, store, scopes, encryption), True
            except TypeError:
                pass
    return UnavailableBackupExecutor(), False


__all__ = [
    "BackupEncryptionProvider",
    "SubprocessBackupEncryptionProvider",
    "SubprocessBackupExecutor",
    "ArtifactStoreBackupExecutor",
    "SqliteBackupExecutor",
    "UnavailableBackupExecutor",
    "build_backup_executor",
]
