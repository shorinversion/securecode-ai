"""System-scoped backup and restore for process-wide OIDC state.

This module is intentionally separate from the tenant backup service.  The
payload contains only the OIDC state tables and is stored in a dedicated
filesystem namespace.  The caller is the local platform maintenance entry
point, not an authenticated tenant request.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, SupportsIndex, SupportsInt

from .backup_executor_runtime import _OIDC_SYSTEM_TABLE_SHAPES

_SCHEMA_VERSION: Final = 1
_SYSTEM_IDENTITY: Final = "securecode-platform-maintenance-v1"
_SYSTEM_NAMESPACE: Final = "oidc-v1"
_MAX_PAYLOAD_BYTES: Final = 67_108_864
_MAX_ENCRYPTED_BYTES: Final = _MAX_PAYLOAD_BYTES * 2
_MAX_ROWS_PER_TABLE: Final = 1_000_000
_BACKUP_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_KEY_REF_LIMIT: Final = 512


class SystemBackupError(RuntimeError):
    """The system backup is invalid, unavailable, or conflicts with a bundle."""


class SystemBackupEncryption(Protocol):
    """Host-owned authenticated encryption boundary."""

    def encrypt(self, payload: bytes, key_ref: str) -> bytes: ...

    def decrypt(self, payload: bytes, key_ref: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class SystemOidcBackupRecord:
    """Immutable metadata for one system OIDC bundle."""

    backup_id: str
    system_identity: str
    encryption_key_ref: str
    created_at: int
    plaintext_sha256: str
    encrypted_sha256: str
    size_bytes: int
    schema_sha256: str
    table_counts: tuple[tuple[str, int], ...]


class SystemOidcBackupRuntime:
    """Create and restore a dedicated bundle containing only OIDC tables."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        root: Path,
        encryption: SystemBackupEncryption,
    ) -> None:
        if type(connection) is not sqlite3.Connection:
            raise TypeError("system backup database is invalid")
        if not isinstance(root, Path) or not root.is_absolute():
            raise TypeError("system backup root is invalid")
        if not all(callable(getattr(encryption, name, None)) for name in ("encrypt", "decrypt")):
            raise TypeError("system backup encryption is unavailable")
        self._db = connection
        self._root = root / _SYSTEM_NAMESPACE
        self._encryption = encryption
        _ensure_directory_chain(self._root)

    @staticmethod
    def platform_identity() -> str:
        """Return the only identity accepted by the system maintenance path."""

        return _SYSTEM_IDENTITY

    def backup(self, backup_id: str, encryption_key_ref: str) -> SystemOidcBackupRecord:
        _validate_backup_id(backup_id)
        _validate_key_ref(encryption_key_ref)
        if self._db.in_transaction:
            raise SystemBackupError("SYSTEM_BACKUP_BUSY")
        try:
            self._db.execute("BEGIN EXCLUSIVE")
            payload, schema_digest, table_counts = _capture_payload(self._db)
            self._db.commit()
        except SystemBackupError:
            self._db.rollback()
            raise
        except (sqlite3.Error, TypeError, ValueError) as error:
            self._db.rollback()
            raise SystemBackupError("SYSTEM_BACKUP_CAPTURE_FAILED") from error
        if len(payload) > _MAX_PAYLOAD_BYTES:
            raise SystemBackupError("SYSTEM_BACKUP_TOO_LARGE")
        encrypted = _encrypt(self._encryption, payload, encryption_key_ref)
        created_at = int(time.time())
        record = SystemOidcBackupRecord(
            backup_id=backup_id,
            system_identity=_SYSTEM_IDENTITY,
            encryption_key_ref=encryption_key_ref,
            created_at=created_at,
            plaintext_sha256=_digest(payload),
            encrypted_sha256=_digest(encrypted),
            size_bytes=len(encrypted),
            schema_sha256=schema_digest,
            table_counts=table_counts,
        )
        return self._store_bundle(record, encrypted)

    def restore(self, backup_id: str) -> SystemOidcBackupRecord:
        _validate_backup_id(backup_id)
        if self._db.in_transaction:
            raise SystemBackupError("SYSTEM_RESTORE_BUSY")
        try:
            self._db.execute("BEGIN EXCLUSIVE")
            record, encrypted = self._load_bundle(backup_id)
            payload = _decrypt(self._encryption, encrypted, record.encryption_key_ref)
            if _digest(payload) != record.plaintext_sha256:
                raise SystemBackupError("SYSTEM_BACKUP_DIGEST_INVALID")
            document = _load_canonical_document(payload)
            schema_digest, table_counts = _validate_payload(document, self._db)
            if schema_digest != record.schema_sha256 or table_counts != record.table_counts:
                raise SystemBackupError("SYSTEM_BACKUP_MANIFEST_INVALID")
            _restore_monotonic_payload(self._db, document, now=int(time.time()))
            if self._db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise SystemBackupError("SYSTEM_RESTORE_INTEGRITY_FAILED")
            self._db.commit()
            return record
        except SystemBackupError:
            self._db.rollback()
            raise
        except (sqlite3.Error, TypeError, ValueError, UnicodeError) as error:
            self._db.rollback()
            raise SystemBackupError("SYSTEM_RESTORE_FAILED") from error

    def _store_bundle(
        self, record: SystemOidcBackupRecord, encrypted: bytes
    ) -> SystemOidcBackupRecord:
        payload_path = self._path(record.backup_id, ".payload")
        record_path = self._path(record.backup_id, ".json")
        document = _record_document(record)
        encoded_record = _canonical_json(document)
        existing_record = _existing_file(record_path, _MAX_PAYLOAD_BYTES)
        existing_payload = _existing_file(payload_path, _MAX_ENCRYPTED_BYTES)
        if existing_record is not None or existing_payload is not None:
            if existing_record is None and existing_payload is not None:
                # The payload is created before its sidecar.  A process crash
                # between those two atomic links leaves an otherwise
                # unrecoverable orphan. Reuse it only after authenticated
                # decryption and validation against the system schema.
                plaintext = _decrypt(self._encryption, existing_payload, record.encryption_key_ref)
                document = _load_canonical_document(plaintext)
                if _digest(plaintext) != _digest(_canonical_json(document)):
                    raise SystemBackupError("SYSTEM_BACKUP_DIGEST_INVALID")
                schema_digest, table_counts = _validate_payload(document, self._db)
                try:
                    details = payload_path.lstat()
                except OSError as error:
                    raise SystemBackupError("SYSTEM_BACKUP_STORAGE_UNAVAILABLE") from error
                if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
                    raise SystemBackupError("SYSTEM_BACKUP_STORAGE_INVALID")
                recovered = SystemOidcBackupRecord(
                    backup_id=record.backup_id,
                    system_identity=_SYSTEM_IDENTITY,
                    encryption_key_ref=record.encryption_key_ref,
                    created_at=max(0, int(details.st_mtime)),
                    plaintext_sha256=_digest(plaintext),
                    encrypted_sha256=_digest(existing_payload),
                    size_bytes=len(existing_payload),
                    schema_sha256=schema_digest,
                    table_counts=table_counts,
                )
                encoded_record = _canonical_json(_record_document(recovered))
                _atomic_create(record_path, encoded_record)
                return recovered
            if existing_record is None or existing_payload is None:
                raise SystemBackupError("SYSTEM_BACKUP_CONFLICT")
            try:
                stored = _record_from_document(_load_canonical_document(existing_record))
            except (SystemBackupError, ValueError, TypeError, UnicodeError):
                raise SystemBackupError("SYSTEM_BACKUP_INVALID") from None
            if (
                stored.backup_id != record.backup_id
                or stored.system_identity != record.system_identity
                or stored.encryption_key_ref != record.encryption_key_ref
                or stored.plaintext_sha256 != record.plaintext_sha256
                or stored.schema_sha256 != record.schema_sha256
                or stored.table_counts != record.table_counts
                or stored.encrypted_sha256 != _digest(existing_payload)
                or stored.size_bytes != len(existing_payload)
            ):
                raise SystemBackupError("SYSTEM_BACKUP_CONFLICT")
            self._require_matching_capture(record, existing_payload)
            return stored
        payload_creation = _atomic_create(payload_path, encrypted)
        try:
            _atomic_create(record_path, encoded_record)
        except Exception:
            # Another process may have completed the sidecar after observing
            # our payload. Never remove that process's completed bundle.
            if (
                payload_creation is not None
                and _existing_file(record_path, _MAX_PAYLOAD_BYTES) is None
            ):
                _remove_atomic_file(payload_path, payload_creation)
            raise
        return record

    def _require_matching_capture(self, record: SystemOidcBackupRecord, encrypted: bytes) -> None:
        plaintext = _decrypt(self._encryption, encrypted, record.encryption_key_ref)
        if _digest(plaintext) != record.plaintext_sha256:
            raise SystemBackupError("SYSTEM_BACKUP_CONFLICT")
        document = _load_canonical_document(plaintext)
        schema_digest, table_counts = _validate_payload(document, self._db)
        if schema_digest != record.schema_sha256 or table_counts != record.table_counts:
            raise SystemBackupError("SYSTEM_BACKUP_CONFLICT")

    def _load_bundle(self, backup_id: str) -> tuple[SystemOidcBackupRecord, bytes]:
        record_path = self._path(backup_id, ".json")
        payload_path = self._path(backup_id, ".payload")
        encoded_record = _existing_file(record_path, _MAX_PAYLOAD_BYTES)
        encrypted = _existing_file(payload_path, _MAX_ENCRYPTED_BYTES)
        if encoded_record is None or encrypted is None:
            raise SystemBackupError("SYSTEM_BACKUP_MISSING")
        try:
            record = _record_from_document(_load_canonical_document(encoded_record))
        except (SystemBackupError, ValueError, TypeError, UnicodeError):
            raise SystemBackupError("SYSTEM_BACKUP_INVALID") from None
        if (
            record.backup_id != backup_id
            or record.system_identity != _SYSTEM_IDENTITY
            or record.size_bytes != len(encrypted)
            or record.encrypted_sha256 != _digest(encrypted)
        ):
            raise SystemBackupError("SYSTEM_BACKUP_DIGEST_INVALID")
        return record, encrypted

    def _path(self, backup_id: str, suffix: str) -> Path:
        _validate_backup_id(backup_id)
        path = self._root / f"{backup_id}{suffix}"
        try:
            path.relative_to(self._root)
        except ValueError:
            raise SystemBackupError("SYSTEM_BACKUP_PATH_INVALID") from None
        return path


class SystemOidcBackupRetention:
    """Remove expired platform OIDC bundles without needing encryption keys."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path) or not root.is_absolute():
            raise TypeError("system backup root is invalid")
        self._root = root / _SYSTEM_NAMESPACE
        _ensure_directory_chain(self._root)

    def purge_expired(
        self,
        *,
        now: object,
        retention_days: object,
        max_items: object,
    ) -> tuple[int, bool]:
        if (
            type(now) is not int
            or now < 0
            or type(retention_days) is not int
            or not 1 <= retention_days <= 36_500
            or type(max_items) is not int
            or not 1 <= max_items <= 256
        ):
            raise SystemBackupError("SYSTEM_BACKUP_RETENTION_INVALID")
        cutoff = now - retention_days * 86_400
        try:
            names = tuple(entry.name for entry in self._root.iterdir())
        except OSError as error:
            raise SystemBackupError("SYSTEM_BACKUP_STORAGE_UNAVAILABLE") from error
        backup_ids = sorted(
            {
                name[: -len(suffix)]
                for name in names
                for suffix in (".json", ".payload")
                if name.endswith(suffix) and _BACKUP_ID.fullmatch(name[: -len(suffix)]) is not None
            }
        )
        purged = 0
        pending = False
        for backup_id in backup_ids:
            record_path = self._root / f"{backup_id}.json"
            payload_path = self._root / f"{backup_id}.payload"
            try:
                record_file = _file_snapshot(record_path, _MAX_PAYLOAD_BYTES)
                payload_file = _file_snapshot(payload_path, _MAX_ENCRYPTED_BYTES)
                expired = _bundle_expired(record_file, payload_file, cutoff)
                if not expired:
                    continue
                if purged >= max_items:
                    pending = True
                    continue
                if record_file is not None and payload_file is not None:
                    _validate_retention_pair(backup_id, record_file[0], payload_file[0])
                    _remove_atomic_file(record_path, record_file[1])
                    _remove_atomic_file(payload_path, payload_file[1])
                else:
                    if record_file is not None:
                        _remove_atomic_file(record_path, record_file[1])
                    if payload_file is not None:
                        _remove_atomic_file(payload_path, payload_file[1])
                if _path_exists(record_path) or _path_exists(payload_path):
                    pending = True
                else:
                    purged += 1
            except (OSError, SystemBackupError, TypeError, ValueError, UnicodeError):
                pending = True
        return purged, pending


def _capture_payload(
    connection: sqlite3.Connection,
) -> tuple[bytes, str, tuple[tuple[str, int], ...]]:
    tables: list[dict[str, object]] = []
    schema_documents: list[dict[str, object]] = []
    counts: list[tuple[str, int]] = []
    for table, expected_columns in _OIDC_SYSTEM_TABLE_SHAPES:
        schema = _table_schema(connection, table, expected_columns)
        rows = _rows(connection, table, expected_columns)
        rows.sort(key=lambda value: _canonical_json(value))
        columns = list(expected_columns)
        row_digest = _digest(_canonical_json({"columns": columns, "rows": rows}))
        tables.append(
            {
                "name": table,
                "columns": columns,
                "schema": schema,
                "rows": rows,
                "rows_sha256": row_digest,
            }
        )
        schema_documents.append({"name": table, "schema": schema})
        counts.append((table, len(rows)))
    schema_digest = _digest(_canonical_json(schema_documents))
    document = {
        "schema_version": _SCHEMA_VERSION,
        "system_identity": _SYSTEM_IDENTITY,
        "tables": tables,
    }
    return _canonical_json(document), schema_digest, tuple(counts)


def _validate_payload(
    document: Mapping[str, object], connection: sqlite3.Connection
) -> tuple[str, tuple[tuple[str, int], ...]]:
    if set(document) != {"schema_version", "system_identity", "tables"}:
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
    if (
        document.get("schema_version") != _SCHEMA_VERSION
        or document.get("system_identity") != _SYSTEM_IDENTITY
    ):
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
    values = document.get("tables")
    if type(values) is not list or len(values) != len(_OIDC_SYSTEM_TABLE_SHAPES):
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
    expected_names = tuple(table for table, _ in _OIDC_SYSTEM_TABLE_SHAPES)
    names: list[str] = []
    schema_documents: list[dict[str, object]] = []
    counts: list[tuple[str, int]] = []
    for value, (expected_name, expected_columns) in zip(
        values, _OIDC_SYSTEM_TABLE_SHAPES, strict=True
    ):
        if type(value) is not dict or set(value) != {
            "name",
            "columns",
            "schema",
            "rows",
            "rows_sha256",
        }:
            raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
        name = value.get("name")
        columns = value.get("columns")
        schema = value.get("schema")
        rows = value.get("rows")
        row_digest = value.get("rows_sha256")
        if (
            type(name) is not str
            or name != expected_name
            or type(columns) is not list
            or tuple(columns) != expected_columns
            or type(rows) is not list
            or len(rows) > _MAX_ROWS_PER_TABLE
            or type(row_digest) is not str
            or _SHA256.fullmatch(row_digest) is None
        ):
            raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
        current_schema = _table_schema(connection, expected_name, expected_columns)
        if schema != current_schema or type(schema) is not list:
            raise SystemBackupError("SYSTEM_BACKUP_SCHEMA_INVALID")
        checked_rows: list[list[object]] = []
        for row in rows:
            if type(row) is not list or len(row) != len(expected_columns):
                raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
            if any(type(item) not in {int, str, type(None)} for item in row):
                raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
            checked_rows.append(row)
        if checked_rows != sorted(checked_rows, key=lambda item: _canonical_json(item)):
            raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
        expected_row_digest = _digest(
            _canonical_json({"columns": list(expected_columns), "rows": checked_rows})
        )
        if expected_row_digest != row_digest:
            raise SystemBackupError("SYSTEM_BACKUP_DIGEST_INVALID")
        names.append(name)
        schema_documents.append({"name": name, "schema": schema})
        counts.append((name, len(checked_rows)))
    if tuple(names) != expected_names:
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
    return _digest(_canonical_json(schema_documents)), tuple(counts)


def _restore_monotonic_payload(
    connection: sqlite3.Connection,
    document: Mapping[str, object],
    *,
    now: int,
) -> None:
    if type(now) is not int or now < 0:
        raise SystemBackupError("SYSTEM_RESTORE_CLOCK_INVALID")
    values = document.get("tables")
    if type(values) is not list:
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
    saved = _payload_table_rows(values)
    live_nonce = _read_nonce_rows(connection, now=now)
    live_rate = _read_rate_rows(connection, "oidc_login_rate_limit", now=now)
    live_source_rate = _read_rate_rows(connection, "oidc_login_source_rate_limit", now=now)
    saved_nonce = _nonce_rows(saved["oidc_nonce_replays"], now=now)
    saved_rate = _aggregate_rate_rows(saved["oidc_login_rate_limit"], now=now)
    saved_source_rate = _source_rate_rows(saved["oidc_login_source_rate_limit"], now=now)
    merged_nonce = _merge_nonce_rows(live_nonce, saved_nonce)
    merged_rate = _merge_aggregate_rate_rows(live_rate, saved_rate)
    merged_source_rate = _merge_source_rate_rows(live_source_rate, saved_source_rate)

    # Pending state is one-shot and must never be resurrected from an older
    # snapshot.  Consumed nonce markers and rate-limit state are monotonic.
    connection.execute("DELETE FROM oidc_login_states")
    connection.execute("DELETE FROM oidc_nonce_replays")
    connection.execute("DELETE FROM oidc_login_rate_limit")
    connection.execute("DELETE FROM oidc_login_source_rate_limit")
    connection.executemany(
        "INSERT INTO oidc_nonce_replays (subject_hash, nonce_hash, expires_at) VALUES (?, ?, ?)",
        merged_nonce,
    )
    connection.executemany(
        "INSERT INTO oidc_login_rate_limit (bucket, window_started_at, attempts) VALUES (?, ?, ?)",
        merged_rate,
    )
    connection.executemany(
        "INSERT INTO oidc_login_source_rate_limit "
        "(bucket, source_hash, window_started_at, window_seconds, attempts) "
        "VALUES (?, ?, ?, ?, ?)",
        merged_source_rate,
    )
    _validate_monotonic_result(
        connection,
        merged_nonce=merged_nonce,
        merged_rate=merged_rate,
        merged_source_rate=merged_source_rate,
    )


def _payload_table_rows(
    values: list[object],
) -> dict[str, list[list[object]]]:
    result: dict[str, list[list[object]]] = {}
    for value in values:
        if type(value) is not dict:
            raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
        name = value.get("name")
        rows = value.get("rows")
        if type(name) is not str or type(rows) is not list:
            raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
        if name in result:
            raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
        result[name] = rows
    expected = {table for table, _ in _OIDC_SYSTEM_TABLE_SHAPES}
    if set(result) != expected:
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
    return result


def _read_nonce_rows(connection: sqlite3.Connection, *, now: int) -> dict[tuple[str, str], int]:
    if type(now) is not int or now < 0:
        raise SystemBackupError("SYSTEM_RESTORE_CLOCK_INVALID")
    try:
        rows = connection.execute(
            "SELECT subject_hash, nonce_hash, expires_at FROM oidc_nonce_replays"
        ).fetchall()
    except sqlite3.Error as error:
        raise SystemBackupError("SYSTEM_RESTORE_STATE_UNAVAILABLE") from error
    result: dict[tuple[str, str], int] = {}
    for row in rows:
        if (
            type(row[0]) is not str
            or _SHA256.fullmatch(row[0]) is None
            or type(row[1]) is not str
            or _SHA256.fullmatch(row[1]) is None
            or type(row[2]) is not int
            or row[2] < 0
        ):
            raise SystemBackupError("SYSTEM_RESTORE_STATE_INVALID")
        key = (row[0], row[1])
        if key in result:
            raise SystemBackupError("SYSTEM_RESTORE_STATE_INVALID")
        if row[2] > now:
            result[key] = row[2]
    return result


def _nonce_rows(rows: list[list[object]], *, now: int) -> dict[tuple[str, str], int]:
    result: dict[tuple[str, str], int] = {}
    for row in rows:
        if (
            len(row) != 3
            or type(row[0]) is not str
            or _SHA256.fullmatch(row[0]) is None
            or type(row[1]) is not str
            or _SHA256.fullmatch(row[1]) is None
            or type(row[2]) is not int
            or row[2] < 0
        ):
            raise SystemBackupError("SYSTEM_BACKUP_STATE_INVALID")
        key = (row[0], row[1])
        if key in result:
            raise SystemBackupError("SYSTEM_BACKUP_STATE_INVALID")
        if row[2] > now:
            result[key] = row[2]
    return result


def _merge_nonce_rows(
    live: dict[tuple[str, str], int], saved: dict[tuple[str, str], int]
) -> tuple[tuple[str, str, int], ...]:
    merged = dict(live)
    for key, expires_at in saved.items():
        merged[key] = max(merged.get(key, 0), expires_at)
    return tuple((key[0], key[1], value) for key, value in sorted(merged.items()))


def _read_rate_rows(
    connection: sqlite3.Connection, table: str, *, now: int
) -> dict[tuple[str, ...], tuple[object, ...]]:
    if type(now) is not int or now < 0:
        raise SystemBackupError("SYSTEM_RESTORE_CLOCK_INVALID")
    if table == "oidc_login_rate_limit":
        statement = "SELECT bucket, window_started_at, attempts FROM oidc_login_rate_limit"
    elif table == "oidc_login_source_rate_limit":
        statement = (
            "SELECT bucket, source_hash, window_started_at, window_seconds, attempts "
            "FROM oidc_login_source_rate_limit"
        )
    else:
        raise SystemBackupError("SYSTEM_RESTORE_STATE_INVALID")
    try:
        rows = connection.execute(statement).fetchall()
    except sqlite3.Error as error:
        raise SystemBackupError("SYSTEM_RESTORE_STATE_UNAVAILABLE") from error
    result: dict[tuple[str, ...], tuple[object, ...]] = {}
    for row in rows:
        values = tuple(row)
        key = _validate_rate_row(table, values, now=now)
        if key in result:
            raise SystemBackupError("SYSTEM_RESTORE_STATE_INVALID")
        result[key] = values
    return result


def _aggregate_rate_rows(
    rows: list[list[object]], *, now: int
) -> dict[tuple[str, ...], tuple[object, ...]]:
    result: dict[tuple[str, ...], tuple[object, ...]] = {}
    for row in rows:
        values = tuple(row)
        if len(values) != 3:
            raise SystemBackupError("SYSTEM_BACKUP_STATE_INVALID")
        key = _validate_rate_row("oidc_login_rate_limit", values, now=now)
        if key in result:
            raise SystemBackupError("SYSTEM_BACKUP_STATE_INVALID")
        result[key] = values
    return result


def _source_rate_rows(
    rows: list[list[object]], *, now: int
) -> dict[tuple[str, ...], tuple[object, ...]]:
    result: dict[tuple[str, ...], tuple[object, ...]] = {}
    for row in rows:
        values = tuple(row)
        if len(values) != 5:
            raise SystemBackupError("SYSTEM_BACKUP_STATE_INVALID")
        key = _validate_rate_row("oidc_login_source_rate_limit", values, now=now)
        if key in result:
            raise SystemBackupError("SYSTEM_BACKUP_STATE_INVALID")
        result[key] = values
    return result


def _validate_rate_row(
    table: str,
    values: tuple[object, ...],
    *,
    now: int | None = None,
) -> tuple[str, ...]:
    if table == "oidc_login_rate_limit":
        if (
            len(values) != 3
            or type(values[0]) is not str
            or values[0] not in {"start", "callback"}
            or type(values[1]) is not int
            or values[1] < 0
            or (now is not None and values[1] > now)
            or type(values[2]) is not int
            or values[2] < 1
        ):
            raise SystemBackupError("SYSTEM_BACKUP_STATE_INVALID")
        return (values[0],)
    if (
        len(values) != 5
        or type(values[0]) is not str
        or values[0] not in {"start", "callback"}
        or type(values[1]) is not str
        or _SHA256.fullmatch(values[1]) is None
        or type(values[2]) is not int
        or values[2] < 0
        or (now is not None and values[2] > now)
        or type(values[3]) is not int
        or not 1 <= values[3] <= 3600
        or type(values[4]) is not int
        or values[4] < 1
    ):
        raise SystemBackupError("SYSTEM_BACKUP_STATE_INVALID")
    return (values[0], values[1])


def _merge_aggregate_rate_rows(
    live: dict[tuple[str, ...], tuple[object, ...]],
    saved: dict[tuple[str, ...], tuple[object, ...]],
) -> tuple[tuple[str, int, int], ...]:
    merged: dict[tuple[str, ...], tuple[object, ...]] = dict(live)
    for key, value in saved.items():
        current = merged.get(key)
        if current is None:
            merged[key] = value
            continue
        merged[key] = (
            key[0],
            max(_row_int(current[1]), _row_int(value[1])),
            max(_row_int(current[2]), _row_int(value[2])),
        )
    return tuple(
        (key[0], _row_int(value[1]), _row_int(value[2])) for key, value in sorted(merged.items())
    )


def _merge_source_rate_rows(
    live: dict[tuple[str, ...], tuple[object, ...]],
    saved: dict[tuple[str, ...], tuple[object, ...]],
) -> tuple[tuple[str, str, int, int, int], ...]:
    merged: dict[tuple[str, ...], tuple[object, ...]] = dict(live)
    for key, value in saved.items():
        current = merged.get(key)
        if current is None:
            merged[key] = value
            continue
        merged[key] = (
            key[0],
            key[1],
            max(_row_int(current[2]), _row_int(value[2])),
            max(_row_int(current[3]), _row_int(value[3])),
            max(_row_int(current[4]), _row_int(value[4])),
        )
    return tuple(
        (key[0], key[1], _row_int(value[2]), _row_int(value[3]), _row_int(value[4]))
        for key, value in sorted(merged.items())
    )


def _row_int(value: object) -> int:
    """Convert a persisted row cell exactly as ``int()`` would, failing on other types."""

    if not isinstance(value, str | bytes | bytearray | SupportsInt | SupportsIndex):
        raise TypeError("row value is not integral")
    return int(value)


def _validate_monotonic_result(
    connection: sqlite3.Connection,
    *,
    merged_nonce: tuple[tuple[str, str, int], ...],
    merged_rate: tuple[tuple[str, int, int], ...],
    merged_source_rate: tuple[tuple[str, str, int, int, int], ...],
) -> None:
    nonce = tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT subject_hash, nonce_hash, expires_at "
            "FROM oidc_nonce_replays ORDER BY subject_hash, nonce_hash"
        ).fetchall()
    )
    aggregate = tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT bucket, window_started_at, attempts FROM oidc_login_rate_limit ORDER BY bucket"
        ).fetchall()
    )
    source = tuple(
        tuple(row)
        for row in connection.execute(
            "SELECT bucket, source_hash, window_started_at, window_seconds, attempts "
            "FROM oidc_login_source_rate_limit ORDER BY bucket, source_hash"
        ).fetchall()
    )
    expected_nonce = tuple(sorted(merged_nonce, key=lambda row: (row[0], row[1])))
    expected_aggregate = tuple(sorted(merged_rate, key=lambda row: row[0]))
    expected_source = tuple(sorted(merged_source_rate, key=lambda row: (row[0], row[1])))
    if nonce != expected_nonce or aggregate != expected_aggregate or source != expected_source:
        raise SystemBackupError("SYSTEM_RESTORE_STATE_INVALID")
    if connection.execute("SELECT 1 FROM oidc_login_states LIMIT 1").fetchone() is not None:
        raise SystemBackupError("SYSTEM_RESTORE_STATE_INVALID")


def _table_schema(
    connection: sqlite3.Connection,
    table: str,
    expected_columns: Sequence[str],
) -> list[list[object]]:
    try:
        rows = connection.execute(f"PRAGMA table_info({_quote_identifier(table)})").fetchall()
    except sqlite3.Error as error:
        raise SystemBackupError("SYSTEM_BACKUP_SCHEMA_INVALID") from error
    if not rows or tuple(row[1] for row in rows) != tuple(expected_columns):
        raise SystemBackupError("SYSTEM_BACKUP_SCHEMA_INVALID")
    result: list[list[object]] = []
    for row in rows:
        values = [row[index] for index in range(6)]
        if (
            type(values[0]) is not int
            or type(values[1]) is not str
            or type(values[2]) is not str
            or type(values[3]) is not int
            or type(values[4]) not in {str, type(None)}
            or type(values[5]) is not int
        ):
            raise SystemBackupError("SYSTEM_BACKUP_SCHEMA_INVALID")
        result.append(values)
    return result


def _rows(
    connection: sqlite3.Connection,
    table: str,
    expected_columns: Sequence[str],
) -> list[list[object]]:
    try:
        values = connection.execute(
            f"SELECT {','.join(_quote_identifier(item) for item in expected_columns)} "
            f"FROM {_quote_identifier(table)}"
        ).fetchall()
    except sqlite3.Error as error:
        raise SystemBackupError("SYSTEM_BACKUP_CAPTURE_FAILED") from error
    if len(values) > _MAX_ROWS_PER_TABLE:
        raise SystemBackupError("SYSTEM_BACKUP_TOO_LARGE")
    result: list[list[object]] = []
    for row in values:
        converted = list(row)
        if any(type(item) not in {int, str, type(None)} for item in converted):
            raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
        result.append(converted)
    return result


def _record_document(record: SystemOidcBackupRecord) -> dict[str, object]:
    return {
        "backup_id": record.backup_id,
        "created_at": record.created_at,
        "encrypted_sha256": record.encrypted_sha256,
        "encryption_key_ref": record.encryption_key_ref,
        "plaintext_sha256": record.plaintext_sha256,
        "schema_sha256": record.schema_sha256,
        "size_bytes": record.size_bytes,
        "system_identity": record.system_identity,
        "table_counts": [[name, count] for name, count in record.table_counts],
        "schema_version": _SCHEMA_VERSION,
    }


def _record_from_document(document: Mapping[str, object]) -> SystemOidcBackupRecord:
    expected = {
        "backup_id",
        "created_at",
        "encrypted_sha256",
        "encryption_key_ref",
        "plaintext_sha256",
        "schema_sha256",
        "size_bytes",
        "system_identity",
        "table_counts",
        "schema_version",
    }
    if set(document) != expected or document.get("schema_version") != _SCHEMA_VERSION:
        raise SystemBackupError("SYSTEM_BACKUP_RECORD_INVALID")
    backup_id = document.get("backup_id")
    identity = document.get("system_identity")
    key_ref = document.get("encryption_key_ref")
    created_at = document.get("created_at")
    plaintext = document.get("plaintext_sha256")
    encrypted = document.get("encrypted_sha256")
    size_bytes = document.get("size_bytes")
    schema_digest = document.get("schema_sha256")
    counts = document.get("table_counts")
    if (
        type(backup_id) is not str
        or type(identity) is not str
        or type(key_ref) is not str
        or type(created_at) is not int
        or type(plaintext) is not str
        or type(encrypted) is not str
        or type(size_bytes) is not int
        or type(schema_digest) is not str
        or type(counts) is not list
        or identity != _SYSTEM_IDENTITY
        or created_at < 0
        or not 1 <= size_bytes <= _MAX_ENCRYPTED_BYTES
        or _SHA256.fullmatch(plaintext) is None
        or _SHA256.fullmatch(encrypted) is None
        or _SHA256.fullmatch(schema_digest) is None
    ):
        raise SystemBackupError("SYSTEM_BACKUP_RECORD_INVALID")
    _validate_backup_id(backup_id)
    _validate_key_ref(key_ref)
    table_counts: list[tuple[str, int]] = []
    for value in counts:
        if (
            type(value) is not list
            or len(value) != 2
            or type(value[0]) is not str
            or type(value[1]) is not int
            or value[1] < 0
        ):
            raise SystemBackupError("SYSTEM_BACKUP_RECORD_INVALID")
        table_counts.append((value[0], value[1]))
    expected_names = tuple(table for table, _ in _OIDC_SYSTEM_TABLE_SHAPES)
    if tuple(name for name, _ in table_counts) != expected_names:
        raise SystemBackupError("SYSTEM_BACKUP_RECORD_INVALID")
    return SystemOidcBackupRecord(
        backup_id=backup_id,
        system_identity=identity,
        encryption_key_ref=key_ref,
        created_at=created_at,
        plaintext_sha256=plaintext,
        encrypted_sha256=encrypted,
        size_bytes=size_bytes,
        schema_sha256=schema_digest,
        table_counts=tuple(table_counts),
    )


def _encrypt(encryption: SystemBackupEncryption, payload: bytes, key_ref: str) -> bytes:
    try:
        encrypted = encryption.encrypt(payload, key_ref)
    except Exception as error:
        raise SystemBackupError("SYSTEM_BACKUP_ENCRYPTION_FAILED") from error
    if (
        type(encrypted) is not bytes
        or not encrypted
        or len(encrypted) > _MAX_ENCRYPTED_BYTES
        or encrypted == payload
    ):
        raise SystemBackupError("SYSTEM_BACKUP_ENCRYPTION_INVALID")
    return encrypted


def _decrypt(encryption: SystemBackupEncryption, payload: bytes, key_ref: str) -> bytes:
    try:
        decrypted = encryption.decrypt(payload, key_ref)
    except Exception as error:
        raise SystemBackupError("SYSTEM_RESTORE_DECRYPTION_FAILED") from error
    if type(decrypted) is not bytes or not decrypted or len(decrypted) > _MAX_PAYLOAD_BYTES:
        raise SystemBackupError("SYSTEM_RESTORE_DECRYPTION_INVALID")
    return decrypted


def _load_canonical_document(payload: bytes) -> dict[str, object]:
    if type(payload) is not bytes or not payload or len(payload) > _MAX_ENCRYPTED_BYTES:
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID") from None
    if type(value) is not dict or _canonical_json(value) != payload:
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID") from None


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _validate_backup_id(value: object) -> None:
    if type(value) is not str or _BACKUP_ID.fullmatch(value) is None:
        raise SystemBackupError("SYSTEM_BACKUP_ID_INVALID")


def _validate_key_ref(value: object) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= _KEY_REF_LIMIT
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
    ):
        raise SystemBackupError("SYSTEM_BACKUP_KEY_REF_INVALID")


def _existing_file(path: Path, maximum: int) -> bytes | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SystemBackupError("SYSTEM_BACKUP_STORAGE_UNAVAILABLE") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SystemBackupError("SYSTEM_BACKUP_STORAGE_INVALID")
    if before.st_size > maximum:
        raise SystemBackupError("SYSTEM_BACKUP_TOO_LARGE")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemBackupError("SYSTEM_BACKUP_STORAGE_UNAVAILABLE") from error
    try:
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                stat.S_ISLNK(opened.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            ):
                raise SystemBackupError("SYSTEM_BACKUP_STORAGE_INVALID")
            if opened.st_size > maximum:
                raise SystemBackupError("SYSTEM_BACKUP_TOO_LARGE")
            value = stream.read(maximum + 1)
            if len(value) != opened.st_size or len(value) > maximum:
                raise SystemBackupError("SYSTEM_BACKUP_STORAGE_INVALID")
    except OSError as error:
        raise SystemBackupError("SYSTEM_BACKUP_STORAGE_UNAVAILABLE") from error
    return value


def _file_snapshot(path: Path, maximum: int) -> tuple[bytes, tuple[int, int], int] | None:
    try:
        before = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as error:
        raise SystemBackupError("SYSTEM_BACKUP_STORAGE_UNAVAILABLE") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise SystemBackupError("SYSTEM_BACKUP_STORAGE_INVALID")
    if before.st_size > maximum:
        raise SystemBackupError("SYSTEM_BACKUP_TOO_LARGE")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemBackupError("SYSTEM_BACKUP_STORAGE_UNAVAILABLE") from error
    try:
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or opened.st_size > maximum
            ):
                raise SystemBackupError("SYSTEM_BACKUP_STORAGE_INVALID")
            value = stream.read(maximum + 1)
            if len(value) != opened.st_size or len(value) > maximum:
                raise SystemBackupError("SYSTEM_BACKUP_STORAGE_INVALID")
    except OSError as error:
        raise SystemBackupError("SYSTEM_BACKUP_STORAGE_UNAVAILABLE") from error
    return value, (opened.st_dev, opened.st_ino), max(0, int(opened.st_mtime))


def _bundle_expired(
    record_file: tuple[bytes, tuple[int, int], int] | None,
    payload_file: tuple[bytes, tuple[int, int], int] | None,
    cutoff: int,
) -> bool:
    if record_file is not None:
        try:
            record = _record_from_document(_load_canonical_document(record_file[0]))
        except (SystemBackupError, ValueError, TypeError, UnicodeError):
            return record_file[2] <= cutoff
        return record.created_at <= cutoff
    return payload_file is not None and payload_file[2] <= cutoff


def _validate_retention_pair(backup_id: str, record_bytes: bytes, encrypted: bytes) -> None:
    record = _record_from_document(_load_canonical_document(record_bytes))
    if (
        record.backup_id != backup_id
        or record.system_identity != _SYSTEM_IDENTITY
        or record.size_bytes != len(encrypted)
        or record.encrypted_sha256 != _digest(encrypted)
    ):
        raise SystemBackupError("SYSTEM_BACKUP_DIGEST_INVALID")


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return True


def _atomic_create(path: Path, payload: bytes) -> tuple[int, int] | None:
    if type(payload) is not bytes or not payload:
        raise SystemBackupError("SYSTEM_BACKUP_PAYLOAD_INVALID")
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=".system-backup-", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        created = True
        try:
            os.link(temporary, path)
        except FileExistsError:
            existing = _existing_file(path, max(len(payload), _MAX_ENCRYPTED_BYTES))
            if existing != payload:
                raise SystemBackupError("SYSTEM_BACKUP_CONFLICT") from None
            created = False
        _sync_directory(path.parent)
        if not created:
            return None
        try:
            details = path.lstat()
        except OSError as error:
            raise SystemBackupError("SYSTEM_BACKUP_STORAGE_FAILED") from error
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise SystemBackupError("SYSTEM_BACKUP_STORAGE_INVALID")
        return details.st_dev, details.st_ino
    except (OSError, SystemBackupError) as error:
        if isinstance(error, SystemBackupError):
            raise
        raise SystemBackupError("SYSTEM_BACKUP_STORAGE_FAILED") from error
    finally:
        with contextlib.suppress(OSError):
            Path(temporary).unlink(missing_ok=True)


def _remove_atomic_file(path: Path, identity: tuple[int, int]) -> None:
    """Remove only the file created by the preceding atomic write.

    A concurrent writer may have completed the paired record between the two
    creates.  Unlinking by pathname unconditionally in the error path could
    then delete that writer's valid payload and leave a corrupt half-bundle.
    """

    try:
        details = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        return
    if (
        stat.S_ISLNK(details.st_mode)
        or not stat.S_ISREG(details.st_mode)
        or (details.st_dev, details.st_ino) != identity
    ):
        return
    with contextlib.suppress(OSError):
        path.unlink()


def _ensure_directory_chain(path: Path) -> None:
    if not path.is_absolute() or not path.anchor:
        raise SystemBackupError("SYSTEM_BACKUP_ROOT_INVALID")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            details = current.lstat()
        except FileNotFoundError:
            try:
                current.mkdir()
                details = current.lstat()
            except OSError as error:
                raise SystemBackupError("SYSTEM_BACKUP_ROOT_UNAVAILABLE") from error
        except OSError as error:
            raise SystemBackupError("SYSTEM_BACKUP_ROOT_UNAVAILABLE") from error
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise SystemBackupError("SYSTEM_BACKUP_ROOT_INVALID")


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _quote_identifier(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise SystemBackupError("SYSTEM_BACKUP_SCHEMA_INVALID")
    return '"' + value.replace('"', '""') + '"'


__all__ = [
    "SystemBackupError",
    "SystemOidcBackupRecord",
    "SystemOidcBackupRetention",
    "SystemOidcBackupRuntime",
]
