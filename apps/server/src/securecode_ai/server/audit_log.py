"""Durable append-only metadata audit log with hash-chain verification."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, cast

from .data_lifecycle import retention_content_sha256


class AuditConflict(Exception):
    """Raised for invalid metadata, CAS conflicts, or chain corruption."""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    tenant_id: str
    repository_id: str
    run_id: str
    actor_id: str
    action: str
    execution_identity_hash: str
    sequence: int
    previous_hash: str
    attributes: dict[str, object]
    created_at: str
    event_hash: str

    def __post_init__(self) -> None:
        for value in (
            self.tenant_id,
            self.repository_id,
            self.run_id,
            self.actor_id,
            self.action,
        ):
            _require_identifier(value)
        _require_sha256(self.execution_identity_hash)
        _require_sha256(self.previous_hash)
        _require_sha256(self.event_hash)
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("audit sequence is invalid")
        _parse_utc(self.created_at)
        _validate_attributes(self.attributes)


@dataclass(frozen=True, slots=True)
class AuditResourceEvent:
    tenant_id: str
    resource_type: str
    resource_key_sha256: str
    actor_id: str
    action: str
    sequence: int
    previous_hash: str
    attributes: dict[str, object]
    created_at: str
    event_hash: str

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.resource_type, self.actor_id, self.action):
            _require_identifier(value)
        for value in (self.resource_key_sha256, self.previous_hash, self.event_hash):
            _require_sha256(value)
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("resource audit sequence is invalid")
        _parse_utc(self.created_at)
        _validate_attributes(self.attributes)


AUDIT_LOG_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS audit_chain_events (
        tenant_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        repository_id TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        action TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        attributes_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        PRIMARY KEY (tenant_id, run_id, sequence),
        UNIQUE (tenant_id, event_hash),
        CHECK (sequence >= 1)
    )""",
    """CREATE TABLE IF NOT EXISTS audit_chain_idempotency (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        run_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, run_id, sequence)
            REFERENCES audit_chain_events (tenant_id, run_id, sequence)
    )""",
    """CREATE TABLE IF NOT EXISTS audit_retention_tombstones (
        tenant_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL,
        deletion_id TEXT NOT NULL,
        deleted_at TEXT NOT NULL,
        head_sequence INTEGER NOT NULL CHECK (head_sequence >= 0),
        head_hash TEXT NOT NULL,
        tombstone_hash TEXT NOT NULL,
        PRIMARY KEY (tenant_id, run_id),
        UNIQUE (tenant_id, deletion_id)
    )""",
    """CREATE TABLE IF NOT EXISTS audit_resource_hmac_key (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        secret BLOB NOT NULL CHECK (length(secret) = 32)
    )""",
    """CREATE TABLE IF NOT EXISTS audit_resource_chain_events (
        tenant_id TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_key_sha256 TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        actor_id TEXT NOT NULL,
        action TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        attributes_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        PRIMARY KEY (tenant_id, resource_type, resource_key_sha256, sequence),
        UNIQUE (tenant_id, event_hash),
        CHECK (sequence >= 1)
    )""",
    """CREATE TABLE IF NOT EXISTS audit_resource_chain_idempotency (
        tenant_id TEXT NOT NULL,
        resource_type TEXT NOT NULL,
        resource_key_sha256 TEXT NOT NULL,
        idempotency_sha256 TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, resource_type, resource_key_sha256, idempotency_sha256),
        FOREIGN KEY (tenant_id, resource_type, resource_key_sha256, sequence)
            REFERENCES audit_resource_chain_events
                (tenant_id, resource_type, resource_key_sha256, sequence)
    )""",
)


class AuditLog:
    """Append-only SQLite audit chain containing allowlisted metadata only."""

    def __init__(
        self,
        connection: sqlite3.Connection | None = None,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._db = connection or sqlite3.connect(":memory:", check_same_thread=False)
        self._now = now
        self._lock = threading.RLock()
        self._db.execute("PRAGMA foreign_keys = ON")
        for statement in AUDIT_LOG_SCHEMA_STATEMENTS:
            self._db.execute(statement)
        key_row = self._db.execute(
            "SELECT secret FROM audit_resource_hmac_key WHERE singleton = 1"
        ).fetchone()
        if key_row is None:
            existing_events = self._db.execute(
                "SELECT 1 FROM audit_resource_chain_events LIMIT 1"
            ).fetchone()
            if existing_events is not None:
                raise AuditConflict("resource audit key is missing")
            self._db.execute(
                "INSERT OR IGNORE INTO audit_resource_hmac_key (singleton, secret) VALUES (1, ?)",
                (os.urandom(32),),
            )
        self._db.commit()
        key_row = self._db.execute(
            "SELECT secret FROM audit_resource_hmac_key WHERE singleton = 1"
        ).fetchone()
        if key_row is None or type(key_row[0]) is not bytes or len(key_row[0]) != 32:
            raise AuditConflict("resource audit key is invalid")
        self._resource_hmac_key = key_row[0]

    def resource_key_sha256(
        self, *, tenant_id: str, resource_type: str, resource_id: str | None
    ) -> str:
        _require_identifier(tenant_id)
        _require_identifier(resource_type)
        scope = "resource" if resource_id is not None else "tenant"
        if resource_id is not None:
            _require_identifier(resource_id)
        material = "\x00".join(
            ("securecode.resource-audit.v1", tenant_id, resource_type, scope, resource_id or "")
        )
        return hmac.new(
            self._resource_hmac_key, material.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def append_resource(
        self,
        *,
        tenant_id: str,
        resource_type: str,
        resource_id: str | None,
        actor_id: str,
        action: str,
        expected_sequence: int | None,
        attributes: dict[str, object],
        idempotency_key: str,
    ) -> AuditResourceEvent:
        for value in (tenant_id, resource_type, actor_id, action):
            _require_identifier(value)
        if resource_id is not None:
            _require_identifier(resource_id)
        if expected_sequence is not None and (
            type(expected_sequence) is not int or expected_sequence < 0
        ):
            raise AuditConflict("expected resource audit sequence is invalid")
        normalized_attributes = _validate_attributes(attributes)
        key_hash = self.resource_key_sha256(
            tenant_id=tenant_id, resource_type=resource_type, resource_id=resource_id
        )
        idempotency_hash = hashlib.sha256(_require_key(idempotency_key).encode("ascii")).hexdigest()
        request_hash = _digest(
            {
                "tenant_id": tenant_id,
                "resource_type": resource_type,
                "resource_key_sha256": key_hash,
                "actor_id": actor_id,
                "action": action,
                "attributes": normalized_attributes,
            }
        )
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self.require_resource_valid(
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    resource_key_sha256=key_hash,
                )
                replay = self._db.execute(
                    """SELECT request_sha256, sequence FROM audit_resource_chain_idempotency
                       WHERE tenant_id=? AND resource_type=? AND resource_key_sha256=?
                         AND idempotency_sha256=?""",
                    (tenant_id, resource_type, key_hash, idempotency_hash),
                ).fetchone()
                if replay is not None:
                    if type(replay[0]) is not str or replay[0] != request_hash:
                        raise AuditConflict("resource audit idempotency key was reused")
                    event = self._resource_event(
                        tenant_id, resource_type, key_hash, _stored_int(replay[1])
                    )
                    if (
                        event is None
                        or event.actor_id != actor_id
                        or event.action != action
                        or event.attributes != normalized_attributes
                    ):
                        raise AuditConflict("resource audit replay is incomplete")
                    self._db.commit()
                    return event
                head = self._db.execute(
                    """SELECT sequence, event_hash FROM audit_resource_chain_events
                       WHERE tenant_id=? AND resource_type=? AND resource_key_sha256=?
                       ORDER BY sequence DESC LIMIT 1""",
                    (tenant_id, resource_type, key_hash),
                ).fetchone()
                sequence = 0 if head is None else _stored_int(head[0])
                if expected_sequence is not None and sequence != expected_sequence:
                    raise AuditConflict("resource audit sequence changed")
                previous_hash = "0" * 64 if head is None else _require_sha256(head[1])
                created_at = _checked_now(self._now).isoformat()
                material = {
                    "tenant_id": tenant_id,
                    "resource_type": resource_type,
                    "resource_key_sha256": key_hash,
                    "actor_id": actor_id,
                    "action": action,
                    "sequence": sequence + 1,
                    "previous_hash": previous_hash,
                    "attributes": normalized_attributes,
                    "created_at": created_at,
                }
                event = AuditResourceEvent(**material, event_hash=_digest(material))
                self._db.execute(
                    """INSERT INTO audit_resource_chain_events VALUES
                       (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        tenant_id,
                        resource_type,
                        key_hash,
                        event.sequence,
                        actor_id,
                        action,
                        previous_hash,
                        _canonical(normalized_attributes),
                        created_at,
                        event.event_hash,
                    ),
                )
                self._db.execute(
                    """INSERT INTO audit_resource_chain_idempotency VALUES
                       (?, ?, ?, ?, ?, ?)""",
                    (tenant_id, resource_type, key_hash, idempotency_hash, request_hash, event.sequence),
                )
                self._db.commit()
                return event
            except Exception:
                self._db.rollback()
                raise

    def resource_head_sequence(
        self, *, tenant_id: str, resource_type: str, resource_key_sha256: str
    ) -> int:
        _require_identifier(tenant_id)
        _require_identifier(resource_type)
        _require_sha256(resource_key_sha256)
        with self._lock:
            row = self._db.execute(
                """SELECT sequence FROM audit_resource_chain_events
                   WHERE tenant_id=? AND resource_type=? AND resource_key_sha256=?
                   ORDER BY sequence DESC LIMIT 1""",
                (tenant_id, resource_type, resource_key_sha256),
            ).fetchone()
            return 0 if row is None else _stored_int(row[0])

    def verified_resource_range(
        self,
        *,
        tenant_id: str,
        resource_type: str,
        resource_key_sha256: str,
        start: int,
        end: int | None,
        maximum_events: int,
    ) -> tuple[AuditResourceEvent, ...]:
        if (
            type(start) is not int
            or start < 1
            or (end is not None and (type(end) is not int or end < start))
            or type(maximum_events) is not int
            or maximum_events < 1
        ):
            raise AuditConflict("resource audit export range is invalid")
        _require_identifier(tenant_id)
        _require_identifier(resource_type)
        _require_sha256(resource_key_sha256)
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self.require_resource_valid(
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    resource_key_sha256=resource_key_sha256,
                )
                head = self.resource_head_sequence(
                    tenant_id=tenant_id,
                    resource_type=resource_type,
                    resource_key_sha256=resource_key_sha256,
                )
                if start > head or (end is not None and end > head):
                    raise AuditConflict("resource audit export range exceeds the audit head")
                upper = head if end is None else end
                if upper - start + 1 > maximum_events:
                    raise ValueError("resource audit export range exceeds the event limit")
                rows = self._resource_rows(
                    tenant_id, resource_type, resource_key_sha256, start, upper
                )
                events = tuple(_resource_from_row(row) for row in rows)
                if len(events) != upper - start + 1:
                    raise AuditConflict("resource audit export range is incomplete")
                self._db.commit()
                return events
            except Exception:
                self._db.rollback()
                raise

    def require_resource_valid(
        self, *, tenant_id: str, resource_type: str, resource_key_sha256: str
    ) -> None:
        previous = "0" * 64
        expected_sequence = 1
        for row in self._resource_rows(
            tenant_id, resource_type, resource_key_sha256, 1, None
        ):
            event = _resource_from_row(row)
            material = {
                "tenant_id": event.tenant_id,
                "resource_type": event.resource_type,
                "resource_key_sha256": event.resource_key_sha256,
                "actor_id": event.actor_id,
                "action": event.action,
                "sequence": event.sequence,
                "previous_hash": event.previous_hash,
                "attributes": event.attributes,
                "created_at": event.created_at,
            }
            if (
                event.sequence != expected_sequence
                or event.previous_hash != previous
                or _digest(material) != event.event_hash
            ):
                raise AuditConflict("resource audit hash chain verification failed")
            previous = event.event_hash
            expected_sequence += 1

    def _resource_rows(
        self,
        tenant_id: str,
        resource_type: str,
        key_hash: str,
        start: int,
        end: int | None,
    ) -> list[tuple[object, ...]]:
        sql = """SELECT tenant_id, resource_type, resource_key_sha256, actor_id, action,
                        sequence, previous_hash, attributes_json, created_at, event_hash
                 FROM audit_resource_chain_events
                 WHERE tenant_id=? AND resource_type=? AND resource_key_sha256=? AND sequence>=?"""
        parameters: tuple[object, ...] = (tenant_id, resource_type, key_hash, start)
        if end is not None:
            sql += " AND sequence<=?"
            parameters += (end,)
        sql += " ORDER BY sequence"
        return self._db.execute(sql, parameters).fetchall()

    def _resource_event(
        self, tenant_id: str, resource_type: str, key_hash: str, sequence: int
    ) -> AuditResourceEvent | None:
        rows = self._resource_rows(tenant_id, resource_type, key_hash, sequence, sequence)
        return None if not rows else _resource_from_row(rows[0])

    def append(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        actor_id: str,
        action: str,
        identity_hash: str,
        expected_sequence: int,
        attributes: dict[str, object],
        idempotency_key: str,
    ) -> AuditEvent:
        for value in (tenant_id, repository_id, run_id, actor_id, action):
            _require_identifier(value)
        _require_sha256(identity_hash)
        if type(expected_sequence) is not int or expected_sequence < 0:
            raise AuditConflict("expected sequence is invalid")
        normalized_attributes = _validate_attributes(attributes)
        key = _require_key(idempotency_key)
        request_hash = _request_hash(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            actor_id=actor_id,
            action=action,
            identity_hash=identity_hash,
            attributes=normalized_attributes,
        )
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._ensure_available(tenant_id=tenant_id, run_id=run_id)
                self.require_valid(tenant_id=tenant_id, run_id=run_id)
                replay = self._db.execute(
                    """SELECT request_sha256, run_id, sequence
                       FROM audit_chain_idempotency
                       WHERE tenant_id = ? AND idempotency_key = ?""",
                    (tenant_id, key),
                ).fetchone()
                if replay is not None:
                    if (
                        type(replay[0]) is not str
                        or replay[0] != request_hash
                        or type(replay[1]) is not str
                        or replay[1] != run_id
                    ):
                        raise AuditConflict("idempotency key was reused")
                    sequence = _stored_int(replay[2])
                    result = self._event(tenant_id, run_id, sequence)
                    if result is None or (
                        result.tenant_id != tenant_id
                        or result.repository_id != repository_id
                        or result.run_id != run_id
                        or result.actor_id != actor_id
                        or result.action != action
                        or result.execution_identity_hash != identity_hash
                        or result.attributes != normalized_attributes
                    ):
                        raise AuditConflict("audit replay is incomplete")
                    self._db.commit()
                    return result
                head = self._db.execute(
                    """SELECT sequence, repository_id, execution_identity_hash, event_hash
                       FROM audit_chain_events
                       WHERE tenant_id = ? AND run_id = ?
                       ORDER BY sequence DESC LIMIT 1""",
                    (tenant_id, run_id),
                ).fetchone()
                current_sequence = 0 if head is None else _stored_int(head[0])
                if current_sequence != expected_sequence:
                    raise AuditConflict("audit sequence changed")
                if head is not None and (
                    type(head[1]) is not str
                    or type(head[2]) is not str
                    or head[1] != repository_id
                    or head[2] != identity_hash
                ):
                    raise AuditConflict("run audit identity changed")
                previous_hash = "0" * 64
                if head is not None:
                    if not _require_sha256_value(head[3]):
                        raise AuditConflict("stored audit hash is invalid")
                    previous_hash = cast(str, head[3])
                created_at = _checked_now(self._now).isoformat()
                material = {
                    "tenant_id": tenant_id,
                    "repository_id": repository_id,
                    "run_id": run_id,
                    "actor_id": actor_id,
                    "action": action,
                    "execution_identity_hash": identity_hash,
                    "sequence": current_sequence + 1,
                    "previous_hash": previous_hash,
                    "attributes": normalized_attributes,
                    "created_at": created_at,
                }
                event_hash = _digest(material)
                event = AuditEvent(
                    tenant_id=tenant_id,
                    repository_id=repository_id,
                    run_id=run_id,
                    actor_id=actor_id,
                    action=action,
                    execution_identity_hash=identity_hash,
                    sequence=current_sequence + 1,
                    previous_hash=previous_hash,
                    attributes=normalized_attributes,
                    created_at=created_at,
                    event_hash=event_hash,
                )
                self._db.execute(
                    """INSERT INTO audit_chain_events (
                           tenant_id, run_id, sequence, repository_id, actor_id,
                           action, execution_identity_hash, previous_hash,
                           attributes_json, created_at, event_hash
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        tenant_id,
                        run_id,
                        event.sequence,
                        repository_id,
                        actor_id,
                        action,
                        identity_hash,
                        previous_hash,
                        _canonical(normalized_attributes),
                        created_at,
                        event_hash,
                    ),
                )
                self._db.execute(
                    "INSERT INTO audit_chain_idempotency VALUES (?, ?, ?, ?, ?)",
                    (tenant_id, key, request_hash, run_id, event.sequence),
                )
                self._db.commit()
                return event
            except Exception:
                self._db.rollback()
                raise

    def range(
        self,
        tenant_id: str,
        run_id: str,
        start: int = 1,
        end: int | None = None,
    ) -> tuple[AuditEvent, ...]:
        _require_identifier(tenant_id)
        _require_identifier(run_id)
        if type(start) is not int or start < 1:
            raise AuditConflict("audit range start is invalid")
        if end is not None and (type(end) is not int or end < start):
            raise AuditConflict("audit range end is invalid")
        with self._lock:
            self._ensure_available(tenant_id=tenant_id, run_id=run_id)
            sql = """SELECT tenant_id, repository_id, run_id, actor_id, action,
                            execution_identity_hash, sequence, previous_hash,
                            attributes_json, created_at, event_hash
                     FROM audit_chain_events
                     WHERE tenant_id = ? AND run_id = ? AND sequence >= ?"""
            parameters: tuple[object, ...] = (tenant_id, run_id, start)
            if end is not None:
                sql += " AND sequence <= ?"
                parameters += (end,)
            sql += " ORDER BY sequence"
            rows = self._db.execute(sql, parameters).fetchall()
            return tuple(_from_row(row) for row in rows)

    def verified_range(
        self,
        *,
        tenant_id: str,
        run_id: str,
        start: int,
        end: int | None,
        maximum_events: int,
    ) -> tuple[AuditEvent, ...]:
        """Verify and capture one bounded range under the append lock."""
        _require_identifier(tenant_id)
        _require_identifier(run_id)
        if (
            type(start) is not int
            or start < 1
            or (end is not None and (type(end) is not int or end < start))
            or type(maximum_events) is not int
            or maximum_events < 1
        ):
            raise AuditConflict("audit export range is invalid")
        with self._lock:
            self._ensure_available(tenant_id=tenant_id, run_id=run_id)
            self.require_valid(tenant_id=tenant_id, run_id=run_id)
            head = self.head_sequence(tenant_id=tenant_id, run_id=run_id)
            if head == 0 and start == 1 and end is None:
                return ()
            if start > head or (end is not None and end > head):
                raise AuditConflict("audit export range exceeds the audit head")
            upper_bound = head if end is None else end
            if upper_bound - start + 1 > maximum_events:
                raise ValueError("audit export range exceeds the event limit")
            events = self.range(tenant_id, run_id, start, upper_bound)
            if len(events) != upper_bound - start + 1:
                raise AuditConflict("audit export range is incomplete")
            return events

    def verify(self, *, tenant_id: str, run_id: str) -> bool:
        """Recompute the complete chain and reject gaps or modified events."""
        _require_identifier(tenant_id)
        _require_identifier(run_id)
        with self._lock:
            self._ensure_available(tenant_id=tenant_id, run_id=run_id)
            cursor = self._db.execute(
                """SELECT tenant_id, repository_id, run_id, actor_id, action,
                          execution_identity_hash, sequence, previous_hash,
                          attributes_json, created_at, event_hash
                   FROM audit_chain_events
                   WHERE tenant_id = ? AND run_id = ?
                   ORDER BY sequence""",
                (tenant_id, run_id),
            )
            previous_hash = "0" * 64
            expected_sequence = 1
            chain_repository_id: str | None = None
            chain_identity_hash: str | None = None
            for row in cursor:
                event = _from_row(tuple(row))
                if event.sequence != expected_sequence or event.previous_hash != previous_hash:
                    return False
                if chain_repository_id is None:
                    chain_repository_id = event.repository_id
                    chain_identity_hash = event.execution_identity_hash
                elif (
                    event.repository_id != chain_repository_id
                    or event.execution_identity_hash != chain_identity_hash
                ):
                    return False
                material = {
                    "tenant_id": event.tenant_id,
                    "repository_id": event.repository_id,
                    "run_id": event.run_id,
                    "actor_id": event.actor_id,
                    "action": event.action,
                    "execution_identity_hash": event.execution_identity_hash,
                    "sequence": event.sequence,
                    "previous_hash": event.previous_hash,
                    "attributes": event.attributes,
                    "created_at": event.created_at,
                }
                if _digest(material) != event.event_hash:
                    return False
                previous_hash = event.event_hash
                expected_sequence += 1
            return True

    def head_sequence(self, *, tenant_id: str, run_id: str) -> int:
        _require_identifier(tenant_id)
        _require_identifier(run_id)
        with self._lock:
            self._ensure_available(tenant_id=tenant_id, run_id=run_id)
            row = self._db.execute(
                """SELECT sequence FROM audit_chain_events
                   WHERE tenant_id = ? AND run_id = ?
                   ORDER BY sequence DESC LIMIT 1""",
                (tenant_id, run_id),
            ).fetchone()
            return 0 if row is None else _stored_int(row[0])

    def require_valid(self, *, tenant_id: str, run_id: str) -> None:
        if not self.verify(tenant_id=tenant_id, run_id=run_id):
            raise AuditConflict("audit hash chain verification failed")

    def _ensure_available(self, *, tenant_id: str, run_id: str) -> None:
        required_tables = {
            "audit_runs",
            "lifecycle_deletions",
            "lifecycle_repository_scopes",
        }
        present = {
            row[0]
            for row in self._db.execute(
                """SELECT name FROM sqlite_master
                   WHERE type='table' AND name IN (?, ?, ?)""",
                tuple(sorted(required_tables)),
            ).fetchall()
            if type(row[0]) is str
        }
        if not present:
            return
        if present != required_tables:
            raise AuditConflict("audit retention state is unavailable")
        run = self._db.execute(
            """SELECT repository_id, execution_identity_hash
               FROM audit_runs
               WHERE tenant_id=? AND run_id=?""",
            (tenant_id, run_id),
        ).fetchone()
        if run is None:
            raise AuditConflict("audit retention state is unavailable")
        repository_id, identity_hash = run
        if type(repository_id) is not str or type(identity_hash) is not str:
            raise AuditConflict("audit retention state is invalid")
        try:
            _require_identifier(repository_id)
            _require_sha256(identity_hash)
            expected = retention_content_sha256(
                data_class="audit",
                tenant_id=tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                identity_hash=identity_hash,
            )
        except Exception as error:
            raise AuditConflict("audit retention state is invalid") from error
        binding = self._db.execute(
            """SELECT repository_id, execution_identity_hash
               FROM audit_chain_events
               WHERE tenant_id=? AND run_id=?
               ORDER BY sequence LIMIT 1""",
            (tenant_id, run_id),
        ).fetchone()
        if binding is not None and (
            type(binding[0]) is not str
            or type(binding[1]) is not str
            or binding[0] != repository_id
            or binding[1] != identity_hash
        ):
            raise AuditConflict("audit retention binding is invalid")
        tombstone_table = self._db.execute(
            """SELECT 1 FROM sqlite_master
                        WHERE type='table' AND name='audit_retention_tombstones'"""
        ).fetchone()
        tombstone = (
            self._db.execute(
                """SELECT tenant_id, run_id, repository_id,
                                  execution_identity_hash, deletion_id, deleted_at,
                                  head_sequence, head_hash, tombstone_hash
                             FROM audit_retention_tombstones
                            WHERE tenant_id=? AND run_id=?""",
                (tenant_id, run_id),
            ).fetchone()
            if tombstone_table is not None
            else None
        )
        if tombstone is not None:
            deletion_id = _validate_retention_tombstone(
                tuple(tombstone),
                tenant_id=tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                identity_hash=identity_hash,
            )
            deletion = self._db.execute(
                """SELECT content_sha256, identity_hash, data_class, executed
                             FROM lifecycle_deletions
                            WHERE tenant_id=? AND deletion_id=?""",
                (tenant_id, deletion_id),
            ).fetchone()
            if deletion is None:
                raise AuditConflict("audit retention state is unavailable")
            if (
                type(deletion[0]) is not str
                or type(deletion[1]) is not str
                or deletion[0] != expected
                or deletion[1] != identity_hash
                or deletion[2] != "audit"
                or deletion[3] != 1
            ):
                raise AuditConflict("audit retention state is invalid")
            scopes = self._db.execute(
                """SELECT repository_id
                             FROM lifecycle_repository_scopes
                            WHERE tenant_id=? AND deletion_id=?
                            LIMIT 2""",
                (tenant_id, deletion_id),
            ).fetchall()
            if len(scopes) != 1 or type(scopes[0][0]) is not str:
                raise AuditConflict("audit retention state is unavailable")
            if scopes[0][0] != repository_id:
                raise AuditConflict("audit retention state is invalid")
            raise AuditConflict("audit retention has expired")
        deletions = self._db.execute(
            """SELECT deletion_id, content_sha256, identity_hash
               FROM lifecycle_deletions
               WHERE tenant_id=? AND data_class='audit' AND executed=1
                 AND content_sha256=?
               LIMIT 2""",
            (tenant_id, expected),
        ).fetchall()
        if not deletions:
            return
        if len(deletions) != 1:
            raise AuditConflict("audit retention state is ambiguous")
        deletion_id, content_sha256, deletion_identity = deletions[0]
        if (
            type(deletion_id) is not str
            or type(content_sha256) is not str
            or type(deletion_identity) is not str
            or content_sha256 != expected
            or deletion_identity != identity_hash
        ):
            raise AuditConflict("audit retention state is invalid")
        scopes = self._db.execute(
            """SELECT repository_id
               FROM lifecycle_repository_scopes
               WHERE tenant_id=? AND deletion_id=?
               LIMIT 2""",
            (tenant_id, deletion_id),
        ).fetchall()
        if len(scopes) != 1 or type(scopes[0][0]) is not str:
            raise AuditConflict("audit retention state is unavailable")
        if scopes[0][0] != repository_id:
            raise AuditConflict("audit retention state is invalid")
        raise AuditConflict("audit retention has expired")

    def _event(self, tenant_id: str, run_id: str, sequence: int) -> AuditEvent | None:
        row = self._db.execute(
            """SELECT tenant_id, repository_id, run_id, actor_id, action,
                      execution_identity_hash, sequence, previous_hash,
                      attributes_json, created_at, event_hash
               FROM audit_chain_events
               WHERE tenant_id = ? AND run_id = ? AND sequence = ?""",
            (tenant_id, run_id, sequence),
        ).fetchone()
        return None if row is None else _from_row(row)


def erase_audit_run(
    cursor: sqlite3.Cursor,
    *,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    identity_hash: str,
    deletion_id: str,
    deleted_at: str,
) -> None:
    """Remove an audit chain's rows under an existing transaction.

    The complete chain is verified before any row is removed.  The durable
    tombstone commits only the non-sensitive binding and the prior chain head,
    so retention cannot turn a corrupt chain into an apparently valid empty
    chain.  This is logical row deletion with a cryptographic commitment; it
    does not claim physical secure deletion of SQLite or WAL copies.  Readers
    reject a tombstoned run through ``_ensure_available``.
    """

    for value in (tenant_id, repository_id, run_id, deletion_id):
        _require_identifier(value)
    _require_sha256(identity_hash)
    _parse_utc(deleted_at)
    required_tables = {
        "audit_chain_events",
        "audit_chain_idempotency",
        "audit_retention_tombstones",
    }
    present = {
        row[0]
        for row in cursor.execute(
            """SELECT name FROM sqlite_master
                       WHERE type='table' AND name IN (?, ?, ?)""",
            tuple(sorted(required_tables)),
        ).fetchall()
        if type(row[0]) is str
    }
    if present != required_tables:
        raise AuditConflict("audit retention schema is incomplete")
    existing = cursor.execute(
        """SELECT tenant_id, run_id, repository_id,
                          execution_identity_hash, deletion_id, deleted_at,
                          head_sequence, head_hash, tombstone_hash
                     FROM audit_retention_tombstones
                    WHERE tenant_id=? AND run_id=?""",
        (tenant_id, run_id),
    ).fetchone()
    if existing is not None:
        raise AuditConflict("audit retention marker already exists")
    head_sequence, head_hash = _verify_chain_cursor(
        cursor,
        tenant_id=tenant_id,
        repository_id=repository_id,
        run_id=run_id,
        identity_hash=identity_hash,
    )
    for row in cursor.execute(
        """SELECT request_sha256, run_id, sequence
                     FROM audit_chain_idempotency
                    WHERE tenant_id=? AND run_id=?""",
        (tenant_id, run_id),
    ).fetchall():
        if (
            type(row[0]) is not str
            or type(row[1]) is not str
            or row[1] != run_id
        ):
            raise AuditConflict("audit retention idempotency state is invalid")
        _require_sha256(row[0])
        sequence = _stored_nonnegative_int(row[2])
        event = cursor.execute(
            """SELECT 1 FROM audit_chain_events
                        WHERE tenant_id=? AND run_id=? AND sequence=?""",
            (tenant_id, run_id, sequence),
        ).fetchone()
        if event is None:
            raise AuditConflict("audit retention idempotency state is invalid")
    material = {
        "deleted_at": deleted_at,
        "deletion_id": deletion_id,
        "execution_identity_hash": identity_hash,
        "head_hash": head_hash,
        "head_sequence": head_sequence,
        "repository_id": repository_id,
        "run_id": run_id,
        "schema_version": 1,
        "tenant_id": tenant_id,
    }
    tombstone_hash = _digest(material)
    try:
        cursor.execute(
            """DELETE FROM audit_chain_idempotency
                        WHERE tenant_id=? AND run_id=?""",
            (tenant_id, run_id),
        )
        cursor.execute(
            """DELETE FROM audit_chain_events
                        WHERE tenant_id=? AND run_id=?""",
            (tenant_id, run_id),
        )
        cursor.execute(
            """INSERT INTO audit_retention_tombstones (
                       tenant_id, run_id, repository_id,
                       execution_identity_hash, deletion_id, deleted_at,
                       head_sequence, head_hash, tombstone_hash
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                tenant_id,
                run_id,
                repository_id,
                identity_hash,
                deletion_id,
                deleted_at,
                head_sequence,
                head_hash,
                tombstone_hash,
            ),
        )
    except sqlite3.Error as error:
        raise AuditConflict("audit retention erasure failed") from error


def _verify_chain_cursor(
    cursor: sqlite3.Cursor,
    *,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    identity_hash: str,
) -> tuple[int, str]:
    previous_hash = "0" * 64
    expected_sequence = 1
    for row in cursor.execute(
        """SELECT tenant_id, repository_id, run_id, actor_id, action,
                          execution_identity_hash, sequence, previous_hash,
                          attributes_json, created_at, event_hash
                     FROM audit_chain_events
                    WHERE tenant_id=? AND run_id=?
                    ORDER BY sequence""",
        (tenant_id, run_id),
    ).fetchall():
        event = _from_row(tuple(row))
        if (
            event.tenant_id != tenant_id
            or event.repository_id != repository_id
            or event.run_id != run_id
            or event.execution_identity_hash != identity_hash
            or event.sequence != expected_sequence
            or event.previous_hash != previous_hash
        ):
            raise AuditConflict("audit hash chain verification failed")
        material = {
            "tenant_id": event.tenant_id,
            "repository_id": event.repository_id,
            "run_id": event.run_id,
            "actor_id": event.actor_id,
            "action": event.action,
            "execution_identity_hash": event.execution_identity_hash,
            "sequence": event.sequence,
            "previous_hash": event.previous_hash,
            "attributes": event.attributes,
            "created_at": event.created_at,
        }
        if _digest(material) != event.event_hash:
            raise AuditConflict("audit hash chain verification failed")
        previous_hash = event.event_hash
        expected_sequence += 1
    return expected_sequence - 1, previous_hash


def _validate_retention_tombstone(
    row: tuple[object, ...],
    *,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    identity_hash: str,
) -> str:
    if len(row) != 9 or not all(
        type(row[index]) is str for index in (0, 1, 2, 3, 4, 5, 7, 8)
    ):
        raise AuditConflict("audit retention marker is invalid")
    marker_tenant = cast(str, row[0])
    marker_run = cast(str, row[1])
    marker_repository = cast(str, row[2])
    marker_identity = cast(str, row[3])
    deletion_id = cast(str, row[4])
    deleted_at = cast(str, row[5])
    head_sequence = _stored_nonnegative_int(row[6])
    head_hash = cast(str, row[7])
    tombstone_hash = cast(str, row[8])
    for value in (marker_tenant, marker_repository, marker_run, deletion_id):
        _require_identifier(value)
    _require_sha256(marker_identity)
    _parse_utc(deleted_at)
    _require_sha256(head_hash)
    _require_sha256(tombstone_hash)
    if head_sequence == 0 and head_hash != "0" * 64:
        raise AuditConflict("audit retention marker is invalid")
    if (
        marker_tenant != tenant_id
        or marker_repository != repository_id
        or marker_run != run_id
        or marker_identity != identity_hash
    ):
        raise AuditConflict("audit retention marker is invalid")
    material = {
        "deleted_at": deleted_at,
        "deletion_id": deletion_id,
        "execution_identity_hash": marker_identity,
        "head_hash": head_hash,
        "head_sequence": head_sequence,
        "repository_id": marker_repository,
        "run_id": marker_run,
        "schema_version": 1,
        "tenant_id": marker_tenant,
    }
    if _digest(material) != tombstone_hash:
        raise AuditConflict("audit retention marker is invalid")
    return deletion_id


_ALLOWED_ATTRIBUTES: Final = {
    "outcome": str,
    "reason_code": str,
    "resource_type": str,
    "retention_marked": bool,
}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_ATTRIBUTE_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_RESOURCE_TYPES = frozenset({"metadata", "artifact", "audit"})
_HEX = frozenset("0123456789abcdef")


def _validate_attributes(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or len(value) > len(_ALLOWED_ATTRIBUTES):
        raise AuditConflict("audit attributes are invalid")
    result: dict[str, object] = {}
    for key, item in value.items():
        if type(key) is not str:
            raise AuditConflict("audit attributes contain disallowed data")
        expected_type = _ALLOWED_ATTRIBUTES.get(key)
        if expected_type is None or type(item) is not expected_type:
            raise AuditConflict("audit attributes contain disallowed data")
        if isinstance(item, str):
            if key == "outcome" and _ATTRIBUTE_TOKEN.fullmatch(item) is None:
                raise AuditConflict("audit attribute string is invalid")
            if key == "reason_code" and _REASON_CODE.fullmatch(item) is None:
                raise AuditConflict("audit attribute string is invalid")
            if key == "resource_type" and item not in _RESOURCE_TYPES:
                raise AuditConflict("audit attribute string is invalid")
        result[key] = item
    return result


def _from_row(row: tuple[object, ...]) -> AuditEvent:
    try:
        if not all(type(row[index]) is str for index in (0, 1, 2, 3, 4, 5, 7, 8, 9, 10)):
            raise AuditConflict("stored audit fields are invalid")
        attributes = json.loads(cast(str, row[8]))
    except json.JSONDecodeError as error:
        raise AuditConflict("stored audit attributes are invalid") from error
    if not isinstance(attributes, dict):
        raise AuditConflict("stored audit attributes are invalid")
    return AuditEvent(
        tenant_id=cast(str, row[0]),
        repository_id=cast(str, row[1]),
        run_id=cast(str, row[2]),
        actor_id=cast(str, row[3]),
        action=cast(str, row[4]),
        execution_identity_hash=cast(str, row[5]),
        sequence=_stored_int(row[6]),
        previous_hash=cast(str, row[7]),
        attributes=_validate_attributes(attributes),
        created_at=cast(str, row[9]),
        event_hash=cast(str, row[10]),
    )


def _resource_from_row(row: tuple[object, ...]) -> AuditResourceEvent:
    try:
        if not all(type(row[index]) is str for index in (0, 1, 2, 3, 4, 6, 7, 8, 9)):
            raise AuditConflict("stored resource audit fields are invalid")
        attributes = json.loads(cast(str, row[7]))
    except json.JSONDecodeError as error:
        raise AuditConflict("stored resource audit attributes are invalid") from error
    if not isinstance(attributes, dict):
        raise AuditConflict("stored resource audit attributes are invalid")
    return AuditResourceEvent(
        tenant_id=cast(str, row[0]),
        resource_type=cast(str, row[1]),
        resource_key_sha256=cast(str, row[2]),
        actor_id=cast(str, row[3]),
        action=cast(str, row[4]),
        sequence=_stored_int(row[5]),
        previous_hash=cast(str, row[6]),
        attributes=_validate_attributes(attributes),
        created_at=cast(str, row[8]),
        event_hash=cast(str, row[9]),
    )


def _stored_int(value: object) -> int:
    if type(value) is not int or value < 1:
        raise AuditConflict("stored audit integer is invalid")
    return value


def _stored_nonnegative_int(value: object) -> int:
    if type(value) is not int or value < 0:
        raise AuditConflict("stored audit integer is invalid")
    return value


def _require_sha256_value(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(item in _HEX for item in value)


def _request_hash(
    *,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    actor_id: str,
    action: str,
    identity_hash: str,
    attributes: dict[str, object],
) -> str:
    return _digest(
        {
            "tenant_id": tenant_id,
            "repository_id": repository_id,
            "run_id": run_id,
            "actor_id": actor_id,
            "action": action,
            "execution_identity_hash": identity_hash,
            "attributes": attributes,
        }
    )


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
        raise AuditConflict("audit metadata is not canonical JSON") from error


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _require_identifier(value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise AuditConflict("audit identifier is invalid")
    return value


def _require_sha256(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(item not in _HEX for item in value):
        raise AuditConflict("audit SHA-256 value is invalid")
    return value


def _require_sha256_value(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(item in "0123456789abcdef" for item in value)


def _require_key(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
    ):
        raise AuditConflict("audit idempotency key is invalid")
    return value


def _parse_utc(value: str) -> datetime:
    if type(value) is not str:
        raise ValueError("audit timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("audit timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("audit timestamp must be UTC")
    return parsed


def _checked_now(source: Callable[[], datetime]) -> datetime:
    value = source()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise AuditConflict("clock returned an invalid timestamp")
    return value


__all__ = [
    "AUDIT_LOG_SCHEMA_STATEMENTS",
    "AuditConflict",
    "AuditEvent",
    "AuditResourceEvent",
    "AuditLog",
    "erase_audit_run",
]
