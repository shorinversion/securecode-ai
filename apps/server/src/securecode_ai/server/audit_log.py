"""Durable append-only metadata audit log with hash-chain verification."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final


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
        self._db.commit()

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
            expected_sequence=expected_sequence,
            attributes=normalized_attributes,
        )
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._db.execute(
                    """SELECT request_sha256, run_id, sequence
                       FROM audit_chain_idempotency
                       WHERE tenant_id = ? AND idempotency_key = ?""",
                    (tenant_id, key),
                ).fetchone()
                if replay is not None:
                    if str(replay[0]) != request_hash or str(replay[1]) != run_id:
                        raise AuditConflict("idempotency key was reused")
                    result = self._event(tenant_id, run_id, int(replay[2]))
                    if result is None:
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
                current_sequence = 0 if head is None else int(head[0])
                if current_sequence != expected_sequence:
                    raise AuditConflict("audit sequence changed")
                if head is not None and (
                    str(head[1]) != repository_id or str(head[2]) != identity_hash
                ):
                    raise AuditConflict("run audit identity changed")
                previous_hash = "0" * 64 if head is None else str(head[3])
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

    def verify(self, *, tenant_id: str, run_id: str) -> bool:
        """Recompute the complete chain and reject gaps or modified events."""
        events = self.range(tenant_id, run_id)
        previous_hash = "0" * 64
        for expected_sequence, event in enumerate(events, start=1):
            if event.sequence != expected_sequence or event.previous_hash != previous_hash:
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
        return True

    def require_valid(self, *, tenant_id: str, run_id: str) -> None:
        if not self.verify(tenant_id=tenant_id, run_id=run_id):
            raise AuditConflict("audit hash chain verification failed")

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


_ALLOWED_ATTRIBUTES: Final = {
    "outcome": str,
    "reason_code": str,
    "resource_type": str,
    "retention_marked": bool,
}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_HEX = frozenset("0123456789abcdef")


def _validate_attributes(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or len(value) > len(_ALLOWED_ATTRIBUTES):
        raise AuditConflict("audit attributes are invalid")
    result: dict[str, object] = {}
    for key, item in value.items():
        expected_type = _ALLOWED_ATTRIBUTES.get(key)
        if expected_type is None or type(item) is not expected_type:
            raise AuditConflict("audit attributes contain disallowed data")
        if isinstance(item, str) and (
            not 1 <= len(item) <= 128 or any(ord(character) < 32 for character in item)
        ):
            raise AuditConflict("audit attribute string is invalid")
        result[key] = item
    return result


def _from_row(row: tuple[object, ...]) -> AuditEvent:
    try:
        attributes = json.loads(str(row[8]))
    except json.JSONDecodeError as error:
        raise AuditConflict("stored audit attributes are invalid") from error
    if not isinstance(attributes, dict):
        raise AuditConflict("stored audit attributes are invalid")
    return AuditEvent(
        tenant_id=str(row[0]),
        repository_id=str(row[1]),
        run_id=str(row[2]),
        actor_id=str(row[3]),
        action=str(row[4]),
        execution_identity_hash=str(row[5]),
        sequence=_stored_int(row[6]),
        previous_hash=str(row[7]),
        attributes=_validate_attributes(attributes),
        created_at=str(row[9]),
        event_hash=str(row[10]),
    )


def _stored_int(value: object) -> int:
    if type(value) is not int:
        raise AuditConflict("stored audit integer is invalid")
    return value


def _request_hash(
    *,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    actor_id: str,
    action: str,
    identity_hash: str,
    expected_sequence: int,
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
            "expected_sequence": expected_sequence,
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


def _require_key(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise AuditConflict("audit idempotency key is invalid")
    return value


def _parse_utc(value: str) -> datetime:
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


__all__ = ["AUDIT_LOG_SCHEMA_STATEMENTS", "AuditConflict", "AuditEvent", "AuditLog"]
