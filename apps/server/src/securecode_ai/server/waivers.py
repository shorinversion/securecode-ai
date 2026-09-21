"""Durable, exact-scope, expiring security waivers."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from .approvals import ApprovalDecision, ApprovalState


class WaiverConflict(Exception):
    """Raised when a waiver is invalid, stale, or replayed divergently."""


@dataclass(frozen=True, slots=True)
class WaiverScope:
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    finding_fingerprint: str | None = None
    cwe_id: str | None = None
    path: str | None = None
    policy_scope: str | None = None

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.repository_id, self.run_id):
            _require_identifier(value)
        _require_sha256(self.execution_identity_hash)
        if self.finding_fingerprint is not None:
            _require_sha256(self.finding_fingerprint)
        if self.cwe_id is not None and re.fullmatch(r"CWE-[1-9][0-9]{0,5}", self.cwe_id) is None:
            raise ValueError("waiver CWE id is invalid")
        if self.path is not None:
            _require_relative_path(self.path)
        if self.policy_scope is not None:
            _require_identifier(self.policy_scope)
        if not any((self.finding_fingerprint, self.cwe_id, self.path, self.policy_scope)):
            raise ValueError("waiver must contain a bounded selector")

    def matches(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        identity_hash: str,
        finding_fingerprint: str | None = None,
        cwe_id: str | None = None,
        path: str | None = None,
        policy_scope: str | None = None,
    ) -> bool:
        if (
            self.tenant_id,
            self.repository_id,
            self.run_id,
            self.execution_identity_hash,
        ) != (tenant_id, repository_id, run_id, identity_hash):
            return False
        supplied = {
            "finding_fingerprint": finding_fingerprint,
            "cwe_id": cwe_id,
            "path": path,
            "policy_scope": policy_scope,
        }
        for name in supplied:
            required = getattr(self, name)
            if required is not None and supplied[name] != required:
                return False
        return True


@dataclass(frozen=True, slots=True)
class WaiverRecord:
    waiver_id: str
    scope: WaiverScope
    expires_at: datetime
    approval_id: str
    rationale_sha256: str
    version: int = 1

    def __post_init__(self) -> None:
        _require_identifier(self.waiver_id)
        _require_identifier(self.approval_id)
        _require_sha256(self.rationale_sha256)
        _require_utc(self.expires_at)
        if type(self.version) is not int or self.version < 1:
            raise ValueError("waiver version must be a positive integer")

    def applies(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        identity_hash: str,
        now: datetime,
    ) -> bool:
        """Compatibility lifecycle check; authorization should call ``matches`` too."""
        return self.expires_at > now and (
            self.scope.tenant_id,
            self.scope.repository_id,
            self.scope.run_id,
            self.scope.execution_identity_hash,
        ) == (tenant_id, repository_id, run_id, identity_hash)


WAIVER_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS security_waivers (
        waiver_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL,
        finding_fingerprint TEXT,
        cwe_id TEXT,
        path TEXT,
        policy_scope TEXT,
        expires_at TEXT NOT NULL,
        approval_id TEXT NOT NULL,
        rationale_sha256 TEXT NOT NULL,
        version INTEGER NOT NULL,
        revoked_at TEXT,
        CHECK (version >= 1)
    )""",
    """CREATE INDEX IF NOT EXISTS security_waivers_tenant_run
        ON security_waivers (tenant_id, repository_id, run_id, expires_at)""",
    """CREATE TABLE IF NOT EXISTS waiver_idempotency (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        waiver_id TEXT NOT NULL,
        result_version INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key)
    )""",
)


class WaiverLedger:
    """Transactional waiver storage bound to approved, separate decisions."""

    def __init__(
        self,
        connection: sqlite3.Connection | None = None,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._db = connection or sqlite3.connect(":memory:", check_same_thread=False)
        self._now = now
        self._lock = threading.RLock()
        for statement in WAIVER_SCHEMA_STATEMENTS:
            self._db.execute(statement)
        self._db.commit()

    def grant(
        self,
        record: WaiverRecord,
        *,
        approval: ApprovalDecision,
        idempotency_key: str,
    ) -> WaiverRecord:
        if (
            approval.approval_id != record.approval_id
            or approval.tenant_id != record.scope.tenant_id
            or approval.state is not ApprovalState.APPROVED
            or approval.rationale_sha256 != record.rationale_sha256
        ):
            raise WaiverConflict("waiver requires its approved decision")
        if approval.actor_id == "":
            raise WaiverConflict("approval actor is invalid")
        now = _checked_now(self._now)
        if record.expires_at <= now or record.expires_at > now + timedelta(days=90):
            raise WaiverConflict("waiver expiry is outside the allowed window")
        key = _require_key(idempotency_key)
        fingerprint = _record_fingerprint(record)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._read_replay(record.scope.tenant_id, key)
                if replay is not None:
                    if replay[:2] != ("grant", fingerprint):
                        raise WaiverConflict("idempotency key was reused")
                    existing = self.get(record.scope.tenant_id, replay[2])
                    if existing is None:
                        raise WaiverConflict("waiver replay is incomplete")
                    self._db.commit()
                    return existing
                if self._row(record.scope.tenant_id, record.waiver_id) is not None:
                    raise WaiverConflict("waiver id already exists")
                self._insert(record)
                self._insert_replay(record.scope.tenant_id, key, "grant", fingerprint, record)
                self._db.commit()
                return record
            except Exception:
                self._db.rollback()
                raise

    def revoke(
        self,
        *,
        tenant_id: str,
        waiver_id: str,
        expected_version: int,
        idempotency_key: str,
    ) -> WaiverRecord:
        _require_identifier(tenant_id)
        _require_identifier(waiver_id)
        if type(expected_version) is not int or expected_version < 1:
            raise WaiverConflict("expected version is invalid")
        key = _require_key(idempotency_key)
        fingerprint = _digest(
            {"tenant_id": tenant_id, "waiver_id": waiver_id, "version": expected_version}
        )
        now = _checked_now(self._now)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._read_replay(tenant_id, key)
                if replay is not None:
                    if replay[:2] != ("revoke", fingerprint):
                        raise WaiverConflict("idempotency key was reused")
                    result = self.get(tenant_id, waiver_id)
                    if result is None:
                        raise WaiverConflict("waiver replay is incomplete")
                    self._db.commit()
                    return result
                changed = self._db.execute(
                    """UPDATE security_waivers
                       SET version = version + 1, revoked_at = ?
                       WHERE tenant_id = ? AND waiver_id = ?
                         AND version = ? AND revoked_at IS NULL""",
                    (now.isoformat(), tenant_id, waiver_id, expected_version),
                ).rowcount
                if changed != 1:
                    raise WaiverConflict("waiver state changed concurrently")
                result = self.get(tenant_id, waiver_id)
                if result is None:
                    raise WaiverConflict("waiver disappeared")
                self._insert_replay(tenant_id, key, "revoke", fingerprint, result)
                self._db.commit()
                return result
            except Exception:
                self._db.rollback()
                raise

    def get(self, tenant_id: str, waiver_id: str) -> WaiverRecord | None:
        _require_identifier(tenant_id)
        _require_identifier(waiver_id)
        row = self._row(tenant_id, waiver_id)
        if row is None:
            return None
        return _from_row(row)

    def active(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        identity_hash: str,
        finding_fingerprint: str | None = None,
        cwe_id: str | None = None,
        path: str | None = None,
        policy_scope: str | None = None,
    ) -> tuple[WaiverRecord, ...]:
        for value in (tenant_id, repository_id, run_id):
            _require_identifier(value)
        _require_sha256(identity_hash)
        if finding_fingerprint is not None:
            _require_sha256(finding_fingerprint)
        if cwe_id is not None and re.fullmatch(r"CWE-[1-9][0-9]{0,5}", cwe_id) is None:
            raise WaiverConflict("waiver CWE id is invalid")
        if path is not None:
            _require_relative_path(path)
        if policy_scope is not None:
            _require_identifier(policy_scope)
        now = _checked_now(self._now)
        rows = self._db.execute(
            """SELECT waiver_id, tenant_id, repository_id, run_id,
                      execution_identity_hash, finding_fingerprint, cwe_id, path,
                      policy_scope, expires_at, approval_id, rationale_sha256, version
               FROM security_waivers
               WHERE tenant_id = ? AND repository_id = ? AND run_id = ?
                 AND execution_identity_hash = ? AND expires_at > ?
                 AND revoked_at IS NULL ORDER BY waiver_id""",
            (tenant_id, repository_id, run_id, identity_hash, now.isoformat()),
        ).fetchall()
        values = tuple(_from_row(row) for row in rows)
        return tuple(
            item
            for item in values
            if item.scope.matches(
                tenant_id=tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                identity_hash=identity_hash,
                finding_fingerprint=finding_fingerprint,
                cwe_id=cwe_id,
                path=path,
                policy_scope=policy_scope,
            )
        )

    def _row(self, tenant_id: str, waiver_id: str) -> tuple[object, ...] | None:
        row: tuple[object, ...] | None = self._db.execute(
            """SELECT waiver_id, tenant_id, repository_id, run_id,
                      execution_identity_hash, finding_fingerprint, cwe_id, path,
                      policy_scope, expires_at, approval_id, rationale_sha256, version
               FROM security_waivers WHERE tenant_id = ? AND waiver_id = ?""",
            (tenant_id, waiver_id),
        ).fetchone()
        return row

    def _insert(self, record: WaiverRecord) -> None:
        scope = record.scope
        self._db.execute(
            """INSERT INTO security_waivers (
                   waiver_id, tenant_id, repository_id, run_id,
                   execution_identity_hash, finding_fingerprint, cwe_id, path,
                   policy_scope, expires_at, approval_id, rationale_sha256, version
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                record.waiver_id,
                scope.tenant_id,
                scope.repository_id,
                scope.run_id,
                scope.execution_identity_hash,
                scope.finding_fingerprint,
                scope.cwe_id,
                scope.path,
                scope.policy_scope,
                record.expires_at.isoformat(),
                record.approval_id,
                record.rationale_sha256,
                record.version,
            ),
        )

    def _read_replay(self, tenant_id: str, key: str) -> tuple[str, str, str, int] | None:
        row = self._db.execute(
            """SELECT operation, request_sha256, waiver_id, result_version
               FROM waiver_idempotency WHERE tenant_id = ? AND idempotency_key = ?""",
            (tenant_id, key),
        ).fetchone()
        return None if row is None else (str(row[0]), str(row[1]), str(row[2]), int(row[3]))

    def _insert_replay(
        self,
        tenant_id: str,
        key: str,
        operation: str,
        fingerprint: str,
        record: WaiverRecord,
    ) -> None:
        self._db.execute(
            "INSERT INTO waiver_idempotency VALUES (?, ?, ?, ?, ?, ?)",
            (tenant_id, key, operation, fingerprint, record.waiver_id, record.version),
        )


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_HEX = frozenset("0123456789abcdef")


def _require_identifier(value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("identifier is invalid")
    return value


def _require_sha256(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(item not in _HEX for item in value):
        raise ValueError("SHA-256 value is invalid")
    return value


def _require_utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be timezone-aware UTC")
    return value


def _require_relative_path(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 1024:
        raise ValueError("waiver path is invalid")
    normalized = value.replace("\\", "/")
    if normalized.startswith("/") or ".." in normalized.split("/") or "\x00" in value:
        raise ValueError("waiver path must be repository-relative")
    return value


def _checked_now(source: Callable[[], datetime]) -> datetime:
    try:
        return _require_utc(source())
    except (TypeError, ValueError) as error:
        raise WaiverConflict("clock returned an invalid timestamp") from error


def _require_key(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise WaiverConflict("idempotency key is invalid")
    return value


def _digest(document: dict[str, object]) -> str:
    payload = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _record_fingerprint(record: WaiverRecord) -> str:
    return _digest(
        {
            "waiver_id": record.waiver_id,
            "scope": {
                "tenant_id": record.scope.tenant_id,
                "repository_id": record.scope.repository_id,
                "run_id": record.scope.run_id,
                "execution_identity_hash": record.scope.execution_identity_hash,
                "finding_fingerprint": record.scope.finding_fingerprint,
                "cwe_id": record.scope.cwe_id,
                "path": record.scope.path,
                "policy_scope": record.scope.policy_scope,
            },
            "expires_at": record.expires_at.isoformat(),
            "approval_id": record.approval_id,
            "rationale_sha256": record.rationale_sha256,
            "version": record.version,
        }
    )


def _from_row(row: tuple[object, ...]) -> WaiverRecord:
    scope = WaiverScope(
        tenant_id=str(row[1]),
        repository_id=str(row[2]),
        run_id=str(row[3]),
        execution_identity_hash=str(row[4]),
        finding_fingerprint=None if row[5] is None else str(row[5]),
        cwe_id=None if row[6] is None else str(row[6]),
        path=None if row[7] is None else str(row[7]),
        policy_scope=None if row[8] is None else str(row[8]),
    )
    return WaiverRecord(
        waiver_id=str(row[0]),
        scope=scope,
        expires_at=datetime.fromisoformat(str(row[9])),
        approval_id=str(row[10]),
        rationale_sha256=str(row[11]),
        version=_stored_int(row[12]),
    )


def _stored_int(value: object) -> int:
    if type(value) is not int:
        raise WaiverConflict("stored waiver version is invalid")
    return value


__all__ = [
    "WAIVER_SCHEMA_STATEMENTS",
    "WaiverConflict",
    "WaiverLedger",
    "WaiverRecord",
    "WaiverScope",
]
