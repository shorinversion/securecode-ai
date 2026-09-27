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

from .approvals import ApprovalDecision, ApprovalRequest, ApprovalState


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
            if type(self.finding_fingerprint) is not str:
                raise ValueError("waiver finding fingerprint is invalid")
            _require_sha256(self.finding_fingerprint)
        if self.cwe_id is not None and (
            type(self.cwe_id) is not str
            or re.fullmatch(r"CWE-[1-9][0-9]{0,5}", self.cwe_id) is None
        ):
            raise ValueError("waiver CWE id is invalid")
        if self.path is not None:
            _require_relative_path(self.path)
        if self.policy_scope is not None:
            if type(self.policy_scope) is not str:
                raise ValueError("waiver policy scope is invalid")
            _require_identifier(self.policy_scope)
        if not any((self.finding_fingerprint, self.cwe_id, self.path, self.policy_scope)):
            raise ValueError("waiver must contain a bounded selector")
        if self.finding_fingerprint is None:
            raise ValueError("waiver must be bound to an exact finding")

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
        if type(self.scope) is not WaiverScope:
            raise ValueError("waiver scope is invalid")
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
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            return False
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
        if connection is not None and type(connection) is not sqlite3.Connection:
            raise WaiverConflict("waiver storage is invalid")
        self._db = (
            connection
            if connection is not None
            else sqlite3.connect(":memory:", check_same_thread=False)
        )
        if not callable(now):
            raise WaiverConflict("waiver clock is invalid")
        self._now = now
        self._lock = threading.RLock()
        try:
            for statement in WAIVER_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            self._db.commit()
        except sqlite3.Error as error:
            raise WaiverConflict("waiver storage is unavailable") from error

    def grant(
        self,
        record: WaiverRecord,
        *,
        approval: ApprovalDecision,
        approval_request: ApprovalRequest,
        idempotency_key: str,
    ) -> WaiverRecord:
        if (
            type(record) is not WaiverRecord
            or type(approval) is not ApprovalDecision
            or type(approval_request) is not ApprovalRequest
            or approval.approval_id != record.approval_id
            or approval_request.approval_id != record.approval_id
            or approval.tenant_id != record.scope.tenant_id
            or approval_request.tenant_id != record.scope.tenant_id
            or approval.state is not ApprovalState.APPROVED
            or approval_request.state is not ApprovalState.APPROVED
            or approval_request.finding_fingerprint != record.scope.finding_fingerprint
            or approval_request.revision_sha is None
            or approval.version != approval_request.version
            or approval.rationale_sha256 != record.rationale_sha256
            or (
                approval_request.repository_id,
                approval_request.run_id,
                approval_request.execution_identity_hash,
            )
            != (
                record.scope.repository_id,
                record.scope.run_id,
                record.scope.execution_identity_hash,
            )
        ):
            raise WaiverConflict("waiver requires an approved decision for its exact scope")
        key = _require_key(idempotency_key)
        fingerprint = _record_fingerprint(record)
        with self._lock:
            self._begin()
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
                self._validate_approved_finding(record, approval_request, approval)
                now = _checked_now(self._now)
                if record.expires_at <= now or record.expires_at > now + timedelta(days=90):
                    raise WaiverConflict("waiver expiry is outside the allowed window")
                if self._row(record.scope.tenant_id, record.waiver_id) is not None:
                    raise WaiverConflict("waiver id already exists")
                self._insert(record)
                self._insert_replay(record.scope.tenant_id, key, "grant", fingerprint, record)
                self._db.commit()
                return record
            except sqlite3.Error as error:
                self._db.rollback()
                raise WaiverConflict("waiver storage is unavailable") from error
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
        with self._lock:
            self._begin()
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
                now = _checked_now(self._now)
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
            except sqlite3.Error as error:
                self._db.rollback()
                raise WaiverConflict("waiver storage is unavailable") from error
            except Exception:
                self._db.rollback()
                raise

    def _begin(self) -> None:
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            raise WaiverConflict("waiver storage is unavailable") from error

    def get(self, tenant_id: str, waiver_id: str) -> WaiverRecord | None:
        _require_identifier(tenant_id)
        _require_identifier(waiver_id)
        try:
            with self._lock:
                row = self._row(tenant_id, waiver_id)
                if row is None:
                    return None
                return _from_row(row)
        except sqlite3.Error as error:
            raise WaiverConflict("waiver storage is unavailable") from error

    def active(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        identity_hash: str,
        finding_id: str,
        finding_fingerprint: str,
        cwe_id: str | None = None,
        path: str | None = None,
        policy_scope: str | None = None,
    ) -> tuple[WaiverRecord, ...]:
        for value in (tenant_id, repository_id, run_id, finding_id):
            _require_identifier(value)
        _require_sha256(identity_hash)
        _require_sha256(finding_fingerprint)
        if cwe_id is not None and (
            type(cwe_id) is not str
            or re.fullmatch(r"CWE-[1-9][0-9]{0,5}", cwe_id) is None
        ):
            raise WaiverConflict("waiver CWE id is invalid")
        if path is not None:
            _require_relative_path(path)
        if policy_scope is not None:
            _require_identifier(policy_scope)
        try:
            with self._lock:
                now = _checked_now(self._now)
                rows = self._db.execute(
                    """SELECT waiver_id, tenant_id, repository_id, run_id,
                              execution_identity_hash, finding_fingerprint, cwe_id, path,
                              policy_scope, expires_at, approval_id, rationale_sha256, version
                       FROM security_waivers
                       WHERE tenant_id = ? AND repository_id = ? AND run_id = ?
                         AND execution_identity_hash = ? AND expires_at > ?
                         AND finding_fingerprint IS NOT NULL
                         AND revoked_at IS NULL ORDER BY waiver_id""",
                    (tenant_id, repository_id, run_id, identity_hash, now.isoformat()),
                )
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
                    and self._approval_matches_scope(item, finding_id=finding_id)
                )
        except sqlite3.Error as error:
            raise WaiverConflict("waiver storage is unavailable") from error

    def is_active(self, tenant_id: str, waiver_id: str) -> bool:
        record = self.get(tenant_id, waiver_id)
        if record is None or record.scope.finding_fingerprint is None:
            return False
        try:
            with self._lock:
                row = self._db.execute(
                    "SELECT finding_id FROM approval_requests WHERE tenant_id=? AND approval_id=?",
                    (tenant_id, record.approval_id),
                ).fetchone()
                if row is None or type(row[0]) is not str:
                    return False
                return record in self.active(
                    tenant_id=record.scope.tenant_id,
                    repository_id=record.scope.repository_id,
                    run_id=record.scope.run_id,
                    identity_hash=record.scope.execution_identity_hash,
                    finding_id=row[0],
                    finding_fingerprint=record.scope.finding_fingerprint,
                    cwe_id=record.scope.cwe_id,
                    path=record.scope.path,
                    policy_scope=record.scope.policy_scope,
                )
        except sqlite3.Error as error:
            raise WaiverConflict("waiver storage is unavailable") from error

    def covers_blocking_findings(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        identity_hash: str,
        findings: tuple[tuple[str, str], ...],
        policy_scope: str | None = None,
    ) -> bool:
        if type(findings) is not tuple or not findings:
            return False
        for finding_id, fingerprint in findings:
            try:
                if not self.active(
                    tenant_id=tenant_id,
                    repository_id=repository_id,
                    run_id=run_id,
                    identity_hash=identity_hash,
                    finding_id=finding_id,
                    finding_fingerprint=fingerprint,
                    policy_scope=policy_scope,
                ):
                    return False
            except (TypeError, ValueError, WaiverConflict):
                return False
        return True

    def revision_hash(
        self,
        *,
        tenant_id: str,
        run_id: str,
        identity_hash: str,
    ) -> str:
        """Return a durable opaque token that changes after grant or revoke."""

        for value in (tenant_id, run_id):
            _require_identifier(value)
        _require_sha256(identity_hash)
        try:
            with self._lock:
                rows = self._db.execute(
                    """SELECT w.repository_id, w.waiver_id, w.finding_fingerprint, w.expires_at,
                              w.approval_id, w.rationale_sha256, w.version, w.revoked_at,
                              a.state, a.version, a.finding_fingerprint, a.revision_sha
                       FROM security_waivers AS w
                       LEFT JOIN approval_requests AS a
                         ON a.tenant_id=w.tenant_id AND a.approval_id=w.approval_id
                       WHERE w.tenant_id=? AND w.run_id=?
                         AND w.execution_identity_hash=?
                       ORDER BY w.waiver_id""",
                    (tenant_id, run_id, identity_hash),
                )
                values: list[list[object]] = []
                for row in rows:
                    if type(row) not in {tuple, sqlite3.Row} or len(row) != 12:
                        raise WaiverConflict("stored waiver revision is invalid")
                    values.append(list(row))
                return _digest(
                    {
                        "tenant_id": tenant_id,
                        "run_id": run_id,
                        "execution_identity_hash": identity_hash,
                        "waivers": values,
                    }
                )
        except sqlite3.Error as error:
            raise WaiverConflict("waiver storage is unavailable") from error

    def expired_published_runs(
        self,
        *,
        tenant_id: str,
        max_items: int,
    ) -> tuple[tuple[str, str], ...]:
        """List bounded runs whose published PASS may rely on an expired waiver."""

        _require_identifier(tenant_id)
        if type(max_items) is not int or not 1 <= max_items <= 256:
            raise WaiverConflict("waiver expiry batch size is invalid")
        now = _checked_now(self._now)
        try:
            with self._lock:
                rows = self._db.execute(
                    """SELECT DISTINCT w.run_id, w.execution_identity_hash
                       FROM security_waivers AS w
                       JOIN scm_publication_targets AS p
                         ON p.tenant_id=w.tenant_id AND p.run_id=w.run_id
                        AND p.execution_identity_hash=w.execution_identity_hash
                       WHERE w.tenant_id=?
                         AND (w.revoked_at IS NOT NULL OR w.expires_at <= ?)
                         AND p.publication_state='PUBLISHED' AND p.outcome='PASS'
                       ORDER BY w.run_id LIMIT ?""",
                    (tenant_id, now.isoformat(), max_items),
                )
                result: list[tuple[str, str]] = []
                for row in rows:
                    if (
                        type(row) not in {tuple, sqlite3.Row}
                        or len(row) != 2
                        or type(row[0]) is not str
                        or type(row[1]) is not str
                    ):
                        raise WaiverConflict("stored waiver expiry scope is invalid")
                    result.append((row[0], row[1]))
                return tuple(result)
        except sqlite3.Error as error:
            raise WaiverConflict("waiver storage is unavailable") from error

    def _validate_approved_finding(
        self,
        record: WaiverRecord,
        approval_request: ApprovalRequest,
        approval: ApprovalDecision,
    ) -> None:
        row = self._db.execute(
            """SELECT r.repository_id, r.execution_identity_hash, r.head_sha,
                      f.revision_sha, f.metadata_json, a.finding_id,
                      a.finding_fingerprint, a.revision_sha, a.state, a.version,
                      d.state, d.version, d.rationale_sha256
               FROM audit_runs AS r
               JOIN finding_occurrences AS f
                 ON f.tenant_id=r.tenant_id AND f.run_id=r.run_id
                AND f.revision_sha=r.head_sha
               JOIN approval_requests AS a
                 ON a.tenant_id=r.tenant_id AND a.run_id=r.run_id
                AND a.finding_id=f.finding_id
               JOIN approval_decisions AS d
                 ON d.tenant_id=a.tenant_id AND d.approval_id=a.approval_id
                AND d.version=a.version
               WHERE r.tenant_id=? AND r.run_id=? AND f.finding_id=?
                 AND a.approval_id=?
                 AND r.state IN ('SUCCEEDED', 'FAILED')""",
            (
                approval_request.tenant_id,
                approval_request.run_id,
                approval_request.finding_id,
                approval_request.approval_id,
            ),
        ).fetchone()
        if row is None or (
            row[0] != record.scope.repository_id
            or row[1] != record.scope.execution_identity_hash
            or type(row[2]) is not str
            or row[2] != row[3]
            or row[2] != row[7]
            or row[7] != approval_request.revision_sha
            or type(row[4]) is not str
            or row[5] != approval_request.finding_id
            or row[6] != record.scope.finding_fingerprint
            or row[6] != approval_request.finding_fingerprint
            or row[8] != ApprovalState.APPROVED.value
            or row[9] != approval_request.version
            or row[10] != ApprovalState.APPROVED.value
            or row[11] != approval.version
            or row[11] != row[9]
            or row[12] != record.rationale_sha256
        ):
            raise WaiverConflict("approved finding does not match the waiver revision")
        try:
            metadata = json.loads(row[4], object_pairs_hook=_closed_json_object)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise WaiverConflict("approved finding metadata is invalid") from None
        if (
            type(metadata) is not dict
            or metadata.get("finding_id") != approval_request.finding_id
            or metadata.get("revision_sha") != approval_request.revision_sha
            or metadata.get("root_cause_fingerprint") != record.scope.finding_fingerprint
            or metadata.get("root_cause_fingerprint") != approval_request.finding_fingerprint
        ):
            raise WaiverConflict("approved finding does not match the waiver fingerprint")

    def _approval_matches_scope(self, record: WaiverRecord, *, finding_id: str) -> bool:
        row = self._db.execute(
            """SELECT r.repository_id, r.run_id, r.finding_id,
                      r.finding_fingerprint, r.revision_sha,
                      r.execution_identity_hash, r.state, r.version,
                      d.state, d.version, ar.repository_id,
                      ar.execution_identity_hash, ar.head_sha,
                      f.revision_sha, f.metadata_json
               FROM approval_requests AS r
               JOIN approval_decisions AS d
                 ON d.tenant_id=r.tenant_id AND d.approval_id=r.approval_id
                AND d.version=r.version
               JOIN audit_runs AS ar
                 ON ar.tenant_id=r.tenant_id AND ar.run_id=r.run_id
               JOIN finding_occurrences AS f
                 ON f.tenant_id=r.tenant_id AND f.run_id=r.run_id
                AND f.finding_id=r.finding_id AND f.revision_sha=ar.head_sha
               WHERE r.tenant_id=? AND r.approval_id=?
                 AND ar.state IN ('SUCCEEDED', 'FAILED')""",
            (record.scope.tenant_id, record.approval_id),
        ).fetchone()
        if row is None or tuple(row[:4]) != (
            record.scope.repository_id,
            record.scope.run_id,
            finding_id,
            record.scope.finding_fingerprint,
        ):
            return False
        return (
            type(row[4]) is str
            and len(row[4]) == 40
            and all(character in "0123456789abcdef" for character in row[4])
            and row[5] == record.scope.execution_identity_hash
            and row[6] == ApprovalState.APPROVED.value
            and type(row[7]) is int
            and row[7] >= 2
            and row[8] == ApprovalState.APPROVED.value
            and row[9] == row[7]
            and row[10] == record.scope.repository_id
            and row[11] == record.scope.execution_identity_hash
            and row[12] == row[4]
            and row[13] == row[4]
            and type(row[14]) is str
            and self._metadata_matches_waiver(
                row[14],
                finding_id=finding_id,
                revision_sha=row[4],
                fingerprint=record.scope.finding_fingerprint,
            )
        )

    @staticmethod
    def _metadata_matches_waiver(
        value: str,
        *,
        finding_id: str,
        revision_sha: str,
        fingerprint: str | None,
    ) -> bool:
        try:
            metadata = json.loads(value, object_pairs_hook=_closed_json_object)
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
            return False
        return (
            type(metadata) is dict
            and metadata.get("finding_id") == finding_id
            and metadata.get("revision_sha") == revision_sha
            and metadata.get("root_cause_fingerprint") == fingerprint
        )

    def _row(
        self,
        tenant_id: str,
        waiver_id: str,
    ) -> tuple[object, ...] | sqlite3.Row | None:
        row = self._db.execute(
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
        if row is None:
            return None
        if (
            type(row) not in {tuple, sqlite3.Row}
            or len(row) != 4
            or not all(type(item) is str for item in row[:3])
            or type(row[3]) is not int
        ):
            raise WaiverConflict("stored waiver replay is invalid")
        if row[0] not in {"grant", "revoke"} or row[3] < 1:
            raise WaiverConflict("stored waiver replay is invalid")
        try:
            _require_sha256(row[1])
            _require_identifier(row[2])
        except ValueError:
            raise WaiverConflict("stored waiver replay is invalid") from None
        return row[0], row[1], row[2], row[3]

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
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("identifier is invalid")
    return value


def _require_sha256(value: object) -> str:
    if type(value) is not str or len(value) != 64 or any(item not in _HEX for item in value):
        raise ValueError("SHA-256 value is invalid")
    return value


def _require_utc(value: datetime) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be timezone-aware UTC")
    return value


def _require_relative_path(value: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 1024:
        raise ValueError("waiver path is invalid")
    normalized = value.replace("\\", "/")
    if (
        normalized.startswith("/")
        or re.match(r"^[A-Za-z]:", normalized) is not None
        or ".." in normalized.split("/")
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ValueError("waiver path must be repository-relative")
    return value


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate metadata key")
        result[key] = value
    return result


def _checked_now(source: Callable[[], datetime]) -> datetime:
    try:
        return _require_utc(source())
    except Exception as error:
        raise WaiverConflict("clock returned an invalid timestamp") from error


def _require_key(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or not value.isascii()
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
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


def _from_row(row: tuple[object, ...] | sqlite3.Row) -> WaiverRecord:
    if (
        type(row) not in {tuple, sqlite3.Row}
        or len(row) != 13
        or not all(type(item) is str for item in (row[0], row[1], row[2], row[3], row[4]))
        or any(item is not None and type(item) is not str for item in row[5:9])
        or type(row[9]) is not str
        or type(row[10]) is not str
        or type(row[11]) is not str
    ):
        raise WaiverConflict("stored waiver is invalid")
    try:
        scope = WaiverScope(
            tenant_id=row[1],
            repository_id=row[2],
            run_id=row[3],
            execution_identity_hash=row[4],
            finding_fingerprint=row[5],
            cwe_id=row[6],
            path=row[7],
            policy_scope=row[8],
        )
        return WaiverRecord(
            waiver_id=row[0],
            scope=scope,
            expires_at=datetime.fromisoformat(row[9]),
            approval_id=row[10],
            rationale_sha256=row[11],
            version=_stored_int(row[12]),
        )
    except (TypeError, ValueError, OverflowError):
        raise WaiverConflict("stored waiver is invalid") from None


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
