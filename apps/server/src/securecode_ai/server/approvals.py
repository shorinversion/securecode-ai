"""Durable tenant-bound approvals with separation of duties and CAS updates."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final


class ApprovalState(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class ApprovalConflict(Exception):
    """Raised when an approval operation is invalid or loses a CAS race."""


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    approval_id: str
    tenant_id: str
    repository_id: str
    run_id: str
    finding_id: str
    execution_identity_hash: str
    requester_id: str
    expires_at: datetime
    version: int
    state: ApprovalState = ApprovalState.PENDING
    finding_fingerprint: str | None = None
    revision_sha: str | None = None
    patch_sha256: str | None = None
    validation_result_sha256: str | None = None
    manifest_sha256: str | None = None
    patch_status_sha256: str | None = None

    def __post_init__(self) -> None:
        for value in (
            self.approval_id,
            self.tenant_id,
            self.repository_id,
            self.run_id,
            self.finding_id,
            self.requester_id,
        ):
            _require_identifier(value)
        _require_sha256(self.execution_identity_hash)
        _require_utc(self.expires_at)
        if type(self.version) is not int or self.version < 1:
            raise ValueError("approval version must be a positive integer")
        if type(self.state) is not ApprovalState:
            raise ValueError("approval state is invalid")
        if self.finding_fingerprint is not None:
            _require_sha256(self.finding_fingerprint)
        if self.revision_sha is not None and (
            type(self.revision_sha) is not str or _COMMIT.fullmatch(self.revision_sha) is None
        ):
            raise ValueError("approval revision is invalid")
        patch_digests = (
            self.patch_sha256,
            self.validation_result_sha256,
            self.manifest_sha256,
            self.patch_status_sha256,
        )
        if any(value is not None for value in patch_digests):
            if any(value is None for value in patch_digests):
                raise ValueError("approval patch binding is incomplete")
            for value in patch_digests:
                _require_sha256(value)
            if self.approval_id.startswith("repair-"):
                expected_id = "repair-" + hashlib.sha256(
                    f"{self.run_id}\x00{self.finding_id}\x00sha256:{self.patch_sha256}".encode(
                        "ascii"
                    )
                ).hexdigest()[:48]
                if self.approval_id != expected_id:
                    raise ValueError("repair approval identity is invalid")
        elif self.approval_id.startswith("repair-"):
            raise ValueError("repair approval patch binding is required")


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    approval_id: str
    tenant_id: str
    version: int
    state: ApprovalState
    actor_id: str
    reason_code: str
    rationale_sha256: str
    created_at: datetime

    def __post_init__(self) -> None:
        _require_identifier(self.approval_id)
        _require_identifier(self.tenant_id)
        _require_identifier(self.actor_id)
        _require_reason_code(self.reason_code)
        _require_sha256(self.rationale_sha256)
        _require_utc(self.created_at)
        if type(self.version) is not int or self.version < 2:
            raise ValueError("decision version must be at least two")
        if type(self.state) is not ApprovalState or self.state not in {
            ApprovalState.APPROVED,
            ApprovalState.REJECTED,
            ApprovalState.REVOKED,
        }:
            raise ValueError("invalid decision state")


APPROVAL_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS approval_requests (
        approval_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        finding_id TEXT NOT NULL,
        finding_fingerprint TEXT,
        revision_sha TEXT,
        patch_sha256 TEXT,
        validation_result_sha256 TEXT,
        manifest_sha256 TEXT,
        patch_status_sha256 TEXT,
        execution_identity_hash TEXT NOT NULL,
        requester_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        version INTEGER NOT NULL,
        state TEXT NOT NULL,
        PRIMARY KEY (tenant_id, approval_id),
        CHECK (version >= 1)
    )""",
    """CREATE INDEX IF NOT EXISTS approval_requests_tenant_run
        ON approval_requests (tenant_id, run_id, approval_id)""",
    """CREATE TABLE IF NOT EXISTS approval_decisions (
        approval_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        state TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        reason_code TEXT NOT NULL,
        rationale_sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, approval_id, version),
        FOREIGN KEY (tenant_id, approval_id)
            REFERENCES approval_requests (tenant_id, approval_id)
    )""",
    """CREATE TABLE IF NOT EXISTS approval_idempotency (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        approval_id TEXT NOT NULL,
        result_version INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, approval_id)
            REFERENCES approval_requests (tenant_id, approval_id)
    )""",
)


class ApprovalLedger:
    """SQLite-backed approval ledger with an in-memory compatibility default."""

    def __init__(
        self,
        connection: sqlite3.Connection | None = None,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if connection is not None and type(connection) is not sqlite3.Connection:
            raise ApprovalConflict("approval storage is invalid")
        self._db = (
            connection
            if connection is not None
            else sqlite3.connect(":memory:", check_same_thread=False)
        )
        self._require_run_scope = connection is not None
        if not callable(now):
            raise ApprovalConflict("approval clock is invalid")
        self._now = now
        self._lock = threading.RLock()
        try:
            self._db.execute("PRAGMA foreign_keys = ON")
            for statement in APPROVAL_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            columns = self._db.execute("PRAGMA table_info(approval_requests)").fetchall()
            existing_columns = {row[1] for row in columns}
            if "finding_fingerprint" not in existing_columns:
                self._db.execute(
                    "ALTER TABLE approval_requests ADD COLUMN finding_fingerprint TEXT"
                )
            if "revision_sha" not in existing_columns:
                self._db.execute(
                    "ALTER TABLE approval_requests ADD COLUMN revision_sha TEXT"
                )
            for column in (
                "patch_sha256",
                "validation_result_sha256",
                "manifest_sha256",
                "patch_status_sha256",
            ):
                if column not in existing_columns:
                    self._db.execute(f"ALTER TABLE approval_requests ADD COLUMN {column} TEXT")
            self._db.commit()
        except sqlite3.Error as error:
            raise ApprovalConflict("approval storage is unavailable") from error

    def request(self, value: ApprovalRequest, *, idempotency_key: str) -> ApprovalRequest:
        if type(value) is not ApprovalRequest:
            raise ApprovalConflict("approval request is invalid")
        key = _require_idempotency_key(idempotency_key)
        if value.state is not ApprovalState.PENDING:
            raise ApprovalConflict("new approval requests must be pending")
        fingerprint = _request_fingerprint(value)
        with self._lock:
            self._begin()
            try:
                replay = self._read_replay(value.tenant_id, key)
                if replay is not None:
                    operation, prior_hash, approval_id, _ = replay
                    if operation != "request" or prior_hash != fingerprint:
                        raise ApprovalConflict("idempotency key was reused")
                    result = self._load_request(approval_id, value.tenant_id)
                    if result is None:
                        raise ApprovalConflict("approval replay is incomplete")
                    self._db.commit()
                    return result
                _validate_expiry(value.expires_at, _checked_now(self._now))
                if self._require_run_scope:
                    self._validate_run_scope(value)
                if self._load_request(value.approval_id, value.tenant_id) is not None:
                    raise ApprovalConflict("approval id already exists")
                self._insert_request(value)
                self._insert_replay(
                    value.tenant_id,
                    key,
                    "request",
                    fingerprint,
                    value.approval_id,
                    value.version,
                )
                self._db.commit()
                return value
            except sqlite3.IntegrityError as error:
                self._db.rollback()
                raise ApprovalConflict("approval request conflicts") from error
            except sqlite3.Error as error:
                self._db.rollback()
                raise ApprovalConflict("approval storage is unavailable") from error
            except Exception:
                self._db.rollback()
                raise

    def decide(
        self,
        *,
        approval_id: str,
        actor_id: str,
        approver_granted: bool,
        expected_version: int,
        approve: bool,
        reason_code: str,
        rationale: str,
        idempotency_key: str,
        tenant_id: str,
    ) -> ApprovalDecision:
        _require_identifier(approval_id)
        _require_identifier(actor_id)
        _require_identifier(tenant_id)
        if type(approver_granted) is not bool or type(approve) is not bool:
            raise ApprovalConflict("approval flags must be boolean")
        if type(expected_version) is not int or expected_version < 1:
            raise ApprovalConflict("expected version is invalid")
        _require_reason_code(reason_code)
        rationale_hash = _rationale_hash(rationale)
        key = _require_idempotency_key(idempotency_key)
        with self._lock:
            self._begin()
            try:
                request = self._load_request(approval_id, tenant_id)
                if request is None:
                    raise ApprovalConflict("approval does not exist in tenant scope")
                fingerprint = _decision_fingerprint(
                    request.tenant_id,
                    approval_id,
                    actor_id,
                    expected_version,
                    approve,
                    reason_code,
                    rationale_hash,
                )
                replay = self._read_replay(request.tenant_id, key)
                if replay is not None:
                    if not approver_granted:
                        raise ApprovalConflict("actor lacks approval authority")
                    if actor_id == request.requester_id:
                        raise ApprovalConflict("requester cannot decide their own approval")
                    operation, prior_hash, replay_id, version = replay
                    if (
                        operation != "decide"
                        or prior_hash != fingerprint
                        or replay_id != approval_id
                    ):
                        raise ApprovalConflict("idempotency key was reused")
                    decision = self._load_decision(request.tenant_id, approval_id, version)
                    if decision is None:
                        raise ApprovalConflict("decision replay is incomplete")
                    self._db.commit()
                    return decision
                now = _checked_now(self._now)
                self._validate_decision(request, actor_id, approver_granted, expected_version, now)
                state = ApprovalState.APPROVED if approve else ApprovalState.REJECTED
                decision = ApprovalDecision(
                    approval_id=approval_id,
                    tenant_id=request.tenant_id,
                    version=expected_version + 1,
                    state=state,
                    actor_id=actor_id,
                    reason_code=reason_code,
                    rationale_sha256=rationale_hash,
                    created_at=now,
                )
                changed = self._db.execute(
                    """UPDATE approval_requests SET version = ?, state = ?
                       WHERE approval_id = ? AND tenant_id = ?
                         AND version = ? AND state = ?""",
                    (
                        decision.version,
                        state.value,
                        approval_id,
                        request.tenant_id,
                        expected_version,
                        ApprovalState.PENDING.value,
                    ),
                ).rowcount
                if changed != 1:
                    raise ApprovalConflict("approval state changed concurrently")
                self._insert_decision(decision)
                self._insert_replay(
                    request.tenant_id,
                    key,
                    "decide",
                    fingerprint,
                    approval_id,
                    decision.version,
                )
                self._db.commit()
                return decision
            except sqlite3.Error as error:
                self._db.rollback()
                raise ApprovalConflict("approval storage is unavailable") from error
            except Exception:
                self._db.rollback()
                raise

    def projection(
        self,
        approval_id: str,
        *,
        tenant_id: str,
    ) -> dict[str, object]:
        _require_identifier(approval_id)
        _require_identifier(tenant_id)
        try:
            with self._lock:
                request = self._load_request(approval_id, tenant_id)
                if request is None:
                    raise ApprovalConflict("approval does not exist in tenant scope")
                state = request.state
                if state is ApprovalState.PENDING and request.expires_at <= _checked_now(self._now):
                    state = ApprovalState.EXPIRED
                value: dict[str, object] = {
                    "approval_id": request.approval_id,
                    "tenant_id": request.tenant_id,
                    "repository_id": request.repository_id,
                    "run_id": request.run_id,
                    "finding_id": request.finding_id,
                    "execution_identity_hash": request.execution_identity_hash,
                    "patch_sha256": request.patch_sha256,
                    "validation_result_sha256": request.validation_result_sha256,
                    "manifest_sha256": request.manifest_sha256,
                    "patch_status_sha256": request.patch_status_sha256,
                    "state": state.value,
                    "version": request.version,
                    "expires_at": request.expires_at.isoformat(),
                }
                if request.state in {
                    ApprovalState.APPROVED,
                    ApprovalState.REJECTED,
                    ApprovalState.REVOKED,
                }:
                    decision = self._load_decision(
                        request.tenant_id,
                        request.approval_id,
                        request.version,
                    )
                    if decision is None:
                        raise ApprovalConflict("approval decision history is incomplete")
                    value["decision"] = {
                        "actor_id": decision.actor_id,
                        "reason_code": decision.reason_code,
                        "rationale_sha256": decision.rationale_sha256,
                        "created_at": decision.created_at.isoformat(),
                    }
                return value
        except sqlite3.Error as error:
            raise ApprovalConflict("approval storage is unavailable") from error

    def approved_request(
        self,
        approval_id: str,
        *,
        tenant_id: str,
    ) -> tuple[ApprovalRequest, ApprovalDecision]:
        """Return an approved decision together with its immutable request scope."""

        _require_identifier(approval_id)
        _require_identifier(tenant_id)
        try:
            with self._lock:
                request = self._load_request(approval_id, tenant_id)
                if request is None or request.state is not ApprovalState.APPROVED:
                    raise ApprovalConflict("approval is not approved in tenant scope")
                decision = self._load_decision(tenant_id, approval_id, request.version)
                if decision is None or decision.state is not ApprovalState.APPROVED:
                    raise ApprovalConflict("approved decision history is incomplete")
                return request, decision
        except sqlite3.Error as error:
            raise ApprovalConflict("approval storage is unavailable") from error

    def _validate_decision(
        self,
        request: ApprovalRequest,
        actor_id: str,
        approver_granted: bool,
        expected_version: int,
        now: datetime,
    ) -> None:
        if not approver_granted:
            raise ApprovalConflict("actor lacks approval authority")
        if actor_id == request.requester_id:
            raise ApprovalConflict("requester cannot decide their own approval")
        if request.version != expected_version or request.state is not ApprovalState.PENDING:
            raise ApprovalConflict("approval version or state changed")
        if request.expires_at <= now:
            raise ApprovalConflict("approval request expired")

    def _validate_run_scope(self, value: ApprovalRequest) -> None:
        if value.finding_fingerprint is None or value.revision_sha is None:
            raise ApprovalConflict("approval finding scope is incomplete")
        row = self._db.execute(
            """SELECT r.repository_id, r.execution_identity_hash, r.head_sha,
                      r.state, f.finding_id, f.revision_sha, f.metadata_json
               FROM audit_runs AS r
               JOIN finding_occurrences AS f
                 ON f.tenant_id=r.tenant_id AND f.run_id=r.run_id
                AND f.revision_sha=r.head_sha
               WHERE r.tenant_id=? AND r.run_id=? AND f.finding_id=?""",
            (value.tenant_id, value.run_id, value.finding_id),
        ).fetchone()
        if row is None or type(row) not in {tuple, sqlite3.Row} or len(row) != 7 or (
            row[0] != value.repository_id
            or row[1] != value.execution_identity_hash
            or row[2] != value.revision_sha
            or row[3] not in _APPROVAL_RUN_STATES
            or row[4] != value.finding_id
            or row[5] != value.revision_sha
            or type(row[6]) is not str
        ):
            raise ApprovalConflict("approval finding scope does not match a stored run")
        try:
            metadata = json.loads(row[6], object_pairs_hook=_closed_json_object)
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
            raise ApprovalConflict("approval finding metadata is invalid") from None
        if (
            type(metadata) is not dict
            or metadata.get("finding_id") != value.finding_id
            or metadata.get("revision_sha") != value.revision_sha
            or metadata.get("root_cause_fingerprint") != value.finding_fingerprint
        ):
            raise ApprovalConflict("approval finding fingerprint does not match")
        if value.patch_sha256 is not None:
            _validate_committed_repair_binding(self._db, value)

    def _insert_request(self, value: ApprovalRequest) -> None:
        self._db.execute(
            """INSERT INTO approval_requests (
                   approval_id, tenant_id, repository_id, run_id, finding_id,
                   finding_fingerprint, revision_sha, patch_sha256,
                   validation_result_sha256, manifest_sha256, patch_status_sha256,
                   execution_identity_hash, requester_id, expires_at, version, state
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                value.approval_id,
                value.tenant_id,
                value.repository_id,
                value.run_id,
                value.finding_id,
                value.finding_fingerprint,
                value.revision_sha,
                value.patch_sha256,
                value.validation_result_sha256,
                value.manifest_sha256,
                value.patch_status_sha256,
                value.execution_identity_hash,
                value.requester_id,
                value.expires_at.isoformat(),
                value.version,
                value.state.value,
            ),
        )

    def _insert_decision(self, value: ApprovalDecision) -> None:
        self._db.execute(
            """INSERT INTO approval_decisions (
                   approval_id, tenant_id, version, state, actor_id, reason_code,
                   rationale_sha256, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                value.approval_id,
                value.tenant_id,
                value.version,
                value.state.value,
                value.actor_id,
                value.reason_code,
                value.rationale_sha256,
                value.created_at.isoformat(),
            ),
        )

    def _load_request(
        self,
        approval_id: str,
        tenant_id: str,
    ) -> ApprovalRequest | None:
        sql = """SELECT approval_id, tenant_id, repository_id, run_id, finding_id,
                        execution_identity_hash, requester_id, expires_at, version, state,
                        finding_fingerprint, revision_sha, patch_sha256,
                        validation_result_sha256, manifest_sha256, patch_status_sha256
                 FROM approval_requests WHERE approval_id = ?"""
        sql += " AND tenant_id = ?"
        row = self._db.execute(sql, (approval_id, tenant_id)).fetchone()
        if row is None:
            return None
        if (
            type(row) not in {tuple, sqlite3.Row}
            or len(row) != 16
            or not all(type(item) is str for item in row[:7])
            or type(row[7]) is not str
            or type(row[8]) is not int
            or type(row[9]) is not str
            or (row[10] is not None and type(row[10]) is not str)
            or (row[11] is not None and type(row[11]) is not str)
            or any(item is not None and type(item) is not str for item in row[12:16])
        ):
            raise ApprovalConflict("stored approval request is invalid")
        try:
            timestamp = datetime.fromisoformat(row[7])
            state = ApprovalState(row[9])
            return ApprovalRequest(
                approval_id=row[0],
                tenant_id=row[1],
                repository_id=row[2],
                run_id=row[3],
                finding_id=row[4],
                execution_identity_hash=row[5],
                requester_id=row[6],
                expires_at=timestamp,
                version=row[8],
                state=state,
                finding_fingerprint=row[10],
                revision_sha=row[11],
                patch_sha256=row[12],
                validation_result_sha256=row[13],
                manifest_sha256=row[14],
                patch_status_sha256=row[15],
            )
        except (TypeError, ValueError, OverflowError):
            raise ApprovalConflict("stored approval request is invalid") from None

    def _load_decision(
        self,
        tenant_id: str,
        approval_id: str,
        version: int,
    ) -> ApprovalDecision | None:
        sql = """SELECT approval_id, tenant_id, version, state, actor_id, reason_code,
                        rationale_sha256, created_at
                 FROM approval_decisions
                 WHERE approval_id = ? AND version = ? AND tenant_id = ?"""
        row = self._db.execute(sql, (approval_id, version, tenant_id)).fetchone()
        if row is None:
            return None
        if (
            type(row) not in {tuple, sqlite3.Row}
            or len(row) != 8
            or not all(
                type(item) is str
                for item in (row[0], row[1], row[3], row[4], row[5], row[6], row[7])
            )
            or type(row[2]) is not int
        ):
            raise ApprovalConflict("stored approval decision is invalid")
        try:
            return ApprovalDecision(
                approval_id=row[0],
                tenant_id=row[1],
                version=row[2],
                state=ApprovalState(row[3]),
                actor_id=row[4],
                reason_code=row[5],
                rationale_sha256=row[6],
                created_at=datetime.fromisoformat(row[7]),
            )
        except (TypeError, ValueError, OverflowError):
            raise ApprovalConflict("stored approval decision is invalid") from None

    def _read_replay(self, tenant_id: str, key: str) -> tuple[str, str, str, int] | None:
        row = self._db.execute(
            """SELECT operation, request_sha256, approval_id, result_version
               FROM approval_idempotency WHERE tenant_id = ? AND idempotency_key = ?""",
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
            raise ApprovalConflict("stored approval replay is invalid")
        try:
            _require_identifier(row[2])
            _require_sha256(row[1])
        except ValueError:
            raise ApprovalConflict("stored approval replay is invalid") from None
        if row[0] not in {"request", "decide"} or row[3] < 1:
            raise ApprovalConflict("stored approval replay is invalid")
        return row[0], row[1], row[2], row[3]

    def _insert_replay(
        self,
        tenant_id: str,
        key: str,
        operation: str,
        fingerprint: str,
        approval_id: str,
        version: int,
    ) -> None:
        self._db.execute(
            """INSERT INTO approval_idempotency (
                   tenant_id, idempotency_key, operation, request_sha256,
                   approval_id, result_version
               ) VALUES (?, ?, ?, ?, ?, ?)""",
            (tenant_id, key, operation, fingerprint, approval_id, version),
        )

    def _begin(self) -> None:
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            raise ApprovalConflict("approval storage is unavailable") from error


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_APPROVAL_RUN_STATES = frozenset({"SUCCEEDED", "FAILED"})
_HEX = frozenset("0123456789abcdef")
_REPAIR_BINDING_KEYS = frozenset(
    {
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
)
_REPAIR_ARTIFACT_KEYS = frozenset(
    {
        "authorization_id",
        "content_id",
        "content_sha256",
        "data_class",
        "purpose",
        "size_bytes",
        "binding",
    }
)


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


def _checked_now(source: Callable[[], datetime]) -> datetime:
    try:
        return _require_utc(source())
    except Exception as error:
        raise ApprovalConflict("clock returned an invalid timestamp") from error


def _validate_expiry(expiry: datetime, now: datetime) -> None:
    _require_utc(expiry)
    if expiry <= now or expiry > now + timedelta(days=30):
        raise ApprovalConflict("approval expiry is outside the allowed window")


def _require_reason_code(value: object) -> str:
    if type(value) is not str or _REASON_CODE.fullmatch(value) is None:
        raise ValueError("reason code is invalid")
    return value


def _rationale_hash(rationale: object) -> str:
    if type(rationale) is not str or not 1 <= len(rationale) <= 1024:
        raise ApprovalConflict("rationale is invalid")
    if any(ord(character) < 32 and character not in "\t\n" for character in rationale):
        raise ApprovalConflict("rationale contains control characters")
    return hashlib.sha256(rationale.encode("utf-8")).hexdigest()


def _require_idempotency_key(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or not value.isascii()
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ApprovalConflict("idempotency key is invalid")
    return value


def _digest(document: dict[str, object]) -> str:
    payload = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate approval finding field")
        result[key] = value
    return result


def _validate_committed_repair_binding(
    connection: sqlite3.Connection,
    value: ApprovalRequest,
) -> None:
    """Require one live committed repair bundle for an approval request."""

    try:
        rows = connection.execute(
            """SELECT a.authorization_id, a.content_sha256, a.metadata_json,
                      z.content_id, z.size_bytes, z.data_class, z.repository_id,
                      z.run_id, z.execution_identity_hash, r.head_sha
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
                 )""",
            (value.tenant_id, value.run_id),
        ).fetchall()
    except sqlite3.Error as error:
        raise ApprovalConflict("approval patch binding is unavailable") from error

    matches = 0
    for row in rows:
        if type(row) not in {tuple, sqlite3.Row} or len(row) != 10:
            raise ApprovalConflict("approval patch binding is invalid")
        try:
            document = json.loads(row[2], object_pairs_hook=_closed_json_object)
        except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
            raise ApprovalConflict("approval patch binding is invalid") from None
        if (
            type(document) is not dict
            or set(document) not in {_REPAIR_ARTIFACT_KEYS, _REPAIR_ARTIFACT_KEYS | {"expires_at"}}
            or document.get("authorization_id") != row[0]
            or document.get("content_sha256") != row[1]
            or document.get("content_id") != row[3]
            or document.get("purpose") != "repair-patch"
            or document.get("data_class") != "DC3_CONFIDENTIAL_SOURCE"
            or document.get("size_bytes") != row[4]
            or not isinstance(document.get("binding"), dict)
        ):
            raise ApprovalConflict("approval patch binding is invalid")
        binding = document["binding"]
        if (
            set(binding) != _REPAIR_BINDING_KEYS
            or binding.get("tenant_id") != value.tenant_id
            or binding.get("repository_id") != value.repository_id
            or binding.get("run_id") != value.run_id
            or binding.get("finding_id") != value.finding_id
            or binding.get("head_sha") != value.revision_sha
            or binding.get("execution_identity_hash") != value.execution_identity_hash
            or binding.get("patch_sha256") != value.patch_sha256
            or binding.get("validation_result_sha256") != value.validation_result_sha256
            or binding.get("manifest_sha256") != value.manifest_sha256
            or binding.get("patch_status_sha256") != value.patch_status_sha256
            or row[6] != value.repository_id
            or row[7] != value.run_id
            or row[8] != value.execution_identity_hash
            or row[9] != value.revision_sha
        ):
            continue
        if (
            type(binding.get("patch_size_bytes")) is not int
            or not 1 <= binding["patch_size_bytes"] <= 131_072
            or type(row[1]) is not str
            or _SHA256.fullmatch(row[1]) is None
        ):
            raise ApprovalConflict("approval patch binding is invalid")
        for name in (
            "execution_identity_hash",
            "manifest_sha256",
            "patch_sha256",
            "patch_status_sha256",
            "validation_result_sha256",
        ):
            if _SHA256.fullmatch(str(binding.get(name))) is None:
                raise ApprovalConflict("approval patch binding is invalid")
        if _COMMIT.fullmatch(str(binding.get("head_sha"))) is None:
            raise ApprovalConflict("approval patch binding is invalid")
        matches += 1
    if matches != 1:
        raise ApprovalConflict("approval patch binding does not match a committed artifact")


def _request_fingerprint(value: ApprovalRequest) -> str:
    return _digest(
        {
            "approval_id": value.approval_id,
            "tenant_id": value.tenant_id,
            "repository_id": value.repository_id,
            "run_id": value.run_id,
            "finding_id": value.finding_id,
            "finding_fingerprint": value.finding_fingerprint,
            "revision_sha": value.revision_sha,
            "patch_sha256": value.patch_sha256,
            "validation_result_sha256": value.validation_result_sha256,
            "manifest_sha256": value.manifest_sha256,
            "patch_status_sha256": value.patch_status_sha256,
            "execution_identity_hash": value.execution_identity_hash,
            "requester_id": value.requester_id,
            "expires_at": value.expires_at.isoformat(),
            "version": value.version,
            "state": value.state.value,
        }
    )


def _decision_fingerprint(
    tenant_id: str,
    approval_id: str,
    actor_id: str,
    expected_version: int,
    approve: bool,
    reason_code: str,
    rationale_sha256: str,
) -> str:
    return _digest(
        {
            "tenant_id": tenant_id,
            "approval_id": approval_id,
            "actor_id": actor_id,
            "expected_version": expected_version,
            "approve": approve,
            "reason_code": reason_code,
            "rationale_sha256": rationale_sha256,
        }
    )


__all__ = [
    "APPROVAL_SCHEMA_STATEMENTS",
    "ApprovalConflict",
    "ApprovalDecision",
    "ApprovalLedger",
    "ApprovalRequest",
    "ApprovalState",
]
