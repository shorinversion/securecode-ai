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
        if self.state not in {
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
        self._db = connection or sqlite3.connect(":memory:", check_same_thread=False)
        self._now = now
        self._lock = threading.RLock()
        self._db.execute("PRAGMA foreign_keys = ON")
        for statement in APPROVAL_SCHEMA_STATEMENTS:
            self._db.execute(statement)
        self._db.commit()

    def request(self, value: ApprovalRequest, *, idempotency_key: str) -> ApprovalRequest:
        key = _require_idempotency_key(idempotency_key)
        if value.state is not ApprovalState.PENDING:
            raise ApprovalConflict("new approval requests must be pending")
        _validate_expiry(value.expires_at, _checked_now(self._now))
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
        now = _checked_now(self._now)
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
        with self._lock:
            request = self._load_request(approval_id, tenant_id)
        if request is None:
            raise ApprovalConflict("approval does not exist in tenant scope")
        state = request.state
        if state is ApprovalState.PENDING and request.expires_at <= _checked_now(self._now):
            state = ApprovalState.EXPIRED
        return {
            "approval_id": request.approval_id,
            "tenant_id": request.tenant_id,
            "repository_id": request.repository_id,
            "run_id": request.run_id,
            "finding_id": request.finding_id,
            "execution_identity_hash": request.execution_identity_hash,
            "state": state.value,
            "version": request.version,
            "expires_at": request.expires_at.isoformat(),
        }

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

    def _insert_request(self, value: ApprovalRequest) -> None:
        self._db.execute(
            """INSERT INTO approval_requests (
                   approval_id, tenant_id, repository_id, run_id, finding_id,
                   execution_identity_hash, requester_id, expires_at, version, state
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                value.approval_id,
                value.tenant_id,
                value.repository_id,
                value.run_id,
                value.finding_id,
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
                        execution_identity_hash, requester_id, expires_at, version, state
                 FROM approval_requests WHERE approval_id = ?"""
        sql += " AND tenant_id = ?"
        row = self._db.execute(sql, (approval_id, tenant_id)).fetchone()
        if row is None:
            return None
        return ApprovalRequest(
            str(row[0]),
            str(row[1]),
            str(row[2]),
            str(row[3]),
            str(row[4]),
            str(row[5]),
            str(row[6]),
            datetime.fromisoformat(str(row[7])),
            int(row[8]),
            ApprovalState(str(row[9])),
        )

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
        return ApprovalDecision(
            approval_id=str(row[0]),
            tenant_id=str(row[1]),
            version=int(row[2]),
            state=ApprovalState(str(row[3])),
            actor_id=str(row[4]),
            reason_code=str(row[5]),
            rationale_sha256=str(row[6]),
            created_at=datetime.fromisoformat(str(row[7])),
        )

    def _read_replay(self, tenant_id: str, key: str) -> tuple[str, str, str, int] | None:
        row = self._db.execute(
            """SELECT operation, request_sha256, approval_id, result_version
               FROM approval_idempotency WHERE tenant_id = ? AND idempotency_key = ?""",
            (tenant_id, key),
        ).fetchone()
        if row is None:
            return None
        return str(row[0]), str(row[1]), str(row[2]), int(row[3])

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
        self._db.execute("BEGIN IMMEDIATE")


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_REASON_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
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


def _checked_now(source: Callable[[], datetime]) -> datetime:
    try:
        return _require_utc(source())
    except (TypeError, ValueError) as error:
        raise ApprovalConflict("clock returned an invalid timestamp") from error


def _validate_expiry(expiry: datetime, now: datetime) -> None:
    _require_utc(expiry)
    if expiry <= now or expiry > now + timedelta(days=30):
        raise ApprovalConflict("approval expiry is outside the allowed window")


def _require_reason_code(value: object) -> str:
    if not isinstance(value, str) or _REASON_CODE.fullmatch(value) is None:
        raise ValueError("reason code is invalid")
    return value


def _rationale_hash(rationale: object) -> str:
    if not isinstance(rationale, str) or not 1 <= len(rationale) <= 1024:
        raise ApprovalConflict("rationale is invalid")
    if any(ord(character) < 32 and character not in "\t\n" for character in rationale):
        raise ApprovalConflict("rationale contains control characters")
    return hashlib.sha256(rationale.encode("utf-8")).hexdigest()


def _require_idempotency_key(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
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


def _request_fingerprint(value: ApprovalRequest) -> str:
    return _digest(
        {
            "approval_id": value.approval_id,
            "tenant_id": value.tenant_id,
            "repository_id": value.repository_id,
            "run_id": value.run_id,
            "finding_id": value.finding_id,
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
