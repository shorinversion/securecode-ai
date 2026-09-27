"""Durable, source-free secret lease accounting and rotation."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from typing import Final

from .secret_provider import OpaqueSecretLease, SecretProvider

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_PURPOSES: Final = frozenset({"github_installation", "provider_api", "artifact_store"})
_GRANT_STATES: Final = frozenset({"ACTIVE", "REVOKED", "EXPIRED"})


class SecretDenied(RuntimeError):
    """A secret operation failed closed without exposing provider details."""

    def __init__(self, code: str = "SECRET_DENIED") -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True, repr=False)
class SecretGrant:
    _handle: str
    grant_id: str = ""
    version: int = 1

    def __post_init__(self) -> None:
        if type(self._handle) is not str or not self._handle:
            raise SecretDenied("INVALID_PROVIDER_LEASE")
        if self.grant_id and _IDENTIFIER.fullmatch(self.grant_id) is None:
            raise SecretDenied("INVALID_GRANT_ID")
        if type(self.version) is not int or self.version < 1:
            raise SecretDenied("INVALID_VERSION")

    def __repr__(self) -> str:
        return "SecretGrant(<redacted>)"


@dataclass(frozen=True, slots=True)
class SecretReceipt:
    """Source-free receipt. It contains only hashes and control metadata."""

    tenant_id: str
    workload_id: str
    purpose: str
    handle_sha256: str
    expires_at: int
    grant_id: str = ""
    state: str = "ACTIVE"
    version: int = 1
    issued_at: int = 0

    def __post_init__(self) -> None:
        if (
            any(
                type(value) is not str or _IDENTIFIER.fullmatch(value) is None
                for value in (self.tenant_id, self.workload_id, self.grant_id)
            )
            or type(self.purpose) is not str
            or self.purpose not in _PURPOSES
            or type(self.handle_sha256) is not str
            or _SHA256.fullmatch(self.handle_sha256) is None
            or type(self.expires_at) is not int
            or type(self.issued_at) is not int
            or self.issued_at < 0
            or self.expires_at <= self.issued_at
            or type(self.state) is not str
            or self.state not in _GRANT_STATES
            or type(self.version) is not int
            or self.version < 1
        ):
            raise SecretDenied("INVALID_RECEIPT")


SECRET_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS secret_grants (
        tenant_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        workload_id TEXT NOT NULL,
        purpose TEXT NOT NULL,
        reference_sha256 TEXT NOT NULL,
        handle_sha256 TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        issued_at INTEGER NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
        version INTEGER NOT NULL,
        rotated_from_grant_id TEXT,
        revoked_at INTEGER,
        PRIMARY KEY (tenant_id, grant_id),
        UNIQUE (tenant_id, handle_sha256)
    )""",
    """CREATE INDEX IF NOT EXISTS secret_grants_active_idx
       ON secret_grants (tenant_id, workload_id, state, expires_at)""",
    """CREATE TABLE IF NOT EXISTS secret_grant_idempotency (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, grant_id)
            REFERENCES secret_grants (tenant_id, grant_id)
    )""",
    """CREATE TABLE IF NOT EXISTS secret_provider_revocations (
        tenant_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        next_attempt_at INTEGER NOT NULL,
        last_error_code TEXT,
        completed_at INTEGER,
        PRIMARY KEY (tenant_id, grant_id)
    )""",
    """CREATE TABLE IF NOT EXISTS secret_grant_consumptions (
        tenant_id TEXT NOT NULL,
        grant_id TEXT NOT NULL,
        consumed_at INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, grant_id),
        FOREIGN KEY (tenant_id, grant_id)
            REFERENCES secret_grants (tenant_id, grant_id)
    )""",
    """CREATE INDEX IF NOT EXISTS secret_provider_revocations_due_idx
       ON secret_provider_revocations (tenant_id, completed_at, next_attempt_at)""",
)


class SecretService:
    """Issues ephemeral grants while persisting only source-free receipts."""

    def __init__(
        self,
        provider: SecretProvider,
        connection: sqlite3.Connection | None = None,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.p = provider
        self._connection = connection or sqlite3.connect(":memory:")
        if not isinstance(self._connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._clock = clock or (lambda: int(time.time()))
        try:
            for statement in SECRET_SCHEMA_STATEMENTS:
                self._connection.execute(statement)
            self._connection.execute(
                """INSERT OR IGNORE INTO secret_provider_revocations (
                       tenant_id, grant_id, attempts, next_attempt_at
                   ) SELECT tenant_id, grant_id, 0, issued_at
                     FROM secret_grants WHERE state IN ('REVOKED', 'EXPIRED')"""
            )
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            yield cursor
            self._connection.commit()
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    @staticmethod
    def _queue_provider_revocation(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        grant_id: str,
        now: int,
    ) -> None:
        cursor.execute(
            """INSERT OR IGNORE INTO secret_provider_revocations (
                   tenant_id, grant_id, attempts, next_attempt_at
               ) VALUES (?, ?, 0, ?)""",
            (tenant_id, grant_id, now),
        )

    def grant(
        self,
        *,
        tenant_id: str,
        workload_id: str,
        reference: str,
        purpose: str,
        idempotency_key: str,
    ) -> tuple[SecretGrant | None, SecretReceipt]:
        _validate_request(tenant_id, workload_id, reference, purpose, idempotency_key)
        request_hash = _request_hash(workload_id, reference, purpose)
        cache_key = (tenant_id, idempotency_key)
        with self._revoke_provider_on_failure() as cleanup, self._transaction() as cursor:
            replay = cursor.execute(
                """SELECT operation, request_sha256, grant_id
                   FROM secret_grant_idempotency
                   WHERE tenant_id=? AND idempotency_key=?""",
                cache_key,
            ).fetchone()
            if replay is not None:
                if (replay["operation"], replay["request_sha256"]) != (
                    "grant",
                    request_hash,
                ):
                    raise SecretDenied("IDEMPOTENCY_CONFLICT")
                return None, self._receipt_at_now(
                    self._load(cursor, tenant_id, replay["grant_id"])
                )

            grant_id = (
                "grant-"
                + hashlib.sha256(
                    f"{tenant_id}\0{idempotency_key}\0{request_hash}".encode()
                ).hexdigest()[:40]
            )
            lease = self._issue(reference, purpose, grant_id)
            handle_hash = _hash_text(lease.handle)
            issued_at = self._now()
            self._require_live_lease(lease, issued_at, grant_id)
            cleanup.append(grant_id)
            receipt = SecretReceipt(
                tenant_id=tenant_id,
                workload_id=workload_id,
                purpose=purpose,
                handle_sha256=handle_hash,
                expires_at=lease.expires_at,
                grant_id=grant_id,
                state="ACTIVE",
                version=1,
                issued_at=issued_at,
            )
            grant = SecretGrant(lease.handle, grant_id, 1)
            try:
                cursor.execute(
                    """INSERT INTO secret_grants (
                        tenant_id, grant_id, workload_id, purpose,
                        reference_sha256, handle_sha256, expires_at, issued_at,
                        state, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 1)""",
                    (
                        tenant_id,
                        grant_id,
                        workload_id,
                        purpose,
                        _hash_text(reference),
                        handle_hash,
                        lease.expires_at,
                        issued_at,
                    ),
                )
                cursor.execute(
                    """INSERT INTO secret_grant_idempotency (
                        tenant_id, idempotency_key, operation,
                        request_sha256, grant_id
                    ) VALUES (?, ?, 'grant', ?, ?)""",
                    (tenant_id, idempotency_key, request_hash, grant_id),
                )
            except sqlite3.IntegrityError as error:
                raise SecretDenied("GRANT_CONFLICT") from error
            return grant, receipt

    def revoke(
        self,
        grant_id: str,
        *,
        tenant_id: str,
        expected_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> SecretReceipt:
        _require_identifier(grant_id, "grant_id")
        result: SecretReceipt | None = None
        resolved_tenant = tenant_id
        with self._transaction() as cursor:
            row = self._find_grant(cursor, grant_id, tenant_id)
            resolved_tenant = row["tenant_id"]
            fingerprint = _hash_values("revoke", resolved_tenant, row["grant_id"], expected_version)
            replay = self._operation_replay(
                cursor,
                tenant_id=resolved_tenant,
                idempotency_key=idempotency_key,
                operation="revoke",
                request_sha256=fingerprint,
            )
            if replay is not None:
                result = replay
            else:
                if expected_version is not None and row["version"] != expected_version:
                    raise SecretDenied("VERSION_CONFLICT")
                if row["state"] == "REVOKED":
                    self._queue_provider_revocation(
                        cursor,
                        tenant_id=resolved_tenant,
                        grant_id=row["grant_id"],
                        now=self._now(),
                    )
                    result = self._receipt_at_now(row)
                elif row["state"] != "ACTIVE":
                    raise SecretDenied("GRANT_NOT_ACTIVE")
                else:
                    now = self._now()
                    cursor.execute(
                        """UPDATE secret_grants
                           SET state='REVOKED', version=version+1, revoked_at=?
                           WHERE tenant_id=? AND grant_id=? AND state='ACTIVE'
                             AND version=?""",
                        (now, resolved_tenant, row["grant_id"], row["version"]),
                    )
                    if cursor.rowcount != 1:
                        raise SecretDenied("VERSION_CONFLICT")
                    self._queue_provider_revocation(
                        cursor,
                        tenant_id=resolved_tenant,
                        grant_id=row["grant_id"],
                        now=now,
                    )
                    updated = self._load(cursor, resolved_tenant, row["grant_id"])
                    self._remember_operation(
                        cursor,
                        tenant_id=resolved_tenant,
                        idempotency_key=idempotency_key,
                        operation="revoke",
                        request_sha256=fingerprint,
                        grant_id=row["grant_id"],
                    )
                    result = self._receipt_at_now(updated)
        self.retry_provider_revocations(tenant_id=resolved_tenant, grant_id=grant_id)
        if result is None:
            raise SecretDenied("REVOCATION_FAILED")
        return result

    def rotate(
        self,
        *,
        tenant_id: str,
        workload_id: str,
        reference: str,
        purpose: str,
        previous_grant_id: str,
        expected_version: int,
        idempotency_key: str,
    ) -> tuple[SecretGrant | None, SecretReceipt]:
        _validate_request(tenant_id, workload_id, reference, purpose, idempotency_key)
        _require_identifier(previous_grant_id, "grant_id")
        if type(expected_version) is not int or expected_version < 1:
            raise SecretDenied("INVALID_VERSION")
        fingerprint = _request_hash(
            workload_id,
            reference,
            purpose,
            previous_grant_id,
            expected_version,
        )
        rotated_grant: SecretGrant | None = None
        rotated_receipt: SecretReceipt | None = None
        replayed_receipt: SecretReceipt | None = None
        with self._revoke_provider_on_failure() as cleanup, self._transaction() as cursor:
            replay = self._operation_replay(
                cursor,
                tenant_id=tenant_id,
                idempotency_key=idempotency_key,
                operation="rotate",
                request_sha256=fingerprint,
            )
            if replay is not None:
                replayed_receipt = replay
                self._queue_provider_revocation(
                    cursor,
                    tenant_id=tenant_id,
                    grant_id=previous_grant_id,
                    now=self._now(),
                )
            else:
                old = self._find_grant(cursor, previous_grant_id, tenant_id)
                precondition_at = self._now()
                if (
                    old["workload_id"] != workload_id
                    or old["purpose"] != purpose
                    or old["state"] != "ACTIVE"
                    or old["version"] != expected_version
                    or old["expires_at"] <= precondition_at
                ):
                    raise SecretDenied("ROTATION_PRECONDITION_FAILED")
                grant_id = (
                    "grant-"
                    + hashlib.sha256(
                        f"{tenant_id}\0{idempotency_key}\0{fingerprint}".encode()
                    ).hexdigest()[:40]
                )
                lease = self._rotate_provider(
                    reference,
                    purpose,
                    previous_grant_id,
                    grant_id,
                )
                handle_hash = _hash_text(lease.handle)
                issued_at = self._now()
                self._require_live_lease(lease, issued_at, grant_id)
                cleanup.append(grant_id)
                try:
                    cursor.execute(
                        """INSERT INTO secret_grants (
                            tenant_id, grant_id, workload_id, purpose,
                            reference_sha256, handle_sha256, expires_at, issued_at,
                            state, version, rotated_from_grant_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 1, ?)""",
                        (
                            tenant_id,
                            grant_id,
                            workload_id,
                            purpose,
                            _hash_text(reference),
                            handle_hash,
                            lease.expires_at,
                            issued_at,
                            old["grant_id"],
                        ),
                    )
                    cursor.execute(
                        """UPDATE secret_grants
                           SET state='REVOKED', version=version+1, revoked_at=?
                           WHERE tenant_id=? AND grant_id=? AND state='ACTIVE'
                             AND version=?""",
                        (issued_at, tenant_id, old["grant_id"], expected_version),
                    )
                    if cursor.rowcount != 1:
                        raise SecretDenied("VERSION_CONFLICT")
                    self._queue_provider_revocation(
                        cursor,
                        tenant_id=tenant_id,
                        grant_id=old["grant_id"],
                        now=issued_at,
                    )
                    self._remember_operation(
                        cursor,
                        tenant_id=tenant_id,
                        idempotency_key=idempotency_key,
                        operation="rotate",
                        request_sha256=fingerprint,
                        grant_id=grant_id,
                    )
                except Exception:
                    raise
                rotated_grant = SecretGrant(lease.handle, grant_id, 1)
                rotated_receipt = SecretReceipt(
                    tenant_id,
                    workload_id,
                    purpose,
                    handle_hash,
                    lease.expires_at,
                    grant_id,
                    "ACTIVE",
                    1,
                    issued_at,
                )
        self.retry_provider_revocations(
            tenant_id=tenant_id,
            grant_id=previous_grant_id,
        )
        if replayed_receipt is not None:
            return None, replayed_receipt
        if rotated_grant is None or rotated_receipt is None:
            raise SecretDenied("ROTATION_FAILED")
        return rotated_grant, rotated_receipt

    def receipt(self, *, tenant_id: str, grant_id: str) -> SecretReceipt:
        _require_identifier(tenant_id, "tenant_id")
        _require_identifier(grant_id, "grant_id")
        row = self._connection.execute(
            """SELECT * FROM secret_grants
               WHERE tenant_id=? AND grant_id=?""",
            (tenant_id, grant_id),
        ).fetchone()
        if row is None:
            raise SecretDenied("GRANT_UNKNOWN")
        return self._receipt_at_now(row)

    def retrieve(
        self,
        *,
        tenant_id: str,
        workload_id: str,
        grant_id: str,
    ) -> SecretGrant:
        """Consume an active grant once and return its lease to a trusted consumer."""

        _require_identifier(tenant_id, "tenant_id")
        _require_identifier(workload_id, "workload_id")
        _require_identifier(grant_id, "grant_id")
        with self._transaction() as cursor:
            row = self._find_grant(cursor, grant_id, tenant_id)
            receipt = _receipt(row)
            if receipt.workload_id != workload_id:
                raise SecretDenied("GRANT_SCOPE_DENIED")
            consumed_at = self._now()
            if receipt.state != "ACTIVE" or receipt.expires_at <= consumed_at:
                raise SecretDenied("GRANT_NOT_ACTIVE")
            consumed = cursor.execute(
                """SELECT 1 FROM secret_grant_consumptions
                   WHERE tenant_id=? AND grant_id=?""",
                (tenant_id, grant_id),
            ).fetchone()
            if consumed is not None:
                raise SecretDenied("GRANT_ALREADY_CONSUMED")
            try:
                cursor.execute(
                    """INSERT INTO secret_grant_consumptions (
                           tenant_id, grant_id, consumed_at
                       ) VALUES (?, ?, ?)""",
                    (tenant_id, grant_id, consumed_at),
                )
            except sqlite3.IntegrityError:
                raise SecretDenied("GRANT_CONSUMPTION_FAILED") from None
        try:
            lease = self.p.retrieve(grant_id)
        except Exception:
            raise SecretDenied("PROVIDER_UNAVAILABLE") from None
        if not isinstance(lease, OpaqueSecretLease):
            raise SecretDenied("INVALID_PROVIDER_LEASE")
        if (
            lease.expires_at != receipt.expires_at
            or lease.expires_at <= self._now()
            or _hash_text(lease.handle) != receipt.handle_sha256
        ):
            raise SecretDenied("PROVIDER_LEASE_MISMATCH")
        return SecretGrant(lease.handle, grant_id, receipt.version)

    def expire(self, *, tenant_id: str, now: int | None = None) -> int:
        expired = self.expire_due_grants(tenant_id=tenant_id, now=now)
        self.retry_provider_revocations(tenant_id=tenant_id)
        return expired

    def expire_due_grants(
        self,
        *,
        tenant_id: str,
        now: int | None = None,
        max_items: int | None = None,
    ) -> int:
        """Persist grant expiry without coupling it to provider availability."""

        _require_identifier(tenant_id, "tenant_id")
        if max_items is not None and (
            type(max_items) is not int or not 1 <= max_items <= 10_000
        ):
            raise SecretDenied("INVALID_LIMIT")
        effective_now = self._now() if now is None else now
        if type(effective_now) is not int or effective_now < 0:
            raise SecretDenied("INVALID_TIME")
        expired = 0
        while True:
            if max_items is not None and expired >= max_items:
                return expired
            batch_size = 100 if max_items is None else min(100, max_items - expired)
            with self._transaction() as cursor:
                rows = cursor.execute(
                    """SELECT grant_id, version FROM secret_grants
                       WHERE tenant_id=? AND state='ACTIVE' AND expires_at<=?
                       ORDER BY expires_at, grant_id LIMIT ?""",
                    (tenant_id, effective_now, batch_size),
                ).fetchall()
            if not rows:
                return expired
            for row in rows:
                grant_id = row["grant_id"]
                version = row["version"]
                _require_identifier(grant_id, "grant_id")
                if type(version) is not int or version < 1:
                    raise SecretDenied("INVALID_VERSION")
                with self._transaction() as cursor:
                    cursor.execute(
                        """UPDATE secret_grants
                           SET state='EXPIRED', version=version+1
                           WHERE tenant_id=? AND grant_id=? AND state='ACTIVE'
                             AND version=? AND expires_at<=?""",
                        (tenant_id, grant_id, version, effective_now),
                    )
                    if cursor.rowcount == 1:
                        self._queue_provider_revocation(
                            cursor,
                            tenant_id=tenant_id,
                            grant_id=grant_id,
                            now=effective_now,
                        )
                        expired += 1
                    else:
                        current = cursor.execute(
                            """SELECT state, version, expires_at FROM secret_grants
                               WHERE tenant_id=? AND grant_id=?""",
                            (tenant_id, grant_id),
                        ).fetchone()
                        if (
                            current is not None
                            and current["state"] == "ACTIVE"
                            and current["version"] == version
                            and current["expires_at"] <= effective_now
                        ):
                            raise SecretDenied("VERSION_CONFLICT")

    def has_due_grants(self, *, tenant_id: str, now: int | None = None) -> bool:
        """Report whether more grants await expiration, without exposing IDs."""

        _require_identifier(tenant_id, "tenant_id")
        effective_now = self._now() if now is None else now
        if type(effective_now) is not int or effective_now < 0:
            raise SecretDenied("INVALID_TIME")
        row = self._connection.execute(
            """SELECT 1 FROM secret_grants
               WHERE tenant_id=? AND state='ACTIVE' AND expires_at<=? LIMIT 1""",
            (tenant_id, effective_now),
        ).fetchone()
        return row is not None

    def has_pending_provider_revocations(self, *, tenant_id: str) -> bool:
        """Report pending provider cleanup without exposing grant identifiers."""

        _require_identifier(tenant_id, "tenant_id")
        row = self._connection.execute(
            """SELECT 1 FROM secret_provider_revocations
               WHERE tenant_id=? AND completed_at IS NULL LIMIT 1""",
            (tenant_id,),
        ).fetchone()
        return row is not None

    def retry_provider_revocations(
        self,
        *,
        tenant_id: str,
        grant_id: str | None = None,
        limit: int = 100,
    ) -> int:
        """Retry durable provider revocations with leases and bounded backoff."""

        _require_identifier(tenant_id, "tenant_id")
        if grant_id is not None:
            _require_identifier(grant_id, "grant_id")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise SecretDenied("INVALID_LIMIT")
        now = self._now()
        query = (
            """SELECT grant_id, attempts, next_attempt_at
               FROM secret_provider_revocations
               WHERE tenant_id=? AND completed_at IS NULL AND next_attempt_at<=?"""
        )
        parameters: tuple[object, ...] = (tenant_id, now)
        if grant_id is not None:
            query += " AND grant_id=?"
            parameters += (grant_id,)
        query += " ORDER BY next_attempt_at, grant_id LIMIT ?"
        parameters += (limit,)
        claimed: list[tuple[str, int, int]] = []
        with self._transaction() as cursor:
            rows = cursor.execute(query, parameters).fetchall()
            for row in rows:
                pending_grant_id = row["grant_id"]
                attempts = row["attempts"]
                due_at = row["next_attempt_at"]
                if (
                    type(pending_grant_id) is not str
                    or _IDENTIFIER.fullmatch(pending_grant_id) is None
                    or type(attempts) is not int
                    or attempts < 0
                    or type(due_at) is not int
                    or due_at < 0
                ):
                    raise SecretDenied("REVOCATION_STATE_INVALID")
                claimed_at = now + 30
                next_attempt = attempts + 1
                cursor.execute(
                    """UPDATE secret_provider_revocations
                       SET attempts=?, next_attempt_at=?
                       WHERE tenant_id=? AND grant_id=? AND attempts=?
                         AND next_attempt_at=? AND completed_at IS NULL
                         AND next_attempt_at<=?""",
                    (
                        next_attempt,
                        claimed_at,
                        tenant_id,
                        pending_grant_id,
                        attempts,
                        due_at,
                        now,
                    ),
                )
                if cursor.rowcount == 1:
                    claimed.append((pending_grant_id, next_attempt, claimed_at))

        completed = 0
        failed = False
        for pending_grant_id, attempts, claimed_at in claimed:
            try:
                self._revoke_provider(pending_grant_id)
            except SecretDenied:
                failed = True
                delay = min(3600, 2 ** min(attempts, 12))
                retry_at = self._now() + delay
                with self._transaction() as cursor:
                    cursor.execute(
                        """UPDATE secret_provider_revocations
                           SET last_error_code='PROVIDER_UNAVAILABLE', next_attempt_at=?
                           WHERE tenant_id=? AND grant_id=? AND attempts=?
                             AND next_attempt_at=? AND completed_at IS NULL""",
                        (
                            retry_at,
                            tenant_id,
                            pending_grant_id,
                            attempts,
                            claimed_at,
                        ),
                    )
                continue
            completed_at = self._now()
            with self._transaction() as cursor:
                cursor.execute(
                    """UPDATE secret_provider_revocations
                       SET last_error_code=NULL, completed_at=?, next_attempt_at=?
                       WHERE tenant_id=? AND grant_id=? AND completed_at IS NULL""",
                    (completed_at, completed_at, tenant_id, pending_grant_id),
                )
                if cursor.rowcount == 1:
                    completed += 1

        pending_query = (
            """SELECT 1 FROM secret_provider_revocations
               WHERE tenant_id=? AND completed_at IS NULL LIMIT 1"""
        )
        pending_parameters: tuple[object, ...] = (tenant_id,)
        if grant_id is not None:
            pending_query = pending_query.replace(
                "completed_at IS NULL LIMIT 1",
                "completed_at IS NULL AND grant_id=? LIMIT 1",
            )
            pending_parameters += (grant_id,)
        pending = self._connection.execute(
            pending_query,
            pending_parameters,
        ).fetchone()
        if failed or pending is not None:
            raise SecretDenied("PROVIDER_UNAVAILABLE")
        return completed

    def _issue(self, reference: str, purpose: str, grant_id: str) -> OpaqueSecretLease:
        try:
            lease = self.p.issue(reference, purpose=purpose, grant_id=grant_id)
        except Exception:
            raise SecretDenied("PROVIDER_UNAVAILABLE") from None
        if not isinstance(lease, OpaqueSecretLease):
            raise SecretDenied("INVALID_PROVIDER_LEASE")
        return lease

    def _rotate_provider(
        self,
        reference: str,
        purpose: str,
        previous_grant_id: str,
        grant_id: str,
    ) -> OpaqueSecretLease:
        try:
            lease = self.p.rotate(
                reference,
                purpose=purpose,
                previous_grant_id=previous_grant_id,
                grant_id=grant_id,
            )
        except Exception:
            raise SecretDenied("PROVIDER_UNAVAILABLE") from None
        if not isinstance(lease, OpaqueSecretLease):
            raise SecretDenied("INVALID_PROVIDER_LEASE")
        return lease

    def _revoke_provider(self, grant_id: str) -> None:
        try:
            self.p.revoke(grant_id)
        except Exception:
            raise SecretDenied("PROVIDER_UNAVAILABLE") from None

    @contextmanager
    def _revoke_provider_on_failure(self) -> Iterator[list[str]]:
        issued_grants: list[str] = []
        try:
            yield issued_grants
        except Exception:
            for grant_id in issued_grants:
                self._best_effort_revoke(grant_id)
            raise

    def _best_effort_revoke(self, grant_id: str) -> None:
        try:
            self.p.revoke(grant_id)
        except Exception:
            return

    def _require_live_lease(self, lease: OpaqueSecretLease, issued_at: int, grant_id: str) -> None:
        if type(lease.expires_at) is not int or lease.expires_at <= issued_at:
            self._best_effort_revoke(grant_id)
            raise SecretDenied("EXPIRED_PROVIDER_LEASE")

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0:
            raise SecretDenied("INVALID_TIME")
        return value

    def _receipt_at_now(self, row: sqlite3.Row) -> SecretReceipt:
        receipt = _receipt(row)
        if receipt.state == "ACTIVE" and receipt.expires_at <= self._now():
            return replace(receipt, state="EXPIRED")
        return receipt

    @staticmethod
    def _find_grant(cursor: sqlite3.Cursor, grant_id: str, tenant_id: str) -> sqlite3.Row:
        _require_identifier(tenant_id, "tenant_id")
        row: sqlite3.Row | None = cursor.execute(
            """SELECT * FROM secret_grants
               WHERE tenant_id=? AND grant_id=?""",
            (tenant_id, grant_id),
        ).fetchone()
        if row is None:
            raise SecretDenied("GRANT_UNKNOWN")
        return row

    @staticmethod
    def _load(cursor: sqlite3.Cursor, tenant_id: str, grant_id: str) -> sqlite3.Row:
        row: sqlite3.Row | None = cursor.execute(
            """SELECT * FROM secret_grants
               WHERE tenant_id=? AND grant_id=?""",
            (tenant_id, grant_id),
        ).fetchone()
        if row is None:
            raise SecretDenied("GRANT_UNKNOWN")
        return row

    def _operation_replay(
        self,
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        idempotency_key: str | None,
        operation: str,
        request_sha256: str,
    ) -> SecretReceipt | None:
        if idempotency_key is None:
            return None
        _require_identifier(idempotency_key, "idempotency_key")
        row = cursor.execute(
            """SELECT operation, request_sha256, grant_id
               FROM secret_grant_idempotency
               WHERE tenant_id=? AND idempotency_key=?""",
            (tenant_id, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if (row["operation"], row["request_sha256"]) != (
            operation,
            request_sha256,
        ):
            raise SecretDenied("IDEMPOTENCY_CONFLICT")
        return self._receipt_at_now(self._load(cursor, tenant_id, row["grant_id"]))

    @staticmethod
    def _remember_operation(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        idempotency_key: str | None,
        operation: str,
        request_sha256: str,
        grant_id: str,
    ) -> None:
        if idempotency_key is None:
            return
        cursor.execute(
            """INSERT INTO secret_grant_idempotency (
                tenant_id, idempotency_key, operation, request_sha256, grant_id
            ) VALUES (?, ?, ?, ?, ?)""",
            (tenant_id, idempotency_key, operation, request_sha256, grant_id),
        )


def _receipt(row: sqlite3.Row) -> SecretReceipt:
    return SecretReceipt(
        tenant_id=row["tenant_id"],
        workload_id=row["workload_id"],
        purpose=row["purpose"],
        handle_sha256=row["handle_sha256"],
        expires_at=row["expires_at"],
        grant_id=row["grant_id"],
        state=row["state"],
        version=row["version"],
        issued_at=row["issued_at"],
    )


def _validate_request(
    tenant_id: str,
    workload_id: str,
    reference: str,
    purpose: str,
    idempotency_key: str,
) -> None:
    _require_identifier(tenant_id, "tenant_id")
    _require_identifier(workload_id, "workload_id")
    _require_identifier(idempotency_key, "idempotency_key")
    if purpose not in _PURPOSES:
        raise SecretDenied("PURPOSE_DENIED")
    if type(reference) is not str or not reference or len(reference) > 2048:
        raise SecretDenied("INVALID_REFERENCE")


def _require_identifier(value: str, field: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise SecretDenied(f"INVALID_{field.upper()}")


def _request_hash(*values: object) -> str:
    redacted = list(values)
    if len(redacted) >= 2 and isinstance(redacted[1], str):
        redacted[1] = _hash_text(redacted[1])
    return _hash_values(*redacted)


def _hash_values(*values: object) -> str:
    payload = json.dumps(
        values,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = [
    "SECRET_SCHEMA_STATEMENTS",
    "SecretDenied",
    "SecretGrant",
    "SecretReceipt",
    "SecretService",
]
