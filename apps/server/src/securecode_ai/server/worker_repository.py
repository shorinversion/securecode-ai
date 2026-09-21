"""SQLite-backed worker leases and journals for restart-safe execution."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

from .worker_sessions import WorkerCommand, WorkerDenied, WorkerSession


class DurableWorkerSessions:
    """Persist every worker mutation under an immediate SQLite transaction."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self._connection.row_factory = sqlite3.Row

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

    def create(
        self,
        *,
        tenant_id: str,
        run_id: str,
        worker_id: str,
        identity_hash: str,
        idempotency_key: str,
    ) -> WorkerSession:
        fingerprint = hashlib.sha256(
            "\x00".join((run_id, worker_id, identity_hash)).encode("utf-8")
        ).hexdigest()
        session_id = f"session-{run_id}"
        with self._transaction() as cursor:
            replay = cursor.execute(
                """SELECT request_sha256, session_id FROM worker_session_idempotency
                   WHERE tenant_id=? AND idempotency_key=?""",
                (tenant_id, idempotency_key),
            ).fetchone()
            if replay is not None:
                if replay["request_sha256"] != fingerprint:
                    raise WorkerDenied()
                return self._load(cursor, tenant_id, replay["session_id"])
            existing = cursor.execute(
                """SELECT * FROM worker_sessions
                   WHERE tenant_id=? AND session_id=?""",
                (tenant_id, session_id),
            ).fetchone()
            if existing is not None:
                session = _session(existing)
                if (
                    session.run_id,
                    session.worker_id,
                    session.identity_hash,
                ) != (run_id, worker_id, identity_hash):
                    raise WorkerDenied()
            else:
                try:
                    cursor.execute(
                        """INSERT INTO worker_sessions
                           (tenant_id, session_id, run_id, worker_id,
                            execution_identity_hash, version, terminal, command, outcome)
                           VALUES (?, ?, ?, ?, ?, 1, 0, ?, NULL)""",
                        (
                            tenant_id,
                            session_id,
                            run_id,
                            worker_id,
                            identity_hash,
                            WorkerCommand.CONTINUE.value,
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise WorkerDenied() from error
                session = self._load(cursor, tenant_id, session_id)
            cursor.execute(
                """INSERT INTO worker_session_idempotency
                   (tenant_id, idempotency_key, request_sha256, session_id)
                   VALUES (?, ?, ?, ?)""",
                (tenant_id, idempotency_key, fingerprint, session_id),
            )
            return session

    def heartbeat(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
    ) -> WorkerSession:
        cursor = self._connection.cursor()
        try:
            return self._require(
                cursor,
                session_id,
                tenant_id,
                worker_id,
                identity_hash,
                expected_version,
            )
        finally:
            cursor.close()

    def append(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        events: tuple[dict[str, object], ...],
    ) -> WorkerSession:
        if not events:
            raise WorkerDenied()
        with self._transaction() as cursor:
            session = self._require(
                cursor,
                session_id,
                tenant_id,
                worker_id,
                identity_hash,
                expected_version,
            )
            count = cursor.execute(
                "SELECT COUNT(*) FROM worker_session_events WHERE tenant_id=? AND session_id=?",
                (tenant_id, session_id),
            ).fetchone()[0]
            for offset, event in enumerate(events, start=1):
                if set(event) != {"event_id", "sequence", "event_hash", "kind"}:
                    raise WorkerDenied()
                if event["sequence"] != count + offset:
                    raise WorkerDenied()
                if not all(
                    isinstance(event[key], str) and event[key]
                    for key in ("event_id", "event_hash", "kind")
                ):
                    raise WorkerDenied()
                try:
                    cursor.execute(
                        """INSERT INTO worker_session_events
                           (tenant_id, session_id, sequence, event_id, event_hash, kind)
                           VALUES (?, ?, ?, ?, ?, ?)""",
                        (
                            tenant_id,
                            session_id,
                            event["sequence"],
                            event["event_id"],
                            event["event_hash"],
                            event["kind"],
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise WorkerDenied() from error
            return session

    def artifact(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        content_sha256: str,
    ) -> WorkerSession:
        with self._transaction() as cursor:
            session = self._require(
                cursor,
                session_id,
                tenant_id,
                worker_id,
                identity_hash,
                expected_version,
            )
            cursor.execute(
                """INSERT OR IGNORE INTO worker_session_artifacts
                   (tenant_id, session_id, content_sha256) VALUES (?, ?, ?)""",
                (tenant_id, session_id, content_sha256),
            )
            return session

    def complete(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        outcome: str,
    ) -> WorkerSession:
        if outcome not in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}:
            raise WorkerDenied()
        with self._transaction() as cursor:
            session = self._require(
                cursor,
                session_id,
                tenant_id,
                worker_id,
                identity_hash,
                expected_version,
                allow_terminal=True,
            )
            if session.terminal:
                if session.outcome != outcome:
                    raise WorkerDenied()
                return session
            command = WorkerCommand.CONTINUE
            if outcome == "CANCELLED":
                command = WorkerCommand.CANCEL
            elif outcome == "SUPERSEDED":
                command = WorkerCommand.SUPERSEDE
            cursor.execute(
                """UPDATE worker_sessions
                   SET version=version+1, terminal=1, command=?, outcome=?
                   WHERE tenant_id=? AND session_id=? AND version=?""",
                (command.value, outcome, tenant_id, session_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise WorkerDenied()
            return self._load(cursor, tenant_id, session_id)

    def command(
        self,
        *,
        session_id: str,
        tenant_id: str,
        command: WorkerCommand,
        expected_version: int,
    ) -> WorkerSession:
        with self._transaction() as cursor:
            cursor.execute(
                """UPDATE worker_sessions SET version=version+1, command=?
                   WHERE tenant_id=? AND session_id=? AND version=? AND terminal=0""",
                (command.value, tenant_id, session_id, expected_version),
            )
            if cursor.rowcount != 1:
                raise WorkerDenied()
            return self._load(cursor, tenant_id, session_id)

    def _require(
        self,
        cursor: sqlite3.Cursor,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        *,
        allow_terminal: bool = False,
    ) -> WorkerSession:
        session = self._load(cursor, tenant_id, session_id)
        if (
            session.worker_id != worker_id
            or session.identity_hash != identity_hash
            or session.version != expected_version
            or (session.terminal and not allow_terminal)
        ):
            raise WorkerDenied()
        return session

    @staticmethod
    def _load(
        cursor: sqlite3.Cursor,
        tenant_id: str,
        session_id: str,
    ) -> WorkerSession:
        row = cursor.execute(
            "SELECT * FROM worker_sessions WHERE tenant_id=? AND session_id=?",
            (tenant_id, session_id),
        ).fetchone()
        if row is None:
            raise WorkerDenied()
        return _session(row)


def _session(row: sqlite3.Row) -> WorkerSession:
    return WorkerSession(
        tenant_id=row["tenant_id"],
        run_id=row["run_id"],
        worker_id=row["worker_id"],
        identity_hash=row["execution_identity_hash"],
        session_id=row["session_id"],
        version=row["version"],
        terminal=bool(row["terminal"]),
        command=WorkerCommand(row["command"]),
        outcome=row["outcome"],
    )


__all__ = ["DurableWorkerSessions"]
