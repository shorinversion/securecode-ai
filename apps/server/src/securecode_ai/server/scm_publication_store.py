"""Durable SCM publication targets and retry-safe publication receipts."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")

SCM_PUBLICATION_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS scm_publication_targets (
        tenant_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        provider TEXT NOT NULL CHECK (provider IN ('github', 'gitlab')),
        installation_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        change_id TEXT NOT NULL,
        head_sha TEXT NOT NULL CHECK (length(head_sha) = 40),
        execution_identity_hash TEXT NOT NULL CHECK (
            length(execution_identity_hash) = 64
        ),
        publication_state TEXT NOT NULL DEFAULT 'PENDING' CHECK (
            publication_state IN ('PENDING', 'PUBLISHED', 'STALE')
        ),
        outcome TEXT,
        receipt_id TEXT,
        PRIMARY KEY (tenant_id, run_id),
        UNIQUE (tenant_id, provider, repository_id, change_id, head_sha)
    )""",
    """CREATE INDEX IF NOT EXISTS scm_publication_pending_idx
       ON scm_publication_targets (tenant_id, publication_state, run_id)""",
)


class SCMPublicationStoreError(RuntimeError):
    """Closed persistence error that contains no remote payload or credentials."""


@dataclass(frozen=True, slots=True)
class SCMPublicationTarget:
    tenant_id: str
    run_id: str
    provider: str
    installation_id: str
    repository_id: str
    change_id: str
    head_sha: str
    execution_identity_hash: str
    publication_state: str = "PENDING"
    outcome: str | None = None
    receipt_id: str | None = None

    def __post_init__(self) -> None:
        identifiers = (
            self.tenant_id,
            self.run_id,
            self.installation_id,
            self.repository_id,
            self.change_id,
        )
        if (
            any(type(value) is not str or _ID.fullmatch(value) is None for value in identifiers)
            or self.provider not in {"github", "gitlab"}
            or type(self.head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.head_sha) is None
            or type(self.execution_identity_hash) is not str
            or _SHA256.fullmatch(self.execution_identity_hash) is None
            or self.publication_state not in {"PENDING", "PUBLISHED", "STALE"}
            or (
                self.outcome is not None
                and self.outcome not in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}
            )
            or (
                self.receipt_id is not None
                and (type(self.receipt_id) is not str or _ID.fullmatch(self.receipt_id) is None)
            )
            or (self.publication_state == "PENDING" and self.receipt_id is not None)
            or (
                self.publication_state == "PUBLISHED"
                and (
                    self.outcome not in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED"}
                    or self.receipt_id is None
                )
            )
            or (
                self.publication_state == "STALE"
                and (self.outcome != "SUPERSEDED" or self.receipt_id is None)
            )
        ):
            raise SCMPublicationStoreError("SCM publication target is invalid")


class SqliteSCMPublicationStore:
    """Persist one exact PR or MR target for each admitted run."""

    __slots__ = ("_connection",)

    def __init__(self, connection: sqlite3.Connection, *, initialize: bool = False) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("SCM publication connection is invalid")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        if initialize:
            for statement in SCM_PUBLICATION_SCHEMA_STATEMENTS:
                connection.execute(statement)
            connection.commit()

    def bind(self, target: SCMPublicationTarget) -> None:
        if type(target) is not SCMPublicationTarget or target.publication_state != "PENDING":
            raise SCMPublicationStoreError("SCM publication target is invalid")
        with self._transaction() as cursor:
            existing = cursor.execute(
                """SELECT * FROM scm_publication_targets
                   WHERE tenant_id=? AND run_id=?""",
                (target.tenant_id, target.run_id),
            ).fetchone()
            if existing is not None:
                if not _same_binding(_target(existing), target):
                    raise SCMPublicationStoreError("SCM publication target conflicts")
                return
            try:
                cursor.execute(
                    """INSERT INTO scm_publication_targets (
                           tenant_id, run_id, provider, installation_id,
                           repository_id, change_id, head_sha,
                           execution_identity_hash, publication_state,
                           outcome, receipt_id
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', NULL, NULL)""",
                    (
                        target.tenant_id,
                        target.run_id,
                        target.provider,
                        target.installation_id,
                        target.repository_id,
                        target.change_id,
                        target.head_sha,
                        target.execution_identity_hash,
                    ),
                )
            except sqlite3.IntegrityError:
                raise SCMPublicationStoreError("SCM publication target conflicts") from None

    def load(self, *, tenant_id: str, run_id: str) -> SCMPublicationTarget | None:
        _identifier(tenant_id)
        _identifier(run_id)
        row = self._connection.execute(
            """SELECT * FROM scm_publication_targets
               WHERE tenant_id=? AND run_id=?""",
            (tenant_id, run_id),
        ).fetchone()
        return None if row is None else _target(row)

    def pending(
        self,
        *,
        tenant_id: str,
        limit: int = 32,
    ) -> tuple[SCMPublicationTarget, ...]:
        """Return a bounded source-free snapshot of retryable publications."""

        _identifier(tenant_id)
        if type(limit) is not int or not 1 <= limit <= 256:
            raise SCMPublicationStoreError("SCM publication batch is invalid")
        try:
            rows = self._connection.execute(
                """SELECT p.tenant_id, p.run_id, p.provider,
                          p.installation_id, p.repository_id, p.change_id,
                          p.head_sha, p.execution_identity_hash,
                          p.publication_state,
                          COALESCE(
                              p.outcome,
                              CASE q.outcome
                                  WHEN 'SUCCEEDED' THEN 'PASS'
                                  WHEN 'FAILED' THEN 'FAIL'
                                  WHEN 'INDETERMINATE' THEN 'INDETERMINATE'
                                  WHEN 'CANCELLED' THEN 'CANCELLED'
                                  WHEN 'SUPERSEDED' THEN 'SUPERSEDED'
                              END
                          ) AS outcome,
                          p.receipt_id
                   FROM scm_publication_targets AS p
                   LEFT JOIN worker_run_queue AS q
                     ON q.tenant_id=p.tenant_id AND q.run_id=p.run_id
                   WHERE p.tenant_id=? AND p.publication_state='PENDING'
                   ORDER BY p.run_id LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            rows = self._connection.execute(
                """SELECT * FROM scm_publication_targets
                   WHERE tenant_id=? AND publication_state='PENDING'
                   ORDER BY run_id LIMIT ?""",
                (tenant_id, limit),
            ).fetchall()
        return tuple(_target(row) for row in rows)

    def mark_pending(
        self,
        *,
        target: SCMPublicationTarget,
        outcome: str,
    ) -> SCMPublicationTarget:
        """Persist the worker outcome before an asynchronous provider write."""

        if (
            type(target) is not SCMPublicationTarget
            or target.publication_state != "PENDING"
            or outcome not in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}
        ):
            raise SCMPublicationStoreError("SCM publication target is invalid")
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT * FROM scm_publication_targets
                   WHERE tenant_id=? AND run_id=?""",
                (target.tenant_id, target.run_id),
            ).fetchone()
            if row is None:
                raise SCMPublicationStoreError("SCM publication target conflicts")
            current = _target(row)
            if not _same_binding(current, target):
                raise SCMPublicationStoreError("SCM publication target conflicts")
            if current.publication_state != "PENDING":
                raise SCMPublicationStoreError("SCM publication target conflicts")
            if current.outcome is not None and current.outcome != outcome:
                raise SCMPublicationStoreError("SCM publication outcome conflicts")
            if current.outcome is None:
                cursor.execute(
                    """UPDATE scm_publication_targets SET outcome=?
                       WHERE tenant_id=? AND run_id=?
                         AND publication_state='PENDING' AND outcome IS NULL""",
                    (outcome, target.tenant_id, target.run_id),
                )
                if cursor.rowcount != 1:
                    raise SCMPublicationStoreError("SCM publication target conflicts")
        stored = self.load(tenant_id=target.tenant_id, run_id=target.run_id)
        if stored is None:
            raise SCMPublicationStoreError("SCM publication target is unavailable")
        return stored

    def resolve(
        self,
        *,
        tenant_id: str,
        provider: str,
        repository_id: str,
        change_id: str,
        head_sha: str,
    ) -> SCMPublicationTarget | None:
        """Resolve one exact SCM change revision without accepting stale work."""

        for value in (tenant_id, repository_id, change_id):
            _identifier(value)
        if provider not in {"github", "gitlab"} or _COMMIT_SHA.fullmatch(head_sha) is None:
            raise SCMPublicationStoreError("SCM publication target is invalid")
        row = self._connection.execute(
            """SELECT * FROM scm_publication_targets
               WHERE tenant_id=? AND provider=? AND repository_id=?
                 AND change_id=? AND head_sha=? AND publication_state='PENDING'""",
            (tenant_id, provider, repository_id, change_id, head_sha),
        ).fetchone()
        return None if row is None else _target(row)

    def record(
        self,
        *,
        target: SCMPublicationTarget,
        outcome: str,
        stale: bool,
        receipt_id: str,
        allow_policy_update: bool = False,
    ) -> SCMPublicationTarget:
        if (
            type(target) is not SCMPublicationTarget
            or outcome not in {"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}
            or type(stale) is not bool
            or type(allow_policy_update) is not bool
        ):
            raise SCMPublicationStoreError("SCM publication receipt is invalid")
        _identifier(receipt_id)
        state = "STALE" if stale else "PUBLISHED"
        with self._transaction() as cursor:
            row = cursor.execute(
                """SELECT * FROM scm_publication_targets
                   WHERE tenant_id=? AND run_id=?""",
                (target.tenant_id, target.run_id),
            ).fetchone()
            if row is None or _same_binding(_target(row), target) is False:
                raise SCMPublicationStoreError("SCM publication target conflicts")
            current = _target(row)
            if current.publication_state != "PENDING":
                if (
                    allow_policy_update
                    and current.publication_state == "PUBLISHED"
                    and state == "PUBLISHED"
                    and current.outcome in {"PASS", "FAIL"}
                    and outcome in {"PASS", "FAIL"}
                    and current.outcome != outcome
                    and current.receipt_id == receipt_id
                ):
                    cursor.execute(
                        """UPDATE scm_publication_targets SET outcome=?
                           WHERE tenant_id=? AND run_id=?
                             AND publication_state='PUBLISHED' AND outcome=?""",
                        (outcome, target.tenant_id, target.run_id, current.outcome),
                    )
                    if cursor.rowcount != 1:
                        raise SCMPublicationStoreError("SCM publication receipt conflicts")
                    current = _target(
                        cursor.execute(
                            """SELECT * FROM scm_publication_targets
                               WHERE tenant_id=? AND run_id=?""",
                            (target.tenant_id, target.run_id),
                        ).fetchone()
                    )
                    return current
                if (
                    current.publication_state != state
                    or current.outcome != outcome
                    or current.receipt_id != receipt_id
                ):
                    raise SCMPublicationStoreError("SCM publication receipt conflicts")
                return current
            cursor.execute(
                """UPDATE scm_publication_targets
                   SET publication_state=?, outcome=?, receipt_id=?
                   WHERE tenant_id=? AND run_id=? AND publication_state='PENDING'""",
                (state, outcome, receipt_id, target.tenant_id, target.run_id),
            )
            if cursor.rowcount != 1:
                raise SCMPublicationStoreError("SCM publication receipt conflicts")
        stored = self.load(tenant_id=target.tenant_id, run_id=target.run_id)
        if stored is None:
            raise SCMPublicationStoreError("SCM publication receipt is unavailable")
        return stored

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


def _target(row: sqlite3.Row) -> SCMPublicationTarget:
    return SCMPublicationTarget(
        tenant_id=row["tenant_id"],
        run_id=row["run_id"],
        provider=row["provider"],
        installation_id=row["installation_id"],
        repository_id=row["repository_id"],
        change_id=row["change_id"],
        head_sha=row["head_sha"],
        execution_identity_hash=row["execution_identity_hash"],
        publication_state=row["publication_state"],
        outcome=row["outcome"],
        receipt_id=row["receipt_id"],
    )


def _same_binding(left: SCMPublicationTarget, right: SCMPublicationTarget) -> bool:
    return (
        left.tenant_id,
        left.run_id,
        left.provider,
        left.installation_id,
        left.repository_id,
        left.change_id,
        left.head_sha,
        left.execution_identity_hash,
    ) == (
        right.tenant_id,
        right.run_id,
        right.provider,
        right.installation_id,
        right.repository_id,
        right.change_id,
        right.head_sha,
        right.execution_identity_hash,
    )


def _identifier(value: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise SCMPublicationStoreError("SCM publication identifier is invalid")


__all__ = [
    "SCM_PUBLICATION_SCHEMA_STATEMENTS",
    "SCMPublicationStoreError",
    "SCMPublicationTarget",
    "SqliteSCMPublicationStore",
]
