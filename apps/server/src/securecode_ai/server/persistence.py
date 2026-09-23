"""Transactional source-free control-plane persistence for P6.2."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

from .migrations import apply_schema


class RepositoryError(Exception):
    code = "OPERATION_FAILED"


class NotFoundError(RepositoryError):
    code = "NOT_FOUND"


class ConflictError(RepositoryError):
    code = "CONFLICT"


class PreconditionError(RepositoryError):
    code = "PRECONDITION_FAILED"


@dataclass(frozen=True, slots=True)
class StoredResponse:
    status: int
    document: dict[str, object]


class DevelopmentRepository:
    """SQLite development repository using DB-API transactions and tenant predicates."""

    def __init__(self, connection: sqlite3.Connection, *, initialize: bool = True) -> None:
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 5000")
        self._connection.execute("PRAGMA synchronous = FULL")
        if _database_path(connection) != "":
            self._connection.execute("PRAGMA journal_mode = WAL")
        if initialize:
            apply_schema(connection)

    @classmethod
    def in_memory(cls) -> DevelopmentRepository:
        return cls(sqlite3.connect(":memory:"))

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
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

    def create_run(
        self,
        *,
        tenant_id: str,
        run_id: str,
        repository_id: str,
        execution_identity_hash: str,
        base_sha: str | None,
        head_sha: str,
        metadata: dict[str, object],
        idempotency_key: str,
        request_sha256: str,
    ) -> StoredResponse:
        _validate_hash(execution_identity_hash)
        _validate_hash(request_sha256)
        if base_sha is not None:
            _validate_sha(base_sha)
        _validate_sha(head_sha)
        now = _now()
        with self.transaction() as cursor:
            replay = _idempotency(
                cursor, tenant_id, idempotency_key, "POST", "/api/v1/runs", request_sha256
            )
            if replay is not None:
                return replay
            existing = cursor.execute(
                "SELECT run_id, execution_identity_hash FROM audit_runs WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
            if existing is not None:
                raise ConflictError()
            cursor.execute(
                "INSERT OR IGNORE INTO scm_repositories (tenant_id, repository_id, created_at) VALUES (?, ?, ?)",
                (tenant_id, repository_id, now),
            )
            try:
                cursor.execute(
                    "INSERT INTO audit_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant_id,
                        run_id,
                        repository_id,
                        execution_identity_hash,
                        base_sha,
                        head_sha,
                        "REQUESTED",
                        1,
                        _canonical(metadata),
                        now,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ConflictError() from error
            response = StoredResponse(
                201,
                _run_projection(
                    tenant_id,
                    run_id,
                    repository_id,
                    execution_identity_hash,
                    base_sha,
                    head_sha,
                    "REQUESTED",
                    1,
                ),
            )
            _store_idempotency(
                cursor, tenant_id, idempotency_key, "POST", "/api/v1/runs", request_sha256, response
            )
            return response

    def get_run(self, tenant_id: str, run_id: str) -> dict[str, object]:
        row = self._connection.execute(
            "SELECT tenant_id, run_id, repository_id, execution_identity_hash, base_sha, head_sha, state, version FROM audit_runs WHERE tenant_id=? AND run_id=?",
            (tenant_id, run_id),
        ).fetchone()
        if row is None:
            raise NotFoundError()
        return _run_projection(*row)

    def list_runs(
        self,
        tenant_id: str,
        repository_id: str,
        cursor_token: str | None,
        limit: int,
    ) -> dict[str, object]:
        """List source-free runs with tenant-bound keyset pagination."""

        if not tenant_id or not repository_id or type(limit) is not int or not 1 <= limit <= 100:
            raise ConflictError()
        after = _cursor_text(cursor_token)
        rows = self._connection.execute(
            """SELECT tenant_id, run_id, repository_id, execution_identity_hash,
                      base_sha, head_sha, state, version
               FROM audit_runs
               WHERE tenant_id=? AND repository_id=? AND run_id>?
               ORDER BY run_id ASC LIMIT ?""",
            (tenant_id, repository_id, after, limit + 1),
        ).fetchall()
        items = [_run_projection(*row) for row in rows[:limit]]
        return _page(items, rows, limit, text=True, cursor_column="run_id")

    def cancel_run(
        self,
        *,
        tenant_id: str,
        run_id: str,
        precondition: int,
        idempotency_key: str,
        request_sha256: str,
    ) -> StoredResponse:
        with self.transaction() as cursor:
            replay = _idempotency(
                cursor,
                tenant_id,
                idempotency_key,
                "POST",
                f"/api/v1/runs/{run_id}:cancel",
                request_sha256,
            )
            if replay is not None:
                return replay
            row = cursor.execute(
                "SELECT version, state FROM audit_runs WHERE tenant_id=? AND run_id=?",
                (tenant_id, run_id),
            ).fetchone()
            if row is None:
                raise NotFoundError()
            if row["version"] != precondition:
                raise PreconditionError()
            if row["state"] not in {"REQUESTED", "RUNNING"}:
                raise ConflictError()
            cursor.execute(
                "UPDATE audit_runs SET state=?, version=?, updated_at=? WHERE tenant_id=? AND run_id=?",
                ("CANCEL_REQUESTED", precondition + 1, _now(), tenant_id, run_id),
            )
            response = StoredResponse(202, self.get_run(tenant_id, run_id))
            _store_idempotency(
                cursor,
                tenant_id,
                idempotency_key,
                "POST",
                f"/api/v1/runs/{run_id}:cancel",
                request_sha256,
                response,
            )
            return response

    def list_events(
        self, tenant_id: str, run_id: str, cursor_token: str | None, limit: int
    ) -> dict[str, object]:
        self.get_run(tenant_id, run_id)
        sequence = _cursor_value(cursor_token)
        rows = self._connection.execute(
            "SELECT sequence, event_id, metadata_json FROM run_events WHERE tenant_id=? AND run_id=? AND sequence>? ORDER BY sequence ASC LIMIT ?",
            (tenant_id, run_id, sequence, limit + 1),
        ).fetchall()
        items = [
            {
                "sequence": row["sequence"],
                "event_id": row["event_id"],
                **json.loads(row["metadata_json"]),
            }
            for row in rows[:limit]
        ]
        return _page(items, rows, limit)

    def list_findings(
        self, tenant_id: str, run_id: str, cursor_token: str | None, limit: int
    ) -> dict[str, object]:
        self.get_run(tenant_id, run_id)
        after = _cursor_text(cursor_token)
        rows = self._connection.execute(
            "SELECT finding_id, revision_sha, metadata_json FROM finding_occurrences WHERE tenant_id=? AND run_id=? AND finding_id>? ORDER BY finding_id ASC LIMIT ?",
            (tenant_id, run_id, after, limit + 1),
        ).fetchall()
        items = [
            {
                "finding_id": row["finding_id"],
                "revision_sha": row["revision_sha"],
                **json.loads(row["metadata_json"]),
            }
            for row in rows[:limit]
        ]
        return _page(items, rows, limit, text=True)

    def list_artifacts(self, tenant_id: str, run_id: str) -> dict[str, object]:
        self.get_run(tenant_id, run_id)
        rows = self._connection.execute(
            """SELECT a.content_sha256, a.purpose, a.committed_at,
                      z.content_id, z.size_bytes, z.data_class
               FROM run_artifacts AS a
               JOIN artifact_upload_authorizations AS z
                 ON z.tenant_id=a.tenant_id
                AND z.authorization_id=a.authorization_id
               WHERE a.tenant_id=? AND a.run_id=?
               ORDER BY a.purpose, a.content_sha256""",
            (tenant_id, run_id),
        ).fetchall()
        return {
            "items": [
                {
                    "content_id": row["content_id"],
                    "content_sha256": row["content_sha256"],
                    "purpose": row["purpose"],
                    "size_bytes": row["size_bytes"],
                    "data_class": row["data_class"],
                    "committed_at": row["committed_at"],
                }
                for row in rows
            ],
            "next_cursor": None,
        }

    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, object]:
        row = self._connection.execute(
            """SELECT o.finding_id, o.run_id, o.revision_sha, o.metadata_json
               FROM finding_occurrences AS o
               JOIN audit_runs AS r
                 ON r.tenant_id=o.tenant_id AND r.run_id=o.run_id
               WHERE o.tenant_id=? AND o.finding_id=?
               ORDER BY r.created_at DESC, o.run_id DESC LIMIT 1""",
            (tenant_id, finding_id),
        ).fetchone()
        if row is None:
            raise NotFoundError()
        return {
            "finding_id": row["finding_id"],
            "run_id": row["run_id"],
            "revision_sha": row["revision_sha"],
            **json.loads(row["metadata_json"]),
        }

    def decide_finding(
        self,
        *,
        tenant_id: str,
        run_id: str,
        finding_id: str,
        revision_sha: str,
        decision_type: str,
        metadata: dict[str, object],
        idempotency_key: str,
        request_sha256: str,
        authorized_repository_ids: frozenset[str] | None,
    ) -> StoredResponse:
        _validate_sha(revision_sha)
        if (
            not isinstance(run_id, str)
            or not run_id
            or (
                authorized_repository_ids is not None
                and (
                    not isinstance(authorized_repository_ids, frozenset)
                    or not all(
                        isinstance(repository_id, str) and repository_id
                        for repository_id in authorized_repository_ids
                    )
                )
            )
        ):
            raise ConflictError()
        if decision_type not in {"approve", "reject", "escalate", "waive"}:
            raise ConflictError()
        with self.transaction() as cursor:
            finding = cursor.execute(
                """SELECT o.revision_sha, r.repository_id
                   FROM finding_occurrences AS o
                   JOIN audit_runs AS r
                      ON r.tenant_id=o.tenant_id AND r.run_id=o.run_id
                    WHERE o.tenant_id=? AND o.run_id=? AND o.finding_id=?""",
                (tenant_id, run_id, finding_id),
            ).fetchone()
            if finding is None:
                raise NotFoundError()
            if finding["revision_sha"] != revision_sha:
                raise PreconditionError()
            if (
                authorized_repository_ids is not None
                and finding["repository_id"] not in authorized_repository_ids
            ):
                raise NotFoundError()
            route = f"/api/v1/findings/{finding_id}/decisions"
            replay = _idempotency(cursor, tenant_id, idempotency_key, "POST", route, request_sha256)
            if replay is not None:
                return replay
            decision_id = hashlib.sha256(
                (idempotency_key + finding_id).encode("utf-8")
            ).hexdigest()[:32]
            cursor.execute(
                """INSERT INTO finding_decisions
                   (tenant_id, run_id, finding_id, decision_id, revision_sha,
                    decision_type, metadata_json, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    tenant_id,
                    run_id,
                    finding_id,
                    decision_id,
                    revision_sha,
                    decision_type,
                    _canonical(metadata),
                    _now(),
                ),
            )
            response = StoredResponse(
                201,
                {
                    "decision_id": decision_id,
                    "run_id": run_id,
                    "finding_id": finding_id,
                    "revision_sha": revision_sha,
                    "decision_type": decision_type,
                },
            )
            _store_idempotency(
                cursor, tenant_id, idempotency_key, "POST", route, request_sha256, response
            )
            return response

    def list_policies(self, tenant_id: str) -> dict[str, object]:
        rows = self._connection.execute(
            "SELECT policy_id, policy_version, content_sha256 FROM policy_versions WHERE tenant_id=? ORDER BY policy_id, policy_version",
            (tenant_id,),
        ).fetchall()
        return {
            "items": [
                {"policy_id": row[0], "policy_version": row[1], "content_sha256": row[2]}
                for row in rows
            ],
            "next_cursor": None,
        }


def _idempotency(
    cursor: sqlite3.Cursor, tenant: str, key: str, method: str, route: str, digest: str
) -> StoredResponse | None:
    row = cursor.execute(
        "SELECT method, route, request_sha256, response_status, response_json FROM idempotency_records WHERE tenant_id=? AND idempotency_key=?",
        (tenant, key),
    ).fetchone()
    if row is None:
        return None
    if (row["method"], row["route"], row["request_sha256"]) != (method, route, digest):
        raise ConflictError()
    return StoredResponse(row["response_status"], json.loads(row["response_json"]))


def _store_idempotency(
    cursor: sqlite3.Cursor,
    tenant: str,
    key: str,
    method: str,
    route: str,
    digest: str,
    response: StoredResponse,
) -> None:
    cursor.execute(
        "INSERT INTO idempotency_records VALUES (?, ?, ?, ?, ?, ?, ?)",
        (tenant, key, method, route, digest, response.status, _canonical(response.document)),
    )


def _run_projection(
    tenant: str,
    run_id: str,
    repository: str,
    identity: str,
    base: str | None,
    head: str,
    state: str,
    version: int,
) -> dict[str, object]:
    return {
        "tenant_id": tenant,
        "run_id": run_id,
        "repository_id": repository,
        "execution_identity_hash": identity,
        "base_sha": base,
        "head_sha": head,
        "state": state,
        "version": version,
    }


def _page(
    items: list[dict[str, object]],
    rows: list[sqlite3.Row],
    limit: int,
    *,
    text: bool = False,
    cursor_column: str = "finding_id",
) -> dict[str, object]:
    next_cursor = None
    if len(rows) > limit:
        value = str(rows[limit - 1][cursor_column if text else "sequence"])
        next_cursor = _encode_cursor(value)
    return {"items": items, "next_cursor": next_cursor}


def _encode_cursor(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("ascii")).decode("ascii").rstrip("=")


def _cursor_value(value: str | None) -> int:
    decoded = _cursor_text(value)
    return int(decoded) if decoded.isdigit() else 0


def _cursor_text(value: str | None) -> str:
    if value is None:
        return ""
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).decode("ascii")
    except (UnicodeDecodeError, ValueError):
        raise ConflictError() from None


def _canonical(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    )


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _validate_hash(value: str) -> None:
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ConflictError()


def _validate_sha(value: str) -> None:
    if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
        raise ConflictError()


def _database_path(connection: sqlite3.Connection) -> str:
    row = connection.execute("PRAGMA database_list").fetchone()
    if row is None:
        return ""
    return str(row[2])
