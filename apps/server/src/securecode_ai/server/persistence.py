"""Transactional source-free control-plane persistence for P6.2."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .migrations import apply_schema
from .run_projection import run_receipt_fields
from .worker_findings import parse_worker_findings
from .worker_queue_models import WorkerQueueConflict
from .worker_scm_policy import (
    ScmPolicyReceiptConflict,
    load_run_scm_policy_decision,
)


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
                    None,
                ),
            )
            _store_idempotency(
                cursor, tenant_id, idempotency_key, "POST", "/api/v1/runs", request_sha256, response
            )
            return response

    def get_run(self, tenant_id: str, run_id: str) -> dict[str, object]:
        row = self._connection.execute(
            """SELECT r.tenant_id, r.run_id, r.repository_id,
                      r.execution_identity_hash, r.base_sha, r.head_sha,
                      r.state, r.version, q.outcome
               FROM audit_runs AS r
               LEFT JOIN worker_run_queue AS q
                 ON q.tenant_id=r.tenant_id AND q.run_id=r.run_id
               WHERE r.tenant_id=? AND r.run_id=?""",
            (tenant_id, run_id),
        ).fetchone()
        if row is None:
            raise NotFoundError()
        return _run_projection(*row)

    def get_run_by_identity(
        self, tenant_id: str, repository_id: str, execution_identity_hash: str
    ) -> dict[str, object]:
        """Resolve the unique admitted run for an execution identity."""

        _validate_hash(execution_identity_hash)
        row = self._connection.execute(
            """SELECT tenant_id, run_id, repository_id, execution_identity_hash,
                      base_sha, head_sha, state, version,
                      (SELECT outcome FROM worker_run_queue AS q
                       WHERE q.tenant_id=audit_runs.tenant_id
                         AND q.run_id=audit_runs.run_id) AS outcome
               FROM audit_runs
               WHERE tenant_id=? AND repository_id=? AND execution_identity_hash=?""",
            (tenant_id, repository_id, execution_identity_hash),
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
        after = _decode_page_cursor(
            cursor_token,
            kind="runs",
            scope=(tenant_id, repository_id),
            width=1,
        )
        after_run_id = after[0] if after else ""
        rows = self._connection.execute(
            """SELECT tenant_id, run_id, repository_id, execution_identity_hash,
                      base_sha, head_sha, state, version,
                      (SELECT outcome FROM worker_run_queue AS q
                       WHERE q.tenant_id=audit_runs.tenant_id
                         AND q.run_id=audit_runs.run_id) AS outcome
               FROM audit_runs
               WHERE tenant_id=? AND repository_id=? AND run_id>?
               ORDER BY run_id ASC LIMIT ?""",
            (tenant_id, repository_id, after_run_id, limit + 1),
        ).fetchall()
        items = [_run_projection(*row) for row in rows[:limit]]
        return _page(
            items,
            rows,
            limit,
            kind="runs",
            scope=(tenant_id, repository_id),
            key=lambda row: (str(row["run_id"]),),
        )

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
        run = self.get_run(tenant_id, run_id)
        _validate_page_limit(limit)
        repository_id = _required_repository_id(run)
        after = _decode_page_cursor(
            cursor_token,
            kind="events",
            scope=(tenant_id, repository_id, run_id),
            width=1,
        )
        sequence = _event_cursor_value(after[0] if after else None)
        rows = self._connection.execute(
            "SELECT sequence, event_id, metadata_json FROM run_events WHERE tenant_id=? AND run_id=? AND sequence>? ORDER BY sequence ASC LIMIT ?",
            (tenant_id, run_id, sequence, limit + 1),
        ).fetchall()
        items: list[dict[str, object]] = []
        for row in rows[:limit]:
            if type(row["sequence"]) is not int or row["sequence"] < 1:
                raise RepositoryError()
            metadata = _metadata_document(row["metadata_json"])
            if row["event_id"] == "securecode-policy-decision-v1":
                try:
                    decision = load_run_scm_policy_decision(
                        self._connection,
                        tenant_id=tenant_id,
                        run_id=run_id,
                        execution_identity_hash=str(run["execution_identity_hash"]),
                    )
                except ScmPolicyReceiptConflict:
                    raise RepositoryError() from None
                # Compare the JSON projection: stored tuples decode as lists.
                if decision is None or metadata != json.loads(
                    json.dumps(
                        {
                            "kind": "SCM_POLICY_DECISION",
                            "policy_decision": decision.metadata(),
                        }
                    )
                ):
                    raise RepositoryError()
            else:
                _require_worker_event(
                    metadata,
                    event_id=row["event_id"],
                    run_id=run_id,
                    execution_identity_hash=str(run["execution_identity_hash"]),
                )
            items.append(
                {
                    **metadata,
                    "sequence": row["sequence"],
                    "event_id": row["event_id"],
                }
            )
        return _page(
            items,
            rows,
            limit,
            kind="events",
            scope=(tenant_id, repository_id, run_id),
            key=lambda row: (str(row["sequence"]),),
        )

    def list_findings(
        self, tenant_id: str, run_id: str, cursor_token: str | None, limit: int
    ) -> dict[str, object]:
        run = self.get_run(tenant_id, run_id)
        _validate_page_limit(limit)
        repository_id = _required_repository_id(run)
        after = _decode_page_cursor(
            cursor_token,
            kind="findings",
            scope=(tenant_id, repository_id, run_id),
            width=1,
        )
        after_finding_id = after[0] if after else ""
        rows = self._connection.execute(
            "SELECT finding_id, revision_sha, metadata_json FROM finding_occurrences WHERE tenant_id=? AND run_id=? AND finding_id>? ORDER BY finding_id ASC LIMIT ?",
            (tenant_id, run_id, after_finding_id, limit + 1),
        ).fetchall()
        items: list[dict[str, object]] = []
        for row in rows[:limit]:
            metadata = _metadata_document(row["metadata_json"])
            document = {
                **metadata,
                "finding_id": row["finding_id"],
                "revision_sha": row["revision_sha"],
            }
            try:
                parsed = parse_worker_findings(
                    [document],
                    required=True,
                    supplied=True,
                )[0]
            except (WorkerQueueConflict, TypeError, ValueError):
                raise RepositoryError() from None
            if (
                parsed.revision_sha != run["head_sha"]
                or parsed.evidence_graph_ref.tenant_id != tenant_id
            ):
                raise RepositoryError()
            items.append(parsed.document())
        return _page(
            items,
            rows,
            limit,
            kind="findings",
            scope=(tenant_id, repository_id, run_id),
            key=lambda row: (str(row["finding_id"]),),
        )

    def list_artifacts(
        self,
        tenant_id: str,
        run_id: str,
        cursor_token: str | None = None,
        limit: int = 50,
    ) -> dict[str, object]:
        run = self.get_run(tenant_id, run_id)
        _validate_page_limit(limit)
        repository_id = _required_repository_id(run)
        after = _decode_page_cursor(
            cursor_token,
            kind="artifacts",
            scope=(tenant_id, repository_id, run_id),
            width=2,
        )
        after_purpose, after_content_sha256 = after or ("", "")
        now = datetime.now(UTC)
        # Metadata validation happens after the join because the canonical
        # binding is stored as JSON.  Fetching only limit+1 raw rows before
        # filtering lets an invalid or expired row consume a page slot and
        # moves the cursor past the next visible artifact.  Scan in bounded
        # chunks and build the cursor from visible rows instead.
        scan_budget = min(1000, max(limit + 1, limit * 4))
        visible_rows: list[sqlite3.Row] = []
        scan_after = (after_purpose, after_content_sha256)
        scanned = 0
        exhausted = False
        while scanned < scan_budget and len(visible_rows) <= limit:
            batch_limit = min(limit + 1, scan_budget - scanned)
            rows = self._connection.execute(
                """SELECT a.authorization_id, a.content_sha256, a.purpose, a.committed_at,
                          a.metadata_json, z.content_id, z.size_bytes, z.data_class
                   FROM run_artifacts AS a
                   JOIN artifact_upload_authorizations AS z
                      ON z.tenant_id=a.tenant_id
                     AND z.authorization_id=a.authorization_id
                    AND z.run_id=a.run_id
                    AND z.content_sha256=a.content_sha256
                    AND z.purpose=a.purpose
                   WHERE a.tenant_id=? AND a.run_id=?
                   AND z.data_class IN ('DC0_PUBLIC', 'DC1_INTERNAL_METADATA',
                                        'DC2_CONFIDENTIAL_SECURITY')
                   AND NOT EXISTS (
                       SELECT 1 FROM lifecycle_storage_tombstones AS t
                       WHERE t.tenant_id=a.tenant_id
                         AND t.content_sha256=a.content_sha256
                   )
                   AND (a.purpose > ? OR
                        (a.purpose = ? AND a.content_sha256 > ?))
                   ORDER BY a.purpose ASC, a.content_sha256 ASC
                   LIMIT ?""",
                (tenant_id, run_id, scan_after[0], scan_after[0], scan_after[1], batch_limit),
            ).fetchall()
            if not rows:
                exhausted = True
                break
            scanned += len(rows)
            for row in rows:
                scan_after = (str(row["purpose"]), str(row["content_sha256"]))
                if _artifact_listing_metadata_is_visible(row, now=now):
                    visible_rows.append(row)
                if len(visible_rows) > limit:
                    break
            if len(visible_rows) > limit:
                break
            if len(rows) < batch_limit:
                exhausted = True
                break

        rows = visible_rows
        items = [
            {
                "content_id": row["content_id"],
                "content_sha256": row["content_sha256"],
                "purpose": row["purpose"],
                "size_bytes": row["size_bytes"],
                "data_class": row["data_class"],
                "committed_at": row["committed_at"],
            }
            for row in rows[:limit]
        ]
        next_cursor = None
        if len(rows) > limit:
            next_cursor = _encode_page_cursor(
                "artifacts",
                (tenant_id, repository_id, run_id),
                (str(rows[limit - 1]["purpose"]), str(rows[limit - 1]["content_sha256"])),
            )
        elif not exhausted and scanned >= scan_budget:
            next_cursor = _encode_page_cursor(
                "artifacts",
                (tenant_id, repository_id, run_id),
                scan_after,
            )
        return {"items": items, "next_cursor": next_cursor}

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
            **_metadata_document(row["metadata_json"]),
            "finding_id": row["finding_id"],
            "run_id": row["run_id"],
            "revision_sha": row["revision_sha"],
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
            if (
                authorized_repository_ids is not None
                and finding["repository_id"] not in authorized_repository_ids
            ):
                raise NotFoundError()
            route = f"/api/v1/findings/{finding_id}/decisions"
            replay = _idempotency(cursor, tenant_id, idempotency_key, "POST", route, request_sha256)
            if replay is not None:
                return replay
            if finding["revision_sha"] != revision_sha:
                raise PreconditionError()
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
    outcome: str | None,
) -> dict[str, object]:
    projection: dict[str, object] = {
        "tenant_id": tenant,
        "run_id": run_id,
        "repository_id": repository,
        "execution_identity_hash": identity,
        "base_sha": base,
        "head_sha": head,
        "state": state,
        "version": version,
        "outcome": outcome,
    }
    projection.update(run_receipt_fields(state, version))
    return projection


def _page(
    items: list[dict[str, object]],
    rows: list[sqlite3.Row],
    limit: int,
    *,
    kind: str,
    scope: tuple[str, ...],
    key: Callable[[sqlite3.Row], tuple[str, ...]],
) -> dict[str, object]:
    next_cursor = None
    if len(rows) > limit:
        next_cursor = _encode_page_cursor(kind, scope, key(rows[limit - 1]))
    return {"items": items, "next_cursor": next_cursor}


_PAGE_CURSOR_VERSION = 1
_PAGE_CURSOR_MAX_LENGTH = 512
_PAGE_CURSOR_KEYS = frozenset({"after", "kind", "scope", "v"})


def _encode_page_cursor(kind: str, scope: tuple[str, ...], after: tuple[str, ...]) -> str:
    if (
        type(kind) is not str
        or not kind
        or type(scope) is not tuple
        or not all(type(item) is str and item for item in scope)
        or type(after) is not tuple
        or not all(type(item) is str and item for item in after)
    ):
        raise ConflictError()
    payload = _canonical(
        {
            "after": list(after),
            "kind": kind,
            "scope": _page_scope_digest(kind, scope),
            "v": _PAGE_CURSOR_VERSION,
        }
    ).encode("ascii")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    if len(encoded) > _PAGE_CURSOR_MAX_LENGTH:
        raise ConflictError()
    return encoded


def _decode_page_cursor(
    value: str | None,
    *,
    kind: str,
    scope: tuple[str, ...],
    width: int,
) -> tuple[str, ...] | None:
    if value is None:
        return None
    if (
        type(value) is not str
        or not value
        or len(value) > _PAGE_CURSOR_MAX_LENGTH
        or any(not _base64url_character(character) for character in value)
    ):
        raise ConflictError()
    try:
        encoded = value + "=" * (-len(value) % 4)
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
        document = json.loads(decoded.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
        raise ConflictError() from None
    if (
        not isinstance(document, dict)
        or frozenset(document) != _PAGE_CURSOR_KEYS
        or document.get("v") != _PAGE_CURSOR_VERSION
        or document.get("kind") != kind
        or document.get("scope") != _page_scope_digest(kind, scope)
    ):
        raise ConflictError()
    raw_after = document.get("after")
    if (
        not isinstance(raw_after, list)
        or len(raw_after) != width
        or any(type(item) is not str or not item for item in raw_after)
    ):
        raise ConflictError()
    after = tuple(raw_after)
    try:
        canonical = _encode_page_cursor(kind, scope, after)
    except ConflictError:
        raise ConflictError() from None
    if canonical != value:
        raise ConflictError() from None
    return after


def _page_scope_digest(kind: str, scope: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for value in (kind, *scope):
        if type(value) is not str:
            raise ConflictError()
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _event_cursor_value(value: str | None) -> int:
    if value is None or not value.isascii() or not value.isdigit() or value.startswith("0"):
        if value is None:
            return 0
        raise ConflictError()
    try:
        result = int(value)
    except ValueError:
        raise ConflictError() from None
    if result > 9_223_372_036_854_775_807:
        raise ConflictError()
    return result


def _validate_page_limit(limit: int) -> None:
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ConflictError()


def _required_repository_id(run: dict[str, object]) -> str:
    repository_id = run.get("repository_id")
    if type(repository_id) is not str or not repository_id:
        raise RepositoryError()
    return repository_id


def _artifact_listing_metadata_is_visible(row: sqlite3.Row, *, now: datetime) -> bool:
    authorization_id = row["authorization_id"]
    content_id = row["content_id"]
    content_sha256 = row["content_sha256"]
    data_class = row["data_class"]
    purpose = row["purpose"]
    size_bytes = row["size_bytes"]
    if (
        type(authorization_id) is not str
        or not authorization_id
        or type(content_id) is not str
        or not content_id
        or type(content_sha256) is not str
        or len(content_sha256) != 64
        or any(character not in "0123456789abcdef" for character in content_sha256)
        or type(data_class) is not str
        or data_class not in {"DC0_PUBLIC", "DC1_INTERNAL_METADATA", "DC2_CONFIDENTIAL_SECURITY"}
        or type(purpose) is not str
        or purpose
        not in {
            "audit-report",
            "audit-run",
            "evidence-graph",
            "repair-report",
            "sarif-report",
        }
        or type(size_bytes) is not int
        or not 1 <= size_bytes <= 1_073_741_824
    ):
        return False
    raw = row["metadata_json"]
    if type(raw) is not str or not raw:
        return False
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object_pairs)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return False
    if type(document) is not dict:
        return False
    expected = {
        "authorization_id": authorization_id,
        "content_id": content_id,
        "content_sha256": content_sha256,
        "data_class": data_class,
        "purpose": purpose,
        "size_bytes": size_bytes,
    }
    # The durable artifact metadata must agree with the joined authorization
    # row.  A missing or altered binding is treated as corruption below.
    authorization_id = document.get("authorization_id")
    if type(authorization_id) is not str or not authorization_id:
        return False
    if any(document.get(key) != value for key, value in expected.items()):
        return False
    try:
        committed = _artifact_timestamp(row["committed_at"])
    except (TypeError, ValueError):
        return False
    keys = frozenset(document)
    required_keys = frozenset(expected)
    if keys == required_keys:
        return True
    if keys != required_keys | {"expires_at"}:
        return False
    expires_at = document.get("expires_at")
    if type(expires_at) is not str or not expires_at:
        return False
    try:
        expiry = _artifact_timestamp(expires_at)
    except (TypeError, ValueError):
        return False
    return committed < expiry and now < expiry


def _artifact_timestamp(value: object) -> datetime:
    if type(value) is not str or not value:
        raise ValueError("artifact timestamp is invalid")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("artifact timestamp is not UTC")
    return parsed.astimezone(UTC)


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate metadata field")
        value[key] = item
    return value


def _metadata_document(value: object) -> dict[str, object]:
    if type(value) is not str or not value:
        raise RepositoryError()
    try:
        document = json.loads(value, object_pairs_hook=_unique_object_pairs)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise RepositoryError() from None
    if type(document) is not dict:
        raise RepositoryError()
    return document


def _require_worker_event(
    metadata: Mapping[str, object],
    *,
    event_id: object,
    run_id: str,
    execution_identity_hash: str,
) -> None:
    if set(metadata) != {"event_hash", "kind", "worker_sequence"}:
        raise RepositoryError()
    event_hash = metadata.get("event_hash")
    kind = metadata.get("kind")
    worker_sequence = metadata.get("worker_sequence")
    if (
        type(event_hash) is not str
        or len(event_hash) != 64
        or any(character not in "0123456789abcdef" for character in event_hash)
        or kind
        not in {
            "RUN_STARTED",
            "RUN_COMPLETED",
            "RUN_CANCELLED",
            "RUN_SUPERSEDED",
            "RUN_FAILED",
        }
        or type(worker_sequence) is not int
        or not 1 <= worker_sequence <= 2_147_483_647
    ):
        raise RepositoryError()
    material = {
        "execution_identity_hash": execution_identity_hash,
        "kind": kind,
        "run_id": run_id,
        "sequence": worker_sequence,
    }
    expected_hash = hashlib.sha256(_canonical(material).encode("ascii")).hexdigest()
    if event_hash != expected_hash or event_id != f"worker-{worker_sequence}-{expected_hash[:32]}":
        raise RepositoryError()


def _base64url_character(value: str) -> bool:
    return "A" <= value <= "Z" or "a" <= value <= "z" or "0" <= value <= "9" or value in {"_", "-"}


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
