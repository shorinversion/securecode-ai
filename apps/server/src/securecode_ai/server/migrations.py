"""DB-API schema definitions shared by SQLite development and PostgreSQL deployments."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from typing import Protocol

from .approvals import APPROVAL_SCHEMA_STATEMENTS
from .assurance_repository import ASSURANCE_SCHEMA_STATEMENTS
from .audit_log import AUDIT_LOG_SCHEMA_STATEMENTS
from .backup_repository import BACKUP_SCHEMA_STATEMENTS
from .data_lifecycle_models import LIFECYCLE_SCHEMA
from .evidence_egress import EGRESS_SCHEMA_STATEMENTS
from .feedback_repository import FEEDBACK_SCHEMA_STATEMENTS
from .lifecycle_scheduler import LIFECYCLE_SCHEDULER_SCHEMA_STATEMENTS
from .operations_handler_backup import BACKUP_SCOPE_SCHEMA_STATEMENTS
from .operations_handler_governance import LIFECYCLE_SCOPE_SCHEMA_STATEMENTS
from .operations_handler_secrets import SECRET_GRANT_SCOPE_SCHEMA_STATEMENTS
from .policy_store import POLICY_STORE_SCHEMA_STATEMENTS
from .retention_planner import RETENTION_PLANNER_SCHEMA_STATEMENTS
from .run_admission_store import RUN_ADMISSION_SCHEMA_STATEMENTS
from .scm_publication_store import SCM_PUBLICATION_SCHEMA_STATEMENTS
from .scm_state_schema import SCM_STATE_SCHEMA_STATEMENTS
from .secret_service import SECRET_SCHEMA_STATEMENTS
from .storage_executor import STORAGE_TOMBSTONE_SCHEMA_STATEMENTS
from .tenant_key_migration import (
    TenantKeyMigrationError,
    has_exact_composite_columns,
    is_exact_legacy_schema,
    migrate_legacy_tenant_keys,
)
from .waivers import WAIVER_SCHEMA_STATEMENTS

SCHEMA_VERSION = "1.3.0"
_OCCURRENCE_SCHEMA_VERSION = "1.2.0"
_TENANT_KEY_SCHEMA_VERSION = "1.1.0"
_LEGACY_SCHEMA_VERSION = "1.0.0"

_TENANT_PRIMARY_KEYS = {
    "approval_requests": ("tenant_id", "approval_id"),
    "approval_decisions": ("tenant_id", "approval_id", "version"),
    "approval_idempotency": ("tenant_id", "idempotency_key"),
    "lifecycle_deletions": ("tenant_id", "deletion_id"),
    "lifecycle_idempotency": ("tenant_id", "idempotency_key"),
    "lifecycle_repository_scopes": ("tenant_id", "deletion_id"),
    "finding_occurrences": ("tenant_id", "run_id", "finding_id"),
    "finding_decisions": ("tenant_id", "finding_id", "decision_id"),
}
_TENANT_FOREIGN_KEYS = {
    "approval_decisions": (
        "approval_requests",
        (("tenant_id", "tenant_id"), ("approval_id", "approval_id")),
    ),
    "approval_idempotency": (
        "approval_requests",
        (("tenant_id", "tenant_id"), ("approval_id", "approval_id")),
    ),
    "lifecycle_idempotency": (
        "lifecycle_deletions",
        (("tenant_id", "tenant_id"), ("deletion_id", "deletion_id")),
    ),
    "lifecycle_repository_scopes": (
        "lifecycle_deletions",
        (("tenant_id", "tenant_id"), ("deletion_id", "deletion_id")),
    ),
    "finding_occurrences": (
        "audit_runs",
        (("tenant_id", "tenant_id"), ("run_id", "run_id")),
    ),
    "finding_decisions": (
        "finding_occurrences",
        (
            ("tenant_id", "tenant_id"),
            ("run_id", "run_id"),
            ("finding_id", "finding_id"),
            ("revision_sha", "revision_sha"),
        ),
    ),
}


class SchemaVersionError(RuntimeError):
    """The database cannot be used by this exact application schema."""


class SchemaCursor(Protocol):
    def execute(self, statement: str) -> object: ...

    def close(self) -> None: ...


class SchemaConnection(Protocol):
    def cursor(self) -> SchemaCursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...


_STATEMENTS = (
    """CREATE TABLE IF NOT EXISTS schema_metadata (
        singleton INTEGER NOT NULL PRIMARY KEY CHECK (singleton = 1),
        schema_version TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS scm_repositories (
        tenant_id TEXT NOT NULL, repository_id TEXT NOT NULL,
        created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, repository_id)
    )""",
    """CREATE TABLE IF NOT EXISTS audit_runs (
        tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, repository_id TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL, base_sha TEXT, head_sha TEXT NOT NULL,
        state TEXT NOT NULL, version INTEGER NOT NULL, metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, run_id),
        UNIQUE (tenant_id, repository_id, execution_identity_hash)
    )""",
    """CREATE TABLE IF NOT EXISTS findings (
        tenant_id TEXT NOT NULL, finding_id TEXT NOT NULL, run_id TEXT NOT NULL,
        revision_sha TEXT NOT NULL, metadata_json TEXT NOT NULL,
        PRIMARY KEY (tenant_id, finding_id),
        FOREIGN KEY (tenant_id, run_id) REFERENCES audit_runs (tenant_id, run_id)
    )""",
    """CREATE TABLE IF NOT EXISTS finding_occurrences (
        tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, finding_id TEXT NOT NULL,
        revision_sha TEXT NOT NULL, metadata_json TEXT NOT NULL,
        PRIMARY KEY (tenant_id, run_id, finding_id),
        FOREIGN KEY (tenant_id, run_id) REFERENCES audit_runs (tenant_id, run_id)
    )""",
    """CREATE UNIQUE INDEX IF NOT EXISTS finding_occurrences_revision_uq
       ON finding_occurrences (tenant_id, run_id, finding_id, revision_sha)""",
    """CREATE TABLE IF NOT EXISTS run_events (
        tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, sequence INTEGER NOT NULL,
        event_id TEXT NOT NULL, metadata_json TEXT NOT NULL,
        PRIMARY KEY (tenant_id, run_id, sequence), UNIQUE (tenant_id, run_id, event_id)
    )""",
    """CREATE TABLE IF NOT EXISTS finding_decisions (
        tenant_id TEXT NOT NULL, run_id TEXT NOT NULL,
        finding_id TEXT NOT NULL, decision_id TEXT NOT NULL,
        revision_sha TEXT NOT NULL, decision_type TEXT NOT NULL, metadata_json TEXT NOT NULL,
        created_at TEXT NOT NULL, PRIMARY KEY (tenant_id, finding_id, decision_id),
        FOREIGN KEY (tenant_id, run_id, finding_id, revision_sha)
            REFERENCES finding_occurrences
                (tenant_id, run_id, finding_id, revision_sha)
    )""",
    """CREATE TABLE IF NOT EXISTS idempotency_records (
        tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, method TEXT NOT NULL,
        route TEXT NOT NULL, request_sha256 TEXT NOT NULL, response_status INTEGER NOT NULL,
        response_json TEXT NOT NULL, PRIMARY KEY (tenant_id, idempotency_key)
    )""",
    """CREATE TABLE IF NOT EXISTS policy_versions (
        tenant_id TEXT NOT NULL, policy_id TEXT NOT NULL, policy_version TEXT NOT NULL,
        content_sha256 TEXT NOT NULL, PRIMARY KEY (tenant_id, policy_id, policy_version)
    )""",
    """CREATE TABLE IF NOT EXISTS worker_sessions (
        tenant_id TEXT NOT NULL, session_id TEXT NOT NULL, run_id TEXT NOT NULL,
        worker_id TEXT NOT NULL, execution_identity_hash TEXT NOT NULL,
        version INTEGER NOT NULL, terminal INTEGER NOT NULL, command TEXT NOT NULL,
        outcome TEXT, PRIMARY KEY (tenant_id, session_id),
        UNIQUE (tenant_id, run_id),
        FOREIGN KEY (tenant_id, run_id) REFERENCES audit_runs (tenant_id, run_id)
    )""",
    """CREATE TABLE IF NOT EXISTS worker_session_idempotency (
        tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
        request_sha256 TEXT NOT NULL, session_id TEXT NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, session_id) REFERENCES worker_sessions (tenant_id, session_id)
    )""",
    """CREATE TABLE IF NOT EXISTS worker_session_events (
        tenant_id TEXT NOT NULL, session_id TEXT NOT NULL, sequence INTEGER NOT NULL,
        event_id TEXT NOT NULL, event_hash TEXT NOT NULL, kind TEXT NOT NULL,
        PRIMARY KEY (tenant_id, session_id, sequence),
        UNIQUE (tenant_id, session_id, event_id),
        FOREIGN KEY (tenant_id, session_id) REFERENCES worker_sessions (tenant_id, session_id)
    )""",
    """CREATE TABLE IF NOT EXISTS worker_session_artifacts (
        tenant_id TEXT NOT NULL, session_id TEXT NOT NULL, content_sha256 TEXT NOT NULL,
        PRIMARY KEY (tenant_id, session_id, content_sha256),
        FOREIGN KEY (tenant_id, session_id) REFERENCES worker_sessions (tenant_id, session_id)
    )""",
    """CREATE TABLE IF NOT EXISTS http_idempotency_records (
        tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
        request_sha256 TEXT NOT NULL, response_status INTEGER,
        response_json TEXT, response_headers_json TEXT, claimed_at_ms BIGINT,
        PRIMARY KEY (tenant_id, idempotency_key)
    )""",
    """CREATE TABLE IF NOT EXISTS worker_run_queue (
        tenant_id TEXT NOT NULL, run_id TEXT NOT NULL,
        execution_identity_json TEXT NOT NULL, lease_owner TEXT,
        lease_expires_at TEXT, session_id TEXT, version INTEGER NOT NULL,
        terminal INTEGER NOT NULL, outcome TEXT,
        PRIMARY KEY (tenant_id, run_id),
        UNIQUE (tenant_id, session_id),
        FOREIGN KEY (tenant_id, run_id) REFERENCES audit_runs (tenant_id, run_id)
    )""",
    """CREATE TABLE IF NOT EXISTS worker_queue_idempotency (
        tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
        request_sha256 TEXT NOT NULL, response_json TEXT NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key)
    )""",
    """CREATE TABLE IF NOT EXISTS artifact_upload_authorizations (
        tenant_id TEXT NOT NULL, authorization_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL, request_sha256 TEXT NOT NULL,
        worker_id TEXT NOT NULL, repository_id TEXT NOT NULL,
        run_id TEXT NOT NULL, execution_identity_hash TEXT NOT NULL,
        content_id TEXT NOT NULL, content_sha256 TEXT NOT NULL,
        size_bytes INTEGER NOT NULL, data_class TEXT NOT NULL,
        purpose TEXT NOT NULL, method TEXT NOT NULL, upload_url TEXT NOT NULL,
        headers_json TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL,
        signer_key_id TEXT NOT NULL, receipt_signature TEXT NOT NULL,
        PRIMARY KEY (tenant_id, authorization_id),
        UNIQUE (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, run_id) REFERENCES audit_runs (tenant_id, run_id)
    )""",
    """CREATE TABLE IF NOT EXISTS run_artifacts (
        tenant_id TEXT NOT NULL, run_id TEXT NOT NULL,
        content_sha256 TEXT NOT NULL, authorization_id TEXT NOT NULL,
        purpose TEXT NOT NULL, metadata_json TEXT NOT NULL,
        committed_at TEXT NOT NULL,
        PRIMARY KEY (tenant_id, run_id, content_sha256, purpose),
        UNIQUE (tenant_id, authorization_id),
        FOREIGN KEY (tenant_id, run_id) REFERENCES audit_runs (tenant_id, run_id),
        FOREIGN KEY (tenant_id, authorization_id)
            REFERENCES artifact_upload_authorizations (tenant_id, authorization_id)
    )""",
) + (
    RUN_ADMISSION_SCHEMA_STATEMENTS
    + SCM_STATE_SCHEMA_STATEMENTS
    + SCM_PUBLICATION_SCHEMA_STATEMENTS
    + ASSURANCE_SCHEMA_STATEMENTS
    + FEEDBACK_SCHEMA_STATEMENTS
    + LIFECYCLE_SCHEMA
    + LIFECYCLE_SCOPE_SCHEMA_STATEMENTS
    + STORAGE_TOMBSTONE_SCHEMA_STATEMENTS
    + RETENTION_PLANNER_SCHEMA_STATEMENTS
    + LIFECYCLE_SCHEDULER_SCHEMA_STATEMENTS
    + SECRET_SCHEMA_STATEMENTS
    + SECRET_GRANT_SCOPE_SCHEMA_STATEMENTS
    + BACKUP_SCHEMA_STATEMENTS
    + BACKUP_SCOPE_SCHEMA_STATEMENTS
    + APPROVAL_SCHEMA_STATEMENTS
    + WAIVER_SCHEMA_STATEMENTS
    + POLICY_STORE_SCHEMA_STATEMENTS
    + AUDIT_LOG_SCHEMA_STATEMENTS
    + EGRESS_SCHEMA_STATEMENTS
)


def schema_statements() -> tuple[str, ...]:
    return _STATEMENTS


def apply_schema(connection: SchemaConnection) -> None:
    if isinstance(connection, sqlite3.Connection):
        _apply_sqlite_schema(connection)
        return
    raise SchemaVersionError("non-SQLite schema upgrades require an external migration runner")


def require_schema_version(connection: sqlite3.Connection) -> None:
    """Fail unless the connection records exactly the supported schema version."""

    _require_recorded_version(connection)
    if not _expected_objects().issubset(_application_objects(connection)):
        raise SchemaVersionError("database schema is incomplete")
    _require_tenant_key_shapes(connection)
    _require_tenant_columns(connection)
    _require_sqlite_integrity(connection)


def postgres_schema_statements() -> Iterable[str]:
    """Return fresh-schema DDL; existing PostgreSQL databases require an external migration."""

    return (
        *_STATEMENTS,
        """ALTER TABLE http_idempotency_records
           ADD COLUMN IF NOT EXISTS claimed_at_ms BIGINT""",
    )


def _migrate_sqlite_http_idempotency(connection: sqlite3.Connection) -> None:
    columns = {
        str(row[1])
        for row in connection.execute("PRAGMA table_info(http_idempotency_records)").fetchall()
    }
    if "claimed_at_ms" not in columns:
        connection.execute("ALTER TABLE http_idempotency_records ADD COLUMN claimed_at_ms INTEGER")


def _apply_sqlite_schema(connection: sqlite3.Connection) -> None:
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA legacy_alter_table = OFF")
        if connection.execute("PRAGMA foreign_keys").fetchone()[0] != 1:
            raise SchemaVersionError("SQLite foreign key enforcement is unavailable")
        connection.execute("BEGIN IMMEDIATE")
        existing = _application_objects(connection)
        expected = _expected_objects()
        occurrence = ("table", "finding_occurrences")
        occurrence_index = ("index", "finding_occurrences_revision_uq")
        pre_occurrence = expected - {occurrence, occurrence_index}
        metadata = ("table", "schema_metadata")
        update_metadata = False
        insert_metadata = False
        if not existing:
            for statement in _STATEMENTS:
                connection.execute(statement)
            insert_metadata = True
        elif metadata not in existing:
            if existing != pre_occurrence - {metadata} or not is_exact_legacy_schema(connection):
                raise SchemaVersionError("unversioned database schema is incompatible")
            connection.execute(_STATEMENTS[0])
            _migrate_legacy_tenant_keys(connection)
            _migrate_finding_occurrences(connection)
            _migrate_finding_decisions(connection)
            insert_metadata = True
        else:
            version = _recorded_version(connection)
            if version == SCHEMA_VERSION:
                if not expected.issubset(existing):
                    raise SchemaVersionError("database schema is incomplete")
                _require_tenant_key_shapes(connection)
                _require_tenant_columns(connection)
            elif version in {_LEGACY_SCHEMA_VERSION, _TENANT_KEY_SCHEMA_VERSION}:
                if not pre_occurrence.issubset(existing) or occurrence in existing:
                    raise SchemaVersionError("legacy database schema is incompatible")
                connection.execute(_STATEMENTS[4])
                if _has_base_tenant_key_shapes(connection) and has_exact_composite_columns(
                    connection
                ):
                    pass
                elif version == _LEGACY_SCHEMA_VERSION and is_exact_legacy_schema(connection):
                    _migrate_legacy_tenant_keys(connection)
                else:
                    raise SchemaVersionError("legacy database schema is incompatible")
                _migrate_finding_occurrences(connection)
                _migrate_finding_decisions(connection)
                update_metadata = True
            elif version == _OCCURRENCE_SCHEMA_VERSION:
                if not (expected - {occurrence_index}).issubset(existing):
                    raise SchemaVersionError("database schema is incomplete")
                _create_finding_occurrence_revision_index(connection)
                _migrate_finding_decisions(connection)
                update_metadata = True
            else:
                raise SchemaVersionError("database schema version is incompatible")
        _migrate_sqlite_http_idempotency(connection)
        _require_tenant_key_shapes(connection)
        _require_tenant_columns(connection)
        _require_sqlite_integrity(connection)
        if insert_metadata:
            connection.execute(
                "INSERT INTO schema_metadata (singleton, schema_version) VALUES (1, ?)",
                (SCHEMA_VERSION,),
            )
        elif update_metadata:
            changed = connection.execute(
                """UPDATE schema_metadata SET schema_version=?
                   WHERE singleton=1 AND schema_version=?""",
                (SCHEMA_VERSION, version),
            ).rowcount
            if changed != 1:
                raise SchemaVersionError("database schema version changed during migration")
        _require_recorded_version(connection)
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _application_objects(connection: sqlite3.Connection) -> frozenset[tuple[str, str]]:
    rows = connection.execute(
        """SELECT type, name FROM sqlite_master
           WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%'"""
    ).fetchall()
    if any(len(row) != 2 or type(row[0]) is not str or type(row[1]) is not str for row in rows):
        raise SchemaVersionError("database schema inventory is invalid")
    return frozenset((str(row[0]), str(row[1])) for row in rows)


def _expected_objects() -> frozenset[tuple[str, str]]:
    prefixes = {
        "CREATE TABLE IF NOT EXISTS ": "table",
        "CREATE INDEX IF NOT EXISTS ": "index",
        "CREATE UNIQUE INDEX IF NOT EXISTS ": "index",
    }
    names: set[tuple[str, str]] = set()
    for statement in _STATEMENTS:
        normalized = " ".join(statement.split())
        matched = False
        for prefix, kind in prefixes.items():
            if normalized.startswith(prefix):
                name = normalized[len(prefix) :].split(" ", 1)[0]
                item = (kind, name)
                if not name.isidentifier() or item in names:
                    raise RuntimeError("migration object declaration is invalid")
                names.add(item)
                matched = True
                break
        if not matched:
            raise RuntimeError("migration statement is unsupported")
    return frozenset(names)


def _require_recorded_version(connection: sqlite3.Connection) -> None:
    if _recorded_version(connection) != SCHEMA_VERSION:
        raise SchemaVersionError("database schema version is incompatible")


def _recorded_version(connection: sqlite3.Connection) -> str:
    try:
        raw_rows = connection.execute(
            """SELECT singleton, schema_version, typeof(schema_version)
               FROM schema_metadata ORDER BY singleton"""
        ).fetchall()
    except sqlite3.DatabaseError as error:
        raise SchemaVersionError("database schema version is unavailable") from error
    rows = [tuple(row) for row in raw_rows]
    if len(rows) != 1 or rows[0][0] != 1 or rows[0][2] != "text" or type(rows[0][1]) is not str:
        raise SchemaVersionError("database schema version is incompatible")
    return str(rows[0][1])


def _require_tenant_key_shapes(connection: sqlite3.Connection) -> None:
    for table, expected_pk in _TENANT_PRIMARY_KEYS.items():
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        primary_key = tuple(
            str(row[1]) for row in sorted(rows, key=lambda item: int(item[5])) if int(row[5]) > 0
        )
        if primary_key != expected_pk:
            raise SchemaVersionError("database tenant key is incompatible")
    for table, expected_fk in _TENANT_FOREIGN_KEYS.items():
        if expected_fk not in _foreign_key_groups(connection, table):
            raise SchemaVersionError("database tenant foreign key is incompatible")


def _has_base_tenant_key_shapes(connection: sqlite3.Connection) -> bool:
    try:
        for table, expected_pk in _TENANT_PRIMARY_KEYS.items():
            if table == "finding_decisions":
                continue
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
            primary_key = tuple(
                str(row[1])
                for row in sorted(rows, key=lambda item: int(item[5]))
                if int(row[5]) > 0
            )
            if primary_key != expected_pk:
                raise SchemaVersionError("database tenant key is incompatible")
        for table, expected_fk in _TENANT_FOREIGN_KEYS.items():
            if table == "finding_decisions":
                continue
            if expected_fk not in _foreign_key_groups(connection, table):
                raise SchemaVersionError("database tenant foreign key is incompatible")
    except SchemaVersionError:
        return False
    return True


def _require_tenant_columns(connection: sqlite3.Connection) -> None:
    if not has_exact_composite_columns(connection):
        raise SchemaVersionError("database tenant table columns are incompatible")


def _migrate_legacy_tenant_keys(connection: sqlite3.Connection) -> None:
    try:
        migrate_legacy_tenant_keys(connection)
    except TenantKeyMigrationError as error:
        raise SchemaVersionError(str(error)) from error


def _migrate_finding_occurrences(connection: sqlite3.Connection) -> None:
    connection.execute(_STATEMENTS[4])
    connection.execute(
        """INSERT INTO finding_occurrences
           (tenant_id, run_id, finding_id, revision_sha, metadata_json)
           SELECT tenant_id, run_id, finding_id, revision_sha, metadata_json FROM findings"""
    )
    _create_finding_occurrence_revision_index(connection)


def _create_finding_occurrence_revision_index(connection: sqlite3.Connection) -> None:
    connection.execute(_STATEMENTS[5])


def _migrate_finding_decisions(connection: sqlite3.Connection) -> None:
    columns = tuple(
        str(row[1]) for row in connection.execute("PRAGMA table_info(finding_decisions)")
    )
    legacy_columns = (
        "tenant_id",
        "finding_id",
        "decision_id",
        "revision_sha",
        "decision_type",
        "metadata_json",
        "created_at",
    )
    if columns != legacy_columns:
        raise SchemaVersionError("legacy finding decision schema is incompatible")
    ambiguous = connection.execute(
        """SELECT d.tenant_id, d.finding_id, d.decision_id
           FROM finding_decisions AS d
           LEFT JOIN finding_occurrences AS o
             ON o.tenant_id=d.tenant_id
            AND o.finding_id=d.finding_id
            AND o.revision_sha=d.revision_sha
           GROUP BY d.tenant_id, d.finding_id, d.decision_id
           HAVING COUNT(o.run_id) != 1
           LIMIT 1"""
    ).fetchone()
    if ambiguous is not None:
        raise SchemaVersionError("legacy finding decision occurrence is ambiguous")
    connection.execute(
        """CREATE TABLE finding_decisions_new (
            tenant_id TEXT NOT NULL, run_id TEXT NOT NULL,
            finding_id TEXT NOT NULL, decision_id TEXT NOT NULL,
            revision_sha TEXT NOT NULL, decision_type TEXT NOT NULL,
            metadata_json TEXT NOT NULL, created_at TEXT NOT NULL,
            PRIMARY KEY (tenant_id, finding_id, decision_id),
            FOREIGN KEY (tenant_id, run_id, finding_id, revision_sha)
                REFERENCES finding_occurrences
                    (tenant_id, run_id, finding_id, revision_sha)
        )"""
    )
    connection.execute(
        """INSERT INTO finding_decisions_new
           (tenant_id, run_id, finding_id, decision_id, revision_sha,
            decision_type, metadata_json, created_at)
           SELECT d.tenant_id, o.run_id, d.finding_id, d.decision_id,
                  d.revision_sha, d.decision_type, d.metadata_json, d.created_at
           FROM finding_decisions AS d
           JOIN finding_occurrences AS o
             ON o.tenant_id=d.tenant_id
            AND o.finding_id=d.finding_id
            AND o.revision_sha=d.revision_sha"""
    )
    connection.execute("DROP TABLE finding_decisions")
    connection.execute("ALTER TABLE finding_decisions_new RENAME TO finding_decisions")


def _foreign_key_groups(
    connection: sqlite3.Connection,
    table: str,
) -> frozenset[tuple[str, tuple[tuple[str, str], ...]]]:
    groups: dict[int, tuple[str, list[tuple[int, str, str]]]] = {}
    for row in connection.execute(f"PRAGMA foreign_key_list({table})").fetchall():
        identifier = int(row[0])
        target = str(row[2])
        group = groups.setdefault(identifier, (target, []))
        if group[0] != target:
            raise SchemaVersionError("database foreign key inventory is invalid")
        group[1].append((int(row[1]), str(row[3]), str(row[4])))
    return frozenset(
        (
            target,
            tuple((source, destination) for _, source, destination in sorted(columns)),
        )
        for target, columns in groups.values()
    )


def _require_sqlite_integrity(connection: sqlite3.Connection) -> None:
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    if foreign_keys is None or tuple(foreign_keys) != (1,):
        raise SchemaVersionError("database foreign key enforcement is disabled")
    if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise SchemaVersionError("database foreign key integrity failed")
    quick_check = connection.execute("PRAGMA quick_check(1)").fetchall()
    if [tuple(row) for row in quick_check] != [("ok",)]:
        raise SchemaVersionError("database integrity check failed")
