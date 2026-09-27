"""Strict SQLite migration from global governance IDs to tenant-scoped keys."""

from __future__ import annotations

import sqlite3
from typing import Final

_LEGACY_COLUMNS: Final = {
    "approval_requests": (
        "approval_id",
        "tenant_id",
        "repository_id",
        "run_id",
        "finding_id",
        "execution_identity_hash",
        "requester_id",
        "expires_at",
        "version",
        "state",
    ),
    "approval_decisions": (
        "approval_id",
        "version",
        "state",
        "actor_id",
        "reason_code",
        "rationale_sha256",
        "created_at",
    ),
    "approval_idempotency": (
        "tenant_id",
        "idempotency_key",
        "operation",
        "request_sha256",
        "approval_id",
        "result_version",
    ),
    "lifecycle_deletions": (
        "deletion_id",
        "tenant_id",
        "content_sha256",
        "data_class",
        "identity_hash",
        "requested_by",
        "version",
        "approved_by",
        "executed",
        "legal_hold",
        "created_at",
        "approved_at",
        "executed_at",
        "hold_actor",
        "hold_reason_sha256",
    ),
    "lifecycle_idempotency": (
        "tenant_id",
        "idempotency_key",
        "operation",
        "request_sha256",
        "deletion_id",
        "resulting_version",
    ),
    "lifecycle_repository_scopes": ("deletion_id", "tenant_id", "repository_id"),
}
_COMPOSITE_COLUMNS: Final = {
    **_LEGACY_COLUMNS,
    "approval_requests": (
        "approval_id",
        "tenant_id",
        "repository_id",
        "run_id",
        "finding_id",
        "finding_fingerprint",
        "revision_sha",
        "patch_sha256",
        "validation_result_sha256",
        "manifest_sha256",
        "patch_status_sha256",
        "execution_identity_hash",
        "requester_id",
        "expires_at",
        "version",
        "state",
    ),
    "approval_decisions": (
        "approval_id",
        "tenant_id",
        "version",
        "state",
        "actor_id",
        "reason_code",
        "rationale_sha256",
        "created_at",
    ),
}
_LEGACY_PRIMARY_KEYS: Final = {
    "approval_requests": ("approval_id",),
    "approval_decisions": ("approval_id", "version"),
    "approval_idempotency": ("tenant_id", "idempotency_key"),
    "lifecycle_deletions": ("deletion_id",),
    "lifecycle_idempotency": ("tenant_id", "idempotency_key"),
    "lifecycle_repository_scopes": ("deletion_id",),
}
_LEGACY_FOREIGN_KEYS: Final = {
    "approval_requests": frozenset(),
    "approval_decisions": frozenset({("approval_requests", (("approval_id", "approval_id"),))}),
    "approval_idempotency": frozenset(),
    "lifecycle_deletions": frozenset(),
    "lifecycle_idempotency": frozenset(
        {("lifecycle_deletions", (("deletion_id", "deletion_id"),))}
    ),
    "lifecycle_repository_scopes": frozenset(),
}

_NEW_TABLES: Final = (
    """CREATE TABLE approval_requests_new (
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
    """CREATE TABLE approval_decisions_new (
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
            REFERENCES approval_requests_new (tenant_id, approval_id)
    )""",
    """CREATE TABLE approval_idempotency_new (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        approval_id TEXT NOT NULL,
        result_version INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, approval_id)
            REFERENCES approval_requests_new (tenant_id, approval_id)
    )""",
    """CREATE TABLE lifecycle_deletions_new (
        deletion_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        data_class TEXT NOT NULL,
        identity_hash TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        version INTEGER NOT NULL,
        approved_by TEXT,
        executed INTEGER NOT NULL,
        legal_hold INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        approved_at TEXT,
        executed_at TEXT,
        hold_actor TEXT,
        hold_reason_sha256 TEXT,
        PRIMARY KEY (tenant_id, deletion_id),
        UNIQUE (tenant_id, content_sha256, identity_hash)
    )""",
    """CREATE TABLE lifecycle_idempotency_new (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        deletion_id TEXT NOT NULL,
        resulting_version INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, deletion_id)
            REFERENCES lifecycle_deletions_new (tenant_id, deletion_id)
    )""",
    """CREATE TABLE lifecycle_repository_scopes_new (
        deletion_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        PRIMARY KEY (tenant_id, deletion_id),
        UNIQUE (tenant_id, repository_id, deletion_id),
        FOREIGN KEY (tenant_id, deletion_id)
            REFERENCES lifecycle_deletions_new (tenant_id, deletion_id)
    )""",
)


class TenantKeyMigrationError(RuntimeError):
    """The legacy governance schema cannot be migrated safely."""


def is_exact_legacy_schema(connection: sqlite3.Connection) -> bool:
    for table, expected_columns in _LEGACY_COLUMNS.items():
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        if tuple(str(row[1]) for row in rows) != expected_columns:
            return False
        primary_key = tuple(
            str(row[1]) for row in sorted(rows, key=lambda item: int(item[5])) if int(row[5])
        )
        if primary_key != _LEGACY_PRIMARY_KEYS[table]:
            return False
        if _foreign_key_groups(connection, table) != _LEGACY_FOREIGN_KEYS[table]:
            return False
    return True


def has_exact_composite_columns(connection: sqlite3.Connection) -> bool:
    return all(
        tuple(str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")) == expected
        for table, expected in _COMPOSITE_COLUMNS.items()
    )


def migrate_legacy_tenant_keys(connection: sqlite3.Connection) -> None:
    _require_no_orphans(connection)
    for statement in _NEW_TABLES:
        connection.execute(statement)
    connection.execute("INSERT INTO approval_requests_new SELECT * FROM approval_requests")
    connection.execute(
        """INSERT INTO approval_decisions_new
           SELECT d.approval_id, r.tenant_id, d.version, d.state, d.actor_id,
                  d.reason_code, d.rationale_sha256, d.created_at
           FROM approval_decisions AS d
           JOIN approval_requests AS r ON r.approval_id=d.approval_id"""
    )
    connection.execute(
        """INSERT INTO approval_idempotency_new
           SELECT i.* FROM approval_idempotency AS i
           JOIN approval_requests AS r
             ON r.tenant_id=i.tenant_id AND r.approval_id=i.approval_id"""
    )
    connection.execute("INSERT INTO lifecycle_deletions_new SELECT * FROM lifecycle_deletions")
    connection.execute(
        """INSERT INTO lifecycle_idempotency_new
           SELECT i.* FROM lifecycle_idempotency AS i
           JOIN lifecycle_deletions AS d
             ON d.tenant_id=i.tenant_id AND d.deletion_id=i.deletion_id"""
    )
    connection.execute(
        """INSERT INTO lifecycle_repository_scopes_new
           SELECT s.* FROM lifecycle_repository_scopes AS s
           JOIN lifecycle_deletions AS d
             ON d.tenant_id=s.tenant_id AND d.deletion_id=s.deletion_id"""
    )
    for table in (
        "approval_decisions",
        "approval_idempotency",
        "approval_requests",
        "lifecycle_idempotency",
        "lifecycle_repository_scopes",
        "lifecycle_deletions",
    ):
        connection.execute(f"DROP TABLE {table}")
    for source, target in (
        ("approval_requests_new", "approval_requests"),
        ("approval_decisions_new", "approval_decisions"),
        ("approval_idempotency_new", "approval_idempotency"),
        ("lifecycle_deletions_new", "lifecycle_deletions"),
        ("lifecycle_idempotency_new", "lifecycle_idempotency"),
        ("lifecycle_repository_scopes_new", "lifecycle_repository_scopes"),
    ):
        connection.execute(f"ALTER TABLE {source} RENAME TO {target}")
    connection.execute(
        """CREATE INDEX approval_requests_tenant_run
           ON approval_requests (tenant_id, run_id, approval_id)"""
    )
    connection.execute(
        """CREATE INDEX lifecycle_deletions_tenant_idx
           ON lifecycle_deletions (tenant_id, executed, legal_hold)"""
    )


def _require_no_orphans(connection: sqlite3.Connection) -> None:
    checks = (
        """SELECT 1 FROM approval_decisions AS d LEFT JOIN approval_requests AS r
           ON r.approval_id=d.approval_id WHERE r.approval_id IS NULL LIMIT 1""",
        """SELECT 1 FROM approval_idempotency AS i LEFT JOIN approval_requests AS r
           ON r.tenant_id=i.tenant_id AND r.approval_id=i.approval_id
           WHERE r.approval_id IS NULL LIMIT 1""",
        """SELECT 1 FROM lifecycle_idempotency AS i LEFT JOIN lifecycle_deletions AS d
           ON d.tenant_id=i.tenant_id AND d.deletion_id=i.deletion_id
           WHERE d.deletion_id IS NULL LIMIT 1""",
        """SELECT 1 FROM lifecycle_repository_scopes AS s
           LEFT JOIN lifecycle_deletions AS d
             ON d.tenant_id=s.tenant_id AND d.deletion_id=s.deletion_id
           WHERE d.deletion_id IS NULL LIMIT 1""",
    )
    if any(connection.execute(statement).fetchone() is not None for statement in checks):
        raise TenantKeyMigrationError("legacy tenant-key data contains orphan rows")


def _foreign_key_groups(
    connection: sqlite3.Connection,
    table: str,
) -> frozenset[tuple[str, tuple[tuple[str, str], ...]]]:
    groups: dict[int, tuple[str, list[tuple[int, str, str]]]] = {}
    for row in connection.execute(f"PRAGMA foreign_key_list({table})").fetchall():
        identifier = int(row[0])
        target = str(row[2])
        group = groups.setdefault(identifier, (target, []))
        group[1].append((int(row[1]), str(row[3]), str(row[4])))
    return frozenset(
        (target, tuple((source, destination) for _, source, destination in sorted(columns)))
        for target, columns in groups.values()
    )


__all__ = [
    "TenantKeyMigrationError",
    "has_exact_composite_columns",
    "is_exact_legacy_schema",
    "migrate_legacy_tenant_keys",
]
