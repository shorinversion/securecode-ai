"""Bounded planning of deletion requests for expired local artifacts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from .data_lifecycle_models import (
    DeletionRequest,
    LifecycleConflict,
    RetentionProfile,
    require_identifier,
)

_SCHEMA_VERSION: Final = 1

RETENTION_PLANNER_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS lifecycle_retention_plans (
        tenant_id TEXT NOT NULL,
        content_sha256 TEXT NOT NULL,
        deletion_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL,
        profile_sha256 TEXT NOT NULL,
        eligible_at TEXT NOT NULL,
        requested_at TEXT NOT NULL,
        schema_version INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, content_sha256),
        UNIQUE (tenant_id, deletion_id)
    )""",
)


@dataclass(frozen=True, slots=True)
class PlannedArtifactDeletion:
    """Source-free result for one newly planned deletion request."""

    deletion_id: str
    tenant_id: str
    repository_id: str
    content_sha256: str
    execution_identity_hash: str
    profile_sha256: str
    eligible_at: str
    requested_at: str


@dataclass(frozen=True, slots=True)
class _ArtifactCandidate:
    tenant_id: str
    repository_id: str
    content_sha256: str
    execution_identity_hash: str
    latest_committed_at: datetime


class ArtifactRetentionPlanner:
    """Create unapproved deletion requests for expired local artifact records.

    Planning is deliberately separate from approval and execution. One bounded
    call performs only source-free SQLite work and creates the lifecycle request
    and repository scope in the same transaction.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        requested_by: str = "retention-planner",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        require_identifier(requested_by, "requested_by")
        self._db = connection
        self._db.row_factory = sqlite3.Row
        self._requested_by = requested_by
        self._clock = clock or (lambda: datetime.now(UTC))
        self._initialize_schema()

    def run_once(
        self,
        *,
        profile: RetentionProfile,
        max_items: int = 32,
    ) -> tuple[PlannedArtifactDeletion, ...]:
        if type(profile) is not RetentionProfile:
            raise TypeError("profile must be a RetentionProfile")
        if type(max_items) is not int or not 1 <= max_items <= 256:
            raise ValueError("retention batch size is invalid")
        now = _utc(self._clock())
        profile_sha256 = _profile_hash(profile)
        cutoff = now - timedelta(days=profile.artifact_days)
        candidates = self._candidates(
            tenant_id=profile.tenant_id,
            cutoff=cutoff,
            limit=max_items,
        )
        results: list[PlannedArtifactDeletion] = []
        for candidate in candidates:
            planned = self._plan_candidate(
                candidate=candidate,
                profile=profile,
                profile_sha256=profile_sha256,
                now=now,
            )
            if planned is not None:
                results.append(planned)
        return tuple(results)

    def _initialize_schema(self) -> None:
        try:
            for statement in RETENTION_PLANNER_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

    def _candidates(
        self,
        *,
        tenant_id: str,
        cutoff: datetime,
        limit: int,
    ) -> tuple[_ArtifactCandidate, ...]:
        rows = self._db.execute(
            """SELECT a.content_sha256,
                      MIN(z.repository_id) AS repository_id,
                      MIN(z.execution_identity_hash) AS execution_identity_hash,
                      MAX(a.committed_at) AS latest_committed_at,
                      COUNT(DISTINCT z.repository_id) AS repository_count,
                      COUNT(DISTINCT z.execution_identity_hash) AS identity_count
               FROM run_artifacts AS a
               JOIN artifact_upload_authorizations AS z
                 ON z.tenant_id=a.tenant_id
                AND z.authorization_id=a.authorization_id
                AND z.run_id=a.run_id
               JOIN audit_runs AS r
                 ON r.tenant_id=a.tenant_id
                AND r.run_id=a.run_id
                AND r.repository_id=z.repository_id
                AND r.execution_identity_hash=z.execution_identity_hash
               WHERE a.tenant_id=?
                 AND NOT EXISTS (
                     SELECT 1 FROM lifecycle_deletions AS d
                     WHERE d.tenant_id=a.tenant_id
                       AND d.content_sha256=a.content_sha256
                 )
                 AND NOT EXISTS (
                     SELECT 1 FROM lifecycle_retention_plans AS p
                     WHERE p.tenant_id=a.tenant_id
                       AND p.content_sha256=a.content_sha256
                 )
               GROUP BY a.content_sha256
               HAVING repository_count=1 AND identity_count=1
               ORDER BY latest_committed_at, a.content_sha256
               LIMIT ?""",
            (tenant_id, limit),
        ).fetchall()
        candidates: list[_ArtifactCandidate] = []
        for row in rows:
            latest = _parse_utc(row["latest_committed_at"])
            if latest > cutoff:
                continue
            candidates.append(
                _ArtifactCandidate(
                    tenant_id=tenant_id,
                    repository_id=str(row["repository_id"]),
                    content_sha256=str(row["content_sha256"]),
                    execution_identity_hash=str(row["execution_identity_hash"]),
                    latest_committed_at=latest,
                )
            )
        return tuple(candidates)

    def _plan_candidate(
        self,
        *,
        candidate: _ArtifactCandidate,
        profile: RetentionProfile,
        profile_sha256: str,
        now: datetime,
    ) -> PlannedArtifactDeletion | None:
        deletion_id = _deletion_id(candidate)
        request = DeletionRequest(
            deletion_id=deletion_id,
            tenant_id=candidate.tenant_id,
            content_sha256=candidate.content_sha256,
            data_class="artifact",
            identity_hash=candidate.execution_identity_hash,
            requested_by=self._requested_by,
            version=1,
        )
        cursor = self._db.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            current = self._reload_candidate(
                cursor,
                tenant_id=candidate.tenant_id,
                content_sha256=candidate.content_sha256,
            )
            if current is None:
                self._db.commit()
                return None
            current_eligible_at = current.latest_committed_at + timedelta(
                days=profile.artifact_days
            )
            if (
                current.repository_id != candidate.repository_id
                or current.execution_identity_hash != candidate.execution_identity_hash
                or current_eligible_at > now
                or self._has_existing_request(cursor, current)
            ):
                self._db.commit()
                return None
            planned = PlannedArtifactDeletion(
                deletion_id=request.deletion_id,
                tenant_id=request.tenant_id,
                repository_id=current.repository_id,
                content_sha256=request.content_sha256,
                execution_identity_hash=request.identity_hash,
                profile_sha256=profile_sha256,
                eligible_at=current_eligible_at.isoformat(),
                requested_at=now.isoformat(),
            )
            self._insert_request(cursor, request, planned)
            self._db.commit()
            return planned
        except sqlite3.IntegrityError as error:
            self._db.rollback()
            raise LifecycleConflict("retention plan conflicts") from error
        except Exception:
            self._db.rollback()
            raise
        finally:
            cursor.close()

    @staticmethod
    def _reload_candidate(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        content_sha256: str,
    ) -> _ArtifactCandidate | None:
        row = cursor.execute(
            """SELECT a.content_sha256,
                      MIN(z.repository_id) AS repository_id,
                      MIN(z.execution_identity_hash) AS execution_identity_hash,
                      MAX(a.committed_at) AS latest_committed_at,
                      COUNT(DISTINCT z.repository_id) AS repository_count,
                      COUNT(DISTINCT z.execution_identity_hash) AS identity_count
               FROM run_artifacts AS a
               JOIN artifact_upload_authorizations AS z
                 ON z.tenant_id=a.tenant_id
                AND z.authorization_id=a.authorization_id
                AND z.run_id=a.run_id
               JOIN audit_runs AS r
                 ON r.tenant_id=a.tenant_id
                AND r.run_id=a.run_id
                AND r.repository_id=z.repository_id
                AND r.execution_identity_hash=z.execution_identity_hash
               WHERE a.tenant_id=? AND a.content_sha256=?
               GROUP BY a.content_sha256""",
            (tenant_id, content_sha256),
        ).fetchone()
        if row is None or int(row["repository_count"]) != 1 or int(row["identity_count"]) != 1:
            return None
        return _ArtifactCandidate(
            tenant_id=tenant_id,
            repository_id=str(row["repository_id"]),
            content_sha256=str(row["content_sha256"]),
            execution_identity_hash=str(row["execution_identity_hash"]),
            latest_committed_at=_parse_utc(row["latest_committed_at"]),
        )

    @staticmethod
    def _has_existing_request(
        cursor: sqlite3.Cursor,
        candidate: _ArtifactCandidate,
    ) -> bool:
        existing = cursor.execute(
            """SELECT 1 FROM lifecycle_deletions
               WHERE tenant_id=? AND content_sha256=?
               LIMIT 1""",
            (candidate.tenant_id, candidate.content_sha256),
        ).fetchone()
        if existing is not None:
            return True
        planned = cursor.execute(
            """SELECT 1 FROM lifecycle_retention_plans
               WHERE tenant_id=? AND content_sha256=?
               LIMIT 1""",
            (candidate.tenant_id, candidate.content_sha256),
        ).fetchone()
        return planned is not None

    @staticmethod
    def _insert_request(
        cursor: sqlite3.Cursor,
        request: DeletionRequest,
        planned: PlannedArtifactDeletion,
    ) -> None:
        cursor.execute(
            """INSERT INTO lifecycle_deletions (
                   deletion_id, tenant_id, content_sha256, data_class,
                   identity_hash, requested_by, version, approved_by,
                   executed, legal_hold, created_at
               ) VALUES (?, ?, ?, ?, ?, ?, 1, NULL, 0, 0, ?)""",
            (
                request.deletion_id,
                request.tenant_id,
                request.content_sha256,
                request.data_class,
                request.identity_hash,
                request.requested_by,
                planned.requested_at,
            ),
        )
        cursor.execute(
            """INSERT INTO lifecycle_repository_scopes (
                   deletion_id, tenant_id, repository_id
               ) VALUES (?, ?, ?)""",
            (
                request.deletion_id,
                request.tenant_id,
                planned.repository_id,
            ),
        )
        cursor.execute(
            """INSERT INTO lifecycle_retention_plans (
                   tenant_id, content_sha256, deletion_id, repository_id,
                   execution_identity_hash, profile_sha256, eligible_at,
                   requested_at, schema_version
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                planned.tenant_id,
                planned.content_sha256,
                planned.deletion_id,
                planned.repository_id,
                planned.execution_identity_hash,
                planned.profile_sha256,
                planned.eligible_at,
                planned.requested_at,
                _SCHEMA_VERSION,
            ),
        )


def _deletion_id(candidate: _ArtifactCandidate) -> str:
    material = {
        "content_sha256": candidate.content_sha256,
        "execution_identity_hash": candidate.execution_identity_hash,
        "repository_id": candidate.repository_id,
        "tenant_id": candidate.tenant_id,
    }
    return f"retention-{_digest(material)}"


def _profile_hash(profile: RetentionProfile) -> str:
    return _digest(
        {
            "artifact_days": profile.artifact_days,
            "audit_days": profile.audit_days,
            "metadata_days": profile.metadata_days,
            "tenant_id": profile.tenant_id,
        }
    )


def _parse_utc(value: object) -> datetime:
    if type(value) is not str:
        raise LifecycleConflict("artifact retention timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise LifecycleConflict("artifact retention timestamp is invalid") from error
    if parsed.tzinfo is None:
        raise LifecycleConflict("artifact retention timestamp is invalid")
    return _utc(parsed)


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise LifecycleConflict("retention clock returned an invalid timestamp")
    result = value.astimezone(UTC)
    if result.utcoffset() != timedelta(0):
        raise LifecycleConflict("retention clock returned an invalid timestamp")
    return result


def _digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise LifecycleConflict("retention metadata is invalid") from error
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "RETENTION_PLANNER_SCHEMA_STATEMENTS",
    "ArtifactRetentionPlanner",
    "PlannedArtifactDeletion",
]
