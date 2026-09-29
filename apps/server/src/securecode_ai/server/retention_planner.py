"""Bounded planning of deletion requests for expired local artifacts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from .data_lifecycle import retention_content_sha256
from .data_lifecycle_models import (
    DeletionRequest,
    LifecycleConflict,
    RetentionProfile,
    require_identifier,
    require_sha256,
)
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard

_SCHEMA_VERSION: Final = 1
_TERMINAL_RUN_STATES: Final = frozenset(
    {"SUCCEEDED", "FAILED", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}
)

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
    eligible_at: datetime


@dataclass(frozen=True, slots=True)
class _RunCandidate:
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    data_class: str
    latest_at: datetime


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
        residency_guard: ResidencyGuard | None = None,
        residency_region: str | None = None,
    ) -> None:
        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        require_identifier(requested_by, "requested_by")
        self._db = connection
        self._db.row_factory = sqlite3.Row
        self._requested_by = requested_by
        self._clock = clock or (lambda: datetime.now(UTC))
        self._db.create_function(
            "securecode_retention_run_content_sha256_v1",
            5,
            _sql_retention_content_sha256,
            deterministic=True,
        )
        if (residency_guard is None) != (residency_region is None):
            raise TypeError("retention residency configuration is incomplete")
        if residency_guard is not None and not callable(
            getattr(residency_guard, "require_region", None)
        ):
            raise TypeError("retention residency guard is invalid")
        self._residency_guard = residency_guard
        self._residency_region = residency_region
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
        self._require_residency(profile.tenant_id)
        now = _utc(self._clock())
        profile_sha256 = _profile_hash(profile)
        candidates = self._candidates(
            tenant_id=profile.tenant_id,
            now=now,
            artifact_days=profile.artifact_days,
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
        remaining = max_items - len(results)
        if remaining:
            for data_class, days in (
                ("metadata", profile.metadata_days),
                ("audit", profile.audit_days),
            ):
                if len(results) >= max_items:
                    break
                run_candidates = self._run_candidates(
                    tenant_id=profile.tenant_id,
                    data_class=data_class,
                    cutoff=now - timedelta(days=days),
                    limit=max_items - len(results),
                )
                for run_candidate in run_candidates:
                    planned = self._plan_run_candidate(
                        candidate=run_candidate,
                        profile=profile,
                        profile_sha256=profile_sha256,
                        now=now,
                    )
                    if planned is not None:
                        results.append(planned)
                    if len(results) >= max_items:
                        break
        return tuple(results)

    def _require_residency(self, tenant_id: str) -> None:
        guard = self._residency_guard
        if guard is None:
            return
        region = self._residency_region
        if type(region) is not str or not region:
            raise LifecycleConflict("retention residency configuration is incomplete")
        try:
            decision = guard.require_region(tenant_id=tenant_id, region=region)
        except ResidencyConflict as error:
            raise LifecycleConflict("retention planning is denied by residency policy") from error
        except Exception as error:
            raise LifecycleConflict("retention residency check failed") from error
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != tenant_id
            or decision.source_region != region
            or decision.destination_region != region
            or not decision.same_region
        ):
            raise LifecycleConflict("retention residency decision is invalid")

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
        now: datetime,
        artifact_days: int,
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
                AND z.content_sha256=a.content_sha256
                AND z.purpose=a.purpose
               JOIN audit_runs AS r
                 ON r.tenant_id=a.tenant_id
                AND r.run_id=a.run_id
                AND r.repository_id=z.repository_id
                AND r.execution_identity_hash=z.execution_identity_hash
               WHERE a.tenant_id=?
                 AND r.state IN (?, ?, ?, ?, ?)
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
                 AND NOT EXISTS (
                     SELECT 1
                     FROM run_artifacts AS a_live
                     JOIN artifact_upload_authorizations AS z_live
                       ON z_live.tenant_id=a_live.tenant_id
                      AND z_live.authorization_id=a_live.authorization_id
                      AND z_live.run_id=a_live.run_id
                      AND z_live.content_sha256=a_live.content_sha256
                      AND z_live.purpose=a_live.purpose
                     JOIN audit_runs AS r_live
                       ON r_live.tenant_id=a_live.tenant_id
                      AND r_live.run_id=a_live.run_id
                      AND r_live.repository_id=z_live.repository_id
                      AND r_live.execution_identity_hash=z_live.execution_identity_hash
                     WHERE a_live.tenant_id=a.tenant_id
                       AND a_live.content_sha256=a.content_sha256
                       AND r_live.state NOT IN (?, ?, ?, ?, ?)
                 )
               GROUP BY a.content_sha256
               HAVING repository_count=1 AND identity_count=1
               ORDER BY latest_committed_at, a.content_sha256
               LIMIT ?""",
            (tenant_id, *_TERMINAL_RUN_STATES, *_TERMINAL_RUN_STATES, limit),
        ).fetchall()
        candidates: list[_ArtifactCandidate] = []
        for row in rows:
            content_sha256 = row["content_sha256"]
            repository_id = row["repository_id"]
            identity_hash = row["execution_identity_hash"]
            require_sha256(content_sha256, "content_sha256")
            require_identifier(repository_id, "repository_id")
            require_sha256(identity_hash, "execution_identity_hash")
            latest = _parse_utc(row["latest_committed_at"])
            candidate = _ArtifactCandidate(
                tenant_id=tenant_id,
                repository_id=repository_id,
                content_sha256=content_sha256,
                execution_identity_hash=identity_hash,
                latest_committed_at=latest,
                eligible_at=self._eligible_at(
                    tenant_id=tenant_id,
                    content_sha256=content_sha256,
                    artifact_days=artifact_days,
                ),
            )
            if candidate.eligible_at > now:
                continue
            candidates.append(candidate)
        return tuple(candidates)

    def _run_candidates(
        self,
        *,
        tenant_id: str,
        data_class: str,
        cutoff: datetime,
        limit: int,
    ) -> tuple[_RunCandidate, ...]:
        if data_class not in {"metadata", "audit"}:
            raise LifecycleConflict("retention data class is invalid")
        if data_class == "audit" and not self._table_exists("audit_chain_events"):
            raise LifecycleConflict("audit retention schema is incomplete")
        rows = self._db.execute(
            """SELECT run_id, repository_id, execution_identity_hash,
                      created_at, updated_at
               FROM audit_runs
               WHERE tenant_id=? AND state IN (?, ?, ?, ?, ?)
                 AND NOT EXISTS (
                     SELECT 1
                     FROM lifecycle_deletions AS d
                     WHERE d.tenant_id=audit_runs.tenant_id
                       AND d.content_sha256=
                           securecode_retention_run_content_sha256_v1(
                               ?, audit_runs.tenant_id, audit_runs.repository_id,
                               audit_runs.run_id, audit_runs.execution_identity_hash
                           )
                 )
               ORDER BY updated_at, run_id
               LIMIT ?""",
            (
                tenant_id,
                *_TERMINAL_RUN_STATES,
                data_class,
                limit,
            ),
        ).fetchall()
        candidates: list[_RunCandidate] = []
        for row in rows:
            run_id = row["run_id"]
            repository_id = row["repository_id"]
            identity_hash = row["execution_identity_hash"]
            if (
                type(run_id) is not str
                or type(repository_id) is not str
                or type(identity_hash) is not str
            ):
                raise LifecycleConflict("retention run metadata is invalid")
            require_identifier(run_id, "run_id")
            require_identifier(repository_id, "repository_id")
            require_sha256(identity_hash, "execution_identity_hash")
            latest = self._run_latest_at(
                tenant_id=tenant_id,
                run_id=run_id,
                data_class=data_class,
                fallback=(row["updated_at"] if data_class == "metadata" else row["created_at"]),
            )
            if latest > cutoff:
                continue
            content_sha256 = retention_content_sha256(
                data_class=data_class,
                tenant_id=tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                identity_hash=identity_hash,
            )
            if self._has_existing_run_request(
                tenant_id=tenant_id,
                data_class=data_class,
                content_sha256=content_sha256,
            ):
                continue
            candidates.append(
                _RunCandidate(
                    tenant_id=tenant_id,
                    repository_id=repository_id,
                    run_id=run_id,
                    execution_identity_hash=identity_hash,
                    data_class=data_class,
                    latest_at=latest,
                )
            )
        return tuple(candidates)

    def _run_latest_at(
        self,
        *,
        tenant_id: str,
        run_id: str,
        data_class: str,
        fallback: object,
    ) -> datetime:
        value = fallback
        if data_class == "audit" and self._table_exists("audit_chain_events"):
            row = self._db.execute(
                """SELECT MAX(created_at) AS latest_at
                   FROM audit_chain_events
                   WHERE tenant_id=? AND run_id=?""",
                (tenant_id, run_id),
            ).fetchone()
            if row is not None and row["latest_at"] is not None:
                value = row["latest_at"]
        return _parse_utc(value)

    def _table_exists(self, name: str) -> bool:
        row = self._db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (name,),
        ).fetchone()
        return row is not None

    def _has_existing_run_request(
        self,
        *,
        tenant_id: str,
        data_class: str,
        content_sha256: str,
    ) -> bool:
        row = self._db.execute(
            """SELECT 1 FROM lifecycle_deletions
               WHERE tenant_id=? AND data_class=? AND content_sha256=?
               LIMIT 1""",
            (tenant_id, data_class, content_sha256),
        ).fetchone()
        return row is not None

    def _plan_run_candidate(
        self,
        *,
        candidate: _RunCandidate,
        profile: RetentionProfile,
        profile_sha256: str,
        now: datetime,
    ) -> PlannedArtifactDeletion | None:
        content_sha256 = retention_content_sha256(
            data_class=candidate.data_class,
            tenant_id=candidate.tenant_id,
            repository_id=candidate.repository_id,
            run_id=candidate.run_id,
            identity_hash=candidate.execution_identity_hash,
        )
        request = DeletionRequest(
            deletion_id=_run_deletion_id(candidate),
            tenant_id=candidate.tenant_id,
            content_sha256=content_sha256,
            data_class=candidate.data_class,
            identity_hash=candidate.execution_identity_hash,
            requested_by=self._requested_by,
            version=1,
        )
        cursor = self._db.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            self._require_residency(candidate.tenant_id)
            current = self._reload_run_candidate(
                cursor,
                tenant_id=candidate.tenant_id,
                run_id=candidate.run_id,
                data_class=candidate.data_class,
            )
            days = (
                profile.metadata_days if candidate.data_class == "metadata" else profile.audit_days
            )
            if (
                current is None
                or current.repository_id != candidate.repository_id
                or current.execution_identity_hash != candidate.execution_identity_hash
                or current.latest_at + timedelta(days=days) > now
                or self._has_existing_run_request_cursor(
                    cursor,
                    tenant_id=candidate.tenant_id,
                    data_class=candidate.data_class,
                    content_sha256=content_sha256,
                )
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
                eligible_at=(current.latest_at + timedelta(days=days)).isoformat(),
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
    def _reload_run_candidate(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        run_id: str,
        data_class: str,
    ) -> _RunCandidate | None:
        row = cursor.execute(
            """SELECT run_id, repository_id, execution_identity_hash,
                      state, created_at, updated_at
               FROM audit_runs
               WHERE tenant_id=? AND run_id=?""",
            (tenant_id, run_id),
        ).fetchone()
        if row is None or row["state"] not in _TERMINAL_RUN_STATES:
            return None
        stored_run_id = row["run_id"]
        repository_id = row["repository_id"]
        identity_hash = row["execution_identity_hash"]
        if (
            type(stored_run_id) is not str
            or type(repository_id) is not str
            or type(identity_hash) is not str
        ):
            raise LifecycleConflict("retention run metadata is invalid")
        require_identifier(stored_run_id, "run_id")
        require_identifier(repository_id, "repository_id")
        require_sha256(identity_hash, "execution_identity_hash")
        latest = _parse_utc(row["updated_at"] if data_class == "metadata" else row["created_at"])
        if data_class == "audit":
            audit_row = cursor.execute(
                """SELECT MAX(created_at) AS latest_at
                   FROM audit_chain_events
                   WHERE tenant_id=? AND run_id=?""",
                (tenant_id, run_id),
            ).fetchone()
            if audit_row is not None and audit_row["latest_at"] is not None:
                latest = _parse_utc(audit_row["latest_at"])
        return _RunCandidate(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=stored_run_id,
            execution_identity_hash=identity_hash,
            data_class=data_class,
            latest_at=latest,
        )

    @staticmethod
    def _has_existing_run_request_cursor(
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        data_class: str,
        content_sha256: str,
    ) -> bool:
        row = cursor.execute(
            """SELECT 1 FROM lifecycle_deletions
               WHERE tenant_id=? AND data_class=? AND content_sha256=?
               LIMIT 1""",
            (tenant_id, data_class, content_sha256),
        ).fetchone()
        return row is not None

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
            self._require_residency(candidate.tenant_id)
            current = self._reload_candidate(
                cursor,
                tenant_id=candidate.tenant_id,
                content_sha256=candidate.content_sha256,
                artifact_days=profile.artifact_days,
            )
            if current is None:
                self._db.commit()
                return None
            current_eligible_at = current.eligible_at
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

    def _reload_candidate(
        self,
        cursor: sqlite3.Cursor,
        *,
        tenant_id: str,
        content_sha256: str,
        artifact_days: int,
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
                AND z.content_sha256=a.content_sha256
                AND z.purpose=a.purpose
               JOIN audit_runs AS r
                 ON r.tenant_id=a.tenant_id
                AND r.run_id=a.run_id
                AND r.repository_id=z.repository_id
                AND r.execution_identity_hash=z.execution_identity_hash
               WHERE a.tenant_id=? AND a.content_sha256=?
                 AND r.state IN (?, ?, ?, ?, ?)
                 AND NOT EXISTS (
                     SELECT 1
                     FROM run_artifacts AS a_live
                     JOIN artifact_upload_authorizations AS z_live
                       ON z_live.tenant_id=a_live.tenant_id
                      AND z_live.authorization_id=a_live.authorization_id
                      AND z_live.run_id=a_live.run_id
                      AND z_live.content_sha256=a_live.content_sha256
                      AND z_live.purpose=a_live.purpose
                     JOIN audit_runs AS r_live
                       ON r_live.tenant_id=a_live.tenant_id
                      AND r_live.run_id=a_live.run_id
                      AND r_live.repository_id=z_live.repository_id
                      AND r_live.execution_identity_hash=z_live.execution_identity_hash
                     WHERE a_live.tenant_id=a.tenant_id
                       AND a_live.content_sha256=a.content_sha256
                       AND r_live.state NOT IN (?, ?, ?, ?, ?)
                 )
               GROUP BY a.content_sha256""",
            (
                tenant_id,
                content_sha256,
                *_TERMINAL_RUN_STATES,
                *_TERMINAL_RUN_STATES,
            ),
        ).fetchone()
        if row is None or row["repository_count"] != 1 or row["identity_count"] != 1:
            return None
        content_sha256_value = row["content_sha256"]
        repository_id = row["repository_id"]
        identity_hash = row["execution_identity_hash"]
        require_sha256(content_sha256_value, "content_sha256")
        require_identifier(repository_id, "repository_id")
        require_sha256(identity_hash, "execution_identity_hash")
        return _ArtifactCandidate(
            tenant_id=tenant_id,
            repository_id=repository_id,
            content_sha256=content_sha256_value,
            execution_identity_hash=identity_hash,
            latest_committed_at=_parse_utc(row["latest_committed_at"]),
            eligible_at=self._eligible_at(
                tenant_id=tenant_id,
                content_sha256=content_sha256_value,
                artifact_days=artifact_days,
            ),
        )

    def _eligible_at(
        self,
        *,
        tenant_id: str,
        content_sha256: str,
        artifact_days: int,
    ) -> datetime:
        rows = self._db.execute(
            """SELECT a.metadata_json, a.committed_at, r.state,
                         a.authorization_id, z.content_id, z.content_sha256,
                         z.data_class, z.purpose, z.size_bytes
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
               WHERE a.tenant_id=? AND a.content_sha256=?""",
            (tenant_id, content_sha256),
        ).fetchall()
        if not rows:
            raise LifecycleConflict("artifact retention target is unavailable")
        deadlines: list[datetime] = []
        for row in rows:
            if row["state"] not in _TERMINAL_RUN_STATES:
                raise LifecycleConflict("artifact retention target is still active")
            committed = _parse_utc(row["committed_at"])
            explicit = _artifact_expiration(
                row["metadata_json"],
                committed,
                expected={
                    "authorization_id": row["authorization_id"],
                    "content_id": row["content_id"],
                    "content_sha256": row["content_sha256"],
                    "data_class": row["data_class"],
                    "purpose": row["purpose"],
                    "size_bytes": row["size_bytes"],
                },
            )
            generic = committed + timedelta(days=artifact_days)
            deadlines.append(min(generic, explicit) if explicit is not None else generic)
        return max(deadlines)

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


def _run_deletion_id(candidate: _RunCandidate) -> str:
    material = {
        "data_class": candidate.data_class,
        "execution_identity_hash": candidate.execution_identity_hash,
        "repository_id": candidate.repository_id,
        "run_id": candidate.run_id,
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


def _sql_retention_content_sha256(
    data_class: str,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    identity_hash: str,
) -> str:
    return retention_content_sha256(
        data_class=data_class,
        tenant_id=tenant_id,
        repository_id=repository_id,
        run_id=run_id,
        identity_hash=identity_hash,
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


def _artifact_expiration(
    metadata_json: object,
    committed_at: datetime,
    *,
    expected: Mapping[str, object],
) -> datetime | None:
    if type(metadata_json) is not str or not metadata_json:
        raise LifecycleConflict("artifact retention metadata is invalid")
    try:
        document = json.loads(metadata_json, object_pairs_hook=_unique_object_pairs)
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise LifecycleConflict("artifact retention metadata is invalid") from None
    if type(document) is not dict:
        raise LifecycleConflict("artifact retention metadata is invalid")
    required = frozenset(expected)
    if set(document) not in {required, required | {"expires_at"}}:
        raise LifecycleConflict("artifact retention metadata is invalid")
    if any(document.get(key) != value for key, value in expected.items()):
        raise LifecycleConflict("artifact retention metadata is invalid")
    if "expires_at" not in document:
        return None
    expires_at = document["expires_at"]
    if type(expires_at) is not str or not expires_at:
        raise LifecycleConflict("artifact retention metadata is invalid")
    expiry = _parse_utc(expires_at)
    if expiry <= committed_at:
        raise LifecycleConflict("artifact retention metadata is invalid")
    return expiry


def _unique_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise LifecycleConflict("artifact retention metadata is invalid")
        value[key] = item
    return value


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
