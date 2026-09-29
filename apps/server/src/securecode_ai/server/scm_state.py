"""Restart-safe, tenant-bound SQLite state for SCM webhook runs."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from typing import Protocol, runtime_checkable

from securecode_ai.contracts import AuditRunOutcome
from securecode_ai.core.scm_run_state import (
    AdmissionDisposition,
    PublicationDisposition,
    SCMRunAdmissionReceipt,
    SCMRunAdmissionRequest,
    SCMRunLifecycle,
    SCMRunPublicationReceipt,
    SCMRunStateError,
    SCMRunStateErrorCode,
)

from . import scm_state_codec as _codec
from .scm_state_schema import SCM_STATE_SCHEMA_STATEMENTS


@runtime_checkable
class SCMRunStatePort(Protocol):
    """Structural surface consumed by the GitHub and GitLab adapters."""

    def admit(
        self, request: SCMRunAdmissionRequest, *, current_head_sha: str
    ) -> SCMRunAdmissionReceipt: ...

    def authorize_publication(
        self, run_id: str, *, current_head_sha: str
    ) -> SCMRunPublicationReceipt: ...

    def complete(
        self,
        run_id: str,
        outcome: AuditRunOutcome,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt: ...


@dataclass(frozen=True, slots=True)
class SCMProviderTarget:
    """Durable coordinates required to refresh a provider change HEAD."""

    provider: str
    installation_id: str
    repository_id: str
    change_id: str
    execution_identity_hash: str


class SqliteSCMRunState:
    """Durable SCM state with exact delivery replay and monotonic transitions.

    One instance is bound to one tenant. Capacity is fail-closed: existing
    deliveries always replay, while new rows are rejected instead of evicting
    receipt history needed for deterministic retries.
    """

    __slots__ = (
        "_connection",
        "_lock",
        "_max_deliveries",
        "_max_runs",
        "_tenant_id",
    )

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        max_runs: int = 100_000,
        max_deliveries: int = 200_000,
        initialize: bool = False,
    ) -> None:
        if (
            not isinstance(connection, sqlite3.Connection)
            or type(tenant_id) is not str
            or _codec.ID_PATTERN.fullmatch(tenant_id) is None
            or not _codec.capacity(max_runs)
            or not _codec.capacity(max_deliveries)
            or type(initialize) is not bool
        ):
            raise TypeError("SQLite SCM state configuration is invalid")
        self._connection = connection
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._tenant_id = tenant_id
        self._max_runs = max_runs
        self._max_deliveries = max_deliveries
        self._lock = RLock()
        if initialize:
            self.install_schema(connection)

    @staticmethod
    def install_schema(connection: sqlite3.Connection) -> None:
        """Development helper; normal bootstrap should use migrations."""

        if not isinstance(connection, sqlite3.Connection):
            raise TypeError("connection must be a sqlite3 connection")
        cursor = connection.cursor()
        try:
            for statement in SCM_STATE_SCHEMA_STATEMENTS:
                cursor.execute(statement)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            cursor.close()

    @property
    def tenant_id(self) -> str:
        """Return the tenant scope that owns every state row in this instance."""

        return self._tenant_id

    def admit(
        self,
        request: SCMRunAdmissionRequest,
        *,
        current_head_sha: str,
    ) -> SCMRunAdmissionReceipt:
        if (
            type(request) is not SCMRunAdmissionRequest
            or not _codec.is_commit_sha(current_head_sha)
            or request.execution_identity.repository_revision.tenant_id != self._tenant_id
        ):
            _codec.reject(SCMRunStateErrorCode.INVALID_REQUEST)
        material_hash = _codec.admission_hash(request)
        identity_json = _codec.canonical(request.execution_identity.model_dump(mode="json"))
        revision = request.execution_identity.repository_revision
        provider, provider_installation_id, change_id = _codec.provider_target(request)
        with self._lock, self._transaction() as cursor:
            replay = cursor.execute(
                """SELECT request_sha256, receipt_json
                   FROM scm_delivery_receipts
                   WHERE tenant_id=? AND delivery_id=?""",
                (self._tenant_id, request.delivery_id),
            ).fetchone()
            if replay is not None:
                if replay["request_sha256"] != material_hash:
                    _codec.reject(SCMRunStateErrorCode.DELIVERY_CONFLICT)
                receipt = _codec.admission_from_json(replay["receipt_json"])
                if receipt.lifecycle is SCMRunLifecycle.SUPERSEDED:
                    return receipt
                row = self._load_run(cursor, receipt.run_id)
                if (
                    row["execution_identity_hash"] != receipt.execution_identity_hash
                    or row["head_sha"] != receipt.head_sha
                ):
                    _codec.reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
                row = self._observe_run_head(cursor, row, current_head_sha)
                if (
                    _codec.lifecycle(row) is receipt.lifecycle
                    and _codec.state_version(row) == receipt.state_version
                ):
                    return receipt
                return _codec.admission_receipt(AdmissionDisposition.DUPLICATE, row, ())

            self._require_delivery_capacity(cursor)
            self._observe_head(
                cursor,
                request.installation_id,
                revision.repository_id,
                current_head_sha,
            )
            semantic_key = _codec.semantic_key(request)
            run_id = _codec.run_id(semantic_key)
            if current_head_sha != request.authorized_head_sha:
                self._supersede_other_heads(
                    cursor,
                    installation_id=request.installation_id,
                    repository_id=revision.repository_id,
                    current_head_sha=current_head_sha,
                    superseding_run_id=None,
                )
                receipt = SCMRunAdmissionReceipt(
                    disposition=AdmissionDisposition.SUPERSEDED,
                    run_id=run_id,
                    execution_identity_hash=(request.execution_identity.execution_identity_hash),
                    head_sha=request.authorized_head_sha,
                    lifecycle=SCMRunLifecycle.SUPERSEDED,
                    state_version=0,
                )
                self._store_delivery(cursor, request.delivery_id, material_hash, receipt)
                return receipt

            existing = cursor.execute(
                """SELECT * FROM scm_run_states
                   WHERE tenant_id=? AND installation_id=? AND repository_id=?
                     AND execution_identity_hash=?""",
                (
                    self._tenant_id,
                    request.installation_id,
                    revision.repository_id,
                    request.execution_identity.execution_identity_hash,
                ),
            ).fetchone()
            if existing is not None:
                if existing["execution_identity_json"] != identity_json:
                    _codec.reject(SCMRunStateErrorCode.SEMANTIC_CONFLICT)
                receipt = _codec.admission_receipt(AdmissionDisposition.DUPLICATE, existing, ())
                self._store_delivery(cursor, request.delivery_id, material_hash, receipt)
                return receipt

            self._require_run_capacity(cursor)
            sequence = _codec.next_sequence(cursor, "scm_run_states", self._tenant_id)
            cursor.execute(
                """INSERT INTO scm_run_states (
                       tenant_id, run_id, provider, provider_installation_id,
                       installation_id, repository_id, change_id, head_sha,
                       execution_identity_hash,
                       execution_identity_json, lifecycle, outcome,
                       state_version, created_sequence
                   ) VALUES (
                       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ADMITTED', NULL, 1, ?
                   )""",
                (
                    self._tenant_id,
                    run_id,
                    provider,
                    provider_installation_id,
                    request.installation_id,
                    revision.repository_id,
                    change_id,
                    revision.head_sha,
                    request.execution_identity.execution_identity_hash,
                    identity_json,
                    sequence,
                ),
            )
            superseded = self._supersede_other_heads(
                cursor,
                installation_id=request.installation_id,
                repository_id=revision.repository_id,
                current_head_sha=current_head_sha,
                superseding_run_id=run_id,
            )
            row = self._load_run(cursor, run_id)
            receipt = _codec.admission_receipt(AdmissionDisposition.ADMITTED, row, superseded)
            self._store_delivery(cursor, request.delivery_id, material_hash, receipt)
            return receipt

    def authorize_publication(
        self,
        run_id: str,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt:
        _codec.validate_run_call(run_id, current_head_sha)
        with self._lock, self._transaction() as cursor:
            row = self._load_run(cursor, run_id)
            row = self._observe_run_head(cursor, row, current_head_sha)
            lifecycle = _codec.lifecycle(row)
            if lifecycle is SCMRunLifecycle.SUPERSEDED:
                receipt = _codec.publication_receipt(
                    PublicationDisposition.SUPERSEDED, row, current_head_sha
                )
            elif lifecycle is SCMRunLifecycle.COMPLETED:
                _codec.reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
            else:
                receipt = _codec.publication_receipt(
                    PublicationDisposition.AUTHORIZED, row, current_head_sha
                )
            self._store_publication(cursor, receipt)
            return receipt

    def provider_target(self, run_id: str) -> SCMProviderTarget:
        """Load the tenant-scoped target needed to rebuild adapter bindings."""

        if type(run_id) is not str or _codec.ID_PATTERN.fullmatch(run_id) is None:
            _codec.reject(SCMRunStateErrorCode.INVALID_REQUEST)
        with self._lock:
            try:
                row = self._connection.execute(
                    """SELECT provider, provider_installation_id,
                              repository_id, change_id, execution_identity_hash
                       FROM scm_run_states
                       WHERE tenant_id=? AND run_id=?""",
                    (self._tenant_id, run_id),
                ).fetchone()
            except sqlite3.Error:
                _codec.reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
        if row is None:
            _codec.reject(SCMRunStateErrorCode.RUN_UNKNOWN)
        try:
            target = SCMProviderTarget(
                provider=row["provider"],
                installation_id=row["provider_installation_id"],
                repository_id=row["repository_id"],
                change_id=row["change_id"],
                execution_identity_hash=row["execution_identity_hash"],
            )
            if (
                target.provider not in {"github", "gitlab"}
                or _codec.ID_PATTERN.fullmatch(target.installation_id) is None
                or _codec.ID_PATTERN.fullmatch(target.repository_id) is None
                or _codec.ID_PATTERN.fullmatch(target.change_id) is None
                or _codec.SHA256_PATTERN.fullmatch(target.execution_identity_hash) is None
            ):
                raise ValueError
            return target
        except (TypeError, ValueError):
            _codec.reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)

    def complete(
        self,
        run_id: str,
        outcome: AuditRunOutcome,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt:
        if type(outcome) is not AuditRunOutcome or outcome is AuditRunOutcome.SUPERSEDED:
            _codec.reject(SCMRunStateErrorCode.INVALID_REQUEST)
        _codec.validate_run_call(run_id, current_head_sha)
        with self._lock, self._transaction() as cursor:
            row = self._load_run(cursor, run_id)
            row = self._observe_run_head(cursor, row, current_head_sha)
            lifecycle = _codec.lifecycle(row)
            if lifecycle is SCMRunLifecycle.SUPERSEDED:
                disposition = PublicationDisposition.SUPERSEDED
            elif lifecycle is SCMRunLifecycle.COMPLETED:
                if _codec.outcome(row) is not outcome:
                    _codec.reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
                disposition = PublicationDisposition.DUPLICATE
            else:
                version = _codec.state_version(row) + 1
                cursor.execute(
                    """UPDATE scm_run_states
                       SET lifecycle='COMPLETED', outcome=?, state_version=?
                       WHERE tenant_id=? AND run_id=? AND state_version=?""",
                    (
                        outcome.value,
                        version,
                        self._tenant_id,
                        run_id,
                        _codec.state_version(row),
                    ),
                )
                if cursor.rowcount != 1:
                    _codec.reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
                row = self._load_run(cursor, run_id)
                disposition = PublicationDisposition.COMPLETED
            receipt = _codec.publication_receipt(disposition, row, current_head_sha)
            self._store_publication(cursor, receipt)
            return receipt

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Cursor]:
        cursor = self._connection.cursor()
        try:
            cursor.execute("BEGIN IMMEDIATE")
            yield cursor
            self._connection.commit()
        except SCMRunStateError:
            self._connection.rollback()
            raise
        except sqlite3.Error:
            self._connection.rollback()
            _codec.reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
        except Exception:
            self._connection.rollback()
            raise
        finally:
            cursor.close()

    def _load_run(self, cursor: sqlite3.Cursor, run_id: str) -> sqlite3.Row:
        row: sqlite3.Row | None = cursor.execute(
            "SELECT * FROM scm_run_states WHERE tenant_id=? AND run_id=?",
            (self._tenant_id, run_id),
        ).fetchone()
        if row is None:
            _codec.reject(SCMRunStateErrorCode.RUN_UNKNOWN)
        try:
            if (
                _codec.ID_PATTERN.fullmatch(row["run_id"]) is None
                or _codec.ID_PATTERN.fullmatch(row["installation_id"]) is None
                or _codec.ID_PATTERN.fullmatch(row["repository_id"]) is None
                or not _codec.is_commit_sha(row["head_sha"])
                or _codec.SHA256_PATTERN.fullmatch(row["execution_identity_hash"]) is None
            ):
                raise ValueError
            _codec.lifecycle(row)
            _codec.outcome(row)
            _codec.state_version(row)
        except (TypeError, ValueError):
            _codec.reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
        return row

    def _observe_head(
        self,
        cursor: sqlite3.Cursor,
        installation_id: str,
        repository_id: str,
        current_head_sha: str,
    ) -> None:
        row = cursor.execute(
            """SELECT current_head_sha, state_version FROM scm_head_scopes
               WHERE tenant_id=? AND installation_id=? AND repository_id=?""",
            (self._tenant_id, installation_id, repository_id),
        ).fetchone()
        if row is None:
            cursor.execute(
                """INSERT INTO scm_head_scopes
                   VALUES (?, ?, ?, ?, 1)""",
                (
                    self._tenant_id,
                    installation_id,
                    repository_id,
                    current_head_sha,
                ),
            )
        elif row["current_head_sha"] != current_head_sha:
            cursor.execute(
                """UPDATE scm_head_scopes
                   SET current_head_sha=?, state_version=?
                   WHERE tenant_id=? AND installation_id=? AND repository_id=?""",
                (
                    current_head_sha,
                    int(row["state_version"]) + 1,
                    self._tenant_id,
                    installation_id,
                    repository_id,
                ),
            )

    def _observe_run_head(
        self,
        cursor: sqlite3.Cursor,
        row: sqlite3.Row,
        current_head_sha: str,
    ) -> sqlite3.Row:
        self._observe_head(
            cursor,
            row["installation_id"],
            row["repository_id"],
            current_head_sha,
        )
        if row["head_sha"] != current_head_sha:
            row = self._supersede(
                cursor,
                row,
                current_head_sha=current_head_sha,
                superseding_run_id=None,
            )
        return row

    def _supersede_other_heads(
        self,
        cursor: sqlite3.Cursor,
        *,
        installation_id: str,
        repository_id: str,
        current_head_sha: str,
        superseding_run_id: str | None,
    ) -> tuple[str, ...]:
        rows = cursor.execute(
            """SELECT * FROM scm_run_states
               WHERE tenant_id=? AND installation_id=? AND repository_id=?
                 AND head_sha<>? AND lifecycle<>'SUPERSEDED'
               ORDER BY run_id""",
            (
                self._tenant_id,
                installation_id,
                repository_id,
                current_head_sha,
            ),
        ).fetchall()
        run_ids: list[str] = []
        for row in rows:
            changed = self._supersede(
                cursor,
                row,
                current_head_sha=current_head_sha,
                superseding_run_id=superseding_run_id,
            )
            receipt = _codec.publication_receipt(
                PublicationDisposition.SUPERSEDED, changed, current_head_sha
            )
            self._store_publication(cursor, receipt)
            run_ids.append(changed["run_id"])
        return tuple(run_ids)

    def _supersede(
        self,
        cursor: sqlite3.Cursor,
        row: sqlite3.Row,
        *,
        current_head_sha: str,
        superseding_run_id: str | None,
    ) -> sqlite3.Row:
        if _codec.lifecycle(row) is SCMRunLifecycle.SUPERSEDED:
            return row
        version = _codec.state_version(row) + 1
        cursor.execute(
            """UPDATE scm_run_states
               SET lifecycle='SUPERSEDED', outcome='SUPERSEDED', state_version=?
               WHERE tenant_id=? AND run_id=? AND state_version=?""",
            (
                version,
                self._tenant_id,
                row["run_id"],
                _codec.state_version(row),
            ),
        )
        if cursor.rowcount != 1:
            _codec.reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
        cursor.execute(
            """INSERT INTO scm_run_supersessions (
                   tenant_id, superseded_run_id, superseding_run_id,
                   superseding_head_sha, superseded_state_version
               ) VALUES (?, ?, ?, ?, ?)""",
            (
                self._tenant_id,
                row["run_id"],
                superseding_run_id,
                current_head_sha,
                version,
            ),
        )
        return self._load_run(cursor, row["run_id"])

    def _store_delivery(
        self,
        cursor: sqlite3.Cursor,
        delivery_id: str,
        request_hash: str,
        receipt: SCMRunAdmissionReceipt,
    ) -> None:
        receipt_json = _codec.admission_json(receipt)
        sequence = _codec.next_sequence(cursor, "scm_delivery_receipts", self._tenant_id)
        cursor.execute(
            """INSERT INTO scm_delivery_receipts
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                self._tenant_id,
                delivery_id,
                request_hash,
                receipt.run_id,
                receipt_json,
                sequence,
            ),
        )
        _codec.store_history(
            cursor,
            self._tenant_id,
            receipt.run_id,
            "ADMISSION",
            receipt.state_version,
            receipt_json,
        )

    def _store_publication(self, cursor: sqlite3.Cursor, receipt: SCMRunPublicationReceipt) -> None:
        _codec.store_history(
            cursor,
            self._tenant_id,
            receipt.run_id,
            "PUBLICATION",
            receipt.state_version,
            _codec.publication_json(receipt),
        )

    def _require_run_capacity(self, cursor: sqlite3.Cursor) -> None:
        _codec.require_capacity(cursor, "scm_run_states", self._tenant_id, self._max_runs)

    def _require_delivery_capacity(self, cursor: sqlite3.Cursor) -> None:
        _codec.require_capacity(
            cursor,
            "scm_delivery_receipts",
            self._tenant_id,
            self._max_deliveries,
        )


__all__ = [
    "SCM_STATE_SCHEMA_STATEMENTS",
    "SCMProviderTarget",
    "SCMRunStatePort",
    "SqliteSCMRunState",
]
