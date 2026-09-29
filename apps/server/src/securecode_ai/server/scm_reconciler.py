"""Dedicated runtime for retrying SCM publications outside the ASGI loop."""

from __future__ import annotations

import contextlib
import re
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from threading import Event, Lock, Thread, current_thread
from typing import Final

from .persistence import DevelopmentRepository
from .residency_registry import load_residency_registry
from .scm_completion import SCMCompletionPublicationService
from .scm_publication_runtime import build_scm_publication_service
from .scm_publication_store import SqliteSCMPublicationStore
from .scm_runtime import build_scm_handlers
from .sqlite_database import open_private_sqlite
from .waivers import WaiverLedger

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_BATCH: Final = 32
_DEFAULT_BATCH: Final = 4
_SHUTDOWN_JOIN_SECONDS: Final = 5.0
_AUDIT_STATE_OUTCOMES: Final = {
    "SUCCEEDED": "PASS",
    "FAILED": "FAIL",
    "INDETERMINATE": "INDETERMINATE",
    "CANCELLED": "CANCELLED",
    "SUPERSEDED": "SUPERSEDED",
}
_RECONCILER_ENVIRONMENT: Final = frozenset(
    {
        "SECURECODE_DATA_REGION",
        "SECURECODE_TENANT_RESIDENCY_REGIONS",
        "SECURECODE_SCM_PINS_FILE",
        "SECURECODE_GITHUB_API_URL",
        "SECURECODE_GITHUB_INSTALLATION_ID",
        "SECURECODE_GITHUB_TOKEN_FILE",
        "SECURECODE_GITHUB_WEBHOOK_SECRET_FILE",
        "SECURECODE_GITHUB_SARIF_ENABLED",
        "SECURECODE_GITLAB_API_URL",
        "SECURECODE_GITLAB_TOKEN_FILE",
        "SECURECODE_GITLAB_WEBHOOK_SECRET_FILE",
    }
)


class SCMPublicationReconciler:
    """Own a private SQLite-backed SCM publication graph and worker thread."""

    __slots__ = (
        "_artifact_root",
        "_closed",
        "_database_path",
        "_lock",
        "_max_items",
        "_stop",
        "_tenant_id",
        "_thread",
        "_values",
        "_wake",
    )

    def __init__(
        self,
        *,
        database_path: Path,
        values: Mapping[str, str],
        tenant_id: str,
        artifact_root: Path,
        max_items: int = _DEFAULT_BATCH,
    ) -> None:
        if (
            not isinstance(database_path, Path)
            or not database_path.is_absolute()
            or not isinstance(values, Mapping)
            or any(type(key) is not str or type(value) is not str for key, value in values.items())
            or type(tenant_id) is not str
            or _ID.fullmatch(tenant_id) is None
            or not isinstance(artifact_root, Path)
            or not artifact_root.is_absolute()
            or type(max_items) is not int
            or not 1 <= max_items <= _MAX_BATCH
        ):
            raise ValueError("SCM reconciler configuration is invalid")
        self._database_path = database_path
        self._values = {
            key: value for key, value in values.items() if key in _RECONCILER_ENVIRONMENT
        }
        self._tenant_id = tenant_id
        self._artifact_root = artifact_root
        self._max_items = max_items
        self._wake = Event()
        self._stop = Event()
        self._lock = Lock()
        self._thread: Thread | None = None
        self._closed = False

    def trigger(self) -> bool:
        """Request one bounded reconciliation without performing blocking work."""

        with self._lock:
            if self._closed:
                return False
            thread = self._thread
            if thread is None or not thread.is_alive():
                thread = Thread(
                    target=self._run,
                    name="securecode-scm-reconciler",
                    daemon=True,
                )
                self._thread = thread
                thread.start()
            self._wake.set()
        return True

    def shutdown(self) -> None:
        """Stop future work and give the private graph a bounded cleanup window."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            self._wake.set()
            thread = self._thread
        if thread is not None and thread is not current_thread():
            thread.join(timeout=_SHUTDOWN_JOIN_SECONDS)

    def _run(self) -> None:
        connection: sqlite3.Connection | None = None
        try:
            if self._stop.is_set():
                return
            connection = open_private_sqlite(self._database_path, create=False)
            publications = SqliteSCMPublicationStore(connection, initialize=True)
            publisher = self._build_publisher(connection, publications=publications)
            while True:
                self._wake.wait()
                self._wake.clear()
                if self._stop.is_set():
                    return
                try:
                    self._hydrate_terminal_outcomes(connection, publications)
                    publisher.reconcile_pending(
                        tenant_id=self._tenant_id,
                        max_items=self._max_items,
                    )
                except (KeyboardInterrupt, SystemExit, GeneratorExit):
                    raise
                except Exception:
                    continue
        finally:
            if connection is not None:
                with contextlib.suppress(sqlite3.Error):
                    connection.close()

    def _build_publisher(
        self,
        connection: sqlite3.Connection,
        *,
        publications: SqliteSCMPublicationStore | None = None,
    ) -> SCMCompletionPublicationService:
        repository = DevelopmentRepository(connection, initialize=False)
        if publications is None:
            publications = SqliteSCMPublicationStore(connection, initialize=True)
        scm = build_scm_handlers(
            self._values,
            tenant_id=self._tenant_id,
            connection=connection,
            publications=publications,
        )
        if scm.run_state is None:
            raise ValueError("SCM reconciler state is unavailable")
        residency = load_residency_registry(connection, self._values)
        residency_region = self._values.get("SECURECODE_DATA_REGION") or None
        waiver_ledger = WaiverLedger(connection)
        return build_scm_publication_service(
            connection=connection,
            repository=repository,
            scm=scm,
            publications=publications,
            waiver_ledger=waiver_ledger,
            artifact_root=self._artifact_root,
            residency_guard=residency if residency_region is not None else None,
            residency_region=residency_region,
        )

    def _hydrate_terminal_outcomes(
        self,
        connection: sqlite3.Connection,
        publications: SqliteSCMPublicationStore,
    ) -> None:
        """Recover a pending target after its worker queue row was retired.

        The SCM run state is durable for the lifetime of publication receipts,
        while queue rows may be compacted sooner.  Without this bridge a
        publication target whose queue outcome was deleted remains PENDING
        forever and is never retried after a restart.
        """

        try:
            targets = publications.pending(tenant_id=self._tenant_id, limit=self._max_items)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            return
        for target in targets:
            if target.outcome is not None:
                continue
            try:
                row = connection.execute(
                    """SELECT provider, installation_id, repository_id,
                              change_id, head_sha, execution_identity_hash,
                              scm_run_states.outcome, audit.state AS audit_state
                       FROM scm_run_states
                       LEFT JOIN audit_runs AS audit
                         ON audit.tenant_id=scm_run_states.tenant_id
                        AND audit.run_id=scm_run_states.run_id
                       WHERE scm_run_states.tenant_id=?
                         AND scm_run_states.run_id=?""",
                    (self._tenant_id, target.run_id),
                ).fetchone()
                if row is None:
                    continue
                if (
                    row["provider"] != target.provider
                    or row["installation_id"] != target.installation_id
                    or row["repository_id"] != target.repository_id
                    or row["change_id"] != target.change_id
                    or row["head_sha"] != target.head_sha
                    or row["execution_identity_hash"] != target.execution_identity_hash
                ):
                    continue
                outcome = row["outcome"]
                if outcome is None:
                    audit_state = row["audit_state"]
                    if type(audit_state) is str:
                        outcome = _AUDIT_STATE_OUTCOMES.get(audit_state)
                if type(outcome) is not str:
                    continue
                if outcome == "ERROR":
                    outcome = "INDETERMINATE"
                if outcome not in {
                    "PASS",
                    "FAIL",
                    "INDETERMINATE",
                    "CANCELLED",
                    "SUPERSEDED",
                }:
                    continue
                publications.mark_pending(target=target, outcome=outcome)
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except Exception:
                continue


__all__ = ["SCMPublicationReconciler"]
