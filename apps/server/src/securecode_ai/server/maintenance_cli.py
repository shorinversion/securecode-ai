"""One-shot maintenance entrypoint for lifecycle planning and execution."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import stat
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NoReturn, TextIO

from .artifact_store import LocalArtifactStore
from .artifact_upload import purge_orphaned_artifact_objects
from .backup_lifecycle import BackupLifecycleAdapter, BackupRetentionCandidate
from .backup_executor_runtime import SubprocessBackupEncryptionProvider
from .bootstrap import _waivers_cover_run_policy
from .data_lifecycle import LifecycleLedger
from .data_lifecycle_models import RetentionProfile
from .filesystem_paths import lexical_absolute_path
from .idempotency import _DEFAULT_CLAIM_LEASE_MS
from .lifecycle_scheduler import ApprovedDeletionScheduler, ScheduledDeletionResult
from .migrations import SchemaVersionError, require_schema_version
from .oidc_sessions import NonceReplayLedger, SqliteOidcLoginState
from .persistence import DevelopmentRepository
from .request_quota import MAX_WINDOW_SECONDS
from .resource_repository import ResourceRepository
from .resource_service import ResourceService
from .retention_planner import ArtifactRetentionPlanner, PlannedArtifactDeletion
from .residency_registry import load_residency_registry
from .runtime import load_settings
from .secret_provider_runtime import build_secret_provider
from .secret_service import SecretDenied, SecretService
from .system_backup_runtime import (
    SystemBackupError,
    SystemOidcBackupRetention,
    SystemOidcBackupRecord,
    SystemOidcBackupRuntime,
)
from .subprocess_protocol import configured_process
from .scm_completion_models import SCMCompletionDisposition
from .scm_publication_store import SqliteSCMPublicationStore
from .scm_publication_runtime import build_scm_publication_service
from .scm_runtime import build_scm_handlers
from .sqlite_database import open_private_sqlite
from .storage_executor import LocalArtifactStorageExecutor
from .waivers import WaiverLedger
from .worker_scm_policy import load_run_scm_policy_decision
from .worker_artifact_authorization import (
    has_expired_artifact_authorizations,
    purge_expired_artifact_authorizations,
)

_SCHEMA_VERSION: Final = 1
_REPARSE_POINT: Final = 0x400
_SESSION_PURGE_SAVEPOINT: Final = "securecode_maintenance_session_purge"
_QUOTA_PURGE_SAVEPOINT: Final = "securecode_maintenance_quota_purge"
_REQUEST_CLAIM_PURGE_SAVEPOINT: Final = "securecode_maintenance_request_claim_purge"
_OIDC_SOURCE_RATE_PURGE_SAVEPOINT: Final = "securecode_maintenance_oidc_source_rate_purge"
_QUOTA_RETENTION_MS: Final = MAX_WINDOW_SECONDS * 1_000


class _MaintenanceParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("maintenance arguments are invalid")


def main() -> None:
    raise SystemExit(run())


def run(arguments: Sequence[str] | None = None) -> int:
    raw_arguments = tuple(sys.argv[1:] if arguments is None else arguments)
    if raw_arguments and raw_arguments[0] in {
        "system-backup",
        "system-restore",
        "system-backup-prune",
    }:
        return _run_system_backup(raw_arguments)
    try:
        options = _parser().parse_args(raw_arguments)
        profile = RetentionProfile(
            tenant_id=options.tenant_id,
            metadata_days=options.metadata_days,
            artifact_days=options.artifact_days,
            audit_days=options.audit_days,
        )
        settings = load_settings()
        database_path, artifact_root = _existing_paths(Path(settings.data_dir))
        connection = _open_existing_database(database_path)
        try:
            _require_schema(connection)
            backup_root = lexical_absolute_path(Path(settings.data_dir) / "backup-records")
            try:
                LocalArtifactStore(backup_root)
            except (OSError, ValueError):
                raise RuntimeError("maintenance backup directory is unsafe") from None
            _require_plain_directory(backup_root)
            scm_publications = SqliteSCMPublicationStore(connection, initialize=True)
            secret_provider, secret_provider_available = build_secret_provider(os.environ)
            secrets = SecretService(secret_provider, connection)
            oidc_states = SqliteOidcLoginState(connection)
            oidc_nonces = NonceReplayLedger(connection=connection)
            residency = load_residency_registry(connection, os.environ)
            residency_region = os.environ.get("SECURECODE_DATA_REGION") or None
            storage = LocalArtifactStorageExecutor(
                connection,
                artifact_root,
                residency_guard=residency if residency_region is not None else None,
                residency_region=residency_region,
            )
            backup_storage = BackupLifecycleAdapter(
                connection,
                backup_root,
                requested_by=options.owner_id,
                residency_guard=residency if residency_region is not None else None,
                residency_region=residency_region,
                fallback=storage,
            )
            ledger = LifecycleLedger(
                connection,
                storage=backup_storage,
                residency_guard=residency if residency_region is not None else None,
                residency_region=residency_region,
            )
            reconciled_legacy_audit_deletions = ledger.reconcile_legacy_audit_deletions(
                tenant_id=profile.tenant_id,
                max_items=options.execute_limit,
            )
            legacy_audit_reconciliation_pending = (
                ledger.has_unreconciled_legacy_audit_deletions(
                    tenant_id=profile.tenant_id,
                )
            )
            planner = ArtifactRetentionPlanner(
                connection,
                requested_by=options.owner_id,
                residency_guard=residency if residency_region is not None else None,
                residency_region=residency_region,
            )
            scheduler = ApprovedDeletionScheduler(
                connection,
                ledger,
                owner_id=options.owner_id,
            )
            planned = planner.run_once(
                profile=profile,
                max_items=options.plan_limit,
            )
            backup_planned = backup_storage.plan_once(
                profile=profile,
                max_items=options.plan_limit,
            )
            executed = scheduler.run_once(
                tenant_id=profile.tenant_id,
                max_items=options.execute_limit,
            )
            scheduler_claim_purge_count = scheduler.purge_completed(
                tenant_id=profile.tenant_id,
                max_items=options.execute_limit,
            )
            scheduler_claim_cleanup_pending = scheduler.has_completed_claims(
                tenant_id=profile.tenant_id,
            )
            expired_secret_grants = secrets.expire_due_grants(
                tenant_id=profile.tenant_id,
                max_items=options.execute_limit,
            )
            secret_expiry_pending = secrets.has_due_grants(tenant_id=profile.tenant_id)
            revoked_secret_leases = 0
            if secret_provider_available:
                try:
                    revoked_secret_leases = secrets.retry_provider_revocations(
                        tenant_id=profile.tenant_id,
                        limit=options.execute_limit,
                    )
                except SecretDenied as error:
                    if error.code != "PROVIDER_UNAVAILABLE":
                        raise
            secret_revocation_pending = secrets.has_pending_provider_revocations(
                tenant_id=profile.tenant_id
            )
            session_purge_count = _purge_inactive_sessions(
                connection,
                max_items=options.execute_limit,
            )
            session_cleanup_pending = _has_inactive_sessions(connection)
            oidc_now = int(time.time())
            oidc_state_purge_count = oidc_states.purge_expired(
                now=oidc_now,
                max_items=options.execute_limit,
            )
            oidc_nonce_purge_count = oidc_nonces.purge_expired(
                now=oidc_now,
                max_items=options.execute_limit,
            )
            oidc_cleanup_pending = (
                oidc_states.has_expired(now=oidc_now)
                or oidc_nonces.has_expired(now=oidc_now)
            )
            oidc_source_rate_purge_count = _purge_expired_oidc_source_rate(
                connection,
                now=oidc_now,
                max_items=options.execute_limit,
            )
            oidc_source_rate_cleanup_pending = _has_expired_oidc_source_rate(
                connection,
                now=oidc_now,
            )
            quota_now_ms = time.time_ns() // 1_000_000
            resources = ResourceService(ResourceRepository(connection))
            expired_resource_reservations = resources.expire_all(
                now_ms=quota_now_ms,
                max_items=options.execute_limit,
                tenant_id=profile.tenant_id,
            )
            resource_expiration_pending = resources.has_expired_any(
                now_ms=quota_now_ms,
                tenant_id=profile.tenant_id,
            )
            quota_purge_count, quota_run_charge_purge_count = _purge_expired_quota_window(
                connection,
                now_ms=quota_now_ms,
                max_items=options.execute_limit,
            )
            quota_cleanup_pending = _has_expired_quota_window(
                connection,
                now_ms=quota_now_ms,
            )
            quota_run_charge_cleanup_pending = _has_expired_quota_run_charges(
                connection,
                now_ms=quota_now_ms,
            )
            request_claim_purge_count = _purge_expired_request_claims(
                connection,
                now_ms=quota_now_ms,
                max_items=options.execute_limit,
            )
            request_claim_cleanup_pending = _has_expired_request_claims(
                connection,
                now_ms=quota_now_ms,
            )
            artifact_authorization_now = datetime.now(UTC)
            artifact_authorization_purge_count = purge_expired_artifact_authorizations(
                connection,
                tenant_id=profile.tenant_id,
                now=artifact_authorization_now,
                max_items=options.execute_limit,
            )
            orphaned_artifact_object_purge_count = purge_orphaned_artifact_objects(
                connection,
                artifact_root,
                tenant_id=profile.tenant_id,
                max_items=options.execute_limit,
            )
            orphaned_artifact_cleanup_pending = (
                orphaned_artifact_object_purge_count >= options.execute_limit
            )
            artifact_authorization_cleanup_pending = has_expired_artifact_authorizations(
                connection,
                tenant_id=profile.tenant_id,
                now=artifact_authorization_now,
            )
            waiver_ledger = WaiverLedger(connection)
            expired_waiver_runs = waiver_ledger.expired_published_runs(
                tenant_id=profile.tenant_id,
                max_items=options.execute_limit,
            )
            waiver_expiry_refresh_count = 0
            waiver_expiry_refresh_pending = False
            scm_tenant = os.environ.get("SECURECODE_SCM_TENANT_ID", profile.tenant_id)
            if scm_tenant == profile.tenant_id and expired_waiver_runs:
                scm = build_scm_handlers(
                    os.environ,
                    tenant_id=scm_tenant,
                    connection=connection,
                )
                if scm.run_state is None:
                    waiver_expiry_refresh_pending = True
                else:
                    publisher = build_scm_publication_service(
                        connection=connection,
                        repository=DevelopmentRepository(connection),
                        scm=scm,
                        publications=scm_publications,
                        waiver_ledger=waiver_ledger,
                        artifact_root=artifact_root,
                        residency_guard=(
                            residency if residency_region is not None else None
                        ),
                        residency_region=residency_region,
                    )
                    for run_id, identity_hash in expired_waiver_runs:
                        try:
                            decision = load_run_scm_policy_decision(
                                connection,
                                tenant_id=profile.tenant_id,
                                run_id=run_id,
                                execution_identity_hash=identity_hash,
                            )
                            if decision is not None and _waivers_cover_run_policy(
                                connection,
                                waiver_ledger,
                                tenant_id=profile.tenant_id,
                                run_id=run_id,
                                identity_hash=identity_hash,
                                decision=decision,
                            ):
                                continue
                            receipt = publisher.refresh_after_waiver(
                                tenant_id=profile.tenant_id,
                                run_id=run_id,
                                execution_identity_hash=identity_hash,
                            )
                            if receipt.disposition in {
                                SCMCompletionDisposition.PUBLISHED,
                                SCMCompletionDisposition.REPLAYED,
                            }:
                                waiver_expiry_refresh_count += 1
                            else:
                                waiver_expiry_refresh_pending = True
                        except Exception:
                            waiver_expiry_refresh_pending = True
            elif expired_waiver_runs:
                waiver_expiry_refresh_pending = True
        finally:
            connection.close()
        conflict_count = sum(item.outcome == "CONFLICT" for item in executed)
        authentication_cleanup_pending = session_cleanup_pending or oidc_cleanup_pending
        partial = (
            conflict_count > 0
            or secret_expiry_pending
            or secret_revocation_pending
            or authentication_cleanup_pending
            or oidc_source_rate_cleanup_pending
            or quota_cleanup_pending
            or quota_run_charge_cleanup_pending
            or request_claim_cleanup_pending
            or artifact_authorization_cleanup_pending
            or orphaned_artifact_cleanup_pending
            or scheduler_claim_cleanup_pending
            or resource_expiration_pending
            or waiver_expiry_refresh_pending
            or legacy_audit_reconciliation_pending
        )
        output = {
            "schema_version": _SCHEMA_VERSION,
            "status": "partial" if partial else "ok",
            "tenant_sha256": _text_hash(profile.tenant_id),
            "owner_sha256": _text_hash(options.owner_id),
            "profile_sha256": _profile_hash(profile),
            "planned_count": len(planned),
            "planned_receipt_sha256": _planned_hash(planned),
            "backup_planned_count": len(backup_planned),
            "backup_planned_receipt_sha256": _backup_planned_hash(backup_planned),
            "executed_count": sum(item.outcome == "EXECUTED" for item in executed),
            "conflict_count": conflict_count,
            "reconciled_legacy_audit_deletion_count": reconciled_legacy_audit_deletions,
            "legacy_audit_reconciliation_pending": legacy_audit_reconciliation_pending,
            "expired_secret_grant_count": expired_secret_grants,
            "secret_expiry_pending": secret_expiry_pending,
            "revoked_secret_lease_count": revoked_secret_leases,
            "secret_revocation_pending": secret_revocation_pending,
            "purged_auth_session_count": session_purge_count,
            "purged_oidc_state_count": oidc_state_purge_count,
            "purged_oidc_nonce_count": oidc_nonce_purge_count,
            "authentication_cleanup_pending": authentication_cleanup_pending,
            "purged_oidc_source_rate_count": oidc_source_rate_purge_count,
            "oidc_source_rate_cleanup_pending": oidc_source_rate_cleanup_pending,
            "purged_quota_bucket_count": quota_purge_count,
            "quota_cleanup_pending": quota_cleanup_pending,
            "purged_quota_run_charge_count": quota_run_charge_purge_count,
            "quota_run_charge_cleanup_pending": quota_run_charge_cleanup_pending,
            "purged_request_claim_count": request_claim_purge_count,
            "request_claim_cleanup_pending": request_claim_cleanup_pending,
            "purged_artifact_authorization_count": artifact_authorization_purge_count,
            "purged_orphaned_artifact_object_count": orphaned_artifact_object_purge_count,
            "orphaned_artifact_cleanup_pending": orphaned_artifact_cleanup_pending,
            "artifact_authorization_cleanup_pending": artifact_authorization_cleanup_pending,
            "purged_scheduler_claim_count": scheduler_claim_purge_count,
            "scheduler_claim_cleanup_pending": scheduler_claim_cleanup_pending,
            "expired_resource_reservation_count": expired_resource_reservations,
            "resource_expiration_pending": resource_expiration_pending,
            "expired_waiver_status_refresh_count": waiver_expiry_refresh_count,
            "waiver_expiry_refresh_pending": waiver_expiry_refresh_pending,
            "execution_receipt_sha256": _execution_hash(executed),
        }
        _write_json(sys.stdout, output)
        return 2 if partial else 0
    except SystemExit:
        raise
    except Exception:
        _write_json(
            sys.stderr,
            {
                "schema_version": _SCHEMA_VERSION,
                "status": "error",
                "error_code": "MAINTENANCE_FAILED",
            },
        )
        return 1


def _run_system_backup(arguments: Sequence[str]) -> int:
    try:
        options = _system_parser().parse_args(arguments)
        settings = load_settings()
        if options.command == "system-backup-prune":
            purged_count, cleanup_pending = SystemOidcBackupRetention(
                Path(settings.data_dir) / "system-backups"
            ).purge_expired(
                now=int(time.time()),
                retention_days=options.retention_days,
                max_items=options.max_items,
            )
            _write_json(
                sys.stdout,
                {
                    "schema_version": _SCHEMA_VERSION,
                    "status": "partial" if cleanup_pending else "ok",
                    "purged_system_backup_count": purged_count,
                    "system_backup_cleanup_pending": cleanup_pending,
                },
            )
            return 2 if cleanup_pending else 0
        database_path = _existing_database_path(Path(settings.data_dir))
        connection = _open_existing_database(database_path)
        try:
            _require_schema(connection)
            process = configured_process(
                os.environ,
                prefix="SECURECODE_BACKUP_ENCRYPTION",
            )
            if process is None:
                raise SystemBackupError("SYSTEM_BACKUP_ENCRYPTION_UNAVAILABLE")
            encryption = SubprocessBackupEncryptionProvider(process)
            runtime = SystemOidcBackupRuntime(
                connection,
                Path(settings.data_dir) / "system-backups",
                encryption,
            )
            if options.command == "system-backup":
                record = runtime.backup(options.backup_id, options.encryption_key_ref)
                operation = "backup"
            else:
                record = runtime.restore(options.backup_id)
                operation = "restore"
        finally:
            connection.close()
        _write_json(sys.stdout, _system_receipt(operation, record))
        return 0
    except SystemExit:
        raise
    except Exception:
        _write_json(
            sys.stderr,
            {
                "schema_version": _SCHEMA_VERSION,
                "status": "error",
                "error_code": "SYSTEM_BACKUP_FAILED",
            },
        )
        return 1


def _system_parser() -> argparse.ArgumentParser:
    parser = _MaintenanceParser(
        prog="securecode-maintenance",
        description="Run a platform-scoped OIDC system backup operation.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    backup = commands.add_parser("system-backup")
    backup.add_argument("--backup-id", required=True)
    backup.add_argument("--encryption-key-ref", required=True)
    restore = commands.add_parser("system-restore")
    restore.add_argument("--backup-id", required=True)
    prune = commands.add_parser("system-backup-prune")
    prune.add_argument("--retention-days", required=True, type=_bounded_backup_retention_days)
    prune.add_argument("--max-items", type=_bounded_batch, default=32)
    return parser


def _system_receipt(
    operation: str, record: SystemOidcBackupRecord
) -> dict[str, object]:
    if operation not in {"backup", "restore"}:
        raise ValueError("system backup receipt is invalid")
    return {
        "schema_version": _SCHEMA_VERSION,
        "status": "ok",
        "operation": operation,
        "backup_id": record.backup_id,
        "system_identity": record.system_identity,
        "created_at": record.created_at,
        "plaintext_sha256": record.plaintext_sha256,
        "encrypted_sha256": record.encrypted_sha256,
        "size_bytes": record.size_bytes,
        "schema_sha256": record.schema_sha256,
        "table_counts": [list(item) for item in record.table_counts],
    }


def _parser() -> argparse.ArgumentParser:
    parser = _MaintenanceParser(
        prog="securecode-maintenance",
        description="Run one bounded lifecycle maintenance pass and exit.",
    )
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--metadata-days", required=True, type=_bounded_days)
    parser.add_argument("--artifact-days", required=True, type=_bounded_days)
    parser.add_argument("--audit-days", required=True, type=_bounded_days)
    parser.add_argument("--plan-limit", type=_bounded_batch, default=32)
    parser.add_argument("--execute-limit", type=_bounded_batch, default=32)
    return parser


def _bounded_days(value: str) -> int:
    if not value.isascii() or not value.isdigit():
        raise argparse.ArgumentTypeError("retention days must be an integer")
    parsed = int(value)
    if not 0 <= parsed <= 36_500:
        raise argparse.ArgumentTypeError("retention days are out of range")
    return parsed


def _bounded_backup_retention_days(value: str) -> int:
    if not value.isascii() or not value.isdigit():
        raise argparse.ArgumentTypeError("system backup retention days must be an integer")
    parsed = int(value)
    if not 1 <= parsed <= 36_500:
        raise argparse.ArgumentTypeError("system backup retention days are out of range")
    return parsed


def _bounded_batch(value: str) -> int:
    if not value.isascii() or not value.isdigit():
        raise argparse.ArgumentTypeError("batch size must be an integer")
    parsed = int(value)
    if not 1 <= parsed <= 256:
        raise argparse.ArgumentTypeError("batch size is out of range")
    return parsed


def _existing_paths(data_dir: Path) -> tuple[Path, Path]:
    root = lexical_absolute_path(data_dir)
    _require_directory_chain(root)
    database_path = root / "control-plane.sqlite3"
    artifact_root = root / "artifacts"
    _require_regular_file(database_path)
    _require_plain_directory(artifact_root)
    return database_path, artifact_root


def _existing_database_path(data_dir: Path) -> Path:
    root = lexical_absolute_path(data_dir)
    _require_directory_chain(root)
    database_path = root / "control-plane.sqlite3"
    _require_regular_file(database_path)
    return database_path


def _open_existing_database(path: Path) -> sqlite3.Connection:
    connection: sqlite3.Connection | None = None
    try:
        connection = open_private_sqlite(path, create=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA synchronous = FULL")
        return connection
    except sqlite3.Error as error:
        if connection is not None:
            connection.close()
        raise RuntimeError("maintenance database is unavailable") from error
    except Exception:
        if connection is not None:
            connection.close()
        raise


def _require_schema(connection: sqlite3.Connection) -> None:
    try:
        require_schema_version(connection)
    except (sqlite3.DatabaseError, SchemaVersionError):
        raise RuntimeError("maintenance schema is unavailable") from None


def _require_plain_directory(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise RuntimeError("maintenance directory is unavailable") from error
    if _link_like(details) or not stat.S_ISDIR(details.st_mode):
        raise RuntimeError("maintenance directory is unsafe")


def _require_directory_chain(path: Path) -> None:
    if not path.is_absolute() or not path.anchor:
        raise RuntimeError("maintenance directory is unsafe")
    current = Path(path.anchor)
    _require_plain_directory(current)
    for part in path.parts[1:]:
        current /= part
        _require_plain_directory(current)


def _require_regular_file(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise RuntimeError("maintenance database is unavailable") from error
    if _link_like(details) or not stat.S_ISREG(details.st_mode):
        raise RuntimeError("maintenance database is unsafe")


def _purge_inactive_sessions(
    connection: sqlite3.Connection,
    *,
    max_items: int,
) -> int:
    stamp = datetime.now(UTC).isoformat(timespec="microseconds")
    cursor = connection.cursor()
    active = False
    try:
        cursor.execute(f"SAVEPOINT {_SESSION_PURGE_SAVEPOINT}")
        active = True
        changed = cursor.execute(
            """DELETE FROM auth_sessions
               WHERE token_hash IN (
                     SELECT token_hash FROM auth_sessions
                     WHERE revoked=1 OR expires_at<=?
                     ORDER BY expires_at, token_hash LIMIT ?
                 )""",
            (stamp, max_items),
        ).rowcount
        cursor.execute(f"RELEASE SAVEPOINT {_SESSION_PURGE_SAVEPOINT}")
        active = False
        return changed
    except sqlite3.Error as error:
        if active:
            _rollback_savepoint(cursor, _SESSION_PURGE_SAVEPOINT)
        raise RuntimeError("maintenance session cleanup is unavailable") from error
    finally:
        cursor.close()


def _has_inactive_sessions(connection: sqlite3.Connection) -> bool:
    stamp = datetime.now(UTC).isoformat(timespec="microseconds")
    try:
        row = connection.execute(
            """SELECT 1 FROM auth_sessions
               WHERE revoked=1 OR expires_at<=? LIMIT 1""",
            (stamp,),
        ).fetchone()
    except sqlite3.Error as error:
        raise RuntimeError("maintenance session state is unavailable") from error
    return row is not None


def _purge_expired_request_claims(
    connection: sqlite3.Connection,
    *,
    now_ms: int,
    max_items: int,
) -> int:
    if (
        type(now_ms) is not int
        or now_ms < 0
        or type(max_items) is not int
        or not 1 <= max_items <= 256
    ):
        raise ValueError("maintenance request claim cleanup arguments are invalid")
    cutoff_ms = now_ms - _DEFAULT_CLAIM_LEASE_MS
    cursor = connection.cursor()
    active = False
    try:
        cursor.execute(f"SAVEPOINT {_REQUEST_CLAIM_PURGE_SAVEPOINT}")
        active = True
        changed = cursor.execute(
            """DELETE FROM http_idempotency_records
               WHERE rowid IN (
                   SELECT rowid FROM http_idempotency_records
                   WHERE response_status IS NULL
                     AND (claimed_at_ms IS NULL OR claimed_at_ms<=?)
                   ORDER BY claimed_at_ms, tenant_id, idempotency_key LIMIT ?
               )""",
            (cutoff_ms, max_items),
        ).rowcount
        cursor.execute(f"RELEASE SAVEPOINT {_REQUEST_CLAIM_PURGE_SAVEPOINT}")
        active = False
        return changed
    except sqlite3.Error as error:
        if active:
            _rollback_savepoint(cursor, _REQUEST_CLAIM_PURGE_SAVEPOINT)
        raise RuntimeError("maintenance request claim cleanup is unavailable") from error
    finally:
        cursor.close()


def _has_expired_request_claims(connection: sqlite3.Connection, *, now_ms: int) -> bool:
    if type(now_ms) is not int or now_ms < 0:
        raise ValueError("maintenance request claim clock is invalid")
    try:
        row = connection.execute(
            """SELECT 1 FROM http_idempotency_records
               WHERE response_status IS NULL
                 AND (claimed_at_ms IS NULL OR claimed_at_ms<=?)
               LIMIT 1""",
            (now_ms - _DEFAULT_CLAIM_LEASE_MS,),
        ).fetchone()
    except sqlite3.Error as error:
        raise RuntimeError("maintenance request claim state is unavailable") from error
    return row is not None


def _purge_expired_oidc_source_rate(
    connection: sqlite3.Connection,
    *,
    now: int,
    max_items: int,
) -> int:
    if (
        type(now) is not int
        or now < 0
        or type(max_items) is not int
        or not 1 <= max_items <= 256
    ):
        raise ValueError("maintenance OIDC source-rate cleanup arguments are invalid")
    cursor = connection.cursor()
    active = False
    try:
        cursor.execute(f"SAVEPOINT {_OIDC_SOURCE_RATE_PURGE_SAVEPOINT}")
        active = True
        changed = cursor.execute(
            """DELETE FROM oidc_login_source_rate_limit
               WHERE rowid IN (
                   SELECT rowid FROM oidc_login_source_rate_limit
                   WHERE window_started_at<=?
                     AND window_started_at + window_seconds<=?
                   ORDER BY window_started_at, bucket, source_hash LIMIT ?
               )""",
            (now, now, max_items),
        ).rowcount
        cursor.execute(f"RELEASE SAVEPOINT {_OIDC_SOURCE_RATE_PURGE_SAVEPOINT}")
        active = False
        return changed
    except sqlite3.Error as error:
        if active:
            _rollback_savepoint(cursor, _OIDC_SOURCE_RATE_PURGE_SAVEPOINT)
        raise RuntimeError("maintenance OIDC source-rate cleanup is unavailable") from error
    finally:
        cursor.close()


def _has_expired_oidc_source_rate(connection: sqlite3.Connection, *, now: int) -> bool:
    if type(now) is not int or now < 0:
        raise ValueError("maintenance OIDC source-rate clock is invalid")
    try:
        row = connection.execute(
            """SELECT 1 FROM oidc_login_source_rate_limit
               WHERE window_started_at<=?
                 AND window_started_at + window_seconds<=?
               LIMIT 1""",
            (now, now),
        ).fetchone()
    except sqlite3.Error as error:
        raise RuntimeError("maintenance OIDC source-rate state is unavailable") from error
    return row is not None


def _purge_expired_quota_window(
    connection: sqlite3.Connection,
    *,
    now_ms: int,
    max_items: int,
) -> tuple[int, int]:
    cutoff_ms = now_ms - _QUOTA_RETENTION_MS
    cursor = connection.cursor()
    active = False
    try:
        cursor.execute(f"SAVEPOINT {_QUOTA_PURGE_SAVEPOINT}")
        active = True
        changed = cursor.execute(
            """DELETE FROM request_quota_windows
               WHERE rowid IN (
                   SELECT rowid FROM request_quota_windows
                   WHERE started_ms<=?
                   ORDER BY started_ms, tenant_id LIMIT ?
               )""",
            (cutoff_ms, max_items),
        ).rowcount
        run_charges_changed = cursor.execute(
            """DELETE FROM request_quota_run_charges
               WHERE rowid IN (
                   SELECT rowid FROM request_quota_run_charges
                   WHERE created_at_ms<=?
                   ORDER BY created_at_ms, tenant_id, idempotency_key_sha256,
                            request_sha256
                   LIMIT ?
               )""",
            (cutoff_ms, max_items),
        ).rowcount
        cursor.execute(f"RELEASE SAVEPOINT {_QUOTA_PURGE_SAVEPOINT}")
        active = False
        return changed, run_charges_changed
    except sqlite3.Error as error:
        if active:
            _rollback_savepoint(cursor, _QUOTA_PURGE_SAVEPOINT)
        raise RuntimeError("maintenance quota cleanup is unavailable") from error
    finally:
        cursor.close()


def _has_expired_quota_window(
    connection: sqlite3.Connection,
    *,
    now_ms: int,
) -> bool:
    try:
        row = connection.execute(
            """SELECT 1 FROM request_quota_windows
               WHERE started_ms<=? LIMIT 1""",
            (now_ms - _QUOTA_RETENTION_MS,),
        ).fetchone()
    except sqlite3.Error as error:
        raise RuntimeError("maintenance quota state is unavailable") from error
    return row is not None


def _has_expired_quota_run_charges(
    connection: sqlite3.Connection,
    *,
    now_ms: int,
) -> bool:
    try:
        row = connection.execute(
            """SELECT 1 FROM request_quota_run_charges
               WHERE created_at_ms<=? LIMIT 1""",
            (now_ms - _QUOTA_RETENTION_MS,),
        ).fetchone()
    except sqlite3.Error as error:
        raise RuntimeError("maintenance quota idempotency state is unavailable") from error
    return row is not None


def _rollback_savepoint(cursor: sqlite3.Cursor, name: str) -> None:
    try:
        cursor.execute(f"ROLLBACK TO SAVEPOINT {name}")
        cursor.execute(f"RELEASE SAVEPOINT {name}")
    except sqlite3.Error:
        pass


def _link_like(details: os.stat_result) -> bool:
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(attributes & _REPARSE_POINT)


def _profile_hash(profile: RetentionProfile) -> str:
    return _document_hash(
        {
            "artifact_days": profile.artifact_days,
            "audit_days": profile.audit_days,
            "metadata_days": profile.metadata_days,
            "tenant_id": profile.tenant_id,
        }
    )


def _planned_hash(values: tuple[PlannedArtifactDeletion, ...]) -> str:
    return _document_hash(
        [
            {
                "content_sha256": item.content_sha256,
                "deletion_id": item.deletion_id,
                "eligible_at": item.eligible_at,
                "execution_identity_hash": item.execution_identity_hash,
                "profile_sha256": item.profile_sha256,
                "repository_id": item.repository_id,
                "requested_at": item.requested_at,
                "tenant_id": item.tenant_id,
            }
            for item in values
        ]
    )


def _backup_planned_hash(values: tuple[BackupRetentionCandidate, ...]) -> str:
    return _document_hash(
        [
            {
                "backup_id": item.backup_id,
                "content_sha256": item.content_sha256,
                "deletion_id": item.deletion_id,
                "eligible_at": item.eligible_at,
                "execution_identity_hash": item.execution_identity_hash,
                "profile_sha256": item.profile_sha256,
                "purpose": item.purpose,
                "repository_id": item.repository_id,
                "requested_at": item.requested_at,
                "tenant_id": item.tenant_id,
            }
            for item in values
        ]
    )


def _execution_hash(values: tuple[ScheduledDeletionResult, ...]) -> str:
    return _document_hash(
        [
            {
                "deletion_id": item.deletion_id,
                "execution_identity_hash": item.execution_identity_hash,
                "outcome": item.outcome,
                "resulting_version": item.resulting_version,
            }
            for item in values
        ]
    )


def _text_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _document_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _write_json(stream: TextIO, value: object) -> None:
    stream.write(
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


__all__ = ["main", "run"]


if __name__ == "__main__":
    main()
