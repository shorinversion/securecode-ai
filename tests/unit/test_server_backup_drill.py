"""P8.9 executable backup and restore drill contracts."""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace
from typing import cast

import pytest
from securecode_ai.server.backup_repository import BackupConflict, BackupRecord, BackupRepository
from securecode_ai.server.backup_service import (
    BackupExecutionResult,
    BackupExecutorUnavailable,
    BackupService,
    manifest_sha256,
)
from securecode_ai.server.operations_handler_backup import (
    BackupOperationsHandler,
    BackupScopeRepository,
)
from securecode_ai.server.ports import ServiceRequest, VerifiedIdentity


class _Executor:
    def __init__(self, *, rpo_seconds: int = 15, rto_seconds: int = 30) -> None:
        self.rpo_seconds = rpo_seconds
        self.rto_seconds = rto_seconds
        self.backups = 0
        self.restores = 0
        self.mismatch = False

    def backup(self, record: BackupRecord) -> BackupExecutionResult:
        self.backups += 1
        return self._result(record)

    def restore(self, record: BackupRecord) -> BackupExecutionResult:
        self.restores += 1
        return self._result(record)

    def _result(self, record: BackupRecord) -> BackupExecutionResult:
        assert record.manifest_sha256 is not None
        return BackupExecutionResult(
            rpo_seconds=self.rpo_seconds,
            rto_seconds=self.rto_seconds,
            manifest_sha256=("f" * 64 if self.mismatch else record.manifest_sha256),
            component_hashes=record.component_hashes,
        )


def _record(*, tenant_id: str = "tenant-1") -> BackupRecord:
    return BackupRecord(
        tenant_id=tenant_id,
        backup_id="backup-1",
        component_hashes=("a" * 64, "b" * 64),
        region="region-1",
        encryption_key_ref="key-reference-1",
        version=1,
        state="PLANNED",
    )


def _service(executor: _Executor) -> BackupService:
    return BackupService(BackupRepository.in_memory(), executor, clock=lambda: 1_000)


def test_backup_restore_drill_persists_verified_rpo_rto_receipt() -> None:
    executor = _Executor(rpo_seconds=15, rto_seconds=30)
    service = _service(executor)

    planned = service.plan(_record(), idempotency_key="plan-1")
    backed_up = service.complete_backup(
        "tenant-1", "backup-1", planned.version, idempotency_key="backup-1"
    )
    restored = service.complete_restore(
        "tenant-1", "backup-1", backed_up.version, idempotency_key="restore-1"
    )
    receipt = service.receipt(tenant_id="tenant-1", backup_id="backup-1")

    assert planned.manifest_sha256 == manifest_sha256(_record())
    assert restored.state == "RESTORED"
    assert restored.backup_verified and restored.restore_verified
    assert receipt.rpo_seconds == 15
    assert receipt.rto_seconds == 30
    assert receipt.component_count == 2
    assert executor.backups == executor.restores == 1


def test_restore_replay_is_idempotent_without_another_executor_call() -> None:
    executor = _Executor()
    service = _service(executor)
    planned = service.plan(_record())
    backed_up = service.complete_backup("tenant-1", "backup-1", planned.version)

    first = service.complete_restore(
        "tenant-1", "backup-1", backed_up.version, idempotency_key="restore-1"
    )
    replay = service.complete_restore(
        "tenant-1", "backup-1", backed_up.version, idempotency_key="restore-1"
    )

    assert replay == first
    assert executor.restores == 1


def test_plan_replay_rejects_a_changed_encryption_key_reference() -> None:
    service = _service(_Executor())
    service.plan(_record(), idempotency_key="plan-1")

    changed = replace(_record(), encryption_key_ref="different-key-reference")
    with pytest.raises(BackupConflict, match="idempotency key"):
        service.plan(changed, idempotency_key="plan-1")


def test_manifest_mismatch_does_not_claim_backup_or_restore_success() -> None:
    executor = _Executor()
    service = _service(executor)
    planned = service.plan(_record())
    executor.mismatch = True

    with pytest.raises(BackupConflict, match="manifest verification"):
        service.complete_backup("tenant-1", "backup-1", planned.version)

    assert service.receipt(tenant_id="tenant-1", backup_id="backup-1").state == "PLANNED"


def test_restore_requires_verified_backup_and_same_tenant() -> None:
    service = _service(_Executor())
    planned = service.plan(_record())

    with pytest.raises(BackupConflict, match="restore precondition"):
        service.complete_restore("tenant-1", "backup-1", planned.version)
    with pytest.raises(BackupConflict, match="unknown"):
        service.complete_backup("tenant-2", "backup-1", planned.version)


def test_executor_failure_is_explicit_and_never_marks_completion() -> None:
    class _BrokenExecutor:
        def backup(self, record: BackupRecord) -> BackupExecutionResult:
            del record
            raise RuntimeError("unavailable")

        def restore(self, record: BackupRecord) -> BackupExecutionResult:
            del record
            raise RuntimeError("unavailable")

    service = BackupService(BackupRepository.in_memory(), _BrokenExecutor())
    planned = service.plan(_record())

    with pytest.raises(BackupExecutorUnavailable):
        service.complete_backup("tenant-1", "backup-1", planned.version)


def test_malformed_executor_result_fails_closed_without_raw_type_error() -> None:
    class _MalformedExecutor:
        def backup(self, record: BackupRecord) -> BackupExecutionResult:
            del record
            return BackupExecutionResult(
                rpo_seconds=15,
                rto_seconds=30,
                manifest_sha256=cast(str, None),
                component_hashes=("a" * 64,),
            )

        def restore(self, record: BackupRecord) -> BackupExecutionResult:
            del record
            raise AssertionError("restore must not run")

    service = BackupService(BackupRepository.in_memory(), _MalformedExecutor())
    planned = service.plan(_record())

    with pytest.raises(BackupConflict, match="invalid manifest digest"):
        service.complete_backup("tenant-1", "backup-1", planned.version)

    assert service.receipt(tenant_id="tenant-1", backup_id="backup-1").state == "PLANNED"


def test_failed_create_does_not_reserve_backup_scope() -> None:
    connection = sqlite3.connect(":memory:")
    scopes = BackupScopeRepository(connection)
    handler = BackupOperationsHandler(
        BackupService(BackupRepository(connection), _Executor()),
        scopes,
        executor_available=True,
    )
    identity = VerifiedIdentity("admin-1", "tenant-1", frozenset({"admin"}))

    first = asyncio.run(
        handler.dispatch(
            _create_request(
                identity,
                backup_id="existing-backup",
                repository_id="repo-a",
                idempotency_key="request-1",
            )
        )
    )
    rejected = asyncio.run(
        handler.dispatch(
            _create_request(
                identity,
                backup_id="retryable-backup",
                repository_id="repo-b",
                idempotency_key="request-1",
            )
        )
    )

    assert first.status == 201
    assert rejected.status == 409
    assert scopes.repository(tenant_id="tenant-1", backup_id="retryable-backup") is None

    accepted = asyncio.run(
        handler.dispatch(
            _create_request(
                identity,
                backup_id="retryable-backup",
                repository_id="repo-c",
                idempotency_key="request-2",
            )
        )
    )

    assert accepted.status == 201
    assert scopes.repository(tenant_id="tenant-1", backup_id="retryable-backup") == "repo-c"


def _create_request(
    identity: VerifiedIdentity,
    *,
    backup_id: str,
    repository_id: str,
    idempotency_key: str,
) -> ServiceRequest:
    return ServiceRequest(
        method="POST",
        route="/api/v1/backups",
        action="backups.create",
        identity=identity,
        idempotency_key=idempotency_key,
        precondition=None,
        path_params={},
        query={},
        document={
            "backup_id": backup_id,
            "repository_id": repository_id,
            "component_hashes": ["a" * 64],
            "region": "region-1",
            "encryption_key_ref": "key-reference-1",
        },
        raw_body=b"{}",
    )
