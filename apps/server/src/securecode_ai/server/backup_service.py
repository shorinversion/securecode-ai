"""Backup and restore orchestration with manifest verification."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from threading import Lock, RLock
from typing import Protocol

from .backup_repository import (
    BackupConflict,
    BackupRecord,
    BackupRepository,
    validate_backup_record,
)


class BackupExecutorUnavailable(BackupConflict):
    """The configured backup port could not execute the requested operation."""


@dataclass(frozen=True, slots=True)
class BackupExecutionResult:
    """Source-free observation returned by a real backup executor."""

    rpo_seconds: int
    rto_seconds: int
    manifest_sha256: str
    component_hashes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BackupReceipt:
    """Source-free durable receipt with no key material or key reference."""

    tenant_id: str
    backup_id: str
    state: str
    manifest_sha256: str
    component_count: int
    version: int
    backup_verified: bool
    restore_verified: bool
    rpo_seconds: int | None
    rto_seconds: int | None
    completed_at: int | None


class BackupExecutor(Protocol):
    def backup(self, record: BackupRecord) -> BackupExecutionResult: ...

    def restore(self, record: BackupRecord) -> BackupExecutionResult: ...


class _TransitionLock(Protocol):
    def acquire(self) -> bool: ...

    def release(self) -> None: ...


class BackupService:
    """Coordinates external I/O and persists only verified state transitions."""

    def __init__(
        self,
        repo: BackupRepository,
        executor: BackupExecutor,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        self.repo = repo
        self.executor = executor
        self._clock = clock or (lambda: int(time.time()))
        self._transition_locks_guard = Lock()
        self._transition_locks: dict[tuple[str, str], tuple[_TransitionLock, int]] = {}

    def plan(self, record: BackupRecord, *, idempotency_key: str | None = None) -> BackupRecord:
        validate_backup_record(record)
        if (
            record.state != "PLANNED"
            or record.version != 1
            or record.rpo_seconds is not None
            or record.rto_seconds is not None
            or record.backup_verified
            or record.restore_verified
            or record.completed_at is not None
        ):
            raise BackupConflict("backup plan is not initial")
        if not record.component_hashes or not record.encryption_key_ref:
            raise BackupConflict("backup plan is incomplete")
        manifest = manifest_sha256(record)
        if record.manifest_sha256 not in (None, manifest):
            raise BackupConflict("backup manifest does not match the plan")
        planned = replace(
            record,
            manifest_sha256=manifest,
            created_at=record.created_at or self._now(),
        )
        # created_at and manifest_sha256 are derived by this method.  They must
        # not change the identity of a retried plan request.
        request_hash = _request_hash("plan", record)
        return self.repo.save(
            planned,
            None,
            idempotency_key=idempotency_key,
            operation="plan" if idempotency_key is not None else None,
            request_sha256=request_hash if idempotency_key is not None else None,
        )

    def complete_backup(
        self,
        tenant: str,
        backup: str,
        expected: int,
        *,
        idempotency_key: str | None = None,
    ) -> BackupRecord:
        _validate_transition_inputs(tenant, backup, expected)
        with self._transition_lock(tenant, backup):
            request_hash = _transition_hash("backup", tenant, backup, expected)
            replay = self.repo.replay(
                tenant_id=tenant,
                idempotency_key=idempotency_key,
                operation="complete-backup",
                request_sha256=request_hash,
            )
            if replay is not None:
                return replay
            item = self.repo.get(tenant, backup)
            if item.state != "PLANNED" or item.version != expected:
                raise BackupConflict("backup precondition failed")
            observed = self._execute_backup(item)
            if not _matches_manifest(item, observed):
                raise BackupConflict("backup content failed manifest verification")
            updated = replace(
                item,
                version=item.version + 1,
                state="BACKED_UP",
                rpo_seconds=observed.rpo_seconds,
                rto_seconds=observed.rto_seconds,
                backup_verified=True,
                restore_verified=False,
                completed_at=self._now(),
            )
            return self.repo.save(
                updated,
                expected,
                idempotency_key=idempotency_key,
                operation="complete-backup" if idempotency_key is not None else None,
                request_sha256=request_hash if idempotency_key is not None else None,
            )

    def complete_restore(
        self,
        tenant: str,
        backup: str,
        expected: int,
        *,
        idempotency_key: str | None = None,
    ) -> BackupRecord:
        _validate_transition_inputs(tenant, backup, expected)
        with self._transition_lock(tenant, backup):
            request_hash = _transition_hash("restore", tenant, backup, expected)
            replay = self.repo.replay(
                tenant_id=tenant,
                idempotency_key=idempotency_key,
                operation="complete-restore",
                request_sha256=request_hash,
            )
            if replay is not None:
                return replay
            item = self.repo.get(tenant, backup)
            if item.state != "BACKED_UP" or item.version != expected or not item.backup_verified:
                raise BackupConflict("restore precondition failed")
            observed = self._execute_restore(item)
            if not _matches_manifest(item, observed):
                raise BackupConflict("restored content failed manifest verification")
            updated = replace(
                item,
                version=item.version + 1,
                state="RESTORED",
                rpo_seconds=observed.rpo_seconds,
                rto_seconds=observed.rto_seconds,
                restore_verified=True,
                completed_at=self._now(),
            )
            return self.repo.save(
                updated,
                expected,
                idempotency_key=idempotency_key,
                operation="complete-restore" if idempotency_key is not None else None,
                request_sha256=request_hash if idempotency_key is not None else None,
            )

    def receipt(self, *, tenant_id: str, backup_id: str) -> BackupReceipt:
        item = self.repo.get(tenant_id, backup_id)
        if item.manifest_sha256 is None:
            raise BackupConflict("backup manifest is missing")
        return BackupReceipt(
            tenant_id=item.tenant_id,
            backup_id=item.backup_id,
            state=item.state,
            manifest_sha256=item.manifest_sha256,
            component_count=len(item.component_hashes),
            version=item.version,
            backup_verified=item.backup_verified,
            restore_verified=item.restore_verified,
            rpo_seconds=item.rpo_seconds,
            rto_seconds=item.rto_seconds,
            completed_at=item.completed_at,
        )

    def _execute_backup(self, item: BackupRecord) -> BackupExecutionResult:
        try:
            result = self.executor.backup(item)
        except Exception as error:
            raise BackupExecutorUnavailable("backup executor failed") from error
        return _validated_result(result)

    def _execute_restore(self, item: BackupRecord) -> BackupExecutionResult:
        try:
            result = self.executor.restore(item)
        except Exception as error:
            raise BackupExecutorUnavailable("restore executor failed") from error
        return _validated_result(result)

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0:
            raise BackupConflict("clock returned an invalid timestamp")
        return value

    @contextmanager
    def _transition_lock(self, tenant: str, backup: str) -> Iterator[None]:
        key = (tenant, backup)
        with self._transition_locks_guard:
            entry = self._transition_locks.get(key)
            if entry is None:
                lock = RLock()
                count = 0
            else:
                lock, count = entry
            self._transition_locks[key] = (lock, count + 1)
        lock.acquire()
        try:
            yield
        finally:
            lock.release()
            with self._transition_locks_guard:
                current = self._transition_locks.get(key)
                if current is not None and current[0] is lock:
                    if current[1] == 1:
                        del self._transition_locks[key]
                    else:
                        self._transition_locks[key] = (lock, current[1] - 1)


def manifest_sha256(record: BackupRecord) -> str:
    """Build a deterministic manifest digest without secrets or payload bytes."""

    document = {
        "backup_id": record.backup_id,
        "component_hashes": list(record.component_hashes),
        "region": record.region,
        "tenant_id": record.tenant_id,
    }
    payload = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _validated_result(result: object) -> BackupExecutionResult:
    if not isinstance(result, BackupExecutionResult):
        raise BackupConflict("executor returned an unverifiable result")
    _validate_execution_result(result)
    return result


def _validate_execution_result(result: BackupExecutionResult) -> None:
    for duration in (result.rpo_seconds, result.rto_seconds):
        if type(duration) is not int or duration < 0 or duration > 315360000:
            raise BackupConflict("executor returned an invalid duration")
    if (
        type(result.manifest_sha256) is not str
        or len(result.manifest_sha256) != 64
        or any(char not in "0123456789abcdef" for char in result.manifest_sha256)
    ):
        raise BackupConflict("executor returned an invalid manifest digest")
    if (
        type(result.component_hashes) is not tuple
        or not result.component_hashes
        or len(set(result.component_hashes)) != len(result.component_hashes)
    ):
        raise BackupConflict("executor returned invalid component hashes")
    for digest in result.component_hashes:
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise BackupConflict("executor returned an invalid component digest")


def _matches_manifest(item: BackupRecord, result: BackupExecutionResult) -> bool:
    return (
        item.manifest_sha256 is not None
        and result.manifest_sha256 == item.manifest_sha256
        and result.component_hashes == item.component_hashes
    )


def _transition_hash(operation: str, tenant: str, backup: str, expected: int) -> str:
    return hashlib.sha256(f"{operation}\0{tenant}\0{backup}\0{expected}".encode()).hexdigest()


def _validate_transition_inputs(tenant: object, backup: object, expected: object) -> None:
    if (
        type(tenant) is not str
        or type(backup) is not str
        or not tenant
        or not backup
        or type(expected) is not int
        or expected < 1
    ):
        raise BackupConflict("backup precondition is invalid")


def _request_hash(operation: str, record: BackupRecord) -> str:
    document = {
        "operation": operation,
        "tenant_id": record.tenant_id,
        "backup_id": record.backup_id,
        "component_hashes": list(record.component_hashes),
        "region": record.region,
        "encryption_key_ref": record.encryption_key_ref,
        "version": record.version,
        "state": record.state,
    }
    if operation != "plan":
        document["manifest_sha256"] = record.manifest_sha256
    payload = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


__all__ = [
    "BackupExecutionResult",
    "BackupExecutor",
    "BackupExecutorUnavailable",
    "BackupReceipt",
    "BackupService",
    "manifest_sha256",
]
