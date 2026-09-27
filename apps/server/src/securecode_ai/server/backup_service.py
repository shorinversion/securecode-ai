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
    BackupRecoveryRecord,
    BackupRepository,
    recovery_request_sha256,
    validate_backup_record,
)
from .residency_registry import ResidencyConflict, ResidencyDecision, ResidencyGuard


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
        residency: ResidencyGuard | None = None,
    ) -> None:
        self.repo = repo
        self.executor = executor
        self._clock = clock or (lambda: int(time.time()))
        if residency is not None and not callable(getattr(residency, "require_region", None)):
            raise TypeError("residency guard is invalid")
        self._residency = residency
        self._transition_locks_guard = Lock()
        self._transition_locks: dict[tuple[str, str], tuple[_TransitionLock, int]] = {}

    def plan(self, record: BackupRecord, *, idempotency_key: str | None = None) -> BackupRecord:
        validate_backup_record(record)
        self._require_residency(record)
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
                return self._validated_transition_result(
                    replay,
                    tenant=tenant,
                    backup=backup,
                    expected=expected,
                    operation="backup",
                )
            transition = self.repo.transition(
                tenant_id=tenant,
                backup_id=backup,
                operation="backup",
                expected_version=expected,
                request_sha256=request_hash,
            )
            if transition is not None:
                if transition[0] == "COMMITTED":
                    assert transition[1] is not None
                    return self._validated_transition_result(
                        transition[1],
                        tenant=tenant,
                        backup=backup,
                        expected=expected,
                        operation="backup",
                    )
                item = self.repo.get(tenant, backup)
                self._require_residency(item)
                return self._recover_pending_transition(
                    item,
                    operation="backup",
                    expected=expected,
                    request_hash=request_hash,
                    idempotency_key=idempotency_key,
                )
            item = self.repo.get(tenant, backup)
            _require_manifest(item)
            if item.state != "PLANNED" or item.version != expected:
                raise BackupConflict("backup precondition failed")
            self._require_residency(item)
            if not self.repo.claim_transition(
                tenant_id=tenant,
                backup_id=backup,
                operation="backup",
                expected_version=expected,
                request_sha256=request_hash,
            ):
                return self._resolve_transition_race(
                    item,
                    operation="backup",
                    expected=expected,
                    request_hash=request_hash,
                    idempotency_key=idempotency_key,
                )
            observed = self._execute_backup(item)
            if not _matches_manifest(item, observed):
                raise BackupConflict("backup content failed manifest verification")
            # The executor may perform external I/O for an extended period.
            # Re-check placement before recording the verified result so a
            # residency change cannot be committed by a stale operation.
            self._require_residency(item)
            updated = replace(
                item,
                version=item.version + 1,
                state="BACKED_UP",
                rpo_seconds=observed.rpo_seconds,
                # A backup execution does not perform recovery. Persisting
                # its wall-clock duration as RTO would claim a restore
                # measurement that has never happened. Keep RTO unknown
                # until complete_restore records the measured restore.
                rto_seconds=None,
                backup_verified=True,
                restore_verified=False,
                completed_at=self._now(),
            )
            self._persist_record(updated)
            return self._commit_transition(
                updated,
                expected=expected,
                operation="backup",
                request_hash=request_hash,
                idempotency_key=idempotency_key,
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
                return self._validated_transition_result(
                    replay,
                    tenant=tenant,
                    backup=backup,
                    expected=expected,
                    operation="restore",
                )
            transition = self.repo.transition(
                tenant_id=tenant,
                backup_id=backup,
                operation="restore",
                expected_version=expected,
                request_sha256=request_hash,
            )
            if transition is not None:
                if transition[0] == "COMMITTED":
                    assert transition[1] is not None
                    return self._validated_transition_result(
                        transition[1],
                        tenant=tenant,
                        backup=backup,
                        expected=expected,
                        operation="restore",
                    )
                item = self.repo.get(tenant, backup)
                self._require_residency(item)
                return self._recover_pending_transition(
                    item,
                    operation="restore",
                    expected=expected,
                    request_hash=request_hash,
                    idempotency_key=idempotency_key,
                )
            item = self.repo.get(tenant, backup)
            _require_manifest(item)
            if item.state != "BACKED_UP" or item.version != expected or not item.backup_verified:
                raise BackupConflict("restore precondition failed")
            self._require_residency(item)
            if self.repo.restore_recovery(
                tenant_id=item.tenant_id,
                backup_id=item.backup_id,
                expected_version=expected,
            ) is not None:
                raise BackupConflict("restore was administratively resolved")
            if not self.repo.claim_transition(
                tenant_id=tenant,
                backup_id=backup,
                operation="restore",
                expected_version=expected,
                request_sha256=request_hash,
            ):
                return self._resolve_transition_race(
                    item,
                    operation="restore",
                    expected=expected,
                    request_hash=request_hash,
                    idempotency_key=idempotency_key,
                )
            observed = self._execute_restore(item)
            if not _matches_manifest(item, observed):
                raise BackupConflict("restored content failed manifest verification")
            self._require_residency(item)
            updated = replace(
                item,
                version=item.version + 1,
                state="RESTORED",
                rpo_seconds=observed.rpo_seconds,
                rto_seconds=observed.rto_seconds,
                restore_verified=True,
                completed_at=self._now(),
            )
            self._persist_record(updated)
            return self._commit_transition(
                updated,
                expected=expected,
                operation="restore",
                request_hash=request_hash,
                idempotency_key=idempotency_key,
            )

    def resolve_stuck_restore(
        self,
        tenant: str,
        backup: str,
        expected: int,
        *,
        actor_id: str,
        reason: str,
        evidence_ref: str,
        idempotency_key: str,
    ) -> BackupRecoveryRecord:
        """Record an explicit admin resolution without applying the restore."""

        _validate_transition_inputs(tenant, backup, expected)
        _validate_recovery_text(actor_id, "actor_id", maximum=256)
        _validate_recovery_text(reason, "reason", maximum=512)
        _validate_recovery_identifier(evidence_ref, "evidence_ref")
        _validate_recovery_text(idempotency_key, "idempotency_key", maximum=128)
        with self._transition_lock(tenant, backup):
            item = self.repo.get(tenant, backup)
            _require_manifest(item)
            if (
                item.state != "BACKED_UP"
                or item.version != expected
                or not item.backup_verified
            ):
                raise BackupConflict("restore resolution precondition failed")
            self._require_residency(item)
            restore_request_hash = _transition_hash("restore", tenant, backup, expected)
            resolution_request_hash = recovery_request_sha256(
                tenant_id=tenant,
                backup_id=backup,
                expected_version=expected,
                restore_request_sha256=restore_request_hash,
                idempotency_key=idempotency_key,
                actor_id=actor_id,
                reason=reason,
                evidence_ref=evidence_ref,
            )
            return self.repo.resolve_stuck_restore(
                tenant_id=tenant,
                backup_id=backup,
                expected_version=expected,
                restore_request_sha256=restore_request_hash,
                resolution_request_sha256=resolution_request_hash,
                idempotency_key=idempotency_key,
                actor_id=actor_id,
                reason=reason,
                evidence_ref=evidence_ref,
                resolved_at=self._now(),
            )

    def receipt(self, *, tenant_id: str, backup_id: str) -> BackupReceipt:
        item = self.repo.get(tenant_id, backup_id)
        self._require_residency(item)
        _require_manifest(item)
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

    def _persist_record(self, item: BackupRecord) -> None:
        persist = getattr(self.executor, "persist_record", None)
        if not callable(persist):
            return
        try:
            persist(item)
        except Exception as error:
            raise BackupExecutorUnavailable("backup record storage failed") from error

    def _commit_transition(
        self,
        value: BackupRecord,
        *,
        expected: int,
        operation: str,
        request_hash: str,
        idempotency_key: str | None,
    ) -> BackupRecord:
        """Commit a verified result and reconcile a concurrent durable commit.

        The executor may already have persisted the result before SQLite commits.
        If the local commit fails, a retry must be able to observe the transition
        journal instead of leaking a raw database exception to the control plane.
        """

        try:
            self._require_residency(value)
            saved = self.repo.save(
                value,
                expected,
                idempotency_key=idempotency_key,
                operation=(
                    "complete-backup" if operation == "backup" else "complete-restore"
                )
                if idempotency_key is not None
                else None,
                request_sha256=request_hash if idempotency_key is not None else None,
                transition_operation=operation,
                transition_expected=expected,
                transition_request_sha256=request_hash,
            )
            return self._validated_transition_result(
                saved,
                tenant=value.tenant_id,
                backup=value.backup_id,
                expected=expected,
                operation=operation,
            )
        except BackupConflict:
            raise
        except Exception as error:
            try:
                transition = self.repo.transition(
                    tenant_id=value.tenant_id,
                    backup_id=value.backup_id,
                    operation=operation,
                    expected_version=expected,
                    request_sha256=request_hash,
                )
            except Exception:
                transition = None
            if transition is not None and transition[0] == "COMMITTED":
                assert transition[1] is not None
                return self._validated_transition_result(
                    transition[1],
                    tenant=value.tenant_id,
                    backup=value.backup_id,
                    expected=expected,
                    operation=operation,
                )
            raise BackupExecutorUnavailable(
                "backup transition could not be committed"
            ) from error

    def _resolve_transition_race(
        self,
        item: BackupRecord,
        *,
        operation: str,
        expected: int,
        request_hash: str,
        idempotency_key: str | None,
    ) -> BackupRecord:
        transition = self.repo.transition(
            tenant_id=item.tenant_id,
            backup_id=item.backup_id,
            operation=operation,
            expected_version=expected,
            request_sha256=request_hash,
        )
        if transition is None:
            raise BackupExecutorUnavailable("backup transition claim was lost")
        if transition[0] == "COMMITTED":
            assert transition[1] is not None
            return self._validated_transition_result(
                transition[1],
                tenant=item.tenant_id,
                backup=item.backup_id,
                expected=expected,
                operation=operation,
            )
        if operation == "restore" and self.repo.restore_recovery(
            tenant_id=item.tenant_id,
            backup_id=item.backup_id,
            expected_version=expected,
        ) is not None:
            raise BackupConflict("restore was administratively resolved")
        return self._recover_pending_transition(
            item,
            operation=operation,
            expected=expected,
            request_hash=request_hash,
            idempotency_key=idempotency_key,
        )

    def _recover_pending_transition(
        self,
        item: BackupRecord,
        *,
        operation: str,
        expected: int,
        request_hash: str,
        idempotency_key: str | None,
    ) -> BackupRecord:
        transition = self.repo.transition(
            tenant_id=item.tenant_id,
            backup_id=item.backup_id,
            operation=operation,
            expected_version=expected,
            request_sha256=request_hash,
        )
        if transition is None:
            raise BackupExecutorUnavailable("backup transition claim was lost")
        if transition[0] == "COMMITTED":
            assert transition[1] is not None
            return self._validated_transition_result(
                transition[1],
                tenant=item.tenant_id,
                backup=item.backup_id,
                expected=expected,
                operation=operation,
            )
        if operation == "restore" and self.repo.restore_recovery(
            tenant_id=item.tenant_id,
            backup_id=item.backup_id,
            expected_version=expected,
        ) is not None:
            raise BackupConflict("restore was administratively resolved")
        recover = getattr(self.executor, "recover_transition", None)
        if not callable(recover):
            raise BackupExecutorUnavailable("backup transition outcome is indeterminate")
        try:
            recovered = recover(item, operation=operation)
            if recovered is None:
                raise BackupExecutorUnavailable(
                    "backup transition outcome is indeterminate"
                )
            validate_backup_record(recovered)
            _require_manifest(recovered)
            expected_state = "BACKED_UP" if operation == "backup" else "RESTORED"
            if (
                recovered.tenant_id != item.tenant_id
                or recovered.backup_id != item.backup_id
                or recovered.version != expected + 1
                or recovered.state != expected_state
                or recovered.component_hashes != item.component_hashes
                or recovered.region != item.region
                or recovered.encryption_key_ref != item.encryption_key_ref
                or recovered.manifest_sha256 != item.manifest_sha256
                or not recovered.backup_verified
                or (operation == "backup" and recovered.rto_seconds is not None)
                or (operation == "restore" and not recovered.restore_verified)
            ):
                raise BackupExecutorUnavailable(
                    "stored backup transition does not match its intent"
                )
            self._require_residency(recovered)
        except BackupExecutorUnavailable:
            raise
        except Exception as error:
            raise BackupExecutorUnavailable(
                "backup transition outcome is indeterminate"
            ) from error
        try:
            saved = self.repo.save(
                recovered,
                expected,
                idempotency_key=idempotency_key,
                operation=(
                    "complete-backup" if operation == "backup" else "complete-restore"
                )
                if idempotency_key is not None
                else None,
                request_sha256=request_hash if idempotency_key is not None else None,
                transition_operation=operation,
                transition_expected=expected,
                transition_request_sha256=request_hash,
            )
            return self._validated_transition_result(
                saved,
                tenant=item.tenant_id,
                backup=item.backup_id,
                expected=expected,
                operation=operation,
            )
        except Exception as error:
            try:
                transition = self.repo.transition(
                    tenant_id=item.tenant_id,
                    backup_id=item.backup_id,
                    operation=operation,
                    expected_version=expected,
                    request_sha256=request_hash,
                )
            except Exception:
                transition = None
            if transition is not None and transition[0] == "COMMITTED":
                assert transition[1] is not None
                return self._validated_transition_result(
                    transition[1],
                    tenant=item.tenant_id,
                    backup=item.backup_id,
                    expected=expected,
                    operation=operation,
                )
            raise BackupExecutorUnavailable(
                "recovered backup transition could not be committed"
            ) from error

    def _validated_transition_result(
        self,
        value: BackupRecord,
        *,
        tenant: str,
        backup: str,
        expected: int,
        operation: str,
    ) -> BackupRecord:
        expected_state = "BACKED_UP" if operation == "backup" else "RESTORED"
        try:
            validate_backup_record(value)
        except (BackupConflict, TypeError, ValueError) as error:
            raise BackupConflict("backup transition result is invalid") from error
        if (
            value.tenant_id != tenant
            or value.backup_id != backup
            or value.version != expected + 1
            or value.state != expected_state
        ):
            raise BackupConflict("backup transition result scope is invalid")
        _require_manifest(value)
        self._require_residency(value)
        return value

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0:
            raise BackupConflict("clock returned an invalid timestamp")
        return value

    def _require_residency(self, item: BackupRecord) -> None:
        guard = self._residency
        if guard is None:
            return
        try:
            decision = guard.require_region(tenant_id=item.tenant_id, region=item.region)
        except ResidencyConflict as error:
            raise BackupConflict("backup region is not permitted by residency policy") from error
        except Exception as error:
            raise BackupConflict("backup residency check failed") from error
        if (
            type(decision) is not ResidencyDecision
            or decision.tenant_id != item.tenant_id
            or decision.source_region != item.region
            or decision.destination_region != item.region
            or not decision.same_region
        ):
            raise BackupConflict("residency guard returned an invalid decision")

    @contextmanager
    def _transition_lock(self, tenant: str, backup: str) -> Iterator[None]:
        key = (tenant, backup)
        with self._transition_locks_guard:
            entry = self._transition_locks.get(key)
            lock: _TransitionLock
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
    if type(result) is not BackupExecutionResult:
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
        or len(result.component_hashes) > 10_000
    ):
        raise BackupConflict("executor returned invalid component hashes")
    for digest in result.component_hashes:
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise BackupConflict("executor returned an invalid component digest")
    if len(set(result.component_hashes)) != len(result.component_hashes):
        raise BackupConflict("executor returned invalid component hashes")


def _matches_manifest(item: BackupRecord, result: BackupExecutionResult) -> bool:
    return (
        item.manifest_sha256 is not None
        and item.manifest_sha256 == manifest_sha256(item)
        and result.manifest_sha256 == item.manifest_sha256
        and result.component_hashes == item.component_hashes
    )


def _require_manifest(record: BackupRecord) -> None:
    if record.manifest_sha256 != manifest_sha256(record):
        raise BackupConflict("backup manifest is invalid")


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
