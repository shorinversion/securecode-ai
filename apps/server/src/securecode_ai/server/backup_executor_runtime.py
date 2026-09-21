"""Configurable local backup and restore subprocess composition."""

from __future__ import annotations

from .backup_repository import BackupRecord
from .backup_service import BackupExecutionResult, BackupExecutor
from .subprocess_protocol import (
    PinnedJsonProcess,
    SubprocessProtocolError,
    configured_process,
)


class SubprocessBackupExecutor:
    """Execute backup operations through one hash-pinned local process."""

    def __init__(self, process: PinnedJsonProcess) -> None:
        if not isinstance(process, PinnedJsonProcess):
            raise TypeError("process must be a PinnedJsonProcess")
        self._process = process

    def backup(self, record: BackupRecord) -> BackupExecutionResult:
        return self._execute("backup", record)

    def restore(self, record: BackupRecord) -> BackupExecutionResult:
        return self._execute("restore", record)

    def _execute(self, operation: str, record: BackupRecord) -> BackupExecutionResult:
        if record.manifest_sha256 is None:
            raise SubprocessProtocolError("BACKUP_MANIFEST_MISSING")
        response = self._process.request(
            {
                "backup_id": record.backup_id,
                "component_hashes": list(record.component_hashes),
                "encryption_key_ref": record.encryption_key_ref,
                "manifest_sha256": record.manifest_sha256,
                "operation": operation,
                "region": record.region,
                "schema_version": 1,
                "tenant_id": record.tenant_id,
            }
        )
        expected = {
            "component_hashes",
            "manifest_sha256",
            "rpo_seconds",
            "rto_seconds",
            "schema_version",
            "status",
        }
        if set(response) != expected:
            raise SubprocessProtocolError("BACKUP_RESPONSE_INVALID")
        if response.get("schema_version") != 1 or response.get("status") != "ok":
            raise SubprocessProtocolError("BACKUP_RESPONSE_INVALID")
        components = response.get("component_hashes")
        manifest = response.get("manifest_sha256")
        rpo = response.get("rpo_seconds")
        rto = response.get("rto_seconds")
        if (
            type(components) is not list
            or not all(type(value) is str for value in components)
            or tuple(components) != record.component_hashes
            or manifest != record.manifest_sha256
            or type(rpo) is not int
            or type(rto) is not int
        ):
            raise SubprocessProtocolError("BACKUP_RESPONSE_INVALID")
        return BackupExecutionResult(
            rpo_seconds=rpo,
            rto_seconds=rto,
            manifest_sha256=manifest,
            component_hashes=tuple(components),
        )


class UnavailableBackupExecutor:
    """Reject backup and restore instead of manufacturing verification evidence."""

    def backup(self, record: BackupRecord) -> BackupExecutionResult:
        del record
        raise RuntimeError("backup executor is unavailable")

    def restore(self, record: BackupRecord) -> BackupExecutionResult:
        del record
        raise RuntimeError("backup executor is unavailable")


def build_backup_executor(values: object) -> tuple[BackupExecutor, bool]:
    process = configured_process(values, prefix="SECURECODE_BACKUP_EXECUTOR")
    if process is None:
        return UnavailableBackupExecutor(), False
    return SubprocessBackupExecutor(process), True


__all__ = [
    "SubprocessBackupExecutor",
    "UnavailableBackupExecutor",
    "build_backup_executor",
]
