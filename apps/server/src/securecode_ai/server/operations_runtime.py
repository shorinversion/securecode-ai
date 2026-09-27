"""Composition helpers for optional secret and backup control-plane ports."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .backup_executor_runtime import build_backup_executor
from .backup_repository import BackupRepository
from .backup_service import BackupService
from .operations_handler_common import error
from .operations_handler_backup import BackupOperationsHandler, BackupScopeRepository
from .operations_handler_secrets import (
    SecretGrantScopeRepository,
    SecretOperationsHandler,
)
from .ports import ServiceRequest, ServiceResponse
from .residency_registry import ResidencyGuard
from .secret_provider_runtime import build_secret_provider
from .secret_service import SecretService


class _RuntimeBackupOperationsHandler(BackupOperationsHandler):
    """Keep backup admission fail-closed with an actionable machine error."""

    _UNAVAILABLE_MESSAGE = (
        "configure a hash-pinned backup executor via "
        "SECURECODE_BACKUP_EXECUTOR_EXECUTABLE and "
        "SECURECODE_BACKUP_EXECUTOR_EXECUTABLE_SHA256, or provide the "
        "equivalent hash-pinned SECURECODE_BACKUP_ENCRYPTION adapter"
    )

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if (
            request.action in {"backups.execute", "backups.restore"}
            and "admin" in request.identity.roles
            and not self._executor_available
        ):
            return error(
                503,
                "BACKUP_EXECUTOR_UNAVAILABLE",
                self._UNAVAILABLE_MESSAGE,
            )
        return await super().dispatch(request)


@dataclass(frozen=True, slots=True)
class OperationalServiceHandlers:
    secrets: SecretOperationsHandler
    backups: BackupOperationsHandler
    secrets_available: bool
    backups_available: bool


def build_operational_handlers(
    values: object,
    connection: sqlite3.Connection,
    *,
    residency: ResidencyGuard | None = None,
) -> OperationalServiceHandlers:
    if not isinstance(connection, sqlite3.Connection):
        raise TypeError("connection must be a sqlite3 connection")
    secret_provider, secret_provider_available = build_secret_provider(values)
    backup_executor, backup_executor_available = build_backup_executor(
        values, connection=connection
    )
    return OperationalServiceHandlers(
        secrets=SecretOperationsHandler(
            SecretService(secret_provider, connection),
            SecretGrantScopeRepository(connection),
            provider_available=secret_provider_available,
        ),
        backups=_RuntimeBackupOperationsHandler(
            BackupService(
                BackupRepository(connection),
                backup_executor,
                residency=residency,
            ),
            BackupScopeRepository(connection),
            executor_available=backup_executor_available,
        ),
        secrets_available=secret_provider_available,
        backups_available=backup_executor_available,
    )


__all__ = ["OperationalServiceHandlers", "build_operational_handlers"]
