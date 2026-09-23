"""Secret-reference, backup, and data-deletion CLI operations."""

from __future__ import annotations

from dataclasses import dataclass

from .connected_runs import (
    ConnectedCollection,
    ConnectedRunSettings,
    ResultKind,
    new_idempotency_key,
)
from .connected_transport import (
    ConnectedApi,
    ConnectedCliError,
    ConnectedCliErrorCode,
    HttpConnectedApi,
    _idempotency_key,
    _identifier,
    _precondition,
)
from .connected_validation import _printable, _sha256


@dataclass(frozen=True, slots=True)
class SecretGrantDraft:
    """Operator-supplied reference for one bounded secret grant.

    Only a reference is carried: the CLI never receives, prints or forwards
    secret material, and the control plane resolves the reference itself.
    """

    repository_id: str
    workload_id: str
    reference: str
    purpose: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.repository_id)
            or not _identifier(self.workload_id)
            or not _identifier(self.purpose)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _secret_reference(self.reference):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def _secret_reference(value: object) -> bool:
    """A bounded, printable reference — never a secret value."""

    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return False
    return all(33 <= ord(character) <= 126 for character in value)


def grant_secret(
    settings: ConnectedRunSettings,
    draft: SecretGrantDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Request one bounded secret grant for a workload."""

    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/secret-grants",
        document={
            "repository_id": draft.repository_id,
            "workload_id": draft.workload_id,
            "reference": draft.reference,
            "purpose": draft.purpose,
        },
        token=settings.token,
        idempotency_key=key,
    )
    return ConnectedCollection(
        run_id=draft.workload_id, kind=ResultKind.FINDINGS, document=document
    )


def read_secret_grant(
    settings: ConnectedRunSettings,
    grant_id: str,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read the durable state of one secret grant."""

    if not _identifier(grant_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(f"/api/v1/secret-grants/{grant_id}", token=settings.token)
    return ConnectedCollection(run_id=grant_id, kind=ResultKind.FINDINGS, document=document)


@dataclass(frozen=True, slots=True)
class BackupDraft:
    """Operator-supplied metadata for one backup request."""

    backup_id: str
    repository_id: str
    component_hashes: tuple[str, ...]
    region: str
    key_reference: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.backup_id)
            or not _identifier(self.repository_id)
            or not _identifier(self.region)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _printable(self.key_reference, maximum=512):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if (
            not isinstance(self.component_hashes, tuple)
            or not 1 <= len(self.component_hashes) <= 10_000
            or len(set(self.component_hashes)) != len(self.component_hashes)
            or any(not _sha256(item) for item in self.component_hashes)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def create_backup(
    settings: ConnectedRunSettings,
    draft: BackupDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Open one backup request over the declared component hashes."""

    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/backups",
        document={
            "backup_id": draft.backup_id,
            "repository_id": draft.repository_id,
            "component_hashes": list(draft.component_hashes),
            "region": draft.region,
            "encryption_key_ref": draft.key_reference,
        },
        token=settings.token,
        idempotency_key=key,
    )
    return ConnectedCollection(run_id=draft.backup_id, kind=ResultKind.FINDINGS, document=document)


def read_backup(
    settings: ConnectedRunSettings, backup_id: str, *, api: ConnectedApi | None = None
) -> ConnectedCollection:
    """Read one backup's durable state."""

    if not _identifier(backup_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/backups/" + backup_id, token=settings.token)
    return ConnectedCollection(run_id=backup_id, kind=ResultKind.FINDINGS, document=document)


def transition_backup(
    settings: ConnectedRunSettings,
    backup_id: str,
    *,
    restore: bool,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Execute a backup, or restore from it, against an exact observed state."""

    if not _identifier(backup_id) or not _precondition(if_match) or type(restore) is not bool:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    action = "restore" if restore else "execute"
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/backups/" + backup_id + ":" + action,
        document={},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=backup_id, kind=ResultKind.FINDINGS, document=document)


@dataclass(frozen=True, slots=True)
class DeletionDraft:
    """Operator-supplied metadata for one erasure request."""

    deletion_id: str
    repository_id: str
    content_sha256: str
    identity_hash: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.deletion_id)
            or not _identifier(self.repository_id)
            or not _sha256(self.content_sha256)
            or not _sha256(self.identity_hash)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def create_deletion(
    settings: ConnectedRunSettings,
    draft: DeletionDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Open one erasure request for an exact stored artifact."""

    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions",
        document={
            "deletion_id": draft.deletion_id,
            "repository_id": draft.repository_id,
            "content_sha256": draft.content_sha256,
            "data_class": "artifact",
            "identity_hash": draft.identity_hash,
        },
        token=settings.token,
        idempotency_key=key,
    )
    return ConnectedCollection(
        run_id=draft.deletion_id, kind=ResultKind.FINDINGS, document=document
    )


def read_deletion(
    settings: ConnectedRunSettings, deletion_id: str, *, api: ConnectedApi | None = None
) -> ConnectedCollection:
    """Read one erasure request's durable state."""

    if not _identifier(deletion_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/lifecycle/deletions/" + deletion_id, token=settings.token)
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=document)


def approve_deletion(
    settings: ConnectedRunSettings,
    deletion_id: str,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Approve one erasure request against the exact observed state."""

    if not _identifier(deletion_id) or not _precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions/" + deletion_id + ":approve",
        document={},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=document)


def hold_deletion(
    settings: ConnectedRunSettings,
    deletion_id: str,
    *,
    enabled: bool,
    identity_hash: str,
    reason: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Place or lift a legal hold on one erasure request."""

    if (
        not _identifier(deletion_id)
        or not _precondition(if_match)
        or type(enabled) is not bool
        or not _sha256(identity_hash)
        or not _printable(reason, maximum=1024)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions/" + deletion_id + ":legal-hold",
        document={"enabled": enabled, "identity_hash": identity_hash, "reason": reason},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=document)


def execute_deletion(
    settings: ConnectedRunSettings,
    deletion_id: str,
    *,
    identity_hash: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Execute one approved erasure request; the server fails closed without its executor."""

    if not _identifier(deletion_id) or not _precondition(if_match) or not _sha256(identity_hash):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions/" + deletion_id + ":execute",
        document={"identity_hash": identity_hash},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=document)
