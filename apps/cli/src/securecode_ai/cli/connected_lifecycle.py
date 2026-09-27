"""Secret-reference, backup, and data-deletion CLI operations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from .connected_runs import ConnectedCollection, ConnectedRunSettings, ResultKind
from .connected_transport import (
    ConnectedApi,
    ConnectedCliError,
    ConnectedCliErrorCode,
    HttpConnectedApi,
    _idempotency_key,
    _identifier,
    _version_precondition,
)
from .connected_validation import _printable, _sha256, _text


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
            or type(self.purpose) is not str
            or self.purpose not in _SECRET_PURPOSES
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _secret_reference(self.reference):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def _secret_reference(value: object) -> bool:
    """A bounded, printable reference — never a secret value."""

    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return False
    return all(33 <= ord(character) <= 126 for character in value)


_SECRET_PURPOSES = frozenset({"github_installation", "provider_api", "artifact_store"})
_SECRET_STATES = frozenset({"ACTIVE", "REVOKED", "EXPIRED"})
_BACKUP_STATES = frozenset({"PLANNED", "BACKED_UP", "RESTORED"})
_DELETION_STATES = frozenset({"REQUESTED", "APPROVED", "HELD", "EXECUTED"})


@dataclass(frozen=True, slots=True)
class WaiverDraft:
    """Operator-supplied waiver bound to one approved finding."""

    waiver_id: str
    approval_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    expires_at: str
    policy_scope: str | None = None

    def __post_init__(self) -> None:
        if any(
            not _identifier(value)
            for value in (
                self.waiver_id,
                self.approval_id,
                self.repository_id,
                self.run_id,
            )
        ) or not _sha256(self.execution_identity_hash) or not _utc_timestamp(self.expires_at):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if self.policy_scope is not None and not _identifier(self.policy_scope):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def _utc_timestamp(value: object) -> bool:
    if type(value) is not str or not 20 <= len(value) <= 40:
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == UTC.utcoffset(parsed)


def _validated_waiver_receipt(
    document: object,
    *,
    expected_waiver_id: str | None = None,
    expected_repository_id: str | None = None,
    expected_version: int | None = None,
    expected_active: bool | None = None,
) -> dict[str, object]:
    fields = {
        "waiver_id",
        "tenant_id",
        "repository_id",
        "run_id",
        "execution_identity_hash",
        "finding_fingerprint",
        "policy_scope",
        "expires_at",
        "approval_id",
        "rationale_sha256",
        "version",
        "active",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if (
        any(
            not _identifier(document.get(name))
            for name in ("waiver_id", "tenant_id", "repository_id", "run_id", "approval_id")
        )
        or not _sha256(document.get("execution_identity_hash"))
        or not _sha256(document.get("finding_fingerprint"))
        or (
            document.get("policy_scope") is not None
            and not _identifier(document.get("policy_scope"))
        )
        or not _utc_timestamp(document.get("expires_at"))
        or not _sha256(document.get("rationale_sha256"))
        or type(document.get("version")) is not int
        or not 1 <= document["version"] <= 2_147_483_647
        or type(document.get("active")) is not bool
        or (expected_waiver_id is not None and document["waiver_id"] != expected_waiver_id)
        or (
            expected_repository_id is not None
            and document["repository_id"] != expected_repository_id
        )
        or (expected_version is not None and document["version"] != expected_version)
        or (expected_active is not None and document["active"] is not expected_active)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return {name: document[name] for name in fields}


def _operation_key(
    settings: ConnectedRunSettings,
    operation: str,
    resource_id: str,
    payload: Mapping[str, object],
    explicit: str | None,
) -> str:
    """Derive one replay-safe key per logical operation.

    The environment key is a stable command seed.  Resource and payload
    binding prevents two lifecycle resources from accidentally sharing a
    server idempotency record while retries of the same command keep the same
    key after a process restart.
    """

    if explicit is not None:
        if not _idempotency_key(explicit):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        return explicit
    key = settings.idempotency_key
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if type(operation) is not str or not operation or type(resource_id) is not str:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    try:
        material = json.dumps(
            {
                "operation": operation,
                "payload": dict(payload),
                "resource_id": resource_id,
                "seed": key,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeEncodeError):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
    return "cli-" + hashlib.sha256(material).hexdigest()[:48]


def _validated_secret_receipt(
    document: object,
    *,
    expected_grant_id: str | None = None,
    expected_repository_id: str | None = None,
    expected_workload_id: str | None = None,
) -> dict[str, object]:
    fields = {
        "tenant_id",
        "workload_id",
        "purpose",
        "handle_sha256",
        "expires_at",
        "grant_id",
        "state",
        "version",
        "issued_at",
        "repository_id",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if (
        not all(_identifier(document.get(name)) for name in ("tenant_id", "workload_id", "grant_id", "repository_id"))
        or type(document.get("purpose")) is not str
        or document.get("purpose") not in _SECRET_PURPOSES
        or not _sha256(document.get("handle_sha256"))
        or type(document.get("state")) is not str
        or document.get("state") not in _SECRET_STATES
        or type(document.get("expires_at")) is not int
        or type(document.get("issued_at")) is not int
        or document["issued_at"] < 0
        or document["expires_at"] <= document["issued_at"]
        or document["expires_at"] > 9_223_372_036_854_775_807
        or type(document.get("version")) is not int
        or not 1 <= document["version"] <= 2_147_483_647
        or (expected_grant_id is not None and document["grant_id"] != expected_grant_id)
        or (
            expected_repository_id is not None
            and document["repository_id"] != expected_repository_id
        )
        or (
            expected_workload_id is not None
            and document["workload_id"] != expected_workload_id
        )
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return {name: document[name] for name in fields}


def _validated_backup_receipt(
    document: object,
    *,
    expected_backup_id: str | None = None,
    expected_repository_id: str | None = None,
) -> dict[str, object]:
    fields = {
        "tenant_id",
        "backup_id",
        "repository_id",
        "state",
        "manifest_sha256",
        "component_count",
        "version",
        "backup_verified",
        "restore_verified",
        "rpo_seconds",
        "rto_seconds",
        "completed_at",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if (
        not _identifier(document.get("tenant_id"))
        or not _identifier(document.get("backup_id"))
        or not _identifier(document.get("repository_id"))
        or type(document.get("state")) is not str
        or document.get("state") not in _BACKUP_STATES
        or document.get("manifest_sha256") is not None
        and not _sha256(document.get("manifest_sha256"))
        or type(document.get("component_count")) is not int
        or not 1 <= document["component_count"] <= 10_000
        or type(document.get("version")) is not int
        or not 1 <= document["version"] <= 2_147_483_647
        or type(document.get("backup_verified")) is not bool
        or type(document.get("restore_verified")) is not bool
        or any(
            value is not None and (type(value) is not int or value < 0)
            for value in (document.get("rpo_seconds"), document.get("rto_seconds"), document.get("completed_at"))
        )
        or document["restore_verified"] and not document["backup_verified"]
        or document["state"] == "PLANNED"
        and (document["backup_verified"] or document["restore_verified"])
        or document["state"] == "BACKED_UP"
        and (not document["backup_verified"] or document["restore_verified"])
        or document["state"] == "RESTORED"
        and (not document["backup_verified"] or not document["restore_verified"])
        or (expected_backup_id is not None and document["backup_id"] != expected_backup_id)
        or (
            expected_repository_id is not None
            and document["repository_id"] != expected_repository_id
        )
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return {name: document[name] for name in fields}


def _validated_backup_recovery(
    document: object,
    *,
    expected_backup_id: str,
    expected_repository_id: str,
    expected_version: int,
) -> dict[str, object]:
    """Whitelist the immutable administrative restore-resolution receipt."""

    fields = {
        "tenant_id",
        "backup_id",
        "repository_id",
        "expected_version",
        "restore_request_sha256",
        "resolution_request_sha256",
        "idempotency_key",
        "actor_id",
        "reason",
        "evidence_ref",
        "resolution",
        "resolved_at",
        "audit_sha256",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if (
        not _identifier(document.get("tenant_id"))
        or not _identifier(document.get("backup_id"))
        or document["backup_id"] != expected_backup_id
        or not _identifier(document.get("repository_id"))
        or document["repository_id"] != expected_repository_id
        or type(document.get("expected_version")) is not int
        or document["expected_version"] != expected_version
        or not 1 <= expected_version <= 2_147_483_647
        or not _sha256(document.get("restore_request_sha256"))
        or not _sha256(document.get("resolution_request_sha256"))
        or not _idempotency_key(document.get("idempotency_key"))
        or not _text(document.get("actor_id"), maximum=256)
        or not _text(document.get("reason"), maximum=512)
        or not _identifier(document.get("evidence_ref"))
        or document.get("resolution") != "ABORTED"
        or type(document.get("resolved_at")) is not int
        or document["resolved_at"] < 0
        or not _sha256(document.get("audit_sha256"))
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return {name: document[name] for name in fields}


def _validated_deletion_receipt(
    document: object,
    *,
    expected_deletion_id: str | None = None,
    expected_repository_id: str | None = None,
) -> dict[str, object]:
    fields = {
        "deletion_id",
        "tenant_id",
        "repository_id",
        "content_sha256",
        "data_class",
        "identity_hash",
        "state",
        "version",
        "legal_hold",
        "executed",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    if (
        not _identifier(document.get("deletion_id"))
        or not _identifier(document.get("tenant_id"))
        or not _identifier(document.get("repository_id"))
        or not _sha256(document.get("content_sha256"))
        or document.get("data_class") not in {"metadata", "artifact", "audit"}
        or not _sha256(document.get("identity_hash"))
        or type(document.get("state")) is not str
        or document.get("state") not in _DELETION_STATES
        or type(document.get("version")) is not int
        or not 1 <= document["version"] <= 2_147_483_647
        or type(document.get("legal_hold")) is not bool
        or type(document.get("executed")) is not bool
        or document["executed"] and document["state"] != "EXECUTED"
        or document["legal_hold"] and document["state"] != "HELD"
        or document["state"] == "EXECUTED" and not document["executed"]
        or document["state"] == "HELD" and not document["legal_hold"]
        or document["state"] == "REQUESTED" and (document["legal_hold"] or document["executed"])
        or document["state"] == "APPROVED" and (document["legal_hold"] or document["executed"])
        or (expected_deletion_id is not None and document["deletion_id"] != expected_deletion_id)
        or (
            expected_repository_id is not None
            and document["repository_id"] != expected_repository_id
        )
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return {name: document[name] for name in fields}


def grant_secret(
    settings: ConnectedRunSettings,
    draft: SecretGrantDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Request one bounded secret grant for a workload."""

    key = _operation_key(
        settings,
        "secret-grant",
        draft.workload_id,
        {
            "purpose": draft.purpose,
            "reference": draft.reference,
            "repository_id": draft.repository_id,
        },
        idempotency_key,
    )
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
    safe_document = _validated_secret_receipt(
        document,
        expected_repository_id=draft.repository_id,
        expected_workload_id=draft.workload_id,
    )
    return ConnectedCollection(run_id=draft.workload_id, kind=ResultKind.FINDINGS, document=safe_document)


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
    safe_document = _validated_secret_receipt(
        document,
        expected_grant_id=grant_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=grant_id, kind=ResultKind.FINDINGS, document=safe_document)


def rotate_secret(
    settings: ConnectedRunSettings,
    grant_id: str,
    *,
    workload_id: str,
    reference: str,
    purpose: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Replace one secret lease while preserving its repository scope."""

    if (
        not _identifier(grant_id)
        or not _identifier(workload_id)
        or not _secret_reference(reference)
        or type(purpose) is not str
        or purpose not in _SECRET_PURPOSES
        or not _version_precondition(if_match, minimum=1)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = _operation_key(
        settings,
        "secret-rotate",
        grant_id,
        {"purpose": purpose, "reference": reference, "workload_id": workload_id, "if_match": if_match},
        idempotency_key,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/secret-grants/" + grant_id + ":rotate",
        document={"workload_id": workload_id, "reference": reference, "purpose": purpose},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    safe_document = _validated_secret_receipt(
        document,
        expected_workload_id=workload_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=grant_id, kind=ResultKind.FINDINGS, document=safe_document)


def revoke_secret(
    settings: ConnectedRunSettings,
    grant_id: str,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Revoke one secret lease against the exact observed version."""

    if not _identifier(grant_id) or not _version_precondition(if_match, minimum=1):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = _operation_key(settings, "secret-revoke", grant_id, {"if_match": if_match}, idempotency_key)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/secret-grants/" + grant_id + ":revoke",
        document={},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    safe_document = _validated_secret_receipt(
        document,
        expected_grant_id=grant_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=grant_id, kind=ResultKind.FINDINGS, document=safe_document)


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

    key = _operation_key(
        settings,
        "backup-create",
        draft.backup_id,
        {
            "component_hashes": list(draft.component_hashes),
            "key_reference": draft.key_reference,
            "region": draft.region,
            "repository_id": draft.repository_id,
        },
        idempotency_key,
    )
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
    safe_document = _validated_backup_receipt(
        document,
        expected_backup_id=draft.backup_id,
        expected_repository_id=draft.repository_id,
    )
    return ConnectedCollection(run_id=draft.backup_id, kind=ResultKind.FINDINGS, document=safe_document)


def read_backup(
    settings: ConnectedRunSettings, backup_id: str, *, api: ConnectedApi | None = None
) -> ConnectedCollection:
    """Read one backup's durable state."""

    if not _identifier(backup_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/backups/" + backup_id, token=settings.token)
    safe_document = _validated_backup_receipt(
        document,
        expected_backup_id=backup_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=backup_id, kind=ResultKind.FINDINGS, document=safe_document)


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

    if (
        not _identifier(backup_id)
        or not _version_precondition(if_match, minimum=1)
        or type(restore) is not bool
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    action = "restore" if restore else "execute"
    key = _operation_key(
        settings,
        "backup-" + action,
        backup_id,
        {"if_match": if_match},
        idempotency_key,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/backups/" + backup_id + ":" + action,
        document={},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    safe_document = _validated_backup_receipt(
        document,
        expected_backup_id=backup_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=backup_id, kind=ResultKind.FINDINGS, document=safe_document)


def resolve_backup(
    settings: ConnectedRunSettings,
    backup_id: str,
    *,
    evidence_ref: str,
    reason: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Record an explicit administrative resolution for a stuck restore."""

    if (
        not _identifier(backup_id)
        or not _identifier(evidence_ref)
        or not _text(reason, maximum=512)
        or not _version_precondition(if_match, minimum=1)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = _operation_key(
        settings,
        "backup-restore-resolve",
        backup_id,
        {"evidence_ref": evidence_ref, "if_match": if_match, "reason": reason},
        idempotency_key,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/backups/" + backup_id + ":restore:resolve",
        document={"evidence_ref": evidence_ref, "reason": reason},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    expected_version = _precondition_version(if_match)
    if expected_version is None:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    safe_document = _validated_backup_recovery(
        document,
        expected_backup_id=backup_id,
        expected_repository_id=settings.repository_id,
        expected_version=expected_version,
    )
    return ConnectedCollection(run_id=backup_id, kind=ResultKind.FINDINGS, document=safe_document)


@dataclass(frozen=True, slots=True)
class DeletionDraft:
    """Operator-supplied metadata for one erasure request."""

    deletion_id: str
    repository_id: str
    content_sha256: str
    identity_hash: str
    data_class: str = "artifact"

    def __post_init__(self) -> None:
        if (
            not _identifier(self.deletion_id)
            or not _identifier(self.repository_id)
            or not _sha256(self.content_sha256)
            or not _sha256(self.identity_hash)
            or type(self.data_class) is not str
            or self.data_class not in {"metadata", "artifact", "audit"}
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

    key = _operation_key(
        settings,
        "deletion-create",
        draft.deletion_id,
        {
            "content_sha256": draft.content_sha256,
            "data_class": draft.data_class,
            "identity_hash": draft.identity_hash,
            "repository_id": draft.repository_id,
        },
        idempotency_key,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions",
        document={
            "deletion_id": draft.deletion_id,
            "repository_id": draft.repository_id,
            "content_sha256": draft.content_sha256,
            "data_class": draft.data_class,
            "identity_hash": draft.identity_hash,
        },
        token=settings.token,
        idempotency_key=key,
    )
    safe_document = _validated_deletion_receipt(
        document,
        expected_deletion_id=draft.deletion_id,
        expected_repository_id=draft.repository_id,
    )
    return ConnectedCollection(
        run_id=draft.deletion_id, kind=ResultKind.FINDINGS, document=safe_document
    )


def read_deletion(
    settings: ConnectedRunSettings, deletion_id: str, *, api: ConnectedApi | None = None
) -> ConnectedCollection:
    """Read one erasure request's durable state."""

    if not _identifier(deletion_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/lifecycle/deletions/" + deletion_id, token=settings.token)
    safe_document = _validated_deletion_receipt(
        document,
        expected_deletion_id=deletion_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=safe_document)


def approve_deletion(
    settings: ConnectedRunSettings,
    deletion_id: str,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Approve one erasure request against the exact observed state."""

    if not _identifier(deletion_id) or not _version_precondition(if_match, minimum=1):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = _operation_key(
        settings,
        "deletion-approve",
        deletion_id,
        {"if_match": if_match},
        idempotency_key,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions/" + deletion_id + ":approve",
        document={},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    safe_document = _validated_deletion_receipt(
        document,
        expected_deletion_id=deletion_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=safe_document)


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
        or not _version_precondition(if_match, minimum=1)
        or type(enabled) is not bool
        or not _sha256(identity_hash)
        or not _printable(reason, maximum=1024)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = _operation_key(
        settings,
        "deletion-legal-hold",
        deletion_id,
        {"enabled": enabled, "identity_hash": identity_hash, "reason": reason, "if_match": if_match},
        idempotency_key,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions/" + deletion_id + ":legal-hold",
        document={"enabled": enabled, "identity_hash": identity_hash, "reason": reason},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    safe_document = _validated_deletion_receipt(
        document,
        expected_deletion_id=deletion_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=safe_document)


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

    if (
        not _identifier(deletion_id)
        or not _version_precondition(if_match, minimum=1)
        or not _sha256(identity_hash)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = _operation_key(
        settings,
        "deletion-execute",
        deletion_id,
        {"identity_hash": identity_hash, "if_match": if_match},
        idempotency_key,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions/" + deletion_id + ":execute",
        document={"identity_hash": identity_hash},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    safe_document = _validated_deletion_receipt(
        document,
        expected_deletion_id=deletion_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=safe_document)


def create_waiver(
    settings: ConnectedRunSettings,
    finding_id: str,
    draft: WaiverDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Grant one exact finding waiver from an already approved decision."""

    if not _identifier(finding_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    payload: dict[str, object] = {
        "waiver_id": draft.waiver_id,
        "approval_id": draft.approval_id,
        "repository_id": draft.repository_id,
        "run_id": draft.run_id,
        "execution_identity_hash": draft.execution_identity_hash,
        "expires_at": draft.expires_at,
    }
    if draft.policy_scope is not None:
        payload["policy_scope"] = draft.policy_scope
    key = _operation_key(
        settings,
        "waiver-create",
        draft.waiver_id,
        payload,
        idempotency_key,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        f"/api/v1/findings/{finding_id}/waivers",
        document=payload,
        token=settings.token,
        idempotency_key=key,
    )
    safe_document = _validated_waiver_receipt(
        document,
        expected_waiver_id=draft.waiver_id,
        expected_repository_id=draft.repository_id,
        expected_active=True,
    )
    return ConnectedCollection(
        run_id=draft.run_id,
        kind=ResultKind.FINDINGS,
        document=safe_document,
    )


def read_waiver(
    settings: ConnectedRunSettings,
    waiver_id: str,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read one tenant-scoped waiver receipt."""

    if not _identifier(waiver_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(f"/api/v1/waivers/{waiver_id}", token=settings.token)
    safe_document = _validated_waiver_receipt(
        document,
        expected_waiver_id=waiver_id,
        expected_repository_id=settings.repository_id,
    )
    return ConnectedCollection(run_id=waiver_id, kind=ResultKind.FINDINGS, document=safe_document)


def revoke_waiver(
    settings: ConnectedRunSettings,
    waiver_id: str,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Revoke one waiver against the exact observed version."""

    version = _precondition_version(if_match)
    if not _identifier(waiver_id) or version is None:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = _operation_key(
        settings,
        "waiver-revoke",
        waiver_id,
        {"if_match": if_match},
        idempotency_key,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        f"/api/v1/waivers/{waiver_id}:revoke",
        document={},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    safe_document = _validated_waiver_receipt(
        document,
        expected_waiver_id=waiver_id,
        expected_repository_id=settings.repository_id,
        expected_version=version + 1,
        expected_active=False,
    )
    return ConnectedCollection(run_id=waiver_id, kind=ResultKind.FINDINGS, document=safe_document)


def _precondition_version(value: str) -> int | None:
    if not _version_precondition(value, minimum=1):
        return None
    if value.startswith('W/"') and value.endswith('"'):
        value = value[3:-1]
    elif value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if not value.isascii() or not value.isdecimal():
        return None
    version = int(value)
    return version if 1 <= version <= 2_147_483_647 else None
