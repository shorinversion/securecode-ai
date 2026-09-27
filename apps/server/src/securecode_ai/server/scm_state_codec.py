"""Canonical encoding and row validation for durable SCM run state."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from typing import Final, NoReturn

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

ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
COMMIT_SHA_PATTERN: Final = re.compile(r"[0-9a-f]{40}\Z")
SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
MAX_CAPACITY: Final = 1_000_000
MAX_RECEIPTS_PER_RUN: Final = 32
_HASH_DOMAIN: Final = b"securecode-ai/scm-run-state/v1\x00"


def admission_receipt(
    disposition: AdmissionDisposition,
    row: sqlite3.Row,
    superseded: tuple[str, ...],
) -> SCMRunAdmissionReceipt:
    return SCMRunAdmissionReceipt(
        disposition=disposition,
        run_id=row["run_id"],
        execution_identity_hash=row["execution_identity_hash"],
        head_sha=row["head_sha"],
        lifecycle=lifecycle(row),
        state_version=state_version(row),
        superseded_run_ids=superseded,
    )


def publication_receipt(
    disposition: PublicationDisposition,
    row: sqlite3.Row,
    current_head_sha: str,
) -> SCMRunPublicationReceipt:
    return SCMRunPublicationReceipt(
        disposition=disposition,
        run_id=row["run_id"],
        execution_identity_hash=row["execution_identity_hash"],
        head_sha=row["head_sha"],
        current_head_sha=current_head_sha,
        lifecycle=lifecycle(row),
        outcome=outcome(row),
        state_version=state_version(row),
    )


def admission_json(receipt: SCMRunAdmissionReceipt) -> str:
    return canonical(
        {
            "disposition": receipt.disposition.value,
            "execution_identity_hash": receipt.execution_identity_hash,
            "head_sha": receipt.head_sha,
            "lifecycle": receipt.lifecycle.value,
            "run_id": receipt.run_id,
            "state_version": receipt.state_version,
            "superseded_run_ids": list(receipt.superseded_run_ids),
        }
    )


def publication_json(receipt: SCMRunPublicationReceipt) -> str:
    return canonical(
        {
            "current_head_sha": receipt.current_head_sha,
            "disposition": receipt.disposition.value,
            "execution_identity_hash": receipt.execution_identity_hash,
            "head_sha": receipt.head_sha,
            "lifecycle": receipt.lifecycle.value,
            "outcome": None if receipt.outcome is None else receipt.outcome.value,
            "run_id": receipt.run_id,
            "state_version": receipt.state_version,
        }
    )


def admission_from_json(value: object) -> SCMRunAdmissionReceipt:
    try:
        if not isinstance(value, (str, bytes, bytearray)):
            raise ValueError
        document = json.loads(value)
        if type(document) is not dict or set(document) != {
            "disposition",
            "execution_identity_hash",
            "head_sha",
            "lifecycle",
            "run_id",
            "state_version",
            "superseded_run_ids",
        }:
            raise ValueError
        superseded = document["superseded_run_ids"]
        if (
            type(superseded) is not list
            or len(superseded) > MAX_CAPACITY
            or any(
                type(item) is not str or ID_PATTERN.fullmatch(item) is None for item in superseded
            )
            or type(document["state_version"]) is not int
            or document["state_version"] < 0
            or ID_PATTERN.fullmatch(document["run_id"]) is None
            or SHA256_PATTERN.fullmatch(document["execution_identity_hash"]) is None
            or not is_commit_sha(document["head_sha"])
        ):
            raise ValueError
        return SCMRunAdmissionReceipt(
            disposition=AdmissionDisposition(document["disposition"]),
            run_id=document["run_id"],
            execution_identity_hash=document["execution_identity_hash"],
            head_sha=document["head_sha"],
            lifecycle=SCMRunLifecycle(document["lifecycle"]),
            state_version=document["state_version"],
            superseded_run_ids=tuple(superseded),
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)


def store_history(
    cursor: sqlite3.Cursor,
    tenant_id: str,
    run_id: str,
    kind: str,
    version: int,
    receipt_json: str,
) -> None:
    digest = hashlib.sha256(receipt_json.encode("ascii")).hexdigest()
    existing = cursor.execute(
        """SELECT 1 FROM scm_run_receipt_history
           WHERE tenant_id=? AND run_id=? AND receipt_sha256=?""",
        (tenant_id, run_id, digest),
    ).fetchone()
    if existing is not None:
        return
    count = cursor.execute(
        """SELECT COUNT(*) FROM scm_run_receipt_history
           WHERE tenant_id=? AND run_id=?""",
        (tenant_id, run_id),
    ).fetchone()[0]
    if type(count) is not int or count >= MAX_RECEIPTS_PER_RUN:
        reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
    cursor.execute(
        """INSERT INTO scm_run_receipt_history
           VALUES (?, ?, ?, ?, ?, ?)""",
        (tenant_id, run_id, digest, kind, version, receipt_json),
    )


def require_capacity(cursor: sqlite3.Cursor, table: str, tenant_id: str, maximum: int) -> None:
    count = cursor.execute(
        f"SELECT COUNT(*) FROM {table} WHERE tenant_id=?", (tenant_id,)
    ).fetchone()[0]
    if type(count) is not int or count >= maximum:
        reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)


def next_sequence(cursor: sqlite3.Cursor, table: str, tenant_id: str) -> int:
    value: object = cursor.execute(
        f"SELECT COALESCE(MAX(created_sequence), 0) + 1 FROM {table} WHERE tenant_id=?",
        (tenant_id,),
    ).fetchone()[0]
    if type(value) is not int or value < 1 or value > MAX_CAPACITY:
        reject(SCMRunStateErrorCode.TRANSITION_CONFLICT)
    return value


def lifecycle(row: sqlite3.Row) -> SCMRunLifecycle:
    return SCMRunLifecycle(row["lifecycle"])


def outcome(row: sqlite3.Row) -> AuditRunOutcome | None:
    value = row["outcome"]
    return None if value is None else AuditRunOutcome(value)


def state_version(row: sqlite3.Row) -> int:
    value = row["state_version"]
    if type(value) is not int or value < 1:
        raise ValueError("invalid state version")
    return value


def semantic_key(request: SCMRunAdmissionRequest) -> tuple[str, str, str, str]:
    revision = request.execution_identity.repository_revision
    return (
        revision.tenant_id,
        request.installation_id,
        revision.repository_id,
        request.execution_identity.execution_identity_hash,
    )


def provider_target(request: SCMRunAdmissionRequest) -> tuple[str, str, str]:
    """Extract the explicit provider lookup target from admitted adapter scope."""

    provider = request.execution_identity.repository_revision.scm_provider
    installation = request.installation_id
    if provider == "github":
        parts = installation.rsplit(":pr:", 1)
        if len(parts) != 2:
            reject(SCMRunStateErrorCode.INVALID_REQUEST)
        provider_installation_id, change_id = parts
    elif provider == "gitlab":
        if not installation.startswith("gitlab:"):
            reject(SCMRunStateErrorCode.INVALID_REQUEST)
        parts = installation[7:].rsplit(":mr:", 1)
        if len(parts) != 2:
            reject(SCMRunStateErrorCode.INVALID_REQUEST)
        provider_installation_id, change_id = parts
    else:
        reject(SCMRunStateErrorCode.INVALID_REQUEST)
    if (
        ID_PATTERN.fullmatch(provider_installation_id) is None
        or ID_PATTERN.fullmatch(change_id) is None
    ):
        reject(SCMRunStateErrorCode.INVALID_REQUEST)
    return provider, provider_installation_id, change_id


def admission_hash(request: SCMRunAdmissionRequest) -> str:
    material: dict[str, object] = {
        "authorized_head_sha": request.authorized_head_sha,
        "execution_identity": request.execution_identity.model_dump(mode="json"),
        "installation_id": request.installation_id,
    }
    if request.delivery_sha256 is not None:
        material["delivery_sha256"] = request.delivery_sha256
    return material_hash(material)


def run_id(semantic: tuple[str, str, str, str]) -> str:
    return "scm-run-" + material_hash({"semantic_key": semantic})[:40]


def material_hash(material: dict[str, object]) -> str:
    return hashlib.sha256(_HASH_DOMAIN + canonical(material).encode("ascii")).hexdigest()


def canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def validate_run_call(run_id_value: str, current_head_sha: str) -> None:
    if (
        type(run_id_value) is not str
        or ID_PATTERN.fullmatch(run_id_value) is None
        or not is_commit_sha(current_head_sha)
    ):
        reject(SCMRunStateErrorCode.INVALID_REQUEST)


def is_commit_sha(value: object) -> bool:
    return type(value) is str and COMMIT_SHA_PATTERN.fullmatch(value) is not None


def capacity(value: object) -> bool:
    return type(value) is int and 1 <= value <= MAX_CAPACITY


def reject(code: SCMRunStateErrorCode) -> NoReturn:
    raise SCMRunStateError(code) from None
