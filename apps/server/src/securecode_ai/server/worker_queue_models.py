"""Value objects and closed serialization for connected worker queues."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from securecode_ai.contracts import RunExecutionIdentity

IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
TERMINAL_STATES: Final = frozenset(
    {"SUCCEEDED", "FAILED", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}
)
OUTCOME_STATES: Final = {
    "PASS": "SUCCEEDED",
    "FAIL": "FAILED",
    "INDETERMINATE": "INDETERMINATE",
    "CANCELLED": "CANCELLED",
    "SUPERSEDED": "SUPERSEDED",
}


class WorkerQueueConflict(Exception):
    """A queue mutation conflicts with the current durable lease."""


@dataclass(frozen=True, slots=True)
class WorkerQueueLease:
    tenant_id: str
    run_id: str
    worker_id: str
    session_id: str
    version: int
    lease_seconds: int
    lease_expires_at: datetime
    command: str
    execution_identity: RunExecutionIdentity
    terminal: bool = False
    outcome: str | None = None

    def job_document(self) -> dict[str, object]:
        return {
            "schema_version": "0.2.0",
            "session_id": self.session_id,
            "run_id": self.run_id,
            "version": self.version,
            "lease_seconds": self.lease_seconds,
            "command": self.command,
            "execution_identity": self.execution_identity.model_dump(mode="json"),
            "execution_identity_hash": self.execution_identity.execution_identity_hash,
        }


def lease_document(lease: WorkerQueueLease) -> dict[str, object]:
    return {
        **lease.job_document(),
        "tenant_id": lease.tenant_id,
        "worker_id": lease.worker_id,
        "lease_expires_at": lease.lease_expires_at.isoformat(),
        "terminal": lease.terminal,
        "outcome": lease.outcome,
    }


def replayed_lease(value: str, lease_seconds: int) -> WorkerQueueLease | None:
    document = json.loads(value)
    if document is None:
        return None
    if not isinstance(document, Mapping):
        raise WorkerQueueConflict()
    try:
        identity_value = document["execution_identity"]
        if not isinstance(identity_value, Mapping):
            raise WorkerQueueConflict()
        identity = RunExecutionIdentity.model_validate(dict(identity_value))
        if document.get("execution_identity_hash") != identity.execution_identity_hash:
            raise WorkerQueueConflict()
        lease = WorkerQueueLease(
            tenant_id=str(document["tenant_id"]),
            run_id=str(document["run_id"]),
            worker_id=str(document["worker_id"]),
            session_id=str(document["session_id"]),
            version=int(document["version"]),
            lease_seconds=lease_seconds,
            lease_expires_at=timestamp(document["lease_expires_at"]),
            command=str(document["command"]),
            execution_identity=identity,
            terminal=bool(document["terminal"]),
            outcome=(document.get("outcome") if isinstance(document.get("outcome"), str) else None),
        )
        identifier(lease.tenant_id)
        identifier(lease.run_id)
        identifier(lease.worker_id)
        identifier(lease.session_id)
        if lease.command not in {"CONTINUE", "CANCEL", "SUPERSEDE"}:
            raise WorkerQueueConflict()
        return lease
    except (KeyError, TypeError, ValueError):
        raise WorkerQueueConflict() from None


def identity(value: RunExecutionIdentity) -> RunExecutionIdentity:
    if not isinstance(value, RunExecutionIdentity):
        raise WorkerQueueConflict()
    return RunExecutionIdentity.model_validate_json(value.model_dump_json())


def identity_document(value: str) -> RunExecutionIdentity:
    try:
        document = json.loads(value)
        if not isinstance(document, dict):
            raise WorkerQueueConflict()
        return RunExecutionIdentity.model_validate_json(value)
    except (json.JSONDecodeError, TypeError, ValueError):
        raise WorkerQueueConflict() from None


def command(state: str) -> str:
    if state in {"CANCEL_REQUESTED", "CANCELLED"}:
        return "CANCEL"
    if state in {"SUPERSEDE_REQUESTED", "SUPERSEDED"}:
        return "SUPERSEDE"
    return "CONTINUE"


def session_id(
    tenant_id: str,
    run_id: str,
    worker_id: str,
    idempotency_key: str,
    version: int,
) -> str:
    material = "\x00".join((tenant_id, run_id, worker_id, idempotency_key, str(version))).encode(
        "utf-8"
    )
    return "session-" + hashlib.sha256(material).hexdigest()[:48]


def lease_arguments(
    tenant_id: str,
    session_id_value: str,
    worker_id: str,
    identity_hash: str,
    expected_version: int,
) -> None:
    identifier(tenant_id)
    identifier(session_id_value)
    identifier(worker_id)
    if SHA256.fullmatch(identity_hash) is None:
        raise WorkerQueueConflict()
    if type(expected_version) is not int or expected_version < 1:
        raise WorkerQueueConflict()


def identifier(value: str) -> None:
    if type(value) is not str or IDENTIFIER.fullmatch(value) is None:
        raise WorkerQueueConflict()


def idempotency_key(value: str) -> None:
    if type(value) is not str or not 8 <= len(value) <= 128 or IDENTIFIER.fullmatch(value) is None:
        raise WorkerQueueConflict()


def timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise WorkerQueueConflict()
    try:
        return utc(datetime.fromisoformat(value))
    except ValueError:
        raise WorkerQueueConflict() from None


def utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise WorkerQueueConflict()
    return value


def canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


__all__ = [
    "OUTCOME_STATES",
    "TERMINAL_STATES",
    "WorkerQueueConflict",
    "WorkerQueueLease",
    "canonical",
    "canonical_sha256",
    "command",
    "idempotency_key",
    "identifier",
    "identity",
    "identity_document",
    "lease_arguments",
    "lease_document",
    "replayed_lease",
    "session_id",
    "timestamp",
    "utc",
]
