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
from securecode_ai.core.resource_governor import ResourceUsage

from .run_admission_models import RunOperation

IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
TERMINAL_STATES: Final = frozenset(
    {"SUCCEEDED", "FAILED", "INDETERMINATE", "CANCELLED", "SUPERSEDED"}
)
_MAX_REPLAY_BYTES: Final = 1_048_576
_MAX_VERSION: Final = 2_147_483_647
_MAX_EVENT_SEQUENCE: Final = 2_147_483_647
_SCHEMA_VERSION: Final = "0.2.0"
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
class WorkerResourceBudget:
    """The exact durable reservation granted to one leased worker run."""

    profile_sha256: str
    reservation_id: str
    reservation_version: int
    reserved: ResourceUsage

    def __post_init__(self) -> None:
        if (
            SHA256.fullmatch(self.profile_sha256) is None
            or IDENTIFIER.fullmatch(self.reservation_id) is None
            or type(self.reservation_version) is not int
            or self.reservation_version < 1
            or type(self.reserved) is not ResourceUsage
        ):
            raise WorkerQueueConflict()

    def document(self) -> dict[str, object]:
        return {
            "profile_sha256": self.profile_sha256,
            "reservation_id": self.reservation_id,
            "reservation_version": self.reservation_version,
            "reserved": {
                "tokens": self.reserved.tokens,
                "cost_microunits": self.reserved.cost_microunits,
                "cpu_ms": self.reserved.cpu_ms,
                "peak_memory_bytes": self.reserved.peak_memory_bytes,
                "wall_ms": self.reserved.wall_ms,
            },
        }


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
    contribution_trust: str = "NOT_SCM"
    next_event_sequence: int = 1
    operation: RunOperation = RunOperation.SCAN
    resource_budget: WorkerResourceBudget | None = None

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
            "contribution_trust": contribution_trust(self.contribution_trust),
            "next_event_sequence": self.next_event_sequence,
            "operation": self.operation.value,
            "resource_budget": (
                self.resource_budget.document() if self.resource_budget is not None else None
            ),
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
    if (
        type(value) is not str
        or len(value) > _MAX_REPLAY_BYTES
        or len(value.encode("utf-8", errors="ignore")) > _MAX_REPLAY_BYTES
        or type(lease_seconds) is not int
        or not 5 <= lease_seconds <= 3600
    ):
        raise WorkerQueueConflict()
    try:
        document = json.loads(value, object_pairs_hook=_closed_object)
    except (
        OverflowError,
        RecursionError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ):
        raise WorkerQueueConflict() from None
    if document is None:
        return None
    if not isinstance(document, Mapping):
        raise WorkerQueueConflict()
    try:
        expected_keys = {
            "schema_version",
            "session_id",
            "run_id",
            "version",
            "lease_seconds",
            "command",
            "execution_identity",
            "execution_identity_hash",
            "contribution_trust",
            "next_event_sequence",
            "operation",
            "resource_budget",
            "tenant_id",
            "worker_id",
            "lease_expires_at",
            "terminal",
            "outcome",
        }
        legacy_key_sets = {
            expected_keys - {"next_event_sequence"},
            expected_keys - {"operation"},
            expected_keys - {"next_event_sequence", "operation"},
            expected_keys - {"resource_budget"},
            expected_keys - {"next_event_sequence", "resource_budget"},
            expected_keys - {"operation", "resource_budget"},
            expected_keys - {"next_event_sequence", "operation", "resource_budget"},
        }
        document_keys = set(document)
        if (
            document_keys != expected_keys
            and document_keys not in legacy_key_sets
            or document["schema_version"] != _SCHEMA_VERSION
        ):
            raise WorkerQueueConflict()
        tenant_id = document["tenant_id"]
        run_id = document["run_id"]
        worker_id = document["worker_id"]
        session_id_value = document["session_id"]
        version = document["version"]
        returned_lease_seconds = document["lease_seconds"]
        command_value = document["command"]
        terminal = document["terminal"]
        outcome = document.get("outcome")
        next_event_sequence = document.get("next_event_sequence", 1)
        operation_value = document.get("operation", RunOperation.SCAN.value)
        resource_budget = _resource_budget(document.get("resource_budget"))
        if (
            any(
                type(value) is not str
                for value in (tenant_id, run_id, worker_id, session_id_value, command_value)
            )
            or type(version) is not int
            or not 1 <= version <= _MAX_VERSION
            or type(returned_lease_seconds) is not int
            or returned_lease_seconds != lease_seconds
            or type(terminal) is not bool
            or (outcome is not None and type(outcome) is not str)
            or type(next_event_sequence) is not int
            or not 1 <= next_event_sequence <= _MAX_EVENT_SEQUENCE
            or terminal
            or outcome is not None
            or type(operation_value) is not str
        ):
            raise WorkerQueueConflict()
        try:
            operation = RunOperation(operation_value)
        except ValueError:
            raise WorkerQueueConflict() from None
        identity_value = document["execution_identity"]
        if not isinstance(identity_value, Mapping):
            raise WorkerQueueConflict()
        identity = RunExecutionIdentity.model_validate_json(
            json.dumps(dict(identity_value), separators=(",", ":"), sort_keys=True)
        )
        if document.get("execution_identity_hash") != identity.execution_identity_hash:
            raise WorkerQueueConflict()
        lease = WorkerQueueLease(
            tenant_id=tenant_id,
            run_id=run_id,
            worker_id=worker_id,
            session_id=session_id_value,
            version=version,
            lease_seconds=lease_seconds,
            lease_expires_at=timestamp(document["lease_expires_at"]),
            command=command_value,
            execution_identity=identity,
            terminal=terminal,
            outcome=outcome,
            contribution_trust=contribution_trust(document.get("contribution_trust", "NOT_SCM")),
            next_event_sequence=next_event_sequence,
            operation=operation,
            resource_budget=resource_budget,
        )
        identifier(lease.tenant_id)
        identifier(lease.run_id)
        identifier(lease.worker_id)
        identifier(lease.session_id)
        if lease.command not in {"CONTINUE", "CANCEL", "SUPERSEDE"}:
            raise WorkerQueueConflict()
        return lease
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        raise WorkerQueueConflict() from None


def identity(value: RunExecutionIdentity) -> RunExecutionIdentity:
    if not isinstance(value, RunExecutionIdentity):
        raise WorkerQueueConflict()
    return RunExecutionIdentity.model_validate_json(value.model_dump_json())


def _resource_budget(value: object) -> WorkerResourceBudget | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != {
        "profile_sha256",
        "reservation_id",
        "reservation_version",
        "reserved",
    }:
        raise WorkerQueueConflict()
    reserved = value["reserved"]
    if not isinstance(reserved, Mapping) or set(reserved) != {
        "tokens",
        "cost_microunits",
        "cpu_ms",
        "peak_memory_bytes",
        "wall_ms",
    }:
        raise WorkerQueueConflict()
    try:
        usage = ResourceUsage(
            tokens=reserved["tokens"],
            cost_microunits=reserved["cost_microunits"],
            cpu_ms=reserved["cpu_ms"],
            peak_memory_bytes=reserved["peak_memory_bytes"],
            wall_ms=reserved["wall_ms"],
        )
        return WorkerResourceBudget(
            profile_sha256=value["profile_sha256"],
            reservation_id=value["reservation_id"],
            reservation_version=value["reservation_version"],
            reserved=usage,
        )
    except (TypeError, ValueError):
        raise WorkerQueueConflict() from None


def identity_document(value: str) -> RunExecutionIdentity:
    if type(value) is not str or len(value) > _MAX_REPLAY_BYTES:
        raise WorkerQueueConflict()
    try:
        document = json.loads(value, object_pairs_hook=_closed_object)
        if not isinstance(document, dict):
            raise WorkerQueueConflict()
        return RunExecutionIdentity.model_validate_json(value)
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError, OverflowError):
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
    if type(expected_version) is not int or not 1 <= expected_version <= _MAX_VERSION:
        raise WorkerQueueConflict()


def identifier(value: str) -> None:
    if type(value) is not str or IDENTIFIER.fullmatch(value) is None:
        raise WorkerQueueConflict()


def contribution_trust(value: object) -> str:
    allowed = {
        "NOT_SCM",
        "TRUSTED_SAME_REPOSITORY",
        "UNTRUSTED_FORK",
        "UNTRUSTED_SAME_REPOSITORY",
        "UNKNOWN",
    }
    if type(value) is not str or value not in allowed:
        raise WorkerQueueConflict()
    return str(value)


def idempotency_key(value: str) -> None:
    if type(value) is not str or not 8 <= len(value) <= 128 or IDENTIFIER.fullmatch(value) is None:
        raise WorkerQueueConflict()


def timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise WorkerQueueConflict()
    try:
        return utc(datetime.fromisoformat(value))
    except (OverflowError, ValueError):
        raise WorkerQueueConflict() from None


def utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
        raise WorkerQueueConflict()
    return value


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("duplicate worker queue field")
        result[key] = item
    return result


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
    "WorkerResourceBudget",
    "canonical",
    "canonical_sha256",
    "command",
    "contribution_trust",
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
