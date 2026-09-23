"""Tenant-scoped worker leases, events, artifacts, commands, and outcomes."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final, Protocol

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOMES: Final = frozenset({"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"})


class WorkerDenied(Exception):
    """The worker request conflicts with the bound lease or journal."""


class WorkerCommand(StrEnum):
    CONTINUE = "CONTINUE"
    CANCEL = "CANCEL"
    SUPERSEDE = "SUPERSEDE"


@dataclass(frozen=True, slots=True)
class WorkerSession:
    tenant_id: str
    run_id: str
    worker_id: str
    identity_hash: str
    session_id: str
    version: int
    terminal: bool = False
    command: WorkerCommand = WorkerCommand.CONTINUE
    outcome: str | None = None


class WorkerSessionStore(Protocol):
    def create(
        self,
        *,
        tenant_id: str,
        run_id: str,
        worker_id: str,
        identity_hash: str,
        idempotency_key: str,
    ) -> WorkerSession: ...

    def heartbeat(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
    ) -> WorkerSession: ...

    def append(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        events: tuple[dict[str, object], ...],
    ) -> WorkerSession: ...

    def artifact(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        content_sha256: str,
    ) -> WorkerSession: ...

    def complete(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        outcome: str,
    ) -> WorkerSession: ...

    def command(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        command: WorkerCommand,
        expected_version: int,
    ) -> WorkerSession: ...


class WorkerSessions:
    """In-process worker state with identity and version-bound mutations."""

    def __init__(self) -> None:
        self._values: dict[str, WorkerSession] = {}
        self._idempotency: dict[tuple[str, str], tuple[str, WorkerSession]] = {}
        self._events: dict[str, list[dict[str, object]]] = {}
        self._artifacts: dict[str, set[str]] = {}

    def create(
        self,
        *,
        tenant_id: str,
        run_id: str,
        worker_id: str,
        identity_hash: str,
        idempotency_key: str,
    ) -> WorkerSession:
        self._validate_identity(tenant_id, run_id, worker_id, identity_hash)
        if _IDENTIFIER.fullmatch(idempotency_key) is None:
            raise WorkerDenied()
        request_fingerprint = "\x00".join((run_id, worker_id, identity_hash))
        key = (tenant_id, idempotency_key)
        prior = self._idempotency.get(key)
        if prior is not None:
            if prior[0] != request_fingerprint:
                raise WorkerDenied()
            return prior[1]
        session_id = f"session-{run_id}"
        existing = self._values.get(session_id)
        if existing is not None:
            if (
                existing.tenant_id,
                existing.run_id,
                existing.worker_id,
                existing.identity_hash,
            ) != (tenant_id, run_id, worker_id, identity_hash):
                raise WorkerDenied()
            session = existing
        else:
            session = WorkerSession(
                tenant_id=tenant_id,
                run_id=run_id,
                worker_id=worker_id,
                identity_hash=identity_hash,
                session_id=session_id,
                version=1,
            )
            self._values[session_id] = session
        self._idempotency[key] = (request_fingerprint, session)
        return session

    def heartbeat(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
    ) -> WorkerSession:
        return self._require(
            session_id,
            tenant_id,
            worker_id,
            identity_hash,
            expected_version,
        )

    def append(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        events: tuple[dict[str, object], ...],
    ) -> WorkerSession:
        value = self._require(
            session_id,
            tenant_id,
            worker_id,
            identity_hash,
            expected_version,
        )
        if value.terminal or not events:
            raise WorkerDenied()
        previous = self._events.setdefault(session_id, [])
        for offset, item in enumerate(events, start=1):
            if set(item) != {"event_id", "sequence", "event_hash", "kind"}:
                raise WorkerDenied()
            if item.get("sequence") != len(previous) + offset:
                raise WorkerDenied()
            if not self._valid_event(item):
                raise WorkerDenied()
        previous.extend(dict(item) for item in events)
        return value

    def artifact(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        content_sha256: str,
    ) -> WorkerSession:
        value = self._require(
            session_id,
            tenant_id,
            worker_id,
            identity_hash,
            expected_version,
        )
        if value.terminal or _SHA256.fullmatch(content_sha256) is None:
            raise WorkerDenied()
        self._artifacts.setdefault(session_id, set()).add(content_sha256)
        return value

    def complete(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        outcome: str,
    ) -> WorkerSession:
        value = self._require(
            session_id,
            tenant_id,
            worker_id,
            identity_hash,
            expected_version,
            allow_terminal=True,
        )
        if outcome not in _OUTCOMES:
            raise WorkerDenied()
        if value.terminal:
            if value.outcome != outcome:
                raise WorkerDenied()
            return value
        command = WorkerCommand.CONTINUE
        if outcome == "CANCELLED":
            command = WorkerCommand.CANCEL
        elif outcome == "SUPERSEDED":
            command = WorkerCommand.SUPERSEDE
        completed = replace(
            value,
            version=value.version + 1,
            terminal=True,
            command=command,
            outcome=outcome,
        )
        self._values[session_id] = completed
        return completed

    def command(
        self,
        *,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        command: WorkerCommand,
        expected_version: int,
    ) -> WorkerSession:
        current = self._values.get(session_id)
        if (
            current is None
            or current.tenant_id != tenant_id
            or current.worker_id != worker_id
            or current.identity_hash != identity_hash
            or current.version != expected_version
            or current.terminal
        ):
            raise WorkerDenied()
        updated = replace(current, version=current.version + 1, command=command)
        self._values[session_id] = updated
        return updated

    @staticmethod
    def _validate_identity(
        tenant_id: str,
        run_id: str,
        worker_id: str,
        identity_hash: str,
    ) -> None:
        if any(_IDENTIFIER.fullmatch(value) is None for value in (tenant_id, run_id, worker_id)):
            raise WorkerDenied()
        if _SHA256.fullmatch(identity_hash) is None:
            raise WorkerDenied()

    @staticmethod
    def _valid_event(item: dict[str, object]) -> bool:
        event_id = item.get("event_id")
        event_hash = item.get("event_hash")
        kind = item.get("kind")
        return (
            isinstance(event_id, str)
            and _IDENTIFIER.fullmatch(event_id) is not None
            and isinstance(event_hash, str)
            and _SHA256.fullmatch(event_hash) is not None
            and isinstance(kind, str)
            and _IDENTIFIER.fullmatch(kind) is not None
        )

    def _require(
        self,
        session_id: str,
        tenant_id: str,
        worker_id: str,
        identity_hash: str,
        expected_version: int,
        *,
        allow_terminal: bool = False,
    ) -> WorkerSession:
        value = self._values.get(session_id)
        if (
            value is None
            or (
                value.tenant_id,
                value.worker_id,
                value.identity_hash,
                value.version,
            )
            != (tenant_id, worker_id, identity_hash, expected_version)
            or (value.terminal and not allow_terminal)
        ):
            raise WorkerDenied()
        return value


__all__ = [
    "WorkerCommand",
    "WorkerDenied",
    "WorkerSession",
    "WorkerSessionStore",
    "WorkerSessions",
]
