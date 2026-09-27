"""Tenant-scoped worker leases, events, artifacts, commands, and outcomes."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import StrEnum
from threading import RLock
from typing import Final, Protocol

_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOMES: Final = frozenset({"PASS", "FAIL", "INDETERMINATE", "CANCELLED", "SUPERSEDED"})
_MAX_VERSION: Final = 2_147_483_647


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
        self._lock = RLock()
        self._values: dict[tuple[str, str], WorkerSession] = {}
        self._idempotency: dict[tuple[str, str], tuple[str, WorkerSession]] = {}
        self._events: dict[tuple[str, str], list[dict[str, object]]] = {}
        self._artifacts: dict[tuple[str, str], set[str]] = {}

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
        if type(idempotency_key) is not str or _IDENTIFIER.fullmatch(idempotency_key) is None:
            raise WorkerDenied()
        with self._lock:
            request_fingerprint = "\x00".join((run_id, worker_id, identity_hash))
            key = (tenant_id, idempotency_key)
            prior = self._idempotency.get(key)
            if prior is not None:
                if prior[0] != request_fingerprint:
                    raise WorkerDenied()
                current = self._values.get((tenant_id, prior[1].session_id))
                if current is None:
                    raise WorkerDenied()
                return current
            session_id = f"session-{run_id}"
            storage_key = (tenant_id, session_id)
            existing = self._values.get(storage_key)
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
                self._values[storage_key] = session
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
        with self._lock:
            current = self._require(
                session_id,
                tenant_id,
                worker_id,
                identity_hash,
                expected_version,
            )
            updated = replace(current, version=_next_version(current))
            self._values[(tenant_id, session_id)] = updated
            return updated

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
        with self._lock:
            value = self._require(
                session_id,
                tenant_id,
                worker_id,
                identity_hash,
                expected_version,
            )
            if value.terminal or not events:
                raise WorkerDenied()
            storage_key = (tenant_id, session_id)
            previous = self._events.setdefault(storage_key, [])
            for offset, item in enumerate(events, start=1):
                if type(item) is not dict or set(item) != {
                    "event_id",
                    "sequence",
                    "event_hash",
                    "kind",
                }:
                    raise WorkerDenied()
                sequence = item.get("sequence")
                if (
                    type(sequence) is not int
                    or not 1 <= sequence <= 2_147_483_647
                    or sequence != len(previous) + offset
                ):
                    raise WorkerDenied()
                if not self._valid_event(item):
                    raise WorkerDenied()
            previous.extend(dict(item) for item in events)
            updated = replace(value, version=_next_version(value))
            self._values[storage_key] = updated
            return updated

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
        with self._lock:
            value = self._require(
                session_id,
                tenant_id,
                worker_id,
                identity_hash,
                expected_version,
            )
            if (
                value.terminal
                or type(content_sha256) is not str
                or _SHA256.fullmatch(content_sha256) is None
            ):
                raise WorkerDenied()
            storage_key = (tenant_id, session_id)
            self._artifacts.setdefault(storage_key, set()).add(content_sha256)
            updated = replace(value, version=_next_version(value))
            self._values[storage_key] = updated
            return updated

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
        with self._lock:
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
            if (
                value.command is WorkerCommand.SUPERSEDE
                and outcome != "SUPERSEDED"
            ) or (
                value.command is WorkerCommand.CANCEL
                and outcome not in {"CANCELLED", "SUPERSEDED"}
            ):
                raise WorkerDenied()
            command = WorkerCommand.CONTINUE
            if outcome == "CANCELLED":
                command = WorkerCommand.CANCEL
            elif outcome == "SUPERSEDED":
                command = WorkerCommand.SUPERSEDE
            elif value.command is not WorkerCommand.CONTINUE:
                command = value.command
            completed = replace(
                value,
                version=_next_version(value),
                terminal=True,
                command=command,
                outcome=outcome,
            )
            self._values[(tenant_id, session_id)] = completed
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
        if type(command) is not WorkerCommand:
            raise WorkerDenied()
        with self._lock:
            current = self._require(
                session_id,
                tenant_id,
                worker_id,
                identity_hash,
                expected_version,
            )
            if current.terminal:
                raise WorkerDenied()
            if command is current.command:
                return current
            if current.command is WorkerCommand.SUPERSEDE or (
                current.command is WorkerCommand.CANCEL
                and command is WorkerCommand.CONTINUE
            ):
                raise WorkerDenied()
            updated = replace(current, version=_next_version(current), command=command)
            self._values[(tenant_id, session_id)] = updated
            return updated

    @staticmethod
    def _validate_identity(
        tenant_id: str,
        run_id: str,
        worker_id: str,
        identity_hash: str,
    ) -> None:
        if any(
            type(value) is not str or _IDENTIFIER.fullmatch(value) is None
            for value in (tenant_id, run_id, worker_id)
        ):
            raise WorkerDenied()
        if type(identity_hash) is not str or _SHA256.fullmatch(identity_hash) is None:
            raise WorkerDenied()

    @staticmethod
    def _valid_event(item: dict[str, object]) -> bool:
        if type(item) is not dict:
            return False
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
        if (
            type(session_id) is not str
            or type(tenant_id) is not str
            or type(worker_id) is not str
            or type(identity_hash) is not str
            or type(expected_version) is not int
        ):
            raise WorkerDenied()
        value = self._values.get((tenant_id, session_id))
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


def _next_version(value: WorkerSession) -> int:
    if type(value.version) is not int or not 1 <= value.version < _MAX_VERSION:
        raise WorkerDenied()
    return value.version + 1


__all__ = [
    "WorkerCommand",
    "WorkerDenied",
    "WorkerSession",
    "WorkerSessionStore",
    "WorkerSessions",
]
