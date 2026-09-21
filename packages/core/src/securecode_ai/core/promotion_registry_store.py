"""Transactional durable state for promotion aliases."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Protocol

from .promotion_decision import PromotionDecisionReceipt


class PromotionStoreError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PromotionAlias:
    alias: str
    revision: int
    content_sha256: str
    decision_sha256: str
    candidate_id: str
    candidate_version: int


class PromotionAliasStore(Protocol):
    def apply(self, decision: PromotionDecisionReceipt) -> PromotionAlias: ...
    def resolve(self, alias: str) -> PromotionAlias | None: ...


class InMemoryPromotionStore:
    """Explicit development/test store matching the SQLite transition rules."""

    def __init__(self) -> None:
        self._aliases: dict[str, PromotionAlias] = {}
        self._candidate_versions: dict[str, int] = {}
        self._version_content: dict[tuple[str, int], str] = {}
        self._history: set[tuple[str, str]] = set()
        self._alias_versions: dict[tuple[str, str], int] = {}
        self._consumed: dict[str, PromotionAlias] = {}
        self._nonces: dict[str, str] = {}
        self._lock = RLock()

    def apply(self, decision: PromotionDecisionReceipt) -> PromotionAlias:
        with self._lock:
            current = self._aliases.get(decision.target_alias)
            consumed = self._consumed.get(decision.authorization_sha256)
            if consumed is not None:
                if current == consumed:
                    return _copy(consumed)
                raise PromotionStoreError()
            if decision.transition_nonce in self._nonces:
                raise PromotionStoreError()
            _validate_transition(
                decision,
                current,
                self._candidate_versions.get(decision.candidate_id, 0),
                self._alias_versions.get((decision.target_alias, decision.candidate_id), 0),
                self._version_content.get((decision.candidate_id, decision.candidate_version)),
                (decision.target_alias, decision.content_sha256) in self._history,
            )
            value = _new_alias(decision, current)
            self._aliases[value.alias] = value
            self._history.add((value.alias, value.content_sha256))
            self._alias_versions[(value.alias, value.candidate_id)] = value.candidate_version
            self._candidate_versions[value.candidate_id] = max(
                self._candidate_versions.get(value.candidate_id, 0), value.candidate_version
            )
            self._version_content[(value.candidate_id, value.candidate_version)] = (
                value.content_sha256
            )
            self._nonces[decision.transition_nonce] = decision.authorization_sha256
            self._consumed[decision.authorization_sha256] = value
            return _copy(value)

    def resolve(self, alias: str) -> PromotionAlias | None:
        with self._lock:
            value = self._aliases.get(alias)
            return None if value is None else _copy(value)


class SqlitePromotionStore:
    """SQLite-backed alias state shared safely by processes and restarts."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path).resolve()
        if str(path) == ":memory:" or (self._path.exists() and not self._path.is_file()):
            raise PromotionStoreError()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript(_SCHEMA)
        finally:
            connection.close()

    def apply(self, decision: PromotionDecisionReceipt) -> PromotionAlias:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = _row_alias(
                connection.execute(
                    "SELECT * FROM promotion_aliases WHERE alias = ?", (decision.target_alias,)
                ).fetchone()
            )
            consumed = _row_alias(
                connection.execute(
                    "SELECT alias, revision, content_sha256, decision_sha256, candidate_id, "
                    "candidate_version FROM promotion_consumed WHERE authorization_sha256 = ?",
                    (decision.authorization_sha256,),
                ).fetchone()
            )
            if consumed is not None:
                if current != consumed:
                    raise PromotionStoreError()
                connection.commit()
                return consumed
            if (
                connection.execute(
                    "SELECT 1 FROM promotion_nonces WHERE transition_nonce = ?",
                    (decision.transition_nonce,),
                ).fetchone()
                is not None
            ):
                raise PromotionStoreError()
            global_row = connection.execute(
                "SELECT candidate_version FROM promotion_candidate_versions WHERE candidate_id = ?",
                (decision.candidate_id,),
            ).fetchone()
            alias_row = connection.execute(
                "SELECT candidate_version FROM promotion_alias_versions "
                "WHERE alias = ? AND candidate_id = ?",
                (decision.target_alias, decision.candidate_id),
            ).fetchone()
            content_row = connection.execute(
                "SELECT content_sha256 FROM promotion_version_content "
                "WHERE candidate_id = ? AND candidate_version = ?",
                (decision.candidate_id, decision.candidate_version),
            ).fetchone()
            in_history = (
                connection.execute(
                    "SELECT 1 FROM promotion_history WHERE alias = ? AND content_sha256 = ?",
                    (decision.target_alias, decision.content_sha256),
                ).fetchone()
                is not None
            )
            _validate_transition(
                decision,
                current,
                0 if global_row is None else int(global_row[0]),
                0 if alias_row is None else int(alias_row[0]),
                None if content_row is None else str(content_row[0]),
                in_history,
            )
            value = _new_alias(decision, current)
            self._write_transition(connection, decision, value)
            connection.commit()
            return value
        except (sqlite3.Error, PromotionStoreError):
            connection.rollback()
            raise PromotionStoreError() from None
        finally:
            connection.close()

    def resolve(self, alias: str) -> PromotionAlias | None:
        connection = self._connect()
        try:
            return _row_alias(
                connection.execute(
                    "SELECT * FROM promotion_aliases WHERE alias = ?", (alias,)
                ).fetchone()
            )
        except sqlite3.Error:
            raise PromotionStoreError() from None
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @staticmethod
    def _write_transition(
        connection: sqlite3.Connection,
        decision: PromotionDecisionReceipt,
        value: PromotionAlias,
    ) -> None:
        fields = (
            value.alias,
            value.revision,
            value.content_sha256,
            value.decision_sha256,
            value.candidate_id,
            value.candidate_version,
        )
        connection.execute(
            "INSERT INTO promotion_aliases VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(alias) DO UPDATE SET revision=excluded.revision, "
            "content_sha256=excluded.content_sha256, decision_sha256=excluded.decision_sha256, "
            "candidate_id=excluded.candidate_id, candidate_version=excluded.candidate_version",
            fields,
        )
        connection.execute(
            "INSERT INTO promotion_history VALUES (?, ?)", (value.alias, value.content_sha256)
        )
        connection.execute(
            "INSERT INTO promotion_alias_versions VALUES (?, ?, ?) "
            "ON CONFLICT(alias, candidate_id) DO UPDATE SET candidate_version=excluded.candidate_version",
            (value.alias, value.candidate_id, value.candidate_version),
        )
        connection.execute(
            "INSERT INTO promotion_candidate_versions VALUES (?, ?) "
            "ON CONFLICT(candidate_id) DO UPDATE SET candidate_version="
            "MAX(candidate_version, excluded.candidate_version)",
            (value.candidate_id, value.candidate_version),
        )
        connection.execute(
            "INSERT INTO promotion_version_content VALUES (?, ?, ?) "
            "ON CONFLICT(candidate_id, candidate_version) DO NOTHING",
            (value.candidate_id, value.candidate_version, value.content_sha256),
        )
        connection.execute(
            "INSERT INTO promotion_nonces VALUES (?, ?)",
            (decision.transition_nonce, decision.authorization_sha256),
        )
        connection.execute(
            "INSERT INTO promotion_consumed VALUES (?, ?, ?, ?, ?, ?, ?)",
            (decision.authorization_sha256, *fields),
        )


def _validate_transition(
    decision: PromotionDecisionReceipt,
    current: PromotionAlias | None,
    global_version: int,
    alias_version: int,
    bound_content: str | None,
    content_in_history: bool,
) -> None:
    current_revision = 0 if current is None else current.revision
    current_decision = None if current is None else current.decision_sha256
    if (
        current_revision != decision.expected_revision
        or current_decision != decision.expected_decision_sha256
        or content_in_history
        or decision.candidate_version <= alias_version
        or decision.candidate_version < global_version
        or (bound_content is not None and bound_content != decision.content_sha256)
    ):
        raise PromotionStoreError()


def _new_alias(
    decision: PromotionDecisionReceipt, current: PromotionAlias | None
) -> PromotionAlias:
    return PromotionAlias(
        decision.target_alias,
        1 if current is None else current.revision + 1,
        decision.content_sha256,
        decision.canonical_sha256,
        decision.candidate_id,
        decision.candidate_version,
    )


def _copy(value: PromotionAlias) -> PromotionAlias:
    return PromotionAlias(
        value.alias,
        value.revision,
        value.content_sha256,
        value.decision_sha256,
        value.candidate_id,
        value.candidate_version,
    )


def _row_alias(row: sqlite3.Row | None) -> PromotionAlias | None:
    if row is None:
        return None
    return PromotionAlias(
        str(row["alias"]),
        int(row["revision"]),
        str(row["content_sha256"]),
        str(row["decision_sha256"]),
        str(row["candidate_id"]),
        int(row["candidate_version"]),
    )


_SCHEMA = """
CREATE TABLE IF NOT EXISTS promotion_aliases (
 alias TEXT PRIMARY KEY, revision INTEGER NOT NULL, content_sha256 TEXT NOT NULL,
 decision_sha256 TEXT NOT NULL, candidate_id TEXT NOT NULL, candidate_version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS promotion_history (
 alias TEXT NOT NULL, content_sha256 TEXT NOT NULL, PRIMARY KEY(alias, content_sha256));
CREATE TABLE IF NOT EXISTS promotion_alias_versions (
 alias TEXT NOT NULL, candidate_id TEXT NOT NULL, candidate_version INTEGER NOT NULL,
 PRIMARY KEY(alias, candidate_id));
CREATE TABLE IF NOT EXISTS promotion_candidate_versions (
 candidate_id TEXT PRIMARY KEY, candidate_version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS promotion_version_content (
 candidate_id TEXT NOT NULL, candidate_version INTEGER NOT NULL, content_sha256 TEXT NOT NULL,
 PRIMARY KEY(candidate_id, candidate_version));
CREATE TABLE IF NOT EXISTS promotion_nonces (
 transition_nonce TEXT PRIMARY KEY, authorization_sha256 TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS promotion_consumed (
 authorization_sha256 TEXT PRIMARY KEY, alias TEXT NOT NULL, revision INTEGER NOT NULL,
 content_sha256 TEXT NOT NULL, decision_sha256 TEXT NOT NULL, candidate_id TEXT NOT NULL,
 candidate_version INTEGER NOT NULL);
"""


__all__ = [
    "InMemoryPromotionStore",
    "PromotionAlias",
    "PromotionAliasStore",
    "PromotionStoreError",
    "SqlitePromotionStore",
]
