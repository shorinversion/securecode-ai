"""Durable, append-only storage for source-free assurance receipts."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from threading import RLock
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_PAYLOAD_BYTES: Final = 65_536
_MAX_PAYLOAD_DEPTH: Final = 6
_MAX_COLLECTION_ITEMS: Final = 256
_FORBIDDEN_PAYLOAD_KEYS: Final = frozenset(
    {
        "access_token",
        "api_key",
        "code",
        "content",
        "credential",
        "password",
        "prompt",
        "raw",
        "raw_source",
        "secret",
        "snippet",
        "source_text",
        "token",
    }
)

ASSURANCE_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS assurance_records (
        tenant TEXT NOT NULL,
        repo TEXT NOT NULL,
        identity_hash TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK (sequence > 0),
        record_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        outcome TEXT NOT NULL,
        verifier_id TEXT NOT NULL,
        verifier_hash TEXT NOT NULL,
        payload TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        record_hash TEXT NOT NULL,
        PRIMARY KEY (tenant, repo, identity_hash, sequence),
        UNIQUE (tenant, repo, identity_hash, record_id)
    )""",
    """CREATE INDEX IF NOT EXISTS assurance_scope_records
       ON assurance_records (tenant, repo, identity_hash, record_id)""",
)


class AssuranceConflict(Exception):
    """A safe failure for invalid, conflicting, or corrupt assurance state."""


@dataclass(frozen=True, slots=True)
class AssuranceRecord:
    tenant_id: str
    repository_id: str
    execution_identity_hash: str
    record_id: str
    kind: str
    outcome: str
    verifier_id: str
    verifier_sha256: str
    payload: dict[str, object]
    sequence: int = 0
    previous_hash: str = ""
    record_hash: str = ""

    def __post_init__(self) -> None:
        if any(
            not _identifier(value)
            for value in (
                self.tenant_id,
                self.repository_id,
                self.record_id,
                self.kind,
                self.outcome,
                self.verifier_id,
            )
        ):
            raise AssuranceConflict()
        if not _sha256(self.execution_identity_hash) or not _sha256(self.verifier_sha256):
            raise AssuranceConflict()
        _canonical_payload(self.payload)
        if type(self.sequence) is not int or self.sequence < 0:
            raise AssuranceConflict()
        if self.sequence == 0:
            if self.previous_hash or self.record_hash:
                raise AssuranceConflict()
        elif not _sha256(self.previous_hash) or not _sha256(self.record_hash):
            raise AssuranceConflict()


class AssuranceRepository:
    """SQLite assurance chain with tenant predicates and idempotent appends."""

    def __init__(self, connection: sqlite3.Connection, *, initialize: bool = True) -> None:
        self._db = connection
        self._lock = RLock()
        if initialize:
            for statement in ASSURANCE_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            self._db.commit()

    @classmethod
    def in_memory(cls) -> AssuranceRepository:
        return cls(sqlite3.connect(":memory:"))

    def append(
        self,
        value: AssuranceRecord,
        *,
        expected_sequence: int | None = None,
    ) -> AssuranceRecord:
        if type(value) is not AssuranceRecord or value.sequence != 0:
            raise AssuranceConflict()
        if expected_sequence is not None and (
            type(expected_sequence) is not int or expected_sequence < 0
        ):
            raise AssuranceConflict()
        payload_json = _canonical_payload(value.payload)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._load_by_id(
                    value.tenant_id,
                    value.repository_id,
                    value.execution_identity_hash,
                    value.record_id,
                )
                if replay is not None:
                    if _same_request(replay, value):
                        self._db.commit()
                        return replay
                    raise AssuranceConflict()

                latest = self._db.execute(
                    """SELECT sequence, record_hash
                       FROM assurance_records
                       WHERE tenant=? AND repo=? AND identity_hash=?
                       ORDER BY sequence DESC LIMIT 1""",
                    (
                        value.tenant_id,
                        value.repository_id,
                        value.execution_identity_hash,
                    ),
                ).fetchone()
                current_sequence = 0 if latest is None else int(latest[0])
                if expected_sequence is not None and expected_sequence != current_sequence:
                    raise AssuranceConflict()
                sequence = current_sequence + 1
                previous_hash = "0" * 64 if latest is None else str(latest[1])
                material = _record_material(
                    value,
                    sequence=sequence,
                    previous_hash=previous_hash,
                )
                record_hash = _hash(material)
                record = AssuranceRecord(
                    tenant_id=value.tenant_id,
                    repository_id=value.repository_id,
                    execution_identity_hash=value.execution_identity_hash,
                    record_id=value.record_id,
                    kind=value.kind,
                    outcome=value.outcome,
                    verifier_id=value.verifier_id,
                    verifier_sha256=value.verifier_sha256,
                    payload=value.payload,
                    sequence=sequence,
                    previous_hash=previous_hash,
                    record_hash=record_hash,
                )
                self._db.execute(
                    """INSERT INTO assurance_records (
                           tenant, repo, identity_hash, sequence, record_id, kind,
                           outcome, verifier_id, verifier_hash, payload,
                           previous_hash, record_hash
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record.tenant_id,
                        record.repository_id,
                        record.execution_identity_hash,
                        record.sequence,
                        record.record_id,
                        record.kind,
                        record.outcome,
                        record.verifier_id,
                        record.verifier_sha256,
                        payload_json,
                        record.previous_hash,
                        record.record_hash,
                    ),
                )
                self._db.commit()
                return record
            except sqlite3.IntegrityError as error:
                self._db.rollback()
                raise AssuranceConflict() from error
            except Exception:
                self._db.rollback()
                raise

    def list(
        self,
        tenant: str,
        repo: str,
        identity: str,
    ) -> tuple[AssuranceRecord, ...]:
        if not _identifier(tenant) or not _identifier(repo) or not _sha256(identity):
            raise AssuranceConflict()
        with self._lock:
            rows = self._db.execute(
                """SELECT sequence, record_id, kind, outcome, verifier_id,
                          verifier_hash, payload, previous_hash, record_hash
                   FROM assurance_records
                   WHERE tenant=? AND repo=? AND identity_hash=?
                   ORDER BY sequence""",
                (tenant, repo, identity),
            ).fetchall()
        records = tuple(_from_row(tenant, repo, identity, row) for row in rows)
        _verify_chain(records)
        return records

    def _load_by_id(
        self,
        tenant_id: str,
        repository_id: str,
        identity_hash: str,
        record_id: str,
    ) -> AssuranceRecord | None:
        row = self._db.execute(
            """SELECT sequence, record_id, kind, outcome, verifier_id,
                      verifier_hash, payload, previous_hash, record_hash
               FROM assurance_records
               WHERE tenant=? AND repo=? AND identity_hash=? AND record_id=?""",
            (tenant_id, repository_id, identity_hash, record_id),
        ).fetchone()
        if row is None:
            return None
        return _from_row(tenant_id, repository_id, identity_hash, row)


def _from_row(
    tenant_id: str,
    repository_id: str,
    identity_hash: str,
    row: tuple[object, ...],
) -> AssuranceRecord:
    try:
        payload = json.loads(str(row[6]))
        if type(payload) is not dict:
            raise AssuranceConflict()
        return AssuranceRecord(
            tenant_id=tenant_id,
            repository_id=repository_id,
            execution_identity_hash=identity_hash,
            record_id=str(row[1]),
            kind=str(row[2]),
            outcome=str(row[3]),
            verifier_id=str(row[4]),
            verifier_sha256=str(row[5]),
            payload=payload,
            sequence=_stored_int(row[0]),
            previous_hash=str(row[7]),
            record_hash=str(row[8]),
        )
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise AssuranceConflict() from error


def _stored_int(value: object) -> int:
    if type(value) is not int:
        raise AssuranceConflict()
    return value


def _same_request(stored: AssuranceRecord, requested: AssuranceRecord) -> bool:
    return (
        stored.tenant_id,
        stored.repository_id,
        stored.execution_identity_hash,
        stored.record_id,
        stored.kind,
        stored.outcome,
        stored.verifier_id,
        stored.verifier_sha256,
        stored.payload,
    ) == (
        requested.tenant_id,
        requested.repository_id,
        requested.execution_identity_hash,
        requested.record_id,
        requested.kind,
        requested.outcome,
        requested.verifier_id,
        requested.verifier_sha256,
        requested.payload,
    )


def _record_material(
    value: AssuranceRecord,
    *,
    sequence: int,
    previous_hash: str,
) -> dict[str, object]:
    return {
        "tenant_id": value.tenant_id,
        "repository_id": value.repository_id,
        "execution_identity_hash": value.execution_identity_hash,
        "record_id": value.record_id,
        "kind": value.kind,
        "outcome": value.outcome,
        "verifier_id": value.verifier_id,
        "verifier_sha256": value.verifier_sha256,
        "payload": value.payload,
        "sequence": sequence,
        "previous_hash": previous_hash,
    }


def _verify_chain(records: tuple[AssuranceRecord, ...]) -> None:
    previous_hash = "0" * 64
    for sequence, record in enumerate(records, start=1):
        if record.sequence != sequence or record.previous_hash != previous_hash:
            raise AssuranceConflict()
        material = _record_material(
            record,
            sequence=sequence,
            previous_hash=previous_hash,
        )
        if _hash(material) != record.record_hash:
            raise AssuranceConflict()
        previous_hash = record.record_hash


def _canonical_payload(payload: object) -> str:
    if type(payload) is not dict:
        raise AssuranceConflict()
    _validate_json_value(payload, depth=0)
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise AssuranceConflict() from error
    if len(encoded.encode("ascii")) > _MAX_PAYLOAD_BYTES:
        raise AssuranceConflict()
    return encoded


def _validate_json_value(value: object, *, depth: int) -> None:
    if depth > _MAX_PAYLOAD_DEPTH:
        raise AssuranceConflict()
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise AssuranceConflict()
        return
    if type(value) is str:
        if len(value) > 1024 or any(ord(char) < 32 for char in value):
            raise AssuranceConflict()
        return
    if type(value) is list:
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise AssuranceConflict()
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if type(value) is dict:
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise AssuranceConflict()
        for key, item in value.items():
            if not _identifier(key) or key.lower() in _FORBIDDEN_PAYLOAD_KEYS:
                raise AssuranceConflict()
            _validate_json_value(item, depth=depth + 1)
        return
    raise AssuranceConflict()


def _hash(material: dict[str, object]) -> str:
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(b"securecode-ai/server-assurance/v1\x00" + encoded).hexdigest()


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


__all__ = [
    "ASSURANCE_SCHEMA_STATEMENTS",
    "AssuranceConflict",
    "AssuranceRecord",
    "AssuranceRepository",
]
