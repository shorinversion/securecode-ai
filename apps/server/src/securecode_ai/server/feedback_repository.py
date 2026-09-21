"""Durable tenant-scoped storage for source-free AppSec feedback receipts."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import asdict, dataclass, replace
from threading import RLock
from typing import Final

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_SHA1: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_DECISIONS: Final = frozenset({"accept", "reject"})
_REASONS: Final = frozenset({"accepted_risk", "false_positive", "incident", "patch_rejected"})

FEEDBACK_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS feedback_records (
        tenant TEXT NOT NULL,
        repo TEXT NOT NULL,
        run TEXT NOT NULL,
        finding TEXT NOT NULL,
        head TEXT NOT NULL,
        identity_hash TEXT NOT NULL,
        body TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL,
        version INTEGER NOT NULL CHECK (version = 1),
        PRIMARY KEY (tenant, repo, finding)
    )""",
    """CREATE INDEX IF NOT EXISTS feedback_scope_records
       ON feedback_records (tenant, repo, run, finding)""",
)


class FeedbackConflict(Exception):
    """A safe failure for invalid or conflicting feedback."""


@dataclass(frozen=True, slots=True)
class Feedback:
    tenant_id: str
    repository_id: str
    run_id: str
    finding_id: str
    head_sha: str
    identity_hash: str
    decision: str
    reason: str
    rationale_sha256: str
    incident_id: str | None = None
    version: int = 0
    receipt_sha256: str = ""

    def __post_init__(self) -> None:
        if any(
            not _identifier(value)
            for value in (
                self.tenant_id,
                self.repository_id,
                self.run_id,
                self.finding_id,
            )
        ):
            raise FeedbackConflict()
        if (
            not _sha1(self.head_sha)
            or not _sha256(self.identity_hash)
            or self.decision not in _DECISIONS
            or self.reason not in _REASONS
            or not _sha256(self.rationale_sha256)
        ):
            raise FeedbackConflict()
        if self.incident_id is not None and not _identifier(self.incident_id):
            raise FeedbackConflict()
        if self.reason == "incident" and self.incident_id is None:
            raise FeedbackConflict()
        if self.version == 0:
            if self.receipt_sha256:
                raise FeedbackConflict()
        elif self.version != 1 or not _sha256(self.receipt_sha256):
            raise FeedbackConflict()


class FeedbackRepository:
    """Append-once SQLite repository with idempotent identical replay."""

    def __init__(self, db: sqlite3.Connection, *, initialize: bool = True) -> None:
        self._db = db
        self._lock = RLock()
        if initialize:
            for statement in FEEDBACK_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            self._db.commit()

    @classmethod
    def in_memory(cls) -> FeedbackRepository:
        return cls(sqlite3.connect(":memory:"))

    @property
    def db(self) -> sqlite3.Connection:
        """Compatibility accessor for the underlying owned connection."""

        return self._db

    def save(self, value: Feedback, *, expected_version: int = 0) -> Feedback:
        if type(value) is not Feedback or value.version != 0:
            raise FeedbackConflict()
        if type(expected_version) is not int or expected_version != 0:
            raise FeedbackConflict()
        receipt_hash = _receipt_hash(value)
        stored = replace(value, version=1, receipt_sha256=receipt_hash)
        body = _canonical(stored)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                prior = self._load(
                    value.tenant_id,
                    value.repository_id,
                    value.finding_id,
                )
                if prior is not None:
                    if prior == stored:
                        self._db.commit()
                        return prior
                    raise FeedbackConflict()
                self._db.execute(
                    """INSERT INTO feedback_records (
                           tenant, repo, run, finding, head, identity_hash,
                           body, receipt_sha256, version
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        stored.tenant_id,
                        stored.repository_id,
                        stored.run_id,
                        stored.finding_id,
                        stored.head_sha,
                        stored.identity_hash,
                        body,
                        stored.receipt_sha256,
                        stored.version,
                    ),
                )
                self._db.commit()
                return stored
            except sqlite3.IntegrityError as error:
                self._db.rollback()
                raise FeedbackConflict() from error
            except Exception:
                self._db.rollback()
                raise

    def list(self, tenant: str, repository: str) -> tuple[Feedback, ...]:
        if not _identifier(tenant) or not _identifier(repository):
            raise FeedbackConflict()
        with self._lock:
            rows = self._db.execute(
                """SELECT body FROM feedback_records
                   WHERE tenant=? AND repo=? ORDER BY finding""",
                (tenant, repository),
            ).fetchall()
        return tuple(_decode(row[0]) for row in rows)

    def _load(
        self,
        tenant_id: str,
        repository_id: str,
        finding_id: str,
    ) -> Feedback | None:
        row = self._db.execute(
            """SELECT body FROM feedback_records
               WHERE tenant=? AND repo=? AND finding=?""",
            (tenant_id, repository_id, finding_id),
        ).fetchone()
        return None if row is None else _decode(row[0])


def _decode(value: object) -> Feedback:
    try:
        document = json.loads(str(value))
        if type(document) is not dict:
            raise FeedbackConflict()
        feedback = Feedback(**document)
        if (
            feedback.version != 1
            or _receipt_hash(
                replace(
                    feedback,
                    version=0,
                    receipt_sha256="",
                )
            )
            != feedback.receipt_sha256
        ):
            raise FeedbackConflict()
        return feedback
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise FeedbackConflict() from error


def _canonical(value: Feedback) -> str:
    return json.dumps(
        asdict(value),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _receipt_hash(value: Feedback) -> str:
    material = asdict(value)
    material.pop("version", None)
    material.pop("receipt_sha256", None)
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(b"securecode-ai/feedback-receipt/v1\x00" + encoded).hexdigest()


def _identifier(value: object) -> bool:
    return type(value) is str and _ID.fullmatch(value) is not None


def _sha1(value: object) -> bool:
    return type(value) is str and _SHA1.fullmatch(value) is not None


def _sha256(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


__all__ = [
    "FEEDBACK_SCHEMA_STATEMENTS",
    "Feedback",
    "FeedbackConflict",
    "FeedbackRepository",
]
