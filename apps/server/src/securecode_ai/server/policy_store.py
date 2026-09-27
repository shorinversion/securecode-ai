"""Durable tenant policy versions, CAS activation, and effective resolution."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Final

from .profiles import ProfileConflict, RolloutMode, ScanProfile, WaiverReference

POLICY_STORE_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS scan_policy_versions (
        tenant_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        content_sha256 TEXT NOT NULL,
        rollout TEXT NOT NULL,
        calibrated INTEGER NOT NULL,
        content_json TEXT NOT NULL,
        PRIMARY KEY (tenant_id, profile_id, version),
        UNIQUE (tenant_id, profile_id, content_sha256),
        CHECK (version >= 1),
        CHECK (calibrated IN (0, 1))
    )""",
    """CREATE TABLE IF NOT EXISTS scan_policy_active (
        tenant_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        version INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, profile_id),
        FOREIGN KEY (tenant_id, profile_id, version)
            REFERENCES scan_policy_versions (tenant_id, profile_id, version)
    )""",
    """CREATE TABLE IF NOT EXISTS scan_policy_repository_assignments (
        tenant_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        profile_version INTEGER NOT NULL,
        assignment_version INTEGER NOT NULL,
        PRIMARY KEY (tenant_id, repository_id),
        FOREIGN KEY (tenant_id, profile_id, profile_version)
            REFERENCES scan_policy_versions (tenant_id, profile_id, version)
    )""",
    """CREATE TABLE IF NOT EXISTS scan_policy_tenant_defaults (
        tenant_id TEXT PRIMARY KEY,
        profile_id TEXT NOT NULL,
        profile_version INTEGER NOT NULL,
        assignment_version INTEGER NOT NULL,
        FOREIGN KEY (tenant_id, profile_id, profile_version)
            REFERENCES scan_policy_versions (tenant_id, profile_id, version)
    )""",
    """CREATE TABLE IF NOT EXISTS scan_policy_idempotency (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        operation TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        result_json TEXT NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key)
    )""",
)


class PolicyStore:
    """SQLite-backed immutable policy registry with tenant-scoped projections."""

    def __init__(
        self,
        connection: sqlite3.Connection | None = None,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if connection is not None and type(connection) is not sqlite3.Connection:
            raise ProfileConflict("policy storage is invalid")
        if not callable(now):
            raise ProfileConflict("policy clock is invalid")
        self._db = (
            connection
            if connection is not None
            else sqlite3.connect(":memory:", check_same_thread=False)
        )
        self._now = now
        self._lock = threading.RLock()
        try:
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA busy_timeout = 5000")
            self._db.execute("PRAGMA synchronous = FULL")
            for statement in POLICY_STORE_SCHEMA_STATEMENTS:
                self._db.execute(statement)
            self._db.commit()
        except sqlite3.Error as error:
            raise ProfileConflict("policy storage is unavailable") from error

    def create(self, profile: ScanProfile, *, idempotency_key: str) -> ScanProfile:
        if type(profile) is not ScanProfile:
            raise ProfileConflict("policy profile is invalid")
        _require_identifier(profile.tenant_id)
        _require_identifier(profile.profile_id)
        key = _require_key(idempotency_key)
        content_json = _canonical_profile_content(profile.content)
        if hashlib.sha256(content_json.encode("ascii")).hexdigest() != profile.content_sha256:
            raise ProfileConflict("profile content hash does not match")
        fingerprint = _digest(_profile_document(profile))
        with self._lock:
            self._begin()
            try:
                replay = self._replay(profile.tenant_id, key)
                if replay is not None:
                    if replay[0] != "create" or replay[1] != fingerprint:
                        raise ProfileConflict("idempotency key was reused")
                    result = self._load(profile.tenant_id, profile.profile_id, profile.version)
                    if result is None:
                        raise ProfileConflict("policy replay is incomplete")
                    self._db.commit()
                    return result
                existing = self._load(profile.tenant_id, profile.profile_id, profile.version)
                if existing is not None:
                    raise ProfileConflict("policy version already exists")
                if (
                    profile.version > 1
                    and self._load(profile.tenant_id, profile.profile_id, profile.version - 1)
                    is None
                ):
                    raise ProfileConflict("policy versions must be contiguous")
                self._db.execute(
                    """INSERT INTO scan_policy_versions (
                           tenant_id, profile_id, version, content_sha256,
                           rollout, calibrated, content_json
                       ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        profile.tenant_id,
                        profile.profile_id,
                        profile.version,
                        profile.content_sha256,
                        profile.rollout.value,
                        int(profile.calibrated),
                        content_json,
                    ),
                )
                self._record_replay(
                    profile.tenant_id,
                    key,
                    "create",
                    fingerprint,
                    {"profile_id": profile.profile_id, "version": profile.version},
                )
                self._db.commit()
                return profile
            except sqlite3.Error as error:
                self._db.rollback()
                raise ProfileConflict("policy storage is unavailable") from error
            except Exception:
                self._db.rollback()
                raise

    def activate(
        self,
        *,
        tenant_id: str,
        profile_id: str,
        version: int,
        expected_active: int | None,
        idempotency_key: str | None = None,
    ) -> ScanProfile:
        _require_identifier(tenant_id)
        _require_identifier(profile_id)
        _require_version(version)
        if expected_active is not None:
            _require_version(expected_active)
        fingerprint = _digest(
            {
                "tenant_id": tenant_id,
                "profile_id": profile_id,
                "version": version,
                "expected_active": expected_active,
            }
        )
        key = None if idempotency_key is None else _require_key(idempotency_key)
        with self._lock:
            self._begin()
            try:
                if key is not None:
                    replay = self._replay(tenant_id, key)
                    if replay is not None:
                        if replay[0] != "activate" or replay[1] != fingerprint:
                            raise ProfileConflict("idempotency key was reused")
                        result = self._load(tenant_id, profile_id, version)
                        if result is None:
                            raise ProfileConflict("policy replay is incomplete")
                        self._db.commit()
                        return result
                profile = self._load(tenant_id, profile_id, version)
                if profile is None:
                    raise ProfileConflict("policy version does not exist")
                row = self._db.execute(
                    "SELECT version FROM scan_policy_active WHERE tenant_id = ? AND profile_id = ?",
                    (tenant_id, profile_id),
                ).fetchone()
                if row is not None and (
                    not _is_storage_row(row)
                    or len(row) != 1
                    or type(row[0]) is not int
                    or row[0] < 1
                ):
                    raise ProfileConflict("stored active policy is invalid")
                current = None if row is None else row[0]
                if current != expected_active:
                    raise ProfileConflict("active policy version changed")
                self._db.execute(
                    """INSERT INTO scan_policy_active (tenant_id, profile_id, version)
                       VALUES (?, ?, ?)
                       ON CONFLICT (tenant_id, profile_id)
                       DO UPDATE SET version = excluded.version""",
                    (tenant_id, profile_id, version),
                )
                if key is not None:
                    self._record_replay(
                        tenant_id,
                        key,
                        "activate",
                        fingerprint,
                        {"profile_id": profile_id, "version": version},
                    )
                self._db.commit()
                return profile
            except sqlite3.Error as error:
                self._db.rollback()
                raise ProfileConflict("policy storage is unavailable") from error
            except Exception:
                self._db.rollback()
                raise

    def assign_repository(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        profile_id: str,
        version: int,
        expected_assignment_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        _require_identifier(repository_id)
        self._assign(
            table="scan_policy_repository_assignments",
            operation="assign_repository",
            tenant_id=tenant_id,
            scope_column="repository_id",
            scope_value=repository_id,
            profile_id=profile_id,
            version=version,
            expected_assignment_version=expected_assignment_version,
            idempotency_key=idempotency_key,
        )

    def set_tenant_default(
        self,
        *,
        tenant_id: str,
        profile_id: str,
        version: int,
        expected_assignment_version: int | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        self._assign(
            table="scan_policy_tenant_defaults",
            operation="set_tenant_default",
            tenant_id=tenant_id,
            scope_column=None,
            scope_value=None,
            profile_id=profile_id,
            version=version,
            expected_assignment_version=expected_assignment_version,
            idempotency_key=idempotency_key,
        )

    def resolve(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        waivers: tuple[WaiverReference, ...] = (),
    ) -> dict[str, object]:
        if type(waivers) is not tuple or any(type(item) is not WaiverReference for item in waivers):
            raise ProfileConflict("waiver references are invalid")
        profile = self.resolve_profile(tenant_id=tenant_id, repository_id=repository_id)
        now = _checked_now(self._now)
        waiver_documents: list[dict[str, str]] = []
        for item in waivers:
            try:
                expiry = datetime.fromisoformat(item.expires_at)
            except (TypeError, ValueError) as error:
                raise ProfileConflict("waiver expiry is invalid") from error
            if expiry.tzinfo is None or expiry.utcoffset() is None:
                raise ProfileConflict("waiver expiry is invalid")
            if expiry <= now:
                continue
            _require_identifier(item.waiver_id)
            _require_reference(item.reason_ref)
            waiver_documents.append(
                {
                    "waiver_id": item.waiver_id,
                    "expires_at": item.expires_at,
                    "reason_ref": item.reason_ref,
                }
            )
        return {
            "profile_id": profile.profile_id,
            "profile_version": profile.version,
            "content_sha256": profile.content_sha256,
            "rollout": profile.rollout.value,
            "waiver_refs": tuple(waiver_documents),
        }

    def resolve_profile(self, *, tenant_id: str, repository_id: str) -> ScanProfile:
        """Return the exact assigned immutable profile for trusted runtime evaluation."""

        _require_identifier(tenant_id)
        _require_identifier(repository_id)
        try:
            with self._lock:
                row = self._db.execute(
                    """SELECT profile_id, profile_version
                       FROM scan_policy_repository_assignments
                       WHERE tenant_id = ? AND repository_id = ?""",
                    (tenant_id, repository_id),
                ).fetchone()
                if row is None:
                    row = self._db.execute(
                        """SELECT profile_id, profile_version
                           FROM scan_policy_tenant_defaults WHERE tenant_id = ?""",
                        (tenant_id,),
                    ).fetchone()
                if (
                    row is None
                    or not _is_storage_row(row)
                    or len(row) != 2
                    or type(row[0]) is not str
                    or type(row[1]) is not int
                    or row[1] < 1
                ):
                    raise ProfileConflict("no policy is assigned in tenant scope")
                profile = self._load(tenant_id, row[0], row[1])
                if profile is None:
                    raise ProfileConflict("assigned policy version does not exist")
                return profile
        except sqlite3.Error as error:
            raise ProfileConflict("policy storage is unavailable") from error

    def get_profile(self, *, tenant_id: str, profile_id: str, version: int) -> ScanProfile:
        """Load one immutable version without crossing the tenant boundary."""

        _require_identifier(tenant_id)
        _require_identifier(profile_id)
        _require_version(version)
        profile = self._load(tenant_id, profile_id, version)
        if profile is None:
            raise ProfileConflict("policy version does not exist")
        return profile

    def list(
        self,
        *,
        tenant_id: str,
        cursor: str | None = None,
        limit: int = 50,
    ) -> dict[str, object]:
        _require_identifier(tenant_id)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ProfileConflict("page limit is invalid")
        after_profile, after_version = _decode_cursor(cursor, tenant_id)
        try:
            with self._lock:
                rows = self._db.execute(
                    """SELECT tenant_id, profile_id, version, content_sha256,
                              rollout, calibrated, content_json
                       FROM scan_policy_versions
                       WHERE tenant_id = ?
                         AND (profile_id > ? OR (profile_id = ? AND version > ?))
                       ORDER BY profile_id, version LIMIT ?""",
                    (tenant_id, after_profile, after_profile, after_version, limit + 1),
                ).fetchall()
        except sqlite3.Error as error:
            raise ProfileConflict("policy storage is unavailable") from error
        page = rows[:limit]
        for row in page:
            if (
                not _is_storage_row(row)
                or len(row) != 7
                or type(row[0]) is not str
                or row[0] != tenant_id
                or type(row[1]) is not str
                or type(row[2]) is not int
                or row[2] < 1
                or type(row[3]) is not str
                or len(row[3]) != 64
                or any(item not in "0123456789abcdef" for item in row[3])
                or type(row[4]) is not str
                or row[4] not in {mode.value for mode in RolloutMode}
                or type(row[5]) is not int
                or row[5] not in {0, 1}
                or type(row[6]) is not str
            ):
                raise ProfileConflict("stored policy profile is invalid")
        items = [
            {
                "profile_id": row[1],
                "version": row[2],
                "content_sha256": row[3],
                "rollout": row[4],
                "calibrated": row[5] == 1,
            }
            for row in page
        ]
        next_cursor = None
        if len(rows) > limit and page:
            next_cursor = _encode_cursor(tenant_id, str(page[-1][1]), int(page[-1][2]))
        return {"items": items, "next_cursor": next_cursor}

    def _assign(
        self,
        *,
        table: str,
        operation: str,
        tenant_id: str,
        scope_column: str | None,
        scope_value: str | None,
        profile_id: str,
        version: int,
        expected_assignment_version: int | None,
        idempotency_key: str | None,
    ) -> None:
        _require_identifier(tenant_id)
        _require_identifier(profile_id)
        _require_version(version)
        if expected_assignment_version is not None:
            _require_version(expected_assignment_version)
        key = None if idempotency_key is None else _require_key(idempotency_key)
        fingerprint = _digest(
            {
                "operation": operation,
                "tenant_id": tenant_id,
                "scope_column": scope_column,
                "scope_value": scope_value,
                "profile_id": profile_id,
                "version": version,
                "expected_assignment_version": expected_assignment_version,
            }
        )
        with self._lock:
            self._begin()
            try:
                if key is not None:
                    replay = self._replay(tenant_id, key)
                    if replay is not None:
                        if replay[0] != operation or replay[1] != fingerprint:
                            raise ProfileConflict("idempotency key was reused")
                        self._db.commit()
                        return
                if self._load(tenant_id, profile_id, version) is None:
                    raise ProfileConflict("policy version does not exist")
                active = self._db.execute(
                    "SELECT version FROM scan_policy_active WHERE tenant_id = ? AND profile_id = ?",
                    (tenant_id, profile_id),
                ).fetchone()
                if active is None or int(active[0]) != version:
                    raise ProfileConflict("policy version is not active")
                where = "tenant_id = ?"
                params: tuple[object, ...] = (tenant_id,)
                if scope_column is not None:
                    where += f" AND {scope_column} = ?"
                    params += (scope_value,)
                row = self._db.execute(
                    f"SELECT profile_id, profile_version, assignment_version FROM {table} WHERE {where}",
                    params,
                ).fetchone()
                if row is not None and (
                    not _is_storage_row(row)
                    or len(row) != 3
                    or type(row[0]) is not str
                    or type(row[1]) is not int
                    or type(row[2]) is not int
                    or row[1] < 1
                    or row[2] < 1
                ):
                    raise ProfileConflict("stored policy assignment is invalid")
                current_version = None if row is None else row[2]
                if row is not None and (row[0], row[1]) == (profile_id, version):
                    if (
                        expected_assignment_version is not None
                        and current_version != expected_assignment_version
                    ):
                        raise ProfileConflict("policy assignment changed")
                    if key is not None:
                        self._record_replay(
                            tenant_id,
                            key,
                            operation,
                            fingerprint,
                            {"profile_id": profile_id, "version": version},
                        )
                    self._db.commit()
                    return
                if current_version != expected_assignment_version:
                    raise ProfileConflict("policy assignment changed")
                next_version = 1 if current_version is None else current_version + 1
                if scope_column is None:
                    self._db.execute(
                        """INSERT INTO scan_policy_tenant_defaults
                               (tenant_id, profile_id, profile_version, assignment_version)
                           VALUES (?, ?, ?, ?)
                           ON CONFLICT (tenant_id) DO UPDATE SET
                               profile_id = excluded.profile_id,
                               profile_version = excluded.profile_version,
                               assignment_version = excluded.assignment_version""",
                        (tenant_id, profile_id, version, next_version),
                    )
                else:
                    self._db.execute(
                        """INSERT INTO scan_policy_repository_assignments
                               (tenant_id, repository_id, profile_id,
                                profile_version, assignment_version)
                           VALUES (?, ?, ?, ?, ?)
                           ON CONFLICT (tenant_id, repository_id) DO UPDATE SET
                               profile_id = excluded.profile_id,
                               profile_version = excluded.profile_version,
                               assignment_version = excluded.assignment_version""",
                        (tenant_id, scope_value, profile_id, version, next_version),
                    )
                if key is not None:
                    self._record_replay(
                        tenant_id,
                        key,
                        operation,
                        fingerprint,
                        {"profile_id": profile_id, "version": version},
                    )
                self._db.commit()
            except sqlite3.Error as error:
                self._db.rollback()
                raise ProfileConflict("policy storage is unavailable") from error
            except Exception:
                self._db.rollback()
                raise

    def _load(self, tenant_id: str, profile_id: str, version: int) -> ScanProfile | None:
        row = self._db.execute(
            """SELECT tenant_id, profile_id, version, content_sha256,
                      rollout, calibrated, content_json
               FROM scan_policy_versions
               WHERE tenant_id = ? AND profile_id = ? AND version = ?""",
            (tenant_id, profile_id, version),
        ).fetchone()
        if row is None:
            return None
        if (
            not _is_storage_row(row)
            or len(row) != 7
            or not all(type(item) is str for item in (row[0], row[1], row[3], row[4], row[6]))
            or type(row[2]) is not int
            or type(row[5]) is not int
            or row[5] not in {0, 1}
            or row[0] != tenant_id
            or row[1] != profile_id
            or row[2] != version
        ):
            raise ProfileConflict("stored policy profile is invalid")
        try:
            content = json.loads(row[6])
            if not isinstance(content, dict):
                raise ProfileConflict("stored policy content is invalid")
            canonical_content = _canonical_profile_content(content)
            if hashlib.sha256(canonical_content.encode("ascii")).hexdigest() != row[3]:
                raise ProfileConflict("stored policy content integrity failed")
            return ScanProfile(
                tenant_id=row[0],
                profile_id=row[1],
                version=row[2],
                content_sha256=row[3],
                rollout=RolloutMode(row[4]),
                calibrated=row[5] == 1,
                content=content,
            )
        except ProfileConflict:
            raise
        except json.JSONDecodeError:
            raise ProfileConflict("stored policy content is invalid") from None
        except (TypeError, ValueError):
            raise ProfileConflict("stored policy profile is invalid") from None

    def _replay(self, tenant_id: str, key: str) -> tuple[str, str, str] | None:
        row = self._db.execute(
            """SELECT operation, request_sha256, result_json
               FROM scan_policy_idempotency
               WHERE tenant_id = ? AND idempotency_key = ?""",
            (tenant_id, key),
        ).fetchone()
        if row is None:
            return None
        if (
            not _is_storage_row(row)
            or len(row) != 3
            or not all(type(item) is str for item in row)
            or row[0]
            not in {
                "create",
                "activate",
                "assign_repository",
                "set_tenant_default",
            }
            or len(row[1]) != 64
            or any(item not in "0123456789abcdef" for item in row[1])
            or len(row[2]) > 1_048_576
        ):
            raise ProfileConflict("stored policy replay is invalid")
        return row[0], row[1], row[2]

    def _record_replay(
        self,
        tenant_id: str,
        key: str,
        operation: str,
        fingerprint: str,
        result: dict[str, object],
    ) -> None:
        self._db.execute(
            "INSERT INTO scan_policy_idempotency VALUES (?, ?, ?, ?, ?)",
            (tenant_id, key, operation, fingerprint, _canonical(result)),
        )

    def _begin(self) -> None:
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            raise ProfileConflict("policy storage is unavailable") from error


_FORBIDDEN_PROFILE_KEYS = frozenset({"raw_source", "source_code", "prompt_text", "secret"})


def _is_storage_row(value: object) -> bool:
    return type(value) is tuple or type(value) is sqlite3.Row


def _canonical_profile_content(content: Mapping[str, object]) -> str:
    _validate_value(content, depth=0)
    payload = _canonical(_plain_json(content))
    if len(payload.encode("ascii")) > 1_048_576:
        raise ProfileConflict("policy content is too large")
    return payload


def _validate_value(value: object, *, depth: int) -> None:
    if depth > 12:
        raise ProfileConflict("policy content is too deeply nested")
    if value is None or type(value) in {str, int, float, bool}:
        if isinstance(value, str) and len(value) > 16_384:
            raise ProfileConflict("policy string is too long")
        return
    if isinstance(value, Mapping):
        if len(value) > 512:
            raise ProfileConflict("policy object is too large")
        for key, item in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise ProfileConflict("policy key is invalid")
            if key.casefold() in _FORBIDDEN_PROFILE_KEYS:
                raise ProfileConflict("raw or secret material cannot be persisted in policy")
            _validate_value(item, depth=depth + 1)
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if len(value) > 2048:
            raise ProfileConflict("policy array is too large")
        for item in value:
            _validate_value(item, depth=depth + 1)
        return
    raise ProfileConflict("policy content contains an unsupported value")


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as error:
        raise ProfileConflict("policy content is not canonical JSON") from error


def _plain_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_plain_json(item) for item in value]
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _profile_document(profile: ScanProfile) -> dict[str, object]:
    return {
        "tenant_id": profile.tenant_id,
        "profile_id": profile.profile_id,
        "version": profile.version,
        "content_sha256": profile.content_sha256,
        "rollout": profile.rollout.value,
        "calibrated": profile.calibrated,
    }


def _require_identifier(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 256:
        raise ProfileConflict("identifier is invalid")
    if (
        value != value.strip()
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise ProfileConflict("identifier contains unsupported characters")
    return value


def _require_reference(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 512:
        raise ProfileConflict("waiver reason reference is invalid")
    if value != value.strip() or any(ord(character) < 33 for character in value):
        raise ProfileConflict("waiver reason reference is invalid")
    return value


def _require_version(value: object) -> int:
    if type(value) is not int or value < 1:
        raise ProfileConflict("version is invalid")
    return value


def _checked_now(source: Callable[[], datetime]) -> datetime:
    try:
        value = source()
        if (
            type(value) is not datetime
            or value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError
        return value.astimezone(UTC)
    except Exception as error:
        raise ProfileConflict("clock returned an invalid timestamp") from error


def _require_key(value: object) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= 128
        or not value.isascii()
        or value != value.strip()
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise ProfileConflict("idempotency key is invalid")
    return value


def _encode_cursor(tenant_id: str, profile_id: str, version: int) -> str:
    payload = _canonical({"tenant": tenant_id, "profile": profile_id, "version": version})
    return base64.urlsafe_b64encode(payload.encode("ascii")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str | None, tenant_id: str) -> tuple[str, int]:
    if cursor is None:
        return "", 0
    if (
        type(cursor) is not str
        or not 1 <= len(cursor) <= 1024
        or not cursor.isascii()
        or re.fullmatch(r"[A-Za-z0-9_-]+", cursor) is None
    ):
        raise ProfileConflict("cursor is invalid")
    try:
        payload = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
        document = json.loads(payload.decode("ascii"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProfileConflict("cursor is invalid") from error
    if (
        type(document) is not dict
        or set(document) != {"profile", "tenant", "version"}
        or document.get("tenant") != tenant_id
    ):
        raise ProfileConflict("cursor is outside tenant scope")
    profile_id = document.get("profile")
    version = document.get("version")
    result = (_require_identifier(profile_id), _require_version(version))
    if _encode_cursor(tenant_id, result[0], result[1]) != cursor:
        raise ProfileConflict("cursor is invalid")
    return result


__all__ = ["POLICY_STORE_SCHEMA_STATEMENTS", "PolicyStore"]
