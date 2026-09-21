"""Fail-closed, metadata-only evidence egress authorization."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
from dataclasses import dataclass
from enum import StrEnum
from typing import Final


class DataClass(StrEnum):
    DC0_PUBLIC = "DC0_PUBLIC"
    DC1_INTERNAL_METADATA = "DC1_INTERNAL_METADATA"
    DC2_DERIVED_SNIPPETS = "DC2_DERIVED_SNIPPETS"
    DC3_RAW_SOURCE = "DC3_RAW_SOURCE"


class EgressDenied(Exception):
    """Raised when egress is not explicitly allowed by the pinned policy."""


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    destination_id: str
    profile_id: str
    capability_id: str
    no_code_egress: bool = True
    allowed_classes: frozenset[DataClass] = frozenset(
        {DataClass.DC0_PUBLIC, DataClass.DC1_INTERNAL_METADATA}
    )

    def __post_init__(self) -> None:
        for value in (self.destination_id, self.profile_id, self.capability_id):
            _require_identifier(value)
        if type(self.no_code_egress) is not bool:
            raise ValueError("no-code-egress flag must be boolean")
        if type(self.allowed_classes) is not frozenset or not self.allowed_classes:
            raise ValueError("egress policy must explicitly allow at least one data class")
        if any(type(item) is not DataClass for item in self.allowed_classes):
            raise ValueError("egress policy contains an unknown data class")
        if DataClass.DC3_RAW_SOURCE in self.allowed_classes:
            raise ValueError("raw source egress cannot be authorized")
        if self.no_code_egress and not self.allowed_classes <= _SOURCE_FREE_CLASSES:
            raise ValueError("no-code-egress policy cannot allow code-derived payloads")

    @property
    def policy_sha256(self) -> str:
        return _digest(
            {
                "destination_id": self.destination_id,
                "profile_id": self.profile_id,
                "capability_id": self.capability_id,
                "no_code_egress": self.no_code_egress,
                "allowed_classes": sorted(item.value for item in self.allowed_classes),
            }
        )

    def permits(self, data_class: DataClass) -> bool:
        if type(data_class) is not DataClass:
            return False
        if data_class is DataClass.DC3_RAW_SOURCE:
            return False
        if self.no_code_egress and data_class not in _SOURCE_FREE_CLASSES:
            return False
        return data_class in self.allowed_classes


@dataclass(frozen=True, slots=True)
class EgressRequest:
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    destination_id: str
    profile_id: str
    capability_id: str
    data_class: DataClass

    def __post_init__(self) -> None:
        for value in (
            self.tenant_id,
            self.repository_id,
            self.run_id,
            self.destination_id,
            self.profile_id,
            self.capability_id,
        ):
            _require_identifier(value)
        _require_sha256(self.execution_identity_hash)
        if type(self.data_class) is not DataClass:
            raise ValueError("egress data class must be explicit")


@dataclass(frozen=True, slots=True)
class EgressAuthorization:
    tenant_id: str
    repository_id: str
    run_id: str
    execution_identity_hash: str
    destination_id: str
    profile_id: str
    capability_id: str
    data_class: DataClass = DataClass.DC1_INTERNAL_METADATA

    def __post_init__(self) -> None:
        EgressRequest(
            tenant_id=self.tenant_id,
            repository_id=self.repository_id,
            run_id=self.run_id,
            execution_identity_hash=self.execution_identity_hash,
            destination_id=self.destination_id,
            profile_id=self.profile_id,
            capability_id=self.capability_id,
            data_class=self.data_class,
        )

    @property
    def authorization_id(self) -> str:
        return _digest(
            {
                "tenant_id": self.tenant_id,
                "repository_id": self.repository_id,
                "run_id": self.run_id,
                "execution_identity_hash": self.execution_identity_hash,
                "destination_id": self.destination_id,
                "profile_id": self.profile_id,
                "capability_id": self.capability_id,
                "data_class": self.data_class.value,
            }
        )


EGRESS_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS evidence_egress_authorizations (
        tenant_id TEXT NOT NULL,
        authorization_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL,
        destination_id TEXT NOT NULL,
        profile_id TEXT NOT NULL,
        capability_id TEXT NOT NULL,
        data_class TEXT NOT NULL,
        policy_sha256 TEXT NOT NULL,
        version INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (tenant_id, authorization_id),
        CHECK (version >= 1),
        CHECK (revoked IN (0, 1))
    )""",
    """CREATE TABLE IF NOT EXISTS evidence_egress_idempotency (
        tenant_id TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        authorization_id TEXT NOT NULL,
        PRIMARY KEY (tenant_id, idempotency_key),
        FOREIGN KEY (tenant_id, authorization_id)
            REFERENCES evidence_egress_authorizations (tenant_id, authorization_id)
    )""",
)


class EgressAuthorizationLedger:
    """Durable metadata-only record of issued and revoked egress grants."""

    def __init__(self, connection: sqlite3.Connection | None = None) -> None:
        self._db = connection or sqlite3.connect(":memory:", check_same_thread=False)
        self._lock = threading.RLock()
        self._db.execute("PRAGMA foreign_keys = ON")
        for statement in EGRESS_SCHEMA_STATEMENTS:
            self._db.execute(statement)
        self._db.commit()

    def issue(
        self,
        policy: EgressPolicy,
        request: EgressRequest,
        *,
        idempotency_key: str,
    ) -> EgressAuthorization:
        key = _require_key(idempotency_key)
        authorization = authorize_request(policy, request)
        request_hash = _digest(
            {
                "authorization_id": authorization.authorization_id,
                "policy_sha256": policy.policy_sha256,
            }
        )
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                replay = self._db.execute(
                    """SELECT request_sha256, authorization_id
                       FROM evidence_egress_idempotency
                       WHERE tenant_id = ? AND idempotency_key = ?""",
                    (request.tenant_id, key),
                ).fetchone()
                if replay is not None:
                    if str(replay[0]) != request_hash:
                        raise EgressDenied("idempotency key was reused")
                    result = self.get(request.tenant_id, str(replay[1]))
                    if result is None:
                        raise EgressDenied("egress replay is incomplete or revoked")
                    self._db.commit()
                    return result
                existing = self._row(request.tenant_id, authorization.authorization_id)
                if existing is not None:
                    if str(existing[9]) != policy.policy_sha256 or bool(existing[11]):
                        raise EgressDenied("authorization identity conflicts with stored state")
                else:
                    self._db.execute(
                        """INSERT INTO evidence_egress_authorizations (
                               tenant_id, authorization_id, repository_id, run_id,
                               execution_identity_hash, destination_id, profile_id,
                               capability_id, data_class, policy_sha256, version, revoked
                           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)""",
                        (
                            request.tenant_id,
                            authorization.authorization_id,
                            request.repository_id,
                            request.run_id,
                            request.execution_identity_hash,
                            request.destination_id,
                            request.profile_id,
                            request.capability_id,
                            request.data_class.value,
                            policy.policy_sha256,
                        ),
                    )
                self._db.execute(
                    "INSERT INTO evidence_egress_idempotency VALUES (?, ?, ?, ?)",
                    (
                        request.tenant_id,
                        key,
                        request_hash,
                        authorization.authorization_id,
                    ),
                )
                self._db.commit()
                return authorization
            except Exception:
                self._db.rollback()
                raise

    def revoke(
        self,
        *,
        tenant_id: str,
        authorization_id: str,
        expected_version: int,
    ) -> int:
        _require_identifier(tenant_id)
        _require_sha256(authorization_id)
        if type(expected_version) is not int or expected_version < 1:
            raise EgressDenied("expected version is invalid")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                changed = self._db.execute(
                    """UPDATE evidence_egress_authorizations
                       SET revoked = 1, version = version + 1
                       WHERE tenant_id = ? AND authorization_id = ?
                         AND version = ? AND revoked = 0""",
                    (tenant_id, authorization_id, expected_version),
                ).rowcount
                if changed != 1:
                    raise EgressDenied("authorization state changed")
                self._db.commit()
                return expected_version + 1
            except Exception:
                self._db.rollback()
                raise

    def get(self, tenant_id: str, authorization_id: str) -> EgressAuthorization | None:
        _require_identifier(tenant_id)
        _require_sha256(authorization_id)
        row = self._row(tenant_id, authorization_id)
        if row is None or bool(row[11]):
            return None
        result = _authorization_from_row(row)
        if result.authorization_id != authorization_id:
            raise EgressDenied("stored authorization identity is corrupt")
        return result

    def _row(self, tenant_id: str, authorization_id: str) -> tuple[object, ...] | None:
        row: tuple[object, ...] | None = self._db.execute(
            """SELECT tenant_id, authorization_id, repository_id, run_id,
                      execution_identity_hash, destination_id, profile_id,
                      capability_id, data_class, policy_sha256, version, revoked
               FROM evidence_egress_authorizations
               WHERE tenant_id = ? AND authorization_id = ?""",
            (tenant_id, authorization_id),
        ).fetchone()
        return row


def authorize_request(policy: EgressPolicy, request: EgressRequest) -> EgressAuthorization:
    if (
        policy.destination_id,
        policy.profile_id,
        policy.capability_id,
    ) != (request.destination_id, request.profile_id, request.capability_id):
        raise EgressDenied("egress policy binding does not match")
    if not policy.permits(request.data_class):
        raise EgressDenied("egress data class is not allowed")
    return EgressAuthorization(
        tenant_id=request.tenant_id,
        repository_id=request.repository_id,
        run_id=request.run_id,
        execution_identity_hash=request.execution_identity_hash,
        destination_id=request.destination_id,
        profile_id=request.profile_id,
        capability_id=request.capability_id,
        data_class=request.data_class,
    )


def authorize(
    policy: EgressPolicy,
    *,
    tenant_id: str,
    repository_id: str,
    run_id: str,
    execution_identity_hash: str,
    destination_id: str,
    profile_id: str,
    capability_id: str,
    data_class: DataClass = DataClass.DC1_INTERNAL_METADATA,
) -> EgressAuthorization:
    """Compatibility entrypoint that still binds an explicit data class."""
    try:
        request = EgressRequest(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            destination_id=destination_id,
            profile_id=profile_id,
            capability_id=capability_id,
            data_class=data_class,
        )
    except ValueError as error:
        raise EgressDenied("egress request is invalid") from error
    return authorize_request(policy, request)


_SOURCE_FREE_CLASSES: Final = frozenset({DataClass.DC0_PUBLIC, DataClass.DC1_INTERNAL_METADATA})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}\Z")
_HEX = frozenset("0123456789abcdef")


def _authorization_from_row(row: tuple[object, ...]) -> EgressAuthorization:
    try:
        data_class = DataClass(str(row[8]))
    except ValueError as error:
        raise EgressDenied("stored egress data class is invalid") from error
    return EgressAuthorization(
        tenant_id=str(row[0]),
        repository_id=str(row[2]),
        run_id=str(row[3]),
        execution_identity_hash=str(row[4]),
        destination_id=str(row[5]),
        profile_id=str(row[6]),
        capability_id=str(row[7]),
        data_class=data_class,
    )


def _require_identifier(value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError("identifier is invalid")
    return value


def _require_sha256(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(item not in _HEX for item in value):
        raise ValueError("SHA-256 value is invalid")
    return value


def _require_key(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise EgressDenied("idempotency key is invalid")
    return value


def _digest(document: dict[str, object]) -> str:
    payload = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


__all__ = [
    "EGRESS_SCHEMA_STATEMENTS",
    "DataClass",
    "EgressAuthorization",
    "EgressAuthorizationLedger",
    "EgressDenied",
    "EgressPolicy",
    "EgressRequest",
    "authorize",
    "authorize_request",
]
