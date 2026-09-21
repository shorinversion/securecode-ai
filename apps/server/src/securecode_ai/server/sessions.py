"""Opaque hashed sessions and single-use, identity-bound capability tokens."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .identity import Principal


class SessionError(Exception):
    pass


@dataclass(frozen=True, slots=True)
class SessionReceipt:
    subject_id: str
    tenant_id: str
    expires_at: datetime
    token_id: str


@dataclass(frozen=True, slots=True)
class CapabilityReceipt:
    tenant_id: str
    repository_id: str
    run_id: str
    action: str
    execution_identity_hash: str
    expires_at: datetime
    token_id: str


@dataclass(slots=True)
class _Record:
    receipt: object
    expires_at: datetime
    revoked: bool = False
    used: bool = False


class SessionStore:
    def __init__(self, *, now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._now = now
        self._sessions: dict[str, tuple[_Record, Principal]] = {}
        self._capabilities: dict[str, _Record] = {}

    def issue_session(
        self, principal: Principal, *, lifetime_seconds: int = 900
    ) -> tuple[str, SessionReceipt]:
        token = _token()
        expiry = self._now() + timedelta(seconds=_lifetime(lifetime_seconds))
        receipt = SessionReceipt(
            principal.subject_id, principal.tenant_id, expiry, _token_id(token)
        )
        self._sessions[_hash(token)] = (_Record(receipt, expiry), principal)
        return token, receipt

    def verify_session(self, token: str) -> Principal:
        record = self._sessions.get(_hash(token))
        if record is None or not _active(record[0], self._now()):
            raise SessionError()
        return record[1]

    def revoke_session(self, token: str) -> None:
        record = self._sessions.get(_hash(token))
        if record is None:
            raise SessionError()
        record[0].revoked = True

    def rotate_session(
        self, token: str, *, lifetime_seconds: int = 900
    ) -> tuple[str, SessionReceipt]:
        principal = self.verify_session(token)
        self.revoke_session(token)
        return self.issue_session(principal, lifetime_seconds=lifetime_seconds)

    def issue_capability(
        self,
        principal: Principal,
        *,
        repository_id: str,
        run_id: str,
        action: str,
        execution_identity_hash: str,
        lifetime_seconds: int = 300,
    ) -> tuple[str, CapabilityReceipt]:
        if (
            not principal.allows(action=action, repository_id=repository_id)
            or len(execution_identity_hash) != 64
        ):
            raise SessionError()
        token = _token()
        expiry = self._now() + timedelta(seconds=_lifetime(lifetime_seconds))
        receipt = CapabilityReceipt(
            principal.tenant_id,
            repository_id,
            run_id,
            action,
            execution_identity_hash,
            expiry,
            _token_id(token),
        )
        self._capabilities[_hash(token)] = _Record(receipt, expiry)
        return token, receipt

    def consume_capability(
        self,
        token: str,
        *,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        action: str,
        execution_identity_hash: str,
    ) -> CapabilityReceipt:
        record = self._capabilities.get(_hash(token))
        if (
            record is None
            or not _active(record, self._now())
            or record.used
            or not isinstance(record.receipt, CapabilityReceipt)
        ):
            raise SessionError()
        receipt = record.receipt
        if (
            receipt.tenant_id,
            receipt.repository_id,
            receipt.run_id,
            receipt.action,
            receipt.execution_identity_hash,
        ) != (tenant_id, repository_id, run_id, action, execution_identity_hash):
            raise SessionError()
        record.used = True
        return receipt


def _token() -> str:
    return secrets.token_urlsafe(32)


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _token_id(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()[:16]


def _active(record: _Record, now: datetime) -> bool:
    return not record.revoked and record.expires_at > now


def _lifetime(value: int) -> int:
    if type(value) is not int or not 1 <= value <= 3600:
        raise SessionError()
    return value
