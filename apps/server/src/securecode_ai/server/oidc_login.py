"""Interactive OIDC login: start a login, then exchange its callback.

This composes the pieces that already existed but had no caller: ``OidcAdmission``
verifies a signed token and binds it to a tenant subject, ``NonceReplayLedger``
refuses a nonce that was already used for a receipt, and ``SessionIssuer`` mints
the session receipt the caller returns. Nothing here trusts the caller for tenant,
subject or roles: those come from the verified admission.

The flow is deliberately small and state-free on the server side — the nonce is
returned to the caller and presented again on the callback, where the ledger
decides whether it is fresh.
"""

from __future__ import annotations

import secrets
import time
from collections import deque
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Final

from .identity import Principal
from .oidc import OidcAdmission, OidcDenied, OidcReceipt
from .oidc_sessions import NonceReplayLedger, SessionIssuer

NONCE_BYTES: Final = 32
MAX_SESSION_SECONDS: Final = 86_400
DEFAULT_ATTEMPT_LIMIT: Final = 60
ATTEMPT_WINDOW_SECONDS: Final = 60
LOGIN_STATE_TTL_SECONDS: Final = 600


class OidcLoginErrorCode(StrEnum):
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    TOKEN_REJECTED = "TOKEN_REJECTED"
    STATE_REJECTED = "STATE_REJECTED"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    RATE_LIMITED = "RATE_LIMITED"


class OidcLoginError(RuntimeError):
    """Bounded login failure that never carries tokens, nonces or subject data."""

    __slots__ = ("code",)

    def __init__(self, code: OidcLoginErrorCode) -> None:
        self.code = code
        super().__init__("OIDC login was rejected")


@dataclass(frozen=True, slots=True)
class OidcLoginStart:
    """One bounded login attempt handle."""

    nonce: str
    state: str

    def document(self) -> dict[str, str]:
        return {"nonce": self.nonce, "state": self.state}


@dataclass(frozen=True, slots=True)
class OidcLoginReceipt:
    """Verified identity plus the session receipt issued for it."""

    principal: Principal
    receipt: OidcReceipt
    session_receipt: OidcReceipt

    def document(self) -> dict[str, object]:
        return {
            "subject_id": self.receipt.subject_id,
            "tenant_id": self.receipt.tenant_id,
            "roles": list(self.receipt.roles),
            "expires_at": self.session_receipt.expires_at,
            "session_expires_at": self.session_receipt.expires_at,
        }


class OidcLoginService:
    """Compose admission, replay protection and session issuance for one login."""

    __slots__ = (
        "_admission",
        "_attempt_limit",
        "_attempts",
        "_issuer",
        "_ledger",
        "_lock",
        "_pending_states",
        "_state_expiry",
    )

    def __init__(
        self,
        *,
        admission: OidcAdmission,
        ledger: NonceReplayLedger,
        issuer: SessionIssuer | None = None,
        attempt_limit: int = DEFAULT_ATTEMPT_LIMIT,
    ) -> None:
        if type(attempt_limit) is not int or not 1 <= attempt_limit <= 100_000:
            raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION)
        if (
            type(admission) is not OidcAdmission
            or type(ledger) is not NonceReplayLedger
            or (issuer is not None and not callable(getattr(issuer, "issue", None)))
        ):
            raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION)
        self._admission = admission
        self._ledger = ledger
        self._issuer = issuer
        self._attempt_limit = attempt_limit
        self._attempts: deque[float] = deque(maxlen=attempt_limit)
        self._pending_states: dict[str, tuple[str, float]] = {}
        self._state_expiry: deque[tuple[float, str]] = deque()
        self._lock = Lock()

    def start(self) -> OidcLoginStart:
        """Begin one login attempt with a fresh, unguessable nonce and state."""

        nonce = secrets.token_urlsafe(NONCE_BYTES)
        state = secrets.token_urlsafe(NONCE_BYTES)
        self._remember_start(state=state, nonce=nonce)
        return OidcLoginStart(nonce=nonce, state=state)

    def callback(self, *, token: str, nonce: str, state: str) -> OidcLoginReceipt:
        """Verify the callback token, refuse a replayed nonce, and issue a session."""

        if (
            type(token) is not str
            or not token
            or type(nonce) is not str
            or not nonce
            or type(state) is not str
            or not state
        ):
            raise OidcLoginError(OidcLoginErrorCode.TOKEN_REJECTED)
        if not self._consume_start(state=state, nonce=nonce):
            raise OidcLoginError(OidcLoginErrorCode.STATE_REJECTED)
        self._charge_attempt()
        try:
            principal, receipt = self._admission.admit(token, nonce=nonce)
        except OidcDenied:
            raise OidcLoginError(OidcLoginErrorCode.TOKEN_REJECTED) from None
        except (TypeError, ValueError):
            raise OidcLoginError(OidcLoginErrorCode.TOKEN_REJECTED) from None
        try:
            self._ledger.consume(receipt, nonce)
        except OidcDenied:
            raise OidcLoginError(OidcLoginErrorCode.REPLAY_REJECTED) from None
        except (TypeError, ValueError):
            raise OidcLoginError(OidcLoginErrorCode.REPLAY_REJECTED) from None
        session = receipt if self._issuer is None else self._issued(principal, receipt)
        return OidcLoginReceipt(principal=principal, receipt=receipt, session_receipt=session)

    def _charge_attempt(self) -> None:
        """Refuse login work once the bounded attempt window is exhausted."""

        now = time.monotonic()
        with self._lock:
            while self._attempts and now - self._attempts[0] >= ATTEMPT_WINDOW_SECONDS:
                self._attempts.popleft()
            if len(self._attempts) >= self._attempt_limit:
                raise OidcLoginError(OidcLoginErrorCode.RATE_LIMITED)
            self._attempts.append(now)

    def _remember_start(self, *, state: str, nonce: str) -> None:
        """Store one bounded, short-lived state to nonce binding."""

        now = time.monotonic()
        expires_at = now + LOGIN_STATE_TTL_SECONDS
        with self._lock:
            self._discard_expired_states(now)
            if len(self._pending_states) >= self._attempt_limit:
                raise OidcLoginError(OidcLoginErrorCode.RATE_LIMITED)
            self._pending_states[state] = (nonce, expires_at)
            self._state_expiry.append((expires_at, state))

    def _consume_start(self, *, state: str, nonce: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._discard_expired_states(now)
            binding = self._pending_states.pop(state, None)
            return binding is not None and secrets.compare_digest(binding[0], nonce)

    def _discard_expired_states(self, now: float) -> None:
        while self._state_expiry and self._state_expiry[0][0] <= now:
            expires_at, state = self._state_expiry.popleft()
            binding = self._pending_states.get(state)
            if binding is not None and binding[1] == expires_at:
                del self._pending_states[state]

    def _issued(self, principal: Principal, receipt: OidcReceipt) -> OidcReceipt:
        issuer = self._issuer
        if issuer is None:  # pragma: no cover - guarded by the caller
            return receipt
        try:
            issued = issuer.issue(principal)
        except Exception:
            raise OidcLoginError(OidcLoginErrorCode.TOKEN_REJECTED) from None
        if (
            type(issued) is not OidcReceipt
            or issued.expires_at > receipt.expires_at + MAX_SESSION_SECONDS
        ):
            raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION)
        return issued


__all__ = [
    "OidcLoginError",
    "OidcLoginErrorCode",
    "OidcLoginReceipt",
    "OidcLoginService",
    "OidcLoginStart",
]
