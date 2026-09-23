"""Interactive OIDC login: start a login, then exchange its callback.

This composes the pieces that already existed but had no caller: ``OidcAdmission``
verifies a signed token and binds it to a tenant subject, ``NonceReplayLedger``
refuses a nonce that was already used for a receipt, and ``SessionIssuer`` mints
the session receipt the caller returns. Nothing here trusts the caller for tenant,
subject or roles: those come from the verified admission.

The login start creates a short-lived server-side state-to-nonce binding. A
public OIDC client receives an authorization URL and PKCE verifier, exchanges
the code with the provider, then sends the signed ID token back for verification.
Only hashes of state and nonce are stored by the SQLite-backed production ledger.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum
from threading import Lock
from typing import Final, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .identity import Principal
from .oidc import OidcDenied, OidcReceipt
from .oidc_sessions import (
    IssuedOidcSession,
    LoginStatePort,
    NonceReplayLedger,
    SessionIssuer,
)

NONCE_BYTES: Final = 32
MAX_SESSION_SECONDS: Final = 86_400
DEFAULT_ATTEMPT_LIMIT: Final = 60
ATTEMPT_WINDOW_SECONDS: Final = 60
LOGIN_STATE_TTL_SECONDS: Final = 600
_OAUTH_SCOPE: Final = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]{1,64}\Z")
_OAUTH_CLIENT_ID: Final = re.compile(r"[A-Za-z0-9._~:/-]{1,256}\Z")


class OidcLoginErrorCode(StrEnum):
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    TOKEN_REJECTED = "TOKEN_REJECTED"
    STATE_REJECTED = "STATE_REJECTED"
    REPLAY_REJECTED = "REPLAY_REJECTED"
    RATE_LIMITED = "RATE_LIMITED"


class OidcLoginError(RuntimeError):
    """Bounded login failure that never carries tokens, nonces or subject data."""

    __slots__ = ("code", "retry_after_seconds")

    def __init__(
        self,
        code: OidcLoginErrorCode,
        *,
        retry_after_seconds: int = ATTEMPT_WINDOW_SECONDS,
    ) -> None:
        if type(retry_after_seconds) is not int or not 1 <= retry_after_seconds <= 3600:
            raise TypeError("OIDC retry interval is invalid")
        self.code = code
        self.retry_after_seconds = retry_after_seconds
        super().__init__("OIDC login was rejected")


class OidcAdmissionPort(Protocol):
    def admit(self, token: str, *, nonce: str) -> tuple[Principal, OidcReceipt]: ...


@dataclass(frozen=True, slots=True)
class OidcLoginStart:
    """One bounded login attempt handle."""

    nonce: str
    state: str
    authorization_url: str | None = None
    code_verifier: str = field(default="", repr=False)
    code_challenge: str | None = None

    def document(self) -> dict[str, str]:
        document = {"nonce": self.nonce, "state": self.state}
        if self.authorization_url is not None:
            document.update(
                {
                    "authorization_url": self.authorization_url,
                    "code_verifier": self.code_verifier,
                    "code_challenge": self.code_challenge or "",
                    "code_challenge_method": "S256",
                }
            )
        return document


@dataclass(frozen=True, slots=True)
class OidcAuthorizationClient:
    authorization_endpoint: str
    client_id: str
    redirect_uri: str
    scope: str = "openid profile email"

    def __post_init__(self) -> None:
        endpoint = _https_url(self.authorization_endpoint, allow_loopback=False)
        redirect = _https_url(self.redirect_uri, allow_loopback=True)
        parts = urlsplit(endpoint)
        try:
            query = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
        except ValueError:
            raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION) from None
        reserved = {
            "client_id",
            "code_challenge",
            "code_challenge_method",
            "nonce",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
        }
        if (
            type(self.client_id) is not str
            or _OAUTH_CLIENT_ID.fullmatch(self.client_id) is None
            or any(key in reserved for key, _ in query)
            or type(self.scope) is not str
            or not 1 <= len(self.scope) <= 512
            or "openid" not in self.scope.split()
            or len(self.scope.split()) != len(set(self.scope.split()))
            or len(self.scope.split()) > 16
            or any(_OAUTH_SCOPE.fullmatch(scope) is None for scope in self.scope.split())
        ):
            raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION)
        object.__setattr__(self, "authorization_endpoint", endpoint)
        object.__setattr__(self, "redirect_uri", redirect)

    def build(self, *, state: str, nonce: str) -> tuple[str, str, str]:
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        code_challenge = challenge.rstrip(b"=").decode("ascii")
        parts = urlsplit(self.authorization_endpoint)
        query = parse_qsl(parts.query, keep_blank_values=True)
        query.extend(
            (
                ("client_id", self.client_id),
                ("code_challenge", code_challenge),
                ("code_challenge_method", "S256"),
                ("nonce", nonce),
                ("redirect_uri", self.redirect_uri),
                ("response_type", "code"),
                ("scope", self.scope),
                ("state", state),
            )
        )
        authorization_url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query), "")
        )
        return authorization_url, verifier, code_challenge


@dataclass(frozen=True, slots=True)
class OidcLoginReceipt:
    """Verified identity plus the session receipt issued for it."""

    principal: Principal
    receipt: OidcReceipt
    session_receipt: OidcReceipt
    session_token: str = field(repr=False)

    def document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "subject_id": self.receipt.subject_id,
            "tenant_id": self.receipt.tenant_id,
            "roles": list(self.receipt.roles),
            "expires_at": self.session_receipt.expires_at,
            "session_expires_at": self.session_receipt.expires_at,
        }
        if self.session_token:
            document["access_token"] = self.session_token
            document["token_type"] = "Bearer"
        return document


class OidcLoginService:
    """Compose admission, replay protection and session issuance for one login."""

    __slots__ = (
        "_admission",
        "_attempt_limit",
        "_attempt_window_seconds",
        "_attempts",
        "_authorization_client",
        "_issuer",
        "_ledger",
        "_lock",
        "_pending_states",
        "_state_expiry",
        "_state_store",
    )

    def __init__(
        self,
        *,
        admission: OidcAdmissionPort,
        ledger: NonceReplayLedger,
        issuer: SessionIssuer | None = None,
        state_store: LoginStatePort | None = None,
        authorization_client: OidcAuthorizationClient | None = None,
        attempt_limit: int = DEFAULT_ATTEMPT_LIMIT,
        attempt_window_seconds: int = ATTEMPT_WINDOW_SECONDS,
    ) -> None:
        if (
            type(attempt_limit) is not int
            or not 1 <= attempt_limit <= 100_000
            or type(attempt_window_seconds) is not int
            or not 1 <= attempt_window_seconds <= 3600
        ):
            raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION)
        if (
            not callable(getattr(admission, "admit", None))
            or type(ledger) is not NonceReplayLedger
            or (issuer is not None and not callable(getattr(issuer, "issue", None)))
            or (
                authorization_client is not None
                and type(authorization_client) is not OidcAuthorizationClient
            )
            or (
                state_store is not None
                and not all(
                    callable(getattr(state_store, method, None))
                    for method in ("create", "consume", "charge_attempt")
                )
            )
        ):
            raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION)
        self._admission = admission
        self._authorization_client = authorization_client
        self._ledger = ledger
        self._issuer = issuer
        self._state_store = state_store
        self._attempt_limit = attempt_limit
        self._attempt_window_seconds = attempt_window_seconds
        self._attempts: deque[float] = deque(maxlen=attempt_limit)
        self._pending_states: dict[str, tuple[str, float]] = {}
        self._state_expiry: deque[tuple[float, str]] = deque()
        self._lock = Lock()

    def start(self) -> OidcLoginStart:
        """Begin one login attempt with a fresh, unguessable nonce and state."""

        nonce = secrets.token_urlsafe(NONCE_BYTES)
        state = secrets.token_urlsafe(NONCE_BYTES)
        if self._state_store is None:
            self._remember_start(state=state, nonce=nonce)
        else:
            try:
                self._state_store.charge_attempt(
                    bucket="start",
                    now=int(time.time()),
                    limit=self._attempt_limit,
                    window_seconds=self._attempt_window_seconds,
                )
                self._state_store.create(
                    state=state,
                    nonce=nonce,
                    expires_at=int(time.time()) + LOGIN_STATE_TTL_SECONDS,
                )
            except Exception:
                raise OidcLoginError(
                    OidcLoginErrorCode.RATE_LIMITED,
                    retry_after_seconds=self._attempt_window_seconds,
                ) from None
        authorization_url = None
        verifier = ""
        challenge = None
        if self._authorization_client is not None:
            authorization_url, verifier, challenge = self._authorization_client.build(
                state=state,
                nonce=nonce,
            )
        return OidcLoginStart(
            nonce=nonce,
            state=state,
            authorization_url=authorization_url,
            code_verifier=verifier,
            code_challenge=challenge,
        )

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
        self._charge_attempt(bucket="callback")
        if not self._consume_start(state=state, nonce=nonce):
            raise OidcLoginError(OidcLoginErrorCode.STATE_REJECTED)
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
        if self._issuer is None:
            session_token, session = "", receipt
        else:
            session_token, session = self._issued(principal, receipt)
        return OidcLoginReceipt(
            principal=principal,
            receipt=receipt,
            session_receipt=session,
            session_token=session_token,
        )

    def _charge_attempt(self, *, bucket: str) -> None:
        """Refuse login work once the bounded attempt window is exhausted."""

        if self._state_store is not None:
            try:
                self._state_store.charge_attempt(
                    bucket=bucket,
                    now=int(time.time()),
                    limit=self._attempt_limit,
                    window_seconds=self._attempt_window_seconds,
                )
            except Exception:
                raise OidcLoginError(
                    OidcLoginErrorCode.RATE_LIMITED,
                    retry_after_seconds=self._attempt_window_seconds,
                ) from None
            return
        now = time.monotonic()
        with self._lock:
            while self._attempts and now - self._attempts[0] >= self._attempt_window_seconds:
                self._attempts.popleft()
            if len(self._attempts) >= self._attempt_limit:
                raise OidcLoginError(
                    OidcLoginErrorCode.RATE_LIMITED,
                    retry_after_seconds=self._attempt_window_seconds,
                )
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
        if self._state_store is not None:
            try:
                return self._state_store.consume(
                    state=state,
                    nonce=nonce,
                    now=int(time.time()),
                )
            except Exception:
                return False
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

    def _issued(self, principal: Principal, receipt: OidcReceipt) -> tuple[str, OidcReceipt]:
        issuer = self._issuer
        if issuer is None:  # pragma: no cover - guarded by the caller
            return "", receipt
        try:
            issued = issuer.issue(principal, token_expires_at=receipt.expires_at)
        except Exception:
            raise OidcLoginError(OidcLoginErrorCode.TOKEN_REJECTED) from None
        if (
            type(issued) is not IssuedOidcSession
            or type(issued.token) is not str
            or not 32 <= len(issued.token) <= 8192
            or not issued.token.isascii()
            or type(issued.receipt) is not OidcReceipt
            or issued.receipt.subject_id != receipt.subject_id
            or issued.receipt.tenant_id != receipt.tenant_id
            or issued.receipt.roles != receipt.roles
            or not int(time.time()) < issued.receipt.expires_at <= receipt.expires_at
            or issued.receipt.expires_at - int(time.time()) > MAX_SESSION_SECONDS
        ):
            raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION)
        return issued.token, issued.receipt


__all__ = [
    "OidcAdmissionPort",
    "OidcAuthorizationClient",
    "OidcLoginError",
    "OidcLoginErrorCode",
    "OidcLoginReceipt",
    "OidcLoginService",
    "OidcLoginStart",
]


def _https_url(value: str, *, allow_loopback: bool) -> str:
    if type(value) is not str or not 1 <= len(value) <= 2048:
        raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION)
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION) from None
    loopback = host in {"localhost", "127.0.0.1", "::1"}
    if (
        parsed.scheme != ("http" if allow_loopback and loopback else "https")
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
        or (allow_loopback and parsed.scheme == "http" and not loopback)
    ):
        raise OidcLoginError(OidcLoginErrorCode.INVALID_CONFIGURATION)
    return value
