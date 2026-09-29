"""Interactive OIDC login: verification, replay refusal and bounded attempts."""

from __future__ import annotations

import sqlite3
import time
from typing import cast

import pytest
from securecode_ai.server.identity import Role
from securecode_ai.server.migrations import apply_schema
from securecode_ai.server.oidc import (
    OidcAdmission,
    OidcPolicy,
    OidcReceipt,
    SubjectBinding,
    TenantState,
)
from securecode_ai.server.oidc_login import (
    OidcLoginError,
    OidcLoginErrorCode,
    OidcLoginService,
    OidcLoginStart,
)
from securecode_ai.server.oidc_sessions import (
    IssuedOidcSession,
    NonceReplayLedger,
    SqliteOidcLoginState,
)

NOW = 2
NONCE = "n"
TOKEN = "a.b.c"
CLAIMS = {
    "alg": "RS256",
    "iss": "issuer",
    "sub": "user",
    "aud": "app",
    "azp": "client",
    "nonce": NONCE,
    "iat": 1,
    "exp": 3_601,
    "groups": ["auditors"],
}


class _Verifier:
    def __init__(self, claims: object = None) -> None:
        self._claims = CLAIMS if claims is None else claims

    def verify(self, token: str) -> object:
        return self._claims if token == TOKEN else None


def _admission(claims: object = None, *, now: int = NOW) -> OidcAdmission:
    return OidcAdmission(
        _Verifier(claims),  # type: ignore[arg-type]
        OidcPolicy("issuer", "app", frozenset({"client"}), {"auditors": Role.AUDITOR}),
        (SubjectBinding("issuer", "user", "tenant", TenantState.ACTIVE, frozenset({"repo"})),),
        now=lambda: now,
    )


def _service(
    *,
    claims: object = None,
    issuer: object = None,
    attempt_limit: int = 60,
    now: int = NOW,
) -> OidcLoginService:
    return OidcLoginService(
        admission=_admission(claims, now=now),
        ledger=NonceReplayLedger(now=lambda: NOW),
        issuer=issuer,  # type: ignore[arg-type]
        attempt_limit=attempt_limit,
    )


def _started_service(
    *,
    claims: object = None,
    issuer: object = None,
    attempt_limit: int = 60,
    now: int = NOW,
) -> tuple[OidcLoginService, OidcLoginStart]:
    values = dict(CLAIMS) if claims is None else claims
    service = _service(claims=values, issuer=issuer, attempt_limit=attempt_limit, now=now)
    start = service.start()
    if isinstance(values, dict):
        values["nonce"] = start.nonce
    return service, start


def _durable_started_service() -> tuple[OidcLoginService, OidcLoginStart, sqlite3.Connection]:
    values = dict(CLAIMS)
    connection = sqlite3.connect(":memory:")
    apply_schema(connection)
    service = OidcLoginService(
        admission=_admission(values),
        ledger=NonceReplayLedger(now=lambda: NOW, connection=connection),
        state_store=SqliteOidcLoginState(connection),
    )
    start = service.start()
    values["nonce"] = start.nonce
    return service, start, connection


class _Issuer:
    def __init__(self, mode: str = "ok") -> None:
        self._mode = mode

    def issue(self, principal: object, *, token_expires_at: int) -> IssuedOidcSession:
        if self._mode == "raise":
            raise RuntimeError("issuer unavailable")
        if self._mode == "wrong":
            return IssuedOidcSession(
                token="s" * 32,
                receipt=OidcReceipt("other", "tenant", ("auditor",), token_expires_at - 1),
            )
        if self._mode == "long":
            return IssuedOidcSession(
                token="s" * 32,
                receipt=OidcReceipt("user", "tenant", ("auditor",), token_expires_at + 200_000),
            )
        return IssuedOidcSession(
            token="s" * 32,
            receipt=OidcReceipt(
                "user",
                "tenant",
                ("auditor",),
                min(token_expires_at, int(time.time()) + 3600),
            ),
        )


class _LooseStateStore:
    def __init__(self, *, matches_result: object, consume_result: object) -> None:
        self._matches_result = matches_result
        self._consume_result = consume_result
        self.consume_calls = 0

    def create(self, *, state: str, nonce: str, expires_at: int) -> None:
        del state, nonce, expires_at

    def matches(self, *, state: str, nonce: str, now: int) -> bool:
        del state, nonce, now
        return cast(bool, self._matches_result)

    def consume(self, *, state: str, nonce: str, now: int) -> bool:
        del state, nonce, now
        self.consume_calls += 1
        return cast(bool, self._consume_result)

    def charge_attempt(self, *, bucket: str, now: int, limit: int, window_seconds: int) -> None:
        del bucket, now, limit, window_seconds

    def charge_source_attempt(self, **arguments: object) -> None:
        del arguments


def test_service_rejects_invalid_configuration() -> None:
    for arguments in (
        {"admission": object(), "ledger": NonceReplayLedger()},
        {"admission": _admission(), "ledger": object()},
        {"admission": _admission(), "ledger": NonceReplayLedger(), "issuer": object()},
        {"admission": _admission(), "ledger": NonceReplayLedger(), "attempt_limit": 0},
    ):
        with pytest.raises(OidcLoginError) as error:
            OidcLoginService(**arguments)  # type: ignore[arg-type]
        assert error.value.code is OidcLoginErrorCode.INVALID_CONFIGURATION


def test_start_returns_unguessable_attempt_handles() -> None:
    service = _service()
    first = service.start()
    second = service.start()
    assert first.nonce != second.nonce
    assert first.state != second.state
    assert len(first.nonce) >= 32 and len(first.state) >= 32
    assert set(first.document()) == {"nonce", "state"}


def test_callback_returns_the_verified_principal() -> None:
    service, start = _started_service()
    receipt = service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    assert receipt.principal.subject_id == "user"
    assert receipt.principal.tenant_id == "tenant"
    assert receipt.principal.roles == frozenset({Role.AUDITOR})
    assert receipt.principal.repository_grants == frozenset({"repo"})
    assert receipt.session_receipt is receipt.receipt
    assert receipt.document()["tenant_id"] == "tenant"


@pytest.mark.parametrize("token", ["", "forged"])
def test_forged_or_empty_tokens_are_refused(token: str) -> None:
    service, start = _started_service()
    with pytest.raises(OidcLoginError) as error:
        service.callback(token=token, nonce=start.nonce, state=start.state)
    assert error.value.code is OidcLoginErrorCode.TOKEN_REJECTED


def test_empty_nonce_is_refused() -> None:
    service, start = _started_service()
    with pytest.raises(OidcLoginError) as error:
        service.callback(token=TOKEN, nonce="", state=start.state)
    assert error.value.code is OidcLoginErrorCode.TOKEN_REJECTED


def test_replayed_nonce_is_refused() -> None:
    service, start = _started_service()
    service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    with pytest.raises(OidcLoginError) as error:
        service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    assert error.value.code is OidcLoginErrorCode.STATE_REJECTED


def test_attempts_are_bounded() -> None:
    service = _service(attempt_limit=2)
    starts: list[OidcLoginStart] = []
    for _ in range(2):
        start = service.start()
        starts.append(start)
        with pytest.raises(OidcLoginError) as error:
            service.callback(token="forged", nonce=start.nonce, state=start.state)
        assert error.value.code is OidcLoginErrorCode.TOKEN_REJECTED
    with pytest.raises(OidcLoginError) as error:
        service.callback(token="forged", nonce=starts[0].nonce, state=starts[0].state)
    assert error.value.code is OidcLoginErrorCode.RATE_LIMITED


def test_issuer_supplies_the_session_receipt() -> None:
    # A session may not outlive the ID token, so the token must be current.
    now = int(time.time())
    claims = {**CLAIMS, "iat": now - 1, "exp": now + 7200}
    service, start = _started_service(claims=claims, issuer=_Issuer("ok"), now=now)
    receipt = service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    assert 0 < receipt.session_receipt.expires_at - int(time.time()) <= 3600
    assert receipt.session_receipt is not receipt.receipt
    assert receipt.document()["session_expires_at"] == receipt.session_receipt.expires_at


def test_failing_issuer_is_refused() -> None:
    service, start = _started_service(issuer=_Issuer("raise"))
    with pytest.raises(OidcLoginError) as error:
        service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    assert error.value.code is OidcLoginErrorCode.TOKEN_REJECTED


@pytest.mark.parametrize("mode", ["wrong", "long"])
def test_implausible_issuer_output_is_refused(mode: str) -> None:
    service, start = _started_service(issuer=_Issuer(mode))
    with pytest.raises(OidcLoginError) as error:
        service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    assert error.value.code is OidcLoginErrorCode.INVALID_CONFIGURATION


def test_admission_denial_never_reaches_the_ledger() -> None:
    """A refused token must not consume the nonce, so a retry stays possible."""

    service, start = _started_service(claims={"alg": "none"})
    with pytest.raises(OidcLoginError) as error:
        service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    assert error.value.code is OidcLoginErrorCode.TOKEN_REJECTED

    good, start = _started_service()
    assert (
        good.callback(token=TOKEN, nonce=start.nonce, state=start.state).principal.subject_id
        == "user"
    )


def test_callback_rejects_a_tampered_or_unknown_state() -> None:
    service, start = _started_service()

    with pytest.raises(OidcLoginError) as error:
        service.callback(token=TOKEN, nonce=start.nonce, state="tampered")

    assert error.value.code is OidcLoginErrorCode.STATE_REJECTED


def test_durable_state_survives_token_rejection_and_is_consumed_once() -> None:
    service, start, connection = _durable_started_service()

    with pytest.raises(OidcLoginError) as error:
        service.callback(token="forged", nonce=start.nonce, state=start.state)
    assert error.value.code is OidcLoginErrorCode.TOKEN_REJECTED
    assert connection.execute("SELECT COUNT(*) FROM oidc_login_states").fetchone() == (1,)

    receipt = service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    assert receipt.principal.subject_id == "user"
    assert connection.execute("SELECT COUNT(*) FROM oidc_login_states").fetchone() == (0,)

    with pytest.raises(OidcLoginError) as error:
        service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    assert error.value.code is OidcLoginErrorCode.STATE_REJECTED


@pytest.mark.parametrize(
    ("matches_result", "consume_result", "consume_calls"),
    [(1, True, 0), ("yes", True, 0), (True, 1, 1)],
)
def test_state_store_requires_exact_boolean_results(
    matches_result: object,
    consume_result: object,
    consume_calls: int,
) -> None:
    """Malformed state-port results must never be treated as authorization."""

    values = dict(CLAIMS)
    state_store = _LooseStateStore(
        matches_result=matches_result,
        consume_result=consume_result,
    )
    service = OidcLoginService(
        admission=_admission(values),
        ledger=NonceReplayLedger(now=lambda: NOW),
        state_store=state_store,
    )
    start = service.start()
    values["nonce"] = start.nonce

    with pytest.raises(OidcLoginError) as error:
        service.callback(token=TOKEN, nonce=start.nonce, state=start.state)

    assert error.value.code is OidcLoginErrorCode.STATE_REJECTED
    assert state_store.consume_calls == consume_calls
