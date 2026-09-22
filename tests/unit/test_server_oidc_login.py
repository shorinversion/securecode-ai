"""Interactive OIDC login: verification, replay refusal and bounded attempts."""

from __future__ import annotations

import pytest
from securecode_ai.server.identity import Role
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
from securecode_ai.server.oidc_sessions import NonceReplayLedger

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
    "exp": 9999999999,
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
) -> OidcLoginService:
    return OidcLoginService(
        admission=_admission(claims),
        ledger=NonceReplayLedger(now=lambda: NOW),
        issuer=issuer,  # type: ignore[arg-type]
        attempt_limit=attempt_limit,
    )


def _started_service(
    *,
    claims: object = None,
    issuer: object = None,
    attempt_limit: int = 60,
) -> tuple[OidcLoginService, OidcLoginStart]:
    values = dict(CLAIMS) if claims is None else claims
    service = _service(claims=values, issuer=issuer, attempt_limit=attempt_limit)
    start = service.start()
    if isinstance(values, dict):
        values["nonce"] = start.nonce
    return service, start


class _Issuer:
    def __init__(self, mode: str = "ok") -> None:
        self._mode = mode

    def issue(self, principal: object) -> object:
        if self._mode == "raise":
            raise RuntimeError("issuer unavailable")
        if self._mode == "wrong":
            return "not-a-receipt"
        if self._mode == "long":
            return OidcReceipt("user", "tenant", ("auditor",), 9999999999 + 200_000)
        return OidcReceipt("user", "tenant", ("auditor",), 9999999999 - 1)


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
    for _ in range(2):
        start = service.start()
        with pytest.raises(OidcLoginError) as error:
            service.callback(token="forged", nonce=start.nonce, state=start.state)
        assert error.value.code is OidcLoginErrorCode.TOKEN_REJECTED
    start = service.start()
    with pytest.raises(OidcLoginError) as error:
        service.callback(token="forged", nonce=start.nonce, state=start.state)
    assert error.value.code is OidcLoginErrorCode.RATE_LIMITED


def test_issuer_supplies_the_session_receipt() -> None:
    service, start = _started_service(issuer=_Issuer("ok"))
    receipt = service.callback(token=TOKEN, nonce=start.nonce, state=start.state)
    assert receipt.session_receipt.expires_at == 9999999999 - 1
    assert receipt.session_receipt is not receipt.receipt
    assert receipt.document()["session_expires_at"] == 9999999999 - 1


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
