"""Configurable local secret-provider subprocess composition."""

from __future__ import annotations

import time

from .secret_provider import OpaqueSecretLease, SecretProvider
from .subprocess_protocol import (
    PinnedJsonProcess,
    SubprocessProtocolError,
    configured_process,
)


class SubprocessSecretProvider:
    """Issue and revoke opaque leases through one hash-pinned local broker."""

    def __init__(self, process: PinnedJsonProcess) -> None:
        if not isinstance(process, PinnedJsonProcess):
            raise TypeError("process must be a PinnedJsonProcess")
        self._process = process

    def issue(
        self,
        reference: str,
        *,
        purpose: str,
        grant_id: str,
    ) -> OpaqueSecretLease:
        response = self._process.request(
            {
                "grant_id": grant_id,
                "operation": "issue",
                "purpose": purpose,
                "reference": reference,
                "schema_version": 1,
            }
        )
        return _lease(response)

    def rotate(
        self,
        reference: str,
        *,
        purpose: str,
        previous_grant_id: str,
        grant_id: str,
    ) -> OpaqueSecretLease:
        response = self._process.request(
            {
                "grant_id": grant_id,
                "operation": "rotate",
                "previous_grant_id": previous_grant_id,
                "purpose": purpose,
                "reference": reference,
                "schema_version": 1,
            }
        )
        return _lease(response)

    def revoke(self, grant_id: str) -> None:
        response = self._process.request(
            {
                "grant_id": grant_id,
                "operation": "revoke",
                "schema_version": 1,
            }
        )
        if (
            set(response) != {"schema_version", "status"}
            or not _schema_version_is_v1(response.get("schema_version"))
            or response.get("status") != "ok"
        ):
            raise SubprocessProtocolError("SECRET_PROVIDER_RESPONSE_INVALID")


class UnavailableSecretProvider:
    """Explicit provider used until an external revocable lease broker is installed."""

    def issue(
        self,
        reference: str,
        *,
        purpose: str,
        grant_id: str,
    ) -> OpaqueSecretLease:
        del reference, purpose, grant_id
        raise RuntimeError("secret provider is unavailable")

    def rotate(
        self,
        reference: str,
        *,
        purpose: str,
        previous_grant_id: str,
        grant_id: str,
    ) -> OpaqueSecretLease:
        del reference, purpose, previous_grant_id, grant_id
        raise RuntimeError("secret provider is unavailable")

    def revoke(self, grant_id: str) -> None:
        del grant_id
        raise RuntimeError("secret provider is unavailable")


def _lease(response: dict[str, object]) -> OpaqueSecretLease:
    if set(response) != {"expires_at", "handle", "schema_version", "status"}:
        raise SubprocessProtocolError("SECRET_PROVIDER_RESPONSE_INVALID")
    if not _schema_version_is_v1(response.get("schema_version")) or response.get("status") != "ok":
        raise SubprocessProtocolError("SECRET_PROVIDER_RESPONSE_INVALID")
    handle = response.get("handle")
    expires_at = response.get("expires_at")
    now = int(time.time())
    if (
        type(handle) is not str
        or not _valid_handle(handle)
        or type(expires_at) is not int
        or not now < expires_at <= now + 3_600
    ):
        raise SubprocessProtocolError("SECRET_PROVIDER_RESPONSE_INVALID")
    try:
        return OpaqueSecretLease(handle, expires_at)
    except ValueError:
        raise SubprocessProtocolError("SECRET_PROVIDER_RESPONSE_INVALID") from None


def build_secret_provider(values: object) -> tuple[SecretProvider, bool]:
    process = configured_process(values, prefix="SECURECODE_SECRET_PROVIDER")
    if process is None:
        return UnavailableSecretProvider(), False
    return SubprocessSecretProvider(process), True


def _valid_handle(value: str) -> bool:
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeEncodeError:
        return False
    return 32 <= len(encoded) <= 8192 and all(
        ord(character) >= 32 and ord(character) != 127 for character in value
    )


def _schema_version_is_v1(value: object) -> bool:
    """Require JSON's schema version to be an integer, not a bool or float."""

    return type(value) is int and value == 1


__all__ = [
    "SubprocessSecretProvider",
    "UnavailableSecretProvider",
    "build_secret_provider",
]
