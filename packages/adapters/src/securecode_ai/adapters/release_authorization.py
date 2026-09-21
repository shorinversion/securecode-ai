"""Concrete cryptographic authority for local release publication."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Final

from securecode_ai.core.release_publisher import PublishAuthorization

_HASH: Final = re.compile(r"[0-9a-f]{64}\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_AUTHORIZATION_DOMAIN: Final = b"securecode-ai/release-cli-authorization/v1\x00"
_SIGNATURE_DOMAIN: Final = b"securecode-ai/release-evidence-signature/v1\x00"
_MAX_AUTHORIZATION_LIFETIME_SECONDS: Final = 24 * 60 * 60


class ReleaseAuthorizationError(ValueError):
    def __init__(self) -> None:
        super().__init__("Release authorization was rejected")
        self.__cause__ = None
        self.__context__ = None


class HmacReleaseAuthority:
    __slots__ = ("_key", "_key_id")

    def __init__(self, key: bytes, key_id: str) -> None:
        if type(key) is not bytes or not 32 <= len(key) <= 4096 or not _ID.fullmatch(key_id):
            raise ReleaseAuthorizationError()
        self._key = key
        self._key_id = key_id

    def verify(self, authorization: PublishAuthorization, *, now: int | None) -> bool:
        if type(authorization) is not PublishAuthorization or authorization.key_id != self._key_id:
            return False
        if now is not None and (
            authorization.expires_at <= now
            or authorization.expires_at > now + _MAX_AUTHORIZATION_LIFETIME_SECONDS
        ):
            return False
        material = {
            "action": authorization.action,
            "approver_id": authorization.approver_id,
            "authorization_id": authorization.authorization_id,
            "candidate_sha256": authorization.candidate_sha256,
            "expires_at": authorization.expires_at,
            "key_id": authorization.key_id,
            "nonce": authorization.nonce,
            "store_identity_sha256": authorization.store_identity_sha256,
        }
        expected = hmac.new(
            self._key, _AUTHORIZATION_DOMAIN + _canonical_json(material), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(authorization.signature_sha256, expected)

    def verify_evidence_signature(self, payload_sha256: str, signature: str) -> bool:
        if not _HASH.fullmatch(payload_sha256) or not _HASH.fullmatch(signature):
            return False
        expected = hmac.new(
            self._key,
            _SIGNATURE_DOMAIN + payload_sha256.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(signature, expected)

    def owns_key_id(self, key_id: object) -> bool:
        return type(key_id) is str and hmac.compare_digest(key_id, self._key_id)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


__all__ = ["HmacReleaseAuthority", "ReleaseAuthorizationError"]
