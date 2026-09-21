"""Pinned asymmetric signature primitives for the authentication boundary."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class RsaPublicKey:
    """Validated RSA public numbers provisioned by trusted configuration."""

    modulus: int
    exponent: int

    def __post_init__(self) -> None:
        if (
            type(self.modulus) is not int
            or not 2048 <= self.modulus.bit_length() <= 8192
            or self.modulus % 2 == 0
            or type(self.exponent) is not int
            or not 3 <= self.exponent <= 2**32
            or self.exponent % 2 == 0
        ):
            raise ValueError("RSA public key is invalid")


class RsaSha256SignatureVerifier:
    """Verify RSASSA-PKCS1-v1_5 SHA-256 with a pinned public key."""

    __slots__ = ()

    _DIGEST_INFO_PREFIX: Final = bytes.fromhex("3031300d060960864801650304020105000420")

    def verify_signature(
        self,
        *,
        algorithm: str,
        key: object,
        signing_input: bytes,
        signature: bytes,
    ) -> bool:
        if algorithm != "RS256" or type(key) is not RsaPublicKey:
            return False
        width = (key.modulus.bit_length() + 7) // 8
        if len(signature) != width:
            return False
        encoded_integer = int.from_bytes(signature, "big")
        if encoded_integer >= key.modulus:
            return False
        decoded = pow(encoded_integer, key.exponent, key.modulus).to_bytes(width, "big")
        digest_info = self._DIGEST_INFO_PREFIX + hashlib.sha256(signing_input).digest()
        padding_size = width - len(digest_info) - 3
        if padding_size < 8:
            return False
        expected = b"\x00\x01" + b"\xff" * padding_size + b"\x00" + digest_info
        return hmac.compare_digest(decoded, expected)


__all__ = ["RsaPublicKey", "RsaSha256SignatureVerifier"]
