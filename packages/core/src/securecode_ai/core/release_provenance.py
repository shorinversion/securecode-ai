"""Release provenance and source-free signature verification receipts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Final, Protocol

_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT: Final = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DIGEST: Final = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}\Z")


class ProvenanceValidationError(ValueError):
    """Raised when release evidence is malformed or cannot be bound."""


@dataclass(frozen=True, slots=True)
class BuildProvenance:
    source_commit: str
    source_tree: str
    lock_sha256: str
    builder_id: str
    workflow_sha256: str
    artifact_digest: str
    image_digest: str

    def __post_init__(self) -> None:
        if type(self.source_commit) is not str or _COMMIT.fullmatch(self.source_commit) is None:
            raise ProvenanceValidationError("invalid source commit")
        if any(
            type(value) is not str or _SHA256.fullmatch(value) is None
            for value in (self.source_tree, self.lock_sha256, self.workflow_sha256)
        ):
            raise ProvenanceValidationError("invalid provenance hash")
        if type(self.builder_id) is not str or _IDENTIFIER.fullmatch(self.builder_id) is None:
            raise ProvenanceValidationError("invalid builder identity")
        if any(
            type(value) is not str or _DIGEST.fullmatch(value) is None
            for value in (self.artifact_digest, self.image_digest)
        ):
            raise ProvenanceValidationError("invalid artifact digest")


@dataclass(frozen=True, slots=True)
class SignatureReceipt:
    key_id: str
    verified: bool
    payload_sha256: str | None = None
    signature_sha256: str | None = None

    def __post_init__(self) -> None:
        if type(self.key_id) is not str or _IDENTIFIER.fullmatch(self.key_id) is None:
            raise ProvenanceValidationError("invalid signature key identity")
        if type(self.verified) is not bool:
            raise ProvenanceValidationError("invalid signature result")
        optional = (self.payload_sha256, self.signature_sha256)
        if (optional[0] is None) != (optional[1] is None):
            raise ProvenanceValidationError("signature binding is incomplete")
        if any(
            value is not None and (type(value) is not str or _SHA256.fullmatch(value) is None)
            for value in optional
        ):
            raise ProvenanceValidationError("invalid signature binding")


class SignatureProvider(Protocol):
    def verify(self, payload: bytes, signature: bytes) -> SignatureReceipt: ...


def checksums(values: dict[str, str]) -> bytes:
    """Build a canonical checksum manifest from validated artifact identities."""
    if type(values) is not dict or not values:
        raise ProvenanceValidationError("checksum manifest cannot be empty")
    for name, digest in values.items():
        if type(name) is not str or _IDENTIFIER.fullmatch(name) is None:
            raise ProvenanceValidationError("invalid checksum artifact identity")
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise ProvenanceValidationError("invalid checksum digest")
    return json.dumps(
        dict(sorted(values.items())),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def release_ready(
    *,
    sbom: bytes | None,
    provenance: BuildProvenance | None,
    signature: SignatureReceipt | None,
) -> bool:
    """Reject incomplete, non-canonical, unverified or wrongly bound evidence."""
    if (
        type(sbom) is not bytes
        or not sbom
        or type(provenance) is not BuildProvenance
        or type(signature) is not SignatureReceipt
        or not signature.verified
    ):
        return False
    if not _canonical_json_document(sbom):
        return False
    if signature.payload_sha256 is None or signature.signature_sha256 is None:
        return False
    expected = hashlib.sha256(canonical_provenance(provenance)).hexdigest()
    return signature.payload_sha256 == expected


def canonical_provenance(value: BuildProvenance) -> bytes:
    if type(value) is not BuildProvenance:
        raise ProvenanceValidationError("invalid provenance value")
    return json.dumps(
        asdict(value),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _canonical_json_document(value: bytes) -> bool:
    try:
        decoded = value.decode("ascii")
        document = json.loads(decoded)
        canonical = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        return False
    return isinstance(document, (dict, list)) and bool(document) and canonical == value


__all__ = [
    "BuildProvenance",
    "ProvenanceValidationError",
    "SignatureProvider",
    "SignatureReceipt",
    "canonical_provenance",
    "checksums",
    "release_ready",
]
