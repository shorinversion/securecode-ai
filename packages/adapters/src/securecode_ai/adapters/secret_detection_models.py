"""Bounded hardcoded-secret detection with value-free retained results."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import NoReturn, Protocol, SupportsIndex

from securecode_ai.core import RepositoryFile, SourceRange

_MAX_LIMITS = (2_000_000, 10_000, 4096, 10_000)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_ID = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_AWS_ACCESS_KEY = re.compile(rb"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])")
_PRIVATE_KEY = re.compile(
    rb"-----BEGIN ((?:RSA |EC |OPENSSH )?PRIVATE KEY)-----\r?\n"
    rb"([A-Za-z0-9+/=\r\n]{16,})"
    rb"-----END \1-----"
)
_ASSIGNMENT = re.compile(
    rb"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password)"
    rb"\s*[:=]\s*[\"']([^\"'\r\n]{8,})[\"']"
)
_ENTROPY_TOKEN = re.compile(rb"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{20,}(?![A-Za-z0-9+/=_-])")
_PLACEHOLDERS = {
    b"changeme",
    b"example",
    b"placeholder",
    b"redacted",
    b"replace_me",
    b"your_api_key",
    b"your_token_here",
}


class SecretKind(StrEnum):
    AWS_ACCESS_KEY_ID = "aws_access_key_id"
    PRIVATE_MATERIAL = "private_key"
    ASSIGNED_CREDENTIAL = "assigned_credential"
    HIGH_ENTROPY_TOKEN = "high_entropy_token"


class SecretProducer(StrEnum):
    FIRST_PARTY = "securecode-secret-detector@1.0"
    APPROVED_EXTERNAL = "detect-secrets@1.5.0"


class SecretDetectionErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    CANDIDATE_LIMIT = "CANDIDATE_LIMIT"
    MATCH_LIMIT = "MATCH_LIMIT"
    EXTERNAL_FAILURE = "EXTERNAL_FAILURE"
    EXTERNAL_OUTPUT_INVALID = "EXTERNAL_OUTPUT_INVALID"


class SecretDetectionError(RuntimeError):
    """Fixed non-echoing secret detection boundary failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: SecretDetectionErrorCode) -> None:
        if type(code) is not SecretDetectionErrorCode:
            raise TypeError("secret detection error code is invalid")
        self.code = code
        self.safe_message = "secret detection failed"
        super().__init__(self.safe_message)

    def __reduce__(self) -> tuple[type[SecretDetectionError], tuple[SecretDetectionErrorCode]]:
        return (type(self), (self.code,))


@dataclass(frozen=True, slots=True)
class SecretDetectionLimits:
    max_source_bytes: int = _MAX_LIMITS[0]
    max_candidates: int = _MAX_LIMITS[1]
    max_match_bytes: int = _MAX_LIMITS[2]
    max_external_detections: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_candidates,
            self.max_match_bytes,
            self.max_external_detections,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("secret detection limits are invalid")


DEFAULT_SECRET_DETECTION_LIMITS = SecretDetectionLimits()


class SecretFingerprintKey:
    """Opaque keyed-fingerprint capability; raw key bytes are not serializable fields."""

    __key_id: str
    __value: bytes
    __slots__ = ("__key_id", "__value")

    def __init__(self, key_id: str, value: bytes) -> None:
        if (
            type(key_id) is not str
            or not _ID.fullmatch(key_id)
            or type(value) is not bytes
            or not 32 <= len(value) <= 64
        ):
            raise ValueError("secret fingerprint key is invalid")
        object.__setattr__(self, "_SecretFingerprintKey__key_id", key_id)
        object.__setattr__(self, "_SecretFingerprintKey__value", value)

    @property
    def key_id(self) -> str:
        return self.__key_id

    def __setattr__(self, name: str, value: object) -> NoReturn:
        del name, value
        raise TypeError("secret fingerprint key is immutable")

    def fingerprint(self, kind: SecretKind, value: bytes) -> str:
        return hmac.digest(self.__value, kind.value.encode("ascii") + b"\0" + value, "sha256").hex()

    def __getstate__(self) -> NoReturn:
        raise TypeError("secret fingerprint key is not serializable")

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("secret fingerprint key is not serializable")

    def __copy__(self) -> NoReturn:
        raise TypeError("secret fingerprint key is not copyable")

    def __deepcopy__(self, memo: dict[int, object]) -> NoReturn:
        del memo
        raise TypeError("secret fingerprint key is not copyable")


@dataclass(frozen=True, slots=True)
class ExternalSecretDetection:
    kind: SecretKind
    start_byte: int
    end_byte: int

    def __post_init__(self) -> None:
        if (
            type(self.kind) is not SecretKind
            or type(self.start_byte) is not int
            or type(self.end_byte) is not int
            or self.start_byte < 0
            or self.end_byte <= self.start_byte
        ):
            raise ValueError("external secret detection is invalid")


@dataclass(frozen=True, slots=True)
class ExternalSecretScanRequest:
    repository_id: str
    revision: str
    file: RepositoryFile
    source: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.repository_id) is not str
            or not self.repository_id
            or len(self.repository_id.encode("utf-8")) > 1024
            or type(self.revision) is not str
            or _SHA1.fullmatch(self.revision) is None
            or type(self.file) is not RepositoryFile
            or type(self.source) is not bytes
            or len(self.source) != self.file.size_bytes
            or hashlib.sha256(self.source).hexdigest() != self.file.content_sha256
        ):
            raise ValueError("external secret scan request is invalid")


@dataclass(frozen=True, slots=True)
class ExternalSecretScanResponse:
    detections: tuple[ExternalSecretDetection, ...]

    def __post_init__(self) -> None:
        if type(self.detections) is not tuple or any(
            type(item) is not ExternalSecretDetection for item in self.detections
        ):
            raise ValueError("external secret scan response is invalid")


class ApprovedExternalSecretScanner(Protocol):
    scanner_id: str
    scanner_version: str

    def scan(self, request: ExternalSecretScanRequest) -> ExternalSecretScanResponse: ...


@dataclass(frozen=True, slots=True)
class SecretCandidate:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    kind: SecretKind
    location: SourceRange
    producer: SecretProducer
    fingerprint_key_id: str
    fingerprint_sha256: str
    redaction: str
    data_class: str = "DC4_RESTRICTED"

    def __post_init__(self) -> None:
        identity_valid = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and len(self.repository_id.encode("utf-8")) <= 1024
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
            and type(self.content_sha256) is str
            and re.fullmatch(r"[0-9a-f]{64}", self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        if (
            not identity_valid
            or type(self.kind) is not SecretKind
            or type(self.location) is not SourceRange
            or self.location.end_byte > self.source_size_bytes
            or type(self.producer) is not SecretProducer
            or not _ID.fullmatch(self.fingerprint_key_id)
            or re.fullmatch(r"[0-9a-f]{64}", self.fingerprint_sha256) is None
            or self.redaction != f"<redacted:{self.kind.value}>"
            or self.data_class != "DC4_RESTRICTED"
        ):
            raise ValueError("secret candidate is invalid")


@dataclass(frozen=True, slots=True)
class SecretScanResult:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    source_size_bytes: int
    candidates: tuple[SecretCandidate, ...]
    scan_sha256: str

    def __post_init__(self) -> None:
        from .secret_detection_scan import _scan_sha256

        identity_valid = (
            type(self.repository_id) is str
            and bool(self.repository_id)
            and len(self.repository_id.encode("utf-8")) <= 1024
            and type(self.revision) is str
            and _SHA1.fullmatch(self.revision) is not None
            and type(self.path) is str
            and type(self.content_sha256) is str
            and re.fullmatch(r"[0-9a-f]{64}", self.content_sha256) is not None
            and type(self.source_size_bytes) is int
            and self.source_size_bytes >= 0
        )
        if identity_valid:
            try:
                RepositoryFile(self.path, self.source_size_bytes, self.content_sha256)
            except ValueError:
                identity_valid = False
        if type(self.candidates) is not tuple or any(
            type(item) is not SecretCandidate for item in self.candidates
        ):
            raise ValueError("secret scan result is invalid")
        order = tuple(
            (item.location.start_byte, item.location.end_byte, item.kind.value, item.producer.value)
            for item in self.candidates
        )
        identities_match = all(
            item.repository_id == self.repository_id
            and item.revision == self.revision
            and item.path == self.path
            and item.content_sha256 == self.content_sha256
            and item.source_size_bytes == self.source_size_bytes
            for item in self.candidates
        )
        if (
            not identity_valid
            or order != tuple(sorted(order))
            or len(order) != len(set(order))
            or not identities_match
            or self.scan_sha256
            != _scan_sha256(
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.source_size_bytes,
                self.candidates,
            )
        ):
            raise ValueError("secret scan result is invalid")
