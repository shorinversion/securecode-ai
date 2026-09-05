"""Bounded hardcoded-secret detection with value-free retained results."""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum
from typing import NoReturn, Protocol, SupportsIndex

from securecode_ai.core import RepositoryFile, SourcePoint, SourceRange

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


def scan_secrets(
    *,
    repository_id: str,
    revision: str,
    file: RepositoryFile,
    source: bytes,
    fingerprint_key: SecretFingerprintKey,
    limits: SecretDetectionLimits = DEFAULT_SECRET_DETECTION_LIMITS,
    external_scanner: ApprovedExternalSecretScanner | None = None,
) -> SecretScanResult:
    """Detect secrets in admitted bytes without retaining matched values."""

    if (
        type(repository_id) is not str
        or not repository_id
        or len(repository_id.encode("utf-8")) > 1024
        or type(revision) is not str
        or _SHA1.fullmatch(revision) is None
        or type(file) is not RepositoryFile
        or type(source) is not bytes
        or type(fingerprint_key) is not SecretFingerprintKey
        or type(limits) is not SecretDetectionLimits
        or hashlib.sha256(source).hexdigest() != file.content_sha256
        or len(source) != file.size_bytes
    ):
        raise SecretDetectionError(SecretDetectionErrorCode.REQUEST_INVALID)
    if len(source) > limits.max_source_bytes:
        raise SecretDetectionError(SecretDetectionErrorCode.SOURCE_LIMIT)

    admitted_file = RepositoryFile(file.path, file.size_bytes, file.content_sha256)
    external_file = RepositoryFile(file.path, file.size_bytes, file.content_sha256)

    raw: list[tuple[SecretKind, int, int, SecretProducer]] = []
    _collect_patterns(source, raw, limits)
    _collect_entropy(source, raw, limits)
    if external_scanner is not None:
        _collect_external(
            external_scanner,
            ExternalSecretScanRequest(repository_id, revision, external_file, source),
            source,
            raw,
            limits,
        )
    unique = sorted(set(raw), key=lambda item: (item[1], item[2], item[0].value, item[3].value))
    if len(unique) > limits.max_candidates:
        raise SecretDetectionError(SecretDetectionErrorCode.CANDIDATE_LIMIT)
    line_starts = (0, *(index + 1 for index, value in enumerate(source) if value == 10))
    candidates = tuple(
        _candidate(
            repository_id,
            revision,
            admitted_file,
            source,
            fingerprint_key,
            line_starts,
            kind,
            start,
            end,
            producer,
        )
        for kind, start, end, producer in unique
    )
    return SecretScanResult(
        repository_id=repository_id,
        revision=revision,
        path=admitted_file.path,
        content_sha256=admitted_file.content_sha256,
        source_size_bytes=admitted_file.size_bytes,
        candidates=candidates,
        scan_sha256=_scan_sha256(
            repository_id,
            revision,
            admitted_file.path,
            admitted_file.content_sha256,
            admitted_file.size_bytes,
            candidates,
        ),
    )


def _collect_patterns(
    source: bytes,
    output: list[tuple[SecretKind, int, int, SecretProducer]],
    limits: SecretDetectionLimits,
) -> None:
    for pattern, kind, group in (
        (_AWS_ACCESS_KEY, SecretKind.AWS_ACCESS_KEY_ID, 0),
        (_PRIVATE_KEY, SecretKind.PRIVATE_MATERIAL, 2),
        (_ASSIGNMENT, SecretKind.ASSIGNED_CREDENTIAL, 1),
    ):
        for match in pattern.finditer(source):
            start, end = match.span(group)
            _require_match_budget(start, end, limits)
            value = source[start:end]
            if kind is SecretKind.ASSIGNED_CREDENTIAL and (
                _is_placeholder(value) or len(set(value)) <= 3
            ):
                continue
            _append(output, kind, start, end, limits)


def _collect_entropy(
    source: bytes,
    output: list[tuple[SecretKind, int, int, SecretProducer]],
    limits: SecretDetectionLimits,
) -> None:
    for match in _ENTROPY_TOKEN.finditer(source):
        start, end = match.span()
        _require_match_budget(start, end, limits)
        value = match.group()
        if _is_placeholder(value) or _looks_like_digest(value) or not _high_entropy(value):
            continue
        if any(
            existing_start <= start and end <= existing_end
            for _, existing_start, existing_end, _ in output
        ):
            continue
        _append(output, SecretKind.HIGH_ENTROPY_TOKEN, start, end, limits)


def _collect_external(
    scanner: ApprovedExternalSecretScanner,
    request: ExternalSecretScanRequest,
    source: bytes,
    output: list[tuple[SecretKind, int, int, SecretProducer]],
    limits: SecretDetectionLimits,
) -> None:
    identity_failed = False
    scanner_id: str | None
    scanner_version: str | None
    try:
        scanner_id = scanner.scanner_id
        scanner_version = scanner.scanner_version
    except Exception:
        identity_failed = True
        scanner_id = None
        scanner_version = None
    if (
        identity_failed
        or type(scanner_id) is not str
        or type(scanner_version) is not str
        or scanner_id != "detect-secrets"
        or scanner_version != "1.5.0"
    ):
        raise SecretDetectionError(SecretDetectionErrorCode.REQUEST_INVALID)
    failed = False
    try:
        response = scanner.scan(request)
    except Exception:
        failed = True
        response = None
    if failed:
        raise SecretDetectionError(SecretDetectionErrorCode.EXTERNAL_FAILURE) from None
    if type(response) is not ExternalSecretScanResponse:
        raise SecretDetectionError(SecretDetectionErrorCode.EXTERNAL_OUTPUT_INVALID)
    output_failed = False
    try:
        raw_detections = response.detections
        if type(raw_detections) is not tuple or any(
            type(item) is not ExternalSecretDetection for item in raw_detections
        ):
            output_failed = True
        detections = raw_detections if not output_failed else ()
    except Exception:
        output_failed = True
        detections = ()
    if output_failed:
        raise SecretDetectionError(SecretDetectionErrorCode.EXTERNAL_OUTPUT_INVALID) from None
    if len(detections) > limits.max_external_detections:
        raise SecretDetectionError(SecretDetectionErrorCode.CANDIDATE_LIMIT)
    previous: tuple[int, int, str] | None = None
    previous_end = -1
    for item in detections:
        copy_failed = False
        try:
            copied = ExternalSecretDetection(item.kind, item.start_byte, item.end_byte)
        except (AttributeError, TypeError, ValueError):
            copy_failed = True
            copied = None
        if copy_failed or copied is None:
            raise SecretDetectionError(SecretDetectionErrorCode.EXTERNAL_OUTPUT_INVALID) from None
        current = (copied.start_byte, copied.end_byte, copied.kind.value)
        if (
            copied.end_byte > len(source)
            or copied.end_byte - copied.start_byte > limits.max_match_bytes
            or (previous is not None and current <= previous)
            or copied.start_byte < previous_end
        ):
            raise SecretDetectionError(SecretDetectionErrorCode.EXTERNAL_OUTPUT_INVALID)
        previous = current
        previous_end = copied.end_byte
        output.append(
            (copied.kind, copied.start_byte, copied.end_byte, SecretProducer.APPROVED_EXTERNAL)
        )


def _append(
    output: list[tuple[SecretKind, int, int, SecretProducer]],
    kind: SecretKind,
    start: int,
    end: int,
    limits: SecretDetectionLimits,
) -> None:
    _require_match_budget(start, end, limits)
    output.append((kind, start, end, SecretProducer.FIRST_PARTY))
    if len(output) > limits.max_candidates:
        raise SecretDetectionError(SecretDetectionErrorCode.CANDIDATE_LIMIT)


def _require_match_budget(start: int, end: int, limits: SecretDetectionLimits) -> None:
    if end - start > limits.max_match_bytes:
        raise SecretDetectionError(SecretDetectionErrorCode.MATCH_LIMIT)


def _candidate(
    repository_id: str,
    revision: str,
    file: RepositoryFile,
    source: bytes,
    key: SecretFingerprintKey,
    line_starts: tuple[int, ...],
    kind: SecretKind,
    start: int,
    end: int,
    producer: SecretProducer,
) -> SecretCandidate:
    value = source[start:end]
    return SecretCandidate(
        repository_id=repository_id,
        revision=revision,
        path=file.path,
        content_sha256=file.content_sha256,
        source_size_bytes=file.size_bytes,
        kind=kind,
        location=SourceRange(
            start, end, _point(source, start, line_starts), _point(source, end, line_starts)
        ),
        producer=producer,
        fingerprint_key_id=key.key_id,
        fingerprint_sha256=key.fingerprint(kind, value),
        redaction=f"<redacted:{kind.value}>",
    )


def _point(source: bytes, offset: int, line_starts: tuple[int, ...]) -> SourcePoint:
    del source
    row = bisect_right(line_starts, offset) - 1
    return SourcePoint(row, offset - line_starts[row])


def _is_placeholder(value: bytes) -> bool:
    normalized = value.strip().lower().replace(b"-", b"_").replace(b" ", b"_")
    return normalized in _PLACEHOLDERS or normalized.startswith((b"example_", b"test_", b"dummy_"))


def _looks_like_digest(value: bytes) -> bool:
    return len(value) in {32, 40, 64, 128} and all(
        byte in b"0123456789abcdefABCDEF" for byte in value
    )


def _high_entropy(value: bytes) -> bool:
    classes = sum(
        any(predicate(byte) for byte in value)
        for predicate in (
            lambda byte: 65 <= byte <= 90,
            lambda byte: 97 <= byte <= 122,
            lambda byte: 48 <= byte <= 57,
            lambda byte: byte in b"+/=_-",
        )
    )
    if classes < 3:
        return False
    counts = Counter(value)
    length = len(value)
    entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
    return entropy >= 3.5


def _scan_sha256(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source_size_bytes: int,
    candidates: tuple[SecretCandidate, ...],
) -> str:
    digest = hashlib.sha256()
    for identity in (repository_id, revision, path, content_sha256):
        encoded_identity = identity.encode("utf-8")
        digest.update(len(encoded_identity).to_bytes(8, "big"))
        digest.update(encoded_identity)
    digest.update(source_size_bytes.to_bytes(8, "big"))
    for item in candidates:
        for value in (
            item.repository_id,
            item.revision,
            item.path,
            item.content_sha256,
            str(item.source_size_bytes),
            item.kind.value,
            str(item.location.start_byte),
            str(item.location.end_byte),
            str(item.location.start_point.row),
            str(item.location.start_point.column),
            str(item.location.end_point.row),
            str(item.location.end_point.column),
            item.producer.value,
            item.fingerprint_key_id,
            item.fingerprint_sha256,
            item.redaction,
            item.data_class,
        ):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return digest.hexdigest()


__all__ = [
    "DEFAULT_SECRET_DETECTION_LIMITS",
    "ApprovedExternalSecretScanner",
    "ExternalSecretDetection",
    "ExternalSecretScanRequest",
    "ExternalSecretScanResponse",
    "SecretCandidate",
    "SecretDetectionError",
    "SecretDetectionErrorCode",
    "SecretDetectionLimits",
    "SecretFingerprintKey",
    "SecretKind",
    "SecretProducer",
    "SecretScanResult",
    "scan_secrets",
]
