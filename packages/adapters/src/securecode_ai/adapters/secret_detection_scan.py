"""Bounded hardcoded-secret detection with value-free retained results."""

from __future__ import annotations

import hashlib
import math
import re
from bisect import bisect_right
from collections import Counter

from securecode_ai.core import RepositoryFile, SourcePoint, SourceRange

from .secret_detection_models import (
    _ASSIGNMENT,
    _AWS_ACCESS_KEY,
    _ENTROPY_TOKEN,
    _PLACEHOLDERS,
    _PRIVATE_KEY,
    _SHA1,
    DEFAULT_SECRET_DETECTION_LIMITS,
    ApprovedExternalSecretScanner,
    ExternalSecretDetection,
    ExternalSecretScanRequest,
    ExternalSecretScanResponse,
    SecretCandidate,
    SecretDetectionError,
    SecretDetectionErrorCode,
    SecretDetectionLimits,
    SecretFingerprintKey,
    SecretKind,
    SecretProducer,
    SecretScanResult,
)


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
                _is_placeholder(value) or len(set(value)) <= 3 or b" " in value.strip()
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
        if (
            _is_placeholder(value)
            or _looks_like_digest(value)
            or _looks_like_code_text(value)
            or not _high_entropy(value)
        ):
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


_UUID = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_SEPARATORS = re.compile(rb"[/_+=.-]+")
_CAMEL_PART = re.compile(rb"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
_WORD_PART = re.compile(rb"[A-Za-z]+[0-9]{0,5}|[0-9]+")


def _looks_like_code_text(value: bytes) -> bool:
    """Identifiers, paths and UUIDs are long and mixed-case but not credentials.

    ``source_security_group_owner_id``, ``_SecureModuleImporter``,
    ``//www.apache.org/licenses/LICENSE-2`` and ``describe_instances_v6`` split
    into plain words (optionally with a short numeric suffix); a random key such
    as ``Q7x3Lm+9Vp2Rz8Tk`` leaves digits inside its parts.
    """

    if _UUID.fullmatch(value):
        return True
    numbered = 0
    for segment in _SEPARATORS.split(value):
        if not segment:
            continue
        parts = [segment] if _WORD_PART.fullmatch(segment) else _CAMEL_PART.findall(segment)
        if b"".join(parts) != segment:
            return False
        merged: list[bytes] = []
        for part in parts:
            if part.isdigit() and merged and len(part) <= 5 and not merged[-1].isdigit():
                merged[-1] += part
            else:
                merged.append(part)
        if not all(_WORD_PART.fullmatch(part) for part in merged):
            return False
        numbered += sum(1 for part in merged if part[:1].isalpha() and part[-1:].isdigit())
    # A random key split on case changes yields many short numbered parts.
    return numbered <= 2


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
