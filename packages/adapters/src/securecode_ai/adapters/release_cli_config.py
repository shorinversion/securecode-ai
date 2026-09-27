"""Bounded source verification for the local release CLI composition."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Final, cast

from securecode_ai.core.release_candidate import ReleaseCandidate
from securecode_ai.core.supply_chain import DependencyPolicy

from .release_provider import (
    ReleaseArtifactSource,
    ReleaseEvidenceSource,
    ReleaseSbomBinding,
    ReleaseSbomInput,
)
from .release_provider_support import (
    HmacReleaseAuthority,
    LocalReleaseProviderError,
    _canonical_artifact_checksums,
    _canonical_sbom_binding,
    _existing_root,
    _open_regular_beneath,
    _open_regular_file,
    _path_argument,
    _read_verified_file,
    _reject_unsafe_ancestors,
    _require_directory,
    _require_safe_ancestors,
    _same_file_state,
    _store_identity,
)

_CHUNK_BYTES: Final = 1024 * 1024
_MAX_ARTIFACT_BYTES: Final = 16 * 1024 * 1024 * 1024
_MAX_ARTIFACTS: Final = 256
_MIN_AUTHORIZATION_KEY_BYTES: Final = 32
_MAX_AUTHORIZATION_KEY_BYTES: Final = 4096
_MAX_CANONICAL_EVIDENCE_BYTES: Final = 16 * 1024 * 1024
_EVIDENCE_FIELDS: Final = frozenset(
    {
        "checksums_sha256",
        "closure_activation_sha256",
        "provenance_sha256",
        "release_signature_sha256",
        "sbom_sha256",
        "server_image_digest",
        "source_tree_sha256",
        "worker_image_digest",
    }
)
_CANONICAL_JSON_EVIDENCE: Final = frozenset(
    {
        "checksums_sha256",
        "closure_activation_sha256",
        "provenance_sha256",
        "sbom_sha256",
    }
)
_DEPENDENCY_POLICY_KEYS: Final = frozenset({"allowed_licenses", "denied_names"})
_MAX_POLICY_VALUES: Final = 256
_MAX_POLICY_TEXT_BYTES: Final = 512


HmacReleaseAuthorizationVerifier = HmacReleaseAuthority


def release_store_identity(path: str | os.PathLike[str]) -> str:
    return _store_identity(_path_argument(path))


def read_bounded_local_file(path: str | os.PathLike[str], maximum_bytes: int) -> bytes:
    """Read one stable regular local file without following a final reparse point."""

    try:
        if type(maximum_bytes) is not int or maximum_bytes < 1:
            raise LocalReleaseProviderError()
        return _read_verified_file(_path_argument(path), maximum_bytes)
    except LocalReleaseProviderError:
        raise
    except (OSError, TypeError, ValueError):
        raise LocalReleaseProviderError() from None


def read_protected_release_key(path: str | os.PathLike[str]) -> bytes:
    """Read a stable host-owned HMAC key from a protected regular file."""

    value = _read_protected_file(
        path,
        minimum_bytes=_MIN_AUTHORIZATION_KEY_BYTES,
        maximum_bytes=_MAX_AUTHORIZATION_KEY_BYTES + 2,
    ).rstrip(b"\r\n")
    if not _MIN_AUTHORIZATION_KEY_BYTES <= len(value) <= _MAX_AUTHORIZATION_KEY_BYTES:
        raise LocalReleaseProviderError()
    return value


def read_protected_release_config(path: str | os.PathLike[str], maximum_bytes: int) -> bytes:
    """Read an absolute stable host-owned publication configuration."""

    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 1024 * 1024:
        raise LocalReleaseProviderError()
    return _read_protected_file(path, minimum_bytes=1, maximum_bytes=maximum_bytes)


def parse_release_dependency_policy(value: object) -> DependencyPolicy:
    """Parse a trusted, protected release policy without supplying defaults."""

    try:
        if type(value) is not dict or frozenset(value) != _DEPENDENCY_POLICY_KEYS:
            raise LocalReleaseProviderError()
        allowed = _policy_values(value["allowed_licenses"], required=True)
        denied = _policy_values(value["denied_names"], required=False)
        return DependencyPolicy(frozenset(allowed), frozenset(denied))
    except LocalReleaseProviderError:
        raise
    except (TypeError, ValueError):
        raise LocalReleaseProviderError() from None


def _policy_values(value: object, *, required: bool) -> tuple[str, ...]:
    if (
        type(value) is not list
        or len(value) > _MAX_POLICY_VALUES
        or (required and not value)
    ):
        raise LocalReleaseProviderError()
    values: list[str] = []
    for item in value:
        if (
            type(item) is not str
            or not 1 <= len(item) <= _MAX_POLICY_TEXT_BYTES
            or item != item.strip()
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in item)
        ):
            raise LocalReleaseProviderError()
        values.append(item)
    if len(values) != len(set(values)):
        raise LocalReleaseProviderError()
    return tuple(values)


def _read_protected_file(
    path: str | os.PathLike[str], *, minimum_bytes: int, maximum_bytes: int
) -> bytes:
    """Read a stable protected file with no final reparse traversal."""

    descriptor = -1
    try:
        if os.name != "posix":
            raise LocalReleaseProviderError()
        raw_path = Path(os.fspath(path))
        if not raw_path.is_absolute():
            raise LocalReleaseProviderError()
        resolved = _path_argument(raw_path)
        _require_safe_ancestors(resolved.parent.resolve(strict=True))
        before = resolved.stat(follow_symlinks=False)
        descriptor = _open_regular_file(resolved)
        opened = os.fstat(descriptor)
        if (
            before.st_nlink != 1
            or opened.st_nlink != 1
            or before.st_dev != opened.st_dev
            or before.st_ino != opened.st_ino
            or before.st_mode != opened.st_mode
            or before.st_size != opened.st_size
            or not minimum_bytes <= opened.st_size <= maximum_bytes
        ):
            raise LocalReleaseProviderError()
        current_uid = cast(Callable[[], int], vars(os)["geteuid"])()
        if opened.st_mode & 0o077 or opened.st_uid not in {0, current_uid}:
            raise LocalReleaseProviderError()
        chunks: list[bytes] = []
        total = 0
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            while chunk := stream.read(1024):
                total += len(chunk)
                if total > maximum_bytes:
                    raise LocalReleaseProviderError()
                chunks.append(chunk)
            after = os.fstat(stream.fileno())
        value = b"".join(chunks)
        if not minimum_bytes <= len(value) <= maximum_bytes or not _same_file_state(opened, after):
            raise LocalReleaseProviderError()
        if b"\x00" in value:
            raise LocalReleaseProviderError()
        return value
    except LocalReleaseProviderError:
        raise
    except (OSError, TypeError, ValueError):
        raise LocalReleaseProviderError() from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def verify_release_sources(
    source_root: str | os.PathLike[str],
    artifacts: tuple[ReleaseArtifactSource, ...],
    evidence: tuple[ReleaseEvidenceSource, ...],
    candidate: ReleaseCandidate,
    sbom_binding: ReleaseSbomBinding | None = None,
) -> None:
    """Re-read every mapped artifact and signature against the candidate hashes."""

    try:
        if (
            type(artifacts) is not tuple
            or not artifacts
            or len(artifacts) > _MAX_ARTIFACTS
            or type(candidate) is not ReleaseCandidate
            or len(candidate.artifacts) != len(artifacts)
            or any(type(item) is not ReleaseArtifactSource for item in artifacts)
            or type(evidence) is not tuple
            or len(evidence) != len(_EVIDENCE_FIELDS)
            or any(type(item) is not ReleaseEvidenceSource for item in evidence)
            or (sbom_binding is not None and type(sbom_binding) is not ReleaseSbomBinding)
        ):
            raise LocalReleaseProviderError()
        expected = {item.artifact_id: item for item in candidate.artifacts}
        if len(expected) != len(artifacts) or {item.artifact_id for item in artifacts} != set(
            expected
        ):
            raise LocalReleaseProviderError()
        root = _existing_root(source_root)
        artifact_mappings = tuple(
            (
                source.artifact_id,
                source.artifact_relative_path,
                expected[source.artifact_id].checksum_sha256,
            )
            for source in artifacts
        )
        for source in artifacts:
            artifact = expected[source.artifact_id]
            _verify_source(root, source.artifact_relative_path, artifact.checksum_sha256)
            _verify_source(root, source.signature_relative_path, artifact.signature_sha256)
        if {item.evidence_id for item in evidence} != _EVIDENCE_FIELDS:
            raise LocalReleaseProviderError()
        sbom_value: bytes | None = None
        for evidence_source in evidence:
            evidence_id = evidence_source.evidence_id
            if evidence_id == "checksums_sha256":
                raw = _verify_source(
                    root,
                    evidence_source.relative_path,
                    None,
                    collect=True,
                )
                value = (
                    raw
                    if raw[:1] == b"{"
                    else _canonical_artifact_checksums(raw, artifact_mappings)
                )
                if hashlib.sha256(value).hexdigest() != candidate.checksums_sha256:
                    raise LocalReleaseProviderError()
                parsed = json.loads(value.decode("ascii"))
                if type(parsed) is not dict or value != _canonical_json(parsed):
                    raise LocalReleaseProviderError()
                continue
            canonical = evidence_id in _CANONICAL_JSON_EVIDENCE
            value = _verify_source(
                root,
                evidence_source.relative_path,
                getattr(candidate, evidence_id),
                collect=canonical,
            )
            if canonical:
                parsed = json.loads(value.decode("ascii"))
                if value != _canonical_json(parsed):
                    raise LocalReleaseProviderError()
            if evidence_id == "sbom_sha256":
                sbom_value = value
        if sbom_binding is not None:
            if sbom_value is None:
                raise LocalReleaseProviderError()
            report_value = _verify_source(
                root,
                sbom_binding.report_relative_path,
                None,
                collect=True,
            )
            assessment_value = _verify_source(
                root,
                sbom_binding.assessment_relative_path,
                sbom_binding.assessment_sha256,
                collect=True,
            )
            expected_sbom = _canonical_sbom_binding(
                report_value,
                assessment_value,
                sbom_binding,
            )
            if (
                expected_sbom != sbom_value
                or hashlib.sha256(expected_sbom).hexdigest() != candidate.sbom_sha256
            ):
                raise LocalReleaseProviderError()
    except LocalReleaseProviderError:
        raise
    except (OSError, TypeError, ValueError):
        raise LocalReleaseProviderError() from None


def bind_release_sbom_inputs(
    source_root: str | os.PathLike[str], inputs: ReleaseSbomInput
) -> ReleaseSbomBinding:
    """Derive a protected SBOM binding from explicit stable source files."""

    try:
        if type(inputs) is not ReleaseSbomInput:
            raise LocalReleaseProviderError()
        root = _existing_root(source_root)
        report = _verify_source(
            root,
            inputs.report_relative_path,
            None,
            collect=True,
        )
        assessment = _verify_source(
            root,
            inputs.assessment_relative_path,
            None,
            collect=True,
        )
        document = json.loads(report.decode("ascii"))
        if type(document) is not dict:
            raise LocalReleaseProviderError()
        binding = ReleaseSbomBinding(
            inputs.report_relative_path,
            inputs.assessment_relative_path,
            hashlib.sha256(_canonical_json(document)).hexdigest(),
            hashlib.sha256(assessment).hexdigest(),
        )
        _canonical_sbom_binding(report, assessment, binding)
        return binding
    except LocalReleaseProviderError:
        raise
    except (OSError, RecursionError, TypeError, UnicodeDecodeError, ValueError):
        raise LocalReleaseProviderError() from None


def verify_release_layout(
    source_root: str | os.PathLike[str], destination_root: str | os.PathLike[str]
) -> None:
    """Validate source/destination separation without creating destination state."""

    try:
        source = _existing_root(source_root)
        destination_input = _path_argument(destination_root)
        if destination_input.exists():
            _require_directory(destination_input)
        destination = destination_input.resolve(strict=False)
        if source == destination or source in destination.parents or destination in source.parents:
            raise LocalReleaseProviderError()
    except LocalReleaseProviderError:
        raise
    except (OSError, TypeError, ValueError):
        raise LocalReleaseProviderError() from None


def _verify_source(
    root: Path, relative_path: str, expected_sha256: str | None, *, collect: bool = False
) -> bytes:
    path = root.joinpath(*PurePosixPath(relative_path).parts)
    _reject_unsafe_ancestors(root, path)
    descriptor = (
        _open_regular_beneath(root, relative_path)
        if os.name == "posix"
        else _open_regular_file(path)
    )
    try:
        before = os.fstat(descriptor)
        limit = _MAX_CANONICAL_EVIDENCE_BYTES if collect else _MAX_ARTIFACT_BYTES
        if before.st_size < 0 or before.st_size > limit:
            raise LocalReleaseProviderError()
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        size = 0
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            while chunk := stream.read(_CHUNK_BYTES):
                size += len(chunk)
                if size > limit:
                    raise LocalReleaseProviderError()
                digest.update(chunk)
                if collect:
                    chunks.append(chunk)
            after = os.fstat(stream.fileno())
        if (
            size != before.st_size
            or (
                expected_sha256 is not None
                and digest.hexdigest() != expected_sha256
            )
            or not _same_file_state(before, after)
        ):
            raise LocalReleaseProviderError()
        return b"".join(chunks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


__all__ = [
    "HmacReleaseAuthorizationVerifier",
    "read_bounded_local_file",
    "read_protected_release_config",
    "read_protected_release_key",
    "bind_release_sbom_inputs",
    "parse_release_dependency_policy",
    "release_store_identity",
    "verify_release_layout",
    "verify_release_sources",
]
