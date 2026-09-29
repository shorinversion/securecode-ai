"""Bounded multi-ecosystem dependency parsing and OSV advisory normalization."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, assert_never

from securecode_ai.core import (
    DependencyEcosystem,
    DependencyManifestEntry,
    DependencyManifestKind,
    RepositoryFile,
    SourcePoint,
    SourceRange,
)

_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(rb"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?")
_VERSION = re.compile(rb"[A-Za-z0-9](?:[A-Za-z0-9.!+_-]{0,126}[A-Za-z0-9])?")
_PIN = re.compile(
    rb"(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?)"
    rb"==(?P<version>[A-Za-z0-9](?:[A-Za-z0-9.!+_-]{0,126}[A-Za-z0-9])?)"
    rb"(?P<hashes>(?:[ \t]+--hash=sha256:[0-9a-fA-F]{64})*)[ \t]*(?:#.*)?"
)
# Real OSV identifiers are mixed case, e.g. GHSA-9hjg-9r4m-mvj7.
_OSV_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}\Z")
_PURL = re.compile(r"pkg:(?:pypi|npm|golang)/[A-Za-z0-9%._!~+/-]+@[A-Za-z0-9.!+_-]{1,128}\Z")
_MAX_LIMITS = (1_048_576, 10_000, 10_000, 64)


class DependencyScanErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    MANIFEST_LIMIT = "MANIFEST_LIMIT"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    DEPENDENCY_LIMIT = "DEPENDENCY_LIMIT"
    SCANNER_FAILURE = "SCANNER_FAILURE"
    SCANNER_OUTPUT_INVALID = "SCANNER_OUTPUT_INVALID"
    ADVISORY_LIMIT = "ADVISORY_LIMIT"


class DependencyScanError(RuntimeError):
    """Fixed, non-echoing dependency boundary failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: DependencyScanErrorCode) -> None:
        if type(code) is not DependencyScanErrorCode:
            raise TypeError("dependency scan error code is invalid")
        self.code = code
        self.safe_message = "dependency scan failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class DependencyScanLimits:
    max_manifest_bytes: int = _MAX_LIMITS[0]
    max_dependencies: int = _MAX_LIMITS[1]
    max_advisories: int = _MAX_LIMITS[2]
    max_aliases_per_advisory: int = _MAX_LIMITS[3]

    def __post_init__(self) -> None:
        values = (
            self.max_manifest_bytes,
            self.max_dependencies,
            self.max_advisories,
            self.max_aliases_per_advisory,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_LIMITS, strict=True)
        ):
            raise ValueError("dependency scan limits are invalid")


DEFAULT_DEPENDENCY_SCAN_LIMITS = DependencyScanLimits()


@dataclass(frozen=True, slots=True)
class DependencyCoordinate:
    repository_id: str
    revision: str
    manifest_path: str
    manifest_sha256: str
    ecosystem: DependencyEcosystem
    name: str
    version: str
    location: SourceRange
    purl: str

    def __post_init__(self) -> None:
        expected_purl = _dependency_purl(self.ecosystem, self.name, self.version)
        if (
            type(self.repository_id) is not str
            or not self.repository_id
            or len(self.repository_id.encode("utf-8")) > 1024
            or type(self.revision) is not str
            or _SHA1.fullmatch(self.revision) is None
            or type(self.manifest_path) is not str
            or type(self.manifest_sha256) is not str
            or _SHA256.fullmatch(self.manifest_sha256) is None
            or type(self.ecosystem) is not DependencyEcosystem
            or type(self.name) is not str
            or not _valid_dependency_name(self.ecosystem, self.name)
            or type(self.version) is not str
            or _VERSION.fullmatch(self.version.encode("ascii", errors="ignore")) is None
            or type(self.location) is not SourceRange
            or self.purl != expected_purl
        ):
            raise ValueError("dependency coordinate is invalid")


@dataclass(frozen=True, slots=True)
class ParsedDependencyManifest:
    repository_id: str
    revision: str
    path: str
    content_sha256: str
    dependencies: tuple[DependencyCoordinate, ...]
    manifest_scan_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.repository_id) is not str
            or not self.repository_id
            or len(self.repository_id.encode("utf-8")) > 1024
            or type(self.revision) is not str
            or _SHA1.fullmatch(self.revision) is None
            or type(self.path) is not str
            or not self.path
            or type(self.content_sha256) is not str
            or _SHA256.fullmatch(self.content_sha256) is None
            or type(self.dependencies) is not tuple
            or any(type(item) is not DependencyCoordinate for item in self.dependencies)
            or tuple((item.purl, item.name, item.version) for item in self.dependencies)
            != tuple(sorted((item.purl, item.name, item.version) for item in self.dependencies))
            or len({item.purl for item in self.dependencies}) != len(self.dependencies)
            or any(
                item.repository_id != self.repository_id
                or item.revision != self.revision
                or item.manifest_path != self.path
                or item.manifest_sha256 != self.content_sha256
                for item in self.dependencies
            )
            or self.manifest_scan_sha256
            != _manifest_hash(
                self.repository_id,
                self.revision,
                self.path,
                self.content_sha256,
                self.dependencies,
            )
        ):
            raise ValueError("parsed dependency manifest is invalid")


@dataclass(frozen=True, slots=True)
class OsvAdvisoryRecord:
    advisory_id: str
    aliases: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.advisory_id) is not str
            or _OSV_ID.fullmatch(self.advisory_id) is None
            or type(self.aliases) is not tuple
            or any(
                type(alias) is not str or _OSV_ID.fullmatch(alias) is None for alias in self.aliases
            )
            or self.aliases != tuple(sorted(set(self.aliases)))
            or self.advisory_id in self.aliases
        ):
            raise ValueError("OSV advisory record is invalid")


@dataclass(frozen=True, slots=True)
class OsvPackageResult:
    purl: str
    advisories: tuple[OsvAdvisoryRecord, ...]

    def __post_init__(self) -> None:
        if (
            type(self.purl) is not str
            or _PURL.fullmatch(self.purl) is None
            or type(self.advisories) is not tuple
            or any(type(item) is not OsvAdvisoryRecord for item in self.advisories)
            or tuple(item.advisory_id for item in self.advisories)
            != tuple(sorted(item.advisory_id for item in self.advisories))
            or len({item.advisory_id for item in self.advisories}) != len(self.advisories)
        ):
            raise ValueError("OSV package result is invalid")


@dataclass(frozen=True, slots=True)
class OsvBatchRequest:
    purls: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.purls) is not tuple
            or not self.purls
            or any(type(item) is not str or _PURL.fullmatch(item) is None for item in self.purls)
            or self.purls != tuple(sorted(set(self.purls)))
        ):
            raise ValueError("OSV batch request is invalid")


@dataclass(frozen=True, slots=True)
class OsvBatchResponse:
    results: tuple[OsvPackageResult, ...]

    def __post_init__(self) -> None:
        if type(self.results) is not tuple or any(
            type(item) is not OsvPackageResult for item in self.results
        ):
            raise ValueError("OSV batch response is invalid")


class ApprovedOsvScanner(Protocol):
    scanner_id: str
    scanner_version: str

    def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse: ...


@dataclass(frozen=True, slots=True)
class DependencyAdvisory:
    coordinate: DependencyCoordinate
    advisory_id: str
    aliases: tuple[str, ...]
    producer: str
    advisory_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.coordinate) is not DependencyCoordinate
            or _OSV_ID.fullmatch(self.advisory_id) is None
            or type(self.aliases) is not tuple
            or self.aliases != tuple(sorted(set(self.aliases)))
            or any(_OSV_ID.fullmatch(alias) is None for alias in self.aliases)
            or self.advisory_id in self.aliases
            or self.producer != "osv.dev@v1"
            or self.advisory_sha256
            != _advisory_hash(self.coordinate.purl, self.advisory_id, self.aliases)
        ):
            raise ValueError("dependency advisory is invalid")


@dataclass(frozen=True, slots=True)
class DependencyScanResult:
    manifest_scan_sha256: str
    advisories: tuple[DependencyAdvisory, ...]
    scan_sha256: str
    coordinates: tuple[DependencyCoordinate, ...] = ()

    def __post_init__(self) -> None:
        if (
            not _SHA256.fullmatch(self.manifest_scan_sha256)
            or type(self.advisories) is not tuple
            or any(type(item) is not DependencyAdvisory for item in self.advisories)
            or tuple((item.coordinate.purl, item.advisory_id) for item in self.advisories)
            != tuple(sorted((item.coordinate.purl, item.advisory_id) for item in self.advisories))
            or len({(item.coordinate.purl, item.advisory_id) for item in self.advisories})
            != len(self.advisories)
            or type(self.coordinates) is not tuple
            or any(type(item) is not DependencyCoordinate for item in self.coordinates)
            or tuple((item.purl, item.name, item.version) for item in self.coordinates)
            != tuple(sorted((item.purl, item.name, item.version) for item in self.coordinates))
            or len({item.purl for item in self.coordinates}) != len(self.coordinates)
            or (
                self.coordinates
                and (
                    any(
                        item.repository_id != self.coordinates[0].repository_id
                        or item.revision != self.coordinates[0].revision
                        or item.manifest_path != self.coordinates[0].manifest_path
                        or item.manifest_sha256 != self.coordinates[0].manifest_sha256
                        or item.ecosystem is not self.coordinates[0].ecosystem
                        for item in self.coordinates
                    )
                    or _manifest_hash(
                        self.coordinates[0].repository_id,
                        self.coordinates[0].revision,
                        self.coordinates[0].manifest_path,
                        self.coordinates[0].manifest_sha256,
                        self.coordinates,
                    )
                    != self.manifest_scan_sha256
                )
            )
            or any(advisory.coordinate not in self.coordinates for advisory in self.advisories)
            or self.scan_sha256 != _scan_hash(self.manifest_scan_sha256, self.advisories)
        ):
            raise ValueError("dependency scan result is invalid")

    @property
    def inventory_sha256(self) -> str:
        """Hash of every pinned coordinate retained for this manifest."""

        return _inventory_hash(self.manifest_scan_sha256, self.coordinates)


def parse_python_requirements(
    *,
    repository_id: str,
    revision: str,
    manifest: DependencyManifestEntry,
    file: RepositoryFile,
    source: bytes,
    limits: DependencyScanLimits = DEFAULT_DEPENDENCY_SCAN_LIMITS,
) -> ParsedDependencyManifest:
    """Parse exact, pinned Python requirements from admitted manifest bytes."""

    if (
        type(repository_id) is not str
        or not repository_id
        or len(repository_id.encode("utf-8")) > 1024
        or type(revision) is not str
        or _SHA1.fullmatch(revision) is None
        or type(manifest) is not DependencyManifestEntry
        or manifest.ecosystem is not DependencyEcosystem.PYTHON
        or manifest.kind is not DependencyManifestKind.REQUIREMENTS
        or manifest.ignored_by_rule_id is not None
        or type(file) is not RepositoryFile
        or file.path != manifest.path
        or file.content_sha256 != manifest.content_sha256
        or type(source) is not bytes
        or len(source) != file.size_bytes
        or hashlib.sha256(source).hexdigest() != file.content_sha256
        or type(limits) is not DependencyScanLimits
    ):
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
    if len(source) > limits.max_manifest_bytes:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_LIMIT)
    try:
        source.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID) from None

    dependencies: list[DependencyCoordinate] = []
    seen: set[str] = set()
    offset = 0
    for row, line_with_ending in enumerate(source.splitlines(keepends=True)):
        line = line_with_ending.rstrip(b"\r\n")
        stripped = line.strip()
        if not stripped or stripped.startswith(b"#"):
            offset += len(line_with_ending)
            continue
        match = _PIN.fullmatch(stripped)
        if match is None:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        raw_name = match.group("name")
        raw_version = match.group("version")
        name = _canonical_name(raw_name.decode("ascii"))
        version = raw_version.decode("ascii")
        if name in seen:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        seen.add(name)
        start_in_line = line.find(raw_name)
        end_in_line = start_in_line + len(raw_name) + 2 + len(raw_version)
        dependencies.append(
            DependencyCoordinate(
                repository_id=repository_id,
                revision=revision,
                manifest_path=file.path,
                manifest_sha256=file.content_sha256,
                ecosystem=DependencyEcosystem.PYTHON,
                name=name,
                version=version,
                location=SourceRange(
                    start_byte=offset + start_in_line,
                    end_byte=offset + end_in_line,
                    start_point=SourcePoint(row, start_in_line),
                    end_point=SourcePoint(row, end_in_line),
                ),
                purl=_dependency_purl(DependencyEcosystem.PYTHON, name, version) or "",
            )
        )
        if len(dependencies) > limits.max_dependencies:
            raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
        offset += len(line_with_ending)
    ordered = tuple(sorted(dependencies, key=lambda item: (item.purl, item.name, item.version)))
    return ParsedDependencyManifest(
        repository_id=repository_id,
        revision=revision,
        path=file.path,
        content_sha256=file.content_sha256,
        dependencies=ordered,
        manifest_scan_sha256=_manifest_hash(
            repository_id, revision, file.path, file.content_sha256, ordered
        ),
    )


def scan_dependency_advisories(
    parsed: ParsedDependencyManifest,
    scanner: ApprovedOsvScanner | None,
    *,
    limits: DependencyScanLimits = DEFAULT_DEPENDENCY_SCAN_LIMITS,
) -> DependencyScanResult:
    """Normalize an approved OSV batch result without granting it path or verdict authority."""

    if type(parsed) is not ParsedDependencyManifest or type(limits) is not DependencyScanLimits:
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
    if not parsed.dependencies:
        return DependencyScanResult(
            parsed.manifest_scan_sha256,
            (),
            _scan_hash(parsed.manifest_scan_sha256, ()),
            parsed.dependencies,
        )
    if scanner is None:
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
    identity_failed = False
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
        or scanner_id != "osv.dev"
        or scanner_version != "v1"
    ):
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
    request = OsvBatchRequest(tuple(sorted(item.purl for item in parsed.dependencies)))
    scanner_failed = False
    try:
        response = scanner.query_batch(request)
    except Exception:
        scanner_failed = True
        response = None
    if scanner_failed:
        raise DependencyScanError(DependencyScanErrorCode.SCANNER_FAILURE) from None
    if type(response) is not OsvBatchResponse:
        raise DependencyScanError(DependencyScanErrorCode.SCANNER_OUTPUT_INVALID)
    expected = {item.purl: item for item in parsed.dependencies}
    if len(response.results) != len(expected):
        raise DependencyScanError(DependencyScanErrorCode.SCANNER_OUTPUT_INVALID)
    results: dict[str, OsvPackageResult] = {}
    advisory_count = 0
    for result in response.results:
        advisory_count += len(result.advisories)
        if (
            result.purl not in expected
            or result.purl in results
            or advisory_count > limits.max_advisories
            or any(
                len(item.aliases) > limits.max_aliases_per_advisory for item in result.advisories
            )
        ):
            raise DependencyScanError(DependencyScanErrorCode.SCANNER_OUTPUT_INVALID)
        results[result.purl] = result
    if set(results) != set(expected):
        raise DependencyScanError(DependencyScanErrorCode.SCANNER_OUTPUT_INVALID)
    advisories = tuple(
        DependencyAdvisory(
            coordinate=expected[purl],
            advisory_id=record.advisory_id,
            aliases=record.aliases,
            producer="osv.dev@v1",
            advisory_sha256=_advisory_hash(purl, record.advisory_id, record.aliases),
        )
        for purl in sorted(results)
        for record in results[purl].advisories
    )
    if len(advisories) > limits.max_advisories:
        raise DependencyScanError(DependencyScanErrorCode.ADVISORY_LIMIT)
    return DependencyScanResult(
        parsed.manifest_scan_sha256,
        advisories,
        _scan_hash(parsed.manifest_scan_sha256, advisories),
        parsed.dependencies,
    )


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _dependency_purl(ecosystem: DependencyEcosystem, name: str, version: str) -> str | None:
    if (
        type(ecosystem) is not DependencyEcosystem
        or type(name) is not str
        or type(version) is not str
    ):
        return None
    if ecosystem is DependencyEcosystem.PYTHON:
        return f"pkg:pypi/{name}@{version}"
    if ecosystem is DependencyEcosystem.JAVASCRIPT:
        if name.startswith("@") and "/" in name:
            namespace, package = name[1:].split("/", 1)
            return f"pkg:npm/%40{namespace}/{package}@{version}"
        return f"pkg:npm/{name}@{version}"
    if ecosystem is DependencyEcosystem.GO:
        escaped = "/".join(
            "".join(
                f"!{character.lower()}" if character.isupper() else character for character in part
            )
            for part in name.split("/")
        )
        return f"pkg:golang/{escaped}@{version}"
    assert_never(ecosystem)


def _valid_dependency_name(ecosystem: DependencyEcosystem, name: str) -> bool:
    if ecosystem is DependencyEcosystem.PYTHON:
        return _NAME.fullmatch(
            name.encode("ascii", errors="ignore")
        ) is not None and name == _canonical_name(name)
    if ecosystem is DependencyEcosystem.JAVASCRIPT:
        raw = name[1:] if name.startswith("@") else name
        parts = raw.split("/")
        return bool(
            name == name.lower()
            and len(parts) in {1, 2}
            and all(re.fullmatch(r"[a-z0-9._~-]{1,214}", part) for part in parts)
            and (not name.startswith("@") or len(parts) == 2)
        )
    if ecosystem is DependencyEcosystem.GO:
        return bool(
            len(name.encode("utf-8")) <= 1024
            and "/" in name
            and all(re.fullmatch(r"[A-Za-z0-9._~+-]{1,255}", part) for part in name.split("/"))
        )
    assert_never(ecosystem)


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _coordinate_projection(item: DependencyCoordinate) -> dict[str, object]:
    return {
        "content_sha256": item.manifest_sha256,
        "ecosystem": item.ecosystem.value,
        "location": [item.location.start_byte, item.location.end_byte],
        "name": item.name,
        "path": item.manifest_path,
        "purl": item.purl,
        "version": item.version,
    }


def _manifest_hash(
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    dependencies: tuple[DependencyCoordinate, ...],
) -> str:
    return _canonical_hash(
        {
            "content_sha256": content_sha256,
            "dependencies": [_coordinate_projection(item) for item in dependencies],
            "path": path,
            "repository_id": repository_id,
            "revision": revision,
        }
    )


def _advisory_hash(purl: str, advisory_id: str, aliases: tuple[str, ...]) -> str:
    return _canonical_hash({"aliases": list(aliases), "id": advisory_id, "purl": purl})


def _scan_hash(manifest_hash: str, advisories: tuple[DependencyAdvisory, ...]) -> str:
    return _canonical_hash(
        {
            "advisories": [item.advisory_sha256 for item in advisories],
            "manifest_scan_sha256": manifest_hash,
        }
    )


def _inventory_hash(manifest_hash: str, coordinates: tuple[DependencyCoordinate, ...]) -> str:
    return _canonical_hash(
        {
            "coordinates": [_coordinate_projection(item) for item in coordinates],
            "manifest_scan_sha256": manifest_hash,
        }
    )
