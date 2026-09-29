"""Deterministic parsing of static npm dependency lockfiles."""

from __future__ import annotations

import hashlib
import json
import re

from securecode_ai.core import (
    DependencyEcosystem,
    DependencyManifestEntry,
    DependencyManifestKind,
    RepositoryFile,
    SourcePoint,
    SourceRange,
)

from .dependency_scanning import (
    DEFAULT_DEPENDENCY_SCAN_LIMITS,
    DependencyCoordinate,
    DependencyScanError,
    DependencyScanErrorCode,
    DependencyScanLimits,
    ParsedDependencyManifest,
    _dependency_purl,
    _manifest_hash,
)

_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.!+_-]{0,126}[A-Za-z0-9])?\Z")
_NPM_PART = re.compile(r"[a-z0-9](?:[a-z0-9._~-]{0,212}[a-z0-9])?\Z")
_NPM_SCOPE = re.compile(r"@[a-z0-9](?:[a-z0-9._~-]{0,212}[a-z0-9])?\Z")
_REGISTRY_TARBALL = re.compile(
    r"/(?:"
    r"@(?P<raw_scope>[a-z0-9._~-]+)/(?P<raw_package>[a-z0-9._~-]+)"
    r"|@(?P<encoded_scope>[a-z0-9._~-]+)%2f(?P<encoded_package>[a-z0-9._~-]+)"
    r"|(?P<plain_package>[a-z0-9._~-]+)"
    r")/-/(?P<filename>[A-Za-z0-9][A-Za-z0-9._+-]*\.tgz)\Z"
)


def parse_javascript_dependency_manifest(
    repository_id: str,
    revision: str,
    manifest: DependencyManifestEntry,
    file: RepositoryFile,
    source: bytes,
    limits: DependencyScanLimits = DEFAULT_DEPENDENCY_SCAN_LIMITS,
) -> ParsedDependencyManifest:
    """Parse exact, pinned packages from npm package lock v1, v2, or v3."""

    _validate_input(repository_id, revision, manifest, file, source, limits)
    try:
        document = json.loads(
            source.decode("utf-8", errors="strict"),
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except DependencyScanError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID) from None
    if type(document) is not dict or type(document.get("lockfileVersion")) is not int:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    lockfile_version = document["lockfileVersion"]
    if lockfile_version == 1:
        pins = _v1_pins(document, limits.max_dependencies)
    elif lockfile_version in {2, 3}:
        pins = _flat_pins(document, limits.max_dependencies)
    else:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)

    unique: dict[str, tuple[str, str]] = {}
    for name, version in pins:
        purl = _dependency_purl(DependencyEcosystem.JAVASCRIPT, name, version)
        if purl is None:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        unique[purl] = (name, version)

    content_sha256 = file.content_sha256
    location = SourceRange(
        start_byte=0,
        end_byte=len(source),
        start_point=SourcePoint(0, 0),
        end_point=_point(source, len(source)),
    )
    dependencies = tuple(
        DependencyCoordinate(
            repository_id=repository_id,
            revision=revision,
            manifest_path=file.path,
            manifest_sha256=content_sha256,
            ecosystem=DependencyEcosystem.JAVASCRIPT,
            name=name,
            version=version,
            location=location,
            purl=purl,
        )
        for purl, (name, version) in sorted(unique.items())
    )
    return ParsedDependencyManifest(
        repository_id=repository_id,
        revision=revision,
        path=file.path,
        content_sha256=content_sha256,
        dependencies=dependencies,
        manifest_scan_sha256=_manifest_hash(
            repository_id, revision, file.path, content_sha256, dependencies
        ),
    )


def _flat_pins(document: dict[str, object], max_dependencies: int) -> set[tuple[str, str]]:
    packages = document.get("packages")
    if type(packages) is not dict:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    package_count = 0
    pins: set[tuple[str, str]] = set()
    for path, value in packages.items():
        if type(path) is not str or type(value) is not dict:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        if path == "":
            if "link" in value and value["link"] is not False:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            continue
        name = _package_name_from_path(path)
        package_count += 1
        if package_count > max_dependencies:
            raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
        pins.add((name, _pinned_version(value, name)))
    return pins


def _v1_pins(document: dict[str, object], max_dependencies: int) -> set[tuple[str, str]]:
    if "packages" in document:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    root_dependencies = document.get("dependencies")
    if type(root_dependencies) is not dict:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    pending: list[tuple[dict[str, object], str]] = [(root_dependencies, "")]
    pins: set[tuple[str, str]] = set()
    seen_paths: set[str] = set()
    package_count = 0
    while pending:
        dependencies, parent_path = pending.pop()
        for name, value in dependencies.items():
            if (
                type(name) is not str
                or type(value) is not dict
                or _package_name_from_path(f"node_modules/{name}") != name
            ):
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            package_path = (
                f"{parent_path}/node_modules/{name}" if parent_path else f"node_modules/{name}"
            )
            if package_path in seen_paths:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            seen_paths.add(package_path)
            package_count += 1
            if package_count > max_dependencies:
                raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
            version = _pinned_version(value, name)
            pins.add((name, version))
            nested = value.get("dependencies", {})
            if type(nested) is not dict:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            pending.append((nested, package_path))
    return pins


def _pinned_version(value: dict[str, object], name: str) -> str:
    if value.get("link") is True or ("link" in value and type(value["link"]) is not bool):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    recorded_name = value.get("name")
    if recorded_name is not None and recorded_name != name:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    version = value.get("version")
    if type(version) is not str or _VERSION.fullmatch(version) is None:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if "resolved" in value and not _standard_registry_source(value["resolved"], name, version):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return version


def _validate_input(
    repository_id: str,
    revision: str,
    manifest: DependencyManifestEntry,
    file: RepositoryFile,
    source: bytes,
    limits: DependencyScanLimits,
) -> None:
    try:
        valid_repository_id = (
            type(repository_id) is str
            and bool(repository_id)
            and len(repository_id.encode("utf-8", errors="strict")) <= 1024
        )
    except UnicodeEncodeError:
        valid_repository_id = False
    if (
        not valid_repository_id
        or type(revision) is not str
        or _REVISION.fullmatch(revision) is None
        or type(manifest) is not DependencyManifestEntry
        or manifest.ecosystem is not DependencyEcosystem.JAVASCRIPT
        or manifest.kind
        not in {
            DependencyManifestKind.PACKAGE_LOCK,
            DependencyManifestKind.NPM_SHRINKWRAP,
        }
        or manifest.ignored_by_rule_id is not None
        or type(file) is not RepositoryFile
        or file.path != manifest.path
        or file.content_sha256 != manifest.content_sha256
        or type(source) is not bytes
        or len(source) != file.size_bytes
        or not _SHA256.fullmatch(file.content_sha256)
        or type(limits) is not DependencyScanLimits
    ):
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
    if len(source) > limits.max_manifest_bytes:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_LIMIT)
    if hashlib.sha256(source).hexdigest() != file.content_sha256:
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_: str) -> object:
    raise ValueError


def _package_name_from_path(path: str) -> str:
    if not path or not path.isascii() or len(path) > 1024 or "\\" in path or path.startswith("/"):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    parts = path.split("/")
    names: list[str] = []
    index = 0
    while index < len(parts):
        if parts[index] != "node_modules" or index + 1 >= len(parts):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        index += 1
        first = parts[index]
        if _NPM_SCOPE.fullmatch(first) is not None:
            if index + 1 >= len(parts) or _NPM_PART.fullmatch(parts[index + 1]) is None:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            names.append(f"{first}/{parts[index + 1]}")
            index += 2
        else:
            if _NPM_PART.fullmatch(first) is None:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            names.append(first)
            index += 1
        if index < len(parts) and parts[index] != "node_modules":
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if not names:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return names[-1]


def _standard_registry_source(value: object, name: str, version: str) -> bool:
    if type(value) is not str or len(value) > 2048:
        return False
    prefix = "https://registry.npmjs.org"
    if not value.startswith(prefix):
        return False
    path = value[len(prefix) :]
    if not path.startswith("/") or "?" in path or "#" in path or "\\" in path:
        return False
    match = _REGISTRY_TARBALL.fullmatch(path)
    if match is None:
        return False
    expected = name.split("/", 1)
    raw_scope = match.group("raw_scope")
    encoded_scope = match.group("encoded_scope")
    if raw_scope is not None:
        actual_name = f"@{raw_scope}/{match.group('raw_package')}"
    elif encoded_scope is not None:
        actual_name = f"@{encoded_scope}/{match.group('encoded_package')}"
    else:
        actual_name = match.group("plain_package")
    return actual_name == name and match.group("filename") == f"{expected[-1]}-{version}.tgz"


def _point(source: bytes, offset: int) -> SourcePoint:
    prefix = source[:offset]
    row = prefix.count(b"\n")
    last = prefix.rfind(b"\n")
    return SourcePoint(row, offset if last < 0 else offset - last - 1)
