"""Strict, bounded parsing of pinned Go module requirements."""

from __future__ import annotations

import hashlib
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
    _valid_dependency_name,
)

_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GO_PATH = re.compile(rb"[A-Za-z0-9._~+-]+(?:/[A-Za-z0-9._~+-]+)+\Z")
_GO_VERSION = re.compile(
    rb"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    rb"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    rb"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    rb"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_REQUIRE = re.compile(
    rb"require[ \t]+(?P<path>[A-Za-z0-9._~+-]+(?:/[A-Za-z0-9._~+-]+)+)"
    rb"[ \t]+(?P<version>v[^ \t]+)(?:[ \t]+//(?:[^\r\n]*))?\Z"
)
_REQUIRE_MEMBER = re.compile(
    rb"(?P<path>[A-Za-z0-9._~+-]+(?:/[A-Za-z0-9._~+-]+)+)"
    rb"[ \t]+(?P<version>v[^ \t]+)(?:[ \t]+//(?:[^\r\n]*))?\Z"
)
_BLOCK_OPEN = re.compile(rb"require[ \t]+\([ \t]*(?://[^\r\n]*)?\Z")
_BLOCK_CLOSE = re.compile(rb"\)[ \t]*(?://[^\r\n]*)?\Z")
_MODULE = re.compile(
    rb"module[ \t]+(?P<path>[A-Za-z0-9._~+-]+(?:/[A-Za-z0-9._~+-]+)+)"
    rb"[ \t]*(?://[^\r\n]*)?\Z"
)
_GO_DIRECTIVE = re.compile(rb"go[ \t]+[0-9]+\.[0-9]+(?:\.[0-9]+)?[ \t]*(?://[^\r\n]*)?\Z")
_TOOLCHAIN = re.compile(
    rb"toolchain[ \t]+go[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:rc[0-9]+|beta[0-9]+)?"
    rb"[ \t]*(?://[^\r\n]*)?\Z"
)
_COMMENT = re.compile(rb"//[^\r\n]*\Z")


def parse_go_dependency_manifest(
    *,
    repository_id: str,
    revision: str,
    manifest: DependencyManifestEntry,
    file: RepositoryFile,
    source: bytes,
    limits: DependencyScanLimits = DEFAULT_DEPENDENCY_SCAN_LIMITS,
) -> ParsedDependencyManifest:
    """Parse exact Go ``require`` lines from a bound ``go.mod`` snapshot."""

    if (
        type(repository_id) is not str
        or not repository_id
        or len(repository_id.encode("utf-8")) > 1024
        or type(revision) is not str
        or _SHA1.fullmatch(revision) is None
        or type(manifest) is not DependencyManifestEntry
        or manifest.ecosystem is not DependencyEcosystem.GO
        or manifest.kind is not DependencyManifestKind.GO_MOD
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
    if source.startswith(b"\xef\xbb\xbf"):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if any((byte < 32 and byte not in {9, 10, 13}) or byte == 127 for byte in source):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)

    dependencies: list[DependencyCoordinate] = []
    seen_purls: set[str] = set()
    require_block = False
    module_seen = False
    go_seen = False
    toolchain_seen = False
    offset = 0

    for row, line_with_ending in enumerate(source.splitlines(keepends=True)):
        line = line_with_ending
        if line.endswith(b"\n"):
            line = line[:-1]
        elif line.endswith(b"\r"):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        if line.endswith(b"\r"):
            line = line[:-1]
        if b"\r" in line:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        stripped = line.strip(b" \t")
        if not stripped or _COMMENT.fullmatch(stripped) is not None:
            offset += len(line_with_ending)
            continue

        if require_block:
            if _BLOCK_CLOSE.fullmatch(stripped) is not None:
                require_block = False
                offset += len(line_with_ending)
                continue
            match = _REQUIRE_MEMBER.fullmatch(stripped)
            if match is None:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            name_raw = match.group("path")
            version_raw = match.group("version")
            dependencies.append(
                _dependency(
                    repository_id,
                    revision,
                    file,
                    row,
                    offset,
                    line,
                    name_raw,
                    version_raw,
                    seen_purls,
                )
            )
            if len(dependencies) > limits.max_dependencies:
                raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
            offset += len(line_with_ending)
            continue

        if _BLOCK_OPEN.fullmatch(stripped) is not None:
            require_block = True
            offset += len(line_with_ending)
            continue
        match = _REQUIRE.fullmatch(stripped)
        if match is not None:
            name_raw = match.group("path")
            version_raw = match.group("version")
            dependencies.append(
                _dependency(
                    repository_id,
                    revision,
                    file,
                    row,
                    offset,
                    line,
                    name_raw,
                    version_raw,
                    seen_purls,
                )
            )
            if len(dependencies) > limits.max_dependencies:
                raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
            offset += len(line_with_ending)
            continue

        if _MODULE.fullmatch(stripped) is not None:
            if module_seen:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            module_seen = True
            offset += len(line_with_ending)
            continue
        if _GO_DIRECTIVE.fullmatch(stripped) is not None:
            if go_seen:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            go_seen = True
            offset += len(line_with_ending)
            continue
        if _TOOLCHAIN.fullmatch(stripped) is not None:
            if toolchain_seen:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            toolchain_seen = True
            offset += len(line_with_ending)
            continue

        directive = stripped.split(None, 1)[0]
        if directive in {b"replace", b"exclude", b"retract", b"tool"}:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)

    if require_block or not module_seen:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
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


def _dependency(
    repository_id: str,
    revision: str,
    file: RepositoryFile,
    row: int,
    line_offset: int,
    line: bytes,
    name_raw: bytes,
    version_raw: bytes,
    seen_purls: set[str],
) -> DependencyCoordinate:
    if (
        len(name_raw) > 1024
        or len(version_raw) > 128
        or _GO_PATH.fullmatch(name_raw) is None
        or _GO_VERSION.fullmatch(version_raw) is None
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    name = name_raw.decode("ascii")
    version = version_raw.decode("ascii")
    if not _valid_dependency_name(DependencyEcosystem.GO, name):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    purl = _dependency_purl(DependencyEcosystem.GO, name, version)
    if purl is None or purl in seen_purls:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    seen_purls.add(purl)

    start_in_line = line.find(name_raw)
    version_start_in_line = line.find(version_raw, start_in_line + len(name_raw))
    end_in_line = version_start_in_line + len(version_raw)
    start_byte = line_offset + start_in_line
    end_byte = line_offset + end_in_line
    return DependencyCoordinate(
        repository_id=repository_id,
        revision=revision,
        manifest_path=file.path,
        manifest_sha256=file.content_sha256,
        ecosystem=DependencyEcosystem.GO,
        name=name,
        version=version,
        location=SourceRange(
            start_byte=start_byte,
            end_byte=end_byte,
            start_point=SourcePoint(row, start_in_line),
            end_point=SourcePoint(row, end_in_line),
        ),
        purl=purl,
    )
