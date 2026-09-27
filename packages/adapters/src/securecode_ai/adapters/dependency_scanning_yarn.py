"""Strict, bounded parsing for Yarn Berry lockfiles."""

from __future__ import annotations

import json
import re

from .dependency_scanning import (
    DependencyScanError,
    DependencyScanErrorCode,
    DependencyScanLimits,
)

_SEMVER = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z"
)
_NPM_PART = re.compile(r"[a-z0-9](?:[a-z0-9._~-]{0,212}[a-z0-9])?\Z")
_NPM_SCOPE = re.compile(r"@[a-z0-9](?:[a-z0-9._~-]{0,212}[a-z0-9])?\Z")
_RANGE = re.compile(r"[A-Za-z0-9.*+|^~<>=!_:/@%?#-]{1,512}\Z")
_METADATA_FIELDS = frozenset({"version", "cacheKey"})
_PACKAGE_FIELDS = frozenset(
    {
        "version",
        "resolution",
        "checksum",
        "languageName",
        "linkType",
        "dependencies",
        "dependenciesMeta",
        "peerDependencies",
        "peerDependenciesMeta",
        "optionalDependencies",
        "transitivePeerDependencies",
        "bin",
        "conditions",
        "discardFromLookup",
        "hasInstallScript",
    }
)
_BLOCK_FIELDS = frozenset(
    {
        "dependencies",
        "dependenciesMeta",
        "peerDependencies",
        "peerDependenciesMeta",
        "optionalDependencies",
        "transitivePeerDependencies",
        "bin",
        "conditions",
    }
)


def parse_yarn_berry_lock(
    text: str,
    limits: DependencyScanLimits,
) -> set[tuple[str, str]]:
    """Extract exact npm pins from a Yarn Berry lockfile.

    Only registry resolutions are accepted. Workspace, patch, git, portal, and
    file protocols remain rejected so source bytes cannot enter the advisory
    request through a lockfile parser.
    """

    if type(text) is not str or type(limits) is not DependencyScanLimits:
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
    metadata_seen = False
    current_kind: str | None = None
    current_key: tuple[str, ...] = ()
    current_fields: dict[str, str | None] = {}
    current_block = False
    selectors_seen: set[str] = set()
    pins: set[tuple[str, str]] = set()

    def finish_current() -> None:
        nonlocal metadata_seen, current_kind, current_key, current_fields
        nonlocal current_block
        if current_kind is None:
            return
        if current_kind == "metadata":
            if metadata_seen or set(current_fields) - _METADATA_FIELDS:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            version = current_fields.get("version")
            if (
                type(version) is not str
                or not version.isdecimal()
                or not 2 <= int(version) <= 16
            ):
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            metadata_seen = True
        else:
            _finish_package(current_key, current_fields, selectors_seen, pins, limits)
        current_kind = None
        current_key = ()
        current_fields = {}
        current_block = False

    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line or any(ord(char) < 32 and char != "\r" for char in line):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            finish_current()
            if not line.endswith(":"):
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            key = _top_level_key(line[:-1])
            if key == "__metadata":
                if metadata_seen:
                    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
                current_kind = "metadata"
                current_key = ()
            else:
                if not metadata_seen:
                    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
                current_kind = "package"
                current_key = _selectors(key)
                current_block = False
            continue
        if indent == 2:
            if current_kind is None:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            key, raw_value = _field(line[2:])
            allowed = (
                _METADATA_FIELDS if current_kind == "metadata" else _PACKAGE_FIELDS
            )
            if key in current_fields or key not in allowed:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            if raw_value == "":
                if key not in _BLOCK_FIELDS:
                    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
                current_fields[key] = None
                current_block = True
            else:
                current_fields[key] = _scalar(raw_value)
                current_block = False
            continue
        if indent < 4 or current_kind is None or not current_block:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        _nested_line(line[indent:])

    finish_current()
    if not metadata_seen or not pins:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return pins


def _finish_package(
    selectors: tuple[str, ...],
    fields: dict[str, str | None],
    selectors_seen: set[str],
    pins: set[tuple[str, str]],
    limits: DependencyScanLimits,
) -> None:
    if not selectors or any(selector in selectors_seen for selector in selectors):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    selectors_seen.update(selectors)
    version = fields.get("version")
    resolution = fields.get("resolution")
    if (
        type(version) is not str
        or _SEMVER.fullmatch(version) is None
        or type(resolution) is not str
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    resolved_name, resolved_version = _resolution(resolution)
    if version != resolved_version or any(
        _selector_name(selector) != resolved_name for selector in selectors
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    language_name = fields.get("languageName")
    link_type = fields.get("linkType")
    if language_name is not None and language_name != "node":
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if link_type is not None and link_type not in {"hard", "soft"}:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    pins.add((resolved_name, resolved_version))
    if len(pins) > limits.max_dependencies:
        raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)


def _selectors(raw: str) -> tuple[str, ...]:
    value = _scalar(raw)
    parts = tuple(part.strip() for part in value.split(","))
    if not parts or any(not part for part in parts):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    for part in parts:
        marker = "@npm:"
        if marker not in part:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        name, request = part.split(marker, 1)
        if not _valid_npm_name(name) or _RANGE.fullmatch(request) is None:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return parts


def _selector_name(selector: str) -> str:
    name, _, request = selector.partition("@npm:")
    if not name or not request:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return name


def _resolution(raw: str) -> tuple[str, str]:
    name, marker, version = raw.partition("@npm:")
    if not marker or not _valid_npm_name(name) or _SEMVER.fullmatch(version) is None:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return name, version


def _valid_npm_name(value: str) -> bool:
    if not value.isascii() or len(value) > 512:
        return False
    if value.startswith("@"):
        parts = value.split("/")
        return (
            len(parts) == 2
            and _NPM_SCOPE.fullmatch(parts[0]) is not None
            and _NPM_PART.fullmatch(parts[1]) is not None
        )
    return "/" not in value and _NPM_PART.fullmatch(value) is not None


def _top_level_key(raw: str) -> str:
    value = _scalar(raw)
    if not value or "\n" in value or "\r" in value:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return value


def _field(line: str) -> tuple[str, str]:
    separator = line.find(":")
    if separator <= 0:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    key = line[:separator]
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return key, line[separator + 1 :].strip()


def _nested_line(line: str) -> None:
    if not line or line.startswith("-"):
        if not line.startswith("- ") or not _RANGE.fullmatch(line[2:].strip()):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        return
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif quote == '"' and char == "\\":
            escaped = True
        elif quote is not None and char == quote:
            quote = None
        elif quote is None and char == '"':
            quote = char
        elif quote is None and char == ":":
            key, value = line[:index].strip(), line[index + 1 :].strip()
            if not key or any(ord(item) < 32 for item in key):
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            if value:
                _scalar(value)
            return
    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)


def _scalar(raw: str) -> str:
    if not raw or any(char in raw for char in "\r\n\t"):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if raw.startswith('"'):
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            value = None
        if type(value) is not str:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        return value
    if raw.startswith("'") or any(char.isspace() for char in raw):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return raw
