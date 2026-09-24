"""Deterministic parsing of static dependency manifests across supported ecosystems."""

from __future__ import annotations

import configparser
import hashlib
import json
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import PurePosixPath

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
    _canonical_name,
    _dependency_purl,
    _manifest_hash,
    parse_python_requirements,
)
from .dependency_scanning_setup_py import parse_static_setup_py

_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z")
_VERSION = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.!+_-]{0,126}[A-Za-z0-9])?\Z")
_EXACT = re.compile(
    r"\s*(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?)"
    r"(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*(?P<version>"
    r"[A-Za-z0-9](?:[A-Za-z0-9.!+_-]{0,126}[A-Za-z0-9])?)\s*\Z"
)
_PYPI_SIMPLE_URLS = frozenset({"https://pypi.org/simple", "https://pypi.org/simple/"})
_PACKAGE_ORIGIN_KEYS = frozenset(
    {"develop", "editable", "file", "git", "path", "source", "url", "vcs"}
)
_UV_INDEX_KEYS = frozenset(
    {
        "default-index",
        "extra-index-url",
        "find-links",
        "index",
        "index-url",
        "no-index",
        "sources",
    }
)


@dataclass(frozen=True, slots=True)
class _Pin:
    raw_name: str
    name: str
    version: str
    start_byte: int | None = None
    end_byte: int | None = None


def parse_python_dependency_manifest(
    *,
    repository_id: str,
    revision: str,
    manifest: DependencyManifestEntry,
    file: RepositoryFile,
    source: bytes,
    limits: DependencyScanLimits = DEFAULT_DEPENDENCY_SCAN_LIMITS,
) -> ParsedDependencyManifest:
    """Parse only complete, static, exactly pinned Python dependency metadata."""

    if manifest.kind is DependencyManifestKind.REQUIREMENTS:
        return parse_python_requirements(
            repository_id=repository_id,
            revision=revision,
            manifest=manifest,
            file=file,
            source=source,
            limits=limits,
        )
    _validate_input(repository_id, revision, manifest, file, source, limits)
    try:
        text = source.decode("utf-8", errors="strict")
        if manifest.kind in {
            DependencyManifestKind.PYPROJECT,
            DependencyManifestKind.PIPFILE,
            DependencyManifestKind.POETRY_LOCK,
            DependencyManifestKind.UV_LOCK,
            DependencyManifestKind.PDM_LOCK,
        }:
            pins = _toml_pins(manifest.kind, tomllib.loads(text))
        elif manifest.kind is DependencyManifestKind.PIPFILE_LOCK:
            pins = _pipfile_lock_pins(json.loads(text, object_pairs_hook=_closed_object))
        elif manifest.kind is DependencyManifestKind.SETUP_CFG:
            pins = _setup_cfg_pins(text)
        elif manifest.kind is DependencyManifestKind.SETUP_PY:
            setup_pins = parse_static_setup_py(source)
            if len(setup_pins) > limits.max_dependencies:
                raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
            pins = _unique(
                _pin(item.raw_name, item.version, item.start_byte, item.end_byte)
                for item in setup_pins
            )
        else:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    except DependencyScanError:
        raise
    except (configparser.Error, json.JSONDecodeError, RecursionError, TOMLDecodeError, ValueError):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID) from None
    if len(pins) > limits.max_dependencies:
        raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
    dependencies = _coordinates(repository_id, revision, manifest, file, source, pins)
    return ParsedDependencyManifest(
        repository_id=repository_id,
        revision=revision,
        path=file.path,
        content_sha256=file.content_sha256,
        dependencies=dependencies,
        manifest_scan_sha256=_manifest_hash(
            repository_id, revision, file.path, file.content_sha256, dependencies
        ),
    )


def parse_dependency_manifest(
    *,
    repository_id: str,
    revision: str,
    manifest: DependencyManifestEntry,
    file: RepositoryFile,
    source: bytes,
    limits: DependencyScanLimits = DEFAULT_DEPENDENCY_SCAN_LIMITS,
) -> ParsedDependencyManifest:
    """Parse one supported ecosystem manifest without converting gaps to empty inventory."""
    if type(manifest) is not DependencyManifestEntry:
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)
    if manifest.ecosystem is DependencyEcosystem.PYTHON:
        return parse_python_dependency_manifest(
            repository_id=repository_id,
            revision=revision,
            manifest=manifest,
            file=file,
            source=source,
            limits=limits,
        )
    if manifest.ecosystem is DependencyEcosystem.JAVASCRIPT:
        from .dependency_scanning_javascript import parse_javascript_dependency_manifest

        return parse_javascript_dependency_manifest(
            repository_id=repository_id,
            revision=revision,
            manifest=manifest,
            file=file,
            source=source,
            limits=limits,
        )
    if manifest.ecosystem is DependencyEcosystem.GO:
        from .dependency_scanning_go import parse_go_dependency_manifest

        return parse_go_dependency_manifest(
            repository_id=repository_id,
            revision=revision,
            manifest=manifest,
            file=file,
            source=source,
            limits=limits,
        )
    raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)


TOMLDecodeError = tomllib.TOMLDecodeError


def _validate_input(
    repository_id: str,
    revision: str,
    manifest: DependencyManifestEntry,
    file: RepositoryFile,
    source: bytes,
    limits: DependencyScanLimits,
) -> None:
    if (
        type(repository_id) is not str
        or not repository_id
        or len(repository_id.encode("utf-8")) > 1024
        or re.fullmatch(r"[0-9a-f]{40}", revision) is None
        or type(manifest) is not DependencyManifestEntry
        or manifest.ecosystem is not DependencyEcosystem.PYTHON
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


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


def _toml_pins(kind: DependencyManifestKind, document: dict[str, object]) -> tuple[_Pin, ...]:
    if kind in {
        DependencyManifestKind.POETRY_LOCK,
        DependencyManifestKind.UV_LOCK,
        DependencyManifestKind.PDM_LOCK,
    }:
        packages = document.get("package")
        if not isinstance(packages, list):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        if not all(isinstance(item, dict) for item in packages):
            return _invalid()
        members = _uv_workspace_members(document) if kind is DependencyManifestKind.UV_LOCK else ()
        lock_pins = (_lock_pin(kind, item, members) for item in packages)
        return _unique(pin for pin in lock_pins if pin is not None)
    if kind is DependencyManifestKind.PIPFILE:
        source_names = _pypi_source_names(document.get("source"))
        sections = []
        for key in ("packages", "dev-packages"):
            value = document.get(key, {})
            if not isinstance(value, dict):
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            sections.append(value)
        pins = []
        for section in sections:
            for name, value in section.items():
                if isinstance(value, str):
                    version = value
                elif (
                    isinstance(value, dict)
                    and set(value).issubset({"index", "version"})
                    and "version" in value
                    and _valid_source_name(value.get("index"), source_names)
                ):
                    version = value["version"]
                else:
                    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
                pins.append(_pin(name, _exact_version(version)))
        return _unique(pins)
    if kind is not DependencyManifestKind.PYPROJECT:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    project_pins: list[_Pin] = []
    build_system = document.get("build-system")
    if build_system is not None:
        if (
            not isinstance(build_system, dict)
            or not set(build_system).issubset({"backend-path", "build-backend", "requires"})
            or "requires" not in build_system
            or (
                "backend-path" in build_system
                and (
                    not isinstance(build_system["backend-path"], list)
                    or any(not isinstance(item, str) for item in build_system["backend-path"])
                )
            )
            or (
                "build-backend" in build_system
                and not isinstance(build_system["build-backend"], str)
            )
        ):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        project_pins.extend(_requirement_list(build_system["requires"]))
    project = document.get("project", {})
    if not isinstance(project, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    dynamic = project.get("dynamic", [])
    if not isinstance(dynamic, list) or any(not isinstance(item, str) for item in dynamic):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if {"dependencies", "optional-dependencies"}.intersection(dynamic):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    project_pins.extend(_requirement_list(project.get("dependencies", [])))
    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    for values in optional.values():
        project_pins.extend(_requirement_list(values))
    dependency_groups = document.get("dependency-groups", {})
    if not isinstance(dependency_groups, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    for values in dependency_groups.values():
        project_pins.extend(_requirement_list(values))
    tool = document.get("tool", {})
    if not isinstance(tool, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    poetry = tool.get("poetry", {})
    if not isinstance(poetry, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if poetry.get("source") not in (None, [], {}):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    project_pins.extend(_poetry_table(poetry.get("dependencies", {})))
    project_pins.extend(_poetry_table(poetry.get("dev-dependencies", {})))
    groups = poetry.get("group", {})
    if not isinstance(groups, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    for group in groups.values():
        if not isinstance(group, dict) or not set(group).issubset({"dependencies", "optional"}):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        project_pins.extend(_poetry_table(group.get("dependencies", {})))
    pdm = tool.get("pdm", {})
    if not isinstance(pdm, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if pdm.get("source") not in (None, [], {}):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    pdm_dev = pdm.get("dev-dependencies", {})
    if not isinstance(pdm_dev, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    for values in pdm_dev.values():
        project_pins.extend(_requirement_list(values))
    uv = tool.get("uv", {})
    if not isinstance(uv, dict) or not _valid_uv_indexes(uv):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return _unique(project_pins)


def _pypi_source_names(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) != 1:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    source = value[0]
    if (
        not isinstance(source, dict)
        or set(source) != {"name", "url", "verify_ssl"}
        or not isinstance(source.get("name"), str)
        or _NAME.fullmatch(source["name"]) is None
        or source.get("url") not in _PYPI_SIMPLE_URLS
        or source.get("verify_ssl") is not True
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return (source["name"],)


def _valid_source_name(value: object, source_names: tuple[str, ...]) -> bool:
    return value is None or (isinstance(value, str) and value in source_names)


def _valid_uv_indexes(uv: dict[str, object]) -> bool:
    present = _UV_INDEX_KEYS.intersection(uv)
    if not present:
        return True
    if present == {"index"}:
        indexes = uv["index"]
        return bool(
            isinstance(indexes, list)
            and len(indexes) == 1
            and isinstance(indexes[0], dict)
            and set(indexes[0]) == {"default", "name", "url"}
            and indexes[0].get("default") is True
            and indexes[0].get("url") in _PYPI_SIMPLE_URLS
            and isinstance(indexes[0].get("name"), str)
            and _NAME.fullmatch(indexes[0]["name"]) is not None
        )
    if present == {"default-index"}:
        return uv["default-index"] in _PYPI_SIMPLE_URLS
    if present == {"index-url"}:
        return uv["index-url"] in _PYPI_SIMPLE_URLS
    return False


def _uv_workspace_members(document: dict[str, object]) -> tuple[str, ...]:
    manifest = document.get("manifest")
    if not isinstance(manifest, dict):
        return ()
    members = manifest.get("members")
    if not isinstance(members, list) or any(not isinstance(item, str) for item in members):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    normalized = tuple(_canonical_name(item) for item in members)
    if any(
        _NAME.fullmatch(item) is None or item != normalized_item
        for item, normalized_item in zip(members, normalized, strict=True)
    ) or len(normalized) != len(set(normalized)):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return tuple(sorted(normalized))


def _uv_local_workspace_package(
    item: dict[str, object],
    source: dict[str, object],
    workspace_members: tuple[str, ...],
) -> bool:
    if len(source) != 1:
        return False
    origin = next(iter(source))
    if origin not in {"editable", "virtual"}:
        return False
    path = source[origin]
    name = item.get("name")
    if not isinstance(name, str) or _canonical_name(name) not in workspace_members:
        return False
    _pin(name, item.get("version"))
    if not isinstance(path, str) or not _repository_relative_path(path):
        return False
    return origin != "virtual" or path == "."


def _repository_relative_path(value: str) -> bool:
    if value == ".":
        return True
    path = PurePosixPath(value)
    return bool(
        value
        and len(value.encode("utf-8")) <= 1024
        and "\\" not in value
        and not path.is_absolute()
        and path.as_posix() == value
        and all(part not in {"", ".", ".."} for part in path.parts)
        and not path.parts[0].endswith(":")
    )


def _lock_pin(
    kind: DependencyManifestKind,
    item: dict[str, object],
    workspace_members: tuple[str, ...] = (),
) -> _Pin | None:
    origin_keys = _PACKAGE_ORIGIN_KEYS.intersection(item)
    if kind is DependencyManifestKind.UV_LOCK:
        source = item.get("source")
        if origin_keys != {"source"} or not isinstance(source, dict):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        if set(source) == {"registry"} and source.get("registry") in _PYPI_SIMPLE_URLS:
            return _pin(item.get("name"), item.get("version"))
        if _uv_local_workspace_package(item, source, workspace_members):
            return None
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    elif origin_keys:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return _pin(item.get("name"), item.get("version"))


def _poetry_table(value: object) -> list[_Pin]:
    if not isinstance(value, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    pins = []
    for name, constraint in value.items():
        if name.lower() == "python":
            continue
        if isinstance(constraint, str):
            version = constraint
        elif isinstance(constraint, dict) and set(constraint) == {"version"}:
            version = constraint["version"]
        else:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        pins.append(_pin(name, _exact_version(version)))
    return pins


def _pipfile_lock_pins(document: dict[str, object]) -> tuple[_Pin, ...]:
    metadata = document.get("_meta")
    if not isinstance(metadata, dict):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    source_names = _pypi_source_names(metadata.get("sources"))
    pins = []
    for key in ("default", "develop"):
        section = document.get(key, {})
        if not isinstance(section, dict):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        for name, value in section.items():
            if not isinstance(value, dict) or "version" not in value:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            forbidden = {"editable", "file", "git", "path", "ref"}
            if forbidden.intersection(value) or not _valid_source_name(
                value.get("index"), source_names
            ):
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            pins.append(_pin(name, _exact_version(value["version"])))
    return _unique(pins)


def _setup_cfg_pins(text: str) -> tuple[_Pin, ...]:
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(text)
    if parser.has_option("options", "dependency_links"):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    values = []
    for option in ("install_requires", "setup_requires", "tests_require"):
        if parser.has_option("options", option):
            values.extend(_requirement_lines(parser.get("options", option)))
    if parser.has_section("options.extras_require"):
        for _, raw in parser.items("options.extras_require"):
            values.extend(_requirement_lines(raw))
    return _unique(values)


def _requirement_lines(value: str) -> list[_Pin]:
    lines = [
        line.strip()
        for line in value.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    return _requirement_list(lines)


def _requirement_list(value: object) -> list[_Pin]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    pins = []
    for item in value:
        match = _EXACT.fullmatch(item)
        if match is None:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        pins.append(_pin(match.group("name"), match.group("version")))
    return pins


def _exact_version(value: object) -> str:
    if not isinstance(value, str):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return value[2:] if value.startswith("==") else value


def _pin(
    raw_name: object,
    version: object,
    start_byte: int | None = None,
    end_byte: int | None = None,
) -> _Pin:
    if (start_byte is None) != (end_byte is None):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if (
        start_byte is not None
        and end_byte is not None
        and (
            type(start_byte) is not int
            or type(end_byte) is not int
            or start_byte < 0
            or end_byte <= start_byte
        )
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if (
        not isinstance(raw_name, str)
        or not isinstance(version, str)
        or _NAME.fullmatch(raw_name) is None
        or _VERSION.fullmatch(version) is None
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return _Pin(raw_name, _canonical_name(raw_name), version, start_byte, end_byte)


def _unique(values: Iterable[_Pin]) -> tuple[_Pin, ...]:
    pins = list(values)
    by_name: dict[str, _Pin] = {}
    for pin in pins:
        previous = by_name.get(pin.name)
        if previous is not None and previous.version != pin.version:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        by_name[pin.name] = pin
    return tuple(by_name[name] for name in sorted(by_name))


def _invalid() -> tuple[_Pin, ...]:
    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)


def _coordinates(
    repository_id: str,
    revision: str,
    manifest: DependencyManifestEntry,
    file: RepositoryFile,
    source: bytes,
    pins: tuple[_Pin, ...],
) -> tuple[DependencyCoordinate, ...]:
    output = []
    for pin in pins:
        if pin.start_byte is None or pin.end_byte is None:
            raw_name = pin.raw_name.encode("utf-8")
            raw_version = pin.version.encode("utf-8")
            start = source.find(raw_name)
            version_start = source.find(raw_version, max(0, start))
            if start < 0 or version_start < 0:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            end = version_start + len(raw_version)
        else:
            start, end = pin.start_byte, pin.end_byte
            if end > len(source):
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        output.append(
            DependencyCoordinate(
                repository_id=repository_id,
                revision=revision,
                manifest_path=file.path,
                manifest_sha256=file.content_sha256,
                ecosystem=DependencyEcosystem.PYTHON,
                name=pin.name,
                version=pin.version,
                location=SourceRange(
                    start_byte=start,
                    end_byte=end,
                    start_point=_point(source, start),
                    end_point=_point(source, end),
                ),
                purl=_dependency_purl(manifest.ecosystem, pin.name, pin.version) or "",
            )
        )
    return tuple(output)


def _point(source: bytes, offset: int) -> SourcePoint:
    prefix = source[:offset]
    row = prefix.count(b"\n")
    last = prefix.rfind(b"\n")
    return SourcePoint(row, offset if last < 0 else offset - last - 1)
