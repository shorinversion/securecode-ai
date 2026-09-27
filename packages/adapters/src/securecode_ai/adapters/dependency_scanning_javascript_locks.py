"""Strict, bounded parsers for supported JavaScript text lockfiles."""

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
from .dependency_scanning_yarn import parse_yarn_berry_lock

_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NPM_PART = re.compile(r"[a-z0-9](?:[a-z0-9._~-]{0,212}[a-z0-9])?\Z")
_NPM_SCOPE = re.compile(r"@[a-z0-9](?:[a-z0-9._~-]{0,212}[a-z0-9])?\Z")
_YARN_RANGE = re.compile(r"[A-Za-z0-9.*+|^~<>=!_:-]{1,512}\Z")
_PNPM_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z"
)


def parse_javascript_lock_manifest(
    *,
    repository_id: str,
    revision: str,
    manifest: DependencyManifestEntry,
    file: RepositoryFile,
    source: bytes,
    limits: DependencyScanLimits = DEFAULT_DEPENDENCY_SCAN_LIMITS,
) -> ParsedDependencyManifest:
    """Parse exact package/version entries from supported text lockfiles."""

    _validate_input(repository_id, revision, manifest, file, source, limits)
    if manifest.kind is DependencyManifestKind.YARN_LOCK:
        pins = _parse_yarn(source, limits)
    elif manifest.kind is DependencyManifestKind.PNPM_LOCK:
        pins = _parse_pnpm(source, limits)
    elif manifest.kind is DependencyManifestKind.BUN_LOCK:
        if file.path.rsplit("/", 1)[-1] != "bun.lock":
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        pins = _parse_bun(source, limits)
    else:
        raise DependencyScanError(DependencyScanErrorCode.REQUEST_INVALID)

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
    expected = {
        "yarn.lock": DependencyManifestKind.YARN_LOCK,
        "pnpm-lock.yaml": DependencyManifestKind.PNPM_LOCK,
        "bun.lock": DependencyManifestKind.BUN_LOCK,
        "bun.lockb": DependencyManifestKind.BUN_LOCK,
    }.get(file.path.rsplit("/", 1)[-1]) if type(file) is RepositoryFile else None
    if (
        not valid_repository_id
        or type(revision) is not str
        or _REVISION.fullmatch(revision) is None
        or type(manifest) is not DependencyManifestEntry
        or manifest.ecosystem is not DependencyEcosystem.JAVASCRIPT
        or manifest.kind not in {
            DependencyManifestKind.YARN_LOCK,
            DependencyManifestKind.PNPM_LOCK,
            DependencyManifestKind.BUN_LOCK,
        }
        or manifest.ignored_by_rule_id is not None
        or type(file) is not RepositoryFile
        or expected is not manifest.kind
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


def _parse_yarn(source: bytes, limits: DependencyScanLimits) -> set[tuple[str, str]]:
    text = _decode_text(source)
    if not any(row.strip() == "# yarn lockfile v1" for row in text.splitlines()):
        return parse_yarn_berry_lock(text, limits)
    return _parse_yarn_v1(text, limits)


def _parse_yarn_v1(text: str, limits: DependencyScanLimits) -> set[tuple[str, str]]:
    pins: set[tuple[str, str]] = set()
    selectors: set[str] = set()
    current: dict[str, object] | None = None
    current_entries: tuple[tuple[str, str], ...] = ()
    current_members: set[str] = set()
    seen_header = False
    dependency_block = False
    for row in text.splitlines():
        if not row.strip() or row.lstrip().startswith("#"):
            if row.strip() == "# yarn lockfile v1":
                seen_header = True
            continue
        if row.startswith(" ") or row.startswith("\t"):
            if current is None:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            if row.startswith("\t") or row.startswith("    "):
                if not dependency_block or len(row) < 5 or row[4] in " \t":
                    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
                member = row[4:]
                split = _split_yarn_member(member)
                key, value = split
                key = _yarn_scalar(key)
                value = _yarn_scalar(value)
                if not _valid_npm_name(key) or not value or key in current_members:
                    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
                current_members.add(key)
                continue
            if not row.startswith("  ") or row.startswith("   "):
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            field = row[2:]
            if field in {"dependencies:", "optionalDependencies:", "peerDependencies:"}:
                if field[:-1] in current or dependency_block:
                    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
                current[field[:-1]] = True
                dependency_block = True
                continue
            if dependency_block:
                dependency_block = False
            match = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)[ \t]+(.+)", field)
            if match is None:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            key, value = match.groups()
            if key not in {"version", "resolved", "integrity"} or key in current:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            scalar = _yarn_scalar(value)
            if not scalar:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            current[key] = scalar
            continue

        dependency_block = False
        if current is not None:
            version = current.get("version")
            if type(version) is not str or _PNPM_VERSION.fullmatch(version) is None:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
            pins.update((name, version) for _, name in current_entries)
            if len(pins) > limits.max_dependencies:
                raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
        if not seen_header or not row.endswith(":"):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        current_entries = _yarn_selectors(row[:-1])
        if any(selector in selectors for selector, _ in current_entries):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        selectors.update(selector for selector, _ in current_entries)
        current = {}
        current_members = set()
    if current is not None:
        version = current.get("version")
        if type(version) is not str or _PNPM_VERSION.fullmatch(version) is None:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        pins.update((name, version) for _, name in current_entries)
    if not seen_header or len(pins) > limits.max_dependencies:
        raise DependencyScanError(
            DependencyScanErrorCode.DEPENDENCY_LIMIT
            if len(pins) > limits.max_dependencies
            else DependencyScanErrorCode.MANIFEST_INVALID
        )
    return pins


def _yarn_selectors(raw: str) -> tuple[tuple[str, str], ...]:
    parts: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(raw):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            parts.append(raw[start:index].strip())
            start = index + 1
    if quoted or escaped:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    parts.append(raw[start:].strip())
    entries: dict[str, str] = {}
    for part in parts:
        selector = _yarn_scalar(part)
        split = selector.rfind("@")
        if split <= 0 or not _valid_npm_name(selector[:split]) or not _YARN_RANGE.fullmatch(selector[split + 1 :]):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        entries[selector] = selector[:split]
    if not entries or len(entries) > 100:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return tuple(sorted(entries.items()))


def _split_yarn_member(member: str) -> tuple[str, str]:
    match = re.fullmatch(r'("(?:[^"\\]|\\.)*"|[^ \t]+)[ \t]+(.+)', member)
    if match is None:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return match.group(1), match.group(2)


def _yarn_scalar(raw: str) -> str:
    if raw.startswith('"'):
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            value = None
        if type(value) is not str:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        return value
    if not raw or any(char in raw for char in "\r\n\t"):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return raw


def _parse_pnpm(source: bytes, limits: DependencyScanLimits) -> set[tuple[str, str]]:
    document = _parse_pnpm_yaml(_decode_text(source))
    version = document.get("lockfileVersion")
    if type(version) is not str or version not in {"6.0", "9.0"}:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    allowed = {
        "lockfileVersion", "settings", "importers", "packages", "snapshots",
        "dependencies", "devDependencies", "optionalDependencies", "specifiers",
        "time", "neverBuiltDependencies", "onlyBuiltDependencies", "overrides",
        "patchedDependencies", "packageExtensionsChecksum", "pnpmfileChecksum",
    }
    if set(document) - allowed or type(document.get("packages")) is not dict:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    package_records = document["packages"]
    pins: set[tuple[str, str]] = set()
    for package_id, record in package_records.items():
        name, package_version = _pnpm_package_id(package_id, version)
        if type(record) is not dict or type(record.get("resolution")) is not dict:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        if not record["resolution"]:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        pins.add((name, package_version))
        if len(pins) > limits.max_dependencies or len(package_records) > limits.max_dependencies:
            raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
    if version == "9.0":
        snapshots = document.get("snapshots")
        if type(snapshots) is not dict:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        for key, value in snapshots.items():
            _pnpm_package_id(key, version)
            if type(value) is not dict:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return pins


def _pnpm_package_id(value: str, lock_version: str) -> tuple[str, str]:
    if type(value) is not str or not value or len(value) > 1024:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    package_id = value
    if lock_version == "6.0":
        if not package_id.startswith("/"):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        package_id = package_id[1:]
    package_id = _strip_peer_suffix(package_id)
    separator = package_id.rfind("@")
    if separator <= 0:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    name, version = package_id[:separator], package_id[separator + 1 :]
    if not _valid_npm_name(name) or _PNPM_VERSION.fullmatch(version) is None:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return name, version


def _strip_peer_suffix(value: str) -> str:
    if "(" not in value:
        if ")" in value:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        return value
    opening = value.find("(")
    if not value.endswith(")") or opening == 0:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    depth = 0
    for char in value[opening:]:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if depth != 0:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return value[:opening]


def _parse_pnpm_yaml(text: str) -> dict[str, object]:
    root: dict[str, object] = {}
    stack: list[tuple[int, dict[str, object]]] = [(-2, root)]
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "\t" in line or line.endswith("\r"):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        indent = len(line) - len(line.lstrip(" "))
        if indent % 2:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        while stack and indent <= stack[-1][0]:
            stack.pop()
        if not stack or indent != stack[-1][0] + 2:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        key, raw_value = _yaml_mapping_line(line[indent:])
        mapping = stack[-1][1]
        if key in mapping:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        if raw_value == "":
            child: dict[str, object] = {}
            mapping[key] = child
            stack.append((indent, child))
        else:
            mapping[key] = _yaml_value(raw_value)
    return root


def _yaml_mapping_line(line: str) -> tuple[str, str]:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
        elif quote == '"' and char == "\\":
            escaped = True
        elif quote is not None and char == quote:
            quote = None
        elif quote is None and char in "\"'":
            quote = char
        elif quote is None and char == ":":
            raw_key = line[:index]
            raw_value = line[index + 1 :].strip()
            key = _yaml_string(raw_key)
            if not key or len(key) > 2048:
                break
            return key, _strip_yaml_comment(raw_value)
    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)


def _strip_yaml_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif quote == '"' and char == "\\":
            escaped = True
        elif quote is not None and char == quote:
            quote = None
        elif quote is None and char in "\"'":
            quote = char
        elif quote is None and char in "[{":
            depth += 1
        elif quote is None and char in "]}":
            depth -= 1
            if depth < 0:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        elif quote is None and depth == 0 and char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
    if quote is not None or depth != 0:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return value


def _yaml_string(raw: str) -> str:
    if raw.startswith("'"):
        if len(raw) < 2 or not raw.endswith("'"):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        inner = raw[1:-1]
        if "'" in inner.replace("''", ""):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        return inner.replace("''", "'")
    if raw.startswith('"'):
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            value = None
        if type(value) is not str:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        return value
    if not raw or not re.fullmatch(r"[A-Za-z0-9@/._:+~!?%=-]+", raw):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return raw


def _yaml_value(raw: str) -> object:
    if raw.startswith(("{", "[")):
        return _parse_flow(raw)
    if raw.startswith(("'", '"')):
        return _yaml_string(raw)
    if not raw or raw in {"&", "*", "!", "|", ">"} or any(ch in raw for ch in "\t\r\n"):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if raw[0] in "&*!|>" or ": " in raw or raw.endswith(":"):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return raw


def _parse_flow(raw: str) -> object:
    if raw[0] not in "[{" or raw[-1] != ("}" if raw[0] == "{" else "]"):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    inner = raw[1:-1].strip()
    if not inner:
        return {} if raw[0] == "{" else []
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    depth = 0
    for index, char in enumerate(inner):
        if escaped:
            escaped = False
        elif quote == '"' and char == "\\":
            escaped = True
        elif quote is not None and char == quote:
            quote = None
        elif quote is None and char in "\"'":
            quote = char
        elif quote is None and char in "[{":
            depth += 1
        elif quote is None and char in "]}":
            depth -= 1
            if depth < 0:
                raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        elif quote is None and depth == 0 and char == ",":
            parts.append(inner[start:index].strip())
            start = index + 1
    if quote is not None or depth != 0:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    parts.append(inner[start:].strip())
    if any(not part for part in parts):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if raw[0] == "[":
        return [_yaml_value(part) for part in parts]
    result: dict[str, object] = {}
    for part in parts:
        pair = _split_flow_pair(part)
        key, value = _yaml_string(pair[0].strip()), _yaml_value(pair[1].strip())
        if key in result:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        result[key] = value
    return result


def _split_flow_pair(value: str) -> tuple[str, str]:
    quote: str | None = None
    for index, char in enumerate(value):
        if quote is not None and char == quote:
            quote = None
        elif quote is None and char in "\"'":
            quote = char
        elif quote is None and char == ":":
            return value[:index], value[index + 1 :]
    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)


def _parse_bun(source: bytes, limits: DependencyScanLimits) -> set[tuple[str, str]]:
    text = _decode_text(source)
    normalized = _remove_json_trailing_commas(text)
    try:
        document = json.loads(
            normalized,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except DependencyScanError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID) from None
    if (
        type(document) is not dict
        or type(document.get("lockfileVersion")) is not int
        or document.get("lockfileVersion") != 1
        or type(document.get("workspaces")) is not dict
        or type(document.get("packages")) is not dict
        or set(document)
        - {"lockfileVersion", "configVersion", "workspaces", "packages", "patchedDependencies", "overrides", "trustedDependencies", "peer"}
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    packages = document["packages"]
    if len(packages) > limits.max_dependencies:
        raise DependencyScanError(DependencyScanErrorCode.DEPENDENCY_LIMIT)
    pins: set[tuple[str, str]] = set()
    for key, record in packages.items():
        if (
            type(key) is not str
            or not _valid_npm_name(key)
            or type(record) is not list
            or len(record) != 4
            or type(record[0]) is not str
            or type(record[1]) is not str
            or type(record[2]) is not dict
            or type(record[3]) is not str
        ):
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        name, version = _bun_package_id(record[0])
        if name != key:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        pins.add((name, version))
    return pins


def _bun_package_id(value: str) -> tuple[str, str]:
    if len(value) > 1024 or "#" in value or ":" in value or value.startswith(("git+", "file:")):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    separator = value.rfind("@")
    if separator <= 0:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    name, version = value[:separator], value[separator + 1 :]
    if not _valid_npm_name(name) or _PNPM_VERSION.fullmatch(version) is None:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return name, version


def _remove_json_trailing_commas(text: str) -> str:
    output: list[str] = []
    in_string = False
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
            output.append(char)
        elif char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead] in " \t\r\n":
                lookahead += 1
            if lookahead == len(text) or text[lookahead] not in "]}":
                output.append(char)
        else:
            output.append(char)
        index += 1
    if in_string or escaped:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return "".join(output)


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
        result[key] = value
    return result


def _reject_constant(_: str) -> object:
    raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)


def _valid_npm_name(value: str) -> bool:
    if not value.isascii() or len(value) > 512:
        return False
    if value.startswith("@"):
        parts = value.split("/")
        return len(parts) == 2 and _NPM_SCOPE.fullmatch(parts[0]) is not None and _NPM_PART.fullmatch(parts[1]) is not None
    return "/" not in value and _NPM_PART.fullmatch(value) is not None


def _decode_text(source: bytes) -> str:
    try:
        text = source.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID) from None
    if text.startswith("\ufeff") or any(
        ord(char) < 32 and char not in "\t\n\r" for char in text
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    if "\x7f" in text or any(
        char == "\r" and (index + 1 == len(text) or text[index + 1] != "\n")
        for index, char in enumerate(text)
    ):
        raise DependencyScanError(DependencyScanErrorCode.MANIFEST_INVALID)
    return text


def _point(source: bytes, offset: int) -> SourcePoint:
    prefix = source[:offset]
    row = prefix.count(b"\n")
    last = prefix.rfind(b"\n")
    return SourcePoint(row, offset if last < 0 else offset - last - 1)
