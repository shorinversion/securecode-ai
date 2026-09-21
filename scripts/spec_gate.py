"""Deterministic fail-closed specification, compatibility and drift gate."""

from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import hashlib
import http.client
import json
import math
import os
import re
import subprocess
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Final, NoReturn, cast
from urllib.parse import unquote, unquote_to_bytes, urlparse, urlsplit

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator, FormatChecker  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]
from rfc3987_syntax import (  # type: ignore[import-untyped]
    is_valid_syntax as rfc3987_is_valid_syntax,
)

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
POLICY_PATH: Final = REPOSITORY_ROOT / "scripts" / "spec_gate_policy.json"
BASELINE_PATH: Final = REPOSITORY_ROOT / "specs" / "baseline.yaml"
TRACEABILITY_PATH: Final = REPOSITORY_ROOT / "specs" / "traceability" / "requirements.yaml"
PLAN_PATH: Final = REPOSITORY_ROOT / "docs" / "PLAN.md"
PUBLIC_SCHEMA_ROOT: Final = (
    REPOSITORY_ROOT
    / "packages"
    / "contracts"
    / "src"
    / "securecode_ai"
    / "contracts"
    / "schemas"
    / "v0.2.0"
)
POLICY_SCHEMA_ROOT: Final = REPOSITORY_ROOT / "specs" / "contracts"
JSON_SCHEMA_DIALECT: Final = "https://json-schema.org/draft/2020-12/schema"
SEMANTIC_VALIDATOR: Final = "securecode_ai.contracts.schema_export:validate_public_document"
TASK_ID_PATTERN: Final = re.compile(r"P(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))?\Z")
GATE_ID_PATTERN: Final = re.compile(r"G(?:0|[1-9][0-9]*)\Z")
REQUIREMENT_ID_PATTERN: Final = re.compile(r"[A-Z][A-Z0-9]*-[A-Z]+-[0-9]{3}\Z")
SHA1_PATTERN: Final = re.compile(r"[0-9a-f]{40}\Z")
SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
DEFINITION_PATTERN: Final = re.compile(
    r"^- `(?P<identifier>[A-Z][A-Z0-9]*-[A-Z]+-[0-9]{3})`: ", re.MULTILINE
)
REFERENCE_PATTERN: Final = re.compile(r"\b[A-Z][A-Z0-9]*-[A-Z]+-[0-9]{3}\b")
TASK_ROW_PATTERN: Final = re.compile(
    r"^\| `(?P<id>P[0-9]+(?:\.[0-9]+)?)` \|.*\| `(?P<status>DONE|TODO|IN PROGRESS|BLOCKED)` \|\r?$",
    re.MULTILINE,
)
GATE_HEADING_PATTERN: Final = re.compile(r"^### (?P<id>G[0-9]+) — ", re.MULTILINE)
MARKDOWN_LINK_PATTERN: Final = re.compile(r"(?<!!)\[[^\]]+\]\((?P<target>[^)]+)\)")
FENCE_PATTERN: Final = re.compile(r"(?ms)^(```|~~~).*?^\1[^\n]*$")
HTML_COMMENT_PATTERN: Final = re.compile(r"(?s)<!--.*?-->")
CRITICAL_TOKEN_PATTERN: Final = re.compile(r"(?i)(?:TBD:|FIXME:)")
MAX_GIT_OUTPUT: Final = 4 * 1024 * 1024
GIT_TIMEOUT_SECONDS: Final = 30

type JSONScalar = None | bool | int | float | str
type JSONValue = JSONScalar | list[JSONValue] | dict[str, JSONValue]


class GateInputError(ValueError):
    """A fixed-code validation failure that never carries raw input."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class Limits:
    input_file_count: int
    bytes_per_json_yaml_or_task_packet: int
    bytes_per_markdown: int
    total_validated_input_bytes: int
    parsed_depth: int
    parsed_nodes_per_document: int
    collection_items_per_node: int
    scalar_utf8_bytes: int
    git_paths: int
    git_path_utf8_bytes: int
    diagnostics: int
    diagnostic_utf8_bytes_each: int
    final_receipt_utf8_bytes: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> Limits:
        fields = cls.__dataclass_fields__
        if set(value) != set(fields):
            raise GateInputError("POLICY_LIMIT_KEYS")
        parsed: dict[str, int] = {}
        for name in fields:
            item = value[name]
            if not isinstance(item, int) or isinstance(item, bool) or item <= 0:
                raise GateInputError("POLICY_LIMIT_VALUE")
            parsed[name] = item
        return cls(**parsed)


@dataclass(slots=True)
class Diagnostics:
    limits: Limits
    _codes: set[str] = field(default_factory=set)

    def add(self, code: str) -> None:
        safe = re.sub(r"[^A-Z0-9_.:/-]", "_", code.upper())
        encoded = safe.encode("utf-8")[: self.limits.diagnostic_utf8_bytes_each]
        self._codes.add(encoded.decode("utf-8", "ignore"))

    def extend(self, codes: Iterable[str]) -> None:
        for code in codes:
            self.add(code)

    def sorted(self) -> tuple[str, ...]:
        return tuple(sorted(self._codes)[: self.limits.diagnostics])


@dataclass(slots=True)
class ReadBudget:
    limits: Limits
    file_count: int = 0
    total_bytes: int = 0

    def account(self, size: int) -> None:
        self.file_count += 1
        self.total_bytes += size
        if self.file_count > self.limits.input_file_count:
            raise GateInputError("RESOURCE_FILE_COUNT")
        if self.total_bytes > self.limits.total_validated_input_bytes:
            raise GateInputError("RESOURCE_TOTAL_BYTES")


class _UniqueSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _UniqueSafeLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        if not isinstance(key_node, yaml.nodes.ScalarNode):
            raise GateInputError("YAML_NON_SCALAR_KEY")
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise GateInputError("YAML_UNHASHABLE_KEY") from error
        if duplicate:
            raise GateInputError("YAML_DUPLICATE_KEY")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _duplicate_json_object(pairs: list[tuple[str, JSONValue]]) -> dict[str, JSONValue]:
    result: dict[str, JSONValue] = {}
    for key, value in pairs:
        if key in result:
            raise GateInputError("JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise GateInputError("JSON_NONFINITE")


def _text_from_bytes(data: bytes, *, kind: str) -> str:
    if data.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        raise GateInputError(f"{kind}_BOM")
    if b"\x00" in data:
        raise GateInputError(f"{kind}_NUL")
    try:
        return data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise GateInputError(f"{kind}_UTF8") from error


def _validate_tree(value: object, limits: Limits) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > limits.parsed_nodes_per_document:
            raise GateInputError("RESOURCE_NODE_COUNT")
        if depth > limits.parsed_depth:
            raise GateInputError("RESOURCE_DEPTH")
        if isinstance(item, str) and len(item.encode("utf-8")) > limits.scalar_utf8_bytes:
            raise GateInputError("RESOURCE_SCALAR_BYTES")
        if isinstance(item, Mapping):
            if len(item) > limits.collection_items_per_node:
                raise GateInputError("RESOURCE_COLLECTION_ITEMS")
            stack.extend((key, depth + 1) for key in item)
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            if len(item) > limits.collection_items_per_node:
                raise GateInputError("RESOURCE_COLLECTION_ITEMS")
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise GateInputError("RESOURCE_NONFINITE")


def strict_json_loads(data: bytes, limits: Limits) -> JSONValue:
    if len(data) > limits.bytes_per_json_yaml_or_task_packet:
        raise GateInputError("JSON_BYTES")
    text = _text_from_bytes(data, kind="JSON")
    try:
        value: JSONValue = json.loads(
            text,
            object_pairs_hook=_duplicate_json_object,
            parse_constant=_reject_constant,
        )
    except GateInputError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise GateInputError("JSON_PARSE") from error
    _validate_tree(value, limits)
    return value


def strict_yaml_loads(data: bytes, limits: Limits) -> object:
    if len(data) > limits.bytes_per_json_yaml_or_task_packet:
        raise GateInputError("YAML_BYTES")
    text = _text_from_bytes(data, kind="YAML")
    try:
        for token in yaml.scan(text):
            if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)):
                raise GateInputError("YAML_ALIAS_ANCHOR")
            if isinstance(token, yaml.tokens.TagToken):
                raise GateInputError("YAML_EXPLICIT_TAG")
        documents = list(yaml.load_all(text, Loader=_UniqueSafeLoader))
    except GateInputError:
        raise
    except (yaml.YAMLError, RecursionError) as error:
        raise GateInputError("YAML_PARSE") from error
    if len(documents) != 1:
        raise GateInputError("YAML_DOCUMENT_COUNT")
    value = documents[0]
    _validate_tree(value, limits)
    return value


def markdown_visible_text(data: bytes, limits: Limits) -> str:
    if len(data) > limits.bytes_per_markdown:
        raise GateInputError("MARKDOWN_BYTES")
    text = _text_from_bytes(data, kind="MARKDOWN")
    return HTML_COMMENT_PATTERN.sub("", FENCE_PATTERN.sub("", text))


def markdown_definitions(data: bytes, limits: Limits) -> tuple[str, ...]:
    visible = markdown_visible_text(data, limits)
    return tuple(match.group("identifier") for match in DEFINITION_PATTERN.finditer(visible))


def length_prefixed_digest(documents: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for raw_path, content in sorted(documents.items()):
        path = normalize_repo_path(raw_path)
        path_bytes = path.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, "big", signed=False))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big", signed=False))
        digest.update(content)
    return digest.hexdigest()


def frozen_digest(documents: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path, content in sorted(documents.items()):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def normalize_repo_path(path: str) -> str:
    if not path or "\x00" in path or "\\" in path:
        raise GateInputError("PATH_ENCODING")
    if path.startswith(("-", "/")) or re.match(r"^[A-Za-z]:", path):
        raise GateInputError("PATH_ABSOLUTE_OPTION")
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise GateInputError("PATH_TRAVERSAL")
    normalized = pure.as_posix()
    if normalized != path:
        raise GateInputError("PATH_NONCANONICAL")
    return normalized


def _safe_path(root: Path, relative: str) -> Path:
    normalized = normalize_repo_path(relative)
    candidate = root.joinpath(*PurePosixPath(normalized).parts)
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=False)
    except OSError as error:
        raise GateInputError("PATH_RESOLVE") from error
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise GateInputError("PATH_OUTSIDE_ROOT")
    return candidate


def _read_file(
    root: Path, relative: str, budget: ReadBudget, *, maximum: int, require_regular: bool = True
) -> bytes:
    path = _safe_path(root, relative)
    try:
        if require_regular and (not path.is_file() or path.is_symlink()):
            raise GateInputError("INPUT_NOT_REGULAR")
        size = path.stat().st_size
        if size > maximum:
            raise GateInputError("INPUT_BYTES")
        data = path.read_bytes()
    except GateInputError:
        raise
    except OSError as error:
        raise GateInputError("INPUT_READ") from error
    if len(data) != size:
        raise GateInputError("INPUT_CHANGED")
    budget.account(len(data))
    return data


def _mapping(value: object, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise GateInputError(code)
    return {str(key): item for key, item in value.items()}


def _sequence(value: object, code: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise GateInputError(code)
    return value


def _strings(value: object, code: str) -> tuple[str, ...]:
    items = _sequence(value, code)
    if any(not isinstance(item, str) for item in items):
        raise GateInputError(code)
    return tuple(str(item) for item in items)


def _git_environment() -> dict[str, str]:
    allowed = (
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "NO_COLOR",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "WINDIR",
    )
    environment = {name: value for name in allowed if (value := os.environ.get(name)) is not None}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _git_executable(root: Path) -> str:

    repository = root.resolve(strict=True)
    executable_name = "git.exe" if os.name == "nt" else "git"
    for raw_directory in os.environ.get("PATH", "").split(os.pathsep):
        directory = Path(raw_directory)
        if not raw_directory or not directory.is_absolute():
            continue
        try:
            candidate = (directory / executable_name).resolve(strict=True)
        except OSError:
            continue
        if (
            not candidate.is_file()
            or not os.access(candidate, os.X_OK)
            or candidate == repository
            or repository in candidate.parents
        ):
            continue
        return str(candidate)
    raise GateInputError("GIT_EXECUTABLE")


def git_bytes(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            (
                _git_executable(root),
                "--no-optional-locks",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.autocrlf=input",
                "-c",
                "core.eol=lf",
                "-c",
                "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol",
                "-c",
                "core.hooksPath=",
                *arguments,
            ),
            cwd=root,
            env=_git_environment(),
            check=False,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise GateInputError("GIT_EXECUTION") from error
    if completed.returncode != 0:
        raise GateInputError("GIT_NONZERO")
    if len(completed.stdout) > MAX_GIT_OUTPUT:
        raise GateInputError("GIT_OUTPUT_BYTES")
    return completed.stdout


def git_text(root: Path, *arguments: str) -> str:
    try:
        return git_bytes(root, *arguments).decode("ascii", "strict")
    except UnicodeDecodeError as error:
        raise GateInputError("GIT_TEXT_ENCODING") from error


def _git_blob(root: Path, revision: str, relative: str) -> bytes:
    normalize_repo_path(relative)
    return git_bytes(root, "cat-file", "blob", f"{revision}:{relative}")


def _walk(value: object) -> Iterable[object]:
    stack = [value]
    while stack:
        item = stack.pop()
        yield item
        if isinstance(item, Mapping):
            stack.extend(item.values())
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            stack.extend(item)


def _resolve_fragment(document: object, reference: str) -> bool:
    if reference == "#":
        return True
    if not reference.startswith("#/"):
        return False
    encoded_pointer = reference[1:]
    if re.search(r"%(?![0-9A-Fa-f]{2})", encoded_pointer):
        return False
    try:
        pointer = unquote_to_bytes(encoded_pointer).decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    if not pointer.startswith("/"):
        return False
    current = document
    for raw_part in pointer[1:].split("/"):
        if re.search(r"~(?:[^01]|$)", raw_part):
            return False
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            if not re.fullmatch(r"0|[1-9][0-9]*", part):
                return False
            index = int(part)
            if index >= len(current):
                return False
            current = current[index]
        else:
            return False
    return True


def schema_document_errors(
    document: object, *, known_formats: frozenset[str], public: bool = False
) -> tuple[str, ...]:
    errors: set[str] = set()
    if not isinstance(document, Mapping):
        return ("SCHEMA_ROOT",)
    if document.get("$schema") != JSON_SCHEMA_DIALECT:
        errors.add("SCHEMA_DIALECT")
    try:
        Draft202012Validator.check_schema(document)
    except SchemaError:
        errors.add("SCHEMA_META")
    for item in _walk(document):
        if not isinstance(item, Mapping):
            continue
        reference = item.get("$ref")
        if reference is not None:
            if not isinstance(reference, str) or not reference.startswith("#"):
                errors.add("SCHEMA_EXTERNAL_REF")
            elif not _resolve_fragment(document, reference):
                errors.add("SCHEMA_UNRESOLVED_REF")
        for dynamic_key in ("$dynamicRef", "$recursiveRef"):
            if dynamic_key in item:
                errors.add("SCHEMA_DYNAMIC_REF")
        format_name = item.get("format")
        if format_name is not None and (
            not isinstance(format_name, str) or format_name not in known_formats
        ):
            errors.add("SCHEMA_UNKNOWN_FORMAT")
    if public and document.get("x-securecode-semantic-validator") != SEMANTIC_VALIDATOR:
        errors.add("SCHEMA_SEMANTIC_VALIDATOR")
    return tuple(sorted(errors))


def _schema_validator(
    document: Mapping[str, object], formats: frozenset[str]
) -> Draft202012Validator:
    checker = FormatChecker(formats=(name for name in formats if name != "uri"))
    if "uri" in formats:
        checker.checkers["uri"] = (_is_uri, ())
    return Draft202012Validator(document, format_checker=checker)


def _is_uri(instance: object) -> bool:
    if not isinstance(instance, str):
        return True
    if any(ord(character) > 127 or character.isspace() for character in instance):
        return False
    try:
        parsed = urlsplit(instance)
    except ValueError:
        return False
    return bool(parsed.scheme) and rfc3987_is_valid_syntax("iri", instance)


def compatibility_errors(old: object, new: object) -> tuple[str, ...]:

    errors: set[str] = set()
    if not isinstance(old, Mapping) or not isinstance(new, Mapping):
        return ("COMPAT_ROOT",)
    old_id = old.get("$id")
    new_id = new.get("$id")
    if old_id != new_id:
        errors.add("COMPAT_ID")
    old_type = old.get("type")
    new_type = new.get("type")
    if old_type != new_type:
        errors.add("COMPAT_TYPE")
    old_required = (
        set(old.get("required", [])) if isinstance(old.get("required", []), list) else set()
    )
    new_required = (
        set(new.get("required", [])) if isinstance(new.get("required", []), list) else set()
    )
    if not new_required.issubset(old_required):
        errors.add("COMPAT_REQUIRED")
    old_properties = old.get("properties", {})
    new_properties = new.get("properties", {})
    if isinstance(old_properties, Mapping) and isinstance(new_properties, Mapping):
        if not set(old_properties).issubset(new_properties):
            errors.add("COMPAT_PROPERTY_REMOVED")
        for name in set(old_properties) & set(new_properties):
            left = old_properties[name]
            right = new_properties[name]
            if left != right:
                errors.add(f"COMPAT_PROPERTY_CHANGED:{name}")
    elif old_properties != new_properties:
        errors.add("COMPAT_PROPERTIES")
    for keyword in ("enum", "minimum", "maximum", "minLength", "maxLength", "pattern"):
        if old.get(keyword) != new.get(keyword):
            errors.add(f"COMPAT_KEYWORD:{keyword}")
    supported = {
        "$comment",
        "$defs",
        "$id",
        "$schema",
        "additionalProperties",
        "description",
        "enum",
        "format",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "pattern",
        "properties",
        "required",
        "title",
        "type",
        "x-securecode-semantic-rules",
        "x-securecode-semantic-validator",
    }
    if (set(old) | set(new)) - supported and old != new:
        errors.add("COMPAT_AMBIGUOUS")
    return tuple(sorted(errors))


def _path_matches(path: str, patterns: Sequence[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def parse_name_status(raw: bytes, *, maximum_paths: int = 4096) -> tuple[tuple[str, ...], ...]:
    parts = raw.split(b"\0")
    records: list[tuple[str, ...]] = []
    index = 0
    while index < len(parts) and parts[index]:
        try:
            status = parts[index].decode("ascii", "strict")
        except UnicodeDecodeError as error:
            raise GateInputError("GIT_STATUS_ENCODING") from error
        index += 1
        if not re.fullmatch(r"[AMD]|[RC][0-9]{1,3}", status):
            raise GateInputError("GIT_STATUS_KIND")
        path_count = 2 if status.startswith(("R", "C")) else 1
        paths: list[str] = []
        for _ in range(path_count):
            if index >= len(parts) or not parts[index]:
                raise GateInputError("GIT_STATUS_FIELDS")
            try:
                path = parts[index].decode("utf-8", "strict")
            except UnicodeDecodeError as error:
                raise GateInputError("GIT_PATH_ENCODING") from error
            paths.append(normalize_repo_path(path))
            index += 1
        records.append((status, *paths))
        if sum(len(record) - 1 for record in records) > maximum_paths:
            raise GateInputError("GIT_PATH_COUNT")
    if any(part for part in parts[index:]):
        raise GateInputError("GIT_STATUS_TRAILING")
    return tuple(records)


def changed_paths(records: Sequence[Sequence[str]]) -> tuple[str, ...]:
    return tuple(sorted({path for record in records for path in record[1:]}))


def _strict_keys(mapping: Mapping[str, object], expected: set[str], code: str) -> None:
    if set(mapping) != expected:
        raise GateInputError(code)


def canonical_review_subject(
    documents: Mapping[str, bytes], *, packet_path: str, stored_hash: str
) -> str:

    if not SHA256_PATTERN.fullmatch(stored_hash):
        raise GateInputError("CHANGE_PACKET_REVIEW_HASH")
    packet = documents.get(packet_path)
    if packet is None:
        raise GateInputError("CHANGE_PACKET_REVIEW_DOCUMENTS")
    needle = stored_hash.encode("ascii")
    if packet.count(needle) != 1:
        raise GateInputError("CHANGE_PACKET_REVIEW_SELF_HASH")
    canonical = dict(documents)
    canonical[packet_path] = packet.replace(needle, b"0" * 64, 1)
    return length_prefixed_digest(canonical)


def task_statuses(data: bytes) -> dict[str, str]:
    text = _text_from_bytes(data, kind="MARKDOWN")
    statuses: dict[str, str] = {}
    for match in TASK_ROW_PATTERN.finditer(text):
        task_id = match.group("id")
        if task_id in statuses:
            raise GateInputError("PLAN_DUPLICATE_TASK")
        statuses[task_id] = match.group("status")
    return statuses


def repository_identity(value: str) -> tuple[str, str] | None:

    if value.count("/") != 1:
        return None
    owner, repository = value.split("/", 1)
    safe = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
    if (
        not safe.fullmatch(owner)
        or not safe.fullmatch(repository)
        or owner in {".", ".."}
        or repository in {".", ".."}
        or repository.lower().endswith(".git")
    ):
        return None
    return owner.lower(), repository.lower()


def github_evidence_identity(source: str, evidence_type: str) -> tuple[str, str] | None:

    try:
        parsed = urlsplit(source)
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
        or port is not None
        or "%" in parsed.path
    ):
        return None
    host = (parsed.hostname or "").lower()
    segments = [unquote(part) for part in parsed.path.split("/") if part]
    if evidence_type == "github_ruleset_required_check":
        if (
            host != "api.github.com"
            or len(segments) != 5
            or segments[0] != "repos"
            or segments[3] != "rulesets"
            or not re.fullmatch(r"[1-9][0-9]*", segments[4])
        ):
            return None
        owner, repository = segments[1:3]
    elif evidence_type == "github_failing_pr_merge_block":
        if host == "github.com" and len(segments) == 5:
            owner, repository = segments[:2]
            suffix = segments[2:]
        else:
            return None
        if suffix[:2] != ["actions", "runs"] or not re.fullmatch(r"[1-9][0-9]*", suffix[2]):
            return None
    else:
        return None
    safe = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
    if (
        not safe.fullmatch(owner)
        or not safe.fullmatch(repository)
        or owner in {".", ".."}
        or repository in {".", ".."}
        or repository.lower().endswith(".git")
    ):
        return None
    return owner.lower(), repository.lower()


def validate_completion_attestation(
    value: object, *, policy: Mapping[str, object], actual_paths: tuple[str, ...]
) -> tuple[str, ...]:
    errors: set[str] = set()
    try:
        data = _mapping(value, "ATTESTATION_ROOT")
        expected_keys = {
            "schema_version",
            "change_type",
            "task_id",
            "starting_commit_sha",
            "packet_sha256",
            "implementation_commit_sha",
            "evidence_refs",
            "allowed_paths",
            "budgets",
        }
        _strict_keys(data, expected_keys, "ATTESTATION_KEYS")
        task_id = data.get("task_id")
        if (
            data.get("schema_version") != "1.0.0"
            or data.get("change_type") != "completion_attestation"
        ):
            errors.add("ATTESTATION_IDENTITY")
        if not isinstance(task_id, str) or not TASK_ID_PATTERN.fullmatch(task_id):
            errors.add("ATTESTATION_TASK")
        for name in ("starting_commit_sha", "implementation_commit_sha"):
            item = data.get(name)
            if not isinstance(item, str) or not SHA1_PATTERN.fullmatch(item):
                errors.add("ATTESTATION_GIT_OID")
        packet_hash = data.get("packet_sha256")
        if not isinstance(packet_hash, str) or not SHA256_PATTERN.fullmatch(packet_hash):
            errors.add("ATTESTATION_PACKET_HASH")
        allowed_paths = _strings(data.get("allowed_paths"), "ATTESTATION_PATHS")
        if tuple(sorted(allowed_paths)) != actual_paths or len(set(allowed_paths)) != len(
            allowed_paths
        ):
            errors.add("ATTESTATION_PATH_SET")
        budgets = _mapping(data.get("budgets"), "ATTESTATION_BUDGETS")
        if budgets != {"max_changed_files": 5, "max_diff_lines": 800}:
            errors.add("ATTESTATION_BUDGETS")
        catalog = _mapping(policy.get("completion_evidence"), "POLICY_COMPLETION_EVIDENCE")
        required = _strings(catalog.get(str(task_id)), "POLICY_COMPLETION_TASK")
        refs = _sequence(data.get("evidence_refs"), "ATTESTATION_EVIDENCE")
        observed: list[str] = []
        external_types = {"protected_pr_gate", "post_merge_gate"}
        for raw_ref in refs:
            ref = _mapping(raw_ref, "ATTESTATION_EVIDENCE_REF")
            ref_type = ref.get("type")
            expected_ref_keys = {"type", "source", "content_sha256"}
            if ref_type in external_types:
                expected_ref_keys.update(
                    {
                        "repository",
                        "run_id",
                        "run_attempt",
                        "event",
                        "conclusion",
                        "head_branch",
                        "head_sha",
                        "workflow_path",
                    }
                )
                if ref_type == "protected_pr_gate":
                    expected_ref_keys.update(
                        {
                            "pull_request_number",
                            "merge_commit_sha",
                            "required_check",
                            "gate_completed_at",
                            "merged_at",
                        }
                    )
            _strict_keys(ref, expected_ref_keys, "ATTESTATION_EVIDENCE_KEYS")
            source = ref.get("source")
            content_hash = ref.get("content_sha256")
            if not isinstance(ref_type, str) or len(ref_type.encode()) > 64:
                errors.add("ATTESTATION_EVIDENCE_TYPE")
                continue
            observed.append(ref_type)
            if not isinstance(source, str) or len(source.encode()) > 1024:
                errors.add("ATTESTATION_EVIDENCE_SOURCE")
            if not isinstance(content_hash, str) or not SHA256_PATTERN.fullmatch(content_hash):
                errors.add("ATTESTATION_EVIDENCE_HASH")
            if ref_type in external_types:
                repository_value = ref.get("repository")
                run_id_value = ref.get("run_id")
                run_attempt_value = ref.get("run_attempt")
                if (
                    not isinstance(repository_value, str)
                    or repository_identity(repository_value) is None
                ):
                    errors.add("ATTESTATION_EXTERNAL_REPOSITORY")
                if not isinstance(run_id_value, int) or run_id_value <= 0:
                    errors.add("ATTESTATION_EXTERNAL_RUN")
                if not isinstance(run_attempt_value, int) or run_attempt_value <= 0:
                    errors.add("ATTESTATION_EXTERNAL_RUN")
                if ref.get("event") not in {"pull_request", "push"}:
                    errors.add("ATTESTATION_EXTERNAL_EVENT")
                if ref.get("conclusion") != "success":
                    errors.add("ATTESTATION_EXTERNAL_CONCLUSION")
                head_branch_value = ref.get("head_branch")
                if (
                    not isinstance(head_branch_value, str)
                    or not 1 <= len(head_branch_value.encode("utf-8")) <= 255
                    or any(character.isspace() for character in head_branch_value)
                ):
                    errors.add("ATTESTATION_EXTERNAL_BRANCH")
                if not isinstance(ref.get("head_sha"), str) or not SHA1_PATTERN.fullmatch(
                    str(ref.get("head_sha"))
                ):
                    errors.add("ATTESTATION_EXTERNAL_COMMIT")
                if ref.get("workflow_path") != ".github/workflows/ci.yml":
                    errors.add("ATTESTATION_EXTERNAL_WORKFLOW")
                if ref_type == "protected_pr_gate":
                    for field_name in ("pull_request_number",):
                        field_value = ref.get(field_name)
                        if not isinstance(field_value, int) or field_value <= 0:
                            errors.add("ATTESTATION_EXTERNAL_MERGE")
                    if not isinstance(
                        ref.get("merge_commit_sha"), str
                    ) or not SHA1_PATTERN.fullmatch(str(ref.get("merge_commit_sha"))):
                        errors.add("ATTESTATION_EXTERNAL_MERGE")
                    if ref.get("required_check") != "gate":
                        errors.add("ATTESTATION_EXTERNAL_MERGE")
                    for field_name in ("gate_completed_at", "merged_at"):
                        field_value = ref.get(field_name)
                        if not isinstance(field_value, str) or len(field_value.encode()) > 64:
                            errors.add("ATTESTATION_EXTERNAL_MERGE")
        if tuple(observed) != required or len(set(observed)) != len(observed):
            errors.add("ATTESTATION_EVIDENCE_CATALOG")
    except GateInputError as error:
        errors.add(error.code)
    return tuple(sorted(errors))


def completion_run_evidence_tasks(policy: Mapping[str, object]) -> frozenset[str]:

    catalog = _mapping(policy.get("completion_evidence"), "POLICY_COMPLETION_EVIDENCE")
    result: set[str] = set()
    external = {"protected_pr_gate", "post_merge_gate"}
    for task_id, raw_required in catalog.items():
        required = _strings(raw_required, f"POLICY_COMPLETION_TASK.{task_id}")
        observed = external.intersection(required)
        if observed and observed != external:
            raise GateInputError("POLICY_GITHUB_RUN_EVIDENCE_PAIR")
        if observed:
            result.add(task_id)
    return frozenset(result)


def _promotion_manifest_errors(
    value: object,
    *,
    gate_id: str,
    policy_paths: tuple[str, ...],
    base_documents: Mapping[str, bytes],
) -> tuple[tuple[str, bytes], ...]:
    manifest = _mapping(value, "PROMOTION_MANIFEST_ROOT")
    _strict_keys(
        manifest,
        {
            "schema_version",
            "gate_id",
            "evidence_bundle_sha256",
            "promotion_subject_sha256",
            "files",
        },
        "PROMOTION_MANIFEST_KEYS",
    )
    if manifest.get("schema_version") != "1.0.0" or manifest.get("gate_id") != gate_id:
        raise GateInputError("PROMOTION_MANIFEST_IDENTITY")
    evidence_hash = manifest.get("evidence_bundle_sha256")
    subject_hash = manifest.get("promotion_subject_sha256")
    if not isinstance(evidence_hash, str) or not SHA256_PATTERN.fullmatch(evidence_hash):
        raise GateInputError("PROMOTION_MANIFEST_EVIDENCE_HASH")
    if not isinstance(subject_hash, str) or not SHA256_PATTERN.fullmatch(subject_hash):
        raise GateInputError("PROMOTION_MANIFEST_SUBJECT_HASH")
    files = _sequence(manifest.get("files"), "PROMOTION_MANIFEST_FILES")
    decoded: dict[str, bytes] = {}
    total_decoded = 0
    for raw_file in files:
        entry = _mapping(raw_file, "PROMOTION_MANIFEST_FILE")
        _strict_keys(
            entry,
            {"path", "base_sha256", "final_sha256", "final_base64"},
            "PROMOTION_MANIFEST_FILE_KEYS",
        )
        path = entry.get("path")
        if not isinstance(path, str):
            raise GateInputError("PROMOTION_MANIFEST_PATH")
        path = normalize_repo_path(path)
        if path in decoded:
            raise GateInputError("PROMOTION_MANIFEST_DUPLICATE_PATH")
        base_hash = entry.get("base_sha256")
        final_hash = entry.get("final_sha256")
        encoded = entry.get("final_base64")
        if not isinstance(base_hash, str) or not SHA256_PATTERN.fullmatch(base_hash):
            raise GateInputError("PROMOTION_MANIFEST_BASE_HASH")
        if not isinstance(final_hash, str) or not SHA256_PATTERN.fullmatch(final_hash):
            raise GateInputError("PROMOTION_MANIFEST_FINAL_HASH")
        if not isinstance(encoded, str) or len(encoded) > 4 * 1024 * 1024:
            raise GateInputError("PROMOTION_MANIFEST_BASE64")
        try:
            final_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise GateInputError("PROMOTION_MANIFEST_BASE64") from error
        total_decoded += len(final_bytes)
        if total_decoded > 16 * 1024 * 1024:
            raise GateInputError("PROMOTION_MANIFEST_TOTAL_BYTES")
        if hashlib.sha256(final_bytes).hexdigest() != final_hash:
            raise GateInputError("PROMOTION_MANIFEST_FINAL_HASH")
        current = base_documents.get(path)
        if current is None or hashlib.sha256(current).hexdigest() != base_hash:
            raise GateInputError("PROMOTION_MANIFEST_BASE_DRIFT")
        decoded[path] = final_bytes
    if tuple(sorted(decoded)) != tuple(sorted(policy_paths)):
        raise GateInputError("PROMOTION_MANIFEST_PATH_SET")
    if length_prefixed_digest(decoded) != subject_hash:
        raise GateInputError("PROMOTION_MANIFEST_SUBJECT_HASH")
    return tuple(sorted(decoded.items()))


def validate_task_packet(
    value: object,
    *,
    packet_path: str,
    base_sha: str,
    changed: tuple[str, ...],
    diff_lines: int,
    policy: Mapping[str, object],
) -> tuple[str, ...]:
    errors: set[str] = set()
    try:
        packet = _mapping(value, "PACKET_ROOT")
        task = _mapping(packet.get("task"), "PACKET_TASK")
        execution = _mapping(packet.get("execution"), "PACKET_EXECUTION")
        scope = _mapping(packet.get("scope"), "PACKET_SCOPE")
        if packet.get("schema_version") != "0.1-draft" or task.get("type") != "implementation":
            errors.add("PACKET_IDENTITY")
        task_id = task.get("id")
        if not isinstance(task_id, str) or packet_path != f"work/task-packets/{task_id}.yaml":
            errors.add("PACKET_FILENAME")
        authority = _mapping(policy.get("baseline"), "POLICY_BASELINE")
        for name in ("baseline_id", "baseline_content_sha256", "baseline_commit_sha"):
            if task.get(name) != authority.get(name):
                errors.add(f"PACKET_{name.upper()}")
        if task.get("starting_commit_sha") != base_sha:
            errors.add("PACKET_BASE")
        lease = _strings(execution.get("exclusive_path_lease"), "PACKET_LEASE")
        allowed = _strings(scope.get("allowed_paths"), "PACKET_ALLOWED")
        forbidden = _strings(scope.get("forbidden_paths"), "PACKET_FORBIDDEN")
        if lease != allowed or len(set(allowed)) != len(allowed) or packet_path not in allowed:
            errors.add("PACKET_CLOSED_PATHS")
        if any(_path_matches(path, forbidden) for path in allowed):
            errors.add("PACKET_ALLOW_FORBID_OVERLAP")
        protected = _strings(policy.get("self_protected_paths"), "POLICY_PROTECTED")
        bootstrap = task_id == "P1.13" and base_sha == authority.get("bootstrap_commit_sha")
        for path in changed:
            if path not in allowed or _path_matches(path, forbidden):
                errors.add("PACKET_SCOPE")
            if _path_matches(path, protected) and not bootstrap:
                errors.add("PACKET_SELF_PROTECTED")
        maximum_files = scope.get("max_changed_files")
        maximum_lines = scope.get("max_diff_lines")
        if not isinstance(maximum_files, int) or len(changed) > maximum_files:
            errors.add("PACKET_FILE_BUDGET")
        if not isinstance(maximum_lines, int) or diff_lines > maximum_lines:
            errors.add("PACKET_LINE_BUDGET")
    except GateInputError as error:
        errors.add(error.code)
    return tuple(sorted(errors))


@dataclass(slots=True)
class SpecGate:
    root: Path = REPOSITORY_ROOT
    policy_path: Path = POLICY_PATH
    github_repository: tuple[str, str] | None = None
    github_token: str | None = None
    policy: Mapping[str, object] = field(init=False)
    limits: Limits = field(init=False)
    diagnostics: Diagnostics = field(init=False)
    budget: ReadBudget = field(init=False)
    github_run_cache: dict[tuple[str, str, int, int], Mapping[str, object]] = field(
        init=False, default_factory=dict
    )
    github_api_cache: dict[str, object] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        raw = self.policy_path.read_bytes()
        bootstrap_limits = Limits(
            input_file_count=1024,
            bytes_per_json_yaml_or_task_packet=1048576,
            bytes_per_markdown=2097152,
            total_validated_input_bytes=16777216,
            parsed_depth=64,
            parsed_nodes_per_document=100000,
            collection_items_per_node=100000,
            scalar_utf8_bytes=262144,
            git_paths=4096,
            git_path_utf8_bytes=4096,
            diagnostics=256,
            diagnostic_utf8_bytes_each=512,
            final_receipt_utf8_bytes=131072,
        )
        loaded = strict_json_loads(raw, bootstrap_limits)
        self.policy = _mapping(loaded, "POLICY_ROOT")
        if self.policy.get("schema_version") != "1.0.0":
            raise GateInputError("POLICY_VERSION")
        self.limits = Limits.from_mapping(
            _mapping(self.policy.get("resource_limits"), "POLICY_LIMITS")
        )
        self.diagnostics = Diagnostics(self.limits)
        self.budget = ReadBudget(self.limits)

    def _read(self, relative: str) -> bytes:
        maximum = (
            self.limits.bytes_per_markdown
            if relative.lower().endswith(".md")
            else self.limits.bytes_per_json_yaml_or_task_packet
        )
        return _read_file(self.root, relative, self.budget, maximum=maximum)

    def _load(self, relative: str) -> object:
        data = self._read(relative)
        suffix = PurePosixPath(relative).suffix.lower()
        if suffix == ".json":
            return strict_json_loads(data, self.limits)
        if suffix in {".yaml", ".yml", ".lock"}:
            return strict_yaml_loads(data, self.limits)
        if suffix == ".md":
            return markdown_visible_text(data, self.limits)
        raise GateInputError("INPUT_SUFFIX")

    def _baseline(self) -> tuple[Mapping[str, object], tuple[str, ...]]:
        baseline = _mapping(self._load("specs/baseline.yaml"), "BASELINE_ROOT")
        authority = _mapping(self.policy.get("baseline"), "POLICY_BASELINE")
        if baseline.get("baseline_id") != authority.get("baseline_id"):
            self.diagnostics.add("BASELINE_ID")
        if baseline.get("schema_version") != "0.2.0" or baseline.get("lifecycle") != "frozen":
            self.diagnostics.add("BASELINE_LIFECYCLE")
        freeze = _mapping(baseline.get("freeze"), "BASELINE_FREEZE")
        if freeze.get("commit_sha") != authority.get("baseline_commit_sha"):
            self.diagnostics.add("BASELINE_COMMIT")
        if freeze.get("content_sha256") != authority.get("baseline_content_sha256"):
            self.diagnostics.add("BASELINE_DECLARED_DIGEST")
        paths = _strings(baseline.get("normative_documents"), "BASELINE_DOCUMENTS")
        if len(set(paths)) != len(paths):
            self.diagnostics.add("BASELINE_DUPLICATE_PATH")
        return baseline, paths

    def _validate_normative(self, paths: tuple[str, ...]) -> set[str]:
        documents: dict[str, bytes] = {}
        committed: dict[str, bytes] = {}
        definitions: dict[str, str] = {}
        references: set[str] = set()
        commit = str(
            _mapping(self.policy.get("baseline"), "POLICY_BASELINE")["baseline_commit_sha"]
        )
        for relative in paths:
            path = f"specs/{normalize_repo_path(relative)}"
            try:
                data = self._read(path)
                documents[relative] = data
                committed[relative] = _git_blob(self.root, commit, path)
                if path.endswith(".json"):
                    parsed_json = strict_json_loads(data, self.limits)
                    for item in _walk(parsed_json):
                        if isinstance(item, str):
                            references.update(REFERENCE_PATTERN.findall(item))
                elif path.endswith((".yaml", ".yml", ".lock")):
                    parsed_yaml = strict_yaml_loads(data, self.limits)
                    for item in _walk(parsed_yaml):
                        if isinstance(item, str):
                            references.update(REFERENCE_PATTERN.findall(item))
                elif path.endswith(".md"):
                    visible = markdown_visible_text(data, self.limits)
                    references.update(REFERENCE_PATTERN.findall(visible))
                    if CRITICAL_TOKEN_PATTERN.search(visible):
                        self.diagnostics.add(f"NORMATIVE_CRITICAL_TOKEN:{relative}")
                    for identifier in markdown_definitions(data, self.limits):
                        if identifier in definitions:
                            self.diagnostics.add(f"NORMATIVE_DUPLICATE_ID:{identifier}")
                        definitions[identifier] = relative
                    self._validate_links(path, visible)
                else:
                    self.diagnostics.add(f"NORMATIVE_SUFFIX:{relative}")
            except GateInputError as error:
                self.diagnostics.add(f"NORMATIVE_{error.code}:{relative}")
        for identifier in sorted(
            item for item in references - set(definitions) if item.startswith("SC-")
        ):
            self.diagnostics.add(f"NORMATIVE_UNDEFINED_ID:{identifier}")
        expected = str(
            _mapping(self.policy.get("baseline"), "POLICY_BASELINE")["baseline_content_sha256"]
        )
        if frozen_digest(documents) != expected:
            self.diagnostics.add("BASELINE_WORKTREE_DIGEST")
        if frozen_digest(committed) != expected:
            self.diagnostics.add("BASELINE_COMMITTED_DIGEST")
        return set(definitions)

    def _validate_links(self, source: str, visible: str) -> None:
        source_directory = PurePosixPath(source).parent
        for match in MARKDOWN_LINK_PATTERN.finditer(visible):
            target = match.group("target").strip().split(maxsplit=1)[0].strip("<>")
            parsed = urlparse(target)
            if not target or parsed.scheme or target.startswith(("#", "mailto:")):
                continue
            path_part = unquote(target.split("#", 1)[0])
            if not path_part:
                continue
            try:
                if PurePosixPath(path_part).is_absolute() or re.match(r"^[A-Za-z]:", path_part):
                    raise GateInputError("MARKDOWN_LINK_ABSOLUTE")
                root = self.root.resolve(strict=True)
                path = (root / Path(source_directory.as_posix()) / Path(path_part)).resolve(
                    strict=False
                )
                if path != root and root not in path.parents:
                    raise GateInputError("MARKDOWN_LINK_OUTSIDE")
            except (GateInputError, OSError):
                self.diagnostics.add(f"MARKDOWN_LINK_PATH:{source}")
                continue
            if not path.exists() or path.is_symlink():
                self.diagnostics.add(f"MARKDOWN_LINK_MISSING:{source}")

    def _plan_catalog(self) -> tuple[dict[str, str], set[str]]:
        data = self._read("docs/PLAN.md")
        text = _text_from_bytes(data, kind="MARKDOWN")
        tasks: dict[str, str] = {}
        for match in TASK_ROW_PATTERN.finditer(text):
            task_id = match.group("id")
            if task_id in tasks:
                self.diagnostics.add(f"PLAN_DUPLICATE_TASK:{task_id}")
            tasks[task_id] = match.group("status")
        gates = [match.group("id") for match in GATE_HEADING_PATTERN.finditer(text)]
        if len(gates) != len(set(gates)):
            self.diagnostics.add("PLAN_DUPLICATE_GATE")
        return tasks, set(gates)

    def _catalogs(self, tasks: Mapping[str, str], gates: set[str]) -> tuple[set[str], set[str]]:
        tests_raw = _mapping(self.policy.get("test_catalog"), "POLICY_TEST_CATALOG")
        test_ids = set(tests_raw)
        allowed_commands = set(_strings(self.policy.get("executable_commands"), "POLICY_COMMANDS"))
        for test_id, raw_entry in tests_raw.items():
            entry = _mapping(raw_entry, "POLICY_TEST_ENTRY")
            owners = _strings(entry.get("owners"), "POLICY_TEST_OWNERS")
            if not owners or any(owner not in tasks for owner in owners):
                self.diagnostics.add(f"CATALOG_TEST_OWNER:{test_id}")
            state = entry.get("state")
            if state == "planned":
                if not any(tasks.get(owner) != "DONE" for owner in owners):
                    self.diagnostics.add(f"CATALOG_STALE_PLANNED:{test_id}")
                if set(entry) != {"owners", "state"}:
                    self.diagnostics.add(f"CATALOG_PLANNED_KEYS:{test_id}")
            elif state == "gate_bound":
                gate_id = entry.get("completion_gate")
                if (
                    set(entry) != {"owners", "state", "command", "completion_gate"}
                    or not isinstance(entry.get("command"), str)
                    or entry.get("command") not in allowed_commands
                    or not isinstance(gate_id, str)
                    or self._succession(gate_id) is None
                ):
                    self.diagnostics.add(f"CATALOG_GATE_BOUND:{test_id}")
                elif all(tasks.get(owner) == "DONE" for owner in owners):
                    decision = _text_from_bytes(
                        self._read(f"artifacts/gates/{gate_id}/decision.md"), kind="MARKDOWN"
                    )
                    if re.findall(r"(?m)^decision: (NO-GO|GO-PROPOSED|GO)$", decision) != ["GO"]:
                        self.diagnostics.add(f"CATALOG_GATE_INCOMPLETE:{test_id}")
            elif state == "executable":
                command = entry.get("command")
                if not isinstance(command, str) or command not in allowed_commands:
                    self.diagnostics.add(f"CATALOG_EXECUTABLE_COMMAND:{test_id}")
                if set(entry) != {"owners", "state", "command"}:
                    self.diagnostics.add(f"CATALOG_EXECUTABLE_KEYS:{test_id}")
            else:
                self.diagnostics.add(f"CATALOG_TEST_STATE:{test_id}")
        evidence_raw = _mapping(self.policy.get("evidence_catalog"), "POLICY_EVIDENCE_CATALOG")
        evidence_ids = set(evidence_raw)
        for evidence_id, raw_entry in evidence_raw.items():
            entry = _mapping(raw_entry, "POLICY_EVIDENCE_ENTRY")
            if evidence_id not in gates or entry.get("gate") != evidence_id:
                self.diagnostics.add(f"CATALOG_EVIDENCE_GATE:{evidence_id}")
            path = entry.get("path")
            state = entry.get("state")
            if not isinstance(path, str):
                self.diagnostics.add(f"CATALOG_EVIDENCE_PATH:{evidence_id}")
            elif state == "completed" and not _safe_path(self.root, path).is_dir():
                self.diagnostics.add(f"CATALOG_EVIDENCE_MISSING:{evidence_id}")
            elif state not in {"completed", "planned"}:
                self.diagnostics.add(f"CATALOG_EVIDENCE_STATE:{evidence_id}")
        return test_ids, evidence_ids

    def _validate_traceability(self, definitions: set[str]) -> None:
        trace = _mapping(self._load("specs/traceability/requirements.yaml"), "TRACE_ROOT")
        tasks, gates = self._plan_catalog()
        test_ids, evidence_ids = self._catalogs(tasks, gates)
        rows: list[Mapping[str, object]] = []
        for section in ("requirements", "threat_traceability"):
            for item in _sequence(trace.get(section), "TRACE_ROWS"):
                rows.append(_mapping(item, "TRACE_ROW"))
        row_ids: set[str] = set()
        for row in rows:
            identifier = row.get("id")
            if not isinstance(identifier, str) or identifier in row_ids:
                self.diagnostics.add("TRACE_DUPLICATE_ROW")
            else:
                row_ids.add(identifier)
            for name, authority in (
                ("normative", definitions),
                ("tasks", set(tasks)),
                ("tests", test_ids),
            ):
                values = _strings(row.get(name), f"TRACE_{name.upper()}")
                if (
                    not values
                    or len(values) != len(set(values))
                    or any(item not in authority for item in values)
                ):
                    self.diagnostics.add(f"TRACE_{name.upper()}:{identifier}")
            if "evidence" in row:
                values = _strings(row.get("evidence"), "TRACE_EVIDENCE")
                if (
                    not values
                    or len(values) != len(set(values))
                    or any(item not in evidence_ids for item in values)
                ):
                    self.diagnostics.add(f"TRACE_EVIDENCE:{identifier}")
        prefix_map = _mapping(trace.get("spec_prefix_coverage"), "TRACE_PREFIXES")
        expected_prefixes = {identifier.rsplit("-", 1)[0] for identifier in definitions}
        if set(prefix_map) != expected_prefixes:
            self.diagnostics.add("TRACE_PREFIX_COVERAGE")

    def _validate_schemas(self, definitions: set[str]) -> None:
        known_formats = frozenset(_strings(self.policy.get("known_formats"), "POLICY_FORMATS"))
        public_hashes = _mapping(self.policy.get("public_schema_sha256"), "POLICY_PUBLIC_SCHEMAS")
        public_names = {path.name for path in PUBLIC_SCHEMA_ROOT.glob("*.schema.json")}
        if public_names != set(public_hashes):
            self.diagnostics.add("PUBLIC_SCHEMA_INVENTORY")
        schema_documents: dict[str, Mapping[str, object]] = {}
        paths = [
            "specs/contracts/provider-profile.schema.json",
            "specs/contracts/policy/egress-policy.schema.json",
            "specs/contracts/policy/retention-policy.schema.json",
        ]
        paths.extend(
            f"packages/contracts/src/securecode_ai/contracts/schemas/v0.2.0/{name}"
            for name in sorted(public_names)
        )
        for relative in paths:
            try:
                data = self._read(relative)
                document = _mapping(strict_json_loads(data, self.limits), "SCHEMA_ROOT")
                public = relative.startswith("packages/")
                self.diagnostics.extend(
                    f"{code}:{PurePosixPath(relative).name}"
                    for code in schema_document_errors(
                        document, known_formats=known_formats, public=public
                    )
                )
                if public:
                    expected_hash = public_hashes.get(PurePosixPath(relative).name)
                    if hashlib.sha256(data).hexdigest() != expected_hash:
                        self.diagnostics.add(f"PUBLIC_SCHEMA_DRIFT:{PurePosixPath(relative).name}")
                    rules = document.get("x-securecode-semantic-rules")
                    if not isinstance(rules, list) or any(
                        rule not in definitions for rule in rules
                    ):
                        self.diagnostics.add(f"SCHEMA_SEMANTIC_RULE:{PurePosixPath(relative).name}")
                schema_documents[relative] = document
            except GateInputError as error:
                self.diagnostics.add(f"SCHEMA_{error.code}:{PurePosixPath(relative).name}")
        self._validate_examples(schema_documents, known_formats)

    def _validate_examples(
        self, schemas: Mapping[str, Mapping[str, object]], known_formats: frozenset[str]
    ) -> None:
        indexes = (
            "specs/contracts/policy/fixtures.yaml",
            "specs/contracts/provider-profile.fixtures.yaml",
        )
        case_ids: set[str] = set()
        instance_paths: set[str] = set()
        for index_path in indexes:
            index = _mapping(self._load(index_path), "EXAMPLE_INDEX")
            base = PurePosixPath(index_path).parent
            default_schema = index.get("schema")
            for raw_case in _sequence(index.get("cases"), "EXAMPLE_CASES"):
                case = _mapping(raw_case, "EXAMPLE_CASE")
                case_id = case.get("id")
                instance = case.get("instance")
                schema_name = case.get("schema", default_schema)
                expectation = case.get("expect")
                if not isinstance(case_id, str) or case_id in case_ids:
                    self.diagnostics.add("EXAMPLE_DUPLICATE_ID")
                    continue
                case_ids.add(case_id)
                if not isinstance(instance, str) or not isinstance(schema_name, str):
                    self.diagnostics.add(f"EXAMPLE_FIELDS:{case_id}")
                    continue
                instance_path = (base / instance).as_posix()
                schema_path = (base / schema_name).as_posix()
                if instance_path in instance_paths:
                    self.diagnostics.add(f"EXAMPLE_DUPLICATE_INSTANCE:{case_id}")
                instance_paths.add(instance_path)
                try:
                    payload = strict_json_loads(self._read(instance_path), self.limits)
                    schema = schemas[schema_path]
                    valid = not list(_schema_validator(schema, known_formats).iter_errors(payload))
                    if expectation not in {"valid", "invalid"} or valid != (expectation == "valid"):
                        self.diagnostics.add(f"EXAMPLE_EXPECTATION:{case_id}")
                except (GateInputError, KeyError):
                    self.diagnostics.add(f"EXAMPLE_VALIDATION:{case_id}")
        indexed_roots = (
            self.root / "specs" / "contracts" / "policy" / "fixtures",
            self.root / "specs" / "contracts" / "provider-fixtures",
        )
        discovered = {
            path.relative_to(self.root).as_posix()
            for root in indexed_roots
            for path in root.glob("*.json")
            if path.is_file() and not path.is_symlink()
        }
        if discovered != instance_paths:
            self.diagnostics.add("EXAMPLE_INSTANCE_INVENTORY")

    def validate_snapshot(self) -> tuple[str, ...]:
        try:
            _, paths = self._baseline()
            definitions = self._validate_normative(paths)
            self._validate_traceability(definitions)
            self._validate_schemas(definitions)
            packet_hash = hashlib.sha256(self._read("work/task-packets/P1.13.yaml")).hexdigest()
            expected_packet = self.policy.get("bootstrap_packet_sha256")
            if packet_hash != expected_packet:
                self.diagnostics.add("BOOTSTRAP_PACKET_DRIFT")
        except GateInputError as error:
            self.diagnostics.add(error.code)
        return self.diagnostics.sorted()

    def _diff_records(
        self, mode: str, base: str, candidate: str | None
    ) -> tuple[tuple[str, ...], ...]:
        if mode == "index-candidate":
            raw = git_bytes(self.root, "diff", "--cached", "--name-status", "-z", "-M", "-C", base)
        else:
            if candidate is None:
                raise GateInputError("CANDIDATE_REQUIRED")
            raw = git_bytes(
                self.root, "diff", "--name-status", "-z", "-M", "-C", f"{base}..{candidate}"
            )
        return parse_name_status(raw, maximum_paths=self.limits.git_paths)

    def _diff_lines(self, mode: str, base: str, candidate: str | None) -> int:
        if mode == "index-candidate":
            raw = git_bytes(self.root, "diff", "--cached", "--numstat", "-z", base)
        else:
            if candidate is None:
                raise GateInputError("CANDIDATE_REQUIRED")
            raw = git_bytes(self.root, "diff", "--numstat", "-z", f"{base}..{candidate}")
        total = 0
        for record in raw.split(b"\0"):
            if not record:
                continue
            fields = record.split(b"\t", 2)
            if len(fields) != 3:
                raise GateInputError("GIT_NUMSTAT")
            for field_value in fields[:2]:
                if field_value == b"-" or not field_value.isdigit():
                    raise GateInputError("GIT_BINARY_OR_NUMSTAT")
                total += int(field_value)
        return total

    def _diff_lines_for_paths(self, base: str, candidate: str, paths: Sequence[str]) -> int:

        if not paths:
            return 0
        raw = git_bytes(
            self.root,
            "diff",
            "--numstat",
            "-z",
            f"{base}..{candidate}",
            "--",
            *paths,
        )
        total = 0
        for record in raw.split(b"\0"):
            if not record:
                continue
            fields = record.split(b"\t", 2)
            if len(fields) != 3:
                raise GateInputError("GIT_NUMSTAT")
            for field_value in fields[:2]:
                if field_value == b"-" or not field_value.isdigit():
                    raise GateInputError("GIT_BINARY_OR_NUMSTAT")
                total += int(field_value)
        return total

    def _candidate_file(self, mode: str, candidate: str | None, path: str) -> bytes:
        if mode == "index-candidate":
            return git_bytes(self.root, "cat-file", "blob", f":{path}")
        if candidate is None:
            raise GateInputError("CANDIDATE_REQUIRED")
        return _git_blob(self.root, candidate, path)

    def _base_file(self, base: str, path: str) -> bytes:
        return _git_blob(self.root, base, path)

    def _validate_git_modes(
        self,
        mode: str,
        *,
        base: str,
        candidate: str | None,
        records: Sequence[Sequence[str]],
    ) -> None:
        def validate_entry(revision: str | None, path: str) -> None:
            arguments = (
                ("ls-files", "--stage", "-z", "--", path)
                if revision is None
                else ("ls-tree", "-z", revision, "--", path)
            )
            raw = git_bytes(self.root, *arguments)
            entries = [entry for entry in raw.split(b"\0") if entry]
            if len(entries) != 1:
                raise GateInputError("GIT_FILE_MODE_RECORD")
            try:
                metadata = entries[0].split(b"\t", 1)[0].decode("ascii", "strict")
            except (UnicodeDecodeError, ValueError) as error:
                raise GateInputError("GIT_FILE_MODE_RECORD") from error
            fields = metadata.split()
            if len(fields) != 3:
                raise GateInputError("GIT_FILE_MODE_RECORD")
            mode_value, middle, final = fields
            if mode_value not in {"100644", "100755"}:
                raise GateInputError("GIT_FILE_MODE")
            object_id = middle if revision is None else final
            if revision is None:
                if final != "0":
                    raise GateInputError("GIT_INDEX_STAGE")
            elif middle != "blob":
                raise GateInputError("GIT_FILE_MODE")
            if not SHA1_PATTERN.fullmatch(object_id) or object_id == "0" * 40:
                raise GateInputError("GIT_OBJECT_ID")

        candidate_revision = None if mode == "index-candidate" else candidate
        for record in records:
            status = record[0][0]
            if status in {"D", "R", "C"}:
                validate_entry(base, record[1])
            if status in {"A", "M", "R", "C"}:
                validate_entry(candidate_revision, record[-1])

    def _candidate_documents(
        self, mode: str, candidate: str | None, paths: Iterable[str]
    ) -> dict[str, bytes]:
        return {path: self._candidate_file(mode, candidate, path) for path in sorted(set(paths))}

    def _github_api_json(self, path: str) -> object:
        cached = self.github_api_cache.get(path)
        if cached is not None:
            return cached
        if not path.startswith("/repos/") or any(character in path for character in "\r\n#"):
            raise GateInputError("ATTESTATION_EXTERNAL_AUTHORITY")
        token = self.github_token
        if (
            not isinstance(token, str)
            or not 1 <= len(token.encode("utf-8")) <= 4096
            or "\r" in token
            or "\n" in token
        ):
            raise GateInputError("ATTESTATION_EXTERNAL_AUTHORITY")
        deadline = time.monotonic() + 15.0
        connection = http.client.HTTPSConnection("api.github.com", timeout=15)

        def apply_remaining_deadline() -> None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GateInputError("ATTESTATION_EXTERNAL_FETCH")
            connection.timeout = remaining
            if connection.sock is not None:
                connection.sock.settimeout(remaining)

        try:
            apply_remaining_deadline()
            connection.request(
                "GET",
                path,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {token}",
                    "User-Agent": "securecode-ai-spec-gate",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            apply_remaining_deadline()
            response = connection.getresponse()
            apply_remaining_deadline()
            content_type = response.getheader("Content-Type", "")
            link = response.getheader("Link", "")
            if (
                response.status != 200
                or not content_type.lower().startswith("application/json")
                or 'rel="next"' in link
            ):
                raise GateInputError("ATTESTATION_EXTERNAL_FETCH")
            chunks: list[bytes] = []
            size = 0
            while True:
                apply_remaining_deadline()
                chunk = response.read(min(65536, 1048577 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > 1048576:
                    raise GateInputError("ATTESTATION_EXTERNAL_FETCH")
            body = b"".join(chunks)
        except (OSError, http.client.HTTPException) as error:
            raise GateInputError("ATTESTATION_EXTERNAL_FETCH") from error
        finally:
            connection.close()
        value = strict_json_loads(body, self.limits)
        self.github_api_cache[path] = value
        return value

    def _github_actions_run(
        self, owner: str, repository: str, run_id: int, run_attempt: int
    ) -> Mapping[str, object]:
        identity = (owner, repository, run_id, run_attempt)
        cached = self.github_run_cache.get(identity)
        if cached is not None:
            return cached
        value = _mapping(
            self._github_api_json(
                f"/repos/{owner}/{repository}/actions/runs/{run_id}/attempts/{run_attempt}"
            ),
            "GITHUB_RUN_ROOT",
        )
        self.github_run_cache[identity] = value
        return value

    def _canonical_github_run(self, value: Mapping[str, object]) -> bytes:
        repository = _mapping(value.get("repository"), "GITHUB_RUN_REPOSITORY")
        projection = {
            "conclusion": value.get("conclusion"),
            "event": value.get("event"),
            "head_branch": value.get("head_branch"),
            "head_sha": value.get("head_sha"),
            "html_url": value.get("html_url"),
            "id": value.get("id"),
            "path": value.get("path"),
            "repository": repository.get("full_name"),
            "run_attempt": value.get("run_attempt"),
            "status": value.get("status"),
            "workflow_id": value.get("workflow_id"),
        }
        if (
            not isinstance(projection["id"], int)
            or not isinstance(projection["run_attempt"], int)
            or not isinstance(projection["workflow_id"], int)
            or any(
                not isinstance(projection[key], str)
                for key in (
                    "conclusion",
                    "event",
                    "head_branch",
                    "head_sha",
                    "html_url",
                    "path",
                    "repository",
                    "status",
                )
            )
        ):
            raise GateInputError("ATTESTATION_EXTERNAL_RESPONSE")
        return json.dumps(projection, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _protected_merge_bundle(
        self,
        owner: str,
        repository: str,
        ref: Mapping[str, object],
        run: Mapping[str, object],
    ) -> tuple[bytes, str, str]:
        run_id = cast(int, ref.get("run_id"))
        run_attempt = cast(int, ref.get("run_attempt"))
        pull_number = cast(int, ref.get("pull_request_number"))
        jobs_root = _mapping(
            self._github_api_json(
                f"/repos/{owner}/{repository}/actions/runs/{run_id}/attempts/{run_attempt}/jobs?per_page=100"
            ),
            "GITHUB_JOBS_ROOT",
        )
        jobs = _sequence(jobs_root.get("jobs"), "GITHUB_JOBS")
        gate_jobs = [
            _mapping(job, "GITHUB_JOB")
            for job in jobs
            if isinstance(job, Mapping) and job.get("name") == ref.get("required_check")
        ]
        if len(gate_jobs) != 1:
            raise GateInputError("ATTESTATION_EXTERNAL_REQUIRED_CHECK")
        gate_job = gate_jobs[0]
        gate_completed_at = gate_job.get("completed_at")
        if (
            gate_job.get("status") != "completed"
            or gate_job.get("conclusion") != "success"
            or gate_job.get("head_sha") != run.get("head_sha")
            or gate_completed_at != ref.get("gate_completed_at")
            or not isinstance(gate_completed_at, str)
        ):
            raise GateInputError("ATTESTATION_EXTERNAL_REQUIRED_CHECK")

        pull = _mapping(
            self._github_api_json(f"/repos/{owner}/{repository}/pulls/{pull_number}"),
            "GITHUB_PULL_ROOT",
        )
        pull_head = _mapping(pull.get("head"), "GITHUB_PULL_HEAD")
        pull_base = _mapping(pull.get("base"), "GITHUB_PULL_BASE")
        base_sha = pull_base.get("sha")
        merge_sha = pull.get("merge_commit_sha")
        merged_at = pull.get("merged_at")
        if (
            pull.get("number") != pull_number
            or pull.get("state") != "closed"
            or pull.get("merged") is not True
            or pull_head.get("sha") != run.get("head_sha")
            or pull_base.get("ref") != "master"
            or not isinstance(base_sha, str)
            or not SHA1_PATTERN.fullmatch(base_sha)
            or merge_sha != ref.get("merge_commit_sha")
            or not isinstance(merge_sha, str)
            or not SHA1_PATTERN.fullmatch(merge_sha)
            or merged_at != ref.get("merged_at")
            or not isinstance(merged_at, str)
        ):
            raise GateInputError("ATTESTATION_EXTERNAL_MERGE")
        try:
            merge_time = datetime.fromisoformat(merged_at.replace("Z", "+00:00"))
            gate_time = datetime.fromisoformat(gate_completed_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise GateInputError("ATTESTATION_EXTERNAL_MERGE") from error
        if gate_time > merge_time:
            raise GateInputError("ATTESTATION_EXTERNAL_REQUIRED_CHECK")

        bundle = {
            "gate_job": {
                "conclusion": gate_job.get("conclusion"),
                "head_sha": gate_job.get("head_sha"),
                "id": gate_job.get("id"),
                "name": gate_job.get("name"),
                "status": gate_job.get("status"),
                "completed_at": gate_completed_at,
            },
            "pull_request": {
                "base_ref": pull_base.get("ref"),
                "base_sha": pull_base.get("sha"),
                "head_sha": pull_head.get("sha"),
                "merge_commit_sha": merge_sha,
                "merged": pull.get("merged"),
                "merged_at": merged_at,
                "number": pull.get("number"),
                "state": pull.get("state"),
            },
            "run": json.loads(self._canonical_github_run(run)),
        }
        return (
            json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            merge_sha,
            base_sha,
        )

    def _completion_errors(
        self,
        mode: str,
        *,
        base: str,
        candidate: str | None,
        attestation_path: str,
        changed: tuple[str, ...],
        diff_lines: int,
        records: Sequence[Sequence[str]],
    ) -> tuple[str, ...]:
        errors: set[str] = set()
        try:
            value = strict_json_loads(
                self._candidate_file(mode, candidate, attestation_path), self.limits
            )
            errors.update(
                validate_completion_attestation(value, policy=self.policy, actual_paths=changed)
            )
            attestation = _mapping(value, "ATTESTATION_ROOT")
            task_id = attestation.get("task_id")
            if not isinstance(task_id, str) or not TASK_ID_PATTERN.fullmatch(task_id):
                raise GateInputError("ATTESTATION_TASK")
            if attestation_path != f"work/task-attestations/{task_id}.json":
                errors.add("ATTESTATION_FILENAME")
            if attestation.get("starting_commit_sha") != base:
                errors.add("ATTESTATION_BASE")
            if diff_lines > 800:
                errors.add("ATTESTATION_ACTUAL_BUDGET")
            closed_paths = {
                attestation_path,
                "README.md",
                "CHANGELOG.md",
                "docs/PLAN.md",
                "docs/CONTEXT.md",
            }
            if not set(changed).issubset(closed_paths) or "docs/PLAN.md" not in changed:
                errors.add("ATTESTATION_CLOSED_PATHS")
            added_attestations = [
                record[1]
                for record in records
                if record[0] == "A" and record[1].startswith("work/task-attestations/")
            ]
            if added_attestations != [attestation_path]:
                errors.add("ATTESTATION_ADDITION")

            base_plan = self._base_file(base, "docs/PLAN.md")
            candidate_plan = self._candidate_file(mode, candidate, "docs/PLAN.md")
            base_text = _text_from_bytes(base_plan, kind="MARKDOWN")
            candidate_text = _text_from_bytes(candidate_plan, kind="MARKDOWN")
            base_matches = [
                match
                for match in TASK_ROW_PATTERN.finditer(base_text)
                if match.group("id") == task_id
            ]
            candidate_matches = [
                match
                for match in TASK_ROW_PATTERN.finditer(candidate_text)
                if match.group("id") == task_id
            ]
            if len(base_matches) != 1 or len(candidate_matches) != 1:
                errors.add("ATTESTATION_PLAN_TASK")
            else:
                base_match = base_matches[0]
                candidate_match = candidate_matches[0]
                if base_match.group("status") not in {"TODO", "IN PROGRESS"}:
                    errors.add("ATTESTATION_BASE_STATUS")
                expected_text = (
                    base_text[: base_match.start("status")]
                    + "DONE"
                    + base_text[base_match.end("status") :]
                )
                if candidate_match.group("status") != "DONE" or candidate_text != expected_text:
                    errors.add("ATTESTATION_STATUS_TRANSITION")

            packet_path = f"work/task-packets/{task_id}.yaml"
            packet_bytes = self._base_file(base, packet_path)
            if hashlib.sha256(packet_bytes).hexdigest() != attestation.get("packet_sha256"):
                errors.add("ATTESTATION_PACKET_HASH")
            packet = _mapping(strict_yaml_loads(packet_bytes, self.limits), "PACKET_ROOT")
            packet_task = _mapping(packet.get("task"), "PACKET_TASK")
            authority = _mapping(self.policy.get("baseline"), "POLICY_BASELINE")
            if packet_task.get("id") != task_id or any(
                packet_task.get(name) != authority.get(name)
                for name in ("baseline_id", "baseline_content_sha256", "baseline_commit_sha")
            ):
                errors.add("ATTESTATION_PACKET_AUTHORITY")
            implementation = attestation.get("implementation_commit_sha")
            if not isinstance(implementation, str) or not SHA1_PATTERN.fullmatch(implementation):
                raise GateInputError("ATTESTATION_IMPLEMENTATION_COMMIT")
            git_bytes(self.root, "merge-base", "--is-ancestor", implementation, base)
            additions = git_text(
                self.root,
                "log",
                "--diff-filter=A",
                "--format=%H",
                base,
                "--",
                packet_path,
            ).splitlines()
            if (
                additions != [implementation]
                or _git_blob(self.root, implementation, packet_path) != packet_bytes
            ):
                errors.add("ATTESTATION_PACKET_PROVENANCE")

            refs = _sequence(attestation.get("evidence_refs"), "ATTESTATION_EVIDENCE")
            external_identities: set[tuple[str, str]] = set()
            run_heads: dict[str, str] = {}
            protected_merge_sha: str | None = None
            protected_base_sha: str | None = None
            github_policy: Mapping[str, object] | None = None
            run_evidence_tasks = completion_run_evidence_tasks(self.policy)
            if task_id == "P1.4" or task_id in run_evidence_tasks:
                github_policy = _mapping(
                    self.policy.get("github_repository_authority"),
                    "POLICY_GITHUB_REPOSITORY_AUTHORITY",
                )
                _strict_keys(
                    github_policy,
                    {"provider", "identity_format", "source", "variable", "evidence_uri_kinds"},
                    "POLICY_GITHUB_REPOSITORY_AUTHORITY_KEYS",
                )
                kinds = _mapping(
                    github_policy.get("evidence_uri_kinds"),
                    "POLICY_GITHUB_EVIDENCE_KINDS",
                )
                if (
                    github_policy.get("provider") != "github"
                    or github_policy.get("identity_format") != "owner/repository"
                    or github_policy.get("source") != "github_actions_default_environment"
                    or github_policy.get("variable") != "GITHUB_REPOSITORY"
                    or kinds
                    != {
                        "github_ruleset_required_check": "api_ruleset",
                        "github_failing_pr_merge_block": "actions_run",
                    }
                ):
                    raise GateInputError("POLICY_GITHUB_EVIDENCE")
                if self.github_repository is None:
                    errors.add("ATTESTATION_EXTERNAL_REPOSITORY_AUTHORITY")
            run_policy: Mapping[str, object] | None = None
            if task_id in run_evidence_tasks:
                run_policy = _mapping(
                    self.policy.get("github_actions_run_evidence"),
                    "POLICY_GITHUB_RUN_EVIDENCE",
                )
                _strict_keys(
                    run_policy,
                    {
                        "provider",
                        "api_host",
                        "token_environment",
                        "workflow_path",
                        "protected_branch",
                        "required_check",
                        "evidence_events",
                    },
                    "POLICY_GITHUB_RUN_EVIDENCE_KEYS",
                )
                if (
                    run_policy.get("provider") != "github"
                    or run_policy.get("api_host") != "api.github.com"
                    or run_policy.get("token_environment") != "GITHUB_TOKEN"
                    or run_policy.get("workflow_path") != ".github/workflows/ci.yml"
                    or run_policy.get("protected_branch") != "master"
                    or run_policy.get("required_check") != "gate"
                    or _mapping(run_policy.get("evidence_events"), "POLICY_GITHUB_RUN_EVENTS")
                    != {"protected_pr_gate": "pull_request", "post_merge_gate": "push"}
                ):
                    raise GateInputError("POLICY_GITHUB_RUN_EVIDENCE")
            for raw_ref in refs:
                ref = _mapping(raw_ref, "ATTESTATION_EVIDENCE_REF")
                ref_type = ref.get("type")
                source = ref.get("source")
                content_hash = ref.get("content_sha256")
                if (
                    not isinstance(ref_type, str)
                    or not isinstance(source, str)
                    or not isinstance(content_hash, str)
                ):
                    continue
                if task_id == "P1.4":
                    identity = github_evidence_identity(source, ref_type)
                    if identity is None:
                        errors.add("ATTESTATION_EXTERNAL_AUTHORITY")
                    else:
                        external_identities.add(identity)
                        if identity != self.github_repository:
                            errors.add("ATTESTATION_EXTERNAL_REPOSITORY")
                elif task_id in run_evidence_tasks and ref_type in {
                    "protected_pr_gate",
                    "post_merge_gate",
                }:
                    try:
                        identity = github_evidence_identity(source, "github_failing_pr_merge_block")
                        declared_repository = ref.get("repository")
                        declared_identity = (
                            repository_identity(declared_repository)
                            if isinstance(declared_repository, str)
                            else None
                        )
                        run_id = ref.get("run_id")
                        run_attempt = ref.get("run_attempt")
                        head_sha = ref.get("head_sha")
                        expected_event = (
                            "pull_request" if ref_type == "protected_pr_gate" else "push"
                        )
                        if (
                            identity is None
                            or declared_identity is None
                            or identity != declared_identity
                            or identity != self.github_repository
                        ):
                            errors.add("ATTESTATION_EXTERNAL_REPOSITORY")
                            continue
                        if not isinstance(run_id, int) or run_id <= 0:
                            errors.add("ATTESTATION_EXTERNAL_RUN")
                            continue
                        if not isinstance(run_attempt, int) or run_attempt <= 0:
                            errors.add("ATTESTATION_EXTERNAL_RUN")
                            continue
                        run = self._github_actions_run(
                            identity[0], identity[1], run_id, run_attempt
                        )
                        canonical = self._canonical_github_run(run)
                        if ref_type == "protected_pr_gate":
                            (
                                canonical,
                                protected_merge_sha,
                                protected_base_sha,
                            ) = self._protected_merge_bundle(identity[0], identity[1], ref, run)
                        if hashlib.sha256(canonical).hexdigest() != content_hash:
                            errors.add("ATTESTATION_EXTERNAL_CONTENT")
                        expected_url = (
                            f"https://github.com/{identity[0]}/{identity[1]}/actions/runs/{run_id}"
                        )
                        repository_value = _mapping(
                            run.get("repository"), "GITHUB_RUN_REPOSITORY"
                        ).get("full_name")
                        if run_policy is None:
                            raise GateInputError("POLICY_GITHUB_RUN_EVIDENCE")
                        if (
                            run.get("id") != run_id
                            or run.get("run_attempt") != run_attempt
                            or run.get("event") != expected_event
                            or ref.get("event") != expected_event
                            or run.get("status") != "completed"
                            or run.get("conclusion") != "success"
                            or ref.get("conclusion") != "success"
                            or run.get("head_branch") != ref.get("head_branch")
                            or (
                                ref_type == "post_merge_gate"
                                and run.get("head_branch") != run_policy.get("protected_branch")
                            )
                            or run.get("head_sha") != head_sha
                            or run.get("path") != run_policy.get("workflow_path")
                            or ref.get("workflow_path") != run_policy.get("workflow_path")
                            or str(repository_value).lower()
                            != f"{identity[0]}/{identity[1]}".lower()
                            or run.get("html_url") != expected_url
                            or source.lower() != expected_url.lower()
                        ):
                            errors.add("ATTESTATION_EXTERNAL_RUN_BINDING")
                        if not isinstance(head_sha, str) or not SHA1_PATTERN.fullmatch(head_sha):
                            errors.add("ATTESTATION_EXTERNAL_COMMIT")
                            continue
                        git_bytes(
                            self.root, "merge-base", "--is-ancestor", implementation, head_sha
                        )
                        git_bytes(self.root, "merge-base", "--is-ancestor", head_sha, base)
                        run_heads[ref_type] = head_sha
                    except GateInputError as error:
                        errors.add(error.code)
                else:
                    try:
                        normalized = normalize_repo_path(source)
                        if normalized in changed:
                            raise GateInputError("ATTESTATION_EVIDENCE_MUTABLE")
                        evidence = self._base_file(base, normalized)
                        if hashlib.sha256(evidence).hexdigest() != content_hash:
                            errors.add("ATTESTATION_EVIDENCE_CONTENT")
                    except GateInputError:
                        errors.add("ATTESTATION_EVIDENCE_AUTHORITY")
            if task_id == "P1.4" and len(external_identities) != 1:
                errors.add("ATTESTATION_EXTERNAL_REPOSITORY")
            if task_id in run_evidence_tasks:
                if set(run_heads) != {"protected_pr_gate", "post_merge_gate"}:
                    errors.add("ATTESTATION_EXTERNAL_RUN_SET")
                else:
                    try:
                        if protected_merge_sha != run_heads["post_merge_gate"]:
                            raise GateInputError("ATTESTATION_EXTERNAL_MERGE")
                        parents = git_text(
                            self.root,
                            "rev-list",
                            "--parents",
                            "-n",
                            "1",
                            protected_merge_sha,
                        ).split()
                        if (
                            len(parents) != 3
                            or parents[0] != protected_merge_sha
                            or parents[1] != protected_base_sha
                            or parents[2] != run_heads["protected_pr_gate"]
                        ):
                            raise GateInputError("ATTESTATION_EXTERNAL_MERGE")
                        git_bytes(
                            self.root,
                            "merge-base",
                            "--is-ancestor",
                            run_heads["protected_pr_gate"],
                            run_heads["post_merge_gate"],
                        )
                    except GateInputError:
                        errors.add("ATTESTATION_EXTERNAL_RUN_ANCESTRY")
        except GateInputError as error:
            errors.add(error.code)
        return tuple(sorted(errors))

    def _historical_completion_errors(self, base: str, task_id: str) -> tuple[str, ...]:
        attestation_path = f"work/task-attestations/{task_id}.json"
        try:
            self._base_file(base, attestation_path)
            additions = git_text(
                self.root,
                "log",
                "--diff-filter=A",
                "--format=%H",
                base,
                "--",
                attestation_path,
            ).splitlines()
            if len(additions) != 1:
                raise GateInputError("ATTESTATION_HISTORICAL_PROVENANCE")
            commit = additions[0]
            parent = self._single_parent(commit)
            records = self._diff_records("committed-candidate", parent, commit)
            return self._completion_errors(
                "committed-candidate",
                base=parent,
                candidate=commit,
                attestation_path=attestation_path,
                changed=changed_paths(records),
                diff_lines=self._diff_lines("committed-candidate", parent, commit),
                records=records,
            )
        except GateInputError as error:
            return (error.code,)

    def _gate_policy(self, gate_id: str) -> Mapping[str, object]:
        policies = _mapping(self.policy.get("gate_policy"), "POLICY_GATE")
        policy = _mapping(policies.get(gate_id), f"POLICY_{gate_id}")
        _strict_keys(
            policy,
            {
                "checklist_ids",
                "evidence_files",
                "prerequisite_tasks",
                "completion_tasks",
                "review_required",
                "promotion_paths",
                "integrated_task_scope",
                "max_changed_files",
                "max_diff_lines",
                "checkpoint_chain_max_changed_files",
                "checkpoint_chain_max_diff_lines",
                "promotion_max_diff_lines",
            },
            f"POLICY_{gate_id}_KEYS",
        )
        return policy

    def _gate_completion_tasks(self, gate_id: str) -> tuple[str, ...]:
        policy = self._gate_policy(gate_id)
        prerequisites = _strings(policy.get("prerequisite_tasks"), "POLICY_GATE_PREREQUISITES")
        completion = _strings(policy.get("completion_tasks"), "POLICY_GATE_COMPLETION_TASKS")
        if len(set(prerequisites)) != len(prerequisites) or len(set(completion)) != len(completion):
            raise GateInputError("POLICY_GATE_TASK_DUPLICATE")
        if not set(completion).issubset(prerequisites):
            raise GateInputError("POLICY_GATE_COMPLETION_SCOPE")
        return completion

    def _succession(self, gate_id: str) -> Mapping[str, object] | None:
        catalog = _mapping(self.policy.get("gate_succession", {}), "POLICY_SUCCESSION")
        return _mapping(catalog[gate_id], "POLICY_SUCCESSION_ENTRY") if gate_id in catalog else None

    def _seed_packet_entry(self, raw: bytes, task_id: str, revision: str) -> Mapping[str, object]:
        packet = _mapping(strict_yaml_loads(raw, self.limits), "SEED_PACKET")
        task = _mapping(packet.get("task"), "SEED_TASK")
        scope = _mapping(packet.get("scope"), "SEED_SCOPE")
        paths = _strings(scope.get("allowed_paths"), "SEED_PATHS")
        start = task.get("starting_commit_sha")
        if not isinstance(start, str) or not SHA1_PATTERN.fullmatch(start):
            raise GateInputError("SEED_BASE")
        git_bytes(self.root, "merge-base", "--is-ancestor", start, revision)
        packet_path = f"work/task-packets/{task_id}.yaml"
        errors = validate_task_packet(
            packet,
            packet_path=packet_path,
            base_sha=start,
            changed=paths,
            diff_lines=0,
            policy=self.policy,
        )
        if errors or task.get("id") != task_id:
            raise GateInputError("SEED_PACKET_INVALID")
        protected = _strings(self.policy.get("self_protected_paths"), "POLICY_PROTECTED")
        for path in paths:
            normalize_repo_path(path)
            if (
                any(character in path for character in "*?[")
                or _path_matches(path, protected)
                or (path.startswith("work/") and path != packet_path)
                or path in {"docs/PLAN.md", "docs/CONTEXT.md", "CHANGELOG.md", "AGENTS.md"}
                or path.startswith(".agents/")
            ):
                raise GateInputError("SEED_PROTECTED_SCOPE")
        budget = {name: scope.get(name) for name in ("max_changed_files", "max_diff_lines")}
        if (
            any(type(value) is not int or value <= 0 for value in budget.values())
            or cast(int, budget["max_changed_files"]) > 64
            or cast(int, budget["max_diff_lines"]) > 12000
        ):
            raise GateInputError("SEED_BUDGET")
        return {
            "packet_allowed_paths": paths,
            "checkpoint_allowed_paths": paths,
            "packet_budget": budget,
            "checkpoint_budget": budget,
        }

    def _integrated_task_entries(self, gate_id: str, base: str | None) -> Mapping[str, object]:
        succession = self._succession(gate_id)
        if succession is None or succession.get("packet_source") == "bootstrap":
            return _mapping(
                self._gate_policy(gate_id).get("integrated_task_scope"),
                "INTEGRATED_TASK_POLICY",
            )
        if succession.get("packet_source") != "protected_base" or base is None:
            raise GateInputError("INTEGRATED_PACKET_AUTHORITY_BASE")
        for task_id in self._gate_completion_tasks(gate_id):
            packet_path = f"work/task-packets/{task_id}.yaml"
            additions = git_text(
                self.root, "log", "--diff-filter=A", "--format=%H", base, "--", packet_path
            ).splitlines()
            if len(additions) != 1:
                raise GateInputError("INTEGRATED_SEED_PROVENANCE")
            seed_commit = additions[0]
            proposal_path = self._integrated_packet_path(
                seed_commit, self._single_parent(seed_commit)
            )
            if proposal_path is None:
                raise GateInputError("INTEGRATED_SEED_PROVENANCE")
            proposal = _mapping(
                strict_yaml_loads(self._base_file(seed_commit, proposal_path), self.limits),
                "INTEGRATED_SEED_PROPOSAL",
            )
            if (
                proposal.get("gate_id") != succession.get("predecessor")
                or packet_path not in _strings(proposal.get("allowed_paths"), "SEED_ADMISSION")
                or self._base_file(seed_commit, packet_path) != self._base_file(base, packet_path)
            ):
                raise GateInputError("INTEGRATED_SEED_PROVENANCE")
        return {
            task_id: self._seed_packet_entry(
                self._base_file(base, f"work/task-packets/{task_id}.yaml"), task_id, base
            )
            for task_id in self._gate_completion_tasks(gate_id)
        }

    def _integrated_task_scopes(
        self, gate_id: str, completion_tasks: tuple[str, ...], base: str | None = None
    ) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:

        configured = self._integrated_task_entries(gate_id, base)
        if set(configured) != set(completion_tasks):
            raise GateInputError("INTEGRATED_TASK_POLICY_SCOPE")
        protected = _strings(self.policy.get("self_protected_paths"), "POLICY_PROTECTED")
        scopes: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
        for task_id in completion_tasks:
            entry = _mapping(configured[task_id], "INTEGRATED_TASK_POLICY_ENTRY")
            _strict_keys(
                entry,
                {
                    "packet_allowed_paths",
                    "checkpoint_allowed_paths",
                    "packet_budget",
                    "checkpoint_budget",
                },
                "INTEGRATED_TASK_POLICY_KEYS",
            )
            packet_paths = _strings(
                entry.get("packet_allowed_paths"), "INTEGRATED_TASK_PACKET_POLICY_PATHS"
            )
            checkpoint_paths = _strings(
                entry.get("checkpoint_allowed_paths"), "INTEGRATED_CHECKPOINT_POLICY_PATHS"
            )
            if (
                not packet_paths
                or not checkpoint_paths
                or len(set(packet_paths)) != len(packet_paths)
                or len(set(checkpoint_paths)) != len(checkpoint_paths)
                or not set(checkpoint_paths).issubset(packet_paths)
                or f"work/task-packets/{task_id}.yaml" not in packet_paths
                or f"work/task-packets/{task_id}.yaml" not in checkpoint_paths
                or any(_path_matches(path, protected) for path in packet_paths)
                or any(_path_matches(path, protected) for path in checkpoint_paths)
            ):
                raise GateInputError("INTEGRATED_TASK_POLICY_PATHS")
            for path in (*packet_paths, *checkpoint_paths):
                normalize_repo_path(path)
            scopes[task_id] = (packet_paths, checkpoint_paths)
        return scopes

    def _integrated_task_budgets(
        self, gate_id: str, completion_tasks: tuple[str, ...], base: str | None = None
    ) -> dict[str, tuple[Mapping[str, int], Mapping[str, int]]]:

        configured = self._integrated_task_entries(gate_id, base)
        if set(configured) != set(completion_tasks):
            raise GateInputError("INTEGRATED_TASK_POLICY_SCOPE")
        budgets: dict[str, tuple[Mapping[str, int], Mapping[str, int]]] = {}
        for task_id in completion_tasks:
            entry = _mapping(configured[task_id], "INTEGRATED_TASK_POLICY_ENTRY")
            packet_budget = _mapping(entry.get("packet_budget"), "INTEGRATED_TASK_PACKET_BUDGET")
            checkpoint_budget = _mapping(
                entry.get("checkpoint_budget"), "INTEGRATED_CHECKPOINT_BUDGET"
            )
            for budget, code in (
                (packet_budget, "INTEGRATED_TASK_PACKET_BUDGET"),
                (checkpoint_budget, "INTEGRATED_CHECKPOINT_BUDGET"),
            ):
                _strict_keys(budget, {"max_changed_files", "max_diff_lines"}, code)
                for _budget_name, value in budget.items():
                    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                        raise GateInputError(code)
            budgets[task_id] = (
                cast(Mapping[str, int], packet_budget),
                cast(Mapping[str, int], checkpoint_budget),
            )
        return budgets

    def _validate_integrated_task_packets(
        self,
        *,
        base: str,
        candidate: str,
        scopes: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]],
        gate_id: str = "G2",
    ) -> None:
        """Accept candidate-only packets only when their authority and scope match policy."""

        budgets = self._integrated_task_budgets(
            gate_id=gate_id, completion_tasks=tuple(scopes), base=base
        )
        succession = self._succession(gate_id)
        for task_id, (packet_paths, _) in scopes.items():
            packet_path = f"work/task-packets/{task_id}.yaml"
            raw = _git_blob(self.root, candidate, packet_path)
            if succession is not None:
                if succession.get("packet_source") == "bootstrap":
                    hashes = _mapping(succession.get("packet_sha256"), "BOOTSTRAP_PACKET_HASHES")
                    chunks = _strings(hashes.get(task_id), "BOOTSTRAP_PACKET_DIGEST")
                    if (
                        len(chunks) != 8
                        or any(re.fullmatch(r"[0-9a-f]{8}", chunk) is None for chunk in chunks)
                        or hashlib.sha256(raw).hexdigest() != "".join(chunks)
                    ):
                        raise GateInputError("BOOTSTRAP_PACKET_BYTES")
                elif raw != self._base_file(base, packet_path):
                    raise GateInputError("INTEGRATED_BASE_PACKET_MUTATION")
                task_changed = tuple(
                    sorted(
                        set(
                            changed_paths(
                                self._diff_records("committed-candidate", base, candidate)
                            )
                        ).intersection(packet_paths)
                    )
                )
                packet_budget, _ = budgets[task_id]
                if (
                    len(task_changed) > packet_budget["max_changed_files"]
                    or self._diff_lines_for_paths(base, candidate, task_changed)
                    > packet_budget["max_diff_lines"]
                ):
                    raise GateInputError("INTEGRATED_TASK_PACKET_BUDGET")
                continue
            if git_text(self.root, "ls-tree", "--name-only", base, "--", packet_path).splitlines():
                raise GateInputError("INTEGRATED_TASK_PACKET_BASE_AUTHORITY")
            packet = strict_yaml_loads(_git_blob(self.root, candidate, packet_path), self.limits)
            packet_errors = validate_task_packet(
                packet,
                packet_path=packet_path,
                base_sha=base,
                changed=packet_paths,
                diff_lines=self._diff_lines_for_paths(base, candidate, packet_paths),
                policy=self.policy,
            )
            if packet_errors:
                raise GateInputError(f"INTEGRATED_TASK_PACKET_{packet_errors[0]}")
            mapping = _mapping(packet, "INTEGRATED_TASK_PACKET")
            execution = _mapping(mapping.get("execution"), "INTEGRATED_TASK_EXECUTION")
            scope = _mapping(mapping.get("scope"), "INTEGRATED_TASK_SCOPE")
            packet_budget, _ = budgets[task_id]
            if (
                _strings(execution.get("exclusive_path_lease"), "INTEGRATED_TASK_LEASE")
                != packet_paths
                or _strings(scope.get("allowed_paths"), "INTEGRATED_TASK_PATHS") != packet_paths
                or scope.get("max_changed_files") != packet_budget["max_changed_files"]
                or scope.get("max_diff_lines") != packet_budget["max_diff_lines"]
            ):
                raise GateInputError("INTEGRATED_TASK_PACKET_SCOPE")

    def _validate_integrated_checkpoint_deltas(
        self,
        *,
        base: str,
        commits: Sequence[str],
        subject_index: int,
        scopes: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]],
        gate_id: str = "G2",
    ) -> None:
        """Reject an out-of-scope checkpoint even if its final-tree trace was removed."""

        checkpoint_paths = {path for _, paths in scopes.values() for path in paths}
        budgets = self._integrated_task_budgets(
            gate_id=gate_id, completion_tasks=tuple(scopes), base=base
        )
        cumulative = {task_id: [0, 0] for task_id in scopes}
        packet_paths = {f"work/task-packets/{task_id}.yaml" for task_id in scopes}
        introduced: dict[str, int] = {
            path: int(bool(git_text(self.root, "ls-tree", "--name-only", base, "--", path)))
            if (self._succession(gate_id) or {}).get("packet_source") == "protected_base"
            else 0
            for path in packet_paths
        }
        bootstrap = (self._succession(gate_id) or {}).get("packet_source") == "bootstrap"
        protected = _strings(self.policy.get("self_protected_paths"), "POLICY_PROTECTED")
        previous = base
        for index, commit in enumerate(commits[: subject_index + 1]):
            if self._single_parent(commit) != previous:
                raise GateInputError("INTEGRATED_CHAIN_PARENT")
            records = self._diff_records("committed-candidate", previous, commit)
            self._validate_git_modes(
                "committed-candidate", base=previous, candidate=commit, records=records
            )
            changed = changed_paths(records)
            if index != subject_index:
                if any(_path_matches(path, protected) for path in changed):
                    raise GateInputError("INTEGRATED_CHECKPOINT_SELF_PROTECTED")
                if not changed or not set(changed).issubset(checkpoint_paths):
                    raise GateInputError("INTEGRATED_CHECKPOINT_SCOPE")
                for task_id, (_, task_paths) in scopes.items():
                    task_changed = tuple(sorted(set(changed).intersection(task_paths)))
                    if task_changed:
                        cumulative[task_id][0] += len(task_changed)
                        cumulative[task_id][1] += self._diff_lines_for_paths(
                            previous, commit, task_changed
                        )
            for record in records:
                for path in record[1:]:
                    if path in packet_paths:
                        if bootstrap and record[0] == "M" and introduced[path] == 1:
                            continue
                        if record[0] != "A" or record[1] != path or introduced[path] != 0:
                            raise GateInputError("INTEGRATED_TASK_PACKET_IMMUTABLE")
                        introduced[path] += 1
            previous = commit
        if any(count != 1 for count in introduced.values()):
            raise GateInputError("INTEGRATED_TASK_PACKET_HISTORY")
        for task_id, (changed_files, changed_lines) in cumulative.items():
            _, checkpoint_budget = budgets[task_id]
            if (
                changed_files > checkpoint_budget["max_changed_files"]
                or changed_lines > checkpoint_budget["max_diff_lines"]
            ):
                raise GateInputError("INTEGRATED_CHECKPOINT_BUDGET")

    def _validate_integrated_chain_budget(
        self, base: str, commits: Sequence[str], gate_id: str
    ) -> None:

        policy = self._gate_policy(gate_id)
        maximum_files = policy.get("checkpoint_chain_max_changed_files")
        maximum_lines = policy.get("checkpoint_chain_max_diff_lines")
        if (
            type(maximum_files) is not int
            or maximum_files <= 0
            or type(maximum_lines) is not int
            or maximum_lines <= 0
        ):
            raise GateInputError("INTEGRATED_CHAIN_BUDGET_POLICY")
        previous = base
        changed_files = 0
        changed_lines = 0
        for commit in commits:
            records = self._diff_records("committed-candidate", previous, commit)
            changed_files += len(changed_paths(records))
            changed_lines += self._diff_lines("committed-candidate", previous, commit)
            previous = commit
        if changed_files > maximum_files or changed_lines > maximum_lines:
            raise GateInputError("INTEGRATED_CHAIN_BUDGET")

    def _promotion_gate_id(self, changed: tuple[str, ...]) -> str | None:
        policies = _mapping(self.policy.get("gate_policy"), "POLICY_GATE")
        matches = [
            gate_id
            for gate_id in policies
            if isinstance(gate_id, str)
            and changed
            == tuple(
                sorted(
                    _strings(
                        self._gate_policy(gate_id).get("promotion_paths"),
                        "POLICY_PROMOTION_PATHS",
                    )
                )
            )
        ]
        if len(matches) > 1:
            raise GateInputError("POLICY_PROMOTION_PATH_AMBIGUOUS")
        return matches[0] if matches else None

    def _base_gate_decision(self, base: str, gate_id: str = "G1") -> str | None:
        path = f"artifacts/gates/{gate_id}/decision.md"
        names = git_text(self.root, "ls-tree", "--name-only", base, "--", path).splitlines()
        if not names:
            return None
        if names != [path]:
            raise GateInputError("GATE_BASE_DECISION")
        document = _text_from_bytes(self._base_file(base, path), kind="MARKDOWN")
        decisions = re.findall(r"(?m)^decision: (NO-GO|GO-PROPOSED|GO)$", document)
        if len(decisions) != 1:
            raise GateInputError("GATE_BASE_DECISION")
        return cast(str, decisions[0])

    def _completed_gate_plan(self, base_plan: bytes, completion_tasks: tuple[str, ...]) -> bytes:
        text = _text_from_bytes(base_plan, kind="MARKDOWN")
        for task_id in completion_tasks:
            matches = [
                match for match in TASK_ROW_PATTERN.finditer(text) if match.group("id") == task_id
            ]
            if len(matches) != 1 or matches[0].group("status") not in {"TODO", "IN PROGRESS"}:
                raise GateInputError("PROMOTION_COMPLETION_STATUS")
            match = matches[0]
            text = text[: match.start("status")] + "DONE" + text[match.end("status") :]
        return text.encode("utf-8")

    def _integrated_packet_path(self, revision: str, base: str | None = None) -> str | None:
        names = (
            [
                record[1]
                for record in self._diff_records("committed-candidate", base, revision)
                if record[0] == "A"
            ]
            if base is not None
            else git_text(
                self.root, "ls-tree", "-r", "--name-only", revision, "--", "work/change-control"
            ).splitlines()
        )
        matches: list[str] = []
        for path in names:
            if re.fullmatch(r"work/change-control/CR-[0-9]{3}\.yaml", path) is None:
                continue
            packet = _mapping(
                strict_yaml_loads(_git_blob(self.root, revision, path), self.limits),
                "INTEGRATED_PACKET",
            )
            if packet.get("change_type") == "integrated_gate_candidate":
                matches.append(path)
        if len(matches) > 1:
            raise GateInputError("INTEGRATED_PACKET_AMBIGUOUS")
        return matches[0] if matches else None

    def _integrated_gate_packet_errors(
        self, base: str, candidate: str, packet_path: str, changed: tuple[str, ...], diff_lines: int
    ) -> tuple[str, str, str, Mapping[str, object]]:

        packet = _mapping(
            strict_yaml_loads(_git_blob(self.root, candidate, packet_path), self.limits),
            "INTEGRATED_PACKET",
        )
        _strict_keys(
            packet,
            {
                "schema_version",
                "change_type",
                "change_id",
                "starting_commit_sha",
                "protected_class",
                "gate_id",
                "decision",
                "evidence_bundle_sha256",
                "review_subject_sha256",
                "allowed_paths",
                "budgets",
            },
            "INTEGRATED_PACKET_KEYS",
        )
        gate_id = packet.get("gate_id")
        if not isinstance(gate_id, str):
            raise GateInputError("INTEGRATED_GATE_ID")
        if self._base_gate_decision(base, gate_id) == "GO":
            raise GateInputError("INTEGRATED_GATE_IMMUTABLE")
        policy = self._gate_policy(gate_id)
        succession = self._succession(gate_id)
        if succession is not None:
            predecessor = succession.get("predecessor")
            if (
                not isinstance(predecessor, str)
                or self._base_gate_decision(base, predecessor) != "GO"
            ):
                raise GateInputError("INTEGRATED_PREDECESSOR_GATE")
        if (
            packet.get("schema_version") != "1.0.0"
            or packet.get("change_type") != "integrated_gate_candidate"
            or not isinstance(packet.get("change_id"), str)
            or packet_path != f"work/change-control/{packet.get('change_id')}.yaml"
            or packet.get("starting_commit_sha") != base
            or packet.get("protected_class") != "gate_evidence"
            or packet.get("decision") != "GO-PROPOSED"
        ):
            raise GateInputError("INTEGRATED_IDENTITY")
        allowed = _strings(packet.get("allowed_paths"), "G2_INTEGRATED_PATHS")
        if tuple(sorted(allowed)) != changed or len(set(allowed)) != len(allowed):
            raise GateInputError("INTEGRATED_PATH_SET")
        maximum_files = policy.get("max_changed_files")
        maximum_lines = policy.get("max_diff_lines")
        budgets = _mapping(packet.get("budgets"), "G2_INTEGRATED_BUDGETS")
        if (
            budgets != {"max_changed_files": maximum_files, "max_diff_lines": maximum_lines}
            or not isinstance(maximum_files, int)
            or not isinstance(maximum_lines, int)
            or len(changed) > maximum_files
            or diff_lines > maximum_lines
        ):
            raise GateInputError("INTEGRATED_BUDGET")
        evidence_paths = tuple(
            f"artifacts/gates/{gate_id}/{name}"
            for name in _strings(policy.get("evidence_files"), "POLICY_GATE_EVIDENCE")
        )
        required = {
            packet_path,
            *evidence_paths,
            f"artifacts/gates/{gate_id}/promotion-manifest.json",
            "CHANGELOG.md",
            "docs/CONTEXT.md",
        }
        completion_tasks = self._gate_completion_tasks(gate_id)
        integrated_scopes = self._integrated_task_scopes(gate_id, completion_tasks, base=base)
        self._validate_integrated_task_packets(
            base=base, candidate=candidate, scopes=integrated_scopes, gate_id=gate_id
        )
        prerequisites = _strings(policy.get("prerequisite_tasks"), "POLICY_GATE_PREREQUISITES")
        statuses = task_statuses(self._base_file(base, "docs/PLAN.md"))
        completed_prerequisites = set(prerequisites).difference(completion_tasks)
        if any(statuses.get(task_id) != "DONE" for task_id in completed_prerequisites) or any(
            statuses.get(task_id) not in {"TODO", "IN PROGRESS"} for task_id in completion_tasks
        ):
            raise GateInputError("INTEGRATED_PREREQUISITES")
        completion_catalog = _mapping(
            self.policy.get("completion_evidence"), "POLICY_COMPLETION_EVIDENCE"
        )
        for task_id in completed_prerequisites:
            if task_id in completion_catalog and self._historical_completion_errors(base, task_id):
                raise GateInputError("INTEGRATED_COMPLETION_RECORD")
        permitted = set(required)
        successor = succession.get("successor") if succession is not None else None
        if successor is not None:
            if not isinstance(successor, str) or self._succession(successor) is None:
                raise GateInputError("INTEGRATED_SUCCESSOR_POLICY")
            for task_id in self._gate_completion_tasks(successor):
                seed_path = f"work/task-packets/{task_id}.yaml"
                raw = _git_blob(self.root, candidate, seed_path)
                self._seed_packet_entry(raw, task_id, base)
                base_paths = git_text(
                    self.root, "ls-tree", "--name-only", base, "--", seed_path
                ).splitlines()
                if base_paths:
                    if raw != self._base_file(base, seed_path):
                        raise GateInputError("INTEGRATED_SEED_MUTATION")
                else:
                    required.add(seed_path)
                    permitted.add(seed_path)
        for packet_paths, _ in integrated_scopes.values():
            permitted.update(packet_paths)
        if not required.issubset(changed) or not set(changed).issubset(permitted):
            raise GateInputError("INTEGRATED_SCOPE")
        documents = self._candidate_documents("committed-candidate", candidate, changed)
        evidence = {path: documents[path] for path in evidence_paths}
        if packet.get("evidence_bundle_sha256") != length_prefixed_digest(evidence):
            raise GateInputError("INTEGRATED_EVIDENCE")
        review_hash = packet.get("review_subject_sha256")
        if (
            not isinstance(review_hash, str)
            or canonical_review_subject(documents, packet_path=packet_path, stored_hash=review_hash)
            != review_hash
        ):
            raise GateInputError("INTEGRATED_REVIEW_HASH")
        checklist = _text_from_bytes(
            evidence[f"artifacts/gates/{gate_id}/checklist.md"], kind="MARKDOWN"
        )
        observed = [
            match.groups()
            for line in checklist.splitlines()
            if (match := re.fullmatch(r"- `([a-z][a-z0-9_]*)`: `(PASS|FAIL)`", line))
        ]
        expected = _strings(policy.get("checklist_ids"), "POLICY_GATE_CRITERIA")
        if tuple(name for name, _ in observed) != expected or any(
            result != "PASS" for _, result in observed
        ):
            raise GateInputError("INTEGRATED_CHECKLIST")
        if re.findall(
            r"(?m)^decision: (NO-GO|GO-PROPOSED|GO)$",
            _text_from_bytes(evidence[f"artifacts/gates/{gate_id}/decision.md"], kind="MARKDOWN"),
        ) != ["GO-PROPOSED"]:
            raise GateInputError("INTEGRATED_DECISION")
        if documents.get("docs/PLAN.md") is not None:
            raise GateInputError("INTEGRATED_PLAN_EARLY")
        promotion_paths = _strings(policy.get("promotion_paths"), "POLICY_PROMOTION_PATHS")
        promotion_base = {
            path: documents[path] if path in documents else self._base_file(base, path)
            for path in promotion_paths
        }
        manifest = strict_json_loads(
            documents[f"artifacts/gates/{gate_id}/promotion-manifest.json"], self.limits
        )
        manifest_mapping = _mapping(manifest, "INTEGRATED_PROMOTION_MANIFEST")
        if manifest_mapping.get("evidence_bundle_sha256") != packet.get("evidence_bundle_sha256"):
            raise GateInputError("INTEGRATED_PROMOTION_EVIDENCE")
        final_documents = dict(
            _promotion_manifest_errors(
                manifest,
                gate_id=gate_id,
                policy_paths=promotion_paths,
                base_documents=promotion_base,
            )
        )
        if final_documents["docs/PLAN.md"] != self._completed_gate_plan(
            promotion_base["docs/PLAN.md"], completion_tasks
        ):
            raise GateInputError("INTEGRATED_PLAN")
        promotion_hash = manifest_mapping.get("promotion_subject_sha256")
        if not isinstance(promotion_hash, str) or not SHA256_PATTERN.fullmatch(promotion_hash):
            raise GateInputError("INTEGRATED_PROMOTION_HASH")
        return gate_id, review_hash, promotion_hash, packet

    def _check_gate_review_roles(self, gate_id: str, roles: set[str], identities: set[str]) -> None:
        expected = (
            {"product_scope", "architecture_contracts", "security_evaluation"}
            if self._gate_policy(gate_id).get("review_required")
            else set()
        )
        if roles != expected or len(identities) != len(expected):
            raise GateInputError("INTEGRATED_REVIEW_INDEPENDENCE")

    def _validate_integrated_pull_request_chain(
        self, base: str, pull_request_head: str
    ) -> tuple[str, ...]:

        errors: set[str] = set()
        try:
            state_before = git_bytes(
                self.root, "status", "--porcelain=v1", "-z", "--untracked-files=all"
            )
            errors.update(self.validate_snapshot())
        except GateInputError as error:
            return (error.code,)
        try:
            commits = git_text(
                self.root, "rev-list", "--reverse", "--topo-order", f"{base}..{pull_request_head}"
            ).splitlines()
            if not commits:
                raise GateInputError("INTEGRATED_CHAIN_LENGTH")
            packet_candidates = [
                (
                    index,
                    self._integrated_packet_path(
                        commit, base if index == 0 else commits[index - 1]
                    ),
                )
                for index, commit in enumerate(commits)
            ]
            packet_matches = [
                (index, path) for index, path in packet_candidates if path is not None
            ]
            if len(packet_matches) != 1:
                raise GateInputError("INTEGRATED_PACKET_MISSING")
            subject_index, packet_path = packet_matches[0]
            packet_preview = _mapping(
                strict_yaml_loads(
                    _git_blob(self.root, commits[subject_index], packet_path), self.limits
                ),
                "INTEGRATED_PACKET",
            )
            preview_gate_id = packet_preview.get("gate_id")
            if not isinstance(preview_gate_id, str):
                raise GateInputError("INTEGRATED_GATE_ID")
            review_required = self._gate_policy(preview_gate_id).get("review_required")
            if not isinstance(review_required, bool):
                raise GateInputError("POLICY_GATE_REVIEW_MODE")
            review_count = 3 if review_required else 0
            if subject_index != len(commits) - 2 - review_count:
                raise GateInputError("INTEGRATED_CHAIN_LENGTH")
            previous = base
            for commit in commits:
                if self._single_parent(commit) != previous:
                    raise GateInputError("INTEGRATED_CHAIN_PARENT")
                previous = commit
            subject = commits[subject_index]
            subject_records = self._diff_records("committed-candidate", base, subject)
            gate_id, review_hash, promotion_hash, packet = self._integrated_gate_packet_errors(
                base,
                subject,
                packet_path,
                changed_paths(subject_records),
                self._diff_lines("committed-candidate", base, subject),
            )
            self._validate_integrated_checkpoint_deltas(
                base=base,
                commits=commits,
                subject_index=subject_index,
                scopes=self._integrated_task_scopes(
                    gate_id, self._gate_completion_tasks(gate_id), base=base
                ),
                gate_id=gate_id,
            )
            self._validate_integrated_chain_budget(base, commits, gate_id)
            evidence_hash = packet.get("evidence_bundle_sha256")
            roles: set[str] = set()
            identities: set[str] = set()
            for commit in commits[subject_index + 1 : subject_index + 1 + review_count]:
                parent = self._single_parent(commit)
                records = self._diff_records("committed-candidate", parent, commit)
                self._validate_git_modes(
                    "committed-candidate", base=parent, candidate=commit, records=records
                )
                changed = changed_paths(records)
                if len(changed) != 2 or any(record[0] != "A" for record in records):
                    raise GateInputError("INTEGRATED_REVIEW_SCOPE")
                receipt_path = next(
                    (path for path in changed if path.endswith("/receipt.json")), None
                )
                note_path = next((path for path in changed if path.endswith("/review.md")), None)
                if receipt_path is None or note_path is None:
                    raise GateInputError("INTEGRATED_REVIEW_FILES")
                receipt = _mapping(
                    strict_json_loads(_git_blob(self.root, commit, receipt_path), self.limits),
                    "INTEGRATED_REVIEW_RECEIPT",
                )
                _strict_keys(
                    receipt,
                    {
                        "schema_version",
                        "change_type",
                        "gate_id",
                        "role",
                        "reviewer_identity",
                        "reviewed_commit_sha",
                        "evidence_bundle_sha256",
                        "review_subject_sha256",
                        "promotion_subject_sha256",
                        "verdict",
                        "source_ref",
                        "source_ref_sha256",
                    },
                    "INTEGRATED_REVIEW_KEYS",
                )
                role = receipt.get("role")
                identity = receipt.get("reviewer_identity")
                if (
                    receipt.get("schema_version") != "1.0.0"
                    or receipt.get("change_type") != "independent_review"
                    or receipt.get("gate_id") != gate_id
                    or role
                    not in {"product_scope", "architecture_contracts", "security_evaluation"}
                    or not isinstance(identity, str)
                    or not identity
                    or receipt.get("reviewed_commit_sha") != subject
                    or receipt.get("evidence_bundle_sha256") != evidence_hash
                    or receipt.get("review_subject_sha256") != review_hash
                    or receipt.get("promotion_subject_sha256") != promotion_hash
                    or receipt.get("verdict") != "PASS"
                ):
                    raise GateInputError("INTEGRATED_REVIEW_RECEIPT")
                directory = f"work/change-control/reviews/{gate_id}/{role}-{review_hash}"
                note = _git_blob(self.root, commit, note_path)
                if (
                    receipt_path != f"{directory}/receipt.json"
                    or note_path != f"{directory}/review.md"
                    or receipt.get("source_ref") != note_path
                    or hashlib.sha256(note).hexdigest() != receipt.get("source_ref_sha256")
                ):
                    raise GateInputError("INTEGRATED_REVIEW_BINDING")
                roles.add(role)
                identities.add(identity)
            self._check_gate_review_roles(gate_id, roles, identities)
            promotion = commits[-1]
            promotion_parent = self._single_parent(promotion)
            promotion_records = self._diff_records(
                "committed-candidate", promotion_parent, promotion
            )
            self._validate_git_modes(
                "committed-candidate",
                base=promotion_parent,
                candidate=promotion,
                records=promotion_records,
            )
            promotion_paths = tuple(
                sorted(
                    _strings(
                        self._gate_policy(gate_id).get("promotion_paths"), "POLICY_PROMOTION_PATHS"
                    )
                )
            )
            if changed_paths(promotion_records) != promotion_paths:
                raise GateInputError("INTEGRATED_PROMOTION_SCOPE")
            manifest = strict_json_loads(
                _git_blob(self.root, subject, f"artifacts/gates/{gate_id}/promotion-manifest.json"),
                self.limits,
            )
            promotion_base = {
                path: _git_blob(self.root, promotion_parent, path) for path in promotion_paths
            }
            expected = dict(
                _promotion_manifest_errors(
                    manifest,
                    gate_id=gate_id,
                    policy_paths=promotion_paths,
                    base_documents=promotion_base,
                )
            )
            actual = {path: _git_blob(self.root, promotion, path) for path in promotion_paths}
            if actual != expected or length_prefixed_digest(actual) != promotion_hash:
                raise GateInputError("INTEGRATED_PROMOTION_BYTES")
            if re.findall(
                r"(?m)^decision: (NO-GO|GO-PROPOSED|GO)$",
                _text_from_bytes(actual[f"artifacts/gates/{gate_id}/decision.md"], kind="MARKDOWN"),
            ) != ["GO"]:
                raise GateInputError("INTEGRATED_PROMOTION_DECISION")
        except GateInputError as error:
            errors.add(error.code)
        try:
            state_after = git_bytes(
                self.root, "status", "--porcelain=v1", "-z", "--untracked-files=all"
            )
            if state_after != state_before:
                errors.add("REPOSITORY_MUTATION")
        except GateInputError as error:
            errors.add(error.code)
        return tuple(sorted(errors))

    def _proposal_errors(
        self,
        mode: str,
        *,
        base: str,
        candidate: str | None,
        packet_path: str,
        changed: tuple[str, ...],
        diff_lines: int,
    ) -> tuple[str, ...]:
        errors: set[str] = set()
        try:
            packet = _mapping(
                strict_yaml_loads(self._candidate_file(mode, candidate, packet_path), self.limits),
                "CHANGE_PACKET_ROOT",
            )
            if packet.get("change_type") == "policy_amendment":
                return self._policy_amendment_proposal_errors(
                    mode,
                    base=base,
                    candidate=candidate,
                    packet_path=packet_path,
                    changed=changed,
                    diff_lines=diff_lines,
                    packet=packet,
                )
            gate_id = packet.get("gate_id")
            if gate_id != "G1":
                raise GateInputError("CHANGE_PACKET_GATE_DECISION")
            if self._base_gate_decision(base, gate_id) == "GO":
                raise GateInputError("CHANGE_PACKET_GATE_IMMUTABLE")
            expected_keys = {
                "schema_version",
                "change_type",
                "change_id",
                "starting_commit_sha",
                "protected_class",
                "gate_id",
                "decision",
                "evidence_bundle_sha256",
                "review_subject_sha256",
                "allowed_paths",
                "budgets",
            }
            _strict_keys(packet, expected_keys, "CHANGE_PACKET_KEYS")
            change_id = packet.get("change_id")
            decision = packet.get("decision")
            if (
                packet.get("schema_version") != "1.0.0"
                or packet.get("change_type") != "spec"
                or packet.get("protected_class") != "gate_evidence"
            ):
                errors.add("CHANGE_PACKET_IDENTITY")
            if (
                not isinstance(change_id, str)
                or not re.fullmatch(r"CR-[0-9]{3}", change_id)
                or packet_path != f"work/change-control/{change_id}.yaml"
            ):
                errors.add("CHANGE_PACKET_FILENAME")
            if packet.get("starting_commit_sha") != base:
                errors.add("CHANGE_PACKET_BASE")
            if decision not in {"NO-GO", "GO-PROPOSED"}:
                errors.add("CHANGE_PACKET_GATE_DECISION")
            gate_policy = self._gate_policy(gate_id)
            evidence_files = tuple(
                f"artifacts/gates/{gate_id}/{path}"
                for path in _strings(gate_policy.get("evidence_files"), "POLICY_GATE_EVIDENCE")
            )
            allowed = _strings(packet.get("allowed_paths"), "CHANGE_PACKET_PATHS")
            if tuple(sorted(allowed)) != changed or len(set(allowed)) != len(allowed):
                errors.add("CHANGE_PACKET_PATH_SET")
            closed_allowed = {
                packet_path,
                *evidence_files,
                f"artifacts/gates/{gate_id}/promotion-manifest.json",
                "CHANGELOG.md",
                "docs/DECISIONS.md",
                "docs/CONTEXT.md",
            }
            required_changed = {
                packet_path,
                f"artifacts/gates/{gate_id}/decision.md",
                "CHANGELOG.md",
                "docs/DECISIONS.md",
            }
            if not set(changed).issubset(closed_allowed) or not required_changed.issubset(changed):
                errors.add("CHANGE_PACKET_CLOSED_PATHS")
            budgets = _mapping(packet.get("budgets"), "CHANGE_PACKET_BUDGETS")
            expected_budgets = {
                "max_changed_files": gate_policy.get("max_changed_files"),
                "max_diff_lines": gate_policy.get("max_diff_lines"),
            }
            if budgets != expected_budgets:
                errors.add("CHANGE_PACKET_BUDGETS")
            maximum_files = gate_policy.get("max_changed_files")
            maximum_lines = gate_policy.get("max_diff_lines")
            if (
                type(maximum_files) is not int
                or type(maximum_lines) is not int
                or len(changed) > maximum_files
                or diff_lines > maximum_lines
            ):
                errors.add("CHANGE_PACKET_ACTUAL_BUDGET")
            documents = self._candidate_documents(mode, candidate, changed)
            if isinstance(change_id, str):
                for path in ("CHANGELOG.md", "docs/DECISIONS.md"):
                    if (
                        documents.get(path, b"").count(change_id.encode()) != 1
                        or self._base_file(base, path).count(change_id.encode()) != 0
                    ):
                        errors.add("CHANGE_PACKET_CR_ADR")
            evidence_documents = self._candidate_documents(mode, candidate, evidence_files)
            evidence_hash = length_prefixed_digest(evidence_documents)
            if packet.get("evidence_bundle_sha256") != evidence_hash:
                errors.add("CHANGE_PACKET_EVIDENCE_HASH")
            stored_review_hash = packet.get("review_subject_sha256")
            if (
                not isinstance(stored_review_hash, str)
                or canonical_review_subject(
                    documents,
                    packet_path=packet_path,
                    stored_hash=stored_review_hash,
                )
                != stored_review_hash
            ):
                errors.add("CHANGE_PACKET_REVIEW_HASH")
            checklist = _text_from_bytes(
                evidence_documents[f"artifacts/gates/{gate_id}/checklist.md"], kind="MARKDOWN"
            )
            expected_criteria = _strings(gate_policy.get("checklist_ids"), "POLICY_GATE_CRITERIA")
            observed_criteria: list[tuple[str, str]] = []
            for line in checklist.splitlines():
                match = re.fullmatch(r"- `([a-z][a-z0-9_]*)`: `(PASS|FAIL)`", line)
                if match:
                    observed_criteria.append((match.group(1), match.group(2)))
            if tuple(item[0] for item in observed_criteria) != expected_criteria:
                errors.add("CHANGE_PACKET_CHECKLIST_IDS")
            if decision == "GO-PROPOSED" and any(
                result != "PASS" for _, result in observed_criteria
            ):
                errors.add("CHANGE_PACKET_CHECKLIST_RESULT")
            decision_text = _text_from_bytes(
                evidence_documents[f"artifacts/gates/{gate_id}/decision.md"], kind="MARKDOWN"
            )
            decision_rows = re.findall(r"(?m)^decision: (NO-GO|GO-PROPOSED|GO)$", decision_text)
            if decision_rows != [decision]:
                errors.add("CHANGE_PACKET_DECISION_BYTES")
            if decision == "GO-PROPOSED":
                prerequisites = _strings(
                    gate_policy.get("prerequisite_tasks"), "POLICY_GATE_PREREQUISITES"
                )
                completion_tasks = self._gate_completion_tasks(gate_id)
                statuses = task_statuses(self._base_file(base, "docs/PLAN.md"))
                completed_prerequisites = set(prerequisites).difference(completion_tasks)
                if any(
                    statuses.get(task_id) != "DONE" for task_id in completed_prerequisites
                ) or any(
                    statuses.get(task_id) not in {"TODO", "IN PROGRESS"}
                    for task_id in completion_tasks
                ):
                    errors.add("CHANGE_PACKET_PREREQUISITES")
                for task_id in prerequisites:
                    task_packet_path = f"work/task-packets/{task_id}.yaml"
                    self._base_file(base, task_packet_path)
                    additions = git_text(
                        self.root,
                        "log",
                        "--diff-filter=A",
                        "--format=%H",
                        base,
                        "--",
                        task_packet_path,
                    ).splitlines()
                    if len(additions) != 1:
                        errors.add("CHANGE_PACKET_PREREQUISITE_RECORD")
                completion_catalog = _mapping(
                    self.policy.get("completion_evidence"), "POLICY_COMPLETION_EVIDENCE"
                )
                for task_id in completed_prerequisites:
                    if task_id in completion_catalog and self._historical_completion_errors(
                        base, task_id
                    ):
                        errors.add("CHANGE_PACKET_COMPLETION_RECORD")
                promotion_paths = _strings(
                    gate_policy.get("promotion_paths"), "POLICY_PROMOTION_PATHS"
                )
                promotion_base_documents = self._candidate_documents(
                    mode, candidate, promotion_paths
                )
                manifest = strict_json_loads(
                    self._candidate_file(
                        mode, candidate, f"artifacts/gates/{gate_id}/promotion-manifest.json"
                    ),
                    self.limits,
                )
                decoded = _promotion_manifest_errors(
                    manifest,
                    gate_id=gate_id,
                    policy_paths=promotion_paths,
                    base_documents=promotion_base_documents,
                )
                manifest_map = _mapping(manifest, "PROMOTION_MANIFEST_ROOT")
                if manifest_map.get("evidence_bundle_sha256") != evidence_hash:
                    errors.add("PROMOTION_MANIFEST_EVIDENCE_HASH")
                final_documents = dict(decoded)
                final_decision = _text_from_bytes(
                    final_documents[f"artifacts/gates/{gate_id}/decision.md"], kind="MARKDOWN"
                )
                if re.findall(r"(?m)^decision: (NO-GO|GO-PROPOSED|GO)$", final_decision) != ["GO"]:
                    errors.add("PROMOTION_MANIFEST_DECISION")
                expected_plan = self._completed_gate_plan(
                    self._base_file(base, "docs/PLAN.md"), completion_tasks
                )
                if (
                    final_documents["docs/PLAN.md"] != expected_plan
                    if completion_tasks
                    else task_statuses(final_documents["docs/PLAN.md"]) != statuses
                ):
                    errors.add("PROMOTION_MANIFEST_TASK_STATUS")
            elif f"artifacts/gates/{gate_id}/promotion-manifest.json" in changed:
                errors.add("CHANGE_PACKET_NO_GO_MANIFEST")
        except GateInputError as error:
            errors.add(error.code)
        return tuple(sorted(errors))

    def _policy_amendment_proposal_errors(
        self,
        mode: str,
        *,
        base: str,
        candidate: str | None,
        packet_path: str,
        changed: tuple[str, ...],
        diff_lines: int,
        packet: Mapping[str, object],
    ) -> tuple[str, ...]:

        errors: set[str] = set()
        try:
            _strict_keys(
                packet,
                {
                    "schema_version",
                    "change_type",
                    "change_id",
                    "starting_commit_sha",
                    "protected_class",
                    "gate_id",
                    "decision",
                    "evidence_bundle_sha256",
                    "review_subject_sha256",
                    "allowed_paths",
                    "budgets",
                },
                "POLICY_CHANGE_PACKET_KEYS",
            )
            change_id = packet.get("change_id")
            if (
                packet.get("schema_version") != "1.0.0"
                or packet.get("change_type") != "policy_amendment"
                or packet.get("protected_class") != "ci_evaluator"
                or packet.get("gate_id") != "POLICY"
                or packet.get("decision") != "CHANGE-PROPOSED"
            ):
                errors.add("POLICY_CHANGE_IDENTITY")
            if (
                not isinstance(change_id, str)
                or re.fullmatch(r"CR-[0-9]{3}", change_id) is None
                or packet_path != f"work/change-control/{change_id}.yaml"
            ):
                raise GateInputError("POLICY_CHANGE_FILENAME")
            if packet.get("starting_commit_sha") != base:
                errors.add("POLICY_CHANGE_BASE")
            amendment_policy = _mapping(self.policy.get("policy_amendment"), "POLICY_AMENDMENT")
            maximum_files = amendment_policy.get("max_changed_files")
            maximum_lines = amendment_policy.get("max_diff_lines")
            maximum_targets = amendment_policy.get("max_target_files")
            budgets = _mapping(packet.get("budgets"), "POLICY_CHANGE_BUDGETS")
            if budgets != {
                "max_changed_files": maximum_files,
                "max_diff_lines": maximum_lines,
            }:
                errors.add("POLICY_CHANGE_BUDGETS")
            if (
                not isinstance(maximum_files, int)
                or not isinstance(maximum_lines, int)
                or len(changed) > maximum_files
                or diff_lines > maximum_lines
            ):
                errors.add("POLICY_CHANGE_ACTUAL_BUDGET")
            manifest_path = f"work/change-control/amendments/{change_id}-manifest.json"
            closed_paths = {
                packet_path,
                manifest_path,
                "CHANGELOG.md",
                "docs/DECISIONS.md",
            }
            allowed = _strings(packet.get("allowed_paths"), "POLICY_CHANGE_PATHS")
            if (
                changed != tuple(sorted(closed_paths))
                or tuple(sorted(allowed)) != changed
                or len(set(allowed)) != len(allowed)
            ):
                errors.add("POLICY_CHANGE_CLOSED_PATHS")
            documents = self._candidate_documents(mode, candidate, changed)
            for path in ("CHANGELOG.md", "docs/DECISIONS.md"):
                if (
                    documents.get(path, b"").count(change_id.encode()) != 1
                    or self._base_file(base, path).count(change_id.encode()) != 0
                ):
                    errors.add("POLICY_CHANGE_CR_ADR")
            evidence_documents = {
                path: documents[path] for path in ("CHANGELOG.md", "docs/DECISIONS.md")
            }
            evidence_hash = length_prefixed_digest(evidence_documents)
            if packet.get("evidence_bundle_sha256") != evidence_hash:
                errors.add("POLICY_CHANGE_EVIDENCE_HASH")
            stored_review_hash = packet.get("review_subject_sha256")
            if (
                not isinstance(stored_review_hash, str)
                or canonical_review_subject(
                    documents,
                    packet_path=packet_path,
                    stored_hash=stored_review_hash,
                )
                != stored_review_hash
            ):
                errors.add("POLICY_CHANGE_REVIEW_HASH")
            allowed_target_values = _strings(
                amendment_policy.get("target_paths"), "POLICY_AMENDMENT_TARGETS"
            )
            if len(set(allowed_target_values)) != len(allowed_target_values):
                raise GateInputError("POLICY_AMENDMENT_TARGET_POLICY")
            allowed_targets = set(allowed_target_values)
            manifest = strict_json_loads(
                self._candidate_file(mode, candidate, manifest_path), self.limits
            )
            manifest_map = _mapping(manifest, "POLICY_PROMOTION_MANIFEST")
            manifest_files = _sequence(manifest_map.get("files"), "POLICY_PROMOTION_MANIFEST_FILES")
            target_paths = tuple(
                sorted(
                    normalize_repo_path(
                        str(_mapping(item, "POLICY_PROMOTION_MANIFEST_FILE").get("path"))
                    )
                    for item in manifest_files
                )
            )
            if (
                not isinstance(maximum_targets, int)
                or not 1 <= len(target_paths) <= maximum_targets
                or len(set(target_paths)) != len(target_paths)
                or not set(target_paths).issubset(allowed_targets)
            ):
                raise GateInputError("POLICY_AMENDMENT_TARGET_POLICY")
            base_documents = {path: self._base_file(base, path) for path in target_paths}
            decoded = dict(
                _promotion_manifest_errors(
                    manifest,
                    gate_id="POLICY",
                    policy_paths=target_paths,
                    base_documents=base_documents,
                )
            )
            if manifest_map.get("evidence_bundle_sha256") != evidence_hash:
                errors.add("POLICY_CHANGE_MANIFEST_EVIDENCE")
            if any(decoded[path] == base_documents[path] for path in target_paths):
                errors.add("POLICY_CHANGE_UNCHANGED_TARGET")
        except GateInputError as error:
            errors.add(error.code)
        return tuple(sorted(errors))

    def _reviewed_proposal(
        self, revision: str, review_hash: str, gate_id: str = "G1"
    ) -> tuple[Mapping[str, object], Mapping[str, object]]:
        names = git_text(
            self.root,
            "ls-tree",
            "-r",
            "--name-only",
            revision,
            "--",
            "work/change-control",
        ).splitlines()
        matches: list[tuple[str, Mapping[str, object]]] = []
        for path in names:
            if not re.fullmatch(r"work/change-control/CR-[0-9]{3}\.yaml", path):
                continue
            packet = _mapping(
                strict_yaml_loads(_git_blob(self.root, revision, path), self.limits),
                "CHANGE_PACKET_ROOT",
            )
            identity = (packet.get("change_type"), packet.get("decision")) == (
                ("spec", "GO-PROPOSED")
                if gate_id != "POLICY"
                else ("policy_amendment", "CHANGE-PROPOSED")
            )
            if (
                identity
                and packet.get("gate_id") == gate_id
                and packet.get("review_subject_sha256") == review_hash
            ):
                matches.append((path, packet))
        if len(matches) != 1:
            raise GateInputError("REVIEW_PROPOSAL_PACKET")
        packet_path, packet = matches[0]
        starting_base = packet.get("starting_commit_sha")
        if not isinstance(starting_base, str) or not SHA1_PATTERN.fullmatch(starting_base):
            raise GateInputError("REVIEW_PROPOSAL_BASE")
        git_bytes(self.root, "merge-base", "--is-ancestor", starting_base, revision)
        if self._single_parent(revision) != starting_base:
            raise GateInputError("REVIEW_PROPOSAL_PARENT")
        additions = git_text(
            self.root,
            "log",
            "--diff-filter=A",
            "--format=%H",
            revision,
            "--",
            packet_path,
        ).splitlines()
        if additions != [revision]:
            raise GateInputError("REVIEW_PROPOSAL_PROVENANCE")
        records = self._diff_records("committed-candidate", starting_base, revision)
        self._validate_git_modes(
            "committed-candidate",
            base=starting_base,
            candidate=revision,
            records=records,
        )
        changed = changed_paths(records)
        if tuple(sorted(_strings(packet.get("allowed_paths"), "CHANGE_PACKET_PATHS"))) != changed:
            raise GateInputError("REVIEW_PROPOSAL_PATHS")
        proposal_errors = self._proposal_errors(
            "committed-candidate",
            base=starting_base,
            candidate=revision,
            packet_path=packet_path,
            changed=changed,
            diff_lines=self._diff_lines("committed-candidate", starting_base, revision),
        )
        if proposal_errors:
            raise GateInputError("REVIEW_PROPOSAL_INVALID")
        manifest_path = (
            f"artifacts/gates/{gate_id}/promotion-manifest.json"
            if gate_id != "POLICY"
            else f"work/change-control/amendments/{packet.get('change_id')}-manifest.json"
        )
        manifest = _mapping(
            strict_json_loads(
                _git_blob(self.root, revision, manifest_path),
                self.limits,
            ),
            "PROMOTION_MANIFEST_ROOT",
        )
        return packet, manifest

    def _review_errors(
        self,
        mode: str,
        *,
        base: str,
        candidate: str | None,
        changed: tuple[str, ...],
        diff_lines: int,
        records: Sequence[Sequence[str]],
    ) -> tuple[str, ...]:
        errors: set[str] = set()
        try:
            reviewed_gate_ids = {
                gate_id
                for gate_id in _mapping(self.policy.get("gate_policy"), "POLICY_GATE")
                if any(
                    path.startswith(f"work/change-control/reviews/{gate_id}/") for path in changed
                )
            }
            if any(
                self._base_gate_decision(base, gate_id) == "GO" for gate_id in reviewed_gate_ids
            ):
                raise GateInputError("REVIEW_GATE_IMMUTABLE")
            if (
                len(changed) != 2
                or diff_lines > 800
                or not all(path.startswith("work/change-control/reviews/") for path in changed)
            ):
                raise GateInputError("REVIEW_PATH_BUDGET")
            if any(record[0] != "A" for record in records):
                raise GateInputError("REVIEW_IMMUTABLE_ADDITION")
            json_paths = [path for path in changed if path.endswith(".json")]
            markdown_paths = [path for path in changed if path.endswith(".md")]
            if len(json_paths) != 1 or len(markdown_paths) != 1:
                raise GateInputError("REVIEW_FILE_SET")
            receipt_path = json_paths[0]
            note_path = markdown_paths[0]
            receipt = _mapping(
                strict_json_loads(self._candidate_file(mode, candidate, receipt_path), self.limits),
                "REVIEW_ROOT",
            )
            expected_keys = {
                "schema_version",
                "change_type",
                "gate_id",
                "role",
                "reviewer_identity",
                "reviewed_commit_sha",
                "evidence_bundle_sha256",
                "review_subject_sha256",
                "promotion_subject_sha256",
                "verdict",
                "source_ref",
                "source_ref_sha256",
            }
            _strict_keys(receipt, expected_keys, "REVIEW_KEYS")
            role = receipt.get("role")
            gate_id = receipt.get("gate_id")
            reviewed = receipt.get("reviewed_commit_sha")
            review_hash = receipt.get("review_subject_sha256")
            reviewer_identity = receipt.get("reviewer_identity")
            if (
                receipt.get("schema_version") != "1.0.0"
                or receipt.get("change_type") != "independent_review"
                or (
                    gate_id != "POLICY"
                    and (
                        not isinstance(gate_id, str)
                        or self._gate_policy(gate_id).get("review_required") is not True
                    )
                )
                or role not in {"product_scope", "architecture_contracts", "security_evaluation"}
                or receipt.get("verdict") not in {"PASS", "BLOCK"}
                or not isinstance(reviewer_identity, str)
                or not 1 <= len(reviewer_identity.encode("utf-8")) <= 256
                or any(
                    character.isspace() and character not in {" ", "\t"}
                    for character in reviewer_identity
                )
            ):
                errors.add("REVIEW_IDENTITY")
            if not isinstance(reviewed, str) or not SHA1_PATTERN.fullmatch(reviewed):
                raise GateInputError("REVIEW_COMMIT")
            git_bytes(self.root, "merge-base", "--is-ancestor", reviewed, base)
            if not isinstance(review_hash, str) or not SHA256_PATTERN.fullmatch(review_hash):
                raise GateInputError("REVIEW_SUBJECT_HASH")
            directory = f"work/change-control/reviews/{gate_id}/{role}-{review_hash}"
            if receipt_path != f"{directory}/receipt.json" or note_path != f"{directory}/review.md":
                errors.add("REVIEW_DIRECTORY")
            if receipt.get("source_ref") != note_path:
                errors.add("REVIEW_SOURCE_PATH")
            note = self._candidate_file(mode, candidate, note_path)
            if len(note) > 65536:
                errors.add("REVIEW_SOURCE_BYTES")
            note_text = _text_from_bytes(note, kind="MARKDOWN")
            if (
                "```" in note_text
                or "~~~" in note_text
                or any(len(line.encode("utf-8")) > 512 for line in note_text.splitlines())
                or re.search(r"(?m)(?:[A-Za-z]:\\|^/[^ /])", note_text)
            ):
                errors.add("REVIEW_SOURCE_CONTENT")
            if hashlib.sha256(note).hexdigest() != receipt.get("source_ref_sha256"):
                errors.add("REVIEW_SOURCE_HASH")
            existing = git_text(
                self.root,
                "ls-tree",
                "-r",
                "--name-only",
                base,
                "--",
                directory,
            ).splitlines()
            if existing:
                errors.add("REVIEW_DUPLICATE_ROLE")
            proposal, manifest = self._reviewed_proposal(reviewed, review_hash, str(gate_id))
            if manifest.get("evidence_bundle_sha256") != receipt.get("evidence_bundle_sha256"):
                errors.add("REVIEW_EVIDENCE_HASH")
            if manifest.get("promotion_subject_sha256") != receipt.get("promotion_subject_sha256"):
                errors.add("REVIEW_PROMOTION_HASH")
            if proposal.get("review_subject_sha256") != review_hash:
                errors.add("REVIEW_SUBJECT_HASH")
        except GateInputError as error:
            errors.add(error.code)
        return tuple(sorted(errors))

    def _single_parent(self, commit: str) -> str:
        fields = git_text(self.root, "rev-list", "--parents", "-n", "1", commit).split()
        if len(fields) != 2 or fields[0] != commit:
            raise GateInputError("COMMIT_SINGLE_PARENT")
        return fields[1]

    def _linear_review_chain(
        self,
        proposal_commit: str,
        receipt_commits: set[str],
        promotion_base: str,
    ) -> bool:

        remaining = set(receipt_commits)
        cursor = proposal_commit
        while remaining:
            successors = [commit for commit in remaining if self._single_parent(commit) == cursor]
            if len(successors) != 1:
                return False
            cursor = successors[0]
            remaining.remove(cursor)
        return cursor == promotion_base

    def _promotion_errors(
        self,
        mode: str,
        *,
        base: str,
        candidate: str | None,
        changed: tuple[str, ...],
        diff_lines: int,
    ) -> tuple[str, ...]:
        errors: set[str] = set()
        try:
            gate_id = self._promotion_gate_id(changed)
            if gate_id is None:
                raise GateInputError("PROMOTION_PATH_BUDGET")
            gate_policy = self._gate_policy(gate_id)
            promotion_paths = _strings(gate_policy.get("promotion_paths"), "POLICY_PROMOTION_PATHS")
            promotion_maximum = gate_policy.get("promotion_max_diff_lines")
            if (
                changed != tuple(sorted(promotion_paths))
                or not isinstance(promotion_maximum, int)
                or diff_lines > promotion_maximum
            ):
                raise GateInputError("PROMOTION_PATH_BUDGET")
            manifest = _mapping(
                strict_json_loads(
                    self._base_file(base, f"artifacts/gates/{gate_id}/promotion-manifest.json"),
                    self.limits,
                ),
                "PROMOTION_MANIFEST_ROOT",
            )
            base_documents = {path: self._base_file(base, path) for path in promotion_paths}
            decoded = dict(
                _promotion_manifest_errors(
                    manifest,
                    gate_id=gate_id,
                    policy_paths=promotion_paths,
                    base_documents=base_documents,
                )
            )
            actual = self._candidate_documents(mode, candidate, changed)
            if actual != decoded:
                errors.add("PROMOTION_FINAL_BYTES")
            if length_prefixed_digest(actual) != manifest.get("promotion_subject_sha256"):
                errors.add("PROMOTION_SUBJECT_HASH")
            evidence_files = tuple(
                f"artifacts/gates/{gate_id}/{path}"
                for path in _strings(gate_policy.get("evidence_files"), "POLICY_GATE_EVIDENCE")
            )
            evidence_documents = {path: self._base_file(base, path) for path in evidence_files}
            if length_prefixed_digest(evidence_documents) != manifest.get("evidence_bundle_sha256"):
                errors.add("PROMOTION_EVIDENCE_HASH")
            checklist = _text_from_bytes(
                evidence_documents[f"artifacts/gates/{gate_id}/checklist.md"], kind="MARKDOWN"
            )
            observed = [
                match.groups()
                for line in checklist.splitlines()
                if (match := re.fullmatch(r"- `([a-z][a-z0-9_]*)`: `(PASS|FAIL)`", line))
            ]
            expected_criteria = _strings(gate_policy.get("checklist_ids"), "POLICY_GATE_CRITERIA")
            if tuple(name for name, _ in observed) != expected_criteria or any(
                result != "PASS" for _, result in observed
            ):
                errors.add("PROMOTION_CHECKLIST")
            base_decision = _text_from_bytes(
                evidence_documents[f"artifacts/gates/{gate_id}/decision.md"], kind="MARKDOWN"
            )
            final_decision = _text_from_bytes(
                actual[f"artifacts/gates/{gate_id}/decision.md"], kind="MARKDOWN"
            )
            if re.findall(r"(?m)^decision: (NO-GO|GO-PROPOSED|GO)$", base_decision) != [
                "GO-PROPOSED"
            ] or re.findall(r"(?m)^decision: (NO-GO|GO-PROPOSED|GO)$", final_decision) != ["GO"]:
                errors.add("PROMOTION_DECISION")
            prerequisites = _strings(
                gate_policy.get("prerequisite_tasks"), "POLICY_GATE_PREREQUISITES"
            )
            completion_tasks = self._gate_completion_tasks(gate_id)
            base_statuses = task_statuses(self._base_file(base, "docs/PLAN.md"))
            completed_prerequisites = set(prerequisites).difference(completion_tasks)
            if any(
                base_statuses.get(task_id) != "DONE" for task_id in completed_prerequisites
            ) or any(
                base_statuses.get(task_id) not in {"TODO", "IN PROGRESS"}
                for task_id in completion_tasks
            ):
                errors.add("PROMOTION_PREREQUISITES")
            expected_plan = self._completed_gate_plan(
                self._base_file(base, "docs/PLAN.md"), completion_tasks
            )
            if (
                actual["docs/PLAN.md"] != expected_plan
                if completion_tasks
                else task_statuses(actual["docs/PLAN.md"]) != base_statuses
            ):
                errors.add("PROMOTION_TASK_STATUS")
            review_paths = git_text(
                self.root,
                "ls-tree",
                "-r",
                "--name-only",
                base,
                "--",
                f"work/change-control/reviews/{gate_id}",
            ).splitlines()
            receipts: list[tuple[str, Mapping[str, object]]] = []
            commits: set[str] = set()
            for path in review_paths:
                if not path.endswith(".json"):
                    continue
                receipt = _mapping(
                    strict_json_loads(self._base_file(base, path), self.limits), "REVIEW_ROOT"
                )
                _strict_keys(
                    receipt,
                    {
                        "schema_version",
                        "change_type",
                        "gate_id",
                        "role",
                        "reviewer_identity",
                        "reviewed_commit_sha",
                        "evidence_bundle_sha256",
                        "review_subject_sha256",
                        "promotion_subject_sha256",
                        "verdict",
                        "source_ref",
                        "source_ref_sha256",
                    },
                    "PROMOTION_RECEIPT_KEYS",
                )
                if receipt.get("promotion_subject_sha256") != manifest.get(
                    "promotion_subject_sha256"
                ) or receipt.get("evidence_bundle_sha256") != manifest.get(
                    "evidence_bundle_sha256"
                ):
                    continue
                receipts.append((path, receipt))
                commit_lines = git_text(
                    self.root,
                    "log",
                    "--diff-filter=A",
                    "--format=%H",
                    base,
                    "--",
                    path,
                ).splitlines()
                if len(commit_lines) != 1:
                    errors.add("PROMOTION_RECEIPT_PROVENANCE")
                else:
                    receipt_commit = commit_lines[0]
                    commits.add(receipt_commit)
                    receipt_base = self._single_parent(receipt_commit)
                    receipt_records = self._diff_records(
                        "committed-candidate", receipt_base, receipt_commit
                    )
                    retrospective = self._review_errors(
                        "committed-candidate",
                        base=receipt_base,
                        candidate=receipt_commit,
                        changed=changed_paths(receipt_records),
                        diff_lines=self._diff_lines(
                            "committed-candidate", receipt_base, receipt_commit
                        ),
                        records=receipt_records,
                    )
                    if retrospective:
                        errors.add("PROMOTION_RECEIPT_INVALID")
            roles = {receipt.get("role") for _, receipt in receipts}
            if roles != {"product_scope", "architecture_contracts", "security_evaluation"}:
                errors.add("PROMOTION_RECEIPT_ROLES")
            if len(receipts) != 3 or len(commits) != 3:
                errors.add("PROMOTION_RECEIPT_SEPARATION")
            reviewed_commits = {receipt.get("reviewed_commit_sha") for _, receipt in receipts}
            review_hashes = {receipt.get("review_subject_sha256") for _, receipt in receipts}
            if len(reviewed_commits) != 1 or len(review_hashes) != 1:
                errors.add("PROMOTION_RECEIPT_SUBJECT")
            for path, receipt in receipts:
                if receipt.get("verdict") != "PASS":
                    errors.add("PROMOTION_RECEIPT_VERDICT")
                role = receipt.get("role")
                review_hash = receipt.get("review_subject_sha256")
                expected_directory = f"work/change-control/reviews/{gate_id}/{role}-{review_hash}"
                if path != f"{expected_directory}/receipt.json":
                    errors.add("PROMOTION_RECEIPT_PATH")
                note_path = receipt.get("source_ref")
                if not isinstance(note_path, str) or note_path != f"{expected_directory}/review.md":
                    errors.add("PROMOTION_RECEIPT_SOURCE")
                else:
                    note = self._base_file(base, note_path)
                    if hashlib.sha256(note).hexdigest() != receipt.get("source_ref_sha256"):
                        errors.add("PROMOTION_RECEIPT_SOURCE")
            if (
                len(reviewed_commits) == 1
                and len(review_hashes) == 1
                and isinstance(next(iter(reviewed_commits)), str)
                and isinstance(next(iter(review_hashes)), str)
            ):
                reviewed = str(next(iter(reviewed_commits)))
                review_hash = str(next(iter(review_hashes)))
                if len(commits) == 3 and not self._linear_review_chain(reviewed, commits, base):
                    errors.add("PROMOTION_RECEIPT_CHAIN")
                proposal, reviewed_manifest = self._reviewed_proposal(
                    reviewed, review_hash, gate_id
                )
                if reviewed_manifest != manifest or proposal.get(
                    "evidence_bundle_sha256"
                ) != manifest.get("evidence_bundle_sha256"):
                    errors.add("PROMOTION_PROPOSAL_DRIFT")
        except GateInputError as error:
            errors.add(error.code)
        return tuple(sorted(errors))

    def _policy_promotion_packet(
        self,
        mode: str,
        *,
        base: str,
        candidate: str | None,
        changed: tuple[str, ...],
    ) -> str | None:

        amendment_policy = _mapping(self.policy.get("policy_amendment"), "POLICY_AMENDMENT")
        allowed = set(_strings(amendment_policy.get("target_paths"), "POLICY_AMENDMENT_TARGETS"))
        if not changed or not set(changed).issubset(allowed):
            return None
        current_hashes = {
            path: hashlib.sha256(self._base_file(base, path)).hexdigest() for path in changed
        }
        candidate_hashes = {
            path: hashlib.sha256(self._candidate_file(mode, candidate, path)).hexdigest()
            for path in changed
        }
        names = git_text(
            self.root, "ls-tree", "-r", "--name-only", base, "--", "work/change-control"
        ).splitlines()
        base_matches: list[str] = []
        exact_matches: list[str] = []
        for path in names:
            if re.fullmatch(r"work/change-control/CR-[0-9]{3}\.yaml", path) is None:
                continue
            packet = _mapping(
                strict_yaml_loads(self._base_file(base, path), self.limits),
                "POLICY_CHANGE_PACKET",
            )
            if packet.get("change_type") != "policy_amendment":
                continue
            change_id = packet.get("change_id")
            if not isinstance(change_id, str) or path != f"work/change-control/{change_id}.yaml":
                raise GateInputError("POLICY_PROMOTION_CHANGE_ID")
            manifest_path = f"work/change-control/amendments/{change_id}-manifest.json"
            manifest = _mapping(
                strict_json_loads(self._base_file(base, manifest_path), self.limits),
                "POLICY_PROMOTION_MANIFEST",
            )
            _strict_keys(
                manifest,
                {
                    "schema_version",
                    "gate_id",
                    "evidence_bundle_sha256",
                    "promotion_subject_sha256",
                    "files",
                },
                "POLICY_PROMOTION_MANIFEST_KEYS",
            )
            if manifest.get("schema_version") != "1.0.0" or manifest.get("gate_id") != "POLICY":
                raise GateInputError("POLICY_PROMOTION_MANIFEST_IDENTITY")
            manifest_base_hashes: dict[str, str] = {}
            manifest_final_hashes: dict[str, str] = {}
            for item in _sequence(manifest.get("files"), "POLICY_PROMOTION_FILES"):
                entry = _mapping(item, "POLICY_PROMOTION_FILE")
                _strict_keys(
                    entry,
                    {"path", "base_sha256", "final_sha256", "final_base64"},
                    "POLICY_PROMOTION_FILE_KEYS",
                )
                raw_target = entry.get("path")
                base_hash = entry.get("base_sha256")
                final_hash = entry.get("final_sha256")
                if not isinstance(raw_target, str):
                    raise GateInputError("POLICY_PROMOTION_PATH")
                target = normalize_repo_path(raw_target)
                if target in manifest_base_hashes:
                    raise GateInputError("POLICY_PROMOTION_DUPLICATE_PATH")
                if not isinstance(base_hash, str) or SHA256_PATTERN.fullmatch(base_hash) is None:
                    raise GateInputError("POLICY_PROMOTION_BASE_HASH")
                if not isinstance(final_hash, str) or SHA256_PATTERN.fullmatch(final_hash) is None:
                    raise GateInputError("POLICY_PROMOTION_FINAL_HASH")
                manifest_base_hashes[target] = base_hash
                manifest_final_hashes[target] = final_hash
            if (
                tuple(sorted(manifest_base_hashes)) == changed
                and manifest_base_hashes == current_hashes
            ):
                base_matches.append(path)
                if manifest_final_hashes == candidate_hashes:
                    exact_matches.append(path)
        if len(exact_matches) > 1:
            raise GateInputError("POLICY_PROMOTION_AMBIGUOUS")
        if exact_matches:
            return exact_matches[0]
        if len(base_matches) > 1:
            raise GateInputError("POLICY_PROMOTION_AMBIGUOUS")
        return base_matches[0] if base_matches else None

    def _policy_promotion_errors(
        self,
        mode: str,
        *,
        base: str,
        candidate: str | None,
        changed: tuple[str, ...],
        diff_lines: int,
        packet_path: str,
    ) -> tuple[str, ...]:

        errors: set[str] = set()
        try:
            if candidate is not None and self._single_parent(candidate) != base:
                errors.add("POLICY_PROMOTION_PARENT")
            amendment_policy = _mapping(self.policy.get("policy_amendment"), "POLICY_AMENDMENT")
            maximum_lines = amendment_policy.get("max_diff_lines")
            if not isinstance(maximum_lines, int) or diff_lines > maximum_lines:
                errors.add("POLICY_PROMOTION_LINE_BUDGET")
            packet = _mapping(
                strict_yaml_loads(self._base_file(base, packet_path), self.limits),
                "POLICY_CHANGE_PACKET",
            )
            change_id = packet.get("change_id")
            review_hash = packet.get("review_subject_sha256")
            if (
                not isinstance(change_id, str)
                or not isinstance(review_hash, str)
                or SHA256_PATTERN.fullmatch(review_hash) is None
            ):
                raise GateInputError("POLICY_PROMOTION_PACKET")
            proposal_commits = git_text(
                self.root,
                "log",
                "--diff-filter=A",
                "--format=%H",
                base,
                "--",
                packet_path,
            ).splitlines()
            if len(proposal_commits) != 1:
                raise GateInputError("POLICY_PROMOTION_PROPOSAL_PROVENANCE")
            proposal_commit = proposal_commits[0]
            reviewed_packet, manifest = self._reviewed_proposal(
                proposal_commit, review_hash, "POLICY"
            )
            if reviewed_packet != packet:
                errors.add("POLICY_PROMOTION_PACKET_DRIFT")
            base_documents = {path: self._base_file(base, path) for path in changed}
            decoded = dict(
                _promotion_manifest_errors(
                    manifest,
                    gate_id="POLICY",
                    policy_paths=changed,
                    base_documents=base_documents,
                )
            )
            actual = self._candidate_documents(mode, candidate, changed)
            if actual != decoded:
                errors.add("POLICY_PROMOTION_FINAL_BYTES")
            if length_prefixed_digest(actual) != manifest.get("promotion_subject_sha256"):
                errors.add("POLICY_PROMOTION_SUBJECT")

            review_root = "work/change-control/reviews/POLICY"
            receipt_paths = [
                path
                for path in git_text(
                    self.root, "ls-tree", "-r", "--name-only", base, "--", review_root
                ).splitlines()
                if path.endswith("/receipt.json")
            ]
            receipts: list[tuple[str, Mapping[str, object]]] = []
            commits: set[str] = set()
            for path in receipt_paths:
                receipt = _mapping(
                    strict_json_loads(self._base_file(base, path), self.limits),
                    "POLICY_PROMOTION_RECEIPT",
                )
                if (
                    receipt.get("reviewed_commit_sha") != proposal_commit
                    or receipt.get("review_subject_sha256") != review_hash
                    or receipt.get("evidence_bundle_sha256")
                    != manifest.get("evidence_bundle_sha256")
                    or receipt.get("promotion_subject_sha256")
                    != manifest.get("promotion_subject_sha256")
                ):
                    continue
                receipts.append((path, receipt))
                additions = git_text(
                    self.root, "log", "--diff-filter=A", "--format=%H", base, "--", path
                ).splitlines()
                if len(additions) != 1:
                    errors.add("POLICY_PROMOTION_RECEIPT_PROVENANCE")
                    continue
                commit = additions[0]
                commits.add(commit)
                parent = self._single_parent(commit)
                records = self._diff_records("committed-candidate", parent, commit)
                if self._review_errors(
                    "committed-candidate",
                    base=parent,
                    candidate=commit,
                    changed=changed_paths(records),
                    diff_lines=self._diff_lines("committed-candidate", parent, commit),
                    records=records,
                ):
                    errors.add("POLICY_PROMOTION_RECEIPT_INVALID")
            roles = {receipt.get("role") for _, receipt in receipts}
            if roles != {"product_scope", "architecture_contracts", "security_evaluation"}:
                errors.add("POLICY_PROMOTION_RECEIPT_ROLES")
            if len(receipts) != 3 or len(commits) != 3:
                errors.add("POLICY_PROMOTION_RECEIPT_SEPARATION")
            elif not self._linear_review_chain(proposal_commit, commits, base):
                errors.add("POLICY_PROMOTION_RECEIPT_CHAIN")
            for path, receipt in receipts:
                if receipt.get("verdict") != "PASS":
                    errors.add("POLICY_PROMOTION_RECEIPT_VERDICT")
                role = receipt.get("role")
                directory = f"{review_root}/{role}-{review_hash}"
                if (
                    path != f"{directory}/receipt.json"
                    or receipt.get("source_ref") != f"{directory}/review.md"
                ):
                    errors.add("POLICY_PROMOTION_RECEIPT_PATH")
        except GateInputError as error:
            errors.add(error.code)
        return tuple(sorted(errors))

    def validate_pull_request_candidate(
        self,
        *,
        base: str,
        synthetic_candidate: str,
        pull_request_head: str,
    ) -> tuple[str, ...]:

        try:
            for value, code in (
                (base, "BASE_FORMAT"),
                (synthetic_candidate, "PR_SYNTHETIC_FORMAT"),
                (pull_request_head, "PR_HEAD_FORMAT"),
            ):
                if not SHA1_PATTERN.fullmatch(value) or value == "0" * 40:
                    raise GateInputError(code)
            head = git_text(self.root, "rev-parse", "HEAD").strip()
            if head != synthetic_candidate:
                raise GateInputError("COMMITTED_CANDIDATE")
            for value in (base, synthetic_candidate, pull_request_head):
                git_bytes(self.root, "cat-file", "-e", f"{value}^{{commit}}")
            parents = git_text(
                self.root, "rev-list", "--parents", "-n", "1", synthetic_candidate
            ).split()
            if parents != [synthetic_candidate, base, pull_request_head]:
                raise GateInputError("PR_SYNTHETIC_PARENTS")
            git_bytes(self.root, "merge-base", "--is-ancestor", base, pull_request_head)
            synthetic_tree = git_text(
                self.root, "rev-parse", f"{synthetic_candidate}^{{tree}}"
            ).strip()
            head_tree = git_text(self.root, "rev-parse", f"{pull_request_head}^{{tree}}").strip()
            if synthetic_tree != head_tree:
                raise GateInputError("PR_SYNTHETIC_TREE")
            commits = git_text(
                self.root,
                "rev-list",
                "--reverse",
                "--topo-order",
                f"{base}..{pull_request_head}",
            ).splitlines()
            if not commits or commits[-1] != pull_request_head:
                raise GateInputError("PR_HEAD_CHAIN")
            previous = base
            for commit in commits:
                if self._single_parent(commit) != previous:
                    raise GateInputError("PR_HEAD_CHAIN")
                previous = commit
            if any(
                self._integrated_packet_path(commit, base if index == 0 else commits[index - 1])
                is not None
                for index, commit in enumerate(commits)
            ):
                return self._validate_integrated_pull_request_chain(base, pull_request_head)
            logical_base = base if len(commits) == 1 else self._single_parent(pull_request_head)
            if len(commits) > 1:
                records = self._diff_records("committed-candidate", logical_base, pull_request_head)
                changed = changed_paths(records)
                protected_promotions = int(self._promotion_gate_id(changed) is not None) + int(
                    self._policy_promotion_packet(
                        "committed-candidate",
                        base=logical_base,
                        candidate=pull_request_head,
                        changed=changed,
                    )
                    is not None
                )
                if protected_promotions != 1:
                    raise GateInputError("PR_HEAD_CHAIN_KIND")
        except GateInputError as error:
            return (error.code,)
        errors = self.validate_candidate(
            "committed-candidate",
            base=logical_base,
            candidate=pull_request_head,
            expected_checkout=synthetic_candidate,
        )
        if errors:
            return errors
        previous = base
        for commit in commits[:-1]:
            errors = self.validate_candidate(
                "committed-candidate",
                base=previous,
                candidate=commit,
                expected_checkout=synthetic_candidate,
                _check_snapshot=False,
            )
            if errors:
                return tuple(sorted({"PR_HEAD_CHAIN_COMMIT", *errors}))
            previous = commit
        return ()

    def validate_push_candidate(self, *, base: str, candidate: str) -> tuple[str, ...]:

        try:
            if not SHA1_PATTERN.fullmatch(candidate) or candidate == "0" * 40:
                raise GateInputError("CANDIDATE_FORMAT")
            parents = git_text(self.root, "rev-list", "--parents", "-n", "1", candidate).split()
            if len(parents) == 2:
                return self.validate_candidate(
                    "committed-candidate",
                    base=base,
                    candidate=candidate,
                )
            if len(parents) != 3 or parents[1] != base:
                raise GateInputError("PUSH_MERGE_PARENTS")
            errors = self.validate_pull_request_candidate(
                base=base,
                synthetic_candidate=candidate,
                pull_request_head=parents[2],
            )
            translations = {
                "PR_SYNTHETIC_FORMAT": "PUSH_MERGE_FORMAT",
                "PR_SYNTHETIC_PARENTS": "PUSH_MERGE_PARENTS",
                "PR_SYNTHETIC_TREE": "PUSH_MERGE_TREE",
                "PR_HEAD_CHAIN": "PUSH_MERGE_HEAD_CHAIN",
                "PR_HEAD_CHAIN_KIND": "PUSH_MERGE_HEAD_CHAIN_KIND",
                "PR_HEAD_CHAIN_COMMIT": "PUSH_MERGE_HEAD_CHAIN_COMMIT",
            }
            return tuple(translations.get(error, error) for error in errors)
        except GateInputError as error:
            return (error.code,)

    def validate_candidate(
        self,
        mode: str,
        *,
        base: str,
        candidate: str | None,
        expected_checkout: str | None = None,
        _check_snapshot: bool = True,
    ) -> tuple[str, ...]:
        self.diagnostics = Diagnostics(self.limits)
        try:
            if mode not in {"index-candidate", "committed-candidate"}:
                raise GateInputError("CANDIDATE_MODE")
            if not SHA1_PATTERN.fullmatch(base) or base == "0" * 40:
                raise GateInputError("BASE_FORMAT")
            if git_text(self.root, "rev-parse", "--is-shallow-repository").strip() != "false":
                raise GateInputError("GIT_SHALLOW")
            git_bytes(self.root, "cat-file", "-e", f"{base}^{{commit}}")
            head = git_text(self.root, "rev-parse", "HEAD").strip()
            if mode == "index-candidate":
                if expected_checkout is not None:
                    raise GateInputError("CANDIDATE_MODE")
                if head != base:
                    raise GateInputError("INDEX_HEAD_BASE")
                if git_bytes(self.root, "diff", "--name-only", "-z") or git_bytes(
                    self.root, "ls-files", "--others", "--exclude-standard", "-z"
                ):
                    raise GateInputError("INDEX_UNSTAGED")
                git_bytes(self.root, "diff", "--cached", "--check", base)
            else:
                checkout_candidate = expected_checkout or candidate
                if (
                    candidate is None
                    or not SHA1_PATTERN.fullmatch(candidate)
                    or candidate == "0" * 40
                    or checkout_candidate is None
                    or not SHA1_PATTERN.fullmatch(checkout_candidate)
                    or checkout_candidate == "0" * 40
                    or head != checkout_candidate
                ):
                    raise GateInputError("COMMITTED_CANDIDATE")
                git_bytes(self.root, "cat-file", "-e", f"{candidate}^{{commit}}")
                git_bytes(self.root, "cat-file", "-e", f"{checkout_candidate}^{{commit}}")
                git_bytes(self.root, "merge-base", "--is-ancestor", base, candidate)
                if base == candidate:
                    raise GateInputError("BASE_SELF")
            state_before = git_bytes(
                self.root, "status", "--porcelain=v1", "-z", "--untracked-files=all"
            )
            records = self._diff_records(mode, base, candidate)
            changed = changed_paths(records)
            if not changed:
                raise GateInputError("CANDIDATE_EMPTY")
            if any(len(path.encode("utf-8")) > self.limits.git_path_utf8_bytes for path in changed):
                raise GateInputError("GIT_PATH_BYTES")
            self._validate_git_modes(mode, base=base, candidate=candidate, records=records)
            diff_lines = self._diff_lines(mode, base, candidate)
            packet_additions = [
                record[1]
                for record in records
                if record[0] == "A"
                and re.fullmatch(r"work/task-packets/P[0-9]+\.[0-9]+\.yaml", record[1])
            ]
            historical_packet_changes = [
                path
                for record in records
                for path in record[1:]
                if path.startswith("work/task-packets/") and path not in packet_additions
            ]
            if historical_packet_changes:
                self.diagnostics.add("HISTORICAL_PACKET_MUTATION")
            attestation_additions = [
                record[1]
                for record in records
                if record[0] == "A"
                and re.fullmatch(r"work/task-attestations/P[0-9]+\.[0-9]+\.json", record[1])
            ]
            proposal_additions = [
                record[1]
                for record in records
                if record[0] == "A"
                and re.fullmatch(r"work/change-control/CR-[0-9]{3}\.yaml", record[1])
            ]
            review_candidate = len(changed) == 2 and all(
                record[0] == "A"
                and re.match(r"work/change-control/reviews/(?:G[1-9]|POLICY)/", record[1])
                for record in records
            )
            promotion_gate_id = self._promotion_gate_id(changed)
            policy_promotion_packet = self._policy_promotion_packet(
                mode,
                base=base,
                candidate=candidate,
                changed=changed,
            )
            kinds: list[str] = []
            if len(packet_additions) == 1:
                kinds.append("implementation")
            if len(attestation_additions) == 1:
                kinds.append("completion")
            if len(proposal_additions) == 1:
                kinds.append("proposal")
            if review_candidate:
                kinds.append("review")
            if promotion_gate_id is not None:
                kinds.append("promotion")
            if policy_promotion_packet is not None:
                kinds.append("policy_promotion")
            if (
                len(packet_additions) > 1
                or len(attestation_additions) > 1
                or len(proposal_additions) > 1
                or len(kinds) > 1
            ):
                self.diagnostics.add("CANDIDATE_KIND_AMBIGUOUS")
            elif not kinds:
                self.diagnostics.add("UNSUPPORTED_CHANGE_KIND")
            elif kinds[0] == "implementation":
                packet_path = packet_additions[0]
                packet = strict_yaml_loads(
                    self._candidate_file(mode, candidate, packet_path), self.limits
                )
                self.diagnostics.extend(
                    validate_task_packet(
                        packet,
                        packet_path=packet_path,
                        base_sha=base,
                        changed=changed,
                        diff_lines=diff_lines,
                        policy=self.policy,
                    )
                )
            elif kinds[0] == "completion":
                self.diagnostics.extend(
                    self._completion_errors(
                        mode,
                        base=base,
                        candidate=candidate,
                        attestation_path=attestation_additions[0],
                        changed=changed,
                        diff_lines=diff_lines,
                        records=records,
                    )
                )
            elif kinds[0] == "proposal":
                self.diagnostics.extend(
                    self._proposal_errors(
                        mode,
                        base=base,
                        candidate=candidate,
                        packet_path=proposal_additions[0],
                        changed=changed,
                        diff_lines=diff_lines,
                    )
                )
            elif kinds[0] == "review":
                self.diagnostics.extend(
                    self._review_errors(
                        mode,
                        base=base,
                        candidate=candidate,
                        changed=changed,
                        diff_lines=diff_lines,
                        records=records,
                    )
                )
            elif kinds[0] == "promotion":
                self.diagnostics.extend(
                    self._promotion_errors(
                        mode,
                        base=base,
                        candidate=candidate,
                        changed=changed,
                        diff_lines=diff_lines,
                    )
                )
            else:
                if policy_promotion_packet is None:
                    raise GateInputError("POLICY_PROMOTION_PACKET")
                self.diagnostics.extend(
                    self._policy_promotion_errors(
                        mode,
                        base=base,
                        candidate=candidate,
                        changed=changed,
                        diff_lines=diff_lines,
                        packet_path=policy_promotion_packet,
                    )
                )
            historical_attestations = [
                path
                for record in records
                for path in record[1:]
                if re.fullmatch(r"work/task-attestations/P[0-9]+\.[0-9]+\.json", path)
                and path not in attestation_additions
            ]
            historical_change_packets = [
                path
                for record in records
                for path in record[1:]
                if re.fullmatch(r"work/change-control/CR-[0-9]{3}\.yaml", path)
                and path not in proposal_additions
            ]
            historical_reviews = [
                path
                for record in records
                for path in record[1:]
                if path.startswith("work/change-control/reviews/") and not review_candidate
            ]
            if historical_attestations:
                self.diagnostics.add("HISTORICAL_ATTESTATION_MUTATION")
            if historical_change_packets:
                self.diagnostics.add("HISTORICAL_CHANGE_PACKET_MUTATION")
            if historical_reviews:
                self.diagnostics.add("HISTORICAL_REVIEW_MUTATION")
            if _check_snapshot:
                self.diagnostics.extend(self.validate_snapshot())
            state_after = git_bytes(
                self.root, "status", "--porcelain=v1", "-z", "--untracked-files=all"
            )
            if state_after != state_before:
                self.diagnostics.add("REPOSITORY_MUTATION")
        except GateInputError as error:
            self.diagnostics.add(error.code)
        return self.diagnostics.sorted()


class _FixedArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise GateInputError("CLI_ARGUMENTS")


def _parser() -> argparse.ArgumentParser:
    parser = _FixedArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    subparsers.add_parser("snapshot")
    index = subparsers.add_parser("index-candidate")
    index.add_argument("--base", required=True)
    index.add_argument("--github-repository", default="")
    committed = subparsers.add_parser("committed-candidate")
    committed.add_argument("--base", required=True)
    committed.add_argument("--candidate", required=True)
    committed.add_argument("--github-repository", default="")
    ci = subparsers.add_parser("ci")
    ci.add_argument("--event", required=True)
    ci.add_argument("--base", default="")
    ci.add_argument("--candidate", required=True)
    ci.add_argument("--pull-request-head", required=True)
    ci.add_argument("--github-repository", required=True)
    return parser


def _receipt(mode: str, errors: Sequence[str]) -> str:
    if errors:
        body = ",".join(errors)
        return f"SPEC_GATE=FAIL mode={mode} errors={len(errors)} codes={body}"
    return f"SPEC_GATE=PASS mode={mode}"


def main(argv: Sequence[str] | None = None) -> int:
    receipt_mode = "unknown"
    try:
        arguments = _parser().parse_args(argv)
        receipt_mode = arguments.mode
        repository_value = getattr(arguments, "github_repository", "")
        parsed_repository = repository_identity(repository_value) if repository_value else None
        if repository_value and parsed_repository is None:
            raise GateInputError("CI_REPOSITORY")
        gate = SpecGate(
            github_repository=parsed_repository,
            github_token=os.environ.get("GITHUB_TOKEN"),
        )
        if arguments.mode == "snapshot":
            errors = gate.validate_snapshot()
        elif arguments.mode == "ci":
            if arguments.event == "workflow_dispatch":
                errors = (
                    ("CI_PR_HEAD_UNEXPECTED",)
                    if arguments.pull_request_head
                    else gate.validate_snapshot()
                )
                receipt_mode = "snapshot"
            elif arguments.event == "pull_request":
                errors = gate.validate_pull_request_candidate(
                    base=arguments.base,
                    synthetic_candidate=arguments.candidate,
                    pull_request_head=arguments.pull_request_head,
                )
                receipt_mode = "committed-candidate"
            elif arguments.event in {"merge_group", "push"}:
                if arguments.pull_request_head:
                    raise GateInputError("CI_PR_HEAD_UNEXPECTED")
                if arguments.event == "push":
                    errors = gate.validate_push_candidate(
                        base=arguments.base,
                        candidate=arguments.candidate,
                    )
                else:
                    errors = gate.validate_candidate(
                        "committed-candidate",
                        base=arguments.base,
                        candidate=arguments.candidate,
                    )
                receipt_mode = "committed-candidate"
            else:
                errors = ("CI_EVENT",)
        else:
            errors = gate.validate_candidate(
                arguments.mode,
                base=arguments.base,
                candidate=getattr(arguments, "candidate", None),
            )
    except (GateInputError, OSError, ValueError, KeyError, TypeError) as error:
        code = error.code if isinstance(error, GateInputError) else "INTERNAL_FAILURE"
        errors = (code,)
    receipt = _receipt(receipt_mode, errors)
    if len(receipt.encode("utf-8")) > 131072:
        receipt = f"SPEC_GATE=FAIL mode={receipt_mode} errors=1 codes=RECEIPT_BYTES"
        errors = ("RECEIPT_BYTES",)
    print(receipt, file=sys.stderr if errors else sys.stdout)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
