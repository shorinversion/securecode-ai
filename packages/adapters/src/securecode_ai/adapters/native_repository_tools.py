"""Closed parsing of native function selections into existing repository-tool DTOs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import RepositoryTool
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryToolRequest,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MAX_CALLS: Final = 4
_SCHEMAS: Final = [
    {
        "type": "function",
        "function": {
            "name": "list_paths",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["schema_version", "head_sha", "prefix", "max_entries"],
                "properties": {
                    "schema_version": {"const": "0.1.0"},
                    "head_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                    "prefix": {"type": "string"},
                    "max_entries": {"type": "integer"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "lookup_symbol",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["schema_version", "head_sha", "symbol", "path"],
                "properties": {
                    "schema_version": {"const": "0.1.0"},
                    "head_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                    "symbol": {"type": "string"},
                    "path": {"type": ["string", "null"]},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_range",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["schema_version", "head_sha", "path", "start_line", "end_line"],
                "properties": {
                    "schema_version": {"const": "0.1.0"},
                    "head_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                    "path": {"type": "string"},
                    "start_line": {"type": "integer"},
                    "end_line": {"type": "integer"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_evidence",
            "strict": True,
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "required": ["schema_version", "head_sha", "evidence_id"],
                "properties": {
                    "schema_version": {"const": "0.1.0"},
                    "head_sha": {"type": "string", "pattern": "^[0-9a-f]{40}$"},
                    "evidence_id": {"type": "string"},
                },
            },
        },
    },
]
NATIVE_REPOSITORY_TOOLS_JSON: Final = json.dumps(
    _SCHEMAS, ensure_ascii=True, separators=(",", ":"), sort_keys=True
).encode()


class NativeToolCallRejection(StrEnum):
    """Closed parser outcome safe to retain outside the native-call boundary."""

    NOT_APPLICABLE = "NOT_APPLICABLE"
    CALL_ENVELOPE = "CALL_ENVELOPE"
    ARGUMENT_TYPE_OR_BYTES = "ARGUMENT_TYPE_OR_BYTES"
    JSON_MALFORMED = "JSON_MALFORMED"
    JSON_DUPLICATE = "JSON_DUPLICATE"
    JSON_NONFINITE = "JSON_NONFINITE"
    ARGUMENT_SCHEMA = "ARGUMENT_SCHEMA"


class NativeToolCallError(ValueError):
    def __init__(
        self, rejection: NativeToolCallRejection = NativeToolCallRejection.CALL_ENVELOPE
    ) -> None:
        super().__init__("native repository tool calls are invalid")
        self.rejection = rejection


@dataclass(frozen=True, slots=True)
class NativeRepositoryToolCall:
    call_id: str
    request: RepositoryToolRequest


def _constant(value: str) -> object:
    del value
    raise NativeToolCallError(NativeToolCallRejection.JSON_NONFINITE)


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise NativeToolCallError(NativeToolCallRejection.JSON_DUPLICATE)
        result[key] = value
    return result


def _arguments(name: str, value: object, head_sha: str) -> RepositoryToolRequest:
    if (
        type(value) is not dict
        or value.get("schema_version") != TOOL_ARGUMENT_SCHEMA_VERSION
        or value.get("head_sha") != head_sha
    ):
        raise NativeToolCallError(NativeToolCallRejection.ARGUMENT_SCHEMA)
    try:
        if name == "list_paths" and set(value) == {
            "schema_version",
            "head_sha",
            "prefix",
            "max_entries",
        }:
            return RepositoryToolRequest(RepositoryTool.LIST_PATHS, ListPathsArguments(**value))
        if name == "lookup_symbol" and set(value) == {
            "schema_version",
            "head_sha",
            "symbol",
            "path",
        }:
            return RepositoryToolRequest(
                RepositoryTool.LOOKUP_SYMBOL, LookupSymbolArguments(**value)
            )
        if name == "read_range" and set(value) == {
            "schema_version",
            "head_sha",
            "path",
            "start_line",
            "end_line",
        }:
            return RepositoryToolRequest(RepositoryTool.READ_RANGE, ReadRangeArguments(**value))
        if name == "read_evidence" and set(value) == {"schema_version", "head_sha", "evidence_id"}:
            return RepositoryToolRequest(
                RepositoryTool.READ_EVIDENCE, ReadEvidenceArguments(**value)
            )
    except (TypeError, ValueError):
        raise NativeToolCallError(NativeToolCallRejection.ARGUMENT_SCHEMA) from None
    raise NativeToolCallError(NativeToolCallRejection.ARGUMENT_SCHEMA)


def parse_native_tool_calls(
    value: object, *, head_sha: str, max_calls: int = _MAX_CALLS
) -> tuple[NativeRepositoryToolCall, ...]:
    if (
        type(value) is not list
        or type(head_sha) is not str
        or not re.fullmatch(r"[0-9a-f]{40}", head_sha)
        or type(max_calls) is not int
        or not 1 <= max_calls <= _MAX_CALLS
        or not 1 <= len(value) <= max_calls
    ):
        raise NativeToolCallError(NativeToolCallRejection.CALL_ENVELOPE)
    calls: list[NativeRepositoryToolCall] = []
    ids: set[str] = set()
    for call in value:
        if (
            type(call) is not dict
            or set(call) != {"id", "type", "function"}
            or type(call["id"]) is not str
            or _ID.fullmatch(call["id"]) is None
            or call["id"] in ids
            or call["type"] != "function"
            or type(call["function"]) is not dict
            or set(call["function"]) != {"name", "arguments"}
        ):
            raise NativeToolCallError(NativeToolCallRejection.CALL_ENVELOPE)
        function = call["function"]
        if type(function["name"]) is not str or type(function["arguments"]) is not str:
            raise NativeToolCallError(NativeToolCallRejection.ARGUMENT_TYPE_OR_BYTES)
        try:
            if not 1 <= len(function["arguments"].encode("utf-8")) <= 4096:
                raise NativeToolCallError(NativeToolCallRejection.ARGUMENT_TYPE_OR_BYTES)
            arguments = json.loads(
                function["arguments"], object_pairs_hook=_object, parse_constant=_constant
            )
        except NativeToolCallError:
            raise
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise NativeToolCallError(NativeToolCallRejection.JSON_MALFORMED) from None
        calls.append(
            NativeRepositoryToolCall(call["id"], _arguments(function["name"], arguments, head_sha))
        )
        ids.add(call["id"])
    return tuple(calls)


__all__ = [
    "NATIVE_REPOSITORY_TOOLS_JSON",
    "NativeRepositoryToolCall",
    "NativeToolCallError",
    "NativeToolCallRejection",
    "parse_native_tool_calls",
]
