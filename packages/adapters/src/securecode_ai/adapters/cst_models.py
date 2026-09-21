"""Bounded Python Tree-sitter adapter over caller-admitted source bytes."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from securecode_ai.core import (
    SourcePoint,
    SourceRange,
)
from tree_sitter import Node, Point

_PARSER_ID = "tree-sitter-python@0.25"
_MAX_CST_LIMIT_VALUES = (2_000_000, 250_000, 25_000, 512, 1_000)


class CstAdapterErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    LANGUAGE_UNSUPPORTED = "LANGUAGE_UNSUPPORTED"
    CONTENT_MISMATCH = "CONTENT_MISMATCH"
    SOURCE_ENCODING_INVALID = "SOURCE_ENCODING_INVALID"
    SOURCE_LIMIT = "SOURCE_LIMIT"
    NODE_LIMIT = "NODE_LIMIT"
    SYMBOL_LIMIT = "SYMBOL_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    DIAGNOSTIC_LIMIT = "DIAGNOSTIC_LIMIT"
    PARSER_FAILURE = "PARSER_FAILURE"


class CstAdapterError(RuntimeError):
    """Fixed, non-echoing CST boundary failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: CstAdapterErrorCode) -> None:
        if type(code) is not CstAdapterErrorCode:
            raise TypeError("CST adapter error code is invalid")
        self.code = code
        self.safe_message = "CST analysis failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class CstLimits:
    max_source_bytes: int = _MAX_CST_LIMIT_VALUES[0]
    max_nodes: int = _MAX_CST_LIMIT_VALUES[1]
    max_symbols: int = _MAX_CST_LIMIT_VALUES[2]
    max_depth: int = _MAX_CST_LIMIT_VALUES[3]
    max_diagnostics: int = _MAX_CST_LIMIT_VALUES[4]

    def __post_init__(self) -> None:
        values = (
            self.max_source_bytes,
            self.max_nodes,
            self.max_symbols,
            self.max_depth,
            self.max_diagnostics,
        )
        if any(
            type(value) is not int or value < 1 or value > ceiling
            for value, ceiling in zip(values, _MAX_CST_LIMIT_VALUES, strict=True)
        ):
            raise ValueError("CST limits are invalid")


DEFAULT_CST_LIMITS = CstLimits()


def _range(node: Node) -> SourceRange:
    return SourceRange(
        start_byte=node.start_byte,
        end_byte=node.end_byte,
        start_point=_point(node.start_point),
        end_point=_point(node.end_point),
    )


def _point(point: Point) -> SourcePoint:
    return SourcePoint(row=point.row, column=point.column)


def _module_name(path: str) -> str:
    value = path[:-4] if path.endswith(".pyi") else path[:-3]
    parts = value.split("/")
    if parts[-1] == "__init__" and len(parts) > 1:
        parts.pop()
    return ".".join(parts)


def _fail(code: CstAdapterErrorCode) -> CstAdapterError:
    return CstAdapterError(code)


def _decode_name(source: bytes, start_byte: int, end_byte: int) -> str:
    invalid = False
    try:
        name = source[start_byte:end_byte].decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        invalid = True
        name = ""
    if invalid:
        raise _fail(CstAdapterErrorCode.SOURCE_ENCODING_INVALID) from None
    return name
