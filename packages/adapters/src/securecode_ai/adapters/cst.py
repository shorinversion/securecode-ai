"""Bounded Python Tree-sitter adapter over caller-admitted source bytes."""

from __future__ import annotations

from securecode_ai.core import SymbolIndex
from securecode_ai.core.symbols import _build_symbol_index
from tree_sitter import Parser

from .cst_ecmascript import (
    build_javascript_symbol_index,
    build_typescript_symbol_index,
)
from .cst_go import build_go_symbol_index
from .cst_models import (
    DEFAULT_CST_LIMITS,
    CstAdapterError,
    CstAdapterErrorCode,
    CstLimits,
)
from .cst_python import _build_python_symbol_index

for _cst_type in (CstAdapterError, CstLimits):
    _cst_type.__module__ = __name__
del _cst_type


def build_python_symbol_index(
    *,
    repository_id: str,
    revision: str,
    path: str,
    content_sha256: str,
    source: bytes,
    language: str = "python",
    limits: CstLimits = DEFAULT_CST_LIMITS,
) -> SymbolIndex:
    """Parse Python through facade-owned compatibility injection points."""

    return _build_python_symbol_index(
        repository_id=repository_id,
        revision=revision,
        path=path,
        content_sha256=content_sha256,
        source=source,
        language=language,
        limits=limits,
        parser_factory=Parser,
        symbol_index_builder=_build_symbol_index,
    )


for _cst_builder in (
    build_go_symbol_index,
    build_javascript_symbol_index,
    build_typescript_symbol_index,
):
    _cst_builder.__module__ = __name__
del _cst_builder
__all__ = [
    "DEFAULT_CST_LIMITS",
    "CstAdapterError",
    "CstAdapterErrorCode",
    "CstLimits",
    "build_go_symbol_index",
    "build_javascript_symbol_index",
    "build_python_symbol_index",
    "build_typescript_symbol_index",
]
