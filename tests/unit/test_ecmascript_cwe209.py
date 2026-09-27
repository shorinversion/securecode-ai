"""Focused ECMAScript CWE-209 discovery behavior."""

from __future__ import annotations

import hashlib

import pytest
from securecode_ai.adapters.cst import build_typescript_symbol_index
from securecode_ai.adapters.ecmascript_cwe209 import (
    EcmaScriptCwe209ScanError,
    EcmaScriptCwe209ScanErrorCode,
    scan_typescript_cwe209,
)
from securecode_ai.core import SymbolIndex


def _index(source: bytes) -> SymbolIndex:
    return build_typescript_symbol_index(
        repository_id="example/ecmascript-cwe209",
        revision="d" * 40,
        path="src/handler.ts",
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )


def test_request_derived_value_reaching_response_is_reported() -> None:
    source = b"function send(req: Request, res: Response) { const value = req.query.item; res.send(value); }"

    result = scan_typescript_cwe209(_index(source))

    assert tuple(signal.cwe for signal in result.signals) == ("CWE-209",)


def test_constant_response_value_is_not_reported() -> None:
    source = b'function send(res: Response) { const value = "safe"; res.send(value); }'

    result = scan_typescript_cwe209(_index(source))

    assert result.signals == ()


def test_new_expression_receiver_fails_closed_instead_of_repeating_same_ast_node() -> None:
    source = b"function send(req: Request) { new Service().send(req.query.token); }"

    with pytest.raises(EcmaScriptCwe209ScanError) as error:
        scan_typescript_cwe209(_index(source))

    assert error.value.code is EcmaScriptCwe209ScanErrorCode.ANALYSIS_UNAVAILABLE
