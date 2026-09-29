"""Focused ECMAScript CWE-521 weak password requirement behavior."""

from __future__ import annotations

import hashlib

import pytest
from securecode_ai.adapters.cst import build_javascript_symbol_index
from securecode_ai.adapters.ecmascript_cwe521 import (
    EcmaScriptCwe521Operation,
    scan_javascript_cwe521,
)
from securecode_ai.core import SymbolIndex


def _index(source: bytes) -> SymbolIndex:
    return build_javascript_symbol_index(
        repository_id="example/ecmascript-cwe521",
        revision="e" * 40,
        path="src/password.js",
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )


def _operations(source: bytes) -> tuple[EcmaScriptCwe521Operation, ...]:
    return tuple(signal.operation for signal in scan_javascript_cwe521(_index(source)).signals)


@pytest.mark.parametrize(
    "source",
    [
        b"const passwordSchema = z.string().min(4);\n",
        b"const passwordPolicy = { minLength: 6 };\n",
    ],
)
def test_weak_password_minimum_is_reported(source: bytes) -> None:
    assert EcmaScriptCwe521Operation.WEAK_MINIMUM_LENGTH in _operations(source)


@pytest.mark.parametrize(
    "source",
    [
        b"const passwordSchema = z.string().min(12);\n",
        b"const passwordSchema = z.string().min(4).min(12);\n",
        b"const passwordPolicy = { minLength: 6, minimumLength: 12 };\n",
    ],
)
def test_accepted_password_minimum_in_the_same_policy_is_not_reported(source: bytes) -> None:
    assert EcmaScriptCwe521Operation.WEAK_MINIMUM_LENGTH not in _operations(source)
