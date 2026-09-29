from __future__ import annotations

import hashlib

from securecode_ai.adapters import analyze_python_ast, build_python_symbol_index
from securecode_ai.adapters.python_cwe613 import (
    PythonCwe613Operation,
    PythonCwe613ScanResult,
    scan_python_cwe613,
)


def _scan(source: bytes) -> PythonCwe613ScanResult:
    index = build_python_symbol_index(
        repository_id="example/secure-repository",
        revision="a" * 40,
        path="src/settings.py",
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )
    return scan_python_cwe613(index, analyze_python_ast(index))


def test_browser_close_disabled_is_reported() -> None:
    result = _scan(b"app.config.update(SESSION_EXPIRE_AT_BROWSER_CLOSE=False)\n")

    assert [signal.operation for signal in result.signals] == [
        PythonCwe613Operation.SESSION_EXPIRATION_DISABLED
    ]


def test_browser_close_enabled_is_not_reported() -> None:
    result = _scan(b"app.config.update(SESSION_EXPIRE_AT_BROWSER_CLOSE=True)\n")

    assert result.signals == ()
