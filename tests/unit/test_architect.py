"""Focused P4.4 path, symbol, and structured-candidate boundary tests."""

from __future__ import annotations

import pytest
from securecode_ai.core.architect import (
    ArchitectErrorCode,
    ArchitectPatchError,
    TouchedSymbol,
    _safe_path,
    _validate_diff,
    _validate_symbols,
)

HASH = "a" * 64


def _symbol(path: str = "app.py") -> TouchedSymbol:
    return TouchedSymbol(path, "function", "get_user", 1, 5, HASH)


def test_minimal_unified_diff_and_symbol_are_bounded() -> None:
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"
    paths = _validate_diff(diff, len(diff.encode()))
    assert paths == ("app.py",)
    assert _validate_symbols((_symbol(),), paths) == (_symbol(),)


@pytest.mark.parametrize(
    "path",
    ["../outside.txt", "/etc/passwd", "C:/outside.txt", "src\\app.py", "specs/policy.md"],
)
def test_traversal_absolute_and_protected_paths_rejected(path: str) -> None:
    with pytest.raises(ArchitectPatchError) as error:
        _validate_diff(f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-x\n+y\n", 64)
    assert error.value.code in {
        ArchitectErrorCode.PATH_TRAVERSAL,
        ArchitectErrorCode.PATH_FORBIDDEN,
    }
    assert _safe_path(path) is None or path.startswith("specs/")


def test_malformed_or_oversized_diff_is_rejected() -> None:
    with pytest.raises(ArchitectPatchError) as malformed:
        _validate_diff("not a diff", 10)
    assert malformed.value.code is ArchitectErrorCode.DIFF_INVALID
    with pytest.raises(ArchitectPatchError) as oversized:
        _validate_diff("x", 131_073)
    assert oversized.value.code is ArchitectErrorCode.DIFF_TOO_LARGE


def test_symbol_path_must_be_in_diff_and_ordered() -> None:
    with pytest.raises(ArchitectPatchError) as missing:
        _validate_symbols((_symbol("other.py"),), ("app.py",))
    assert missing.value.code is ArchitectErrorCode.SYMBOL_SET_INVALID
    with pytest.raises(ArchitectPatchError):
        _validate_symbols((_symbol("z.py"), _symbol("app.py")), ("app.py", "z.py"))
