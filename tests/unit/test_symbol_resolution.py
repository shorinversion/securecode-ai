"""Exact symbol reference resolution over per-file symbol indexes."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from securecode_ai.adapters.cst import build_python_symbol_index
from securecode_ai.core import SourcePoint, SourceRange, SymbolIndex
from securecode_ai.core.symbols import (
    SymbolReference,
    SymbolResolution,
    SymbolTarget,
    resolve_symbol_reference,
)

REPOSITORY = "example/symbols"
REVISION = "a" * 40
CALLER = b"def caller():\n    return helper()\n"
CALLEE = b"def helper():\n    return 1\n"


def _index(path: str, source: bytes, *, revision: str = REVISION) -> SymbolIndex:
    return build_python_symbol_index(
        repository_id=REPOSITORY,
        revision=revision,
        path=path,
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )


def _reference(source: bytes, path: str, spelling: str, *, occurrence: int = 0) -> SymbolReference:
    start = -1
    for _ in range(occurrence + 1):
        start = source.index(spelling.encode(), start + 1)
    end = start + len(spelling.encode())
    row = source.count(b"\n", 0, start)
    column_start = start - (source.rfind(b"\n", 0, start) + 1)
    return SymbolReference(
        path=path,
        location=SourceRange(
            start,
            end,
            SourcePoint(row, column_start),
            SourcePoint(row, column_start + len(spelling.encode())),
        ),
        spelling=spelling,
    )


def test_reference_resolves_to_the_single_matching_declaration() -> None:
    indexes = (_index("caller.py", CALLER), _index("callee.py", CALLEE))
    reference = _reference(CALLER, "caller.py", "helper")

    resolution = resolve_symbol_reference(reference, indexes)

    target = resolution.target
    assert target is not None
    assert target.path == "callee.py"
    assert target.symbol.name == "helper"
    assert target.index_sha256 == indexes[1].index_sha256


def test_unknown_spelling_has_no_target() -> None:
    source = b"def caller():\n    return missing()\n"
    resolution = resolve_symbol_reference(
        _reference(source, "caller.py", "missing"), (_index("caller.py", source),)
    )

    assert resolution.targets == ()
    assert resolution.target is None


def test_duplicate_declarations_are_ambiguous_and_sorted() -> None:
    indexes = (
        _index("caller.py", CALLER),
        _index("b_callee.py", CALLEE),
        _index("a_callee.py", CALLEE),
    )
    resolution = resolve_symbol_reference(_reference(CALLER, "caller.py", "helper"), indexes)

    assert [target.path for target in resolution.targets] == ["a_callee.py", "b_callee.py"]
    assert resolution.target is None


def test_reference_must_match_the_indexed_source_text() -> None:
    indexes = (_index("caller.py", CALLER),)
    wrong = replace(_reference(CALLER, "caller.py", "helper"), spelling="import")

    with pytest.raises(ValueError, match="does not match source"):
        resolve_symbol_reference(wrong, indexes)


def test_reference_path_must_be_in_the_catalogue() -> None:
    with pytest.raises(ValueError, match="source is unavailable"):
        resolve_symbol_reference(
            _reference(CALLER, "other.py", "helper"), (_index("caller.py", CALLER),)
        )


def test_reference_beyond_the_source_is_rejected() -> None:
    index = _index("caller.py", CALLER)
    reference = _reference(CALLER, "caller.py", "helper")
    beyond = replace(
        reference,
        location=replace(reference.location, end_byte=len(CALLER) + 10),
    )

    with pytest.raises(ValueError):
        resolve_symbol_reference(beyond, (index,))


def test_catalogue_must_share_one_repository_revision_and_unique_paths() -> None:
    reference = _reference(CALLER, "caller.py", "helper")
    with pytest.raises(ValueError, match="catalogue is invalid"):
        resolve_symbol_reference(
            reference,
            (_index("caller.py", CALLER), _index("callee.py", CALLEE, revision="b" * 40)),
        )
    with pytest.raises(ValueError, match="catalogue is invalid"):
        resolve_symbol_reference(
            reference, (_index("caller.py", CALLER), _index("caller.py", CALLER))
        )


@pytest.mark.parametrize("indexes", [(), [], ("not-an-index",)])
def test_empty_or_malformed_index_collections_are_rejected(indexes: object) -> None:
    with pytest.raises(ValueError, match="request is invalid"):
        resolve_symbol_reference(_reference(CALLER, "caller.py", "helper"), indexes)  # type: ignore[arg-type]


def test_reference_value_objects_validate_their_fields() -> None:
    location = _reference(CALLER, "caller.py", "helper").location
    with pytest.raises(ValueError, match="reference is invalid"):
        SymbolReference(path="../escape.py", location=location, spelling="helper")
    with pytest.raises(ValueError, match="reference is invalid"):
        SymbolReference(path="caller.py", location=location, spelling="")
    with pytest.raises(ValueError, match="reference is invalid"):
        SymbolReference(path="caller.py", location=location, spelling="bad\x00name")
    with pytest.raises(ValueError, match="target is invalid"):
        SymbolTarget(path="caller.py", index_sha256="short", symbol=None)  # type: ignore[arg-type]
    reference = _reference(CALLER, "caller.py", "helper")
    with pytest.raises(ValueError, match="resolution is invalid"):
        SymbolResolution(reference=reference, targets=("x",))  # type: ignore[arg-type]
