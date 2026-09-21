"""Production source-view checks with real sealed scanner-independent indexes."""

import hashlib
import json
from collections.abc import Callable

import pytest
from securecode_ai.adapters.cst import (
    build_go_symbol_index,
    build_javascript_symbol_index,
    build_python_symbol_index,
    build_typescript_symbol_index,
)
from securecode_ai.adapters.repository_view import SealedRepositoryView
from securecode_ai.core.symbols import SymbolIndex
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION as VERSION,
)
from securecode_ai.core.tool_policy import (
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryToolWindow,
)

HEAD = "1" * 40
WINDOW = RepositoryToolWindow(10000, 10000)


def _index(
    source: bytes = b"def hello():\n    return 1\n",
    *,
    repository_id: str = "repo-a",
    revision: str = HEAD,
    path: str = "a.py",
) -> SymbolIndex:
    return build_python_symbol_index(
        repository_id=repository_id,
        revision=revision,
        path=path,
        source=source,
        content_sha256=hashlib.sha256(source).hexdigest(),
    )


def test_exact_partial_crlf_unicode_and_terminal_empty_rows() -> None:
    source = "# separator\u2028within row\r\nx = 1\r\n".encode()
    view = SealedRepositoryView((_index(source),))
    result = view.read_range(ReadRangeArguments(VERSION, HEAD, "a.py", 2, 3), window=WINDOW)
    assert result.content == "x = 1\r\n"
    assert result.content_sha256 == hashlib.sha256(b"x = 1\r\n").hexdigest()
    assert result.content_sha256 != hashlib.sha256(source).hexdigest()


def test_retained_bytes_and_symbols_ignore_caller_mutation() -> None:
    index = _index()
    view = SealedRepositoryView((index,))
    object.__setattr__(index, "source", b"poison")
    object.__setattr__(index.symbols[1], "name", "poison")
    assert (
        view.read_range(ReadRangeArguments(VERSION, HEAD, "a.py", 1, 1), window=WINDOW).content
        == "def hello():\n"
    )
    assert (
        json.loads(
            view.lookup_symbol(LookupSymbolArguments(VERSION, HEAD, "hello"), window=WINDOW).content
        )[0]["name"]
        == "hello"
    )
    with pytest.raises(ValueError):
        SealedRepositoryView((index,))


def test_mixed_identity_duplicate_paths_and_bad_evidence_rejected() -> None:
    with pytest.raises(ValueError):
        SealedRepositoryView((_index(), _index(path="b.py", revision="2" * 40)))
    with pytest.raises(ValueError):
        SealedRepositoryView((_index(), _index()))
    with pytest.raises(ValueError):
        SealedRepositoryView((_index(),), evidence=(("evidence-a", b"hi", "0" * 64),))


def test_stale_missing_out_of_range_and_budget_rejected() -> None:
    view = SealedRepositoryView((_index(),))
    for args in (
        ReadRangeArguments(VERSION, "2" * 40, "a.py", 1, 1),
        ReadRangeArguments(VERSION, HEAD, "a.py", 1, 99),
    ):
        with pytest.raises(ValueError):
            view.read_range(args, window=WINDOW)
    with pytest.raises(KeyError):
        view.read_range(ReadRangeArguments(VERSION, HEAD, "missing.py", 1, 1), window=WINDOW)
    with pytest.raises(ValueError):
        view.read_range(
            ReadRangeArguments(VERSION, HEAD, "a.py", 1, 1), window=RepositoryToolWindow(1, 100)
        )


def test_listing_never_silently_truncates_and_evidence_bytes_are_hashed() -> None:
    content = b"evidence text"
    view = SealedRepositoryView(
        (_index(), _index(path="b.py")),
        evidence=(("evidence-a", content, hashlib.sha256(content).hexdigest()),),
    )
    with pytest.raises(ValueError):
        view.list_paths(ListPathsArguments(VERSION, HEAD, "", 1), window=WINDOW)
    assert json.loads(
        view.list_paths(ListPathsArguments(VERSION, HEAD, "", 2), window=WINDOW).content
    ) == ["a.py", "b.py"]
    assert (
        view.read_evidence(
            ReadEvidenceArguments(VERSION, HEAD, "evidence-a"), window=WINDOW
        ).content
        == content.decode()
    )


@pytest.mark.parametrize(
    ("builder", "path", "source"),
    (
        (build_python_symbol_index, "empty.py", b""),
        (build_javascript_symbol_index, "empty.js", b""),
        (build_typescript_symbol_index, "empty.ts", b""),
        (build_go_symbol_index, "empty.go", b"package main\n"),
    ),
)
def test_all_languages_exposed_without_scanner_signals(
    builder: Callable[..., SymbolIndex], path: str, source: bytes
) -> None:
    index = builder(
        repository_id="repo-a",
        revision=HEAD,
        path=path,
        source=source,
        content_sha256=hashlib.sha256(source).hexdigest(),
    )
    view = SealedRepositoryView((index,))
    assert json.loads(
        view.list_paths(ListPathsArguments(VERSION, HEAD, "", 1), window=WINDOW).content
    ) == [path]
    assert (
        view.read_range(ReadRangeArguments(VERSION, HEAD, path, 1, 1), window=WINDOW).content
        == source.decode()
    )


def test_real_guard_dispatch_counts_exact_window_and_denies_second_call() -> None:
    from securecode_ai.core.tool_policy import (
        RepositoryTool,
        RepositoryToolBudget,
        RepositoryToolGuard,
        RepositoryToolRequest,
        RepositoryToolScope,
        ToolReason,
    )

    view = SealedRepositoryView((_index(),))
    guard = RepositoryToolGuard(
        scope=RepositoryToolScope("tenant-a", "repo-a", HEAD, ("a.py",), ()),
        budget=RepositoryToolBudget(1, 1000, 1000),
    )
    request = RepositoryToolRequest(
        RepositoryTool.READ_RANGE, ReadRangeArguments(VERSION, HEAD, "a.py", 1, 1)
    )
    result = guard.dispatch(request, view)
    assert result.output is not None
    assert result.output.content == "def hello():\n"
    assert result.receipt.bytes_used == len(result.output.content.encode())
    assert result.receipt.tokens_used == result.output.byte_count
    second = guard.dispatch(request, view)
    assert second.output is None
    assert second.receipt.reason is ToolReason.BUDGET_EXHAUSTED
