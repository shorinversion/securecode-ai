"""Bounded read-only views of already admitted, authority-sealed source indexes.

The host must bind intake bytes to the actual revision before constructing indexes.
This adapter never reads a mutable checkout or treats parser metadata as Git proof.
"""

from __future__ import annotations

import copy
import hashlib
import json

from securecode_ai.core.symbols import SymbolIndex
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryToolOutput,
    RepositoryToolWindow,
)


class SealedRepositoryView:
    """Snapshot sealed source bytes, with Core guard owning external authorization."""

    __slots__ = ("_evidence", "_head", "_sources", "_symbols")

    def __init__(
        self,
        indexes: tuple[SymbolIndex, ...],
        *,
        evidence: tuple[tuple[str, bytes, str], ...] = (),
    ) -> None:
        if type(indexes) is not tuple or not indexes or len(indexes) > 4096:
            raise ValueError("source catalogue is invalid")
        sources: dict[str, str] = {}
        symbols: list[tuple[str, str, str, int, int]] = []
        identity: tuple[str, str] | None = None
        total = 0
        for supplied in indexes:
            if type(supplied) is not SymbolIndex:
                raise ValueError("source catalogue is invalid")
            index = copy.deepcopy(supplied)
            index.__post_init__()
            current = (index.repository_id, index.revision)
            if (identity is not None and identity != current) or index.path in sources:
                raise ValueError("source catalogue identity is invalid")
            identity = current
            total += len(index.source)
            if total > 64 * 1024 * 1024:
                raise ValueError("source catalogue exceeds budget")
            sources[index.path] = index.source.decode("utf-8", errors="strict")
            for symbol in index.symbols:
                symbols.append(
                    (
                        index.path,
                        symbol.name,
                        symbol.qualified_name,
                        symbol.declaration.start_point.row + 1,
                        symbol.declaration.end_point.row + 1,
                    )
                )
                if len(symbols) > 100_000:
                    raise ValueError("symbol catalogue exceeds budget")
        if type(evidence) is not tuple or len(evidence) > 4096:
            raise ValueError("evidence catalogue is invalid")
        stored: dict[str, str] = {}
        assert identity is not None
        for entry in evidence:
            if type(entry) is not tuple or len(entry) != 3:
                raise ValueError("evidence catalogue is invalid")
            evidence_id, content, expected_hash = entry
            ReadEvidenceArguments(TOOL_ARGUMENT_SCHEMA_VERSION, identity[1], evidence_id)
            if (
                type(content) is not bytes
                or type(expected_hash) is not str
                or hashlib.sha256(content).hexdigest() != expected_hash
                or evidence_id in stored
            ):
                raise ValueError("evidence catalogue is invalid")
            total += len(content)
            if total > 64 * 1024 * 1024:
                raise ValueError("evidence catalogue exceeds budget")
            stored[evidence_id] = content.decode("utf-8", errors="strict")
        self._head = identity[1]
        self._sources = sources
        self._symbols = tuple(sorted(symbols))
        self._evidence = stored

    def _head_matches(self, head: str) -> None:
        if head != self._head:
            raise ValueError("repository revision mismatch")

    @staticmethod
    def _output(content: str, items: int, window: RepositoryToolWindow) -> RepositoryToolOutput:
        size = len(content.encode("utf-8"))
        # UTF-8 byte count is a conservative token ceiling, not a tokenizer claim.
        if (
            type(window) is not RepositoryToolWindow
            or type(window.remaining_bytes) is not int
            or type(window.remaining_tokens) is not int
            or size > window.remaining_bytes
            or size > window.remaining_tokens
        ):
            raise ValueError("repository output exceeds budget")
        return RepositoryToolOutput.build(content, token_count=size, item_count=items)

    def list_paths(
        self, arguments: ListPathsArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        if type(arguments) is not ListPathsArguments:
            raise ValueError("repository arguments are invalid")
        arguments.__post_init__()
        self._head_matches(arguments.head_sha)
        paths = [
            path
            for path in sorted(self._sources)
            if not arguments.prefix
            or path == arguments.prefix
            or path.startswith(arguments.prefix + "/")
        ]
        if len(paths) > arguments.max_entries:
            raise ValueError("repository listing is incomplete")
        return self._output(json.dumps(paths, ensure_ascii=True), len(paths), window)

    def lookup_symbol(
        self, arguments: LookupSymbolArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        if type(arguments) is not LookupSymbolArguments:
            raise ValueError("repository arguments are invalid")
        arguments.__post_init__()
        self._head_matches(arguments.head_sha)
        matches = [
            {"path": path, "name": name, "qualified_name": qualified, "start": start, "end": end}
            for path, name, qualified, start, end in self._symbols
            if arguments.symbol in (name, qualified)
            and (arguments.path is None or path == arguments.path)
        ]
        return self._output(json.dumps(matches, ensure_ascii=True), len(matches), window)

    def read_range(
        self, arguments: ReadRangeArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        if type(arguments) is not ReadRangeArguments:
            raise ValueError("repository arguments are invalid")
        arguments.__post_init__()
        self._head_matches(arguments.head_sha)
        source = self._sources[arguments.path]
        # LF defines parser rows. Unicode separators must not introduce extra rows.
        # Preserve exact CRLF bytes, Unicode separators and terminal empty rows.
        parts = source.split("\n")
        lines = [part + "\n" for part in parts[:-1]] + [parts[-1]]
        if arguments.end_line > len(lines):
            raise ValueError("repository range is outside source")
        return self._output(
            "".join(lines[arguments.start_line - 1 : arguments.end_line]),
            arguments.end_line - arguments.start_line + 1,
            window,
        )

    def read_evidence(
        self, arguments: ReadEvidenceArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        if type(arguments) is not ReadEvidenceArguments:
            raise ValueError("repository arguments are invalid")
        arguments.__post_init__()
        self._head_matches(arguments.head_sha)
        return self._output(self._evidence[arguments.evidence_id], 1, window)
