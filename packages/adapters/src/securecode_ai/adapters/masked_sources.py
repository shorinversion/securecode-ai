"""Model-visible views of files whose detected secret values are masked.

A file with a detected secret is still useful for analysis: the vulnerable query or
command may sit next to the credential. Its source is served with every secret value
replaced by the detector's redaction marker; raw evidence windows of such files stay
unavailable, so no tool can return the value itself.
"""

from __future__ import annotations

from collections.abc import Mapping

from securecode_ai.core.tool_policy import (
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryToolOutput,
    RepositoryToolWindow,
    RepositoryView,
)


def read_masked_range(
    source: str, arguments: ReadRangeArguments, *, window: RepositoryToolWindow
) -> RepositoryToolOutput:
    """Serve one line range of a masked source with the sealed view's line rules."""
    parts = source.split("\n")
    lines = [part + "\n" for part in parts[:-1]] + [parts[-1]]
    if arguments.end_line > len(lines):
        raise ValueError("repository range is outside source")
    content = "".join(lines[arguments.start_line - 1 : arguments.end_line])
    size = len(content.encode("utf-8"))
    if (
        type(window) is not RepositoryToolWindow
        or size > window.remaining_bytes
        or size > window.remaining_tokens
    ):
        raise ValueError("repository output exceeds budget")
    return RepositoryToolOutput.build(
        content, token_count=size, item_count=arguments.end_line - arguments.start_line + 1
    )


class MaskedSourceView:
    """Delegate to a repository view, serving listed files from their masked source."""

    __slots__ = ("_backend", "_head", "_masked")

    def __init__(self, backend: RepositoryView, masked: Mapping[str, str], *, head_sha: str):
        self._backend = backend
        self._masked = dict(masked)
        self._head = head_sha

    def read_range(
        self, arguments: ReadRangeArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        source = self._masked.get(arguments.path)
        if source is None:
            return self._backend.read_range(arguments, window=window)
        if arguments.head_sha != self._head:
            raise ValueError("repository revision mismatch")
        return read_masked_range(source, arguments, window=window)

    def read_evidence(
        self, arguments: ReadEvidenceArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        return self._backend.read_evidence(arguments, window=window)

    def list_paths(
        self, arguments: ListPathsArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        return self._backend.list_paths(arguments, window=window)

    def lookup_symbol(
        self, arguments: LookupSymbolArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        return self._backend.lookup_symbol(arguments, window=window)
