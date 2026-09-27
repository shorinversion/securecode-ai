"""Fail-closed policy boundary for bounded read-only repository tools."""

from __future__ import annotations

import hashlib
import re
from threading import RLock
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from securecode_ai.contracts import RepositoryTool as RepositoryTool

from .injection_boundary import InstructionAuthority

TOOL_ARGUMENT_SCHEMA_VERSION: Final = "0.1.0"
_SHA40: Final = re.compile(r"[0-9a-f]{40}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")


class ToolDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class ToolOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    NON_SUCCESS = "NON_SUCCESS"


class ToolReason(StrEnum):
    AUTHORIZED = "AUTHORIZED"
    SUCCEEDED = "SUCCEEDED"
    INVALID_REQUEST = "INVALID_REQUEST"
    UNKNOWN_TOOL = "UNKNOWN_TOOL"
    SCHEMA_VERSION_MISMATCH = "SCHEMA_VERSION_MISMATCH"
    REVISION_SCOPE_MISMATCH = "REVISION_SCOPE_MISMATCH"
    RESOURCE_SCOPE_MISMATCH = "RESOURCE_SCOPE_MISMATCH"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    BACKEND_FAILURE = "BACKEND_FAILURE"
    INVALID_RESULT = "INVALID_RESULT"


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 128
        and value[0].isascii()
        and value[0].isalnum()
        and all(
            character.isascii() and (character.isalnum() or character in "._:-")
            for character in value
        )
    )


def _valid_path(value: object, *, allow_empty: bool = False) -> bool:
    if type(value) is not str:
        return False
    if not value:
        return allow_empty
    if value.startswith("/") or "\\" in value or value.endswith("/"):
        return False
    if len(value) >= 2 and value[0].isascii() and value[0].isalpha() and value[1] == ":":
        return False
    parts = value.split("/")
    return all(
        part
        and part not in {".", ".."}
        # A colon in a Windows path component selects an NTFS alternate data
        # stream (for example ``source.py:secret``), which is outside the
        # repository file named by the scope.  Repository paths are portable
        # POSIX-style names at this boundary, so reject that selector before a
        # backend can interpret it with filesystem semantics.
        and ":" not in part
        and unicodedata.normalize("NFC", part) == part
        and not any(ord(character) < 32 or ord(character) == 127 for character in part)
        for part in parts
    )


def _require_common(schema_version: object, head_sha: object) -> None:
    if schema_version != TOOL_ARGUMENT_SCHEMA_VERSION:
        raise ValueError("repository tool argument schema is unsupported")
    if type(head_sha) is not str or _SHA40.fullmatch(head_sha) is None:
        raise ValueError("repository tool revision is invalid")


@dataclass(frozen=True, slots=True)
class ListPathsArguments:
    schema_version: str
    head_sha: str
    prefix: str
    max_entries: int

    def __post_init__(self) -> None:
        _require_common(self.schema_version, self.head_sha)
        if not _valid_path(self.prefix, allow_empty=True):
            raise ValueError("list_paths arguments are invalid")
        if type(self.max_entries) is not int or not 1 <= self.max_entries <= 4096:
            raise ValueError("list_paths arguments are invalid")


@dataclass(frozen=True, slots=True)
class LookupSymbolArguments:
    schema_version: str
    head_sha: str
    symbol: str
    path: str | None = None

    def __post_init__(self) -> None:
        _require_common(self.schema_version, self.head_sha)
        if type(self.symbol) is not str or not 1 <= len(self.symbol.encode("utf-8")) <= 512:
            raise ValueError("lookup_symbol arguments are invalid")
        if any(ord(character) < 32 or ord(character) == 127 for character in self.symbol):
            raise ValueError("lookup_symbol arguments are invalid")
        if self.path is not None and not _valid_path(self.path):
            raise ValueError("lookup_symbol arguments are invalid")


@dataclass(frozen=True, slots=True)
class ReadRangeArguments:
    schema_version: str
    head_sha: str
    path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        _require_common(self.schema_version, self.head_sha)
        if not _valid_path(self.path):
            raise ValueError("read_range arguments are invalid")
        if (
            type(self.start_line) is not int
            or type(self.end_line) is not int
            or self.start_line < 1
            or self.end_line < self.start_line
            or self.end_line - self.start_line >= 2000
        ):
            raise ValueError("read_range arguments are invalid")


@dataclass(frozen=True, slots=True)
class ReadEvidenceArguments:
    schema_version: str
    head_sha: str
    evidence_id: str

    def __post_init__(self) -> None:
        _require_common(self.schema_version, self.head_sha)
        if not _valid_identifier(self.evidence_id):
            raise ValueError("read_evidence arguments are invalid")


RepositoryToolArguments = (
    ListPathsArguments | LookupSymbolArguments | ReadRangeArguments | ReadEvidenceArguments
)


@dataclass(frozen=True, slots=True)
class RepositoryToolRequest:
    tool: RepositoryTool
    arguments: RepositoryToolArguments


@dataclass(frozen=True, slots=True)
class RepositoryToolScope:
    tenant_id: str
    repository_id: str
    head_sha: str
    path_prefixes: tuple[str, ...]
    evidence_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _valid_identifier(self.tenant_id) or not _valid_identifier(self.repository_id):
            raise ValueError("repository tool scope is invalid")
        if type(self.head_sha) is not str or _SHA40.fullmatch(self.head_sha) is None:
            raise ValueError("repository tool scope is invalid")
        if (
            type(self.path_prefixes) is not tuple
            or any(not _valid_path(path) for path in self.path_prefixes)
            or self.path_prefixes != tuple(sorted(set(self.path_prefixes)))
            or type(self.evidence_ids) is not tuple
            or any(not _valid_identifier(item) for item in self.evidence_ids)
            or self.evidence_ids != tuple(sorted(set(self.evidence_ids)))
        ):
            raise ValueError("repository tool scope is invalid")


@dataclass(frozen=True, slots=True)
class RepositoryToolBudget:
    max_calls: int
    max_bytes: int
    max_tokens: int

    def __post_init__(self) -> None:
        if any(
            type(value) is not int or value < 0
            for value in (self.max_calls, self.max_bytes, self.max_tokens)
        ) or self.max_bytes == 0 or self.max_tokens == 0:
            raise ValueError("repository tool budget is invalid")


@dataclass(frozen=True, slots=True)
class RepositoryToolOutput:
    content: str
    content_sha256: str
    byte_count: int
    token_count: int
    item_count: int
    instruction_authority: InstructionAuthority = InstructionAuthority.NONE

    def __post_init__(self) -> None:
        encoded = self.content.encode("utf-8") if type(self.content) is str else b""
        if (
            type(self.content) is not str
            or type(self.content_sha256) is not str
            or _SHA256.fullmatch(self.content_sha256) is None
            or hashlib.sha256(encoded).hexdigest() != self.content_sha256
            or type(self.byte_count) is not int
            or self.byte_count != len(encoded)
            or type(self.token_count) is not int
            or self.token_count < 0
            or type(self.item_count) is not int
            or self.item_count < 0
            or self.instruction_authority is not InstructionAuthority.NONE
        ):
            raise ValueError("repository tool output is invalid")

    @classmethod
    def build(cls, content: str, *, token_count: int, item_count: int) -> RepositoryToolOutput:
        encoded = content.encode("utf-8")
        return cls(
            content=content,
            content_sha256=hashlib.sha256(encoded).hexdigest(),
            byte_count=len(encoded),
            token_count=token_count,
            item_count=item_count,
        )


@dataclass(frozen=True, slots=True)
class RepositoryToolWindow:
    remaining_bytes: int
    remaining_tokens: int


class RepositoryView(Protocol):
    def list_paths(
        self, arguments: ListPathsArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput: ...

    def lookup_symbol(
        self, arguments: LookupSymbolArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput: ...

    def read_range(
        self, arguments: ReadRangeArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput: ...

    def read_evidence(
        self, arguments: ReadEvidenceArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput: ...


@dataclass(frozen=True, slots=True)
class RepositoryToolReceipt:
    sequence: int
    tool: str
    decision: ToolDecision
    outcome: ToolOutcome
    reason: ToolReason
    calls_used: int
    bytes_used: int
    tokens_used: int
    output_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class GuardedToolResult:
    output: RepositoryToolOutput | None
    receipt: RepositoryToolReceipt


_ARGUMENT_TYPES: Final = {
    RepositoryTool.LIST_PATHS: ListPathsArguments,
    RepositoryTool.LOOKUP_SYMBOL: LookupSymbolArguments,
    RepositoryTool.READ_RANGE: ReadRangeArguments,
    RepositoryTool.READ_EVIDENCE: ReadEvidenceArguments,
}


class RepositoryToolGuard:
    """Authorize and meter one immutable RepositoryView scope."""

    __slots__ = ("_budget", "_bytes", "_calls", "_lock", "_scope", "_sequence", "_tokens")

    def __init__(self, *, scope: RepositoryToolScope, budget: RepositoryToolBudget) -> None:
        self._scope = scope
        self._budget = budget
        self._calls = 0
        self._bytes = 0
        self._tokens = 0
        self._sequence = 0
        self._lock = RLock()

    def _receipt(
        self,
        *,
        tool: str,
        decision: ToolDecision,
        outcome: ToolOutcome,
        reason: ToolReason,
        output_sha256: str | None = None,
    ) -> GuardedToolResult:
        self._sequence += 1
        return GuardedToolResult(
            output=None,
            receipt=RepositoryToolReceipt(
                sequence=self._sequence,
                tool=tool,
                decision=decision,
                outcome=outcome,
                reason=reason,
                calls_used=self._calls,
                bytes_used=self._bytes,
                tokens_used=self._tokens,
                output_sha256=output_sha256,
            ),
        )

    def _path_allowed(self, path: str) -> bool:
        return any(
            path == root or path.startswith(f"{root}/") for root in self._scope.path_prefixes
        )

    def _scope_reason(self, arguments: RepositoryToolArguments) -> ToolReason | None:
        if arguments.schema_version != TOOL_ARGUMENT_SCHEMA_VERSION:
            return ToolReason.SCHEMA_VERSION_MISMATCH
        if arguments.head_sha != self._scope.head_sha:
            return ToolReason.REVISION_SCOPE_MISMATCH
        if isinstance(arguments, ListPathsArguments):
            return (
                None
                if arguments.prefix and self._path_allowed(arguments.prefix)
                else ToolReason.RESOURCE_SCOPE_MISMATCH
            )
        if isinstance(arguments, LookupSymbolArguments):
            return (
                None
                if arguments.path is not None and self._path_allowed(arguments.path)
                else ToolReason.RESOURCE_SCOPE_MISMATCH
            )
        if isinstance(arguments, ReadRangeArguments):
            return (
                None if self._path_allowed(arguments.path) else ToolReason.RESOURCE_SCOPE_MISMATCH
            )
        if isinstance(arguments, ReadEvidenceArguments):
            return (
                None
                if arguments.evidence_id in self._scope.evidence_ids
                else ToolReason.RESOURCE_SCOPE_MISMATCH
            )

    def dispatch(self, request: object, backend: RepositoryView) -> GuardedToolResult:
        # Tool sessions may receive concurrent model actions. Serialize policy
        # decisions and backend reads so calls, byte and token budgets share one
        # atomic accounting sequence.
        with self._lock:
            return self._dispatch_locked(request, backend)

    def _dispatch_locked(self, request: object, backend: RepositoryView) -> GuardedToolResult:
        if type(request) is not RepositoryToolRequest:
            return self._receipt(
                tool="unknown",
                decision=ToolDecision.DENY,
                outcome=ToolOutcome.NON_SUCCESS,
                reason=ToolReason.INVALID_REQUEST,
            )
        tool = request.tool
        if type(tool) is not RepositoryTool or tool not in _ARGUMENT_TYPES:
            return self._receipt(
                tool="unknown",
                decision=ToolDecision.DENY,
                outcome=ToolOutcome.NON_SUCCESS,
                reason=ToolReason.UNKNOWN_TOOL,
            )
        if type(request.arguments) is not _ARGUMENT_TYPES[tool]:
            return self._receipt(
                tool=tool.value,
                decision=ToolDecision.DENY,
                outcome=ToolOutcome.NON_SUCCESS,
                reason=ToolReason.INVALID_REQUEST,
            )
        reason = self._scope_reason(request.arguments)
        if reason is not None:
            return self._receipt(
                tool=tool.value,
                decision=ToolDecision.DENY,
                outcome=ToolOutcome.NON_SUCCESS,
                reason=reason,
            )
        if (
            self._calls >= self._budget.max_calls
            or self._bytes >= self._budget.max_bytes
            or self._tokens >= self._budget.max_tokens
        ):
            return self._receipt(
                tool=tool.value,
                decision=ToolDecision.DENY,
                outcome=ToolOutcome.NON_SUCCESS,
                reason=ToolReason.BUDGET_EXHAUSTED,
            )
        window = RepositoryToolWindow(
            remaining_bytes=self._budget.max_bytes - self._bytes,
            remaining_tokens=self._budget.max_tokens - self._tokens,
        )
        self._calls += 1
        arguments = request.arguments
        try:
            if tool is RepositoryTool.LIST_PATHS and isinstance(arguments, ListPathsArguments):
                output = backend.list_paths(arguments, window=window)
            elif tool is RepositoryTool.LOOKUP_SYMBOL and isinstance(
                arguments, LookupSymbolArguments
            ):
                output = backend.lookup_symbol(arguments, window=window)
            elif tool is RepositoryTool.READ_RANGE and isinstance(arguments, ReadRangeArguments):
                output = backend.read_range(arguments, window=window)
            elif tool is RepositoryTool.READ_EVIDENCE and isinstance(
                arguments, ReadEvidenceArguments
            ):
                output = backend.read_evidence(arguments, window=window)
            else:
                return self._receipt(
                    tool=tool.value,
                    decision=ToolDecision.DENY,
                    outcome=ToolOutcome.NON_SUCCESS,
                    reason=ToolReason.INVALID_REQUEST,
                )
        except Exception:
            return self._receipt(
                tool=tool.value,
                decision=ToolDecision.ALLOW,
                outcome=ToolOutcome.NON_SUCCESS,
                reason=ToolReason.BACKEND_FAILURE,
            )
        if type(output) is not RepositoryToolOutput:
            return self._receipt(
                tool=tool.value,
                decision=ToolDecision.ALLOW,
                outcome=ToolOutcome.NON_SUCCESS,
                reason=ToolReason.INVALID_RESULT,
            )
        if isinstance(arguments, ListPathsArguments) and output.item_count > arguments.max_entries:
            return self._receipt(
                tool=tool.value,
                decision=ToolDecision.ALLOW,
                outcome=ToolOutcome.NON_SUCCESS,
                reason=ToolReason.INVALID_RESULT,
            )
        self._bytes += output.byte_count
        self._tokens += output.token_count
        if self._bytes > self._budget.max_bytes or self._tokens > self._budget.max_tokens:
            return self._receipt(
                tool=tool.value,
                decision=ToolDecision.ALLOW,
                outcome=ToolOutcome.NON_SUCCESS,
                reason=ToolReason.BUDGET_EXHAUSTED,
            )
        successful = self._receipt(
            tool=tool.value,
            decision=ToolDecision.ALLOW,
            outcome=ToolOutcome.SUCCEEDED,
            reason=ToolReason.SUCCEEDED,
            output_sha256=output.content_sha256,
        )
        return GuardedToolResult(output=output, receipt=successful.receipt)


__all__ = [
    "TOOL_ARGUMENT_SCHEMA_VERSION",
    "GuardedToolResult",
    "InstructionAuthority",
    "ListPathsArguments",
    "LookupSymbolArguments",
    "ReadEvidenceArguments",
    "ReadRangeArguments",
    "RepositoryToolBudget",
    "RepositoryToolGuard",
    "RepositoryToolOutput",
    "RepositoryToolReceipt",
    "RepositoryToolRequest",
    "RepositoryToolScope",
    "RepositoryToolWindow",
    "RepositoryView",
    "ToolDecision",
    "ToolOutcome",
    "ToolReason",
]
