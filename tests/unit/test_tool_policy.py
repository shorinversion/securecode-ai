"""P3.7 fail-closed repository tool policy tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from securecode_ai.contracts import RepositoryTool
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    InstructionAuthority,
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryToolBudget,
    RepositoryToolGuard,
    RepositoryToolOutput,
    RepositoryToolRequest,
    RepositoryToolScope,
    RepositoryToolWindow,
    ToolDecision,
    ToolOutcome,
    ToolReason,
)

HEAD = "1" * 40


class RecordingView:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.output = RepositoryToolOutput.build("safe", token_count=1, item_count=1)

    def list_paths(
        self, arguments: ListPathsArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        self.calls.append(f"list:{arguments.prefix}:{window.remaining_bytes}")
        return self.output

    def lookup_symbol(
        self, arguments: LookupSymbolArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        self.calls.append(f"symbol:{arguments.symbol}:{window.remaining_tokens}")
        return self.output

    def read_range(
        self, arguments: ReadRangeArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        self.calls.append(f"range:{arguments.path}:{window.remaining_bytes}")
        return self.output

    def read_evidence(
        self, arguments: ReadEvidenceArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        self.calls.append(f"evidence:{arguments.evidence_id}:{window.remaining_tokens}")
        return self.output


def _guard(
    *, max_calls: int = 4, max_bytes: int = 100, max_tokens: int = 10
) -> RepositoryToolGuard:
    return RepositoryToolGuard(
        scope=RepositoryToolScope(
            tenant_id="tenant-a",
            repository_id="repo-a",
            head_sha=HEAD,
            path_prefixes=("packages",),
            evidence_ids=("evidence-1",),
        ),
        budget=RepositoryToolBudget(
            max_calls=max_calls,
            max_bytes=max_bytes,
            max_tokens=max_tokens,
        ),
    )


def _request(tool: RepositoryTool, arguments: object) -> RepositoryToolRequest:
    return RepositoryToolRequest(tool=tool, arguments=arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("tool", "arguments", "prefix"),
    [
        (
            RepositoryTool.LIST_PATHS,
            ListPathsArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "packages", 10),
            "list:",
        ),
        (
            RepositoryTool.LOOKUP_SYMBOL,
            LookupSymbolArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "Guard", "packages/core"),
            "symbol:",
        ),
        (
            RepositoryTool.READ_RANGE,
            ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "packages/core/a.py", 1, 5),
            "range:",
        ),
        (
            RepositoryTool.READ_EVIDENCE,
            ReadEvidenceArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "evidence-1"),
            "evidence:",
        ),
    ],
)
def test_complete_allowlist_dispatches_read_only_typed_operations(
    tool: RepositoryTool, arguments: object, prefix: str
) -> None:
    backend = RecordingView()
    result = _guard().dispatch(_request(tool, arguments), backend)
    assert result.output is backend.output
    assert result.output.instruction_authority is InstructionAuthority.NONE
    assert result.receipt.decision is ToolDecision.ALLOW
    assert result.receipt.outcome is ToolOutcome.SUCCEEDED
    assert backend.calls[0].startswith(prefix)


@pytest.mark.parametrize(
    "candidate_request",
    [
        object(),
        _request(RepositoryTool.READ_RANGE, object()),
        _request(
            RepositoryTool.READ_RANGE,
            ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, "2" * 40, "packages/a.py", 1, 2),
        ),
        _request(
            RepositoryTool.READ_RANGE,
            ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "tests/a.py", 1, 2),
        ),
        _request(
            RepositoryTool.READ_EVIDENCE,
            ReadEvidenceArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "evidence-2"),
        ),
    ],
)
def test_malformed_unknown_or_out_of_scope_request_has_zero_backend_effect(
    candidate_request: object,
) -> None:
    backend = RecordingView()
    result = _guard().dispatch(candidate_request, backend)
    assert result.output is None
    assert result.receipt.decision is ToolDecision.DENY
    assert result.receipt.outcome is ToolOutcome.NON_SUCCESS
    assert backend.calls == []


def test_budget_is_cumulative_and_cannot_be_widened_by_a_request() -> None:
    backend = RecordingView()
    guard = _guard(max_calls=1)
    request = _request(
        RepositoryTool.READ_RANGE,
        ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "packages/a.py", 1, 2),
    )
    assert guard.dispatch(request, backend).receipt.outcome is ToolOutcome.SUCCEEDED
    denied = guard.dispatch(request, backend)
    assert denied.receipt.reason is ToolReason.BUDGET_EXHAUSTED
    assert len(backend.calls) == 1


def test_oversized_backend_result_is_not_released_and_exhausts_budget() -> None:
    backend = RecordingView()
    backend.output = RepositoryToolOutput.build("0123456789", token_count=6, item_count=1)
    result = _guard(max_bytes=5, max_tokens=5).dispatch(
        _request(
            RepositoryTool.READ_RANGE,
            ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "packages/a.py", 1, 2),
        ),
        backend,
    )
    assert result.output is None
    assert result.receipt.reason is ToolReason.BUDGET_EXHAUSTED


def test_backend_failure_is_safe_non_success_without_retry_or_echo() -> None:
    class BrokenView(RecordingView):
        def read_range(
            self, arguments: ReadRangeArguments, *, window: RepositoryToolWindow
        ) -> RepositoryToolOutput:
            self.calls.append("attempt")
            raise RuntimeError("untrusted source secret")

    backend = BrokenView()
    result = _guard().dispatch(
        _request(
            RepositoryTool.READ_RANGE,
            ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "packages/a.py", 1, 2),
        ),
        backend,
    )
    assert result.receipt.reason is ToolReason.BACKEND_FAILURE
    assert "secret" not in repr(result.receipt)
    assert backend.calls == ["attempt"]


def test_scope_and_arguments_are_immutable() -> None:
    arguments = ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "packages/a.py", 1, 2)
    with pytest.raises(FrozenInstanceError):
        arguments.path = "tests/a.py"  # type: ignore[misc]


def test_windows_alternate_data_stream_selector_is_not_a_repository_path() -> None:
    """A scoped file path must not authorize an NTFS alternate data stream."""

    with pytest.raises(ValueError):
        ReadRangeArguments(
            TOOL_ARGUMENT_SCHEMA_VERSION,
            HEAD,
            "packages/a.py:secret",
            1,
            2,
        )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: ListPathsArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "../packages", 1),
        lambda: ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "packages\\a.py", 1, 2),
        lambda: ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "packages/a.py", 5, 2),
        lambda: ReadEvidenceArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, "bad id"),
    ],
)
def test_argument_constructors_reject_traversal_and_malformed_values(factory: object) -> None:
    with pytest.raises(ValueError):
        factory()  # type: ignore[operator]
