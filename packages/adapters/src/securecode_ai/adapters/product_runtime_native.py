"""Authorized product-model ports built on the existing provider harness."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field

from securecode_ai.contracts import (
    DataClass,
)
from securecode_ai.core.model_discovery import (
    RepositoryToolSession,
)
from securecode_ai.core.tool_policy import (
    GuardedToolResult,
    RepositoryToolRequest,
    ToolOutcome,
)

from .native_repository_tools import NativeRepositoryToolCall, parse_native_tool_calls


@dataclass(frozen=True, slots=True)
class NativeRepositoryBatch:
    """Nonterminal guarded native selections; source-bearing results stay ephemeral."""

    calls: tuple[NativeRepositoryToolCall, ...] = field(repr=False)
    results: tuple[GuardedToolResult, ...] = field(repr=False)

    @property
    def is_complete(self) -> bool:
        return (
            bool(self.calls)
            and len(self.calls) == len(self.results)
            and all(
                result.receipt.outcome is ToolOutcome.SUCCEEDED and result.output is not None
                for result in self.results
            )
        )


def dispatch_native_repository_calls(
    value: object,
    *,
    head_sha: str,
    tools: RepositoryToolSession,
    max_calls: int = 4,
    before_dispatch: Callable[[], object] | None = None,
    result_cache: dict[RepositoryToolRequest, GuardedToolResult] | None = None,
) -> NativeRepositoryBatch:
    """Validate the entire native batch before dispatching through the existing guard."""
    if type(tools) is not RepositoryToolSession:
        raise ValueError("native repository session is invalid")
    calls = parse_native_tool_calls(value, head_sha=head_sha, max_calls=max_calls)
    if before_dispatch is not None and not callable(before_dispatch):
        raise ValueError("native repository deadline guard is invalid")
    results = []
    for call in calls:
        cached = None if result_cache is None else result_cache.get(call.request)
        if cached is not None:
            results.append(cached)
            continue
        if before_dispatch is not None:
            before_dispatch()
        result = tools.dispatch(call.request)
        results.append(result)
        if result_cache is not None:
            result_cache[call.request] = result
    return NativeRepositoryBatch(calls, tuple(results))


def native_repository_history(
    batch: NativeRepositoryBatch,
    *,
    head_sha: str,
    data_class: DataClass = DataClass.CONFIDENTIAL_SOURCE,
) -> list[dict[str, object]]:
    """Prepare quoted successful tool results; incomplete batches stop before another send."""
    if (
        type(batch) is not NativeRepositoryBatch
        or type(data_class) is not DataClass
        or data_class not in {DataClass.PUBLIC, DataClass.CONFIDENTIAL_SOURCE}
        or not batch.is_complete
        or any(call.request.arguments.head_sha != head_sha for call in batch.calls)
    ):
        raise ValueError("native repository batch is unavailable")
    wire_calls = [
        {
            "id": call.call_id,
            "type": "function",
            "function": {
                "name": call.request.tool.value,
                "arguments": json.dumps(
                    asdict(call.request.arguments),
                    sort_keys=True,
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ),
            },
        }
        for call in batch.calls
    ]
    history: list[dict[str, object]] = [
        {"role": "assistant", "content": None, "tool_calls": wire_calls}
    ]
    for call, result in zip(batch.calls, batch.results, strict=True):
        if result.output is None:
            raise ValueError("native repository result is unavailable")
        history.append(
            {
                "role": "tool",
                "tool_call_id": call.call_id,
                "content": json.dumps(
                    {
                        "instruction_authority": "NONE",
                        "head_sha": head_sha,
                        "data_class": data_class.value,
                        "content": result.output.content,
                    },
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ),
            }
        )
    return history
