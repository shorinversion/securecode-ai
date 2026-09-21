"""Process-local, lock-linearized WorkflowRuntime adapter."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from securecode_ai.core import (
    RunExecutionIdentity,
    WorkflowDefinition,
    WorkflowRuntimeResult,
    WorkflowSnapshot,
    WorkflowTransitionEvent,
)

RuntimeClock = Callable[[], int]


def _monotonic_milliseconds() -> int:
    return time.monotonic_ns() // 1_000_000


@dataclass(slots=True)
class _RunRecord:
    identity: RunExecutionIdentity
    definition: WorkflowDefinition
    journal: list[WorkflowTransitionEvent]
    started_at_ms: int

    @property
    def snapshot(self) -> WorkflowSnapshot:
        return self.journal[-1].resulting_snapshot


@dataclass(frozen=True, slots=True)
class _Reservation:
    semantic_sha256: str
    result: WorkflowRuntimeResult
