"""Small state holders shared by the worker service loop."""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field, replace

from .protocol import WorkerCommand, WorkerJob


@dataclass(slots=True)
class ActiveSession:
    job: WorkerJob
    sequence: int = 0
    heartbeat_attempt: int = 0
    last_heartbeat: float = field(default_factory=time.monotonic)

    def apply(self, *, version: int, command: WorkerCommand, renewed: bool = False) -> None:
        self.job = replace(self.job, version=version, command=command)
        if renewed:
            self.last_heartbeat = time.monotonic()


class Backoff:
    def __init__(self, initial: float, maximum: float) -> None:
        self._initial = initial
        self._maximum = maximum
        self._failures = 0

    def reset(self) -> None:
        self._failures = 0

    def next_delay(self) -> float:
        growth: float = 2.0 ** min(self._failures, 12)
        ceiling: float = min(self._maximum, self._initial * growth)
        self._failures += 1
        jitter_units = int.from_bytes(os.urandom(3), "big") % 1_000_000
        jitter: float = jitter_units / 1_000_000
        return ceiling * (0.8 + jitter * 0.4)


async def await_task_completion[T](task: asyncio.Task[T]) -> T:
    """Wait through repeated cancellation until a bounded background task exits."""

    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done():
                return task.result()


__all__ = ["ActiveSession", "Backoff", "await_task_completion"]
