"""Small state holders shared by the worker service loop."""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field, replace
from math import isfinite

from .protocol import WorkerCommand, WorkerJob

_MAX_VERSION = 2_147_483_647


@dataclass(slots=True)
class ActiveSession:
    job: WorkerJob
    sequence: int = 0
    heartbeat_attempt: int = 0
    last_heartbeat: float = field(default_factory=time.monotonic)
    control_plane_lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def apply(self, *, version: int, command: WorkerCommand, renewed: bool = False) -> None:
        if (
            type(version) is not int
            or not 1 <= version <= _MAX_VERSION
            or type(command) is not WorkerCommand
        ):
            raise ValueError("worker session update is invalid")
        current_version = self.job.version
        if version < current_version:
            return
        command_rank = {
            WorkerCommand.CONTINUE: 0,
            WorkerCommand.CANCEL: 1,
            WorkerCommand.SUPERSEDE: 2,
        }
        current_command = self.job.command
        if version == current_version and command_rank[command] < command_rank[current_command]:
            return
        effective_command = (
            command
            if command_rank[command] >= command_rank[current_command]
            else current_command
        )
        self.job = replace(self.job, version=version, command=effective_command)
        if renewed:
            self.last_heartbeat = time.monotonic()


class Backoff:
    def __init__(self, initial: float, maximum: float) -> None:
        if (
            type(initial) not in {int, float}
            or type(maximum) not in {int, float}
            or not isfinite(initial)
            or not isfinite(maximum)
            or initial <= 0
            or maximum < initial
        ):
            raise ValueError("worker backoff settings are invalid")
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
        return min(self._maximum, ceiling * (0.8 + jitter * 0.4))


async def await_task_completion[T](task: asyncio.Task[T]) -> T:
    """Wait through repeated cancellation until a bounded background task exits."""

    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done():
                return task.result()


__all__ = ["ActiveSession", "Backoff", "await_task_completion"]
