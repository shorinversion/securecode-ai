"""Private dependency types for installed local product execution."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .git_snapshot import OfflineGitObjectReader


class _GitCommand(Protocol):
    def __call__(self, checkout: Path, executable: Path, *arguments: str) -> str: ...


class _ReaderFactory(Protocol):
    def __call__(
        self, *, objects_dir: Path, git_executable: Path, timeout_seconds: int = 10
    ) -> OfflineGitObjectReader: ...


__all__ = ["_GitCommand", "_ReaderFactory"]
