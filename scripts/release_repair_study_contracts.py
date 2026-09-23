"""Shared contracts for the local release repair study."""

from __future__ import annotations

import hashlib

_LANGUAGE_SUFFIX = {
    "python": ".py",
    "javascript-typescript": ".ts",
    "go": ".go",
}
_MAX_PATCHES_PER_CASE = 50
_GIT_TIMEOUT_SECONDS = 15


class RepairStudyError(ValueError):
    """Fixed, non-echo failure for an invalid repair-study run."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


__all__ = ["RepairStudyError", "sha256"]
