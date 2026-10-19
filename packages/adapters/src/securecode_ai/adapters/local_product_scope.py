"""The files an incremental run (``--base REV``) audits: those changed since the merge base.

The base is an operator-named revision; it is validated before any Git call, resolved to a
commit, and only the diff between its merge base with HEAD and HEAD selects files. Git runs
through the sealed helper of the runner, so a repository configuration cannot redirect it.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Final

from securecode_ai.core.tool_policy import TOOL_ARGUMENT_SCHEMA_VERSION, ReadRangeArguments

from .local_product_runner_config import (
    _BASE as BASE_PATTERN,
)
from .local_product_runner_config import (
    LocalProductScanScope,
    LocalProductUnavailableError,
)

_COMMIT: Final = re.compile(r"[0-9a-f]{40}\Z")

# ``run_git(*arguments)`` returns the stripped standard output of one sealed Git call and
# raises ``LocalProductUnavailableError("GIT_COMMAND_FAILED")`` when Git fails.
RunGit = Callable[..., str]


def valid_base(base: str) -> bool:
    return type(base) is str and BASE_PATTERN.fullmatch(base) is not None


def changed_paths_since(run_git: RunGit, base: str, head: str) -> LocalProductScanScope:
    """The scope of a run that audits what changed between ``base`` and ``head``.

    Raises ``LocalProductUnavailableError`` with a fixed reason: ``BASE_REVISION_INVALID``
    (the name does not resolve to a commit), ``BASE_NOT_RELATED`` (no common ancestor),
    ``BASE_CONTAINS_HEAD`` (HEAD is already in the base: nothing changed),
    ``BASE_DIFF_TOO_LARGE`` (the list of changes does not fit the Git output limit) and
    ``NO_CHANGED_FILES``.
    """

    if not valid_base(base) or _COMMIT.fullmatch(head) is None:
        raise LocalProductUnavailableError("BASE_REVISION_INVALID")
    try:
        base_sha = run_git("rev-parse", "--verify", "--end-of-options", base + "^{commit}")
    except LocalProductUnavailableError as error:
        if error.reason != "GIT_COMMAND_FAILED":
            raise
        raise LocalProductUnavailableError("BASE_REVISION_INVALID") from None
    if _COMMIT.fullmatch(base_sha) is None:
        raise LocalProductUnavailableError("BASE_REVISION_INVALID")
    try:
        merge_base = run_git("merge-base", base_sha, head)
    except LocalProductUnavailableError as error:
        if error.reason != "GIT_COMMAND_FAILED":
            raise
        raise LocalProductUnavailableError("BASE_NOT_RELATED") from None
    if _COMMIT.fullmatch(merge_base) is None:
        raise LocalProductUnavailableError("BASE_NOT_RELATED")
    if merge_base == head:
        raise LocalProductUnavailableError("BASE_CONTAINS_HEAD")
    try:
        listing = run_git("diff", "--name-only", "--no-renames", "-z", merge_base, head)
    except LocalProductUnavailableError as error:
        if error.reason != "GIT_COMMAND_FAILED":
            raise
        raise LocalProductUnavailableError("BASE_DIFF_TOO_LARGE") from None
    paths = sorted({item for item in listing.split("\x00") if item and _readable(item, head)})
    if not paths:
        raise LocalProductUnavailableError("NO_CHANGED_FILES")
    return LocalProductScanScope(base, base_sha, merge_base, tuple(paths), ())


def _readable(path: str, head: str) -> bool:
    """Whether the path can be read through the repository tools (the rest cannot be audited)."""

    try:
        ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, head, path, 1, 1)
    except ValueError:
        return False
    return True


__all__ = ["BASE_PATTERN", "changed_paths_since", "valid_base"]
