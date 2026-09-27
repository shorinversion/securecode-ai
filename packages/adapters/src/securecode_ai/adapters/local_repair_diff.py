"""Strict, complete path validation for local Architect unified diffs."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Final

_HUNK_HEADER: Final = re.compile(
    r"@@ -(?:[0-9]+)(?:,([0-9]+))? \+(?:[0-9]+)(?:,([0-9]+))? @@(?: .*)?\Z"
)
_FORBIDDEN_SECTION_PREFIXES: Final = (
    "old mode ",
    "new mode ",
    "deleted file mode ",
    "new file mode ",
    "similarity index ",
    "dissimilarity index ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "GIT binary patch",
    "Binary files ",
)


def validated_diff_paths(diff: str) -> tuple[str, ...]:
    """Return every changed path after parsing the complete text diff.

    Local repair supports in-place textual modifications only. Every section
    must contain canonical old/new headers and at least one complete hunk.
    Creation, deletion, rename, copy, mode-only and binary sections are rejected
    instead of being ignored by a partial ``---``/``+++`` scan.
    """

    if type(diff) is not str or not diff or "\x00" in diff or "\r" in diff:
        raise ValueError("unified diff is invalid")
    lines = diff.splitlines()
    if not lines:
        raise ValueError("unified diff is invalid")

    paths: set[str] = set()
    index = 0
    while index < len(lines):
        declared_path: str | None = None
        line = lines[index]
        if line.startswith("diff --git "):
            declared_path = _diff_git_path(line)
            index += 1
            if index >= len(lines):
                raise ValueError("unified diff section is incomplete")

        while index < len(lines) and lines[index].startswith("index "):
            index += 1
        if index >= len(lines) or any(
            lines[index].startswith(prefix) for prefix in _FORBIDDEN_SECTION_PREFIXES
        ):
            raise ValueError("unsupported unified diff section")
        if not lines[index].startswith("--- "):
            raise ValueError("unified diff old header is missing")
        old_path = _header_path(lines[index][4:])
        index += 1
        if index >= len(lines) or not lines[index].startswith("+++ "):
            raise ValueError("unified diff new header is missing")
        new_path = _header_path(lines[index][4:])
        index += 1
        if old_path != new_path or (declared_path is not None and declared_path != old_path):
            raise ValueError("unified diff path identity is inconsistent")

        hunk_count = 0
        while index < len(lines) and not lines[index].startswith("diff --git "):
            if any(lines[index].startswith(prefix) for prefix in _FORBIDDEN_SECTION_PREFIXES):
                raise ValueError("unsupported unified diff section")
            match = _HUNK_HEADER.fullmatch(lines[index])
            if match is None:
                raise ValueError("unified diff hunk header is invalid")
            old_remaining = int(match.group(1) or "1")
            new_remaining = int(match.group(2) or "1")
            index += 1
            while old_remaining or new_remaining:
                if index >= len(lines) or lines[index].startswith("diff --git "):
                    raise ValueError("unified diff hunk is truncated")
                hunk_line = lines[index]
                if not hunk_line:
                    raise ValueError("unified diff hunk line is invalid")
                marker = hunk_line[0]
                if marker == " ":
                    old_remaining -= 1
                    new_remaining -= 1
                elif marker == "-":
                    old_remaining -= 1
                elif marker == "+":
                    new_remaining -= 1
                else:
                    raise ValueError("unified diff hunk line is invalid")
                if old_remaining < 0 or new_remaining < 0:
                    raise ValueError("unified diff hunk length is invalid")
                index += 1
                if index < len(lines) and lines[index] == r"\ No newline at end of file":
                    index += 1
            hunk_count += 1
        if hunk_count == 0:
            raise ValueError("unified diff section contains no hunks")
        paths.add(old_path)

    if not paths:
        raise ValueError("unified diff contains no changed paths")
    return tuple(sorted(paths))


def _diff_git_path(line: str) -> str:
    fields = line.split(" ")
    if len(fields) != 4 or fields[:2] != ["diff", "--git"]:
        raise ValueError("unified diff declaration is invalid")
    old_path = _header_path(fields[2], required_prefix="a/")
    new_path = _header_path(fields[3], required_prefix="b/")
    if old_path != new_path:
        raise ValueError("rename and copy diffs are outside repair scope")
    return old_path


def _header_path(raw: str, *, required_prefix: str | None = None) -> str:
    path = raw.split("\t", 1)[0]
    if path == "/dev/null":
        raise ValueError("file creation and deletion are outside repair scope")
    if required_prefix is not None:
        if not path.startswith(required_prefix):
            raise ValueError("unified diff path prefix is invalid")
        path = path[len(required_prefix) :]
    elif path.startswith(("a/", "b/")):
        path = path[2:]
    if (
        not path
        or "\\" in path
        or path.startswith("/")
        or any(part in ("", ".", "..") for part in path.split("/"))
        or str(PurePosixPath(path)) != path
        or any(ord(character) < 32 or not character.isprintable() for character in path)
    ):
        raise ValueError("unified diff path is invalid")
    return path


__all__ = ["validated_diff_paths"]
