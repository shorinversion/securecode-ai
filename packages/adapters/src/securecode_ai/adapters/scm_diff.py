"""Bounded parsing of authenticated SCM unified diff metadata."""

from __future__ import annotations

import re
import unicodedata
from pathlib import PurePosixPath
from typing import Final

MAX_SCM_DIFF_BYTES: Final = 131_072
MAX_SCM_DIFF_LINES: Final = 16_384
MAX_SCM_CHANGED_LINES: Final = 100_000

_HUNK_HEADER: Final = re.compile(
    r"@@ -([0-9]+)(?:,([0-9]+))? \+([0-9]+)(?:,([0-9]+))? @@(?: .*)?\Z"
)
_NO_NEWLINE_MARKER: Final = r"\ No newline at end of file"
_PATH_MAX_LENGTH: Final = 1_024


class SCMDiffError(ValueError):
    """A provider diff was missing, incomplete, or outside the parser budget."""


def parse_unified_diff_changed_lines(
    diff: object,
    *,
    expected_path: object,
    expected_additions: int | None = None,
    expected_deletions: int | None = None,
) -> tuple[tuple[str, int], ...]:
    """Return changed HEAD locations from one complete provider diff section.

    The parser accepts optional file headers because GitLab may include them and
    GitHub commonly returns only hunk text in ``patch``. Every hunk count must
    be consumed exactly, so a truncated patch cannot produce a partial scope.
    """

    path = _validate_path(expected_path)
    if type(diff) is not str or not diff or "\x00" in diff or "\r" in diff:
        raise SCMDiffError("SCM diff is invalid")
    try:
        encoded_size = len(diff.encode("utf-8", "strict"))
    except UnicodeError:
        raise SCMDiffError("SCM diff is invalid") from None
    if encoded_size > MAX_SCM_DIFF_BYTES:
        raise SCMDiffError("SCM diff is oversized")
    lines = diff.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or len(lines) > MAX_SCM_DIFF_LINES:
        raise SCMDiffError("SCM diff is invalid")

    index = _skip_headers(lines, path)
    changed: list[tuple[str, int]] = []
    additions = 0
    deletions = 0
    hunk_count = 0
    while index < len(lines):
        match = _HUNK_HEADER.fullmatch(lines[index])
        if match is None:
            raise SCMDiffError("SCM diff hunk is invalid")
        old_start = int(match.group(1))
        old_remaining = int(match.group(2) or "1")
        new_start = int(match.group(3))
        new_remaining = int(match.group(4) or "1")
        if (
            (old_start == 0 and old_remaining != 0)
            or (new_start == 0 and new_remaining != 0)
            or (old_remaining == 0 and new_remaining == 0)
        ):
            raise SCMDiffError("SCM diff hunk range is invalid")
        old_line = old_start
        new_line = new_start
        index += 1
        previous_hunk_line = False
        while old_remaining or new_remaining:
            if index >= len(lines):
                raise SCMDiffError("SCM diff hunk is truncated")
            hunk_line = lines[index]
            if hunk_line == _NO_NEWLINE_MARKER:
                if not previous_hunk_line:
                    raise SCMDiffError("SCM diff marker is invalid")
                previous_hunk_line = False
                index += 1
                continue
            if not hunk_line or hunk_line[0] not in {" ", "+", "-"}:
                raise SCMDiffError("SCM diff hunk line is invalid")
            marker = hunk_line[0]
            if marker == " ":
                if old_remaining <= 0 or new_remaining <= 0:
                    raise SCMDiffError("SCM diff hunk length is invalid")
                old_remaining -= 1
                new_remaining -= 1
                old_line += 1
                new_line += 1
            elif marker == "-":
                if old_remaining <= 0:
                    raise SCMDiffError("SCM diff hunk length is invalid")
                old_remaining -= 1
                old_line += 1
                deletions += 1
            else:
                if new_remaining <= 0:
                    raise SCMDiffError("SCM diff hunk length is invalid")
                new_remaining -= 1
                if new_line < 1:
                    raise SCMDiffError("SCM diff location is invalid")
                changed.append((path, new_line))
                additions += 1
                new_line += 1
            previous_hunk_line = True
            index += 1
            if len(changed) > MAX_SCM_CHANGED_LINES:
                raise SCMDiffError("SCM diff changed-line scope is oversized")
        while index < len(lines) and lines[index] == _NO_NEWLINE_MARKER:
            if not previous_hunk_line:
                raise SCMDiffError("SCM diff marker is invalid")
            previous_hunk_line = False
            index += 1
        hunk_count += 1

    if hunk_count == 0:
        raise SCMDiffError("SCM diff contains no hunks")
    if expected_additions is not None and additions != _nonnegative_count(expected_additions):
        raise SCMDiffError("SCM diff additions are incomplete")
    if expected_deletions is not None and deletions != _nonnegative_count(expected_deletions):
        raise SCMDiffError("SCM diff deletions are incomplete")
    if len(changed) != len(set(changed)):
        raise SCMDiffError("SCM diff changed-line locations are duplicated")
    return tuple(sorted(changed))


def _skip_headers(lines: list[str], expected_path: str) -> int:
    index = 0
    old_header: str | None = None
    new_header: str | None = None
    git_header_seen = False
    file_headers_seen = False
    while index < len(lines) and not lines[index].startswith("@@"):
        line = lines[index]
        if line.startswith("diff --git "):
            if git_header_seen:
                raise SCMDiffError("SCM diff declarations are duplicated")
            git_header_seen = True
            fields = line.split(" ")
            if len(fields) != 4:
                raise SCMDiffError("SCM diff declaration is invalid")
            old_header = _header_path(fields[2], prefix="a/")
            new_header = _header_path(fields[3], prefix="b/")
            if old_header is None or new_header != expected_path:
                raise SCMDiffError("SCM diff path identity is invalid")
        elif line.startswith("--- "):
            if file_headers_seen:
                raise SCMDiffError("SCM diff headers are duplicated")
            file_headers_seen = True
            parsed_old_header = _header_path(line[4:])
            index += 1
            if index >= len(lines) or not lines[index].startswith("+++ "):
                raise SCMDiffError("SCM diff new header is missing")
            parsed_new_header = _header_path(lines[index][4:])
            if parsed_new_header is not None and parsed_new_header != expected_path:
                raise SCMDiffError("SCM diff path identity is invalid")
            if old_header is None:
                old_header = parsed_old_header
            if new_header is None:
                new_header = parsed_new_header
        elif line.startswith(
            (
                "index ",
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
            )
        ):
            pass
        else:
            raise SCMDiffError("SCM diff preamble is invalid")
        index += 1
    return index


def _header_path(raw: str, *, prefix: str | None = None) -> str | None:
    value = raw.split("\t", 1)[0].strip()
    if value == "/dev/null":
        return None
    if prefix is not None:
        if not value.startswith(prefix):
            raise SCMDiffError("SCM diff path prefix is invalid")
        value = value[len(prefix) :]
    elif value.startswith(("a/", "b/")):
        value = value[2:]
    return _validate_path(value)


def _validate_path(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise SCMDiffError("SCM diff path is invalid")
    normalized = PurePosixPath(value)
    if (
        len(value) > _PATH_MAX_LENGTH
        or "\\" in value
        or any(ord(character) < 32 or not character.isprintable() for character in value)
        or unicodedata.normalize("NFC", value) != value
        or normalized.is_absolute()
        or normalized.as_posix() != value
        or not normalized.parts
        or any(part in {"", ".", ".."} for part in normalized.parts)
        or normalized.parts[0].endswith(":")
    ):
        raise SCMDiffError("SCM diff path is invalid")
    return value


def _nonnegative_count(value: object) -> int:
    if type(value) is not int or value < 0:
        raise SCMDiffError("SCM diff count is invalid")
    return value


__all__ = [
    "MAX_SCM_CHANGED_LINES",
    "MAX_SCM_DIFF_BYTES",
    "MAX_SCM_DIFF_LINES",
    "SCMDiffError",
    "parse_unified_diff_changed_lines",
]
