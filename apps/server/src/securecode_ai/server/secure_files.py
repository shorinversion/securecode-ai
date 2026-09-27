"""Bounded no-follow readers for server-owned configuration and secrets."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import cast

_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def read_bounded_regular(path: Path, limit: int) -> bytes:
    if (
        os.name != "posix"
        or _O_NOFOLLOW == 0
        or not isinstance(path, Path)
        or not path.is_absolute()
        or path.is_symlink()
        or _has_symlink_ancestor(path)
        or ".." in path.parts
        or type(limit) is not int
        or not 1 <= limit <= 1_048_576
    ):
        raise ValueError("configuration path is unsafe")
    directory_descriptor = -1
    opened_directories: list[int] = []
    descriptor = -1
    docker_secret_mount = _is_docker_secret_mount(path)
    try:
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | _O_NOFOLLOW
        )
        directory_descriptor = os.open(path.anchor, directory_flags)
        opened_directories.append(directory_descriptor)
        for component in path.parent.parts[1:]:
            if component in {"", ".", ".."}:
                raise ValueError("configuration path is unsafe")
            directory_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            opened_directories.append(directory_descriptor)
        before = os.stat(path.name, dir_fd=directory_descriptor, follow_symlinks=False)
        _validate_regular_file(before, limit, allow_docker_secret=docker_secret_mount)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_BINARY", 0)
            | _O_NOFOLLOW
        )
        descriptor = os.open(path.name, flags, dir_fd=directory_descriptor)
        opened = os.fstat(descriptor)
        _validate_regular_file(opened, limit, allow_docker_secret=docker_secret_mount)
        if not _same_file(before, opened):
            raise ValueError("configuration file changed while opening")
        value = _read_descriptor(descriptor, limit + 1)
        after = os.fstat(descriptor)
        _validate_regular_file(after, limit, allow_docker_secret=docker_secret_mount)
        if not _same_state(opened, after):
            raise ValueError("configuration file changed while reading")
    except OSError:
        raise ValueError("configuration file is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        for opened_directory in reversed(opened_directories):
            os.close(opened_directory)
    if not value or len(value) > limit:
        raise ValueError("configuration file is invalid")
    return value


def _has_symlink_ancestor(path: Path) -> bool:
    """Reject paths whose parent traversal can be redirected by a symlink."""
    current = path.parent
    while True:
        try:
            details = current.lstat()
        except OSError:
            return True
        if stat.S_ISLNK(details.st_mode):
            return True
        parent = current.parent
        if parent == current:
            return False
        current = parent


def _validate_regular_file(
    details: os.stat_result,
    limit: int,
    *,
    allow_docker_secret: bool = False,
) -> None:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(details, "st_file_attributes", 0)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_size > limit
        or details.st_nlink != 1
        or (reparse_flag and attributes & reparse_flag)
    ):
        raise ValueError("configuration file is invalid")
    if os.name == "posix":
        mode = stat.S_IMODE(details.st_mode)
        if mode & 0o077 and not (
            allow_docker_secret
            and details.st_uid == 0
            and not mode & 0o222
            and not mode & 0o111
            and not mode & 0o7000
        ):
            raise ValueError("configuration file permissions are unsafe")
        current_uid = cast(Callable[[], int], vars(os)["geteuid"])()
        if details.st_uid not in {0, current_uid}:
            raise ValueError("configuration file owner is unsafe")


def _is_docker_secret_mount(path: Path) -> bool:
    """Recognize only direct Compose secret mounts.

    Docker Compose file-backed secrets are read-only bind mounts and commonly
    retain mode ``0444``.  They are confined to the container's exact
    ``/run/secrets`` directory; all other configuration paths keep the strict
    private-file requirement above.
    """

    return path.parent == Path("/run/secrets")


def _same_file(before: os.stat_result, opened: os.stat_result) -> bool:
    return (
        before.st_dev == opened.st_dev
        and before.st_ino == opened.st_ino
        and before.st_mode == opened.st_mode
    )


def _same_state(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        _same_file(before, after)
        and before.st_size == after.st_size
        and before.st_nlink == after.st_nlink
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


def _read_descriptor(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_json_object(path: Path, limit: int) -> dict[str, object]:
    raw = read_bounded_regular(path, limit)

    def closed(pairs: list[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON key")
            output[key] = value
        return output

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=closed,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("configuration JSON is invalid") from None
    if type(value) is not dict:
        raise ValueError("configuration JSON is invalid")
    return value


def read_secret_bytes(path: Path, *, minimum: int = 32, maximum: int = 4096) -> bytes:
    value = read_bounded_regular(path, maximum + 2).rstrip(b"\r\n")
    if not minimum <= len(value) <= maximum or b"\x00" in value:
        raise ValueError("secret file is invalid")
    return value


def decode_ascii_secret(value: bytes) -> str:
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("secret file is invalid") from None
    if any(ord(character) < 33 or ord(character) > 126 for character in decoded):
        raise ValueError("secret file is invalid")
    return decoded


__all__ = [
    "decode_ascii_secret",
    "read_bounded_regular",
    "read_json_object",
    "read_secret_bytes",
]
