"""Secure local SQLite file preparation for the development control plane."""

from __future__ import annotations

import os
import sqlite3
import stat
from collections.abc import Callable
from pathlib import Path
from threading import Lock
from typing import Final, cast

from .migrations import SchemaVersionError, require_schema_version

_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_SQLITE_OPEN_LOCK: Final = Lock()


class SqliteSchemaReadiness:
    """Report readiness only while the open database has the exact supported schema."""

    __slots__ = ("_connection",)

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def ready(self) -> bool:
        try:
            require_schema_version(self._connection)
        except (sqlite3.DatabaseError, SchemaVersionError):
            return False
        return True


def prepare_private_data_directory(path: Path) -> Path:
    """Create and validate an absolute, link-free private directory chain."""

    if (
        os.name != "posix"
        or _O_NOFOLLOW == 0
        or not isinstance(path, Path)
        or not path.is_absolute()
        or not path.anchor
    ):
        raise ValueError("server data directory is unsafe")
    current = Path(path.anchor)
    _require_directory(current, private=False)
    for part in path.parts[1:]:
        current /= part
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise ValueError("server data directory is unavailable") from error
        _require_directory(current, private=current == path)
    return path


def open_private_sqlite(path: Path, *, create: bool = True) -> sqlite3.Connection:
    """Create or open one private regular database file without accepting links."""

    if (
        os.name != "posix"
        or _O_NOFOLLOW == 0
        or not isinstance(path, Path)
        or not path.is_absolute()
        or not path.name
    ):
        raise ValueError("server database path is unsafe")
    _require_directory(path.parent, private=True)
    if type(create) is not bool:
        raise ValueError("server database mode is invalid")
    with _SQLITE_OPEN_LOCK:
        return _open_private_sqlite(path, create=create)


def _open_private_sqlite(path: Path, *, create: bool) -> sqlite3.Connection:
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    if create:
        flags |= os.O_CREAT | os.O_EXCL
    flags |= _O_NOFOLLOW
    created = False
    descriptor = -1
    try:
        descriptor = os.open(path, flags, 0o600)
        created = create
    except FileExistsError:
        if not create:
            raise ValueError("server database is unavailable") from None
        try:
            descriptor = os.open(
                path,
                os.O_RDWR | getattr(os, "O_BINARY", 0) | _O_NOFOLLOW,
            )
        except OSError as error:
            raise ValueError("server database is unavailable") from error
    except OSError as error:
        raise ValueError("server database is unavailable") from error
    connection: sqlite3.Connection | None = None
    opened: os.stat_result | None = None
    try:
        opened = os.fstat(descriptor)
        before = _require_database_file(path)
        if _identity(before) != _identity(opened):
            raise ValueError("server database path changed during open")
        descriptor_inventory = _open_descriptors()
        if descriptor_inventory is None:
            raise ValueError("server database descriptor verification is unavailable")
        connection = sqlite3.connect(path, check_same_thread=False)
        _require_connection_descriptor(descriptor_inventory, _identity(opened))
        after = _require_database_file(path)
        if _identity(before) != _identity(after):
            raise ValueError("server database path changed during open")
        if descriptor >= 0:
            os.close(descriptor)
            descriptor = -1
        return connection
    except Exception:
        if connection is not None:
            connection.close()
        if descriptor >= 0:
            os.close(descriptor)
        if created and opened is not None:
            try:
                current = path.stat(follow_symlinks=False)
                if _identity(current) == _identity(opened):
                    path.unlink()
            except OSError:
                pass
        raise


def _open_descriptors() -> frozenset[int] | None:
    directory = next(
        (Path(value) for value in ("/proc/self/fd", "/dev/fd") if Path(value).is_dir()), None
    )
    if directory is None:
        return None
    try:
        candidates = {int(entry.name) for entry in directory.iterdir() if entry.name.isdecimal()}
    except OSError:
        return None
    opened: set[int] = set()
    for descriptor in candidates:
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        opened.add(descriptor)
    return frozenset(opened)


def _require_connection_descriptor(before: frozenset[int], expected: tuple[int, int]) -> None:
    after = _open_descriptors()
    if after is None:
        raise ValueError("server database descriptor verification is unavailable")
    for descriptor in after - before:
        try:
            details = os.fstat(descriptor)
        except OSError:
            continue
        if stat.S_ISREG(details.st_mode) and _identity(details) == expected:
            return
    raise ValueError("SQLite opened an unverified database file")


def _require_directory(path: Path, *, private: bool) -> os.stat_result:
    try:
        details = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ValueError("server data directory is unavailable") from error
    if _link_like(details) or not stat.S_ISDIR(details.st_mode):
        raise ValueError("server data directory is unsafe")
    if private and os.name == "posix":
        current_uid = cast(Callable[[], int], vars(os)["geteuid"])()
        if details.st_mode & 0o077 or details.st_uid not in {0, current_uid}:
            raise ValueError("server data directory permissions are unsafe")
    return details


def _require_database_file(path: Path) -> os.stat_result:
    try:
        details = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ValueError("server database is unavailable") from error
    if _link_like(details) or not stat.S_ISREG(details.st_mode):
        raise ValueError("server database is unsafe")
    if os.name == "posix":
        current_uid = cast(Callable[[], int], vars(os)["geteuid"])()
        if (
            details.st_mode & 0o077
            or details.st_nlink != 1
            or details.st_uid not in {0, current_uid}
        ):
            raise ValueError("server database permissions are unsafe")
    return details


def _link_like(details: os.stat_result) -> bool:
    attributes = getattr(details, "st_file_attributes", 0)
    reparse_tag = getattr(details, "st_reparse_tag", 0)
    return stat.S_ISLNK(details.st_mode) or bool(attributes & _REPARSE_POINT) or bool(reparse_tag)


def _identity(details: os.stat_result) -> tuple[int, int]:
    return details.st_dev, details.st_ino


__all__ = ["SqliteSchemaReadiness", "open_private_sqlite", "prepare_private_data_directory"]
