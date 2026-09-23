"""Fail-closed container directory preparation and process handoff."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from collections.abc import Callable, MutableMapping
from pathlib import Path
from typing import cast

_TLS_KEY_ENV = "SECURECODE_TLS_KEY_FILE"
_RUNTIME_TLS_KEY_NAME = "server-tls.key"
_MAX_TLS_KEY_BYTES = 65_536


def prepare() -> None:
    try:
        directories = {
            name: _prepare_private_directory(name)
            for name in ("SECURECODE_DATA_DIR", "SECURECODE_TMP_DIR")
        }
        _materialize_tls_private_key(directories["SECURECODE_DATA_DIR"])
    except (OSError, ValueError):
        raise SystemExit(64) from None


def _prepare_private_directory(name: str) -> Path:
    value = os.environ.get(name)
    if value is None or not value.startswith("/"):
        raise OSError
    directory = Path(value)
    descriptor = -1
    try:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if getattr(os, "O_DIRECTORY", 0) == 0 or getattr(os, "O_NOFOLLOW", 0) == 0:
            raise OSError
        descriptor = os.open(directory, flags)
        details = os.fstat(descriptor)
        geteuid = cast(Callable[[], int], vars(os)["geteuid"])
        fchmod = cast(Callable[[int, int], None], vars(os)["fchmod"])
        if not stat.S_ISDIR(details.st_mode) or details.st_uid != geteuid():
            raise OSError
        fchmod(descriptor, 0o700)
        return directory
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _materialize_tls_private_key(
    data_dir: Path,
    environment: MutableMapping[str, str] | None = None,
) -> None:
    """Copy a Compose-mounted key into private state before the server starts.

    Docker Compose may expose file-backed secrets as read-only root-owned files.
    The server deliberately rejects such a key because it is group/world readable.
    Copying it into the already verified private data directory gives the non-root
    server a stable mode-0600 path without weakening that server-side check.
    """

    values = os.environ if environment is None else environment
    source_text = values.get(_TLS_KEY_ENV)
    if source_text is None:
        return
    source = Path(source_text)
    if not source.is_absolute() or source.is_symlink():
        raise OSError
    key_bytes = _read_tls_private_key(source)
    target = data_dir / _RUNTIME_TLS_KEY_NAME
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".securecode-tls-",
        suffix=".tmp",
        dir=data_dir,
    )
    temporary = Path(temporary_name)
    try:
        _chmod_private(descriptor, temporary)
        _write_all(descriptor, key_bytes)
        os.fsync(descriptor)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)
    try:
        temporary.replace(target)
        target.chmod(0o600)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    values[_TLS_KEY_ENV] = str(target)


def _read_tls_private_key(source: Path) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            source,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or not 1 <= details.st_size <= _MAX_TLS_KEY_BYTES:
            raise OSError
        content = bytearray()
        while len(content) < _MAX_TLS_KEY_BYTES:
            chunk = os.read(descriptor, _MAX_TLS_KEY_BYTES - len(content))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != details.st_size:
            raise OSError
        return bytes(content)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_all(descriptor: int, content: bytes) -> None:
    offset = 0
    while offset < len(content):
        written = os.write(descriptor, content[offset:])
        if written <= 0:
            raise OSError
        offset += written


def _chmod_private(descriptor: int, path: Path) -> None:
    fchmod = getattr(os, "fchmod", None)
    if fchmod is not None:
        fchmod(descriptor, 0o600)
        return
    path.chmod(0o600)


if __name__ == "__main__":
    prepare()
    if len(sys.argv) < 2:
        raise SystemExit(64)
    os.execvp(sys.argv[1], sys.argv[1:])
