"""Pinned, bounded JSON subprocess transport for local control-plane ports."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Final

_SHA256: Final = frozenset("0123456789abcdef")
_MAX_EXECUTABLE_BYTES: Final = 268_435_456
_MAX_INPUT_BYTES: Final = 1_048_576
_CREATE_NO_WINDOW: Final[int] = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class SubprocessProtocolError(RuntimeError):
    """The configured child is unavailable or returned an invalid envelope."""


class PinnedJsonProcess:
    """Invoke one hash-pinned executable through a closed JSON protocol."""

    def __init__(
        self,
        executable: Path,
        executable_sha256: str,
        *,
        timeout_seconds: int = 30,
        max_output_bytes: int = 65_536,
    ) -> None:
        if (
            not isinstance(executable, Path)
            or not executable.is_absolute()
            or type(executable_sha256) is not str
            or len(executable_sha256) != 64
            or any(character not in _SHA256 for character in executable_sha256)
            or type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 300
            or type(max_output_bytes) is not int
            or not 1024 <= max_output_bytes <= 1_048_576
        ):
            raise ValueError("subprocess configuration is invalid")
        self._executable = executable
        self._expected_sha256 = executable_sha256
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        self._verify_executable()

    def request(self, document: Mapping[str, object]) -> dict[str, object]:
        payload = _canonical(document)
        if len(payload) > _MAX_INPUT_BYTES:
            raise SubprocessProtocolError("SUBPROCESS_REQUEST_TOO_LARGE")
        with self._locked_executable() as (target, pass_fds):
            output = self._execute(payload, target=target, pass_fds=pass_fds)
        return _strict_document(output)

    def _execute(
        self,
        payload: bytes,
        *,
        target: str,
        pass_fds: tuple[int, ...],
    ) -> bytes:
        environment = _sanitized_environment()
        flags = _CREATE_NO_WINDOW if os.name == "nt" else 0
        process: subprocess.Popen[bytes] | None = None
        output: list[bytes] = []
        overflow = threading.Event()
        io_error = threading.Event()
        try:
            process = _spawn_process(
                target=target,
                pass_fds=pass_fds,
                environment=environment,
                flags=flags,
                cwd=self._executable.parent,
            )
            assert process.stdin is not None and process.stdout is not None

            def read_output() -> None:
                try:
                    assert process is not None and process.stdout is not None
                    value = process.stdout.read(self._max_output_bytes + 1)
                    output.append(value)
                    if len(value) > self._max_output_bytes:
                        overflow.set()
                        process.kill()
                except (OSError, ValueError):
                    io_error.set()

            def write_input() -> None:
                try:
                    assert process is not None and process.stdin is not None
                    process.stdin.write(payload)
                    process.stdin.close()
                except (BrokenPipeError, OSError, ValueError):
                    io_error.set()

            reader = threading.Thread(target=read_output, daemon=True)
            writer = threading.Thread(target=write_input, daemon=True)
            reader.start()
            writer.start()
            try:
                code = process.wait(timeout=self._timeout_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
                raise SubprocessProtocolError("SUBPROCESS_TIMEOUT") from None
            reader.join(timeout=2)
            writer.join(timeout=2)
            if (
                reader.is_alive()
                or writer.is_alive()
                or overflow.is_set()
                or io_error.is_set()
                or code != 0
                or len(output) != 1
            ):
                raise SubprocessProtocolError("SUBPROCESS_FAILED")
            return output[0]
        except SubprocessProtocolError:
            raise
        except (BrokenPipeError, OSError, subprocess.SubprocessError):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            raise SubprocessProtocolError("SUBPROCESS_FAILED") from None
        finally:
            if process is not None:
                if process.stdin is not None:
                    process.stdin.close()
                if process.stdout is not None:
                    process.stdout.close()

    @contextmanager
    def _locked_executable(self) -> Iterator[tuple[str, tuple[int, ...]]]:
        """Hold the executable identity stable for the whole child invocation."""

        self._verify_executable()
        if os.name == "posix" and sys.platform.startswith("linux"):
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self._executable, flags)
            except OSError:
                raise SubprocessProtocolError("EXECUTABLE_UNAVAILABLE") from None
            try:
                details = os.fstat(descriptor)
                if not _valid_executable_stat(details):
                    raise SubprocessProtocolError("EXECUTABLE_INVALID")
                if _descriptor_sha256(descriptor) != self._expected_sha256:
                    raise SubprocessProtocolError("EXECUTABLE_IDENTITY_MISMATCH")
                yield f"/proc/self/fd/{descriptor}", (descriptor,)
            finally:
                os.close(descriptor)
            return
        if os.name == "nt":
            handle, closer = _lock_windows_executable(self._executable)
            try:
                if _path_sha256(self._executable) != self._expected_sha256:
                    raise SubprocessProtocolError("EXECUTABLE_IDENTITY_MISMATCH")
                yield str(self._executable), ()
            finally:
                closer(handle)
            return
        raise SubprocessProtocolError("EXECUTABLE_PLATFORM_UNSUPPORTED")

    def _verify_executable(self) -> None:
        path = self._executable
        try:
            if path.is_symlink():
                raise SubprocessProtocolError("EXECUTABLE_INVALID")
            details = path.stat(follow_symlinks=False)
            if not _valid_executable_stat(details):
                raise SubprocessProtocolError("EXECUTABLE_INVALID")
            resolved = path.resolve(strict=True)
            if resolved != path:
                raise SubprocessProtocolError("EXECUTABLE_INVALID")
            if _path_sha256(path) != self._expected_sha256:
                raise SubprocessProtocolError("EXECUTABLE_IDENTITY_MISMATCH")
        except SubprocessProtocolError:
            raise
        except OSError:
            raise SubprocessProtocolError("EXECUTABLE_UNAVAILABLE") from None


def configured_process(
    values: object,
    *,
    prefix: str,
) -> PinnedJsonProcess | None:
    """Build a configured process, rejecting incomplete configuration."""

    if not hasattr(values, "get"):
        raise ValueError("subprocess environment is invalid")
    get = values.get
    executable = get(f"{prefix}_EXECUTABLE")
    digest = get(f"{prefix}_EXECUTABLE_SHA256")
    timeout_value = get(f"{prefix}_TIMEOUT_SECONDS")
    if executable is None and digest is None and timeout_value is None:
        return None
    if type(executable) is not str or type(digest) is not str:
        raise ValueError("subprocess configuration is incomplete")
    timeout = 30
    if timeout_value is not None:
        if type(timeout_value) is not str or not timeout_value.isascii():
            raise ValueError("subprocess timeout is invalid")
        try:
            timeout = int(timeout_value)
        except ValueError:
            raise ValueError("subprocess timeout is invalid") from None
    return PinnedJsonProcess(Path(executable), digest, timeout_seconds=timeout)


def _canonical(document: Mapping[str, object]) -> bytes:
    if not isinstance(document, Mapping):
        raise SubprocessProtocolError("SUBPROCESS_REQUEST_INVALID")
    try:
        return json.dumps(
            dict(document),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise SubprocessProtocolError("SUBPROCESS_REQUEST_INVALID") from None


def _strict_document(payload: bytes) -> dict[str, object]:
    def closed(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=closed,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise SubprocessProtocolError("SUBPROCESS_RESPONSE_INVALID") from None
    if type(value) is not dict:
        raise SubprocessProtocolError("SUBPROCESS_RESPONSE_INVALID")
    return value


def _sanitized_environment() -> dict[str, str]:
    result = {"PATH": ""}
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            value = os.environ.get(name)
            if value is not None:
                result[name] = value
    return result


def _spawn_process(
    *,
    target: str,
    pass_fds: tuple[int, ...],
    environment: Mapping[str, str],
    flags: int,
    cwd: Path,
) -> subprocess.Popen[bytes]:
    if pass_fds:
        return subprocess.Popen(
            (target,),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            shell=False,
            creationflags=flags,
            close_fds=True,
            cwd=str(cwd),
            pass_fds=pass_fds,
        )
    return subprocess.Popen(
        (target,),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=environment,
        shell=False,
        creationflags=flags,
        close_fds=True,
        cwd=str(cwd),
    )


def _valid_executable_stat(details: os.stat_result) -> bool:
    return (
        stat.S_ISREG(details.st_mode)
        and 1 <= details.st_size <= _MAX_EXECUTABLE_BYTES
        and (os.name != "posix" or details.st_mode & 0o111 != 0)
    )


def _path_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(65_536):
                digest.update(chunk)
    except OSError:
        raise SubprocessProtocolError("EXECUTABLE_UNAVAILABLE") from None
    return digest.hexdigest()


def _descriptor_sha256(descriptor: int) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while chunk := os.read(descriptor, 65_536):
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError:
        raise SubprocessProtocolError("EXECUTABLE_UNAVAILABLE") from None
    return digest.hexdigest()


def _lock_windows_executable(path: Path) -> tuple[int, Callable[[int], object]]:
    try:
        import ctypes

        loader = getattr(ctypes, "WinDLL", None)
        if not callable(loader):
            raise SubprocessProtocolError("EXECUTABLE_UNAVAILABLE")
        kernel = loader("kernel32", use_last_error=True)
        opener = kernel.CreateFileW
        opener.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        opener.restype = ctypes.c_void_p
        handle = opener(
            str(path),
            0x80000000 | 0x00020000,
            0x00000001,
            None,
            3,
            0x00200000,
            None,
        )
        if not handle or handle == ctypes.c_void_p(-1).value:
            raise SubprocessProtocolError("EXECUTABLE_UNAVAILABLE")
        attributes = kernel.GetFileInformationByHandleEx
        attributes.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        attributes.restype = ctypes.c_int
        information = (ctypes.c_uint32 * 2)()
        if not attributes(
            ctypes.c_void_p(handle),
            9,
            information,
            ctypes.sizeof(information),
        ) or information[0] & (0x400 | 0x10):
            kernel.CloseHandle(ctypes.c_void_p(handle))
            raise SubprocessProtocolError("EXECUTABLE_INVALID")
        closer = kernel.CloseHandle
        closer.argtypes = [ctypes.c_void_p]
        closer.restype = ctypes.c_int
        return int(handle), lambda value: closer(ctypes.c_void_p(value))
    except SubprocessProtocolError:
        raise
    except Exception:
        raise SubprocessProtocolError("EXECUTABLE_UNAVAILABLE") from None


__all__ = [
    "PinnedJsonProcess",
    "SubprocessProtocolError",
    "configured_process",
]
