"""Fail-closed container directory preparation and process handoff."""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, MutableMapping
from contextlib import suppress
from pathlib import Path
from typing import cast

_TLS_KEY_ENV = "SECURECODE_TLS_KEY_FILE"
_RUNTIME_TLS_KEY_NAME = "server-tls.key"
_MAX_TLS_KEY_BYTES = 65_536
_WORKER_TOKEN_ENV = "SECURECODE_WORKER_TOKEN_FILE"
_DOCKER_WORKER_TOKENS = frozenset(
    {
        Path("/run/secrets/securecode_worker_token"),
        Path("/run/secrets/worker_token"),
    }
)
_GITLAB_WORKER_TOKEN_PREFIX = ".gitlab-worker-token-"
_RUNTIME_WORKER_TOKEN_NAME = ".securecode-worker-token"
_MIN_WORKER_TOKEN_BYTES = 32
_MAX_WORKER_TOKEN_BYTES = 8192
_GATEWAY_HEALTH_INTERVAL_SECONDS = 15.0
_GATEWAY_HEALTH_TIMEOUT_SECONDS = 5.0
_GATEWAY_HEALTH_FAILURE_LIMIT = 3


def prepare() -> None:
    try:
        directories = {
            name: _prepare_private_directory(name)
            for name in ("SECURECODE_DATA_DIR", "SECURECODE_TMP_DIR")
        }
        _materialize_worker_token(directories["SECURECODE_TMP_DIR"])
        _materialize_tls_private_key(directories["SECURECODE_TMP_DIR"])
    except (OSError, ValueError):
        raise SystemExit(64) from None


_GATEWAY_ENVIRONMENT = frozenset(
    {
        "HOME",
        "PATH",
        "PYTHONNOUSERSITE",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONUNBUFFERED",
        "PYTHONPATH",
        "SECURECODE_AI_ARTIFACT_ROOT",
        "SECURECODE_DATA_DIR",
        "SECURECODE_GATEWAY_OBSERVATION_FILE",
        "SystemRoot",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
)


def _gateway_wait_seconds() -> int:
    timeout_text = os.environ.get("SECURECODE_WORKER_LOCAL_PROVIDER_WAIT_SECONDS", "300")
    if (
        not timeout_text.isascii()
        or not timeout_text.isdecimal()
        or len(timeout_text) > 3
        or not 1 <= int(timeout_text) <= 600
    ):
        raise ValueError("local provider readiness configuration is invalid")
    return int(timeout_text)


def _gateway_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key in _GATEWAY_ENVIRONMENT
    }


def _start_gateway() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-m", "securecode_ai.worker.provider_gateway"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=None,
        env=_gateway_environment(),
    )


def _wait_for_gateway(provider: subprocess.Popen[bytes], timeout_seconds: int) -> None:
    """Keep the worker from claiming runs before its approved model is ready."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if provider.poll() is not None:
            raise OSError
        remaining = deadline - time.monotonic()
        try:
            result = subprocess.run(
                [sys.executable, "-m", "securecode_ai.worker.provider_gateway", "--ready"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_gateway_environment(),
                timeout=min(35.0, remaining),
                check=False,
            )
            if result.returncode == 0 and result.stdout == b"ready\n":
                return
        except (OSError, subprocess.SubprocessError):
            pass
        time.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
    raise OSError("approved local provider readiness timed out")


def _gateway_ready(timeout_seconds: float = _GATEWAY_HEALTH_TIMEOUT_SECONDS) -> bool:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "securecode_ai.worker.provider_gateway", "--ready"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_gateway_environment(),
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and result.stdout == b"ready\n"


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
    if source_text is None or source_text == "":
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


def _materialize_worker_token(
    private_tmp_dir: Path,
    environment: MutableMapping[str, str] | None = None,
) -> None:
    """Copy the provisioned private Compose secret into the worker tmpfs.

    Standalone Compose file secrets are exposed through a bind mount whose
    owner and mode come from provisioning.  The worker's regular secret reader
    requires a private source, so only the exact Docker secret path is accepted
    here and the validated bytes are moved into a mode-0600 file owned by the
    worker.
    """

    values = os.environ if environment is None else environment
    source_text = values.get(_WORKER_TOKEN_ENV)
    if source_text is None:
        return
    source = Path(source_text)
    if source in _DOCKER_WORKER_TOKENS:
        token = _read_docker_worker_token(source)
        consume_source = False
    elif (
        source.is_absolute()
        and source.parent == private_tmp_dir
        and source.name.startswith(_GITLAB_WORKER_TOKEN_PREFIX)
    ):
        token = _read_private_worker_token(source, private_tmp_dir)
        consume_source = True
    else:
        raise OSError
    target = private_tmp_dir / _RUNTIME_WORKER_TOKEN_NAME
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".securecode-worker-token-",
        suffix=".tmp",
        dir=private_tmp_dir,
    )
    temporary = Path(temporary_name)
    try:
        _chmod_private(descriptor, temporary)
        _write_all(descriptor, token)
        os.fsync(descriptor)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)
    try:
        temporary.replace(target)
        target.chmod(0o600)
        details = target.stat()
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or not _MIN_WORKER_TOKEN_BYTES <= details.st_size <= _MAX_WORKER_TOKEN_BYTES
        ):
            raise OSError
        if consume_source:
            source.unlink()
    except OSError:
        temporary.unlink(missing_ok=True)
        raise
    values[_WORKER_TOKEN_ENV] = str(target)


def _read_docker_worker_token(source: Path) -> bytes:
    if source not in _DOCKER_WORKER_TOKENS:
        raise OSError
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if getattr(os, "O_DIRECTORY", 0) == 0 or getattr(os, "O_NOFOLLOW", 0) == 0:
        raise OSError
    directory = -1
    descriptor = -1
    try:
        directory = os.open(str(source.parent), directory_flags)
        before = os.stat(source.name, dir_fd=directory, follow_symlinks=False)
        descriptor = os.open(
            source.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory,
        )
        opened = os.fstat(descriptor)
        if not _docker_worker_token_file(before) or not _same_source(before, opened):
            raise OSError
        content = bytearray()
        while len(content) <= _MAX_WORKER_TOKEN_BYTES:
            chunk = os.read(descriptor, _MAX_WORKER_TOKEN_BYTES + 1 - len(content))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(content) != opened.st_size
            or not _docker_worker_token_file(after)
            or not _same_source(opened, after)
        ):
            raise OSError
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)
    return _normalize_worker_token(bytes(content))


def _read_private_worker_token(source: Path, private_directory: Path) -> bytes:
    """Read a single-use GitLab token copy from the worker's private tmp dir."""
    if (
        not source.is_absolute()
        or source.parent != private_directory
        or not source.name.startswith(_GITLAB_WORKER_TOKEN_PREFIX)
    ):
        raise OSError
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if getattr(os, "O_DIRECTORY", 0) == 0 or getattr(os, "O_NOFOLLOW", 0) == 0:
        raise OSError
    directory = -1
    descriptor = -1
    try:
        directory = os.open(str(private_directory), directory_flags)
        before = os.stat(source.name, dir_fd=directory, follow_symlinks=False)
        descriptor = os.open(
            source.name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory,
        )
        opened = os.fstat(descriptor)
        if (
            not _private_worker_token_file(before)
            or not _same_source(before, opened)
        ):
            raise OSError
        content = bytearray()
        while len(content) <= _MAX_WORKER_TOKEN_BYTES:
            chunk = os.read(descriptor, _MAX_WORKER_TOKEN_BYTES + 1 - len(content))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(content) != opened.st_size
            or not _private_worker_token_file(after)
            or not _same_source(opened, after)
        ):
            raise OSError
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)
    return _normalize_worker_token(bytes(content))


def _private_worker_token_file(details: os.stat_result) -> bool:
    return (
        stat.S_ISREG(details.st_mode)
        and details.st_uid == os.geteuid()
        and stat.S_IMODE(details.st_mode) == 0o600
        and details.st_nlink == 1
        and _MIN_WORKER_TOKEN_BYTES <= details.st_size <= _MAX_WORKER_TOKEN_BYTES + 2
    )


def _normalize_worker_token(value: bytes) -> bytes:
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith((b"\r", b"\n")):
        value = value[:-1]
    if not _MIN_WORKER_TOKEN_BYTES <= len(value) <= _MAX_WORKER_TOKEN_BYTES:
        raise ValueError
    try:
        decoded = value.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError from None
    if any(ord(character) < 33 or ord(character) > 126 for character in decoded):
        raise ValueError
    return value


def _docker_worker_token_file(details: os.stat_result) -> bool:
    mode = stat.S_IMODE(details.st_mode)
    owner = details.st_uid
    effective_uid = os.geteuid()
    readable = mode & (0o400 if owner == effective_uid else 0o004)
    private_owner_file = (
        owner == effective_uid
        and (mode & 0o077) == 0
        and (mode & 0o111) == 0
        and readable != 0
    )
    docker_secret_file = (
        owner == 0
        and (mode & 0o222) == 0
        and (mode & 0o111) == 0
        and (mode & 0o7000) == 0
        and readable != 0
    )
    return (
        stat.S_ISREG(details.st_mode)
        and (private_owner_file or docker_secret_file)
        and details.st_nlink == 1
        and _MIN_WORKER_TOKEN_BYTES <= details.st_size <= _MAX_WORKER_TOKEN_BYTES + 2
    )


def _same_source(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev == after.st_dev
        and before.st_ino == after.st_ino
        and before.st_mode == after.st_mode
        and before.st_uid == after.st_uid
        and before.st_nlink == after.st_nlink
        and before.st_size == after.st_size
        and before.st_mtime_ns == after.st_mtime_ns
        and before.st_ctime_ns == after.st_ctime_ns
    )


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


def _worker_mode(command: tuple[str, ...]) -> bool:
    if not command or not Path(command[0]).name.lower().startswith("python"):
        return False
    return command[1:] == ("-m", "securecode_ai.worker.service") or command[1:] == (
        "-P",
        "-m",
        "securecode_ai.worker.service",
    )


def _forward_signal(processes: tuple[subprocess.Popen[bytes], ...], signum: int) -> None:
    for process in processes:
        if process.poll() is None:
            try:
                process.send_signal(signum)
            except OSError:
                pass


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.terminate()
        process.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        with suppress(OSError):
            process.kill()
        with suppress(OSError, subprocess.TimeoutExpired):
            process.wait(timeout=2)


def _returncode(value: int | None) -> int:
    if value is None:
        return 1
    if value < 0:
        return min(255, 128 - value)
    return min(255, value)


def _run_worker(command: tuple[str, ...]) -> int:
    provider = _start_gateway()
    worker: subprocess.Popen[bytes] | None = None
    processes: tuple[subprocess.Popen[bytes], ...] = (provider,)
    previous_handlers = {
        signal_number: signal.getsignal(signal_number)
        for signal_number in (signal.SIGTERM, signal.SIGINT)
    }

    def handle_signal(signum: int, frame: object) -> None:
        del frame
        _forward_signal(processes, signum)

    try:
        for signal_number in previous_handlers:
            signal.signal(signal_number, handle_signal)
        _wait_for_gateway(provider, _gateway_wait_seconds())
        worker = subprocess.Popen(command, stdin=None, stdout=None, stderr=None)
        processes = (provider, worker)
        next_gateway_check = time.monotonic() + _GATEWAY_HEALTH_INTERVAL_SECONDS
        readiness_failures = 0
        try:
            while True:
                worker_code = worker.poll()
                provider_code = provider.poll()
                if worker_code is not None:
                    return _returncode(worker_code)
                if provider_code is not None:
                    _stop_process(worker)
                    return _returncode(provider_code) or 1
                now = time.monotonic()
                if now >= next_gateway_check:
                    next_gateway_check = now + _GATEWAY_HEALTH_INTERVAL_SECONDS
                    if _gateway_ready():
                        readiness_failures = 0
                    else:
                        readiness_failures += 1
                        if readiness_failures >= _GATEWAY_HEALTH_FAILURE_LIMIT:
                            _stop_process(worker)
                            _stop_process(provider)
                            return 1
                time.sleep(0.1)
        finally:
            for signal_number, handler in previous_handlers.items():
                signal.signal(signal_number, handler)
    finally:
        if worker is not None:
            _stop_process(worker)
        _stop_process(provider)


if __name__ == "__main__":
    prepare()
    if len(sys.argv) < 2:
        raise SystemExit(64)
    command = tuple(sys.argv[1:])
    if _worker_mode(command):
        try:
            raise SystemExit(_run_worker(command))
        except (OSError, ValueError):
            raise SystemExit(75) from None
    os.execvp(command[0], command)
