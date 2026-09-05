"""Cross-platform, fail-closed launcher for SecureCode AI pre-commit hooks."""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Final

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
EXPECTED_UV_VERSION: Final = "uv 0.12.0"
COMMANDS: Final = {
    "development": (
        "run",
        "--locked",
        "--offline",
        "--no-sync",
        "--group",
        "quality",
        "python",
        "-I",
        "-m",
        "pytest",
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
        "-o",
        "xfail_strict=true",
        "--strict-config",
        "--strict-markers",
        "--import-mode=importlib",
        "-q",
    ),
    "policy": (
        "run",
        "--locked",
        "--offline",
        "--no-sync",
        "--only-group",
        "quality",
        "python",
        "-I",
        "scripts/ci_policy.py",
        "validate",
    ),
    "secrets": (
        "run",
        "--locked",
        "--offline",
        "--no-sync",
        "--only-group",
        "quality",
        "python",
        "-I",
        "scripts/ci_policy.py",
        "secrets",
    ),
    "workflow": (
        "run",
        "--locked",
        "--offline",
        "--no-sync",
        "--only-group",
        "quality",
        "zizmor",
        "--offline",
        "--strict-collection",
        "--persona=pedantic",
        ".",
    ),
    "quality": (
        "run",
        "--locked",
        "--offline",
        "--no-sync",
        "--group",
        "quality",
        "python",
        "-I",
        "scripts/quality.py",
    ),
}


def child_environment() -> dict[str, str]:
    """Remove resolver/interpreter overrides and use an ignored local cache."""

    environment = dict(os.environ)
    for key in tuple(environment):
        if key.startswith(("UV_", "PIP_", "PYTHON")) or key == "VIRTUAL_ENV":
            environment.pop(key)
    cache = REPOSITORY_ROOT / "work" / "precommit-uv-cache"
    cache.mkdir(parents=True, exist_ok=True)
    environment["UV_CACHE_DIR"] = str(cache)
    environment["UV_NO_PROGRESS"] = "1"
    return environment


def project_uv() -> Path:
    """Return the project-owned uv binary or fail before any hook command runs."""

    relative = Path("Scripts/uv.exe") if os.name == "nt" else Path("bin/uv")
    executable = REPOSITORY_ROOT / ".venv" / relative
    if not executable.is_file():
        raise RuntimeError("project uv is missing; run the locked environment setup first")
    return executable


def build_command(selection: str, filenames: Sequence[str]) -> tuple[str, ...]:
    """Build a closed hook command or a bounded list of explicit unit-test files."""

    arguments = COMMANDS.get(selection)
    if arguments is None:
        raise RuntimeError(f"unknown pre-commit selection: {selection}")
    if selection == "development":
        if not 1 <= len(filenames) <= 8 or len(set(filenames)) != len(filenames):
            raise RuntimeError("development requires one to eight distinct test files")
        for filename in filenames:
            if re.fullmatch(r"tests/unit/test_[a-z0-9_]+\.py", filename) is None:
                raise RuntimeError("development accepts explicit unit-test files only")
            target = REPOSITORY_ROOT / filename
            if not target.is_file() or target.resolve() != REPOSITORY_ROOT.resolve() / filename:
                raise RuntimeError("development test must be a regular repository file")
    elif filenames:
        raise RuntimeError(f"{selection} does not accept file arguments")
    return (str(project_uv()), *arguments, *filenames)


def development_environment(temporary_root: Path) -> dict[str, str]:
    """Do not pass parent credentials or interpreter/plugin overrides to tests."""

    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required for development checks")
    environment = {
        name: os.environ[name]
        for name in ("COMSPEC", "LANG", "LC_ALL", "PATHEXT", "SYSTEMROOT", "WINDIR")
        if name in os.environ
    }
    environment.update(
        {
            "PATH": os.pathsep.join((str(project_uv().parent), str(Path(git).parent))),
            "HOME": str(temporary_root),
            "USERPROFILE": str(temporary_root),
            "TEMP": str(temporary_root),
            "TMP": str(temporary_root),
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONHASHSEED": "0",
            "UV_CACHE_DIR": str(REPOSITORY_ROOT / "work" / "precommit-uv-cache"),
            "UV_NO_PROGRESS": "1",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
        }
    )
    return environment


def windows_taskkill() -> Path:
    """Resolve the OS-owned tree terminator without trusting PATH or environment."""

    loader = getattr(ctypes, "WinDLL", None)
    if not callable(loader):
        raise RuntimeError("system process-tree terminator is unavailable")
    kernel = loader("kernel32", use_last_error=True)
    get_directory = kernel.GetSystemDirectoryW
    get_directory.argtypes = (ctypes.c_wchar_p, ctypes.c_uint)
    get_directory.restype = ctypes.c_uint
    buffer = ctypes.create_unicode_buffer(32768)
    length = get_directory(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise RuntimeError("system process-tree terminator is unavailable")
    executable = Path(buffer.value) / "taskkill.exe"
    if not executable.is_absolute() or not executable.is_file():
        raise RuntimeError("system process-tree terminator is unavailable")
    return executable


def terminate_development_tree(
    process: subprocess.Popen[bytes],
    environment: dict[str, str],
    terminator: Path | None,
) -> None:
    """Stop the owned process tree before reaping its leader, with bounded cleanup."""

    try:
        if terminator is not None:
            completed = subprocess.run(
                (str(terminator), "/PID", str(process.pid), "/T", "/F"),
                env=environment,
                cwd=REPOSITORY_ROOT,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            if completed.returncode != 0:
                raise RuntimeError("development process-tree termination failed")
        else:
            kill_group = getattr(os, "killpg", None)
            kill_signal = getattr(signal, "SIGKILL", None)
            if not callable(kill_group) or kill_signal is None:
                raise RuntimeError("process-group termination is unavailable")
            kill_group(process.pid, kill_signal)
    finally:
        # Reap our child even when the OS tree terminator reports an error.
        # Cleanup failure propagates; it can never become a successful test run.
        if process.poll() is None:
            process.kill()
        process.wait(timeout=10)


def run_development(
    command: Sequence[str],
    environment: dict[str, str],
    *,
    timeout: float = 360,
) -> int:
    """Own the launcher and terminate its descendants when the deadline expires."""

    terminator = windows_taskkill() if os.name == "nt" else None
    process = subprocess.Popen(
        command,
        cwd=REPOSITORY_ROOT,
        env=environment,
        shell=False,
        start_new_session=os.name != "nt",
    )
    try:
        return process.wait(timeout=timeout)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        terminate_development_tree(process, environment, terminator)
        raise RuntimeError("development checks exceeded their execution boundary") from None


def main(argv: Sequence[str] | None = None) -> int:
    """Verify the executable identity and propagate the selected hook result."""

    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        print("PRE_COMMIT_ENTRY=FAIL (missing selection)", file=sys.stderr)
        return 2
    try:
        command = build_command(values[0], values[1:])
        environment = child_environment()
        version = subprocess.run(
            [command[0], "--version"],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if version.returncode != 0 or version.stdout.split()[:2] != EXPECTED_UV_VERSION.split():
            raise RuntimeError("project uv version differs from the locked tool version")
        with tempfile.TemporaryDirectory(prefix="securecode-development-") as temporary:
            if values[0] == "development":
                environment = development_environment(Path(temporary))
                return run_development(command, environment)
            completed = subprocess.run(
                command,
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=False,
                timeout=600,
            )
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"PRE_COMMIT_ENTRY=FAIL ({error})", file=sys.stderr)
        return 2
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
