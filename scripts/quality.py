"""Run the canonical local/CI quality stages without mutating the repository."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
PYTHON_ROOTS: Final = ("packages", "apps", "integrations", "scripts", "tests")
EXCLUDED_PYTHON_TARGETS: Final = frozenset({"scripts/validate_g0.py"})
STAGE_TIMEOUT_SECONDS: Final = 360

# Windows refuses to spawn a process whose command line exceeds 32767
# characters; batches stay well below that while the file set is unchanged.
MAX_ARGUMENT_BYTES: Final = 24_000
UNIT_STAGE_TIMEOUT_SECONDS: Final = 900
GIT_TIMEOUT_SECONDS: Final = 30
SAFE_PARENT_VARIABLES: Final = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "NO_COLOR",
    "PATHEXT",
    "SYSTEMROOT",
    "WINDIR",
)


@dataclass(frozen=True, slots=True)
class QualityStage:
    """One deterministic quality command."""

    name: str
    arguments: tuple[str, ...]
    executes_repository_code: bool = False
    timeout_seconds: int = STAGE_TIMEOUT_SECONDS
    chunked: bool = False
    response_file: bool = False


def _python_targets() -> tuple[str, ...]:
    """Return every first-party Python file in deterministic repository order."""

    targets: set[str] = set()
    for root_name in PYTHON_ROOTS:
        root = REPOSITORY_ROOT / root_name
        if root.exists():
            targets.update(
                path.relative_to(REPOSITORY_ROOT).as_posix() for path in root.rglob("*.py")
            )
    return tuple(sorted(targets - EXCLUDED_PYTHON_TARGETS))


def _stages(targets: tuple[str, ...]) -> tuple[QualityStage, ...]:
    return (
        QualityStage(
            "format",
            ("-m", "ruff", "format", "--no-cache", "--check", *targets),
            chunked=True,
        ),
        QualityStage(
            "lint",
            ("-m", "ruff", "check", "--no-cache", *targets),
            chunked=True,
        ),
        QualityStage(
            "types-linux",
            (
                "-m",
                "mypy",
                "--config-file",
                "pyproject.toml",
                "--no-incremental",
                "--platform",
                "linux",
                *targets,
            ),
            response_file=True,
        ),
        QualityStage(
            "types-win32",
            (
                "-m",
                "mypy",
                "--config-file",
                "pyproject.toml",
                "--no-incremental",
                "--platform",
                "win32",
                *targets,
            ),
            response_file=True,
        ),
        QualityStage(
            "unit",
            (
                "-m",
                "pytest",
                "-p",
                "pytest_cov",
                "-p",
                "no:cacheprovider",
                "-o",
                "addopts=",
                "-o",
                "xfail_strict=true",
                "--strict-config",
                "--strict-markers",
                "--import-mode=importlib",
                "-ra",
                "--cov=securecode_ai.core",
                "--cov-branch",
                "--cov-report=term-missing",
                "--cov-fail-under=80",
                "tests/unit",
                # The reviewer demo is exercised end to end with fake model runtimes.
                "tests/integration/test_p917_real_local_demo.py",
            ),
            executes_repository_code=True,
            timeout_seconds=UNIT_STAGE_TIMEOUT_SECONDS,
        ),
    )


def _sanitized_environment(temporary_root: Path) -> dict[str, str]:
    """Build a minimal child environment without credentials, proxies or Python injection."""

    git_executable = shutil.which("git")
    if git_executable is None:
        raise RuntimeError("git is required for the specification gate")
    tool_directories = tuple(
        dict.fromkeys((str(Path(sys.executable).parent), str(Path(git_executable).parent)))
    )
    environment = {
        name: value for name in SAFE_PARENT_VARIABLES if (value := os.environ.get(name)) is not None
    }
    environment.update(
        {
            "COVERAGE_FILE": str(temporary_root / ".coverage"),
            "HOME": str(temporary_root),
            "MYPY_CACHE_DIR": str(temporary_root / "mypy-cache"),
            "PATH": os.pathsep.join(tool_directories),
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "TEMP": str(temporary_root),
            "TMP": str(temporary_root),
            "USERPROFILE": str(temporary_root),
            "XDG_CACHE_HOME": str(temporary_root / "cache"),
        }
    )
    return environment


def _git_paths() -> tuple[Path, ...]:
    git_executable = shutil.which("git")
    if git_executable is None:
        raise RuntimeError("git is required for the repository-mutation oracle")
    git_environment = {
        name: value for name in SAFE_PARENT_VARIABLES if (value := os.environ.get(name)) is not None
    }
    git_environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    completed = subprocess.run(
        (
            git_executable,
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ),
        cwd=REPOSITORY_ROOT,
        env=git_environment,
        check=True,
        capture_output=True,
        timeout=GIT_TIMEOUT_SECONDS,
    )
    return tuple(
        REPOSITORY_ROOT / path
        for path in completed.stdout.decode("utf-8").rstrip("\0").split("\0")
        if path
    )


def _repository_snapshot() -> str:
    """Hash tracked and non-ignored untracked repository bytes and path identities."""

    digest = hashlib.sha256()
    for path in sorted(_git_paths()):
        relative_path = path.relative_to(REPOSITORY_ROOT).as_posix()
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        if path.is_file():
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(block)
        else:
            digest.update(b"<missing>")
        digest.update(b"\0")
    return digest.hexdigest()


def _chunked_commands(arguments: tuple[str, ...]) -> tuple[tuple[str, ...], ...]:
    """Split a trailing file list into batches the host can actually spawn."""

    boundary = next(
        (index for index, value in enumerate(arguments) if value.endswith(".py")),
        len(arguments),
    )
    prefix = arguments[:boundary]
    files = arguments[boundary:]
    if not files:
        return (arguments,)
    batches: list[tuple[str, ...]] = []
    current: list[str] = []
    size = 0
    for name in files:
        cost = len(name) + 1
        if current and size + cost > MAX_ARGUMENT_BYTES:
            batches.append((*prefix, *current))
            current = []
            size = 0
        current.append(name)
        size += cost
    if current:
        batches.append((*prefix, *current))
    return tuple(batches)


def _run_response_file_stage(
    stage: QualityStage,
    arguments: tuple[str, ...],
    environment: dict[str, str],
) -> int:
    """Run one mypy invocation, passing the file list through a response file.

    Splitting the file set would change module mapping (sibling ``app.py``
    fixtures would collide), so the list travels in a file the tool expands
    itself while the command line stays short enough for the host to spawn.
    """

    boundary = next(
        (index for index, value in enumerate(arguments) if value.endswith(".py")),
        len(arguments),
    )
    prefix = arguments[:boundary]
    files = arguments[boundary:]
    if not files:
        return _run_command(stage.name, prefix, environment, stage.timeout_seconds)
    descriptor, name = tempfile.mkstemp(prefix="securecode-quality-args-", suffix=".txt")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(chr(10).join(files))
        command = (*prefix, "@" + name)
        return _run_command(stage.name, command, environment, stage.timeout_seconds)
    finally:
        with suppress(OSError):
            Path(name).unlink()


def _run_command(
    label: str,
    arguments: tuple[str, ...],
    environment: dict[str, str],
    timeout_seconds: int,
) -> int:
    """Spawn one stage command and report a bounded, sanitized outcome."""

    command = (sys.executable, "-I", *arguments)
    print(f"==> {label}: {' '.join(command)}", flush=True)
    try:
        completed = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        print(f"{label}: timed out after {timeout_seconds}s", file=sys.stderr)
        return 124
    return completed.returncode


def _run_stage(stage: QualityStage, environment: dict[str, str]) -> int:
    commands = _chunked_commands(stage.arguments) if stage.chunked else (stage.arguments,)
    if stage.response_file:
        return _run_response_file_stage(stage, commands[0], environment)
    outcome = 0
    for index, arguments in enumerate(commands):
        command = (sys.executable, "-I", *arguments)
        label = stage.name if len(commands) == 1 else f"{stage.name} [{index + 1}/{len(commands)}]"
        print(f"==> {label}: {' '.join(command)}", flush=True)
        try:
            completed = subprocess.run(
                command,
                cwd=REPOSITORY_ROOT,
                env=environment,
                check=False,
                timeout=stage.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            print(f"{label}: timed out after {stage.timeout_seconds}s", file=sys.stderr)
            return 124
        if completed.returncode != 0 and outcome == 0:
            outcome = completed.returncode
    return outcome


def main() -> int:
    """Run static preflight first, then tests, and fail on repository mutation."""

    targets = _python_targets()
    stages = _stages(targets)
    before = _repository_snapshot()
    failures: list[tuple[str, int]] = []

    with tempfile.TemporaryDirectory(prefix="securecode-quality-") as temporary_directory:
        environment = _sanitized_environment(Path(temporary_directory))
        preflight_failed = False
        for stage in stages:
            if stage.executes_repository_code and preflight_failed:
                print(f"==> {stage.name}: SKIPPED (static preflight failed)", flush=True)
                failures.append((stage.name, 125))
                continue
            return_code = _run_stage(stage, environment)
            if return_code != 0:
                failures.append((stage.name, return_code))
                if not stage.executes_repository_code:
                    preflight_failed = True

    if _repository_snapshot() != before:
        failures.append(("repository-mutation", 126))

    if failures:
        summary = ", ".join(f"{name}={code}" for name, code in failures)
        print(f"QUALITY=FAIL ({summary})", file=sys.stderr)
        return 1

    print("QUALITY=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
