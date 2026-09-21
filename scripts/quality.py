"""Run the canonical local/CI quality stages without mutating the repository."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
PYTHON_ROOTS: Final = ("packages", "apps", "integrations", "scripts", "tests")
EXCLUDED_PYTHON_TARGETS: Final = frozenset({"scripts/validate_g0.py"})
STAGE_TIMEOUT_SECONDS: Final = 360
UNIT_STAGE_TIMEOUT_SECONDS: Final = 540
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
        QualityStage("spec", ("scripts/spec_gate.py", "snapshot")),
        QualityStage("format", ("-m", "ruff", "format", "--no-cache", "--check", *targets)),
        QualityStage("lint", ("-m", "ruff", "check", "--no-cache", *targets)),
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


def _run_stage(stage: QualityStage, environment: dict[str, str]) -> int:
    command = (sys.executable, "-I", *stage.arguments)
    print(f"==> {stage.name}: {' '.join(command)}", flush=True)
    try:
        completed = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=False,
            timeout=stage.timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        print(f"{stage.name}: timed out after {stage.timeout_seconds}s", file=sys.stderr)
        return 124
    return completed.returncode


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
