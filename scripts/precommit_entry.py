"""Cross-platform, fail-closed launcher for SecureCode AI pre-commit hooks."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
EXPECTED_UV_VERSION: Final = "uv 0.12.0"
COMMANDS: Final = {
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
    """Build one closed command; only the secret hook accepts file arguments."""

    arguments = COMMANDS.get(selection)
    if arguments is None:
        raise RuntimeError(f"unknown pre-commit selection: {selection}")
    if filenames:
        raise RuntimeError(f"{selection} does not accept file arguments")
    return (str(project_uv()), *arguments, *filenames)


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
