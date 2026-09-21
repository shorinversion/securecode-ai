"""Closed compile and test command planning for OCI repair validation."""

from __future__ import annotations

import json
import re
import shutil
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

_NODE_SUFFIXES = frozenset({".js", ".mjs", ".cjs"})
_TYPESCRIPT_SUFFIXES = frozenset({".jsx", ".ts", ".mts", ".cts", ".tsx"})
_SUPPORTED_SUFFIXES = frozenset({".py", ".go"}) | _NODE_SUFFIXES | _TYPESCRIPT_SUFFIXES
_MAX_COMPILE_PATHS = 256
_DEPENDENCIES_UNAVAILABLE = "VALIDATION_DEPENDENCIES_UNAVAILABLE"
_GO_REQUIRE = re.compile(r"(?m)^\s*require(?:\s|\()")


class OciCommandPolicyError(ValueError):
    """The repository command policy cannot be derived without guessing."""


@dataclass(frozen=True, slots=True)
class OciCommandPlan:
    commands: tuple[tuple[str, ...], ...]
    indeterminate_reason: str | None = None


def compile_commands(root: Path) -> tuple[tuple[str, ...], ...]:
    return compile_plan(root).commands


def compile_plan(root: Path) -> OciCommandPlan:
    commands: list[tuple[str, ...]] = []
    indeterminate = False
    files = _supported_files(root)
    python = shutil.which("python") or sys.executable
    if any(path.suffix.lower() == ".py" for path in files):
        commands.append((python, "-I", "-m", "compileall", "-q", "."))
    node = shutil.which("node")
    node_files = tuple(path for path in files if path.suffix.lower() in _NODE_SUFFIXES)
    if node_files:
        if not node:
            indeterminate = True
        else:
            commands.extend((node, "--check", str(path)) for path in node_files)
    typed_files = tuple(path for path in files if path.suffix.lower() in _TYPESCRIPT_SUFFIXES)
    if typed_files:
        typescript = shutil.which("tsc")
        if not typescript:
            indeterminate = True
        else:
            commands.append(
                (
                    typescript,
                    "--noEmit",
                    "--noCheck",
                    "--pretty",
                    "false",
                    "--allowJs",
                    "--checkJs",
                    "false",
                    "--jsx",
                    "preserve",
                    "--module",
                    "preserve",
                    "--moduleResolution",
                    "bundler",
                    "--target",
                    "es2022",
                    *(str(path) for path in typed_files),
                )
            )
        config = root / "tsconfig.json"
        if (
            typescript
            and config.is_file()
            and not config.is_symlink()
            and _node_dependencies_available(root)
        ):
            commands.append(
                (
                    typescript,
                    "--noEmit",
                    "--pretty",
                    "false",
                    "--skipLibCheck",
                    "--project",
                    str(config),
                )
            )
        elif config.is_file() and not config.is_symlink():
            indeterminate = True
    go = shutil.which("go")
    if any(path.suffix.lower() == ".go" for path in files):
        module = root / "go.mod"
        if module.is_symlink():
            raise OciCommandPolicyError
        gofmt = shutil.which("gofmt")
        if not go or not gofmt or not module.is_file():
            indeterminate = True
        else:
            commands.extend(
                (gofmt, "-d", str(path)) for path in files if path.suffix.lower() == ".go"
            )
            try:
                module_text = module.read_text(encoding="utf-8")
            except (OSError, UnicodeError):
                raise OciCommandPolicyError from None
            vendor = root / "vendor"
            if _GO_REQUIRE.search(module_text) and not (
                vendor.is_dir() and not vendor.is_symlink()
            ):
                indeterminate = True
            else:
                commands.append((go, "test", "-run", "^$", "./..."))
    return OciCommandPlan(tuple(commands), _DEPENDENCIES_UNAVAILABLE if indeterminate else None)


def _supported_files(root: Path) -> tuple[Path, ...]:
    files = tuple(
        sorted(
            path
            for path in root.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and ".git" not in path.parts
            and path.suffix.lower() in _SUPPORTED_SUFFIXES
        )
    )
    if len(files) > _MAX_COMPILE_PATHS:
        raise OciCommandPolicyError
    return files


def test_commands(root: Path) -> tuple[tuple[str, ...], ...]:
    commands: list[tuple[str, ...]] = []
    python = shutil.which("python") or sys.executable
    if (root / "tests").is_dir() or any(
        (root / name).is_file() for name in ("pytest.ini", "pyproject.toml", "setup.cfg")
    ):
        commands.append((python, "-I", "-m", "pytest", "-q"))
    package = root / "package.json"
    npm = shutil.which("npm")
    if npm and package.is_file():
        try:
            document = json.loads(package.read_text(encoding="utf-8"))
        except Exception:
            raise OciCommandPolicyError from None
        if (
            type(document) is dict
            and type(document.get("scripts")) is dict
            and "test" in document["scripts"]
        ):
            commands.append((npm, "test"))
    go = shutil.which("go")
    if go and (root / "go.mod").is_file():
        commands.append((go, "test", "./..."))
    return tuple(commands)


def test_plan(root: Path) -> OciCommandPlan:
    if (
        not _node_dependencies_available(root)
        or _go_dependencies_unavailable(root)
        or _python_dependencies_unavailable(root)
    ):
        return OciCommandPlan((), _DEPENDENCIES_UNAVAILABLE)
    return OciCommandPlan(test_commands(root))


def _node_dependencies_available(root: Path) -> bool:
    package = root / "package.json"
    if not package.is_file() or package.is_symlink():
        return True
    try:
        document = json.loads(package.read_text(encoding="utf-8"))
    except Exception:
        raise OciCommandPolicyError from None
    if type(document) is not dict:
        raise OciCommandPolicyError
    declared = any(
        type(document.get(key)) is dict and bool(document[key])
        for key in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        )
    )
    modules = root / "node_modules"
    return not declared or (modules.is_dir() and not modules.is_symlink())


def _go_dependencies_unavailable(root: Path) -> bool:
    module = root / "go.mod"
    if not module.is_file() or module.is_symlink():
        return False
    try:
        required = _GO_REQUIRE.search(module.read_text(encoding="utf-8")) is not None
    except (OSError, UnicodeError):
        raise OciCommandPolicyError from None
    vendor = root / "vendor"
    return required and not (vendor.is_dir() and not vendor.is_symlink())


def _python_dependencies_unavailable(root: Path) -> bool:
    if any(path.is_file() and not path.is_symlink() for path in root.glob("requirements*.txt")):
        return True
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file() or pyproject.is_symlink():
        return False
    try:
        document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        raise OciCommandPolicyError from None
    project = document.get("project")
    if type(project) is dict and (
        bool(project.get("dependencies")) or bool(project.get("optional-dependencies"))
    ):
        return True
    if bool(document.get("dependency-groups")):
        return True
    tool = document.get("tool")
    if type(tool) is not dict:
        return False
    poetry = tool.get("poetry")
    dependencies = poetry.get("dependencies") if type(poetry) is dict else None
    if type(dependencies) is dict and any(key.casefold() != "python" for key in dependencies):
        return True
    if type(poetry) is dict and bool(poetry.get("group")):
        return True
    pdm = tool.get("pdm")
    return type(pdm) is dict and bool(pdm.get("dependencies") or pdm.get("dev-dependencies"))


__all__ = [
    "OciCommandPlan",
    "OciCommandPolicyError",
    "compile_commands",
    "compile_plan",
    "test_commands",
    "test_plan",
]
