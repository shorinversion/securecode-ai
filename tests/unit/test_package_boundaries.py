"""Executable baseline for the P1 repository and dependency boundaries."""

from __future__ import annotations

import ast
import importlib
import importlib.metadata
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class PackagePolicy:
    source_root: Path
    package_prefix: str
    allowed_absolute_prefixes: frozenset[str]


POLICIES = (
    PackagePolicy(
        REPOSITORY_ROOT / "packages" / "contracts" / "src",
        "securecode_ai.contracts",
        frozenset({"pydantic", "securecode_ai.contracts"}),
    ),
    PackagePolicy(
        REPOSITORY_ROOT / "packages" / "core" / "src",
        "securecode_ai.core",
        frozenset({"securecode_ai.contracts", "securecode_ai.core"}),
    ),
)
DYNAMIC_IMPORT_NAMES = frozenset({"__import__", "compile", "eval", "exec"})
DYNAMIC_IMPORT_ATTRIBUTES = frozenset({"importlib.import_module", "importlib.__import__"})
BLOCKED_STDLIB_IMPORT_ROOTS = frozenset({"builtins", "importlib", "runpy"})


def _python_files(root: Path) -> Iterable[Path]:
    yield from root.rglob("*.py")


def _dotted_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _dotted_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _allowed_absolute(module_name: str, policy: PackagePolicy) -> bool:
    root = module_name.partition(".")[0]
    if root in BLOCKED_STDLIB_IMPORT_ROOTS:
        return False
    if root in sys.stdlib_module_names:
        return True
    return any(
        module_name == prefix or module_name.startswith(f"{prefix}.")
        for prefix in policy.allowed_absolute_prefixes
    )


def _relative_target(path: Path, node: ast.ImportFrom, policy: PackagePolicy) -> str | None:
    relative = path.relative_to(policy.source_root).with_suffix("")
    current_parts = [*relative.parts[:-1]]
    if node.level > len(current_parts):
        return None
    retained = current_parts[: len(current_parts) - node.level + 1]
    target_parts = [*retained, *(node.module.split(".") if node.module else ())]
    return ".".join(target_parts)


def _policy_violations(path: Path, policy: PackagePolicy) -> list[str]:
    violations: list[str] = []
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            violations.extend(
                f"undeclared absolute import: {alias.name}"
                for alias in node.names
                if not _allowed_absolute(alias.name, policy)
            )
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                target = _relative_target(path, node, policy)
                if target is None or not (
                    target == policy.package_prefix
                    or target.startswith(f"{policy.package_prefix}.")
                ):
                    violations.append(
                        f"relative import escapes package: {node.level}:{node.module}"
                    )
            elif node.module and not _allowed_absolute(node.module, policy):
                violations.append(f"undeclared absolute import: {node.module}")
        elif isinstance(node, ast.Call):
            callable_name = _dotted_name(node.func)
            if callable_name in DYNAMIC_IMPORT_NAMES | DYNAMIC_IMPORT_ATTRIBUTES:
                violations.append(f"dynamic import is not permitted: {callable_name}")
        elif isinstance(node, ast.Name) and node.id in DYNAMIC_IMPORT_NAMES:
            violations.append(f"dynamic loader reference is not permitted: {node.id}")
    return violations


@pytest.mark.parametrize(
    "module_name",
    ["securecode_ai.adapters", "securecode_ai.contracts", "securecode_ai.core"],
)
def test_workspace_packages_are_importable(module_name: str) -> None:
    module = importlib.import_module(module_name)
    assert module.__file__ is not None


def test_securecode_ai_remains_an_implicit_namespace() -> None:
    namespace = importlib.import_module("securecode_ai")
    assert namespace.__file__ is None


def test_domain_imports_follow_closed_package_allow_lists() -> None:
    violations = {
        str(path.relative_to(REPOSITORY_ROOT)): found
        for policy in POLICIES
        for path in _python_files(policy.source_root)
        if (found := _policy_violations(path, policy))
    }
    assert violations == {}


@pytest.mark.parametrize(
    ("distribution", "expected_dependency"),
    [
        ("securecode-ai-adapters", "securecode-ai-core==0.1.0a0"),
        ("securecode-ai-contracts", "pydantic>=2.12,<3"),
        ("securecode-ai-core", "securecode-ai-contracts==0.1.0a0"),
    ],
)
def test_declared_dependencies_point_inward(distribution: str, expected_dependency: str) -> None:
    requirements = importlib.metadata.requires(distribution) or []
    assert requirements == [expected_dependency]


@pytest.mark.parametrize(
    ("source", "expected_fragment"),
    [
        ("from securecode_ai.adapters import llm\n", "securecode_ai.adapters"),
        ("import asyncpg\n", "asyncpg"),
        ("import importlib\nimportlib.import_module('redis')\n", "dynamic import"),
        ("from importlib import import_module\nimport_module('redis')\n", "importlib"),
        ("from builtins import __import__ as load\nload('redis')\n", "builtins"),
    ],
)
def test_closed_policy_rejects_infrastructure_and_dynamic_imports(
    tmp_path: Path, source: str, expected_fragment: str
) -> None:
    policy = POLICIES[1]
    path = tmp_path / "module.py"
    path.write_text(source, encoding="utf-8")
    violations = _policy_violations(path, policy)
    assert any(expected_fragment in violation for violation in violations)
