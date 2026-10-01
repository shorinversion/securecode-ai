"""Executable baseline for the P1 repository and dependency boundaries."""

from __future__ import annotations

import ast
import importlib
import importlib.metadata
import importlib.resources
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
        REPOSITORY_ROOT / "apps" / "cli" / "src",
        "securecode_ai.cli",
        frozenset(
            {
                "securecode_ai.adapters",
                "securecode_ai.cli",
                "securecode_ai.contracts",
                "securecode_ai.core",
            }
        ),
    ),
    PackagePolicy(
        REPOSITORY_ROOT / "packages" / "adapters" / "src",
        "securecode_ai.adapters",
        frozenset(
            {
                "securecode_ai.adapters",
                "securecode_ai.contracts",
                "securecode_ai.core",
                "pydantic",
                "tree_sitter",
                "tree_sitter_go",
                "tree_sitter_javascript",
                "tree_sitter_python",
                "tree_sitter_typescript",
            }
        ),
    ),
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
BLOCKED_STDLIB_IMPORT_ROOTS = frozenset({"builtins", "runpy"})


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
            if callable_name == "import_module":
                literal_module = (
                    node.args[0].value
                    if len(node.args) == 1
                    and not node.keywords
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    else None
                )
                if (
                    literal_module is None
                    or literal_module.partition(".")[0] not in sys.stdlib_module_names
                ):
                    violations.append("dynamic import is not a literal standard-library module")
            elif callable_name in DYNAMIC_IMPORT_NAMES | DYNAMIC_IMPORT_ATTRIBUTES:
                violations.append(f"dynamic import is not permitted: {callable_name}")
        elif isinstance(node, ast.Name) and node.id in DYNAMIC_IMPORT_NAMES:
            violations.append(f"dynamic loader reference is not permitted: {node.id}")
    return violations


@pytest.mark.parametrize(
    "module_name",
    [
        "securecode_ai.adapters",
        "securecode_ai.cli",
        "securecode_ai.contracts",
        "securecode_ai.core",
    ],
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
        (
            "securecode-ai-adapters",
            (
                "pydantic>=2.12,<3",
                "securecode-ai-contracts==1.1.0",
                "securecode-ai-core==1.1.0",
                "tree-sitter>=0.25,<0.26",
                "tree-sitter-go==0.25.0",
                "tree-sitter-javascript==0.25.0",
                "tree-sitter-python>=0.25,<0.26",
                "tree-sitter-typescript==0.23.2",
            ),
        ),
        (
            "securecode-ai-cli",
            (
                "securecode-ai-adapters==1.1.0",
                "securecode-ai-contracts==1.1.0",
                "securecode-ai-core==1.1.0",
            ),
        ),
        ("securecode-ai-contracts", "pydantic>=2.12,<3"),
        ("securecode-ai-core", "securecode-ai-contracts==1.1.0"),
    ],
)
def test_declared_dependencies_point_inward(
    distribution: str, expected_dependency: str | tuple[str, ...]
) -> None:
    requirements = importlib.metadata.requires(distribution) or []
    expected = (
        list(expected_dependency)
        if isinstance(expected_dependency, tuple)
        else [expected_dependency]
    )
    assert requirements == expected


def test_contract_package_contains_complete_public_schema_inventory() -> None:
    schema_root = importlib.resources.files("securecode_ai.contracts").joinpath("schemas", "v0.2.0")
    assert {item.name for item in schema_root.iterdir() if item.name.endswith(".schema.json")} == {
        "audit-event.schema.json",
        "audit-run.schema.json",
        "cli-doctor-result.schema.json",
        "cli-error-result.schema.json",
        "evidence.schema.json",
        "finding-case.schema.json",
        "model-call-result.schema.json",
        "model-request.schema.json",
        "patch-candidate.schema.json",
        "validation-result.schema.json",
        "workflow-definition.schema.json",
        "workflow-runtime-request.schema.json",
        "workflow-runtime-result.schema.json",
        "workflow-snapshot.schema.json",
        "workflow-transition-event.schema.json",
    }


def test_internal_telemetry_does_not_create_a_public_contract_root() -> None:
    contracts = importlib.import_module("securecode_ai.contracts")
    core = importlib.import_module("securecode_ai.core")
    adapters = importlib.import_module("securecode_ai.adapters")
    assert not hasattr(contracts, "TelemetryRecord")
    assert core.TelemetryRecord.__module__ == "securecode_ai.core.telemetry"
    assert adapters.InMemoryTelemetrySink.__module__ == "securecode_ai.adapters.telemetry"


def test_repository_intake_contract_stays_internal_and_adapter_owned() -> None:
    contracts = importlib.import_module("securecode_ai.contracts")
    core = importlib.import_module("securecode_ai.core")
    adapters = importlib.import_module("securecode_ai.adapters")
    assert not hasattr(contracts, "RepositoryInventory")
    assert core.RepositoryInventory.__module__ == "securecode_ai.core.repository"
    assert adapters.FileSystemRepositoryIntake.__module__ == "securecode_ai.adapters.repository"


def test_symbol_index_contract_stays_internal_and_adapter_owned() -> None:
    contracts = importlib.import_module("securecode_ai.contracts")
    core = importlib.import_module("securecode_ai.core")
    adapters = importlib.import_module("securecode_ai.adapters")
    assert not hasattr(contracts, "SymbolIndex")
    assert core.SymbolIndex.__module__ == "securecode_ai.core.symbols"
    assert adapters.build_python_symbol_index.__module__ == "securecode_ai.adapters.cst"


def test_program_graph_contract_stays_internal_and_adapter_owned() -> None:
    contracts = importlib.import_module("securecode_ai.contracts")
    core = importlib.import_module("securecode_ai.core")
    adapters = importlib.import_module("securecode_ai.adapters")
    assert not hasattr(contracts, "ProgramGraph")
    assert core.ProgramGraph.__module__ == "securecode_ai.core.program_graph"
    assert adapters.build_program_graph.__module__ == "securecode_ai.adapters.program_graph"


def test_scm_policy_and_baseline_are_available_through_core_api() -> None:
    core = importlib.import_module("securecode_ai.core")

    assert core.BaselineFingerprintSnapshot.__module__ == "securecode_ai.core.baseline_fingerprints"
    assert core.ScmPolicyDocument.__module__ == "securecode_ai.core.scm_policy"
    assert (
        core.compare_baseline_fingerprints.__module__ == "securecode_ai.core.baseline_fingerprints"
    )
    assert core.evaluate_scm_policy.__module__ == "securecode_ai.core.scm_policy"


@pytest.mark.parametrize(
    ("source", "expected_fragment"),
    [
        ("from securecode_ai.adapters import llm\n", "securecode_ai.adapters"),
        ("import asyncpg\n", "asyncpg"),
        ("import importlib\nimportlib.import_module('redis')\n", "dynamic import"),
        (
            "from importlib import import_module\nimport_module('redis')\n",
            "literal standard-library",
        ),
        ("from builtins import __import__ as load\nload('redis')\n", "builtins"),
    ],
)
def test_closed_policy_rejects_infrastructure_and_dynamic_imports(
    tmp_path: Path, source: str, expected_fragment: str
) -> None:
    policy = POLICIES[2]
    path = tmp_path / "module.py"
    path.write_text(source, encoding="utf-8")
    violations = _policy_violations(path, policy)
    assert any(expected_fragment in violation for violation in violations)
