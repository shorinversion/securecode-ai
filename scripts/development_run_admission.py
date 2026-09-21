"""Closed admission for supplemental P7.17 development detection runs.

This module deliberately performs no corpus, provider, or plan-command execution.
It only freezes and verifies identities before a runner is permitted to read source
data or create mutable run outputs.
"""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import marshal
import platform
import re
import stat
import subprocess
import sys
import types
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

RUN_ROOT = Path(".securecode/development-runs")
PLAN_SCHEMA = "development-benchmark-plan-1.1"
RECEIPT_SCHEMA = "development-benchmark-execution-receipt-1.1"
PATH_KEYS = ("plan", "records", "aggregate", "recomputed", "receipt")
RUN_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,63})\Z")
_PACKAGE_TREES = {
    "securecode_ai.adapters": "packages/adapters/src",
    "securecode_ai.core": "packages/core/src",
    "securecode_ai.contracts": "packages/contracts/src",
}
_REJECTED_SOURCE_SUFFIXES = {".pyd", ".so"}


@dataclass(frozen=True)
class Admission:
    """Verified run identity returned to the runner or independent recomputer."""

    root: Path
    plan_path: Path
    plan: dict[str, Any]
    paths: Mapping[str, Path]


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _json(path: Path) -> dict[str, Any]:
    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(path.read_bytes(), object_pairs_hook=pairs_hook)
    if type(value) is not dict:
        raise ValueError("JSON object required")
    return value


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        check=False,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise ValueError("candidate Git identity unavailable")
    return result.stdout.strip()


def _candidate_identity(root: Path) -> dict[str, str]:
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ValueError("candidate has dirty tracked bytes")
    head = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    if not re.fullmatch(r"[0-9a-f]{40}", head) or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise ValueError("unsupported candidate Git identity")
    return {"head": f"git-sha1:{head}", "tree": f"git-sha1:{tree}"}


def _has_reparse_component(path: Path) -> bool:
    current = Path(path.anchor) if path.anchor else Path()
    for part in path.parts[1:] if path.is_absolute() else path.parts:
        current /= part
        if not current.exists():
            continue
        attributes = getattr(current.stat(), "st_file_attributes", 0)
        if current.is_symlink() or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            return True
    return False


def _within(parent: Path, path: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _relative_path(root: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or not value or "\\" in value or ".." in path.parts:
        raise ValueError("run path must be a portable relative path")
    candidate = (root / path).resolve(strict=False)
    if _has_reparse_component(root / path) or not _within(root, candidate):
        raise ValueError("run path escapes through link or traversal")
    return candidate


def _run_paths(root: Path, run_id: str) -> dict[str, Path]:
    directory = root / RUN_ROOT / run_id
    return {
        "plan": directory / "plan.json",
        "records": directory / "records.jsonl",
        "aggregate": directory / "aggregate.json",
        "recomputed": directory / "recomputed.json",
        "receipt": directory / "receipt.json",
    }


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _trusted_python_files(package_root: Path) -> dict[str, str]:
    """List the executable source set, rejecting links, native code and orphan caches."""

    if not package_root.is_dir() or _has_reparse_component(package_root):
        raise ValueError("package source is unavailable")
    result: dict[str, str] = {}
    for path in sorted(package_root.rglob("*")):
        if _has_reparse_component(path):
            raise ValueError("package source contains a link or reparse point")
        if path.is_dir():
            continue
        if path.suffix.lower() in _REJECTED_SOURCE_SUFFIXES:
            raise ValueError("native extension is not admitted")
        relative = path.relative_to(package_root)
        if path.suffix == ".py":
            if "__pycache__" in relative.parts:
                raise ValueError("Python source inside __pycache__ is not admitted")
            result[relative.as_posix()] = _sha256(path.read_bytes())
        elif path.suffix == ".pyc":
            _verify_cache_file(path)
    return result


def _verify_cache_file(cache: Path) -> None:
    """Accept only bytecode that compiles to the exact admitted source bytes."""

    if cache.parent.name != "__pycache__":
        raise ValueError("sourceless bytecode is not admitted")
    source_stem = cache.name.split(".", 1)[0]
    source = cache.parent.parent / f"{source_stem}.py"
    if not source.is_file() or _has_reparse_component(source):
        raise ValueError("stale cache-only bytecode is not admitted")
    optimization = _cache_optimization(cache, source)
    payload = cache.read_bytes()
    if len(payload) < 16 or payload[:4] != importlib.util.MAGIC_NUMBER:
        raise ValueError("bytecode cache magic or header is invalid")
    flags = int.from_bytes(payload[4:8], byteorder="little")
    if flags not in {0, 3}:
        raise ValueError("bytecode cache flags are unsupported")
    try:
        cached = marshal.loads(payload[16:])
        expected = compile(
            source.read_bytes(), str(source), "exec", dont_inherit=True, optimize=optimization
        )
    except (EOFError, SyntaxError, ValueError) as error:
        raise ValueError("bytecode cache is malformed") from error
    if not isinstance(cached, types.CodeType):
        raise ValueError("bytecode cache does not contain a code object")
    if _normalize_code(cached) != _normalize_code(expected):
        raise ValueError("bytecode cache code differs from exact source")


def _cache_optimization(cache: Path, source: Path) -> int:
    tag = sys.implementation.cache_tag
    if type(tag) is not str:
        raise ValueError("Python cache tag is unavailable")
    if cache.name == f"{source.stem}.{tag}.pyc":
        return 0
    match = re.fullmatch(
        rf"{re.escape(source.stem)}\.{re.escape(tag)}\.opt-([12])\.pyc", cache.name
    )
    if match is None:
        raise ValueError("bytecode cache filename is unsupported")
    optimization = int(match.group(1))
    return optimization


def _normalize_code(code: types.CodeType) -> types.CodeType:
    constants = tuple(
        _normalize_code(value) if isinstance(value, types.CodeType) else value
        for value in code.co_consts
    )
    return code.replace(co_filename="<securecode-bound-source>", co_consts=constants)


def _source_bindings(root: Path) -> dict[str, dict[str, str]]:
    """Bind every candidate production Python byte, not just direct imports."""

    result: dict[str, dict[str, str]] = {}
    for module, source_root in _PACKAGE_TREES.items():
        package_name = module.rsplit(".", maxsplit=1)[1]
        package_root = root / source_root / "securecode_ai" / package_name
        for relative, digest in _trusted_python_files(package_root).items():
            path = f"securecode_ai/{package_name}/{relative}"
            result[f"{module}:{path}"] = {"path": path, "sha256": digest}
    return result


def _environment(root: Path) -> dict[str, str]:
    lock = root / "uv.lock"
    if not lock.is_file():
        raise ValueError("uv lock unavailable")
    return {
        "interpreter": str(Path(sys.executable).resolve()),
        "python_implementation": sys.implementation.name,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "uv_lock_sha256": _sha256(lock.read_bytes()),
    }


def _run_id_from_output(root: Path, output: Path) -> str:
    resolved = output.resolve(strict=False)
    prefix = (root / RUN_ROOT).resolve(strict=False)
    if not _within(prefix, resolved) or resolved.name != "plan.json":
        raise ValueError("plan must be .securecode/development-runs/<runid>/plan.json")
    relative = resolved.relative_to(prefix)
    if len(relative.parts) != 2 or not RUN_ID.fullmatch(relative.parts[0]):
        raise ValueError("invalid development run id")
    if _has_reparse_component(root / RUN_ROOT / relative.parts[0]):
        raise ValueError("run directory contains a link or reparse point")
    return relative.parts[0]


def _expected_argv(root: Path, paths: Mapping[str, Path]) -> dict[str, list[str]]:
    plan = _relative(root, paths["plan"])
    records = _relative(root, paths["records"])
    aggregate = _relative(root, paths["aggregate"])
    recomputed = _relative(root, paths["recomputed"])
    receipt = _relative(root, paths["receipt"])
    return {
        "execute": [
            str(Path(sys.executable).resolve()),
            "scripts/run_development_benchmark.py",
            "--plan",
            plan,
            "--records",
            records,
            "--aggregate",
            aggregate,
            "--receipt",
            receipt,
        ],
        "recompute": [
            str(Path(sys.executable).resolve()),
            "scripts/recompute_development_benchmark.py",
            "--plan",
            plan,
            "--records",
            records,
            "--output",
            recomputed,
            "--receipt",
            receipt,
        ],
    }


def prepare_plan(
    *,
    root: Path,
    output: Path,
    bindings: Mapping[str, str],
    environment: Mapping[str, object],
) -> dict[str, Any]:
    """Freeze a new untracked 1.1 plan without executing it."""

    root = root.resolve()
    if _has_reparse_component(root):
        raise ValueError("repository root contains a link or reparse point")
    run_id = _run_id_from_output(root, output)
    paths = _run_paths(root, run_id)
    if output.resolve(strict=False) != paths["plan"].resolve(strict=False):
        raise ValueError("plan output aliases its required path")
    if any(path.exists() for path in paths.values()):
        raise ValueError("development run paths already exist")
    identity = _candidate_identity(root)
    historical = _json(root / "evaluation/development/run-plan.yaml")
    if historical.get("schema_version") != "development-benchmark-plan-1.0":
        raise ValueError("historical plan is not frozen plan 1.0")
    if set(bindings) != {
        "component_sha256",
        "core_sha256",
        "recompute_sha256",
        "corpus_validator_sha256",
        "prompt_sha256",
        "policy_sha256",
        "schema_sha256",
        "admission_sha256",
    }:
        raise ValueError("prepare requires every current component binding")
    plan = {
        **historical,
        "schema_version": PLAN_SCHEMA,
        "study_id": f"p7.17-development-detection-1.1-{run_id}-{identity['head'][9:21]}",
        "candidate_commit": identity["head"],
        "bindings": dict(bindings),
        "environment": dict(environment),
        "execution": {
            "candidate": identity,
            "environment": _environment(root),
            "package_source_bindings": _source_bindings(root),
            "paths": {name: _relative(root, path) for name, path in paths.items()},
            "argv": _expected_argv(root, paths),
        },
    }
    paths["plan"].parent.mkdir(parents=True, exist_ok=False)
    paths["plan"].write_bytes(_canonical(plan))
    return plan


def _admitted_paths(root: Path, plan_path: Path, plan: Mapping[str, Any]) -> dict[str, Path]:
    _verify_frozen_matrix(root, plan)
    execution = plan.get("execution")
    if type(execution) is not dict or set(execution) != {
        "candidate",
        "environment",
        "package_source_bindings",
        "paths",
        "argv",
    }:
        raise ValueError("missing closed execution metadata")
    paths = execution["paths"]
    if type(paths) is not dict or set(paths) != set(PATH_KEYS):
        raise ValueError("invalid execution paths")
    candidate = execution["candidate"]
    if type(candidate) is not dict or set(candidate) != {"head", "tree"}:
        raise ValueError("invalid candidate metadata")
    identity = _candidate_identity(root)
    if candidate != identity or plan.get("candidate_commit") != identity["head"]:
        raise ValueError("stale candidate HEAD or tree")
    expected = _run_paths(root, _run_id_from_output(root, plan_path))
    result = {name: _relative_path(root, value) for name, value in paths.items()}
    if result != expected or plan_path.resolve(strict=False) != result["plan"]:
        raise ValueError("execution paths are not the declared run directory")
    if execution["environment"] != _environment(root):
        raise ValueError("interpreter, platform, or lock identity drift")
    expected_bindings = _source_bindings(root)
    if execution["package_source_bindings"] != expected_bindings:
        raise ValueError("candidate package source binding drift")
    bindings = plan.get("bindings")
    if type(bindings) is not dict or bindings.get("admission_sha256") != _sha256(
        (root / "scripts/development_run_admission.py").read_bytes()
    ):
        raise ValueError("admission helper binding drift")
    expected_argv = _expected_argv(root, result)
    if execution["argv"] != expected_argv:
        raise ValueError("execution argv binding drift")
    return result


def _verify_frozen_matrix(root: Path, plan: Mapping[str, Any]) -> None:
    """Keep 1.1 as a new execution envelope around the exact 1.0 matrix."""

    historical = _json(root / "evaluation/development/run-plan.yaml")
    if historical.get("schema_version") != "development-benchmark-plan-1.0":
        raise ValueError("historical plan is not frozen plan 1.0")
    mutable = {
        "schema_version",
        "study_id",
        "candidate_commit",
        "bindings",
        "environment",
        "reproduction_commands",
        "execution",
    }
    if set(plan) != set(historical).union({"execution"}):
        raise ValueError("supplemental plan has unknown or missing top-level fields")
    for key in set(historical).difference(mutable):
        if plan.get(key) != historical[key]:
            raise ValueError(f"supplemental plan changed frozen {key}")
    if plan.get("schema_version") != PLAN_SCHEMA:
        raise ValueError("supplemental plan schema drift")
    repetitions = plan.get("repetitions")
    if repetitions != {
        "deterministic_only": 1,
        "scanner_seeded_investigation": 3,
        "model_native_only": 3,
        "one_shot_llm": 3,
        "full_hybrid": 3,
    }:
        raise ValueError("supplemental plan repetition matrix drift")
    if plan.get("budget") != {"tokens": 4096, "calls": 1, "wall_seconds": 60, "retries": 0}:
        raise ValueError("supplemental plan budget drift")


def verify_imported_package_bindings(plan: Mapping[str, Any]) -> None:
    """Bind product import locations before the runner imports their executable code."""

    execution = plan.get("execution")
    if type(execution) is not dict:
        raise ValueError("missing execution metadata")
    bindings = execution.get("package_source_bindings")
    if type(bindings) is not dict:
        raise ValueError("missing package source bindings")
    expected_by_module = _expected_package_trees(bindings)
    parent = importlib.machinery.PathFinder.find_spec("securecode_ai")
    if (
        parent is None
        or parent.loader is not None
        or parent.origin is not None
        or parent.submodule_search_locations is None
    ):
        raise ValueError("securecode_ai must resolve as a namespace package")
    parent_locations = tuple(parent.submodule_search_locations)
    if not parent_locations:
        raise ValueError("securecode_ai namespace has no locations")
    for module_name, expected in expected_by_module.items():
        spec = importlib.machinery.PathFinder.find_spec(module_name, parent_locations)
        if (
            spec is None
            or type(spec.origin) is not str
            or spec.submodule_search_locations is None
            or Path(spec.origin).name != "__init__.py"
        ):
            raise ValueError("product package must resolve as a regular source package")
        package_root = Path(spec.origin).parent
        if _trusted_python_files(package_root) != expected:
            raise ValueError("resolved package source set or bytes differ from candidate")


def _expected_package_trees(bindings: Mapping[str, Any]) -> dict[str, dict[str, str]]:
    expected: dict[str, dict[str, str]] = {module: {} for module in _PACKAGE_TREES}
    for keyed_name, binding in bindings.items():
        if type(binding) is not dict or set(binding) != {"path", "sha256"}:
            raise ValueError("invalid package source binding")
        module_name, separator, source_path = keyed_name.partition(":")
        if module_name not in expected or not separator or source_path != binding["path"]:
            raise ValueError("invalid package source binding key")
        package_name = module_name.rsplit(".", maxsplit=1)[1]
        prefix = f"securecode_ai/{package_name}/"
        if not source_path.startswith(prefix) or not source_path.endswith(".py"):
            raise ValueError("invalid package source path")
        relative = source_path.removeprefix(prefix)
        if not relative or relative == "/" or ".." in Path(relative).parts:
            raise ValueError("invalid package source path")
        if type(binding["sha256"]) is not str or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", binding["sha256"]
        ):
            raise ValueError("invalid package source digest")
        if relative in expected[module_name]:
            raise ValueError("duplicate package source binding")
        expected[module_name][relative] = binding["sha256"]
    if any(not files for files in expected.values()):
        raise ValueError("missing package source bindings")
    return expected


def _runtime_argv(
    root: Path, action: Literal["execute", "recompute"], argv: tuple[str, ...]
) -> list[str]:
    script = (
        "scripts/run_development_benchmark.py"
        if action == "execute"
        else "scripts/recompute_development_benchmark.py"
    )
    return [str(Path(sys.executable).resolve()), script, *argv]


def admit_run(
    *,
    root: Path,
    plan_path: Path,
    action: Literal["execute", "recompute"],
    argv: tuple[str, ...],
    paths: Mapping[str, Path],
) -> Admission:
    """Validate the requested action before corpus/model/output access."""

    if action not in {"execute", "recompute"}:
        raise ValueError("unknown admission action")
    root = root.resolve()
    plan_path = plan_path.resolve(strict=False)
    if not plan_path.is_file():
        raise ValueError("admission plan is unavailable")
    plan = _json(plan_path)
    if plan.get("schema_version") != PLAN_SCHEMA:
        raise ValueError("admission only supports plan 1.1")
    admitted = _admitted_paths(root, plan_path, plan)
    caller_paths = {name: Path(path).resolve(strict=False) for name, path in paths.items()}
    if caller_paths != admitted:
        raise ValueError("caller paths differ from frozen plan")
    execution = plan["execution"]
    if _runtime_argv(root, action, argv) != execution["argv"][action]:
        raise ValueError("actual argv differs from frozen plan")
    if action == "execute":
        if any(admitted[name].exists() for name in ("records", "aggregate", "receipt")):
            raise ValueError("completed or partial execution paths already exist")
    else:
        if not admitted["receipt"].is_file():
            raise ValueError("recompute requires an execution receipt")
        verify_execution_receipt(
            root=root,
            plan_path=plan_path,
            plan=plan,
            records_path=admitted["records"],
            aggregate_path=admitted["aggregate"],
        )
        if admitted["recomputed"].exists():
            raise ValueError("recomputed output already exists")
    return Admission(root=root, plan_path=plan_path, plan=plan, paths=admitted)


def execution_receipt(*, admission: Admission) -> dict[str, object]:
    """Build the receipt content after all records and aggregate bytes are final."""

    records = admission.paths["records"]
    aggregate = admission.paths["aggregate"]
    document = _json(aggregate)
    planned = document.get("planned_cells")
    recorded = document.get("recorded_cells")
    incomplete = document.get("incomplete")
    if type(planned) is not int or type(recorded) is not int or type(incomplete) is not bool:
        raise ValueError("aggregate lacks closed completion facts")
    return {
        "schema_version": RECEIPT_SCHEMA,
        "admission": "accepted",
        "execution_status": "incomplete" if incomplete else "complete",
        "candidate": admission.plan["execution"]["candidate"],
        "hashes": {
            "plan_sha256": _sha256(admission.plan_path.read_bytes()),
            "records_sha256": _sha256(records.read_bytes()),
            "aggregate_sha256": _sha256(aggregate.read_bytes()),
        },
        "records": {"planned_cells": planned, "recorded_cells": recorded},
    }


def write_execution_receipt(*, admission: Admission) -> None:
    receipt = admission.paths["receipt"]
    if receipt.exists():
        raise ValueError("execution receipt already exists")
    receipt.write_bytes(_canonical(execution_receipt(admission=admission)))


def verify_execution_receipt(
    *,
    root: Path,
    plan_path: Path,
    plan: Mapping[str, Any],
    records_path: Path,
    aggregate_path: Path,
) -> dict[str, Any]:
    """Validate an immutable execute receipt for read-only independent recomputation."""

    root = root.resolve()
    paths = _admitted_paths(root, plan_path.resolve(strict=False), plan)
    if (
        records_path.resolve(strict=False) != paths["records"]
        or aggregate_path.resolve(strict=False) != paths["aggregate"]
    ):
        raise ValueError("receipt paths differ from frozen plan")
    receipt = _json(paths["receipt"])
    if set(receipt) != {
        "schema_version",
        "admission",
        "execution_status",
        "candidate",
        "hashes",
        "records",
    }:
        raise ValueError("receipt has unknown or missing fields")
    if receipt["schema_version"] != RECEIPT_SCHEMA or receipt["admission"] != "accepted":
        raise ValueError("receipt admission drift")
    aggregate = _json(aggregate_path)
    planned = aggregate.get("planned_cells")
    recorded = aggregate.get("recorded_cells")
    incomplete = aggregate.get("incomplete")
    if type(planned) is not int or type(recorded) is not int or type(incomplete) is not bool:
        raise ValueError("aggregate completion facts invalid")
    if receipt["candidate"] != plan["execution"]["candidate"]:
        raise ValueError("receipt candidate drift")
    if receipt["hashes"] != {
        "plan_sha256": _sha256(plan_path.read_bytes()),
        "records_sha256": _sha256(records_path.read_bytes()),
        "aggregate_sha256": _sha256(aggregate_path.read_bytes()),
    }:
        raise ValueError("receipt artifact hash drift")
    if receipt["records"] != {"planned_cells": planned, "recorded_cells": recorded}:
        raise ValueError("receipt record count drift")
    expected_status = "incomplete" if incomplete else "complete"
    if receipt["execution_status"] != expected_status or planned != 312 or recorded != 312:
        raise ValueError("receipt does not close the 312-cell denominator")
    if len(records_path.read_text(encoding="utf-8").splitlines()) != 312:
        raise ValueError("record file does not close the 312-cell denominator")
    return receipt
