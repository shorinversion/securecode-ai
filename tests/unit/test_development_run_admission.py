import copy
import importlib.machinery
import importlib.util
import json
import os
import py_compile
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "development_run_admission", ROOT / "scripts/development_run_admission.py"
)
assert SPEC is not None and SPEC.loader is not None
ADMISSION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADMISSION
SPEC.loader.exec_module(ADMISSION)


def _bindings() -> dict[str, str]:
    return dict.fromkeys(
        (
            "component_sha256",
            "core_sha256",
            "recompute_sha256",
            "corpus_validator_sha256",
            "prompt_sha256",
            "policy_sha256",
            "schema_sha256",
            "admission_sha256",
        ),
        "sha256:" + "0" * 64,
    )


def test_candidate_identity_rejects_dirty_tracked_or_untracked_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        ADMISSION,
        "_git",
        lambda _root, *_args: " M packages/core/src/securecode_ai/core/example.py",
    )
    with pytest.raises(ValueError, match="dirty tracked bytes"):
        ADMISSION._candidate_identity(tmp_path)


@pytest.mark.parametrize("path", ("../outside.json", ".securecode/../outside.json", "a\\b.json"))
def test_admission_paths_reject_traversal_and_aliases(path: str, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"relative path|escapes"):
        ADMISSION._relative_path(tmp_path, path)


def test_prepare_plan_freezes_new_run_without_self_hash(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    historical = tmp_path / "evaluation/development/run-plan.yaml"
    historical.parent.mkdir(parents=True)
    historical.write_text(
        json.dumps(
            {
                "schema_version": "development-benchmark-plan-1.0",
                "study_id": "historical",
                "bindings": {},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        ADMISSION,
        "_candidate_identity",
        lambda _root: {"head": "git-sha1:" + "a" * 40, "tree": "git-sha1:" + "b" * 40},
    )
    monkeypatch.setattr(ADMISSION, "_source_bindings", lambda _root: {})
    monkeypatch.setattr(ADMISSION, "_environment", lambda _root: {"interpreter": "test"})
    output = tmp_path / ".securecode/development-runs/unit-run/plan.json"

    plan = ADMISSION.prepare_plan(
        root=tmp_path,
        output=output,
        bindings=_bindings(),
        environment={"host_mode": "test"},
    )

    assert output.is_file()
    assert plan["schema_version"] == "development-benchmark-plan-1.1"
    assert plan["study_id"] != "historical"
    assert "plan_sha256" not in plan["bindings"]
    assert plan["execution"]["paths"]["receipt"].endswith("/receipt.json")
    with pytest.raises(ValueError, match="already exist"):
        ADMISSION.prepare_plan(
            root=tmp_path,
            output=output,
            bindings=_bindings(),
            environment={"host_mode": "test"},
        )


def test_admit_rejects_argv_that_differs_from_the_frozen_execution(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    paths = ADMISSION._run_paths(tmp_path, "unit-run")
    paths["plan"].parent.mkdir(parents=True)
    paths["plan"].write_text(
        json.dumps(
            {
                "schema_version": "development-benchmark-plan-1.1",
                "execution": {"argv": {"execute": ["frozen"], "recompute": ["frozen"]}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(ADMISSION, "_admitted_paths", lambda *_args: paths)
    with pytest.raises(ValueError, match="actual argv differs"):
        ADMISSION.admit_run(
            root=tmp_path,
            plan_path=paths["plan"],
            action="execute",
            argv=("--plan", "wrong.json"),
            paths=paths,
        )


def test_recompute_admission_rejects_missing_execution_receipt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    paths = ADMISSION._run_paths(tmp_path, "unit-run")
    paths["plan"].parent.mkdir(parents=True)
    argv = (
        "--plan",
        "plan.json",
        "--records",
        "records.jsonl",
        "--output",
        "recomputed.json",
        "--receipt",
        "receipt.json",
    )
    paths["plan"].write_text(
        json.dumps(
            {
                "schema_version": "development-benchmark-plan-1.1",
                "execution": {
                    "argv": {
                        "execute": ["irrelevant"],
                        "recompute": ADMISSION._runtime_argv(tmp_path, "recompute", argv),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(ADMISSION, "_admitted_paths", lambda *_args: paths)
    with pytest.raises(ValueError, match="requires an execution receipt"):
        ADMISSION.admit_run(
            root=tmp_path,
            plan_path=paths["plan"],
            action="recompute",
            argv=argv,
            paths=paths,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda plan: plan.__setitem__("corpus_manifest", "outside/private-corpus.json"), "corpus"),
        (
            lambda plan: plan.__setitem__("budget", {"tokens": 999999}),
            "budget",
        ),
        (
            lambda plan: plan.__setitem__("repetitions", {"full_hybrid": 99}),
            "repetition",
        ),
        (lambda plan: plan.__setitem__("unexpected", True), "top-level"),
    ),
)
def test_supplemental_plan_rejects_matrix_or_schema_escape(mutation: object, message: str) -> None:
    historical = json.loads(
        (ROOT / "evaluation/development/run-plan.yaml").read_text(encoding="utf-8")
    )
    plan = {
        **copy.deepcopy(historical),
        "schema_version": "development-benchmark-plan-1.1",
        "execution": {},
    }
    assert callable(mutation)
    mutation(plan)
    with pytest.raises(ValueError, match=message):
        ADMISSION._verify_frozen_matrix(ROOT, plan)


def test_receipt_rejects_altered_aggregate_bytes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    paths = ADMISSION._run_paths(tmp_path, "unit-run")
    paths["plan"].parent.mkdir(parents=True)
    plan = {
        "execution": {"candidate": {"head": "git-sha1:" + "a" * 40, "tree": "git-sha1:" + "b" * 40}}
    }
    paths["plan"].write_text(json.dumps(plan), encoding="utf-8")
    paths["records"].write_text("{}\n" * 312, encoding="utf-8")
    aggregate = {"planned_cells": 312, "recorded_cells": 312, "incomplete": True}
    paths["aggregate"].write_text(json.dumps(aggregate), encoding="utf-8")
    receipt = {
        "schema_version": ADMISSION.RECEIPT_SCHEMA,
        "admission": "accepted",
        "execution_status": "incomplete",
        "candidate": plan["execution"]["candidate"],
        "hashes": {
            "plan_sha256": ADMISSION._sha256(paths["plan"].read_bytes()),
            "records_sha256": ADMISSION._sha256(paths["records"].read_bytes()),
            "aggregate_sha256": ADMISSION._sha256(paths["aggregate"].read_bytes()),
        },
        "records": {"planned_cells": 312, "recorded_cells": 312},
    }
    paths["receipt"].write_text(json.dumps(receipt), encoding="utf-8")
    monkeypatch.setattr(ADMISSION, "_admitted_paths", lambda *_args: paths)
    assert (
        ADMISSION.verify_execution_receipt(
            root=tmp_path,
            plan_path=paths["plan"],
            plan=plan,
            records_path=paths["records"],
            aggregate_path=paths["aggregate"],
        )["admission"]
        == "accepted"
    )
    paths["aggregate"].write_text(json.dumps({**aggregate, "incomplete": False}), encoding="utf-8")
    with pytest.raises(ValueError, match="hash drift"):
        ADMISSION.verify_execution_receipt(
            root=tmp_path,
            plan_path=paths["plan"],
            plan=plan,
            records_path=paths["records"],
            aggregate_path=paths["aggregate"],
        )


def _package_spec(name: str, init: Path) -> importlib.machinery.ModuleSpec:
    spec = importlib.machinery.ModuleSpec(
        name, importlib.machinery.SourceFileLoader(name, str(init)), is_package=True
    )
    spec.origin = str(init)
    spec.submodule_search_locations = [str(init.parent)]
    return spec


def _namespace_spec(location: Path) -> importlib.machinery.ModuleSpec:
    spec = importlib.machinery.ModuleSpec("securecode_ai", None, is_package=True)
    spec.submodule_search_locations = [str(location)]
    return spec


def test_regular_foreign_parent_is_rejected_without_executing_marker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    parent = tmp_path / "foreign/securecode_ai"
    parent.mkdir(parents=True)
    marker = tmp_path / "parent-imported"
    (parent / "__init__.py").write_text(
        "from pathlib import Path\n" + f"Path({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(parent.parent))
    plan = {
        "execution": {
            "package_source_bindings": ADMISSION._source_bindings(ROOT),
        }
    }
    with pytest.raises(ValueError, match="namespace package"):
        ADMISSION.verify_imported_package_bindings(plan)
    assert not marker.exists()


def test_resolved_cwe89_package_shadow_is_rejected_before_import(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    namespace = tmp_path / "securecode_ai"
    adapter = namespace / "adapters"
    core = namespace / "core"
    contracts = namespace / "contracts"
    for package in (adapter, core, contracts):
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("\n", encoding="utf-8")
    (adapter / "cwe89.py").write_text("candidate\n", encoding="utf-8")
    shadow = adapter / "cwe89"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("shadow\n", encoding="utf-8")
    bindings = {
        "securecode_ai.adapters:securecode_ai/adapters/__init__.py": {
            "path": "securecode_ai/adapters/__init__.py",
            "sha256": ADMISSION._sha256((adapter / "__init__.py").read_bytes()),
        },
        "securecode_ai.adapters:securecode_ai/adapters/cwe89.py": {
            "path": "securecode_ai/adapters/cwe89.py",
            "sha256": ADMISSION._sha256((adapter / "cwe89.py").read_bytes()),
        },
        "securecode_ai.core:securecode_ai/core/__init__.py": {
            "path": "securecode_ai/core/__init__.py",
            "sha256": ADMISSION._sha256((core / "__init__.py").read_bytes()),
        },
        "securecode_ai.contracts:securecode_ai/contracts/__init__.py": {
            "path": "securecode_ai/contracts/__init__.py",
            "sha256": ADMISSION._sha256((contracts / "__init__.py").read_bytes()),
        },
    }

    def resolve(name: str, _path: object = None) -> importlib.machinery.ModuleSpec | None:
        if name == "securecode_ai":
            return _namespace_spec(namespace)
        packages = {
            "securecode_ai.adapters": adapter,
            "securecode_ai.core": core,
            "securecode_ai.contracts": contracts,
        }
        return _package_spec(name, packages[name] / "__init__.py") if name in packages else None

    monkeypatch.setattr(ADMISSION.importlib.machinery.PathFinder, "find_spec", resolve)
    with pytest.raises(ValueError, match="source set or bytes differ"):
        ADMISSION.verify_imported_package_bindings(
            {"execution": {"package_source_bindings": bindings}}
        )


def test_actual_namespace_candidate_package_set_binds_without_import() -> None:
    plan = {"execution": {"package_source_bindings": ADMISSION._source_bindings(ROOT)}}
    ADMISSION.verify_imported_package_bindings(plan)


def test_matching_ordinary_cache_is_admitted(tmp_path: Path) -> None:
    source = tmp_path / "example.py"
    source.write_text("value = 1\n", encoding="utf-8")
    py_compile.compile(str(source), doraise=True)

    bound = ADMISSION._trusted_python_files(tmp_path)

    assert bound == {"example.py": ADMISSION._sha256(source.read_bytes())}


def test_same_size_same_mtime_stale_timestamp_cache_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "example.py"
    source.write_text("value = 1\n", encoding="utf-8")
    py_compile.compile(str(source), doraise=True)
    original = source.stat()
    source.write_text("value = 2\n", encoding="utf-8")
    os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))

    with pytest.raises(ValueError, match="code differs from exact source"):
        ADMISSION._trusted_python_files(tmp_path)


def test_stale_unchecked_hash_cache_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "example.py"
    source.write_text("value = 1\n", encoding="utf-8")
    py_compile.compile(
        str(source), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH
    )
    source.write_text("value = 2\n", encoding="utf-8")

    with pytest.raises(ValueError, match="flags are unsupported"):
        ADMISSION._trusted_python_files(tmp_path)
