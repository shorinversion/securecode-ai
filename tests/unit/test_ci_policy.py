"""Mutation tests for the P1.4 CI, secret and dependency policies."""

from __future__ import annotations

import copy
import ctypes
import importlib.util
import json
import os
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest
from detect_secrets.core import scan as detect_secrets_scan

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPOSITORY_ROOT / "scripts" / "ci_policy.py"
PRECOMMIT_PATH = REPOSITORY_ROOT / "scripts" / "precommit_entry.py"
QUALITY_PATH = REPOSITORY_ROOT / "scripts" / "quality.py"
CANARY = "".join(("ghp_1234567890", "1234567890", "1234567890", "123456"))


def _load_policy() -> ModuleType:
    spec = importlib.util.spec_from_file_location("securecode_ci_policy", POLICY_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load CI policy module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


POLICY = _load_policy()


def _load_precommit_entry() -> ModuleType:
    spec = importlib.util.spec_from_file_location("securecode_precommit_entry", PRECOMMIT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load pre-commit launcher module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PRECOMMIT = _load_precommit_entry()


def _load_quality() -> ModuleType:
    spec = importlib.util.spec_from_file_location("securecode_quality", QUALITY_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load quality module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


QUALITY = _load_quality()
ORIGINAL_POPEN = subprocess.Popen


def _workflow() -> dict[str, Any]:
    return copy.deepcopy(POLICY._load_workflow())


def _baseline() -> dict[str, Any]:
    return copy.deepcopy(POLICY._read_json(POLICY.BASELINE_PATH))


def _lock_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    with (REPOSITORY_ROOT / "pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)
    with (REPOSITORY_ROOT / "uv.lock").open("rb") as handle:
        lock = tomllib.load(handle)
    return pyproject, lock


def _workspace_inputs() -> dict[str, dict[str, Any]]:
    pyproject, _ = _lock_inputs()
    projects = POLICY._workspace_projects_for_root(pyproject)
    documents: dict[str, dict[str, Any]] = {}
    for relative in projects:
        with (REPOSITORY_ROOT / relative).open("rb") as handle:
            documents[relative] = tomllib.load(handle)
    return documents


def _release_candidate_workspace_inputs() -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {}
    for relative, (name, dependencies, sources, module_name) in POLICY.WORKSPACE_PROJECTS.items():
        if relative == "apps/server/pyproject.toml":
            project = copy.deepcopy(POLICY.EXPECTED_SERVER_PROJECT)
        elif relative == "apps/worker/pyproject.toml":
            project = copy.deepcopy(POLICY.EXPECTED_WORKER_PROJECT)
        else:
            project = {
                "name": name,
                "version": "1.2.2",
                "description": "reviewed release-candidate package",
                "readme": "README.md",
                "requires-python": ">=3.12,<3.15",
                "dependencies": copy.deepcopy(dependencies),
                "classifiers": ["Private :: Do Not Upload"],
            }
            scripts = POLICY.WORKSPACE_CONSOLE_SCRIPTS.get(relative)
            if scripts is not None:
                project["scripts"] = copy.deepcopy(scripts)
        uv: dict[str, Any] = {"build-backend": {"module-name": module_name}}
        if sources:
            uv["sources"] = copy.deepcopy(sources)
        documents[relative] = {
            "build-system": {
                "requires": ["uv_build>=0.11.32,<0.13"],
                "build-backend": "uv_build",
            },
            "project": project,
            "tool": {"uv": uv},
        }
    return documents


def _release_candidate_lock_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    pyproject, lock = _lock_inputs()
    pyproject["project"]["version"] = "1.2.2"
    pyproject["project"]["dependencies"] = copy.deepcopy(POLICY.EXPECTED_ROOT_DEPENDENCIES)
    pyproject["tool"]["uv"]["sources"] = copy.deepcopy(POLICY.RC_WORKSPACE_SOURCES)
    pyproject["tool"]["uv"]["workspace"]["members"] = copy.deepcopy(POLICY.RC_WORKSPACE_MEMBERS)
    pyproject["tool"]["mypy"]["mypy_path"] = copy.deepcopy(POLICY.EXPECTED_ROOT_MYPY_PATHS)
    lock["manifest"]["members"] = [
        "securecode-ai-adapters",
        "securecode-ai-cli",
        "securecode-ai-contracts",
        "securecode-ai-core",
        "securecode-ai-server",
        "securecode-ai-worker",
        "securecode-ai-workspace",
    ]
    workspace_names = set(lock["manifest"]["members"])
    for package in lock["package"]:
        if package.get("name") in workspace_names:
            package["version"] = "1.2.2"
    if not any(package.get("name") == "securecode-ai-server" for package in lock["package"]):
        lock["package"].append(
            {
                "name": "securecode-ai-server",
                "version": "1.2.2",
                "source": {"editable": "apps/server"},
            }
        )
    if not any(package.get("name") == "securecode-ai-worker" for package in lock["package"]):
        lock["package"].append(
            {
                "name": "securecode-ai-worker",
                "version": "1.2.2",
                "source": {"editable": "apps/worker"},
            }
        )
    return pyproject, lock


def _worker_workspace_inputs() -> dict[str, dict[str, Any]]:
    return _workspace_inputs()


def _worker_lock_inputs() -> tuple[dict[str, Any], dict[str, Any]]:
    return _lock_inputs()


def _first_step(workflow: dict[str, Any], action_name: str) -> dict[str, Any]:
    for raw_job in workflow["jobs"].values():
        for step in raw_job["steps"]:
            if str(step.get("uses", "")).startswith(f"{action_name}@"):
                return cast(dict[str, Any], step)
    raise AssertionError(f"missing action {action_name}")


def _run_step(workflow: dict[str, Any], job_name: str, fragment: str) -> dict[str, Any]:
    for step in workflow["jobs"][job_name]["steps"]:
        if fragment in str(step.get("run", "")):
            return cast(dict[str, Any], step)
    raise AssertionError(f"missing run fragment {fragment}")


def test_accepted_ci_policy_inputs_pass() -> None:
    pyproject, lock = _lock_inputs()
    assert POLICY.workflow_errors(_workflow()) == []
    assert POLICY.precommit_errors(POLICY._load_precommit()) == []
    assert POLICY.baseline_errors(_baseline()) == []
    assert POLICY.lock_errors(pyproject, lock) == []
    assert POLICY.workspace_metadata_errors(_workspace_inputs()) == []


@pytest.mark.parametrize(
    "mutate",
    [
        lambda workflow: _first_step(workflow, "actions/checkout").update(
            uses="actions/checkout@v6"
        ),
        lambda workflow: workflow.update(permissions={"contents": "write"}),
        lambda workflow: workflow["on"].update(pull_request_target={}),
        lambda workflow: _first_step(workflow, "actions/checkout")["with"].update(
            {"persist-credentials": "true"}
        ),
        lambda workflow: workflow["jobs"]["policy"].update(
            env={"TOKEN": "${{ secrets.CI_TOKEN }}"}
        ),
        lambda workflow: workflow["jobs"]["policy"]["steps"].append(
            {"uses": "actions/cache@0123456789012345678901234567890123456789"}
        ),
        lambda workflow: workflow["jobs"]["gate"].update({"if": "${{ success() }}"}),
        lambda workflow: _run_step(workflow, "quality", "scripts/quality.py").update(
            {"run": "echo bypassed"}
        ),
        lambda workflow: _run_step(workflow, "gate", "CI_GATE").update({"run": "exit 0"}),
        lambda workflow: _run_step(workflow, "quality", "scripts/quality.py").update(
            {"if": "false"}
        ),
        lambda workflow: _run_step(workflow, "gate", "CI_GATE").update({"if": "false"}),
        lambda workflow: _first_step(workflow, "actions/checkout")["with"].update(
            {"repository": "attacker/other"}
        ),
        lambda workflow: workflow.update(defaults={"run": {"shell": "./attacker {0}"}}),
        lambda workflow: workflow["jobs"]["quality"].update(
            env={"GITHUB_TOKEN": "${{ github.token }}"}
        ),
        lambda workflow: workflow["jobs"]["dependency"].update(
            permissions={
                "actions": "read",
                "contents": "read",
                "pull-requests": "write",
            }
        ),
        lambda workflow: _run_step(workflow, "dependency", "audit-negative").update(
            env={"GITHUB_TOKEN": "${{ github.token }}"}
        ),
        lambda workflow: workflow["jobs"]["quality"].update(
            container={"image": "attacker/image:latest"}
        ),
        lambda workflow: _first_step(workflow, "actions/setup-python")["with"].update(
            {"cache": "pip"}
        ),
        lambda workflow: _run_step(workflow, "quality", "scripts/quality.py").update(
            {"shell": "./attacker {0}"}
        ),
    ],
)
def test_workflow_mutations_fail_closed(mutate: Callable[[dict[str, Any]], None]) -> None:
    workflow = _workflow()
    mutate(workflow)
    assert POLICY.workflow_errors(workflow)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda workflow: workflow["jobs"]["quality"]["steps"][0]["with"].update(
            {"fetch-depth": "1"}
        ),
        lambda workflow: workflow["jobs"]["quality"].update(needs=["policy", "secrets"]),
        lambda workflow: workflow["jobs"]["gate"].update(needs=["policy", "secrets", "dependency"]),
        lambda workflow: workflow["jobs"]["gate"]["env"].pop("QUALITY_RESULT"),
        lambda workflow: _run_step(workflow, "quality", "scripts/quality.py").update(
            run="echo bypassed"
        ),
    ],
)
def test_quality_and_gate_cannot_be_detached(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    workflow = _workflow()
    mutate(workflow)
    assert POLICY.workflow_errors(workflow)


def test_baseline_cannot_weaken_detectors_or_filters() -> None:
    baseline = _baseline()
    baseline["plugins_used"] = baseline["plugins_used"][1:]
    assert POLICY.baseline_errors(baseline)
    baseline = _baseline()
    baseline["filters_used"] = []
    assert POLICY.baseline_errors(baseline)


def test_baseline_rejects_manual_truth_labels() -> None:
    baseline = _baseline()
    baseline["results"]["new.py"] = [
        {
            "type": "GitHub Token",
            "hashed_secret": "0123456789012345678901234567890123456789",
            "is_verified": False,
            "is_secret": False,
        }
    ]
    assert POLICY.baseline_errors(baseline)


def test_precommit_entry_mutation_fails_closed() -> None:
    configuration = copy.deepcopy(POLICY._load_precommit())
    configuration["repos"][0]["hooks"][0]["entry"] = "python -c 'raise SystemExit(0)'"
    assert POLICY.precommit_errors(configuration)


@pytest.mark.parametrize(
    "mutation",
    ["source", "hash", "quality", "root-dependency", "optional", "uv-option"],
)
def test_dependency_policy_rejects_source_integrity_and_tool_drift(mutation: str) -> None:
    pyproject, lock = _lock_inputs()
    if mutation == "source":
        external = next(package for package in lock["package"] if "registry" in package["source"])
        external["source"] = {"git": "https://example.invalid/dependency"}
    elif mutation == "hash":
        external = next(package for package in lock["package"] if package.get("wheels"))
        external["wheels"][0].pop("hash")
    elif mutation == "quality":
        pyproject["dependency-groups"]["quality"].append("unreviewed-tool==1.0.0")
    elif mutation == "root-dependency":
        pyproject["project"]["dependencies"].append("unreviewed-package==1.0.0")
    elif mutation == "optional":
        pyproject["project"]["optional-dependencies"] = {"bypass": ["package==1.0.0"]}
    else:
        pyproject["tool"]["uv"]["no-build-isolation-package"] = ["attacker"]
    assert POLICY.lock_errors(pyproject, lock)


def test_legacy_workspace_requires_one_closed_metadata_and_lock_shape() -> None:
    pyproject, lock = _worker_lock_inputs()
    assert POLICY.lock_errors(pyproject, lock) == []
    assert POLICY.workspace_metadata_errors(_worker_workspace_inputs()) == []


def test_release_candidate_workspace_state_passes_as_one_closed_shape() -> None:
    pyproject, lock = _release_candidate_lock_inputs()
    assert POLICY.lock_errors(pyproject, lock) == []
    assert POLICY.workspace_metadata_errors(_release_candidate_workspace_inputs()) == []


@pytest.mark.parametrize("field", ["version", "dependencies", "sources", "members", "mypy"])
def test_release_candidate_workspace_rejects_mixed_state(field: str) -> None:
    pyproject, lock = _release_candidate_lock_inputs()
    if field == "version":
        pyproject["project"]["version"] = "0.1.0a0"
    elif field == "dependencies":
        pyproject["project"]["dependencies"] = copy.deepcopy(
            POLICY.LEGACY_EXPECTED_ROOT_DEPENDENCIES
        )
    elif field == "sources":
        pyproject["tool"]["uv"]["sources"] = copy.deepcopy(POLICY.LEGACY_WORKSPACE_SOURCES)
    elif field == "members":
        pyproject["tool"]["uv"]["workspace"]["members"] = copy.deepcopy(
            POLICY.LEGACY_WORKSPACE_MEMBERS
        )
    else:
        pyproject["tool"]["mypy"]["mypy_path"] = copy.deepcopy(
            POLICY.LEGACY_EXPECTED_ROOT_MYPY_PATHS
        )
    assert POLICY.lock_errors(pyproject, lock)


def test_legacy_workspace_rejects_partial_or_substituted_inputs() -> None:
    pyproject, lock = _worker_lock_inputs()
    pyproject["tool"]["uv"]["workspace"]["members"].remove("packages/core")
    assert POLICY.lock_errors(pyproject, lock)

    pyproject, lock = _worker_lock_inputs()
    pyproject["tool"]["mypy"]["mypy_path"].remove("packages/core/src")
    assert POLICY.lock_errors(pyproject, lock)

    pyproject, lock = _worker_lock_inputs()
    lock["manifest"]["members"].remove("securecode-ai-core")
    assert POLICY.lock_errors(pyproject, lock)

    documents = _worker_workspace_inputs()
    documents["apps/cli/pyproject.toml"]["project"]["scripts"] = {"securecode": "attacker:main"}
    assert POLICY.workspace_metadata_errors(documents)


def test_validate_lock_loads_and_enforces_the_selected_legacy_metadata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    workspace = tmp_path / "workspace"
    root_pyproject, _ = _lock_inputs()
    projects = POLICY._workspace_projects_for_root(root_pyproject)
    for relative in projects:
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((REPOSITORY_ROOT / relative).read_bytes())
    cli_path = workspace / "apps/cli/pyproject.toml"
    pyproject_path = workspace / "pyproject.toml"
    pyproject_path.write_bytes((REPOSITORY_ROOT / "pyproject.toml").read_bytes())
    lock_path = workspace / "uv.lock"
    lock_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(POLICY, "REPOSITORY_ROOT", workspace)
    monkeypatch.setattr(POLICY, "PYPROJECT_PATH", pyproject_path)
    monkeypatch.setattr(POLICY, "LOCK_PATH", lock_path)
    monkeypatch.setattr(POLICY, "lock_errors", lambda *_: [])
    monkeypatch.setattr(POLICY, "_git", lambda *_: "uv.lock\n")

    assert POLICY.validate("lock") == []
    cli_source = cli_path.read_text(encoding="utf-8")
    cli_path.unlink()
    assert POLICY.validate("lock") == ["workspace metadata could not be read"]

    cli_path.write_text(
        cli_source.replace("uv_build>=0.11.32,<0.13", "attacker>=1"), encoding="utf-8"
    )
    assert POLICY.validate("lock")


def test_workspace_metadata_rejects_a_malicious_build_backend() -> None:
    documents = _workspace_inputs()
    documents["packages/core/pyproject.toml"]["build-system"]["build-backend"] = "attacker"
    assert POLICY.workspace_metadata_errors(documents)


def test_workspace_metadata_accepts_only_reviewed_tree_sitter_dependencies() -> None:
    documents = _release_candidate_workspace_inputs()
    adapter_dependencies = documents["packages/adapters/pyproject.toml"]["project"]["dependencies"]
    adapter_dependencies[:] = ["securecode-ai-core==1.2.2"]
    assert POLICY.workspace_metadata_errors(documents)

    pre_grammar = [
        "securecode-ai-core==1.2.2",
        "tree-sitter>=0.25,<0.26",
        "tree-sitter-python>=0.25,<0.26",
    ]
    adapter_dependencies[:] = pre_grammar
    assert POLICY.workspace_metadata_errors(documents)

    reviewed = [
        "pydantic>=2.12,<3",
        "securecode-ai-contracts==1.2.2",
        "securecode-ai-core==1.2.2",
        "tree-sitter>=0.25,<0.26",
        "tree-sitter-go==0.25.0",
        "tree-sitter-javascript==0.25.0",
        "tree-sitter-python>=0.25,<0.26",
        "tree-sitter-typescript==0.23.2",
    ]
    adapter_dependencies[:] = reviewed
    assert POLICY.workspace_metadata_errors(documents) == []

    adapter_dependencies[:] = [*reviewed, "tree-sitter-rust==0.24.0"]
    assert POLICY.workspace_metadata_errors(documents)

    for name, version in (
        ("tree-sitter-go", "0.24.0"),
        ("tree-sitter-javascript", "0.23.1"),
        ("tree-sitter-typescript", "0.23.1"),
    ):
        adapter_dependencies[:] = [
            f"{name}=={version}" if dependency.startswith(f"{name}==") else dependency
            for dependency in reviewed
        ]
        assert POLICY.workspace_metadata_errors(documents)


@pytest.mark.parametrize("path", ["x.py", 'space and "quote".py', "line\nbreak.py"])
def test_intermediate_commit_canary_is_detected_without_returning_its_value(path: str) -> None:
    assert detect_secrets_scan.scan_line is not None
    findings = POLICY.scan_text(path, f"TOKEN = '{CANARY}'", _baseline())
    rendered = repr(findings)
    assert findings == [(path, "GitHub Token")]
    assert CANARY not in rendered


def test_inline_allowlist_cannot_hide_a_secret() -> None:
    content = f"TOKEN = '{CANARY}'  # pragma: allowlist secret"
    findings = POLICY.scan_text("x.py", content, _baseline())
    assert ("x.py", "GitHub Token") in findings


def _completion_attestation() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        json.loads((REPOSITORY_ROOT / "work/task-attestations/P1.13.json").read_text()),
    )


def test_schema_valid_completion_attestation_digests_are_metadata_not_secrets() -> None:
    path = "work/task-attestations/P1.13.json"
    content = json.dumps(_completion_attestation(), sort_keys=True)
    assert POLICY.scan_text(path, content, _baseline()) == []


def _external_completion_attestation() -> tuple[str, dict[str, Any]]:
    path = "work/task-attestations/P2.14.json"
    digest = "".join(
        (
            "5f04f819",
            "a5a388d2",
            "dfe4aa1c",
            "11afc82f",
            "c68cf363",
            "1d569714",
            "ec2bb60c",
            "5be5cc99",
        )
    )
    head = "".join(("e44fe903", "27013526", "65061e24", "88e0de3a", "c7fc5e21"))
    merge = "".join(("b45a4b83", "01f0898a", "02d8a14e", "9d269f9b", "646268a3"))
    value = {
        "allowed_paths": [path, "docs/PLAN.md"],
        "budgets": {"max_changed_files": 5, "max_diff_lines": 800},
        "change_type": "completion_attestation",
        "evidence_refs": [
            {
                "content_sha256": digest,
                "source": "tests/unit/test_repository_intake.py",
                "type": "targeted_tests",
            },
            {"content_sha256": digest, "source": "scripts/quality.py", "type": "full_quality"},
            {
                "content_sha256": digest,
                "source": "work/change-control/README.md",
                "type": "independent_reviews",
            },
            {
                "conclusion": "success",
                "content_sha256": digest,
                "event": "pull_request",
                "gate_completed_at": "2026-08-22T09:10:05Z",
                "head_branch": "codex/p2-1-attestation",
                "head_sha": head,
                "merge_commit_sha": merge,
                "merged_at": "2026-08-22T09:10:26Z",
                "pull_request_number": 12,
                "repository": "shorinversion/securecode-ai",
                "required_check": "gate",
                "run_attempt": 1,
                "run_id": 32564092644,
                "source": "https://github.com/shorinversion/securecode-ai/actions/runs/32564092644",
                "type": "protected_pr_gate",
                "workflow_path": ".github/workflows/ci.yml",
            },
            {
                "conclusion": "success",
                "content_sha256": digest,
                "event": "push",
                "head_branch": "master",
                "head_sha": merge,
                "repository": "shorinversion/securecode-ai",
                "run_attempt": 1,
                "run_id": 32564227372,
                "source": "https://github.com/shorinversion/securecode-ai/actions/runs/32564227372",
                "type": "post_merge_gate",
                "workflow_path": ".github/workflows/ci.yml",
            },
        ],
        "implementation_commit_sha": head,
        "packet_sha256": digest,
        "schema_version": "1.0.0",
        "starting_commit_sha": merge,
        "task_id": "P2.14",
    }
    return path, value


def test_external_completion_attestation_typed_hashes_are_not_secrets() -> None:
    path, value = _external_completion_attestation()
    assert POLICY.scan_text(path, json.dumps(value, sort_keys=True), _baseline()) == []


@pytest.mark.parametrize(
    ("reference", "mutation"),
    [
        (3, "extra-field"),
        (3, "bad-head"),
        (3, "bad-event"),
        (3, "bad-check"),
        (3, "whitespace-branch"),
        (3, "local-source"),
        (3, "wrong-run-source"),
        (3, "source-repository-mismatch"),
        (3, "bad-time"),
        (4, "missing-run"),
        (4, "bad-workflow"),
        (4, "wrong-protected-branch"),
        (4, "merge-head-mismatch"),
    ],
)
def test_external_completion_attestation_recognition_fails_closed(
    reference: int, mutation: str
) -> None:
    path, value = _external_completion_attestation()
    ref = value["evidence_refs"][reference]
    if mutation == "extra-field":
        ref["unreviewed"] = "field"
    elif mutation == "bad-head":
        ref["head_sha"] = "not-an-object-id"
    elif mutation == "bad-event":
        ref["event"] = "push"
    elif mutation == "bad-check":
        ref["required_check"] = "other"
    elif mutation == "whitespace-branch":
        ref["head_branch"] = "codex/unsafe branch"
    elif mutation == "local-source":
        ref["source"] = "work/evidence/run.json"
    elif mutation == "wrong-run-source":
        ref["source"] = "https://github.com/shorinversion/securecode-ai/actions/runs/1"
    elif mutation == "source-repository-mismatch":
        ref["repository"] = "other/securecode-ai"
    elif mutation == "bad-time":
        ref["merged_at"] = "not-a-time"
    elif mutation == "missing-run":
        ref.pop("run_id")
    elif mutation == "bad-workflow":
        ref["workflow_path"] = ".github/workflows/other.yml"
    elif mutation == "wrong-protected-branch":
        ref["head_branch"] = "other"
    else:
        ref["head_sha"] = value["implementation_commit_sha"]
    content = json.dumps(value, sort_keys=True)
    assert POLICY._completion_attestation_scan_view(path, content) == content


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-path",
        "extra-field",
        "wrong-task",
        "wrong-evidence-order",
        "bad-digest",
        "duplicate-key",
    ],
)
def test_completion_attestation_metadata_recognition_fails_closed(mutation: str) -> None:
    path = "work/task-attestations/P1.13.json"
    value = _completion_attestation()
    if mutation == "wrong-path":
        path = "work/other/P1.13.json"
    elif mutation == "extra-field":
        value["unreviewed"] = "field"
    elif mutation == "wrong-task":
        value["task_id"] = "P1.4"
    elif mutation == "wrong-evidence-order":
        value["evidence_refs"].reverse()
    elif mutation == "bad-digest":
        value["packet_sha256"] = "not-a-digest"
    else:
        content = json.dumps(value).replace(
            '"task_id": "P1.13"', '"task_id": "P1.13", "task_id": "P1.13"'
        )
        assert POLICY._completion_attestation_scan_view(path, content) == content
        return
    content = json.dumps(value, sort_keys=True)
    assert POLICY._completion_attestation_scan_view(path, content) == content


@pytest.mark.parametrize("field", ["source", "type"])
def test_valid_completion_attestation_still_scans_non_digest_metadata(field: str) -> None:
    path = "work/task-attestations/P1.13.json"
    value = _completion_attestation()
    value["evidence_refs"][0][field] = CANARY
    if field == "type":
        policy = cast(dict[str, Any], POLICY._read_json(POLICY.SPEC_GATE_POLICY_PATH))
        policy["completion_evidence"]["P1.13"][0] = CANARY
        original = POLICY._read_json

        def fake_read_json(candidate: Path) -> dict[str, Any]:
            return (
                policy
                if candidate == POLICY.SPEC_GATE_POLICY_PATH
                else cast(dict[str, Any], original(candidate))
            )

        with pytest.MonkeyPatch.context() as monkeypatch:
            monkeypatch.setattr(POLICY, "_read_json", fake_read_json)
            findings = POLICY.scan_text(path, json.dumps(value), _baseline())
    else:
        findings = POLICY.scan_text(path, json.dumps(value), _baseline())
    assert (path, "GitHub Token") in findings


def _policy_change_packet() -> tuple[str, dict[str, Any]]:
    path = "work/change-control/CR-019.yaml"
    return path, cast(dict[str, Any], json.loads((REPOSITORY_ROOT / path).read_text()))


def test_schema_valid_change_packet_digests_are_metadata_not_secrets() -> None:
    path, packet = _policy_change_packet()
    assert POLICY.scan_text(path, json.dumps(packet), _baseline()) == []


def test_integrated_g2_packet_metadata_requires_closed_policy_shape() -> None:
    path = "work/change-control/CR-049.yaml"
    gate_policy = POLICY._read_json(POLICY.SPEC_GATE_POLICY_PATH)["gate_policy"]["G2"]
    packet = {
        "schema_version": "1.0.0",
        "change_type": "integrated_gate_candidate",
        "change_id": "CR-049",
        "starting_commit_sha": "a" * 40,
        "protected_class": "gate_evidence",
        "gate_id": "G2",
        "decision": "GO-PROPOSED",
        "evidence_bundle_sha256": "c" * 64,
        "review_subject_sha256": "d" * 64,
        "allowed_paths": [
            "CHANGELOG.md",
            "docs/CONTEXT.md",
            path,
            *(f"artifacts/gates/G2/{item}" for item in gate_policy["evidence_files"]),
            "artifacts/gates/G2/promotion-manifest.json",
            "packages/core/src/securecode_ai/core/example.py",
        ],
        "budgets": {
            "max_changed_files": gate_policy["max_changed_files"],
            "max_diff_lines": gate_policy["max_diff_lines"],
        },
    }
    content = json.dumps(packet, sort_keys=True)
    sanitized = POLICY._change_packet_scan_view(path, content)
    assert "typed-git-object-id" in sanitized
    assert "typed-sha256-digest" in sanitized
    cast(list[str], packet["allowed_paths"]).remove("docs/CONTEXT.md")
    assert POLICY._change_packet_scan_view(path, json.dumps(packet, sort_keys=True)) == json.dumps(
        packet, sort_keys=True
    )
    cast(list[str], packet["allowed_paths"]).append("docs/CONTEXT.md")
    packet["implementation_commit_sha"] = "b" * 40
    assert POLICY._change_packet_scan_view(path, json.dumps(packet, sort_keys=True)) == json.dumps(
        packet, sort_keys=True
    )


@pytest.mark.parametrize(
    "mutation",
    ["wrong-path", "extra-field", "bad-decision", "bad-paths", "bad-digest", "duplicate-key"],
)
def test_change_packet_metadata_recognition_fails_closed(mutation: str) -> None:
    path, packet = _policy_change_packet()
    if mutation == "wrong-path":
        path = "work/change-control/CR-998.yaml"
    elif mutation == "extra-field":
        packet["unreviewed"] = "field"
    elif mutation == "bad-decision":
        packet["decision"] = "GO"
    elif mutation == "bad-paths":
        packet["allowed_paths"].append("unreviewed.txt")
    elif mutation == "bad-digest":
        packet["review_subject_sha256"] = "not-a-digest"
    else:
        content = json.dumps(packet).replace(
            '"change_id": "CR-019"', '"change_id": "CR-019", "change_id": "CR-019"'
        )
        assert POLICY._change_packet_scan_view(path, content) == content
        return
    content = json.dumps(packet, sort_keys=True)
    assert POLICY._change_packet_scan_view(path, content) == content


def _promotion_manifest(gate_id: str, final_documents: dict[str, bytes]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "gate_id": gate_id,
        "evidence_bundle_sha256": "a" * 64,
        "promotion_subject_sha256": POLICY._length_prefixed_digest(final_documents),
        "files": [
            {
                "path": target,
                "base_sha256": "b" * 64,
                "final_sha256": POLICY.hashlib.sha256(final_bytes).hexdigest(),
                "final_base64": POLICY.base64.b64encode(final_bytes).decode(),
            }
            for target, final_bytes in sorted(final_documents.items())
        ],
    }


def test_policy_manifest_decodes_and_scans_final_target_bytes() -> None:
    path = "work/change-control/amendments/CR-998-manifest.json"
    final_documents = {"scripts/ci_policy.py": f"TOKEN = '{CANARY}'\n".encode()}
    manifest = _promotion_manifest("POLICY", final_documents)
    findings = POLICY.scan_text(path, json.dumps(manifest), _baseline())
    assert findings == [(path, "GitHub Token")]
    assert CANARY not in repr(findings)


def test_policy_manifest_metadata_is_clean_only_after_exact_validation() -> None:
    path = "work/change-control/amendments/CR-998-manifest.json"
    final_documents = {"scripts/ci_policy.py": b"value = 1\n"}
    manifest = _promotion_manifest("POLICY", final_documents)
    assert POLICY.scan_text(path, json.dumps(manifest), _baseline()) == []
    manifest["files"][0]["final_sha256"] = "c" * 64
    assert POLICY._promotion_manifest_scan_views(path, json.dumps(manifest)) is None


def _review_receipt(reviewer_identity: str = "independent-reviewer") -> tuple[str, str]:
    review_hash = "d" * 64
    directory = f"work/change-control/reviews/POLICY/product_scope-{review_hash}"
    path = f"{directory}/receipt.json"
    receipt = {
        "schema_version": "1.0.0",
        "change_type": "independent_review",
        "gate_id": "POLICY",
        "role": "product_scope",
        "reviewer_identity": reviewer_identity,
        "reviewed_commit_sha": "e" * 40,
        "evidence_bundle_sha256": "a" * 64,
        "review_subject_sha256": review_hash,
        "promotion_subject_sha256": "b" * 64,
        "verdict": "PASS",
        "source_ref": f"{directory}/review.md",
        "source_ref_sha256": "c" * 64,
    }
    return path, json.dumps(receipt)


def test_schema_valid_review_receipt_digests_are_metadata_not_secrets() -> None:
    path, content = _review_receipt()
    assert POLICY.scan_text(path, content, _baseline()) == []


def test_schema_valid_review_receipt_still_scans_reviewer_identity() -> None:
    path, content = _review_receipt(CANARY)
    assert (path, "GitHub Token") in POLICY.scan_text(path, content, _baseline())


def test_git_blob_records_are_nul_safe_and_preserve_symlinks_as_blobs() -> None:
    first = "a" * 40
    second = "b" * 40
    index = f'100644 {first} 0\tline\nwith "quotes".py\0'.encode()
    tree = f"120000 blob {second}\tsymlink\0".encode()
    assert POLICY.parse_git_blob_records(index, index=True) == [('line\nwith "quotes".py', first)]
    assert POLICY.parse_git_blob_records(tree, index=False) == [("symlink", second)]


def test_git_blob_scanner_reads_object_ids_instead_of_checkout_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    object_id = "a" * 40
    calls: list[tuple[str, ...]] = []

    def fake_git_bytes(*arguments: str) -> bytes:
        calls.append(arguments)
        return f"TOKEN = '{CANARY}'".encode()

    monkeypatch.setattr(POLICY, "_git_bytes", fake_git_bytes)
    findings = POLICY._scan_git_blobs(
        [("line\nlink", object_id)], _baseline(), prefix="candidate-history secret candidate"
    )
    assert calls == [("cat-file", "blob", object_id)]
    assert findings == [r"candidate-history secret candidate: line\nlink (GitHub Token)"]
    assert CANARY not in repr(findings)


def test_git_blob_scanner_reuses_only_identical_path_object_pairs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[str] = []

    def fake_git_bytes(*arguments: str) -> bytes:
        assert arguments[:2] == ("cat-file", "blob")
        reads.append(arguments[2])
        return b"ordinary text\n"

    monkeypatch.setattr(POLICY, "_git_bytes", fake_git_bytes)
    seen: set[tuple[str, str]] = set()
    records = [
        ("same.txt", "a" * 40),
        ("same.txt", "a" * 40),
        ("same.txt", "b" * 40),
    ]
    assert POLICY._scan_git_blobs(records, _baseline(), prefix="candidate", seen=seen) == []
    assert POLICY._scan_git_blobs(records, _baseline(), prefix="candidate", seen=seen) == []
    assert (
        POLICY._scan_git_blobs(
            [("renamed.txt", "a" * 40)], _baseline(), prefix="candidate", seen=seen
        )
        == []
    )
    assert reads == ["a" * 40, "b" * 40, "a" * 40]


def test_secret_errors_shares_deduplication_across_index_and_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads: list[str] = []
    baseline = _baseline()

    def fake_git_bytes(*arguments: str) -> bytes:
        assert arguments[:2] == ("cat-file", "blob")
        reads.append(arguments[2])
        return b"ordinary text\n"

    monkeypatch.setattr(POLICY, "_read_json", lambda path: baseline)
    monkeypatch.setattr(POLICY, "baseline_errors", lambda baseline: [])
    monkeypatch.setattr(POLICY, "_index_blob_records", lambda: [("same.txt", "a" * 40)])
    monkeypatch.setattr(POLICY, "_candidate_commits", lambda base: ["candidate"])
    monkeypatch.setattr(
        POLICY,
        "_tree_blob_records",
        lambda commit: [("same.txt", "a" * 40), ("same.txt", "b" * 40)],
    )
    monkeypatch.setattr(POLICY, "_git_bytes", fake_git_bytes)

    assert POLICY.secret_errors("c" * 40) == []
    assert reads == ["a" * 40, "b" * 40]


@pytest.mark.parametrize("base_mode", ["zero", "head", "incremental"])
def test_candidate_commit_walk_covers_full_history_and_merge_commits(
    monkeypatch: pytest.MonkeyPatch, base_mode: str
) -> None:
    head = "f" * 40
    base = {"zero": "0" * 40, "head": head, "incremental": "e" * 40}[base_mode]
    calls: list[tuple[str, ...]] = []

    def fake_git(*arguments: str) -> str:
        calls.append(arguments)
        return head if arguments == ("rev-parse", "HEAD") else "merge\nchild\n"

    monkeypatch.setattr(POLICY, "_git", fake_git)
    assert POLICY._candidate_commits(base) == ["merge", "child"]
    rev_list = calls[1]
    assert rev_list[:4] == ("rev-list", "--reverse", "--topo-order", "HEAD")
    assert (rev_list[-2:] == ("--not", "e" * 40)) is (base_mode == "incremental")


@pytest.mark.parametrize(
    ("returncode", "output", "passes"),
    [
        (0, '{"dependencies": []}', False),
        (2, "", False),
        (1, "not-json", False),
        (1, '{"dependencies": [{"name": "pip", "version": "21.2.4", "vulns": []}]}', False),
        (
            1,
            '{"dependencies": [{"name": "pip", "version": "21.2.4", "vulns": [{"id": "VULN"}]}]}',
            True,
        ),
    ],
)
def test_known_vulnerable_audit_receipt_is_fail_closed(
    returncode: int, output: str, passes: bool
) -> None:
    assert (POLICY.known_vulnerable_audit_errors(returncode, output) == []) is passes


def test_precommit_launcher_uses_the_project_owned_uv_and_closed_commands() -> None:
    command = PRECOMMIT.build_command("quality", [])
    relative_uv = "Scripts/uv.exe" if os.name == "nt" else "bin/uv"
    assert Path(command[0]).resolve() == (REPOSITORY_ROOT / ".venv" / relative_uv).resolve()
    assert command[1:] == PRECOMMIT.COMMANDS["quality"]
    assert PRECOMMIT.build_command("secrets", [])[-4:] == (
        "python",
        "-I",
        "scripts/ci_policy.py",
        "secrets",
    )
    with pytest.raises(RuntimeError, match="does not accept"):
        PRECOMMIT.build_command("secrets", ["--option-shaped.py"])
    with pytest.raises(RuntimeError, match="does not accept"):
        PRECOMMIT.build_command("quality", ["untrusted.py"])
    with pytest.raises(RuntimeError, match="unknown"):
        PRECOMMIT.build_command("unknown", [])


def test_canonical_type_stages_cover_linux_and_win32_before_unit() -> None:
    targets = ("first.py", "second.py")
    stages = QUALITY._stages(targets)
    type_stages = tuple(stage for stage in stages if stage.name.startswith("types-"))

    assert tuple(stage.name for stage in type_stages) == ("types-linux", "types-win32")
    assert tuple(stage.arguments for stage in type_stages) == tuple(
        (
            "-m",
            "mypy",
            "--config-file",
            "pyproject.toml",
            "--no-incremental",
            "--platform",
            platform,
            *targets,
        )
        for platform in ("linux", "win32")
    )
    assert all(not stage.executes_repository_code for stage in type_stages)
    unit_index = next(index for index, stage in enumerate(stages) if stage.name == "unit")
    assert all(stages.index(stage) < unit_index for stage in type_stages)


@pytest.mark.parametrize("failed_stage", ["types-linux", "types-win32"])
def test_type_failure_runs_remaining_static_checks_but_skips_unit(
    monkeypatch: pytest.MonkeyPatch,
    failed_stage: str,
) -> None:
    observed: list[tuple[str, dict[str, str]]] = []
    sanitized = {"PATH": "trusted-tools", "PYTHONHASHSEED": "0"}
    snapshots = iter(("same", "same"))

    monkeypatch.setattr(QUALITY, "_python_targets", lambda: ("target.py",))
    monkeypatch.setattr(QUALITY, "_repository_snapshot", lambda: next(snapshots))
    monkeypatch.setattr(QUALITY, "_sanitized_environment", lambda _root: sanitized)

    def run(stage: Any, environment: dict[str, str]) -> int:
        observed.append((stage.name, environment))
        return 1 if stage.name == failed_stage else 0

    monkeypatch.setattr(QUALITY, "_run_stage", run)

    assert QUALITY.main() == 1
    assert [name for name, _environment in observed] == [
        "format",
        "lint",
        "types-linux",
        "types-win32",
    ]
    assert all(environment is sanitized for _name, environment in observed)
    assert "unit" not in {name for name, _environment in observed}


def test_hook_cadence_preserves_policy_secrets_and_workflow_without_full_quality() -> None:
    configuration = POLICY._load_precommit()
    assert POLICY.precommit_errors(configuration) == []
    hooks = configuration["repos"][0]["hooks"]
    assert [hook["id"] for hook in hooks] == [
        "securecode-ci-policy",
        "securecode-secrets",
        "securecode-workflow-security",
    ]
    for index in range(len(hooks)):
        mutated = copy.deepcopy(configuration)
        mutated["repos"][0]["hooks"].pop(index)
        assert POLICY.precommit_errors(mutated)
    assert "scripts/quality.py" in PRECOMMIT.build_command("quality", [])


def test_development_command_runs_only_explicit_targeted_tests() -> None:
    filenames = ["tests/unit/test_ci_policy.py", "tests/unit/test_spec_gate.py"]
    command = PRECOMMIT.build_command("development", filenames)
    assert command[-2:] == tuple(filenames)
    assert "scripts/quality.py" not in command
    assert not any(argument.startswith("--cov") for argument in command)


@pytest.mark.parametrize(
    "filenames",
    [
        [],
        ["tests/unit"],
        ["--collect-only"],
        ["../tests/unit/test_ci_policy.py"],
        ["tests/unit/test_ci_policy.py::test_example"],
        ["tests/unit/test_ci_policy.py"] * 2,
        [f"tests/unit/test_missing_{index}.py" for index in range(9)],
        ["tests/unit/test_missing.py"],
    ],
)
def test_development_command_rejects_unbounded_or_untrusted_selection(filenames: list[str]) -> None:
    with pytest.raises(RuntimeError):
        PRECOMMIT.build_command("development", filenames)


def test_development_environment_removes_credentials_and_plugin_injection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-credential")
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTHONPATH", "untrusted")
    monkeypatch.setenv("UV_INDEX_URL", "https://untrusted.invalid")
    environment = PRECOMMIT.development_environment(tmp_path)
    assert not {"GITHUB_TOKEN", "PYTEST_ADDOPTS", "PYTHONPATH", "UV_INDEX_URL"} & environment.keys()
    assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
    assert environment["HOME"] == str(tmp_path)


def test_development_launcher_propagates_failure_with_bounded_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def run(*arguments: Any, **options: Any) -> SimpleNamespace:
        calls.append(options)
        return SimpleNamespace(returncode=0, stdout="uv 0.12.0\n")

    def development(command: Any, environment: Any, *, timeout: float = 360) -> int:
        assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
        assert timeout == 360
        return 5

    monkeypatch.setattr(PRECOMMIT.subprocess, "run", run)
    monkeypatch.setattr(PRECOMMIT, "run_development", development)
    assert PRECOMMIT.main(["development", "tests/unit/test_ci_policy.py"]) == 5
    assert [call["timeout"] for call in calls] == [10]


def _development_pid_running(pid: int) -> bool:
    if os.name == "nt":
        loader = getattr(ctypes, "WinDLL", None)
        assert callable(loader)
        kernel = loader("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.c_uint)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint)
        kernel.WaitForSingleObject.restype = ctypes.c_uint
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if not handle:
            assert getattr(ctypes, "get_last_error", lambda: -1)() in (87, 1168)
            return False
        try:
            return bool(kernel.WaitForSingleObject(handle, 0) == 258)
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    status = Path(f"/proc/{pid}/stat")
    try:
        return not status.exists() or status.read_text().split(")", 1)[1].split()[0] != "Z"
    except FileNotFoundError:
        return False


def test_development_timeout_terminates_real_descendant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    pid_file = tmp_path / "descendant.pid"
    child = (
        "import os,time; from pathlib import Path; "
        f"Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(30)"
    )
    parent = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,'-I','-c',{child!r}]); time.sleep(30)"
    )
    environment = PRECOMMIT.development_environment(tmp_path)
    try:
        with pytest.raises(RuntimeError) as failure:
            PRECOMMIT.run_development(
                (sys.executable, "-I", "-c", parent),
                environment,
                timeout=3,
            )
        assert str(failure.value) in {
            "development checks exceeded their execution boundary",
            "development process-tree termination failed",
        }
        assert pid_file.is_file(), "descendant must start before the deadline"
        pid = int(pid_file.read_text())
        deadline = time.monotonic() + 2
        while _development_pid_running(pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        assert not _development_pid_running(pid), "timeout left the descendant alive"
    finally:
        if pid_file.is_file():
            pid = int(pid_file.read_text())
            if _development_pid_running(pid):
                if os.name == "nt":
                    subprocess.run(
                        (str(PRECOMMIT.windows_taskkill()), "/PID", str(pid), "/T", "/F"),
                        check=False,
                        capture_output=True,
                        timeout=10,
                    )
                else:
                    os.kill(pid, 9)


def test_development_tree_termination_failure_is_not_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    killed: list[bool] = []
    process = SimpleNamespace(
        pid=123,
        poll=lambda: None,
        kill=lambda: killed.append(True),
        wait=lambda timeout: 0,
    )

    def fail(*arguments: Any, **options: Any) -> SimpleNamespace:
        assert arguments[0] == (str(tmp_path / "taskkill.exe"), "/PID", "123", "/T", "/F")
        assert options["timeout"] == 10
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(PRECOMMIT.subprocess, "run", fail)
    with pytest.raises(RuntimeError, match="termination failed"):
        PRECOMMIT.terminate_development_tree(process, {}, tmp_path / "taskkill.exe")
    assert killed == [True]


def test_development_timeout_kills_before_reaping_launcher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def wait(timeout: float) -> int:
        raise subprocess.TimeoutExpired("owned-test-process", timeout)

    process = SimpleNamespace(pid=123, wait=wait)

    def launch(*arguments: Any, **options: Any) -> SimpleNamespace:
        assert options["shell"] is False
        assert options["start_new_session"] is (os.name != "nt")
        events.append("launch")
        return process

    def terminate(*arguments: Any) -> None:
        assert arguments[0] is process
        events.append("terminate-tree")

    monkeypatch.setattr(PRECOMMIT.subprocess, "Popen", launch)
    monkeypatch.setattr(PRECOMMIT, "terminate_development_tree", terminate)
    with pytest.raises(RuntimeError, match="execution boundary"):
        PRECOMMIT.run_development(("owned-test-process",), {}, timeout=0.1)
    assert events == ["launch", "terminate-tree"]


def test_development_posix_group_is_killed_and_leader_reaped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, int]] = []
    process = SimpleNamespace(
        pid=123,
        poll=lambda: 0,
        wait=lambda timeout: events.append(("wait", timeout)),
    )
    monkeypatch.setattr(
        PRECOMMIT.os,
        "killpg",
        lambda pid, sig: events.append(("killpg", pid)),
        raising=False,
    )
    monkeypatch.setattr(PRECOMMIT.signal, "SIGKILL", 9, raising=False)
    PRECOMMIT.terminate_development_tree(process, {}, None)
    assert events == [("killpg", 123), ("wait", 10)]


def test_development_tree_terminator_timeout_propagates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    killed: list[bool] = []
    process = SimpleNamespace(
        pid=123,
        poll=lambda: None,
        kill=lambda: killed.append(True),
        wait=lambda timeout: 0,
    )

    def timeout(*arguments: Any, **options: Any) -> None:
        raise subprocess.TimeoutExpired("system-terminator", 10)

    monkeypatch.setattr(PRECOMMIT.subprocess, "run", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        PRECOMMIT.terminate_development_tree(process, {}, tmp_path / "taskkill.exe")
    assert killed == [True]


def test_windows_tree_terminator_unavailable_fails_before_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(PRECOMMIT.ctypes, "WinDLL", None, raising=False)
    with pytest.raises(RuntimeError, match="terminator is unavailable"):
        PRECOMMIT.windows_taskkill()


def test_precommit_launcher_fails_closed_on_version_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        PRECOMMIT.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="uv 9.9.9\n"),
    )
    assert PRECOMMIT.main(["policy"]) == 2
