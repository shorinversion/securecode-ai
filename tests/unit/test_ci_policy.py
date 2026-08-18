"""Mutation tests for the P1.4 CI, secret and dependency policies."""

from __future__ import annotations

import copy
import importlib.util
import os
import sys
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
    documents: dict[str, dict[str, Any]] = {}
    for relative in POLICY.WORKSPACE_PROJECTS:
        with (REPOSITORY_ROOT / relative).open("rb") as handle:
            documents[relative] = tomllib.load(handle)
    return documents


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
        lambda workflow: workflow["jobs"]["spec"].update(name="renamed-spec"),
        lambda workflow: workflow["jobs"]["spec"].update({"if": "false"}),
        lambda workflow: workflow["jobs"]["spec"]["env"].update(
            BASE_SHA="${{ github.event.before || github.sha }}"
        ),
        lambda workflow: workflow["jobs"]["spec"]["env"].update(
            CANDIDATE_SHA="${{ github.event.pull_request.head.sha }}"
        ),
        lambda workflow: workflow["jobs"]["spec"]["env"].update(
            GITHUB_REPOSITORY="attacker/repository"
        ),
        lambda workflow: workflow["jobs"]["spec"]["steps"][0]["with"].update({"fetch-depth": "1"}),
        lambda workflow: workflow["jobs"]["quality"].update(
            needs=["policy", "secrets", "dependency"]
        ),
        lambda workflow: workflow["jobs"]["gate"].update(
            needs=["policy", "secrets", "dependency", "quality"]
        ),
        lambda workflow: workflow["jobs"]["gate"]["env"].pop("SPEC_RESULT"),
        lambda workflow: _run_step(workflow, "spec", "scripts/spec_gate.py").update(
            run="echo bypassed"
        ),
    ],
)
def test_spec_job_cannot_be_renamed_skipped_or_detached(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    workflow = _workflow()
    mutate(workflow)
    assert POLICY.workflow_errors(workflow)


def test_baseline_cannot_self_approve_a_new_finding() -> None:
    baseline = _baseline()
    baseline["results"]["new.py"] = [
        {
            "type": "GitHub Token",
            "hashed_secret": "0123456789012345678901234567890123456789",
            "is_verified": False,
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


def test_workspace_metadata_rejects_a_malicious_build_backend() -> None:
    documents = _workspace_inputs()
    documents["packages/core/pyproject.toml"]["build-system"]["build-backend"] = "attacker"
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
    secret_command = PRECOMMIT.build_command("secrets", ["--option-shaped.py"])
    assert secret_command[-2:] == ("--", "--option-shaped.py")
    with pytest.raises(RuntimeError, match="does not accept"):
        PRECOMMIT.build_command("quality", ["untrusted.py"])
    with pytest.raises(RuntimeError, match="unknown"):
        PRECOMMIT.build_command("unknown", [])


def test_precommit_launcher_fails_closed_on_version_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        PRECOMMIT.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="uv 9.9.9\n"),
    )
    assert PRECOMMIT.main(["policy"]) == 2
