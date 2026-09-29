"""Fail-closed policy checks for SecureCode AI's P1 GitHub CI boundary."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlparse

REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[1]
WORKFLOW_PATH: Final = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
PRECOMMIT_PATH: Final = REPOSITORY_ROOT / ".pre-commit-config.yaml"
BASELINE_PATH: Final = REPOSITORY_ROOT / ".secrets.baseline"
SPEC_GATE_POLICY_PATH: Final = REPOSITORY_ROOT / "scripts" / "spec_gate_policy.json"
PYPROJECT_PATH: Final = REPOSITORY_ROOT / "pyproject.toml"
LOCK_PATH: Final = REPOSITORY_ROOT / "uv.lock"
VULNERABLE_FIXTURE_PATH: Final = (
    REPOSITORY_ROOT / "tests" / "fixtures" / "p1_4" / "known-vulnerable-requirement.json"
)
WORKSPACE_PROJECTS: Final = {
    "apps/cli/pyproject.toml": (
        "securecode-ai-cli",
        [
            "securecode-ai-adapters==1.0.0",
            "securecode-ai-contracts==1.0.0",
            "securecode-ai-core==1.0.0",
        ],
        {
            "securecode-ai-adapters": {"workspace": True},
            "securecode-ai-contracts": {"workspace": True},
            "securecode-ai-core": {"workspace": True},
        },
        "securecode_ai.cli",
    ),
    "apps/server/pyproject.toml": (
        "securecode-ai-server",
        [
            "securecode-ai-adapters==1.0.0",
            "securecode-ai-contracts==1.0.0",
            "securecode-ai-core==1.0.0",
        ],
        {
            "securecode-ai-adapters": {"workspace": True},
            "securecode-ai-contracts": {"workspace": True},
            "securecode-ai-core": {"workspace": True},
        },
        "securecode_ai.server",
    ),
    "apps/worker/pyproject.toml": (
        "securecode-ai-worker",
        [
            "securecode-ai-adapters==1.0.0",
            "securecode-ai-contracts==1.0.0",
            "securecode-ai-core==1.0.0",
        ],
        {
            "securecode-ai-adapters": {"workspace": True},
            "securecode-ai-contracts": {"workspace": True},
            "securecode-ai-core": {"workspace": True},
        },
        "securecode_ai.worker",
    ),
    "packages/contracts/pyproject.toml": (
        "securecode-ai-contracts",
        ["pydantic>=2.12,<3"],
        {},
        "securecode_ai.contracts",
    ),
    "packages/core/pyproject.toml": (
        "securecode-ai-core",
        ["securecode-ai-contracts==1.0.0"],
        {"securecode-ai-contracts": {"workspace": True}},
        "securecode_ai.core",
    ),
    "packages/adapters/pyproject.toml": (
        "securecode-ai-adapters",
        [
            "pydantic>=2.12,<3",
            "securecode-ai-contracts==1.0.0",
            "securecode-ai-core==1.0.0",
            "tree-sitter>=0.25,<0.26",
            "tree-sitter-go==0.25.0",
            "tree-sitter-javascript==0.25.0",
            "tree-sitter-python>=0.25,<0.26",
            "tree-sitter-typescript==0.23.2",
        ],
        {
            "securecode-ai-contracts": {"workspace": True},
            "securecode-ai-core": {"workspace": True},
        },
        "securecode_ai.adapters",
    ),
}
LEGACY_WORKSPACE_PROJECTS: Final = {
    "apps/cli/pyproject.toml": (
        "securecode-ai-cli",
        [
            "securecode-ai-adapters==0.1.0a0",
            "securecode-ai-contracts==0.1.0a0",
            "securecode-ai-core==0.1.0a0",
        ],
        {
            "securecode-ai-adapters": {"workspace": True},
            "securecode-ai-contracts": {"workspace": True},
            "securecode-ai-core": {"workspace": True},
        },
        "securecode_ai.cli",
    ),
    "packages/contracts/pyproject.toml": (
        "securecode-ai-contracts",
        ["pydantic>=2.12,<3"],
        {},
        "securecode_ai.contracts",
    ),
    "packages/core/pyproject.toml": (
        "securecode-ai-core",
        ["securecode-ai-contracts==0.1.0a0"],
        {"securecode-ai-contracts": {"workspace": True}},
        "securecode_ai.core",
    ),
    "packages/adapters/pyproject.toml": (
        "securecode-ai-adapters",
        [
            "securecode-ai-core==0.1.0a0",
            "tree-sitter>=0.25,<0.26",
            "tree-sitter-go==0.25.0",
            "tree-sitter-javascript==0.25.0",
            "tree-sitter-python>=0.25,<0.26",
            "tree-sitter-typescript==0.23.2",
        ],
        {"securecode-ai-core": {"workspace": True}},
        "securecode_ai.adapters",
    ),
}
WORKSPACE_CONSOLE_SCRIPTS: Final = {
    "apps/cli/pyproject.toml": {"securecode": "securecode_ai.cli:main"},
    "apps/server/pyproject.toml": {
        "securecode-maintenance": "securecode_ai.server.maintenance_cli:main",
        "securecode-capacity": "securecode_ai.server.capacity_cli:main",
        "securecode-server": "securecode_ai.server.main:main",
    },
    "apps/worker/pyproject.toml": {
        "securecode-worker": "securecode_ai.worker.cli:main",
        "securecode-worker-service": "securecode_ai.worker.service:main",
    },
}
LEGACY_WORKSPACE_CONSOLE_SCRIPTS: Final = {
    "apps/cli/pyproject.toml": {"securecode": "securecode_ai.cli:main"},
}
PYPI_INDEX: Final = "https://pypi.org/simple"
PYPI_ARTIFACT_HOST: Final = "files.pythonhosted.org"
ACTION_REFS: Final = {
    "actions/checkout": "".join(
        (
            "de0fac2e45",
            "00dabe0009",
            "e67214ff5f",
            "5447ce83dd",
        )
    ),
    "actions/setup-python": "".join(
        (
            "a309ff8b42",
            "6b58ec0e2a",
            "45f0f869d4",
            "6889d02405",
        )
    ),
    "astral-sh/setup-uv": "".join(
        (
            "c771a70e62",
            "77c0a99b61",
            "7c7a806ffe",
            "daca235ff9",
        )
    ),
}
EXPECTED_QUALITY_DEPENDENCIES: Final = {
    "detect-secrets==1.5.0",
    "jsonschema==4.26.0",
    "mypy==2.3.0",
    "pip-audit==2.10.1",
    "pre-commit==4.6.0",
    "pytest==9.1.1",
    "pytest-cov==7.1.0",
    "pyyaml==6.0.3",
    "rfc3339-validator==0.1.4",
    "rfc3987-syntax==1.1.0",
    "ruff==0.15.22",
    "uv==0.12.0",
    "zizmor==1.28.0",
}
EXPECTED_ROOT_DEPENDENCIES: Final = [
    "securecode-ai-adapters==1.0.0",
    "securecode-ai-cli==1.0.0",
    "securecode-ai-contracts==1.0.0",
    "securecode-ai-core==1.0.0",
    "securecode-ai-server==1.0.0",
    "securecode-ai-worker==1.0.0",
]
LEGACY_EXPECTED_ROOT_DEPENDENCIES: Final = [
    "securecode-ai-adapters==0.1.0a0",
    "securecode-ai-cli==0.1.0a0",
    "securecode-ai-contracts==0.1.0a0",
    "securecode-ai-core==0.1.0a0",
]


EXPECTED_ROOT_MYPY_PATHS: Final = [
    "apps/cli/src",
    "apps/server/src",
    "apps/worker/src",
    "packages/adapters/src",
    "packages/contracts/src",
    "packages/core/src",
]
LEGACY_EXPECTED_ROOT_MYPY_PATHS: Final = [
    "apps/cli/src",
    "packages/adapters/src",
    "packages/contracts/src",
    "packages/core/src",
]
RC_WORKSPACE_SOURCES: Final = {
    "securecode-ai-adapters": {"workspace": True},
    "securecode-ai-cli": {"workspace": True},
    "securecode-ai-contracts": {"workspace": True},
    "securecode-ai-core": {"workspace": True},
    "securecode-ai-server": {"workspace": True},
    "securecode-ai-worker": {"workspace": True},
}
LEGACY_WORKSPACE_SOURCES: Final = {
    key: value
    for key, value in RC_WORKSPACE_SOURCES.items()
    if key not in {"securecode-ai-server", "securecode-ai-worker"}
}
RC_WORKSPACE_MEMBERS: Final = [
    "apps/cli",
    "apps/server",
    "apps/worker",
    "packages/adapters",
    "packages/contracts",
    "packages/core",
]
LEGACY_WORKSPACE_MEMBERS: Final = [
    "apps/cli",
    "packages/adapters",
    "packages/contracts",
    "packages/core",
]
EXPECTED_SERVER_PROJECT: Final = {
    "name": "securecode-ai-server",
    "version": "1.0.0",
    "description": "SecureCode AI ASGI control-plane boundary",
    "readme": "README.md",
    "requires-python": ">=3.12,<3.15",
    "dependencies": [
        "securecode-ai-adapters==1.0.0",
        "securecode-ai-contracts==1.0.0",
        "securecode-ai-core==1.0.0",
    ],
    "classifiers": ["Private :: Do Not Upload"],
    "scripts": {
        "securecode-server": "securecode_ai.server.main:main",
        "securecode-maintenance": "securecode_ai.server.maintenance_cli:main",
        "securecode-capacity": "securecode_ai.server.capacity_cli:main",
    },
}
EXPECTED_WORKER_PROJECT: Final = {
    "name": "securecode-ai-worker",
    "version": "1.0.0",
    "description": "Linux-only offline SecureCode AI CI metadata worker",
    "readme": "README.md",
    "requires-python": ">=3.12,<3.15",
    "dependencies": [
        "securecode-ai-adapters==1.0.0",
        "securecode-ai-contracts==1.0.0",
        "securecode-ai-core==1.0.0",
    ],
    "classifiers": [
        "Private :: Do Not Upload",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
    "scripts": {
        "securecode-worker": "securecode_ai.worker.cli:main",
        "securecode-worker-service": "securecode_ai.worker.service:main",
    },
}
LEGACY_EXPECTED_WORKER_PROJECT: Final = {
    "name": "securecode-ai-worker",
    "version": "0.1.0a0",
    "description": "Linux-only offline SecureCode AI CI metadata worker",
    "readme": "README.md",
    "requires-python": ">=3.12,<3.15",
    "dependencies": ["securecode-ai-contracts==0.1.0a0"],
    "classifiers": [
        "Private :: Do Not Upload",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
    "scripts": {"securecode-worker": "securecode_ai.worker.cli:main"},
}


def _workspace_projects_for_paths(
    paths: set[str],
) -> Mapping[str, tuple[str, list[str], Mapping[str, Any], str]] | None:
    if paths == set(WORKSPACE_PROJECTS):
        return WORKSPACE_PROJECTS
    if paths == set(LEGACY_WORKSPACE_PROJECTS):
        return LEGACY_WORKSPACE_PROJECTS
    return None


def _workspace_state_for_root(pyproject: Mapping[str, Any]) -> str:
    project = _mapping(pyproject.get("project"), "project")
    tool = _mapping(pyproject.get("tool"), "pyproject.tool")
    uv = _mapping(tool.get("uv"), "pyproject.tool.uv")
    mypy = _mapping(tool.get("mypy"), "pyproject.tool.mypy")
    observed = (
        project.get("version"),
        list(_sequence(project.get("dependencies"), "project.dependencies")),
        _mapping(uv.get("sources"), "pyproject.tool.uv.sources"),
        list(
            _sequence(
                _mapping(uv.get("workspace"), "pyproject.tool.uv.workspace").get("members"),
                "workspace members",
            )
        ),
        list(_sequence(mypy.get("mypy_path"), "pyproject.tool.mypy.mypy_path")),
    )
    states = {
        "release": (
            "1.0.0",
            EXPECTED_ROOT_DEPENDENCIES,
            RC_WORKSPACE_SOURCES,
            RC_WORKSPACE_MEMBERS,
            EXPECTED_ROOT_MYPY_PATHS,
        ),
        "legacy": (
            "0.1.0a0",
            LEGACY_EXPECTED_ROOT_DEPENDENCIES,
            LEGACY_WORKSPACE_SOURCES,
            LEGACY_WORKSPACE_MEMBERS,
            LEGACY_EXPECTED_ROOT_MYPY_PATHS,
        ),
    }
    matches = [name for name, expected in states.items() if observed == expected]
    if len(matches) != 1:
        raise PolicyError("workspace release state differs from the closed states")
    return matches[0]


def _workspace_projects_for_root(
    pyproject: Mapping[str, Any],
) -> Mapping[str, tuple[str, list[str], Mapping[str, Any], str]]:
    if _workspace_state_for_root(pyproject) == "release":
        return WORKSPACE_PROJECTS
    return LEGACY_WORKSPACE_PROJECTS


EXPECTED_VULNERABLE_HASHES: Final = [
    "".join(
        (
            "fa9ebb85",
            "d3fd6076",
            "17c0c44a",
            "ca302b1b",
            "45d87f9c",
            "2a1649b4",
            "6c26167c",
            "a4296323",
        )
    ),
    "".join(
        (
            "0eb8a151",
            "6c3d138a",
            "e8689c0c",
            "1a60fde7",
            "14331083",
            "2f9dc77e",
            "11d8a4bc",
            "62de193b",
        )
    ),
]
EXPECTED_BASELINE_DIGEST: Final = "".join(
    ("c2e34109", "0c4f97cb", "3153f63f", "4097307f", "56dedb7e", "8d7ec6f6", "e0cb3ed9", "f51cddde")
)
MAX_BASELINE_FINDINGS: Final = 10_000
UV_LINUX_SHA256: Final = "".join(
    ("eaf84226", "2aa1c418", "d8ecc560", "5f02ee1e", "bfd36912", "4fa48548", "e85f9481", "a47831a9")
)
EXPECTED_JOBS: Final = {"policy", "secrets", "dependency", "quality", "gate"}
SECRETS_JOB_NAME: Final = "".join(("sec", "rets"))
EXPECTED_TIMEOUTS: Final = {
    "policy": "15",
    "secrets": "15",
    "dependency": "15",
    "quality": "20",
    "gate": "2",
}
EXPECTED_JOB_NAMES: Final = {
    "policy": "policy",
    SECRETS_JOB_NAME: SECRETS_JOB_NAME,
    "dependency": "dependency",
    "quality": "quality / python-${{ matrix.python-version }}",
    "gate": "gate",
}
EXPECTED_RUN_COMMANDS: Final = {
    "policy": (
        "python -I scripts/ci_policy.py lock",
        "uv sync --locked --only-group quality --no-editable",
        "uv run --locked --offline --no-sync --only-group quality python -I scripts/ci_policy.py validate",
        "uv run --locked --offline --no-sync --only-group quality pre-commit validate-config",
        "uv run --locked --offline --no-sync --only-group quality zizmor --offline --strict-collection --persona=pedantic .",
    ),
    "secrets": (
        "python -I scripts/ci_policy.py lock",
        "uv sync --locked --only-group quality --no-editable",
        'uv run --locked --offline --no-sync --only-group quality python -I scripts/ci_policy.py secrets --base "$BASE_SHA"',
    ),
    "dependency": (
        "python -I scripts/ci_policy.py lock",
        "uv sync --locked --only-group quality --no-editable",
        'uv export --locked --all-packages --all-groups --no-emit-workspace --format requirements-txt --output-file "$RUNNER_TEMP/locked-requirements.txt"',
        'uv run --locked --offline --no-sync --only-group quality pip-audit --require-hashes --disable-pip --progress-spinner off --requirement "$RUNNER_TEMP/locked-requirements.txt"',
        "uv run --locked --offline --no-sync --only-group quality python -I scripts/ci_policy.py audit-negative",
    ),
    "quality": (
        "python -I scripts/ci_policy.py lock",
        "uv sync --locked --no-editable --group quality",
        "uv run --locked --offline --no-sync --group quality python -I scripts/quality.py",
    ),
    "gate": (
        "python -c \"import os,sys; names=('POLICY_RESULT','SECRETS_RESULT','DEPENDENCY_RESULT','QUALITY_RESULT'); failed=[name for name in names if os.environ.get(name) != 'success']; print('CI_GATE=' + ('PASS' if not failed else 'FAIL')); sys.exit(bool(failed))\"",
    ),
}
FULL_SHA_PATTERN: Final = re.compile(r"[0-9a-f]{40}\Z")
ARTIFACT_HASH_PATTERN: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
SAFE_BASE_PATTERN: Final = re.compile(r"[0-9a-f]{40}\Z")


class PolicyError(RuntimeError):
    """Raised for malformed input that cannot be safely interpreted."""


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise PolicyError(f"{path.name} must contain a JSON object")
    return value


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError(f"{label} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _sequence(value: object, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise PolicyError(f"{label} must be a sequence")
    return value


def _walk(value: object) -> Iterable[object]:
    yield value
    if isinstance(value, Mapping):
        for key, item in value.items():
            yield from _walk(key)
            yield from _walk(item)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            yield from _walk(item)


def _load_workflow(path: Path = WORKFLOW_PATH) -> dict[str, Any]:
    # Deliberately lazy: `lock` must run before third-party dependencies are installed.
    import yaml  # type: ignore[import-untyped]

    value = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    if not isinstance(value, dict):
        raise PolicyError("workflow must contain one YAML mapping")
    return {str(key): item for key, item in value.items()}


def _load_precommit(path: Path = PRECOMMIT_PATH) -> dict[str, Any]:
    """Load pre-commit with string-preserving YAML semantics."""

    import yaml

    value = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    if not isinstance(value, dict):
        raise PolicyError("pre-commit config must contain one YAML mapping")
    return {str(key): item for key, item in value.items()}


def precommit_errors(configuration: Mapping[str, Any]) -> list[str]:
    """Reject local hook bypasses and alternate dependency bootstraps."""

    expected = {
        "minimum_pre_commit_version": "4.6.0",
        "default_install_hook_types": ["pre-commit", "pre-push"],
        "fail_fast": "true",
        "repos": [
            {
                "repo": "local",
                "hooks": [
                    {
                        "id": "securecode-ci-policy",
                        "name": "SecureCode CI policy",
                        "language": "system",
                        "entry": "python -I scripts/precommit_entry.py policy",
                        "pass_filenames": "false",
                        "always_run": "true",
                    },
                    {
                        "id": "securecode-secrets",
                        "name": "SecureCode staged secret scan",
                        "language": "system",
                        "entry": "python -I scripts/precommit_entry.py secrets",
                        "pass_filenames": "false",
                        "always_run": "true",
                    },
                    {
                        "id": "securecode-workflow-security",
                        "name": "SecureCode workflow security audit",
                        "language": "system",
                        "entry": "python -I scripts/precommit_entry.py workflow",
                        "pass_filenames": "false",
                        "always_run": "true",
                    },
                ],
            }
        ],
    }
    return [] if configuration == expected else ["pre-commit policy differs from the closed set"]


def workflow_errors(workflow: Mapping[str, Any]) -> list[str]:
    """Return deterministic violations for the single authoritative workflow."""

    errors: list[str] = []
    if set(workflow) != {"name", "on", "permissions", "concurrency", "jobs"}:
        errors.append("workflow top-level keys differ from the closed set")
    if workflow.get("name") != "ci":
        errors.append("workflow name must be ci")
    events = _mapping(workflow.get("on"), "workflow.on")
    required_events = {"pull_request", "push", "merge_group", "workflow_dispatch"}
    if set(events) != required_events:
        errors.append(f"workflow events must be exactly {sorted(required_events)}")
    push = _mapping(events.get("push"), "workflow.on.push")
    if set(push) != {"branches"} or list(_sequence(push.get("branches"), "push.branches")) != [
        "master"
    ]:
        errors.append("push must target only master")
    for event_name in ("pull_request", "merge_group"):
        event = _mapping(events.get(event_name), f"workflow.on.{event_name}")
        if event:
            errors.append(f"{event_name} must not use path/type filters")

    permissions = _mapping(workflow.get("permissions"), "workflow.permissions")
    if permissions != {"contents": "read"}:
        errors.append("top-level permissions must be exactly contents: read")
    concurrency = _mapping(workflow.get("concurrency"), "workflow.concurrency")
    if concurrency != {
        "group": "ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
        "cancel-in-progress": "true",
    }:
        errors.append("workflow concurrency policy differs from the reviewed value")

    jobs = _mapping(workflow.get("jobs"), "workflow.jobs")
    if set(jobs) != EXPECTED_JOBS:
        errors.append(f"workflow jobs must be exactly {sorted(EXPECTED_JOBS)}")

    uses_seen: set[str] = set()
    for job_name, raw_job in jobs.items():
        job = _mapping(raw_job, f"jobs.{job_name}")
        expected_job_keys = {
            "policy": {"name", "runs-on", "timeout-minutes", "steps"},
            "secrets": {"name", "needs", "runs-on", "timeout-minutes", "env", "steps"},
            "dependency": {"name", "needs", "runs-on", "timeout-minutes", "steps"},
            "spec": {
                "name",
                "needs",
                "permissions",
                "runs-on",
                "timeout-minutes",
                "env",
                "steps",
            },
            "quality": {"name", "needs", "runs-on", "timeout-minutes", "strategy", "steps"},
            "gate": {
                "name",
                "if",
                "needs",
                "runs-on",
                "timeout-minutes",
                "permissions",
                "env",
                "steps",
            },
        }
        if set(job) != expected_job_keys.get(job_name, set()):
            errors.append(f"{job_name}: job keys differ from the closed set")
        if job.get("name") != EXPECTED_JOB_NAMES.get(job_name):
            errors.append(f"{job_name}: display name differs from the stable check contract")
        runner = job.get("runs-on")
        if runner != "ubuntu-24.04":
            errors.append(f"{job_name}: runner must be ubuntu-24.04")
        if job.get("timeout-minutes") != EXPECTED_TIMEOUTS.get(job_name):
            errors.append(f"{job_name}: timeout-minutes differs from the bounded value")
        if job.get("continue-on-error") == "true":
            errors.append(f"{job_name}: continue-on-error is forbidden")
        job_permissions = job.get("permissions")
        if job_name == "spec":
            parsed_permissions = _mapping(job_permissions, "jobs.spec.permissions")
            if parsed_permissions != {
                "actions": "read",
                "contents": "read",
                "pull-requests": "read",
            }:
                errors.append(
                    "spec: permissions must be exactly actions:read, contents:read, "
                    "and pull-requests:read"
                )
        elif job_permissions is not None:
            parsed_permissions = _mapping(job_permissions, f"jobs.{job_name}.permissions")
            for permission, level in parsed_permissions.items():
                if level != "read" and level != "none":
                    errors.append(f"{job_name}: permission {permission}={level} is forbidden")

        steps = _sequence(job.get("steps"), f"jobs.{job_name}.steps")
        run_commands = tuple(
            str(_mapping(step, f"jobs.{job_name}.step").get("run"))
            for step in steps
            if _mapping(step, f"jobs.{job_name}.step").get("run") is not None
        )
        if run_commands != EXPECTED_RUN_COMMANDS.get(job_name, ()):
            errors.append(f"{job_name}: authoritative run command sequence changed")
        action_sequence: list[str] = []
        for index, raw_step in enumerate(steps):
            step = _mapping(raw_step, f"jobs.{job_name}.steps[{index}]")
            run = step.get("run")
            spec_gate_step = job_name == "spec" and run == EXPECTED_RUN_COMMANDS["spec"][-1]
            expected_step_keys = (
                {"name", "uses", "with"}
                if "uses" in step
                else ({"name", "env", "run"} if spec_gate_step else {"name", "run"})
            )
            if set(step) != expected_step_keys:
                errors.append(f"{job_name}[{index}]: step keys differ from the closed set")
            if spec_gate_step and _mapping(
                step.get("env"), f"jobs.{job_name}.steps[{index}].env"
            ) != {"GITHUB_TOKEN": "${{ github.token }}"}:
                errors.append(f"{job_name}[{index}]: GitHub API authority differs")
            if step.get("continue-on-error") == "true":
                errors.append(f"{job_name}[{index}]: continue-on-error is forbidden")
            if isinstance(run, str) and "${{" in run:
                errors.append(f"{job_name}[{index}]: expressions are forbidden in run scripts")
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            uses_seen.add(uses)
            action, separator, revision = uses.partition("@")
            action_sequence.append(action)
            if separator != "@" or not FULL_SHA_PATTERN.fullmatch(revision):
                errors.append(f"{job_name}[{index}]: action ref must be a full commit SHA")
                continue
            expected = ACTION_REFS.get(action)
            if expected is None or revision != expected:
                errors.append(
                    f"{job_name}[{index}]: action {action} is not allowlisted at this SHA"
                )
            inputs = _mapping(step.get("with", {}), f"jobs.{job_name}.steps[{index}].with")
            if action == "actions/checkout":
                expected_checkout = {
                    "persist-credentials": "false",
                    "fetch-depth": "0" if job_name in {"secrets", "quality"} else "1",
                    "lfs": "false",
                    "submodules": "false",
                    "set-safe-directory": "false",
                }
                if inputs != expected_checkout:
                    errors.append(
                        f"{job_name}[{index}]: checkout inputs differ from the closed set"
                    )
            elif action == "actions/setup-python":
                expected_python = (
                    "${{ matrix.python-version }}" if job_name == "quality" else "3.13"
                )
                if inputs != {"python-version": expected_python, "check-latest": "false"}:
                    errors.append(
                        f"{job_name}[{index}]: setup-python inputs differ from the closed set"
                    )
            elif action == "astral-sh/setup-uv":
                if inputs != {
                    "version": "0.12.0",
                    "checksum": UV_LINUX_SHA256,
                    "enable-cache": "false",
                    "add-problem-matchers": "false",
                }:
                    errors.append(
                        f"{job_name}[{index}]: setup-uv inputs differ from the closed set"
                    )
        if job_name != "gate" and action_sequence != [
            "actions/checkout",
            "actions/setup-python",
            "astral-sh/setup-uv",
        ]:
            errors.append(f"{job_name}: action sequence differs from the closed bootstrap")

    used_actions = {reference.partition("@")[0] for reference in uses_seen}
    if used_actions != set(ACTION_REFS):
        errors.append(f"workflow actions must be exactly {sorted(ACTION_REFS)}")

    serialized = json.dumps(workflow, sort_keys=True)
    forbidden_fragments = (
        "pull_request_target",
        "workflow_run",
        "self-hosted",
        "${{ secrets.",
        "id-token",
        "actions/cache",
        "restore-cache",
        "save-cache",
        "docker.sock",
        "|| true",
    )
    for fragment in forbidden_fragments:
        if fragment in serialized:
            errors.append(f"workflow contains forbidden fragment: {fragment}")

    quality = _mapping(jobs.get("quality"), "jobs.quality")
    strategy = _mapping(quality.get("strategy"), "jobs.quality.strategy")
    matrix = _mapping(strategy.get("matrix"), "jobs.quality.strategy.matrix")
    versions = list(_sequence(matrix.get("python-version"), "quality python matrix"))
    if strategy.get("fail-fast") != "false" or versions != ["3.12", "3.13", "3.14"]:
        errors.append("quality matrix must be fail-fast:false over Python 3.12, 3.13 and 3.14")
    quality_needs = set(_sequence(quality.get("needs"), "jobs.quality.needs"))
    if quality_needs != {"policy", "secrets", "dependency"}:
        errors.append("quality must require policy, secrets and dependency")

    gate = _mapping(jobs.get("gate"), "jobs.gate")
    if gate.get("if") != "${{ always() }}":
        errors.append("gate must run under always()")
    gate_needs = set(_sequence(gate.get("needs"), "jobs.gate.needs"))
    if gate_needs != {"policy", "secrets", "dependency", "quality"}:
        errors.append("gate must aggregate every mandatory job")
    expected_gate_environment = {
        "POLICY_RESULT": "${{ needs.policy.result }}",
        "SECRETS_RESULT": "${{ needs.secrets.result }}",
        "DEPENDENCY_RESULT": "${{ needs.dependency.result }}",
        "QUALITY_RESULT": "${{ needs.quality.result }}",
    }
    if _mapping(gate.get("env"), "jobs.gate.env") != expected_gate_environment:
        errors.append("gate result environment differs from the closed mandatory set")
    expected_secret_environment = {
        "BASE_SHA": "${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.event.before || github.sha }}"
    }
    if _mapping(jobs.get("secrets"), "jobs.secrets").get("env") != expected_secret_environment:
        errors.append("secret history base environment differs from the reviewed expression")
    if _mapping(jobs.get("secrets"), "jobs.secrets").get("needs") != ["policy"]:
        errors.append("secrets must require policy success")
    if _mapping(jobs.get("dependency"), "jobs.dependency").get("needs") != ["policy"]:
        errors.append("dependency must require policy success")
    return sorted(set(errors))


def baseline_errors(baseline: Mapping[str, Any]) -> list[str]:
    """Reject baseline self-approval, detector weakening or manual truth labels."""

    errors: list[str] = []
    protected = {key: baseline.get(key) for key in ("version", "plugins_used", "filters_used")}
    canonical = json.dumps(protected, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    if digest != EXPECTED_BASELINE_DIGEST:
        errors.append("secret baseline detectors or filters differ from the reviewed set")

    results = _mapping(baseline.get("results"), "baseline.results")
    count = 0
    for path, raw_findings in results.items():
        if Path(path).is_absolute() or ".." in Path(path).parts:
            errors.append(f"baseline path is unsafe: {path}")
        for raw_finding in _sequence(raw_findings, f"baseline.results.{path}"):
            finding = _mapping(raw_finding, f"baseline finding in {path}")
            count += 1
            if finding.get("is_secret") is not None:
                errors.append(f"baseline contains a manual truth label: {path}")
            hashed = finding.get("hashed_secret")
            if not isinstance(hashed, str) or not re.fullmatch(r"[0-9a-f]{40}", hashed):
                errors.append(f"baseline contains a malformed secret hash: {path}")
    if count > MAX_BASELINE_FINDINGS:
        errors.append(f"secret baseline exceeds {MAX_BASELINE_FINDINGS} findings")
    return sorted(set(errors))


def lock_errors(pyproject: Mapping[str, Any], lock: Mapping[str, Any]) -> list[str]:
    """Validate all sources and integrity metadata before dependency installation."""

    errors: list[str] = []
    if set(pyproject) != {"project", "tool", "dependency-groups"}:
        errors.append("root pyproject top-level keys differ from the closed set")
    tool = _mapping(pyproject.get("tool"), "pyproject.tool")
    if set(tool) != {"uv", "ruff", "mypy", "pytest", "coverage"}:
        errors.append("root tool tables differ from the closed set")
    uv = _mapping(tool.get("uv"), "pyproject.tool.uv")
    if set(uv) != {
        "package",
        "required-version",
        "default-groups",
        "exclude-newer",
        "build-constraint-dependencies",
        "sources",
        "workspace",
        "index",
    }:
        errors.append("root uv keys differ from the closed set")
    if uv.get("required-version") != "==0.12.0":
        errors.append("uv required-version must be exactly 0.12.0")
    if uv.get("default-groups") != [] or uv.get("package") is not False:
        errors.append("root uv default-group/package policy differs from the reviewed values")
    if uv.get("exclude-newer") != "2026-08-13T00:00:00Z":
        errors.append("dependency upload-time cutoff differs from the reviewed value")
    indexes = _sequence(uv.get("index"), "pyproject.tool.uv.index")
    if len(indexes) != 1 or _mapping(indexes[0], "pyproject.tool.uv.index[0]") != {
        "name": "pypi",
        "url": PYPI_INDEX,
        "default": True,
    }:
        errors.append("pyproject must define exactly one default PyPI index")
    if set(_sequence(uv.get("build-constraint-dependencies"), "build constraints")) != {
        "uv_build>=0.11.32,<0.13"
    }:
        errors.append("build backend constraint differs from the reviewed range")
    project = _mapping(pyproject.get("project"), "project")
    direct_dependencies = list(_sequence(project.get("dependencies"), "project.dependencies"))
    try:
        release_candidate = _workspace_state_for_root(pyproject) == "release"
    except PolicyError:
        errors.append("root workspace release state differs from the closed states")
        return sorted(set(errors))
    expected_root_dependencies = (
        EXPECTED_ROOT_DEPENDENCIES if release_candidate else LEGACY_EXPECTED_ROOT_DEPENDENCIES
    )
    expected_mypy_paths = (
        EXPECTED_ROOT_MYPY_PATHS if release_candidate else LEGACY_EXPECTED_ROOT_MYPY_PATHS
    )
    expected_source_declarations = (
        RC_WORKSPACE_SOURCES if release_candidate else LEGACY_WORKSPACE_SOURCES
    )
    mypy = _mapping(tool.get("mypy"), "pyproject.tool.mypy")
    if (
        list(_sequence(mypy.get("mypy_path"), "pyproject.tool.mypy.mypy_path"))
        != expected_mypy_paths
    ):
        errors.append("root mypy path inventory differs from the closed set")
    workspace_sources = _mapping(uv.get("sources"), "pyproject.tool.uv.sources")
    if workspace_sources != expected_source_declarations:
        errors.append("workspace source declarations differ from the closed set")
    expected_members = RC_WORKSPACE_MEMBERS if release_candidate else LEGACY_WORKSPACE_MEMBERS
    workspace = _mapping(uv.get("workspace"), "pyproject.tool.uv.workspace")
    if workspace != {"members": expected_members}:
        errors.append("workspace member inventory differs from the closed set")

    dependency_groups = _mapping(pyproject.get("dependency-groups"), "dependency-groups")
    if set(dependency_groups) != {"build", "quality"}:
        errors.append("dependency groups differ from the closed root set")
    if set(_sequence(dependency_groups.get("build"), "dependency-groups.build")) != {
        "uv-build>=0.11.32,<0.13"
    }:
        errors.append("build dependency group differs from the reviewed range")
    quality = set(_sequence(dependency_groups.get("quality"), "dependency-groups.quality"))
    if quality != EXPECTED_QUALITY_DEPENDENCIES:
        errors.append("quality dependencies differ from the exact reviewed set")
    if set(project) != {
        "name",
        "version",
        "description",
        "readme",
        "requires-python",
        "dependencies",
        "classifiers",
    }:
        errors.append("root project metadata keys differ from the closed set")
    direct_dependencies = list(_sequence(project.get("dependencies"), "project.dependencies"))
    if (
        project.get("name") != "securecode-ai-workspace"
        or project.get("version") != ("1.0.0" if release_candidate else "0.1.0a0")
        or project.get("description") != "Reproducible workspace authority for SecureCode AI"
        or project.get("readme") != "README.md"
        or project.get("requires-python") != ">=3.12,<3.15"
        or project.get("classifiers") != ["Private :: Do Not Upload"]
        or direct_dependencies != expected_root_dependencies
    ):
        errors.append("root project identity or dependencies differ from the closed set")
    for dependency in [*direct_dependencies, *quality]:
        if not isinstance(dependency, str) or any(
            fragment in dependency.lower() for fragment in (" @ ", "git+", "http://", "https://")
        ):
            errors.append(f"direct dependency uses a forbidden source: {dependency!r}")

    manifest = _mapping(lock.get("manifest"), "uv.lock manifest")
    expected_manifest_members = [
        "securecode-ai-adapters",
        "securecode-ai-cli",
        "securecode-ai-contracts",
        "securecode-ai-core",
        *(["securecode-ai-server"] if release_candidate else []),
        *(["securecode-ai-worker"] if release_candidate else []),
        "securecode-ai-workspace",
    ]
    if (
        list(_sequence(manifest.get("members"), "uv.lock manifest.members"))
        != expected_manifest_members
    ):
        errors.append("workspace lock manifest members differ from the closed set")

    packages = _sequence(lock.get("package"), "uv.lock package")
    expected_lock_sources = {
        "securecode-ai-adapters": {"editable": "packages/adapters"},
        "securecode-ai-cli": {"editable": "apps/cli"},
        "securecode-ai-contracts": {"editable": "packages/contracts"},
        "securecode-ai-core": {"editable": "packages/core"},
        **({"securecode-ai-server": {"editable": "apps/server"}} if release_candidate else {}),
        **({"securecode-ai-worker": {"editable": "apps/worker"}} if release_candidate else {}),
        "securecode-ai-workspace": {"virtual": "."},
    }
    observed_workspace_sources: dict[str, Mapping[str, Any]] = {}
    for raw_package in packages:
        package = _mapping(raw_package, "uv.lock package entry")
        name = package.get("name")
        source = _mapping(package.get("source"), f"uv.lock source for {name}")
        if name in expected_lock_sources:
            if name in observed_workspace_sources:
                errors.append(f"duplicate workspace package entry for {name}")
            observed_workspace_sources[name] = source
            if source != expected_lock_sources[name]:
                errors.append(f"workspace source mismatch for {name}")
            expected_workspace_version = "1.0.0" if release_candidate else "0.1.0a0"
            if package.get("version") != expected_workspace_version:
                errors.append(f"workspace version mismatch for {name}")
            continue
        if source != {"registry": PYPI_INDEX}:
            errors.append(f"non-PyPI or unknown source for {name}")
            continue
        artifacts: list[Mapping[str, Any]] = []
        sdist = package.get("sdist")
        if sdist is not None:
            artifacts.append(_mapping(sdist, f"sdist for {name}"))
        artifacts.extend(
            _mapping(wheel, f"wheel for {name}")
            for wheel in _sequence(package.get("wheels", []), f"wheels for {name}")
        )
        if not artifacts:
            errors.append(f"registry package has no locked artifacts: {name}")
        for artifact in artifacts:
            url = artifact.get("url")
            digest = artifact.get("hash")
            if not isinstance(url, str) or (
                urlparse(url).scheme != "https" or urlparse(url).hostname != PYPI_ARTIFACT_HOST
            ):
                errors.append(f"artifact URL is not approved for {name}")
            if not isinstance(digest, str) or not ARTIFACT_HASH_PATTERN.fullmatch(digest):
                errors.append(f"artifact SHA-256 is missing for {name}")
    if observed_workspace_sources != expected_lock_sources:
        errors.append("workspace lock package inventory differs from the closed set")
    return sorted(set(errors))


def workspace_metadata_errors(documents: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Reject build hooks, scripts or dependencies outside the reviewed workspace metadata."""

    errors: list[str] = []
    projects = _workspace_projects_for_paths(set(documents))
    if projects is None:
        errors.append("workspace pyproject inventory differs from the closed set")
        return errors
    release_candidate = projects is WORKSPACE_PROJECTS
    expected_version = "1.0.0" if release_candidate else "0.1.0a0"
    expected_console_scripts = (
        WORKSPACE_CONSOLE_SCRIPTS if release_candidate else LEGACY_WORKSPACE_CONSOLE_SCRIPTS
    )
    expected_worker_project = (
        EXPECTED_WORKER_PROJECT if release_candidate else LEGACY_EXPECTED_WORKER_PROJECT
    )
    for path, (name, dependencies, sources, module_name) in projects.items():
        document = _mapping(documents[path], path)
        if set(document) != {"build-system", "project", "tool"}:
            errors.append(f"{path}: top-level metadata keys differ from the closed set")
        build_system = _mapping(document.get("build-system"), f"{path}.build-system")
        if build_system != {
            "requires": ["uv_build>=0.11.32,<0.13"],
            "build-backend": "uv_build",
        }:
            errors.append(f"{path}: build backend differs from the reviewed backend")
        project = _mapping(document.get("project"), f"{path}.project")
        expected_project_keys = {
            "name",
            "version",
            "description",
            "readme",
            "requires-python",
            "dependencies",
            "classifiers",
        }
        expected_scripts = expected_console_scripts.get(path)
        if expected_scripts is not None:
            expected_project_keys.add("scripts")
        if set(project) != expected_project_keys:
            errors.append(f"{path}: project metadata keys differ from the closed set")
        if (
            project.get("name") != name
            or project.get("version") != expected_version
            or project.get("requires-python") != ">=3.12,<3.15"
            or project.get("dependencies") != dependencies
        ):
            errors.append(f"{path}: identity or dependencies differ from the reviewed values")
        if (
            expected_scripts is not None
            and _mapping(project.get("scripts"), f"{path}.project.scripts") != expected_scripts
        ):
            errors.append(f"{path}: console scripts differ from the reviewed set")
        tool = _mapping(document.get("tool"), f"{path}.tool")
        uv = _mapping(tool.get("uv"), f"{path}.tool.uv")
        expected_uv_keys = {"build-backend"} | ({"sources"} if sources else set())
        if set(uv) != expected_uv_keys:
            errors.append(f"{path}: uv metadata keys differ from the closed set")
        if _mapping(uv.get("build-backend"), f"{path}.tool.uv.build-backend") != {
            "module-name": module_name
        }:
            errors.append(f"{path}: module ownership differs from the reviewed value")
        if sources and _mapping(uv.get("sources"), f"{path}.tool.uv.sources") != sources:
            errors.append(f"{path}: workspace dependency sources differ from the reviewed set")
        if path == "apps/worker/pyproject.toml" and project != expected_worker_project:
            errors.append(f"{path}: project metadata differs from the reviewed worker contract")
        if path == "apps/server/pyproject.toml" and project != EXPECTED_SERVER_PROJECT:
            errors.append(f"{path}: project metadata differs from the reviewed server contract")
    return sorted(set(errors))


def _approved_secret_keys(baseline: Mapping[str, Any]) -> set[tuple[str, str, str]]:
    approved: set[tuple[str, str, str]] = set()
    for path, raw_findings in _mapping(baseline.get("results"), "baseline.results").items():
        for raw_finding in _sequence(raw_findings, f"baseline.results.{path}"):
            finding = _mapping(raw_finding, f"baseline finding in {path}")
            approved.add(
                (path.replace("\\", "/"), str(finding["type"]), str(finding["hashed_secret"]))
            )
    return approved


class _DuplicateJSONKey(ValueError):
    """Reject ambiguous metadata before any digest field is suppressed."""


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(value)


def _completion_attestation_scan_view(path: str, content: str) -> str:
    """Suppress only typed digest metadata in one closed completion attestation.

    Invalid, unknown or path-mismatched documents are returned byte-for-byte as
    text so the ordinary secret detectors remain authoritative.
    """

    normalized_path = path.replace("\\", "/")
    match = re.fullmatch(r"work/task-attestations/(P[0-9]+\.[0-9]+)\.json", normalized_path)
    if match is None:
        return content
    try:
        value = json.loads(
            content,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "change_type",
            "task_id",
            "starting_commit_sha",
            "packet_sha256",
            "implementation_commit_sha",
            "evidence_refs",
            "allowed_paths",
            "budgets",
        }:
            return content
        task_id = match.group(1)
        if (
            value["schema_version"] != "1.0.0"
            or value["change_type"] != "completion_attestation"
            or value["task_id"] != task_id
        ):
            return content
        git_oids = (value["starting_commit_sha"], value["implementation_commit_sha"])
        if any(
            not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{40}", item) is None
            for item in git_oids
        ):
            return content
        if (
            not isinstance(value["packet_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["packet_sha256"]) is None
        ):
            return content
        allowed_paths = value["allowed_paths"]
        if (
            not isinstance(allowed_paths, list)
            or not 1 <= len(allowed_paths) <= 5
            or any(not isinstance(item, str) or not item for item in allowed_paths)
            or len(set(allowed_paths)) != len(allowed_paths)
            or normalized_path not in allowed_paths
        ):
            return content
        if value["budgets"] != {"max_changed_files": 5, "max_diff_lines": 800}:
            return content
        policy = _read_json(SPEC_GATE_POLICY_PATH)
        catalog = _mapping(policy.get("completion_evidence"), "completion_evidence")
        required = _sequence(catalog.get(task_id), f"completion_evidence.{task_id}")
        refs = value["evidence_refs"]
        if not isinstance(refs, list) or not 1 <= len(refs) <= 16:
            return content
        observed: list[str] = []
        external_types = {"protected_pr_gate", "post_merge_gate"}
        for ref in refs:
            if not isinstance(ref, dict):
                return content
            ref_type = ref.get("type")
            expected_ref_keys = {"type", "source", "content_sha256"}
            if ref_type in external_types:
                expected_ref_keys.update(
                    {
                        "repository",
                        "run_id",
                        "run_attempt",
                        "event",
                        "conclusion",
                        "head_branch",
                        "head_sha",
                        "workflow_path",
                    }
                )
                if ref_type == "protected_pr_gate":
                    expected_ref_keys.update(
                        {
                            "pull_request_number",
                            "merge_commit_sha",
                            "required_check",
                            "gate_completed_at",
                            "merged_at",
                        }
                    )
            if set(ref) != expected_ref_keys:
                return content
            source = ref.get("source")
            digest = ref.get("content_sha256")
            if (
                not isinstance(ref_type, str)
                or not 1 <= len(ref_type.encode("utf-8")) <= 64
                or not isinstance(source, str)
                or not 1 <= len(source.encode("utf-8")) <= 1024
                or not isinstance(digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                return content
            if ref_type in external_types:
                expected_event = "pull_request" if ref_type == "protected_pr_gate" else "push"
                repository = ref.get("repository")
                run_id = ref.get("run_id")
                repository_parts = repository.split("/") if isinstance(repository, str) else []
                safe_repository_part = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
                if (
                    len(repository_parts) != 2
                    or any(
                        safe_repository_part.fullmatch(part) is None or part in {".", ".."}
                        for part in repository_parts
                    )
                    or repository_parts[1].lower().endswith(".git")
                    or not isinstance(run_id, int)
                    or run_id <= 0
                    or source.lower()
                    != f"https://github.com/{repository}/actions/runs/{run_id}".lower()
                    or not isinstance(ref.get("run_attempt"), int)
                    or ref["run_attempt"] <= 0
                    or ref.get("event") != expected_event
                    or ref.get("conclusion") != "success"
                    or not isinstance(ref.get("head_branch"), str)
                    or not 1 <= len(ref["head_branch"].encode("utf-8")) <= 255
                    or any(character.isspace() for character in ref["head_branch"])
                    or not isinstance(ref.get("head_sha"), str)
                    or re.fullmatch(r"[0-9a-f]{40}", ref["head_sha"]) is None
                    or ref.get("workflow_path") != ".github/workflows/ci.yml"
                ):
                    return content
                if ref_type == "protected_pr_gate" and (
                    not isinstance(ref.get("pull_request_number"), int)
                    or ref["pull_request_number"] <= 0
                    or not isinstance(ref.get("merge_commit_sha"), str)
                    or re.fullmatch(r"[0-9a-f]{40}", ref["merge_commit_sha"]) is None
                    or ref.get("required_check") != "gate"
                    or any(
                        not isinstance(ref.get(field), str)
                        or re.fullmatch(
                            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", ref[field]
                        )
                        is None
                        for field in ("gate_completed_at", "merged_at")
                    )
                ):
                    return content
            observed.append(ref_type)
        if observed != list(required) or len(set(observed)) != len(observed):
            return content
        if external_types.issubset(observed):
            protected = next(ref for ref in refs if ref["type"] == "protected_pr_gate")
            post_merge = next(ref for ref in refs if ref["type"] == "post_merge_gate")
            if (
                post_merge["head_branch"] != "master"
                or protected["repository"].lower() != post_merge["repository"].lower()
                or protected["merge_commit_sha"] != post_merge["head_sha"]
            ):
                return content

        scan_value = json.loads(json.dumps(value))
        scan_value["starting_commit_sha"] = "typed-git-object-id"
        scan_value["implementation_commit_sha"] = "typed-git-object-id"
        scan_value["packet_sha256"] = "typed-sha256-digest"
        for ref in scan_value["evidence_refs"]:
            ref["content_sha256"] = "typed-sha256-digest"
            if ref["type"] in external_types:
                ref["head_sha"] = "typed-git-object-id"
                if ref["type"] == "protected_pr_gate":
                    ref["merge_commit_sha"] = "typed-git-object-id"
        return json.dumps(scan_value, ensure_ascii=True, sort_keys=True)
    except (KeyError, PolicyError, TypeError, ValueError, json.JSONDecodeError):
        return content


def _length_prefixed_digest(documents: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256()
    for path, content in sorted(documents.items()):
        path_bytes = path.encode("utf-8")
        digest.update(len(path_bytes).to_bytes(8, "big", signed=False))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big", signed=False))
        digest.update(content)
    return digest.hexdigest()


def _promotion_manifest_scan_views(path: str, content: str) -> list[tuple[str, str]] | None:
    """Return sanitized metadata plus decoded target bytes for a valid manifest."""

    normalized_path = path.replace("\\", "/")
    gate_id: str
    match = re.fullmatch(r"artifacts/gates/(G[1-9])/promotion-manifest\.json", normalized_path)
    if match is not None:
        gate_id = match.group(1)
    elif re.fullmatch(
        r"work/change-control/amendments/CR-[0-9]{3}-manifest\.json", normalized_path
    ):
        gate_id = "POLICY"
    else:
        return None
    try:
        value = json.loads(
            content,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "gate_id",
            "evidence_bundle_sha256",
            "promotion_subject_sha256",
            "files",
        }:
            return None
        if value["schema_version"] != "1.0.0" or value["gate_id"] != gate_id:
            return None
        for field in ("evidence_bundle_sha256", "promotion_subject_sha256"):
            if (
                not isinstance(value[field], str)
                or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None
            ):
                return None

        policy = _read_json(SPEC_GATE_POLICY_PATH)
        if gate_id.startswith("G"):
            gate_policy = _mapping(
                _mapping(policy.get("gate_policy"), "gate_policy").get(gate_id), gate_id
            )
            allowed_paths = tuple(_sequence(gate_policy.get("promotion_paths"), "promotion_paths"))
            require_exact_paths = True
            maximum_files = len(allowed_paths)
        else:
            amendment = _mapping(policy.get("policy_amendment"), "policy_amendment")
            allowed_paths = tuple(_sequence(amendment.get("target_paths"), "target_paths"))
            raw_maximum_files = amendment.get("max_target_files")
            if not isinstance(raw_maximum_files, int) or isinstance(raw_maximum_files, bool):
                return None
            maximum_files = raw_maximum_files
            require_exact_paths = False
        if any(not isinstance(item, str) or not item for item in allowed_paths) or len(
            set(allowed_paths)
        ) != len(allowed_paths):
            return None
        allowed = set(allowed_paths)
        files = value["files"]
        if (
            not isinstance(files, list)
            or not 1 <= len(files) <= maximum_files
            or len(files) > len(allowed)
        ):
            return None

        decoded: dict[str, bytes] = {}
        total_bytes = 0
        for raw_entry in files:
            if not isinstance(raw_entry, dict) or set(raw_entry) != {
                "path",
                "base_sha256",
                "final_sha256",
                "final_base64",
            }:
                return None
            target = raw_entry["path"]
            if not isinstance(target, str) or target not in allowed or target in decoded:
                return None
            for field in ("base_sha256", "final_sha256"):
                if (
                    not isinstance(raw_entry[field], str)
                    or re.fullmatch(r"[0-9a-f]{64}", raw_entry[field]) is None
                ):
                    return None
            encoded = raw_entry["final_base64"]
            if not isinstance(encoded, str) or len(encoded) > 4 * 1024 * 1024:
                return None
            try:
                final_bytes = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                return None
            total_bytes += len(final_bytes)
            if total_bytes > 16 * 1024 * 1024:
                return None
            if hashlib.sha256(final_bytes).hexdigest() != raw_entry["final_sha256"]:
                return None
            decoded[target] = final_bytes
        observed_paths = tuple(sorted(decoded))
        if require_exact_paths:
            if observed_paths != tuple(sorted(allowed_paths)):
                return None
        elif not observed_paths:
            return None
        if _length_prefixed_digest(decoded) != value["promotion_subject_sha256"]:
            return None

        scan_value = json.loads(json.dumps(value))
        scan_value["evidence_bundle_sha256"] = "typed-sha256-digest"
        scan_value["promotion_subject_sha256"] = "typed-sha256-digest"
        for entry in scan_value["files"]:
            entry["base_sha256"] = "typed-sha256-digest"
            entry["final_sha256"] = "typed-sha256-digest"
            entry["final_base64"] = "decoded-and-scanned-target-bytes"
        views = [(normalized_path, json.dumps(scan_value, ensure_ascii=True, sort_keys=True))]
        views.extend(
            (target, final_bytes.decode("utf-8", "replace"))
            for target, final_bytes in sorted(decoded.items())
        )
        return views
    except (KeyError, PolicyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _review_receipt_scan_view(path: str, content: str) -> str:
    """Suppress only closed-schema receipt identity digests and Git object IDs."""

    normalized_path = path.replace("\\", "/")
    match = re.fullmatch(
        r"work/change-control/reviews/(G[1-9]|POLICY)/"
        r"(product_scope|architecture_contracts|security_evaluation)-([0-9a-f]{64})/receipt\.json",
        normalized_path,
    )
    if match is None:
        return content
    try:
        value = json.loads(
            content,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "change_type",
            "gate_id",
            "role",
            "reviewer_identity",
            "reviewed_commit_sha",
            "evidence_bundle_sha256",
            "review_subject_sha256",
            "promotion_subject_sha256",
            "verdict",
            "source_ref",
            "source_ref_sha256",
        }:
            return content
        gate_id, role, review_hash = match.groups()
        source_ref = normalized_path.removesuffix("receipt.json") + "review.md"
        if (
            value["schema_version"] != "1.0.0"
            or value["change_type"] != "independent_review"
            or value["gate_id"] != gate_id
            or value["role"] != role
            or value["review_subject_sha256"] != review_hash
            or value["verdict"] not in {"PASS", "BLOCK"}
            or value["source_ref"] != source_ref
        ):
            return content
        reviewer = value["reviewer_identity"]
        if (
            not isinstance(reviewer, str)
            or not 1 <= len(reviewer.encode("utf-8")) <= 256
            or any(character.isspace() and character not in {" ", "\t"} for character in reviewer)
        ):
            return content
        if (
            not isinstance(value["reviewed_commit_sha"], str)
            or re.fullmatch(r"[0-9a-f]{40}", value["reviewed_commit_sha"]) is None
        ):
            return content
        for field in (
            "evidence_bundle_sha256",
            "review_subject_sha256",
            "promotion_subject_sha256",
            "source_ref_sha256",
        ):
            if (
                not isinstance(value[field], str)
                or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None
            ):
                return content

        scan_value = json.loads(json.dumps(value))
        scan_value["reviewed_commit_sha"] = "typed-git-object-id"
        for field in (
            "evidence_bundle_sha256",
            "review_subject_sha256",
            "promotion_subject_sha256",
            "source_ref_sha256",
        ):
            scan_value[field] = "typed-sha256-digest"
        scan_value["source_ref"] = "typed-review-note-path"
        return json.dumps(scan_value, ensure_ascii=True, sort_keys=True)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return content


def _change_packet_scan_view(path: str, content: str) -> str:
    """Suppress only typed identities in one exact closed change packet."""

    normalized_path = path.replace("\\", "/")
    match = re.fullmatch(r"work/change-control/(CR-[0-9]{3})\.yaml", normalized_path)
    if match is None:
        return content
    try:
        value = json.loads(
            content,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "change_type",
            "change_id",
            "starting_commit_sha",
            "protected_class",
            "gate_id",
            "decision",
            "evidence_bundle_sha256",
            "review_subject_sha256",
            "allowed_paths",
            "budgets",
        }:
            return content
        change_id = match.group(1)
        if value["schema_version"] != "1.0.0" or value["change_id"] != change_id:
            return content
        if (
            not isinstance(value["starting_commit_sha"], str)
            or re.fullmatch(r"[0-9a-f]{40}", value["starting_commit_sha"]) is None
        ):
            return content
        for field in ("evidence_bundle_sha256", "review_subject_sha256"):
            if (
                not isinstance(value[field], str)
                or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None
            ):
                return content
        allowed_paths = value["allowed_paths"]
        if (
            not isinstance(allowed_paths, list)
            or any(not isinstance(item, str) or not item for item in allowed_paths)
            or len(set(allowed_paths)) != len(allowed_paths)
        ):
            return content
        policy = _read_json(SPEC_GATE_POLICY_PATH)
        if value["change_type"] == "spec":
            gate_policy = _mapping(
                _mapping(policy.get("gate_policy"), "gate_policy").get("G1"), "G1"
            )
            evidence_files = _sequence(gate_policy.get("evidence_files"), "evidence_files")
            expected_paths = {
                "CHANGELOG.md",
                "docs/CONTEXT.md",
                "docs/DECISIONS.md",
                normalized_path,
                "artifacts/gates/G1/promotion-manifest.json",
                *(f"artifacts/gates/G1/{item}" for item in evidence_files),
            }
            expected_identity = ("gate_evidence", "G1", "GO-PROPOSED")
            expected_budgets = {"max_changed_files": 11, "max_diff_lines": 3000}
        elif value["change_type"] == "integrated_gate_candidate":
            gate_id = value["gate_id"]
            if not isinstance(gate_id, str) or re.fullmatch(r"G[1-9]", gate_id) is None:
                return content
            gate_policy = _mapping(
                _mapping(policy.get("gate_policy"), "gate_policy").get(gate_id), gate_id
            )
            evidence_files = _sequence(gate_policy.get("evidence_files"), "evidence_files")
            maximum_files = gate_policy.get("max_changed_files")
            maximum_lines = gate_policy.get("max_diff_lines")
            if not isinstance(maximum_files, int) or not isinstance(maximum_lines, int):
                return content
            expected_paths = {
                "CHANGELOG.md",
                "docs/CONTEXT.md",
                normalized_path,
                *(f"artifacts/gates/{gate_id}/{item}" for item in evidence_files),
                f"artifacts/gates/{gate_id}/promotion-manifest.json",
            }
            expected_identity = ("gate_evidence", gate_id, "GO-PROPOSED")
            expected_budgets = {
                "max_changed_files": maximum_files,
                "max_diff_lines": maximum_lines,
            }
        elif value["change_type"] == "policy_amendment":
            amendment = _mapping(policy.get("policy_amendment"), "policy_amendment")
            maximum_files = amendment.get("max_changed_files")
            maximum_lines = amendment.get("max_diff_lines")
            if (
                not isinstance(maximum_files, int)
                or isinstance(maximum_files, bool)
                or not isinstance(maximum_lines, int)
                or isinstance(maximum_lines, bool)
            ):
                return content
            expected_paths = {
                "CHANGELOG.md",
                "docs/DECISIONS.md",
                normalized_path,
                f"work/change-control/amendments/{change_id}-manifest.json",
            }
            expected_identity = ("ci_evaluator", "POLICY", "CHANGE-PROPOSED")
            expected_budgets = {
                "max_changed_files": maximum_files,
                "max_diff_lines": maximum_lines,
            }
        else:
            return content
        if (
            (value["protected_class"], value["gate_id"], value["decision"]) != expected_identity
            or (
                not expected_paths.issubset(allowed_paths)
                if value["change_type"] == "integrated_gate_candidate"
                else set(allowed_paths) != expected_paths
            )
            or value["budgets"] != expected_budgets
        ):
            return content

        scan_value = json.loads(json.dumps(value))
        scan_value["starting_commit_sha"] = "typed-git-object-id"
        scan_value["evidence_bundle_sha256"] = "typed-sha256-digest"
        scan_value["review_subject_sha256"] = "typed-sha256-digest"
        return json.dumps(scan_value, ensure_ascii=True, sort_keys=True)
    except (KeyError, PolicyError, TypeError, ValueError, json.JSONDecodeError):
        return content


def _secret_scan_views(path: str, content: str) -> list[tuple[str, str]]:
    manifest_views = _promotion_manifest_scan_views(path, content)
    if manifest_views is not None:
        return manifest_views
    packet_view = _change_packet_scan_view(path, content)
    attestation_view = _completion_attestation_scan_view(path, packet_view)
    return [(path, _review_receipt_scan_view(path, attestation_view))]


def scan_text(
    path: str,
    content: str,
    baseline: Mapping[str, Any],
) -> list[tuple[str, str]]:
    """Scan one immutable blob and return only safe path/type diagnostics."""

    from detect_secrets.core.scan import _process_line_based_plugins
    from detect_secrets.settings import transient_settings

    approved = _approved_secret_keys(baseline)
    findings: set[tuple[str, str]] = set()
    with transient_settings(dict(baseline)):
        normalized_path = path.replace("\\", "/")
        for scan_path, scan_view in _secret_scan_views(path, content):
            lines = list(enumerate(scan_view.splitlines(), start=1))
            for candidate in _process_line_based_plugins(lines, filename=scan_path):
                approved_key = (scan_path.replace("\\", "/"), candidate.type, candidate.secret_hash)
                if approved_key not in approved:
                    findings.add((normalized_path, candidate.type))
    return sorted(findings)


def _git(*arguments: str) -> str:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    return completed.stdout


def _git_bytes(*arguments: str) -> bytes:
    completed = subprocess.run(
        ("git", *arguments),
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        timeout=60,
    )
    return completed.stdout


def parse_git_blob_records(raw: bytes, *, index: bool) -> list[tuple[str, str]]:
    """Parse NUL-safe index/tree records into path/object pairs."""

    records: list[tuple[str, str]] = []
    for raw_record in raw.split(b"\0"):
        if not raw_record:
            continue
        try:
            metadata, raw_path = raw_record.split(b"\t", 1)
            fields = metadata.decode("ascii").split()
        except (UnicodeDecodeError, ValueError) as error:
            raise PolicyError("Git blob inventory is malformed") from error
        if len(fields) != 3:
            raise PolicyError("Git blob inventory field count is invalid")
        mode = fields[0]
        object_id = fields[1] if index else fields[2]
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", object_id):
            raise PolicyError("Git blob object ID is invalid")
        if index:
            if fields[2] != "0":
                raise PolicyError("Git index contains an unresolved merge stage")
        else:
            if fields[1] != "blob":
                continue
            if mode not in {"100644", "100755", "120000"}:
                continue
        path = raw_path.decode("utf-8", "surrogateescape")
        if not path:
            raise PolicyError("Git blob path is empty")
        records.append((path, object_id))
    return records


def _scan_git_blobs(
    records: Sequence[tuple[str, str]],
    baseline: Mapping[str, Any],
    *,
    prefix: str,
    seen: set[tuple[str, str]] | None = None,
) -> list[str]:
    """Scan immutable object-database blobs and emit secret-safe diagnostics."""

    errors: list[str] = []
    for path, object_id in records:
        identity = (path, object_id)
        if seen is not None:
            if identity in seen:
                continue
            seen.add(identity)
        if path.replace("\\", "/") == ".secrets.baseline":
            continue
        blob = _git_bytes("cat-file", "blob", object_id)
        for found_path, finding_type in scan_text(path, blob.decode("utf-8", "replace"), baseline):
            safe_path = json.dumps(found_path, ensure_ascii=True)[1:-1]
            errors.append(f"{prefix}: {safe_path} ({finding_type})")
    return errors


def _index_blob_records() -> list[tuple[str, str]]:
    return parse_git_blob_records(_git_bytes("ls-files", "--stage", "-z"), index=True)


def _tree_blob_records(commit: str) -> list[tuple[str, str]]:
    return parse_git_blob_records(
        _git_bytes("ls-tree", "-r", "-z", commit),
        index=False,
    )


def _candidate_commits(base_sha: str) -> list[str]:
    head = _git("rev-parse", "HEAD").strip()
    if base_sha in {"0" * 40, head}:
        arguments: tuple[str, ...] = ("rev-list", "--reverse", "--topo-order", "HEAD")
    else:
        arguments = ("rev-list", "--reverse", "--topo-order", "HEAD", "--not", base_sha)
    return [commit for commit in _git(*arguments).splitlines() if commit]


def secret_errors(base_sha: str | None) -> list[str]:
    """Scan index blobs and every candidate commit tree without following filesystem links."""

    baseline_data = _read_json(BASELINE_PATH)
    errors = baseline_errors(baseline_data)
    seen: set[tuple[str, str]] = set()
    errors.extend(
        _scan_git_blobs(
            _index_blob_records(),
            baseline_data,
            prefix="unapproved index secret candidate",
            seen=seen,
        )
    )

    if base_sha:
        if not SAFE_BASE_PATTERN.fullmatch(base_sha):
            errors.append("base SHA is not a full lowercase commit SHA")
        else:
            try:
                for commit in _candidate_commits(base_sha):
                    errors.extend(
                        _scan_git_blobs(
                            _tree_blob_records(commit),
                            baseline_data,
                            prefix="candidate-history secret candidate",
                            seen=seen,
                        )
                    )
            except subprocess.SubprocessError:
                errors.append("PR history could not be scanned")
    return sorted(set(errors))


def known_vulnerable_audit_errors(returncode: int, output: str) -> list[str]:
    """Accept only a valid pip-audit finding receipt for the locked negative fixture."""

    if returncode != 1:
        return [f"known-vulnerable audit returned {returncode}, expected findings exit 1"]
    try:
        report = json.loads(output)
        dependencies = _sequence(
            _mapping(report, "pip-audit report").get("dependencies"), "dependencies"
        )
    except (json.JSONDecodeError, PolicyError):
        return ["known-vulnerable audit did not return valid JSON"]
    vulnerabilities: list[Any] = []
    for raw_dependency in dependencies:
        dependency = _mapping(raw_dependency, "pip-audit dependency")
        if dependency.get("name") == "pip" and dependency.get("version") == "21.2.4":
            vulnerabilities.extend(_sequence(dependency.get("vulns"), "pip vulnerabilities"))
    if not vulnerabilities:
        return ["known-vulnerable audit returned no pip 21.2.4 findings"]
    return []


def run_known_vulnerable_audit() -> list[str]:
    """Run pip-audit against a hash-complete immutable negative fixture."""

    fixture = _read_json(VULNERABLE_FIXTURE_PATH)
    if set(fixture) != {"name", "version", "sha256_chunks", "minimum_vulnerabilities"}:
        return ["known-vulnerable fixture keys differ from the closed set"]
    if (
        fixture.get("name") != "pip"
        or fixture.get("version") != "21.2.4"
        or fixture.get("minimum_vulnerabilities") != 1
    ):
        return ["known-vulnerable fixture identity differs from the reviewed value"]
    hashes = [
        "".join(str(chunk) for chunk in _sequence(raw_chunks, "fixture hash chunks"))
        for raw_chunks in _sequence(fixture.get("sha256_chunks"), "fixture hashes")
    ]
    if hashes != EXPECTED_VULNERABLE_HASHES:
        return ["known-vulnerable fixture hashes are malformed"]
    requirement = "pip==21.2.4 " + " ".join(f"--hash=sha256:{digest}" for digest in hashes)
    with tempfile.TemporaryDirectory(prefix="securecode-audit-negative-") as directory:
        requirement_path = Path(directory) / "requirements.txt"
        requirement_path.write_text(requirement + "\n", encoding="utf-8")
        completed = subprocess.run(
            (
                sys.executable,
                "-I",
                "-m",
                "pip_audit",
                "--require-hashes",
                "--disable-pip",
                "--progress-spinner",
                "off",
                "--format",
                "json",
                "--requirement",
                str(requirement_path),
            ),
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    return known_vulnerable_audit_errors(completed.returncode, completed.stdout)


def validate(selection: str, base_sha: str | None = None) -> list[str]:
    """Run one policy family or the complete non-network policy suite."""

    errors: list[str] = []
    if selection in {"lock", "validate"}:
        with PYPROJECT_PATH.open("rb") as handle:
            pyproject = tomllib.load(handle)
        with LOCK_PATH.open("rb") as handle:
            lock = tomllib.load(handle)
        errors.extend(lock_errors(pyproject, lock))
        workspace_documents: dict[str, Mapping[str, Any]] = {}
        try:
            for relative in _workspace_projects_for_root(pyproject):
                with (REPOSITORY_ROOT / relative).open("rb") as handle:
                    workspace_documents[relative] = tomllib.load(handle)
        except (OSError, PolicyError, tomllib.TOMLDecodeError):
            errors.append("workspace metadata could not be read")
        else:
            errors.extend(workspace_metadata_errors(workspace_documents))
        tracked_lockfiles = _git("ls-files", "*uv.lock").splitlines()
        if tracked_lockfiles != ["uv.lock"]:
            errors.append("repository must contain exactly one root uv.lock")
    if selection in {"workflow", "validate"}:
        errors.extend(workflow_errors(_load_workflow()))
        errors.extend(precommit_errors(_load_precommit()))
    if selection in {"baseline", "validate"}:
        errors.extend(baseline_errors(_read_json(BASELINE_PATH)))
    if selection == "secrets":
        errors.extend(secret_errors(base_sha))
    if selection == "audit-negative":
        errors.extend(run_known_vulnerable_audit())
    return sorted(set(errors))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "selection",
        choices=("validate", "lock", "workflow", "baseline", "secrets", "audit-negative"),
    )
    parser.add_argument("--base", help="trusted 40-hex base commit for PR history scanning")
    arguments = parser.parse_args(argv)
    try:
        errors = validate(arguments.selection, arguments.base)
    except (
        OSError,
        ValueError,
        KeyError,
        PolicyError,
        subprocess.SubprocessError,
        tomllib.TOMLDecodeError,
    ) as exception:
        print(
            f"CI_POLICY=FAIL (malformed policy input: {type(exception).__name__})", file=sys.stderr
        )
        return 2
    if errors:
        print("CI_POLICY=FAIL", file=sys.stderr)
        for violation in errors:
            print(f"- {violation}", file=sys.stderr)
        return 1
    print(f"CI_POLICY=PASS ({arguments.selection})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
