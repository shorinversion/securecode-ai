"""Boundary, mutation and adversarial tests for the P1.13 specification gate."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = REPOSITORY_ROOT / "scripts" / "spec_gate.py"
ORIGINAL_POPEN = subprocess.Popen
CANARY = "source-secret-canary-value"


@pytest.fixture
def lifecycle_parent() -> Iterator[Path]:
    """Keep committed-history paths below the legacy Windows path ceiling."""

    with tempfile.TemporaryDirectory(prefix="sc-p113-", dir=REPOSITORY_ROOT.parent) as directory:
        yield Path(directory)


def _load_gate() -> ModuleType:
    spec = importlib.util.spec_from_file_location("securecode_spec_gate", GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load specification gate module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GATE = _load_gate()


def _limits() -> Any:
    return GATE.SpecGate().limits


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b'{"x":1,"x":2}', "JSON_DUPLICATE_KEY"),
        (b'{"x":NaN}', "JSON_NONFINITE"),
        (b'{"x":Infinity}', "JSON_NONFINITE"),
        (b'{"x":1} trailing', "JSON_PARSE"),
        (b"\xef\xbb\xbf{}", "JSON_BOM"),
        (b'{"x":"\x00"}', "JSON_NUL"),
        (b"\xff", "JSON_UTF8"),
    ],
)
def test_strict_json_rejects_ambiguous_or_nonportable_input(payload: bytes, code: str) -> None:
    with pytest.raises(GATE.GateInputError) as caught:
        GATE.strict_json_loads(payload, _limits())
    assert caught.value.code == code
    assert CANARY not in str(caught.value)


def test_strict_json_accepts_closed_finite_utf8() -> None:
    assert GATE.strict_json_loads(b'{"x":[1,true,null]}', _limits()) == {"x": [1, True, None]}


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b"x: 1\nx: 2\n", "YAML_DUPLICATE_KEY"),
        (b"x: &a 1\ny: *a\n", "YAML_ALIAS_ANCHOR"),
        (b"x: !!python/object:builtins.object {}\n", "YAML_EXPLICIT_TAG"),
        (b"? [a, b]\n: value\n", "YAML_NON_SCALAR_KEY"),
        (b"x: 1\n---\ny: 2\n", "YAML_DOCUMENT_COUNT"),
        (b"\xef\xbb\xbfx: 1\n", "YAML_BOM"),
        (b"x: \x00\n", "YAML_NUL"),
    ],
)
def test_strict_yaml_rejects_alias_tag_duplicate_and_multidoc(payload: bytes, code: str) -> None:
    with pytest.raises(GATE.GateInputError) as caught:
        GATE.strict_yaml_loads(payload, _limits())
    assert caught.value.code == code


def test_tree_limits_reject_depth_nodes_collection_and_scalar() -> None:
    limits = replace(_limits(), parsed_depth=2)
    with pytest.raises(GATE.GateInputError, match="RESOURCE_DEPTH"):
        GATE.strict_json_loads(b'{"x":{"y":1}}', limits)
    limits = replace(_limits(), collection_items_per_node=1)
    with pytest.raises(GATE.GateInputError, match="RESOURCE_COLLECTION_ITEMS"):
        GATE.strict_json_loads(b"[1,2]", limits)
    limits = replace(_limits(), scalar_utf8_bytes=2)
    with pytest.raises(GATE.GateInputError, match="RESOURCE_SCALAR_BYTES"):
        GATE.strict_json_loads('"€"'.encode(), limits)


def test_markdown_definitions_ignore_code_comments_links_and_prose() -> None:
    markdown = b"""- `SC-OK-001`: accepted\n
```text
- `SC-NO-002`: code
```
<!-- - `SC-NO-003`: comment -->
[SC-NO-004](target) and SC-NO-005 prose.
"""
    assert GATE.markdown_definitions(markdown, _limits()) == ("SC-OK-001",)


@pytest.mark.parametrize(
    "path",
    ["", "/root", "C:/host", "../escape", "a/../escape", "./x", "-option", "a\\b"],
)
def test_repository_paths_are_canonical_and_option_safe(path: str) -> None:
    with pytest.raises(GATE.GateInputError):
        GATE.normalize_repo_path(path)


def test_length_framing_distinguishes_delimiter_ambiguity() -> None:
    left = {"A": b"xB\0y", "B": b"z"}
    right = {"A": b"x", "B": b"yB\0z"}
    assert GATE.length_prefixed_digest(left) != GATE.length_prefixed_digest(right)
    assert GATE.length_prefixed_digest(left) == GATE.length_prefixed_digest(
        dict(reversed(left.items()))
    )


def test_review_subject_zeros_only_the_single_self_hash_scalar() -> None:
    packet_path = "work/change-control/CR-001.yaml"
    zero_packet = b'review_subject_sha256: "' + b"0" * 64 + b'"\nvalue: exact\n'
    documents = {packet_path: zero_packet, "docs/CONTEXT.md": b"context\n"}
    expected = GATE.length_prefixed_digest(documents)
    final_documents = {
        packet_path: zero_packet.replace(b"0" * 64, expected.encode()),
        "docs/CONTEXT.md": b"context\n",
    }
    assert (
        GATE.canonical_review_subject(
            final_documents, packet_path=packet_path, stored_hash=expected
        )
        == expected
    )
    final_documents["docs/CONTEXT.md"] = b"changed\n"
    assert (
        GATE.canonical_review_subject(
            final_documents, packet_path=packet_path, stored_hash=expected
        )
        != expected
    )


def test_review_subject_rejects_duplicate_or_missing_self_hash() -> None:
    digest = "a" * 64
    with pytest.raises(GATE.GateInputError, match="CHANGE_PACKET_REVIEW_SELF_HASH"):
        GATE.canonical_review_subject(
            {"work/change-control/CR-001.yaml": (digest + digest).encode()},
            packet_path="work/change-control/CR-001.yaml",
            stored_hash=digest,
        )


def test_task_status_rows_are_equivalent_under_lf_and_crlf_checkout() -> None:
    row = "| `P1.4` | task | P1.3 | result | `IN PROGRESS` |"
    assert GATE.task_statuses((row + "\n").encode()) == {"P1.4": "IN PROGRESS"}
    assert GATE.task_statuses((row + "\r\n").encode()) == {"P1.4": "IN PROGRESS"}


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        (b"A\0plain.py\0", (("A", "plain.py"),)),
        (b"M\0space and quote.py\0", (("M", "space and quote.py"),)),
        (b"R100\0old.py\0new.py\0", (("R100", "old.py", "new.py"),)),
        (b"C75\0source.py\0copy.py\0", (("C75", "source.py", "copy.py"),)),
    ],
)
def test_git_name_status_parser_preserves_both_endpoints(
    records: bytes, expected: tuple[tuple[str, ...], ...]
) -> None:
    assert GATE.parse_name_status(records) == expected


@pytest.mark.parametrize(
    "records",
    [b"X\0x\0", b"R100\0only-one\0", b"A\0\xff\0", b"A\0../escape\0", b"A\0-option\0"],
)
def test_git_name_status_parser_fails_closed(records: bytes) -> None:
    with pytest.raises(GATE.GateInputError):
        GATE.parse_name_status(records)


def test_git_environment_keeps_only_the_sanitized_executable_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PATH", "closed-tool-path")
    monkeypatch.setenv("SOURCE_SECRET_CANARY", CANARY)
    environment = GATE._git_environment()
    assert environment["PATH"] == "closed-tool-path"
    assert "SOURCE_SECRET_CANARY" not in environment
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    repository = tmp_path / "repository"
    trusted = tmp_path / "trusted"
    repository.mkdir()
    trusted.mkdir()
    executable_name = "git.exe" if GATE.os.name == "nt" else "git"
    (repository / executable_name).write_bytes(b"repository-shadow")
    trusted_executable = trusted / executable_name
    trusted_executable.write_bytes(b"trusted")
    trusted_executable.chmod(0o755)
    monkeypatch.setenv("PATH", f"{repository}{GATE.os.pathsep}{trusted}")
    assert GATE._git_executable(repository) == str(trusted_executable.resolve())
    commands: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...], **_: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, b"", b"")

    monkeypatch.setattr(GATE.subprocess, "run", fake_run)
    monkeypatch.setattr(GATE, "_git_executable", lambda root: str(trusted_executable.resolve()))
    assert GATE.git_bytes(REPOSITORY_ROOT, "status") == b""
    assert commands == [
        (
            str(trusted_executable.resolve()),
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.autocrlf=input",
            "-c",
            "core.eol=lf",
            "-c",
            "core.whitespace=blank-at-eol,blank-at-eof,space-before-tab,cr-at-eol",
            "-c",
            "core.hooksPath=",
            "status",
        )
    ]


def _schema() -> dict[str, Any]:
    return {
        "$schema": GATE.JSON_SCHEMA_DIALECT,
        "$defs": {"name": {"type": "string", "format": "uri"}},
        "type": "object",
        "properties": {"name": {"$ref": "#/$defs/name"}},
    }


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (
            lambda schema: schema.update({"$schema": "http://json-schema.org/draft-07/schema#"}),
            "SCHEMA_DIALECT",
        ),
        (
            lambda schema: schema["properties"]["name"].update({"$ref": "https://evil.invalid/x"}),
            "SCHEMA_EXTERNAL_REF",
        ),
        (
            lambda schema: schema["properties"]["name"].update({"$ref": "#/$defs/missing"}),
            "SCHEMA_UNRESOLVED_REF",
        ),
        (
            lambda schema: (
                schema.update({"x": [{"type": "string"}]}),
                schema["properties"]["name"].update({"$ref": "#/x/-1"}),
            ),
            "SCHEMA_UNRESOLVED_REF",
        ),
        (
            lambda schema: (
                schema.update({"x~2y": {"type": "string"}}),
                schema["properties"]["name"].update({"$ref": "#/x~2y"}),
            ),
            "SCHEMA_UNRESOLVED_REF",
        ),
        (
            lambda schema: schema["$defs"]["name"].update({"format": "unknown"}),
            "SCHEMA_UNKNOWN_FORMAT",
        ),
        (lambda schema: schema.update({"$dynamicRef": "#x"}), "SCHEMA_DYNAMIC_REF"),
    ],
)
def test_schema_contract_rejects_dialect_ref_and_format_bypasses(
    mutate: Callable[[dict[str, Any]], None], code: str
) -> None:
    schema = _schema()
    mutate(schema)
    assert code in GATE.schema_document_errors(schema, known_formats=frozenset({"uri"}))


def test_format_checker_enforces_uri_and_date_time() -> None:
    escaped = {"a/b": {"m~n": {"percent key": True}}}
    assert GATE._resolve_fragment(escaped, "#/a~1b/m~0n/percent%20key")
    schema = {
        "$schema": GATE.JSON_SCHEMA_DIALECT,
        "type": "object",
        "properties": {
            "uri": {"type": "string", "format": "uri"},
            "time": {"type": "string", "format": "date-time"},
        },
        "required": ["uri", "time"],
    }
    validator = GATE._schema_validator(schema, frozenset({"uri", "date-time"}))
    assert not list(
        validator.iter_errors({"uri": "https://example.com/x", "time": "2026-08-18T00:00:00Z"})
    )
    assert list(validator.iter_errors({"uri": "not a uri", "time": "not a time"}))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda schema: schema["required"].append("new"),
        lambda schema: schema["properties"].pop("name"),
        lambda schema: schema["properties"]["name"].update({"pattern": "^narrow$"}),
        lambda schema: schema.update({"type": "array"}),
        lambda schema: schema.update({"unsupported": True}),
    ],
)
def test_compatibility_is_conservative_for_breaking_or_ambiguous_delta(
    mutation: Callable[[dict[str, Any]], None],
) -> None:
    old = {
        "$id": "v1",
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    }
    new = copy.deepcopy(old)
    mutation(new)
    assert GATE.compatibility_errors(old, new)


@pytest.mark.parametrize(
    ("source", "evidence_type", "identity"),
    [
        (
            "https://api.github.com/repos/Owner/Repo/rulesets/1",
            "github_ruleset_required_check",
            ("owner", "repo"),
        ),
        (
            "https://github.com/Owner/Repo/actions/runs/2",
            "github_failing_pr_merge_block",
            ("owner", "repo"),
        ),
        ("https://github.com/owner/repo", "github_failing_pr_merge_block", None),
        ("https://api.github.com/repos/owner/repo", "github_ruleset_required_check", None),
        (
            "https://raw.githubusercontent.com/owner/repo/main/receipt.json",
            "github_ruleset_required_check",
            None,
        ),
        ("http://github.com/owner/repo/actions/runs/1", "github_failing_pr_merge_block", None),
        (
            "https://github.com/owner/repo/actions/runs/1",
            "github_ruleset_required_check",
            None,
        ),
        (
            "https://github.com/%6fwner/repo/actions/runs/1",
            "github_failing_pr_merge_block",
            None,
        ),
        (
            "https://github.com/owner/repo/actions/runs/1?canary=value",
            "github_failing_pr_merge_block",
            None,
        ),
    ],
)
def test_github_evidence_authority_is_closed(
    source: str, evidence_type: str, identity: tuple[str, str] | None
) -> None:
    assert GATE.github_evidence_identity(source, evidence_type) == identity
    assert GATE.repository_identity("Owner/Repo") == ("owner", "repo")
    assert GATE.repository_identity("https://github.com/owner/repo") is None


def test_promotion_manifest_binds_current_and_exact_final_bytes() -> None:
    paths = ("CHANGELOG.md", "docs/CONTEXT.md")
    base = {path: f"base:{path}\n".encode() for path in paths}
    final = {path: f"final:{path}\n".encode() for path in paths}
    manifest = {
        "schema_version": "1.0.0",
        "gate_id": "G1",
        "evidence_bundle_sha256": "a" * 64,
        "promotion_subject_sha256": GATE.length_prefixed_digest(final),
        "files": [
            {
                "path": path,
                "base_sha256": hashlib.sha256(base[path]).hexdigest(),
                "final_sha256": hashlib.sha256(final[path]).hexdigest(),
                "final_base64": GATE.base64.b64encode(final[path]).decode(),
            }
            for path in paths
        ],
    }
    assert (
        dict(
            GATE._promotion_manifest_errors(
                manifest, gate_id="G1", policy_paths=paths, base_documents=base
            )
        )
        == final
    )
    drifted = dict(base)
    drifted[paths[0]] = b"drift"
    with pytest.raises(GATE.GateInputError, match="PROMOTION_MANIFEST_BASE_DRIFT"):
        GATE._promotion_manifest_errors(
            manifest, gate_id="G1", policy_paths=paths, base_documents=drifted
        )


def test_policy_promotion_selector_uses_exact_current_base_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gate = GATE.SpecGate()
    base = "a" * 40
    target = "scripts/ci_policy.py"
    current = b"current evaluator bytes\n"
    old = b"old evaluator bytes\n"
    candidate = b"next evaluator bytes\n"
    old_candidate = b"historical final evaluator bytes\n"

    def manifest(base_bytes: bytes, final_bytes: bytes) -> bytes:
        value = {
            "schema_version": "1.0.0",
            "gate_id": "POLICY",
            "evidence_bundle_sha256": "b" * 64,
            "promotion_subject_sha256": "c" * 64,
            "files": [
                {
                    "path": target,
                    "base_sha256": hashlib.sha256(base_bytes).hexdigest(),
                    "final_sha256": hashlib.sha256(final_bytes).hexdigest(),
                    "final_base64": "",
                }
            ],
        }
        return json.dumps(value).encode()

    documents = {
        target: current,
        "work/change-control/CR-997.yaml": b'{"change_type":"policy_amendment","change_id":"CR-997"}',
        "work/change-control/CR-998.yaml": b'{"change_type":"policy_amendment","change_id":"CR-998"}',
        "work/change-control/amendments/CR-997-manifest.json": manifest(old, old_candidate),
        "work/change-control/amendments/CR-998-manifest.json": manifest(current, candidate),
    }
    names = "\n".join(
        (
            "work/change-control/CR-997.yaml",
            "work/change-control/CR-998.yaml",
        )
    )
    monkeypatch.setattr(GATE, "git_text", lambda *args: names)
    monkeypatch.setattr(
        GATE.SpecGate,
        "_base_file",
        lambda _self, _revision, path: documents[path],
    )
    monkeypatch.setattr(
        GATE.SpecGate,
        "_candidate_file",
        lambda _self, _mode, _revision, path: candidate if path == target else b"",
    )
    changed = (target,)
    assert (
        gate._policy_promotion_packet(
            "committed-candidate", base=base, candidate="e" * 40, changed=changed
        )
        == "work/change-control/CR-998.yaml"
    )

    documents["work/change-control/amendments/CR-997-manifest.json"] = manifest(
        current, old_candidate
    )
    assert (
        gate._policy_promotion_packet(
            "committed-candidate", base=base, candidate="e" * 40, changed=changed
        )
        == "work/change-control/CR-998.yaml"
    )
    documents["work/change-control/amendments/CR-997-manifest.json"] = manifest(current, candidate)
    with pytest.raises(GATE.GateInputError, match="POLICY_PROMOTION_AMBIGUOUS"):
        gate._policy_promotion_packet(
            "committed-candidate", base=base, candidate="e" * 40, changed=changed
        )


@pytest.mark.parametrize(
    ("parents", "promotion_base", "expected"),
    [
        ({"r1": "p", "r2": "r1", "r3": "r2"}, "r3", True),
        ({"r1": "p", "r2": "p", "r3": "r2"}, "r3", False),
        ({"r1": "p", "r2": "r1", "r3": "r2"}, "merge", False),
        ({"r1": "p", "r2": "gap", "r3": "r2"}, "r3", False),
    ],
)
def test_review_chain_rejects_divergent_merge_and_intermediate_histories(
    monkeypatch: pytest.MonkeyPatch,
    parents: dict[str, str],
    promotion_base: str,
    expected: bool,
) -> None:
    gate = GATE.SpecGate()
    monkeypatch.setattr(
        GATE.SpecGate,
        "_single_parent",
        lambda _self, commit: parents[commit],
    )
    assert gate._linear_review_chain("p", set(parents), promotion_base) is expected


def test_current_packet_is_closed_and_mutations_fail() -> None:
    gate = GATE.SpecGate()
    assert ".secrets.baseline" in gate.policy["self_protected_paths"]
    packet = yaml.safe_load((REPOSITORY_ROOT / "work/task-packets/P1.13.yaml").read_text())
    changed = tuple(packet["scope"]["allowed_paths"])
    assert (
        GATE.validate_task_packet(
            packet,
            packet_path="work/task-packets/P1.13.yaml",
            base_sha="b157512cf867e834298770c2778da02259fde7b9",
            changed=changed,
            diff_lines=5000,
            policy=gate.policy,
        )
        == ()
    )
    mutation = copy.deepcopy(packet)
    mutation["scope"]["allowed_paths"].append("specs/baseline.yaml")
    assert GATE.validate_task_packet(
        mutation,
        packet_path="work/task-packets/P1.13.yaml",
        base_sha="b157512cf867e834298770c2778da02259fde7b9",
        changed=changed,
        diff_lines=5000,
        policy=gate.policy,
    )


def _completion() -> dict[str, Any]:
    evidence = [
        {
            "type": name,
            "source": f"https://github.com/example/repo/{name}",
            "content_sha256": "a" * 64,
        }
        for name in ("github_ruleset_required_check", "github_failing_pr_merge_block")
    ]
    return {
        "schema_version": "1.0.0",
        "change_type": "completion_attestation",
        "task_id": "P1.4",
        "starting_commit_sha": "a" * 40,
        "packet_sha256": "b" * 64,
        "implementation_commit_sha": "c" * 40,
        "evidence_refs": evidence,
        "allowed_paths": ["work/task-attestations/P1.4.json"],
        "budgets": {"max_changed_files": 5, "max_diff_lines": 800},
    }


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(extra=True),
        lambda value: value.update(task_id="P1.13"),
        lambda value: value.update(starting_commit_sha="0" * 64),
        lambda value: value.update(evidence_refs=[]),
        lambda value: value["evidence_refs"].reverse(),
        lambda value: value["evidence_refs"][0].update(content_sha256="bad"),
        lambda value: value["budgets"].update(max_changed_files=99),
    ],
)
def test_completion_attestation_cannot_self_select_evidence_or_budgets(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    gate = GATE.SpecGate()
    value = _completion()
    mutate(value)
    assert GATE.validate_completion_attestation(
        value,
        policy=gate.policy,
        actual_paths=("work/task-attestations/P1.4.json",),
    )


def test_snapshot_passes_current_authoritative_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(REPOSITORY_ROOT)
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    assert GATE.SpecGate().validate_snapshot() == ()


def _run_git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _write_candidate(repository: Path, relative: str, data: bytes) -> None:
    target = repository / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _commit_all(repository: Path, message: str) -> str:
    _run_git(repository, "add", "-A")
    if _run_git(repository, "status", "--porcelain"):
        _run_git(repository, "-c", "core.hooksPath=", "commit", "-m", message)
    return _run_git(repository, "rev-parse", "HEAD")


def _clone_index_candidate(parent: Path) -> tuple[Path, str]:
    repository = parent / "lifecycle"
    _run_git(parent, "clone", "--quiet", "--no-hardlinks", str(REPOSITORY_ROOT), str(repository))
    _run_git(repository, "config", "user.name", "Spec Gate Test")
    _run_git(repository, "config", "user.email", "spec-gate@example.invalid")
    _run_git(repository, "config", "core.autocrlf", "false")
    _run_git(repository, "config", "core.longpaths", "true")
    prefix = f"{repository.resolve().as_posix()}/"
    _run_git(
        REPOSITORY_ROOT,
        "-c",
        "core.autocrlf=false",
        "-c",
        "core.eol=lf",
        "checkout-index",
        "--all",
        "--force",
        f"--prefix={prefix}",
    )
    _commit_all(repository, "P1.13 implementation candidate")
    additions = _run_git(
        repository,
        "log",
        "--diff-filter=A",
        "--format=%H",
        "HEAD",
        "--",
        "work/task-packets/P1.13.yaml",
    ).splitlines()
    assert len(additions) == 1
    _run_git(repository, "switch", "--detach", additions[0])
    return repository, additions[0]


def _replace_task_status(repository: Path, task_id: str) -> None:
    path = repository / "docs/PLAN.md"
    pattern = re.compile(
        rb"(?m)(^\| `" + re.escape(task_id.encode()) + rb"` \|[^\r\n]*\| `)IN PROGRESS(` \|\r?$)"
    )
    updated, count = pattern.subn(rb"\1DONE\2", path.read_bytes())
    assert count == 1
    path.write_bytes(updated)


def _complete_task(
    repository: Path, task_id: str, *, evidence_repository: str = "example/repo"
) -> tuple[str, str]:
    base = _run_git(repository, "rev-parse", "HEAD")
    packet_path = f"work/task-packets/{task_id}.yaml"
    packet = (repository / packet_path).read_bytes()
    implementation = _run_git(
        repository,
        "log",
        "--diff-filter=A",
        "--format=%H",
        base,
        "--",
        packet_path,
    ).splitlines()
    assert len(implementation) == 1
    evidence_types = GATE.SpecGate().policy["completion_evidence"][task_id]
    sources: tuple[str, ...]
    if task_id == "P1.4":
        owner, name = evidence_repository.split("/", 1)
        sources = (
            f"https://api.github.com/repos/{owner}/{name}/rulesets/1",
            f"https://github.com/{owner}/{name}/actions/runs/2",
        )
    else:
        source = "docs/DECISIONS.md"
        sources = tuple(source for _ in evidence_types)
    refs = []
    for evidence_type, source in zip(evidence_types, sources, strict=True):
        content_hash = (
            "a" * 64
            if task_id == "P1.4"
            else hashlib.sha256((repository / source).read_bytes()).hexdigest()
        )
        refs.append({"type": evidence_type, "source": source, "content_sha256": content_hash})
    attestation_path = f"work/task-attestations/{task_id}.json"
    _replace_task_status(repository, task_id)
    attestation = {
        "schema_version": "1.0.0",
        "change_type": "completion_attestation",
        "task_id": task_id,
        "starting_commit_sha": base,
        "packet_sha256": hashlib.sha256(packet).hexdigest(),
        "implementation_commit_sha": implementation[0],
        "evidence_refs": refs,
        "allowed_paths": sorted(("docs/PLAN.md", attestation_path)),
        "budgets": {"max_changed_files": 5, "max_diff_lines": 800},
    }
    _write_candidate(
        repository, attestation_path, json.dumps(attestation, sort_keys=True).encode() + b"\n"
    )
    return base, _commit_all(repository, f"Complete {task_id}")


def _proposal_candidate(
    repository: Path, *, failed_check: bool = False
) -> tuple[str, str, dict[str, Any]]:
    base = _run_git(repository, "rev-parse", "HEAD")
    gate = GATE.SpecGate()
    policy = gate.policy["gate_policy"]["G1"]
    evidence_paths = tuple(f"artifacts/gates/G1/{name}" for name in policy["evidence_files"])
    checklist = b"".join(
        f"- `{name}`: `{'FAIL' if failed_check and index == 0 else 'PASS'}`\n".encode()
        for index, name in enumerate(policy["checklist_ids"])
    )
    evidence = {
        evidence_paths[0]: checklist,
        evidence_paths[1]: b"benchmark: PASS\n",
        evidence_paths[2]: b"security: PASS\n",
        evidence_paths[3]: b"risks: none\n",
        evidence_paths[4]: b"decision: GO-PROPOSED\n",
        evidence_paths[5]: b"foundation: PASS\n",
    }
    change_id = "CR-999"
    packet_path = f"work/change-control/{change_id}.yaml"
    changelog = (repository / "CHANGELOG.md").read_bytes() + b"\n- CR-999 proposal\n"
    decisions = (repository / "docs/DECISIONS.md").read_bytes() + b"\n## CR-999 proposal\n"
    context = (repository / "docs/CONTEXT.md").read_bytes() + b"\nG1: GO-PROPOSED\n"
    promotion_base = {
        "artifacts/gates/G1/decision.md": evidence["artifacts/gates/G1/decision.md"],
        "CHANGELOG.md": changelog,
        "docs/PLAN.md": (repository / "docs/PLAN.md").read_bytes(),
        "docs/CONTEXT.md": context,
    }
    final = {
        "artifacts/gates/G1/decision.md": b"decision: GO\n",
        "CHANGELOG.md": changelog + b"- G1 promotion: GO\n",
        "docs/PLAN.md": promotion_base["docs/PLAN.md"] + b"\nG1 promotion: GO\n",
        "docs/CONTEXT.md": context + b"G1 effective: GO\n",
    }
    evidence_hash = GATE.length_prefixed_digest(evidence)
    promotion_hash = GATE.length_prefixed_digest(final)
    manifest = {
        "schema_version": "1.0.0",
        "gate_id": "G1",
        "evidence_bundle_sha256": evidence_hash,
        "promotion_subject_sha256": promotion_hash,
        "files": [
            {
                "path": path,
                "base_sha256": hashlib.sha256(promotion_base[path]).hexdigest(),
                "final_sha256": hashlib.sha256(final[path]).hexdigest(),
                "final_base64": GATE.base64.b64encode(final[path]).decode(),
            }
            for path in policy["promotion_paths"]
        ],
    }
    documents = {
        **evidence,
        "artifacts/gates/G1/promotion-manifest.json": (
            json.dumps(manifest, sort_keys=True).encode() + b"\n"
        ),
        "CHANGELOG.md": changelog,
        "docs/DECISIONS.md": decisions,
        "docs/CONTEXT.md": context,
    }
    changed = sorted((*documents, packet_path))
    packet = {
        "schema_version": "1.0.0",
        "change_type": "spec",
        "change_id": change_id,
        "starting_commit_sha": base,
        "protected_class": "gate_evidence",
        "gate_id": "G1",
        "decision": "GO-PROPOSED",
        "evidence_bundle_sha256": evidence_hash,
        "review_subject_sha256": "0" * 64,
        "allowed_paths": changed,
        "budgets": {"max_changed_files": 11, "max_diff_lines": 3000},
    }
    zero_packet = json.dumps(packet, sort_keys=True, indent=2).encode() + b"\n"
    review_hash = GATE.length_prefixed_digest({**documents, packet_path: zero_packet})
    packet["review_subject_sha256"] = review_hash
    documents[packet_path] = json.dumps(packet, sort_keys=True, indent=2).encode() + b"\n"
    for path, data in documents.items():
        _write_candidate(repository, path, data)
    candidate = _commit_all(repository, "Propose G1")
    return (
        base,
        candidate,
        {
            "reviewed_commit_sha": candidate,
            "evidence_bundle_sha256": evidence_hash,
            "review_subject_sha256": review_hash,
            "promotion_subject_sha256": promotion_hash,
            "final": final,
        },
    )


def _review_candidate(
    repository: Path,
    role: str,
    proposal: Mapping[str, Any],
    *,
    tamper_note: bool = False,
    gate_id: str = "G1",
    verdict: str = "PASS",
) -> tuple[str, str]:
    base = _run_git(repository, "rev-parse", "HEAD")
    review_hash = proposal["review_subject_sha256"]
    directory = f"work/change-control/reviews/{gate_id}/{role}-{review_hash}"
    note_path = f"{directory}/review.md"
    receipt_path = f"{directory}/receipt.json"
    note = f"# {role}\n\nVerdict: {verdict}\n".encode()
    receipt = {
        "schema_version": "1.0.0",
        "change_type": "independent_review",
        "gate_id": gate_id,
        "role": role,
        "reviewer_identity": f"test-{role}",
        "reviewed_commit_sha": proposal["reviewed_commit_sha"],
        "evidence_bundle_sha256": proposal["evidence_bundle_sha256"],
        "review_subject_sha256": review_hash,
        "promotion_subject_sha256": proposal["promotion_subject_sha256"],
        "verdict": verdict,
        "source_ref": note_path,
        "source_ref_sha256": hashlib.sha256(note).hexdigest(),
    }
    _write_candidate(repository, note_path, note + (b"tampered\n" if tamper_note else b""))
    _write_candidate(repository, receipt_path, json.dumps(receipt, sort_keys=True).encode() + b"\n")
    return base, _commit_all(repository, f"Review G1 as {role}")


def _promotion_candidate(
    repository: Path, proposal: Mapping[str, Any], *, tamper: bool = False
) -> tuple[str, str]:
    base = _run_git(repository, "rev-parse", "HEAD")
    final = dict(proposal["final"])
    if tamper:
        final["docs/CONTEXT.md"] += b"tampered\n"
    for path, data in final.items():
        _write_candidate(repository, path, data)
    return base, _commit_all(repository, "Promote G1")


def _policy_amendment_proposal(repository: Path) -> tuple[str, str, dict[str, Any]]:
    base = _run_git(repository, "rev-parse", "HEAD")
    change_id = "CR-998"
    packet_path = f"work/change-control/{change_id}.yaml"
    manifest_path = f"work/change-control/amendments/{change_id}-manifest.json"
    target = "scripts/ci_policy.py"
    base_bytes = (repository / target).read_bytes()
    final_bytes = base_bytes + b"\n# exact reviewed policy amendment\n"
    changelog = (repository / "CHANGELOG.md").read_bytes() + b"\n- CR-998 amendment\n"
    decisions = (repository / "docs/DECISIONS.md").read_bytes() + b"\n## CR-998 amendment\n"
    evidence = {"CHANGELOG.md": changelog, "docs/DECISIONS.md": decisions}
    evidence_hash = GATE.length_prefixed_digest(evidence)
    promotion_hash = GATE.length_prefixed_digest({target: final_bytes})
    manifest = {
        "schema_version": "1.0.0",
        "gate_id": "POLICY",
        "evidence_bundle_sha256": evidence_hash,
        "promotion_subject_sha256": promotion_hash,
        "files": [
            {
                "path": target,
                "base_sha256": hashlib.sha256(base_bytes).hexdigest(),
                "final_sha256": hashlib.sha256(final_bytes).hexdigest(),
                "final_base64": GATE.base64.b64encode(final_bytes).decode(),
            }
        ],
    }
    documents = {
        **evidence,
        manifest_path: json.dumps(manifest, sort_keys=True).encode() + b"\n",
    }
    changed = sorted((*documents, packet_path))
    packet = {
        "schema_version": "1.0.0",
        "change_type": "policy_amendment",
        "change_id": change_id,
        "starting_commit_sha": base,
        "protected_class": "ci_evaluator",
        "gate_id": "POLICY",
        "decision": "CHANGE-PROPOSED",
        "evidence_bundle_sha256": evidence_hash,
        "review_subject_sha256": "0" * 64,
        "allowed_paths": changed,
        "budgets": {"max_changed_files": 4, "max_diff_lines": 6000},
    }
    zero_packet = json.dumps(packet, sort_keys=True, indent=2).encode() + b"\n"
    review_hash = GATE.length_prefixed_digest({**documents, packet_path: zero_packet})
    packet["review_subject_sha256"] = review_hash
    documents[packet_path] = json.dumps(packet, sort_keys=True, indent=2).encode() + b"\n"
    for path, data in documents.items():
        _write_candidate(repository, path, data)
    candidate = _commit_all(repository, "Propose policy amendment")
    return (
        base,
        candidate,
        {
            "reviewed_commit_sha": candidate,
            "evidence_bundle_sha256": evidence_hash,
            "review_subject_sha256": review_hash,
            "promotion_subject_sha256": promotion_hash,
            "final": {target: final_bytes},
        },
    )


def _policy_amendment_promotion(
    repository: Path, proposal: Mapping[str, Any], *, tamper: bool = False
) -> tuple[str, str]:
    base = _run_git(repository, "rev-parse", "HEAD")
    final = dict(proposal["final"])
    if tamper:
        final["scripts/ci_policy.py"] += b"# unreviewed\n"
    for path, data in final.items():
        _write_candidate(repository, path, data)
    return base, _commit_all(repository, "Promote policy amendment")


def _committed_errors(repository: Path, base: str, candidate: str) -> tuple[str, ...]:
    return cast(
        tuple[str, ...],
        GATE.SpecGate(
            root=repository,
            policy_path=GATE.POLICY_PATH,
            github_repository=("example", "repo"),
        ).validate_candidate("committed-candidate", base=base, candidate=candidate),
    )


def test_closed_candidate_lifecycle_accepts_exact_committed_chain(
    lifecycle_parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    monkeypatch.setattr(GATE.SpecGate, "validate_snapshot", lambda self: ())
    repository, _ = _clone_index_candidate(lifecycle_parent)
    for task_id in ("P1.4", "P1.13"):
        base, candidate = _complete_task(repository, task_id)
        assert _committed_errors(repository, base, candidate) == ()
    base, candidate, proposal = _proposal_candidate(repository)
    assert _committed_errors(repository, base, candidate) == ()
    for role in ("product_scope", "architecture_contracts", "security_evaluation"):
        base, candidate = _review_candidate(repository, role, proposal)
        assert _committed_errors(repository, base, candidate) == ()
    base, candidate = _promotion_candidate(repository, proposal)
    assert _committed_errors(repository, base, candidate) == ()
    stale_base, stale_candidate = _review_candidate(
        repository, "product_scope", proposal, tamper_note=True
    )
    gate = GATE.SpecGate(
        root=repository,
        policy_path=GATE.POLICY_PATH,
        github_repository=("example", "repo"),
    )
    stale_records = gate._diff_records("committed-candidate", stale_base, stale_candidate)
    assert "REVIEW_GATE_IMMUTABLE" in gate._review_errors(
        "committed-candidate",
        base=stale_base,
        candidate=stale_candidate,
        changed=GATE.changed_paths(stale_records),
        diff_lines=gate._diff_lines("committed-candidate", stale_base, stale_candidate),
        records=stale_records,
    )

    proposal_base, proposal_candidate, _ = _proposal_candidate(repository)
    records = gate._diff_records("committed-candidate", proposal_base, proposal_candidate)
    assert "CHANGE_PACKET_GATE_IMMUTABLE" in gate._proposal_errors(
        "committed-candidate",
        base=proposal_base,
        candidate=proposal_candidate,
        packet_path="work/change-control/CR-999.yaml",
        changed=GATE.changed_paths(records),
        diff_lines=gate._diff_lines("committed-candidate", proposal_base, proposal_candidate),
    )


def test_closed_candidate_lifecycle_rejects_cross_lane_bypasses(
    lifecycle_parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    monkeypatch.setattr(GATE.SpecGate, "validate_snapshot", lambda self: ())
    repository, implementation = _clone_index_candidate(lifecycle_parent)
    base, candidate = _complete_task(repository, "P1.4", evidence_repository="unrelated/repository")
    assert "ATTESTATION_EXTERNAL_REPOSITORY" in _committed_errors(repository, base, candidate)

    _run_git(repository, "switch", "--detach", implementation)
    for task_id in ("P1.4", "P1.13"):
        _complete_task(repository, task_id)
    completed = _run_git(repository, "rev-parse", "HEAD")
    base, candidate, _ = _proposal_candidate(repository, failed_check=True)
    assert "CHANGE_PACKET_CHECKLIST_RESULT" in _committed_errors(repository, base, candidate)

    _run_git(repository, "switch", "--detach", completed)
    base, candidate, proposal = _proposal_candidate(repository)
    assert _committed_errors(repository, base, candidate) == ()
    base, candidate = _review_candidate(repository, "product_scope", proposal, tamper_note=True)
    assert "REVIEW_SOURCE_HASH" in _committed_errors(repository, base, candidate)

    _run_git(repository, "switch", "--detach", proposal["reviewed_commit_sha"])
    for role in ("product_scope", "architecture_contracts"):
        base, candidate = _review_candidate(repository, role, proposal)
        assert _committed_errors(repository, base, candidate) == ()
    base, candidate = _promotion_candidate(repository, proposal, tamper=True)
    promotion_errors = _committed_errors(repository, base, candidate)
    assert "PROMOTION_FINAL_BYTES" in promotion_errors
    assert "PROMOTION_RECEIPT_SEPARATION" in promotion_errors
    assert "COMMITTED_CANDIDATE" in _committed_errors(
        repository, base, proposal["reviewed_commit_sha"]
    )


def test_policy_amendment_requires_proposal_three_reviews_and_exact_promotion(
    lifecycle_parent: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    monkeypatch.setattr(GATE.SpecGate, "validate_snapshot", lambda self: ())
    repository, _ = _clone_index_candidate(lifecycle_parent)
    base, candidate, proposal = _policy_amendment_proposal(repository)
    assert _committed_errors(repository, base, candidate) == ()
    for role in ("product_scope", "architecture_contracts", "security_evaluation"):
        base, candidate = _review_candidate(repository, role, proposal, gate_id="POLICY")
        assert _committed_errors(repository, base, candidate) == ()
    base, candidate = _policy_amendment_promotion(repository, proposal)
    assert _committed_errors(repository, base, candidate) == ()


@pytest.mark.parametrize("failure", ["missing-review", "block-review", "tampered-bytes"])
def test_policy_amendment_rejects_incomplete_blocked_or_tampered_promotion(
    lifecycle_parent: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    monkeypatch.setattr(GATE.SpecGate, "validate_snapshot", lambda self: ())
    repository, _ = _clone_index_candidate(lifecycle_parent)
    _, _, proposal = _policy_amendment_proposal(repository)
    roles = ("product_scope", "architecture_contracts", "security_evaluation")
    for index, role in enumerate(roles):
        if failure == "missing-review" and index == 2:
            break
        _review_candidate(
            repository,
            role,
            proposal,
            gate_id="POLICY",
            verdict="BLOCK" if failure == "block-review" and index == 2 else "PASS",
        )
    base, candidate = _policy_amendment_promotion(
        repository, proposal, tamper=failure == "tampered-bytes"
    )
    errors = _committed_errors(repository, base, candidate)
    expected = {
        "missing-review": "POLICY_PROMOTION_RECEIPT_ROLES",
        "block-review": "POLICY_PROMOTION_RECEIPT_VERDICT",
        "tampered-bytes": "POLICY_PROMOTION_FINAL_BYTES",
    }[failure]
    assert expected in errors


def _staged_implementation_candidate(repository: Path) -> tuple[str, dict[str, Any]]:
    repository.mkdir()
    _run_git(repository, "init", "-b", "master")
    _run_git(repository, "config", "user.name", "Spec Gate Test")
    _run_git(repository, "config", "user.email", "spec-gate@example.invalid")
    _run_git(repository, "config", "core.autocrlf", "false")
    (repository / "README.md").write_bytes(b"base\n")
    _run_git(repository, "add", "--", "README.md")
    _run_git(repository, "commit", "-m", "base")
    base = _run_git(repository, "rev-parse", "HEAD")
    packet_path = "work/task-packets/P2.1.yaml"
    allowed = ["README.md", packet_path]
    packet = {
        "schema_version": "0.1-draft",
        "task": {
            "id": "P2.1",
            "type": "implementation",
            "baseline_id": "securecode-definition-0.2.0",
            "baseline_content_sha256": (
                "dedb43be8ba055dfa47858b975630b4c870af3bed2dda842b0e8422c8354b5c9"
            ),
            "baseline_commit_sha": "f5cd4ef2a0f7130d16cb2c206091908be71b0702",
            "starting_commit_sha": base,
        },
        "execution": {"exclusive_path_lease": allowed},
        "scope": {
            "allowed_paths": allowed,
            "forbidden_paths": ["specs/**"],
            "max_changed_files": 2,
            "max_diff_lines": 1000,
        },
    }
    packet_file = repository / packet_path
    packet_file.parent.mkdir(parents=True)
    packet_file.write_bytes(json.dumps(packet, sort_keys=True).encode() + b"\n")
    (repository / "README.md").write_bytes(b"candidate\n")
    _run_git(repository, "add", "--", "README.md", packet_path)
    return base, packet


def test_index_candidate_dispatch_accepts_one_closed_implementation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    repository = tmp_path / "candidate"
    base, _ = _staged_implementation_candidate(repository)
    monkeypatch.setattr(GATE.SpecGate, "validate_snapshot", lambda self: ())
    gate = GATE.SpecGate(root=repository, policy_path=GATE.POLICY_PATH)
    assert gate.validate_candidate("index-candidate", base=base, candidate=None) == ()


def test_index_candidate_rejects_unstaged_and_mixed_candidate_kinds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    repository = tmp_path / "unstaged"
    base, _ = _staged_implementation_candidate(repository)
    monkeypatch.setattr(GATE.SpecGate, "validate_snapshot", lambda self: ())
    (repository / "README.md").write_bytes(b"unstaged\n")
    gate = GATE.SpecGate(root=repository, policy_path=GATE.POLICY_PATH)
    assert "INDEX_UNSTAGED" in gate.validate_candidate("index-candidate", base=base, candidate=None)

    repository = tmp_path / "mixed"
    base, packet = _staged_implementation_candidate(repository)
    attestation_path = "work/task-attestations/P1.4.json"
    attestation = repository / attestation_path
    attestation.parent.mkdir(parents=True)
    attestation.write_bytes(b"{}\n")
    packet["execution"]["exclusive_path_lease"].append(attestation_path)
    packet["scope"]["allowed_paths"].append(attestation_path)
    packet["scope"]["max_changed_files"] = 3
    (repository / "work/task-packets/P2.1.yaml").write_bytes(
        json.dumps(packet, sort_keys=True).encode() + b"\n"
    )
    _run_git(
        repository,
        "add",
        "--",
        "work/task-packets/P2.1.yaml",
        attestation_path,
    )
    gate = GATE.SpecGate(root=repository, policy_path=GATE.POLICY_PATH)
    assert "CANDIDATE_KIND_AMBIGUOUS" in gate.validate_candidate(
        "index-candidate", base=base, candidate=None
    )


@pytest.mark.parametrize("mode_value", ["120000", "160000", "100644"])
def test_git_mode_validation_rejects_links_submodules_and_intent_to_add(
    mode_value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    object_id = "0" * 40 if mode_value == "100644" else "a" * 40

    def fake_git_bytes(root: Path, *arguments: str) -> bytes:
        assert arguments[0] == "ls-files"
        return f"{mode_value} {object_id} 0\tpath\0".encode()

    monkeypatch.setattr(GATE, "git_bytes", fake_git_bytes)
    gate = GATE.SpecGate()
    with pytest.raises(GATE.GateInputError):
        gate._validate_git_modes(
            "index-candidate",
            base="b" * 40,
            candidate=None,
            records=(("A", "path"),),
        )


def test_cli_exception_receipt_is_fixed_and_non_echo(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def fail() -> None:
        raise ValueError(CANARY)

    monkeypatch.setattr(GATE.SpecGate, "validate_snapshot", lambda self: fail())
    assert GATE.main(["snapshot"]) == 1
    rendered = capsys.readouterr().err
    assert "INTERNAL_FAILURE" in rendered
    assert CANARY not in rendered


@pytest.mark.parametrize(
    "arguments",
    [
        [CANARY],
        ["snapshot", f"--{CANARY}"],
        ["index-candidate", "--base"],
    ],
)
def test_cli_argument_failures_are_fixed_and_non_echo(
    arguments: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert GATE.main(arguments) == 1
    rendered = capsys.readouterr().err
    assert rendered == "SPEC_GATE=FAIL mode=unknown errors=1 codes=CLI_ARGUMENTS\n"
    assert CANARY not in rendered


def test_policy_and_bootstrap_packet_hash_are_independent() -> None:
    gate = GATE.SpecGate()
    packet = (REPOSITORY_ROOT / "work/task-packets/P1.13.yaml").read_bytes()
    assert gate.policy["bootstrap_packet_sha256"] == GATE.hashlib.sha256(packet).hexdigest()
    assert set(gate.policy["test_catalog"]) != set(
        yaml.safe_load((REPOSITORY_ROOT / "specs/traceability/requirements.yaml").read_text())
    )


def test_strict_json_round_trip_never_uses_raw_exception_text() -> None:
    payload = json.dumps({"x": CANARY}).encode() + b" trailing"
    with pytest.raises(GATE.GateInputError) as caught:
        GATE.strict_json_loads(payload, _limits())
    assert CANARY not in str(caught.value)
