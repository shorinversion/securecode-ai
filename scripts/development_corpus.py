"""Fail-closed admission and Docker oracle runner for the P7.6 corpus.

The corpus files are untrusted data. This module reads bytes and parses JSON
metadata only during normal validation; it never imports, compiles, or executes
corpus source or oracle code on the host. The explicit Docker mode executes the
oracle in a pinned, no-network, read-only, resource-bounded container.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, cast

REQUIRED_STRATA = frozenset(
    {"vulnerable", "fixed-safe", "guard-counterevidence", "inter-file", "zero-scanner"}
)
ROOT_KEYS = frozenset(
    {
        "acquisition",
        "case_count",
        "cases",
        "content_identity",
        "corpus_content_sha256",
        "corpus_id",
        "exclusions",
        "frozen_case_ids",
        "ground_truth_status",
        "label_stratum_invariants",
        "license",
        "lineage_groups",
        "oracle",
        "purpose",
        "scanner",
        "schema_version",
        "split",
        "version",
    }
)
CASE_KEYS = frozenset(
    {
        "case_content_sha256",
        "case_id",
        "exclusions",
        "expected_label",
        "ground_truth_status",
        "language",
        "lineage_group",
        "origin",
        "root_cause_group",
        "scanner_receipt",
        "security_semantics",
        "sources",
        "split",
        "strata",
    }
)
SOURCE_KEYS = frozenset({"git_blob_sha1", "path", "sha256"})
ORACLE_KEYS = frozenset({"execution", "path", "rules_path", "rules_sha256", "sha256"})
SHA256_LENGTH = 64
DOCKER_IMAGE = "python@sha256:e16ab55c341bfd0e7da665bc2d48939cff890b43a41867fe6e1f0690638ceb7c"
DOCKER_TIMEOUT_SECONDS = 60
DOCKER_CLEANUP_TIMEOUT_SECONDS = 10


class CorpusValidationError(ValueError):
    """A closed admission failure for untrusted corpus metadata or bytes."""


def _fail(message: str) -> None:
    raise CorpusValidationError(message)


def _no_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _canonical_sha256(value: object) -> str:
    return _sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    )


def _mapping(value: object, name: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{name} must be an object")
    return cast(dict[str, Any], value)


def _list(value: object, name: str) -> list[Any]:
    if type(value) is not list:
        _fail(f"{name} must be an array")
    return cast(list[Any], value)


def _string(value: object, name: str) -> str:
    if type(value) is not str or not value:
        _fail(f"{name} must be a non-empty string")
    return cast(str, value)


def _digest(value: object, name: str) -> str:
    result = _string(value, name)
    prefix = "sha256:"
    digest = result.removeprefix(prefix)
    if (
        not result.startswith(prefix)
        or len(digest) != SHA256_LENGTH
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        _fail(f"{name} must be a typed lowercase SHA-256 digest")
    return digest


def _git_digest(value: object, name: str) -> str:
    result = _string(value, name)
    prefix = "sha1:"
    digest = result.removeprefix(prefix)
    if (
        not result.startswith(prefix)
        or len(digest) != 40
        or any(char not in "0123456789abcdef" for char in digest)
    ):
        _fail(f"{name} must be a typed lowercase Git blob SHA-1")
    return digest


def _exact_keys(value: dict[str, Any], keys: frozenset[str], name: str) -> None:
    if set(value) != keys:
        _fail(f"{name} keys are not closed")


def _json_object(path: Path, name: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_object)
    except CorpusValidationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CorpusValidationError(f"{name} is unreadable or non-canonical JSON YAML") from error
    return _mapping(value, name)


def _corpus_file(root: Path, relative_path: str, name: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts or candidate.parts[:1] != ("corpus",):
        _fail(f"{name} escapes the corpus root")
    corpus_root = (root / "corpus").resolve(strict=True)
    resolved = (root / candidate).resolve(strict=True)
    if corpus_root not in resolved.parents or not resolved.is_file():
        _fail(f"{name} is not a corpus regular file")
    return resolved


def _load_rules(root: Path, oracle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    _exact_keys(oracle, ORACLE_KEYS, "oracle")
    if (
        oracle.get("execution")
        != "docker-only-credential-free-network-none-read-only-resource-bounded"
    ):
        _fail("oracle execution boundary is invalid")
    oracle_path = _corpus_file(root, _string(oracle.get("path"), "oracle.path"), "oracle path")
    if _sha256(oracle_path.read_bytes()) != _digest(oracle.get("sha256"), "oracle.sha256"):
        _fail("oracle hash drift")
    rules_path = _corpus_file(
        root, _string(oracle.get("rules_path"), "oracle.rules_path"), "rules path"
    )
    if _sha256(rules_path.read_bytes()) != _digest(
        oracle.get("rules_sha256"), "oracle.rules_sha256"
    ):
        _fail("oracle rules hash drift")
    document = _json_object(rules_path, "oracle rules")
    if set(document) != {"schema_version", "rules"} or document.get("schema_version") != "2.0":
        _fail("oracle rules schema is invalid")
    raw_rules = _mapping(document.get("rules"), "oracle rules entries")
    rules: dict[str, dict[str, Any]] = {}
    for case_id, raw_rule in raw_rules.items():
        if type(case_id) is not str:
            _fail("oracle rule identity is invalid")
        rule = _mapping(raw_rule, f"oracle rule {case_id}")
        _exact_keys(
            rule,
            frozenset({"probes", "security_property", "source_path"}),
            f"oracle rule {case_id}",
        )
        _string(rule.get("security_property"), "oracle security property")
        _corpus_file(
            root, _string(rule.get("source_path"), "oracle source path"), "oracle source path"
        )
        probes = _list(rule.get("probes"), "oracle probes")
        if not probes:
            _fail("oracle probes are missing")
        for raw_probe in probes:
            probe = _mapping(raw_probe, "oracle probe")
            if set(probe) != {"call", "secure_assertion"}:
                _fail("oracle probe keys are invalid")
            call = _mapping(probe.get("call"), "oracle call")
            if set(call) != {"entrypoint", "arguments"} or type(call.get("arguments")) is not list:
                _fail("oracle call is invalid")
            _string(call.get("entrypoint"), "oracle entrypoint")
            assertion = _mapping(probe.get("secure_assertion"), "oracle secure assertion")
            if assertion.get("kind") not in {
                "contains",
                "db_bound_input",
                "db_parameterized",
                "db_query_contains",
                "db_query_excludes",
                "equals",
                "inside_root_or_none",
                "outside_root",
                "shell_safe",
                "shell_plan_contains",
            }:
                _fail("oracle assertion kind is invalid")
            if set(assertion) not in ({"kind"}, {"kind", "expected"}):
                _fail("oracle assertion keys are invalid")
        rules[case_id] = rule
    return rules


def load_manifest(path: Path) -> dict[str, Any]:
    return _json_object(path, "manifest")


def validate_manifest(path: Path, *, verify_tree_hash: bool = True) -> str:
    manifest_path = path.resolve(strict=True)
    manifest = load_manifest(manifest_path)
    _exact_keys(manifest, ROOT_KEYS, "manifest")
    if (
        manifest.get("schema_version") != "2.0"
        or manifest.get("split") != "development"
        or manifest.get("license") != "CC0-1.0"
        or manifest.get("case_count") != 24
        or manifest.get("ground_truth_status") != "behavioral-property-rule-independently-reviewed"
    ):
        _fail("manifest identity is invalid")
    root = manifest_path.parent
    if (
        _string(manifest.get("corpus_id"), "corpus ID") != "securecode-development-educational-v1"
        or _string(manifest.get("version"), "version") != "1.0.0-candidate"
    ):
        _fail("manifest corpus identity is invalid")
    acquisition = _mapping(manifest.get("acquisition"), "acquisition")
    if (
        set(acquisition) != {"external_acquisition", "instructions", "source_revision"}
        or acquisition.get("source_revision") != "self-authored-v1"
    ):
        _fail("acquisition metadata is invalid")
    _string(acquisition.get("external_acquisition"), "external acquisition")
    _string(acquisition.get("instructions"), "acquisition instructions")
    exclusions = _list(manifest.get("exclusions"), "manifest exclusions")
    if len(exclusions) != 2 or any(type(item) is not str for item in exclusions):
        _fail("manifest exclusions are invalid")
    identity = _mapping(manifest.get("content_identity"), "content identity")
    if identity != {
        "starting_git_commit": ("git:72a9490787c1d317bc88290983d88997af0670f3"),
        "git_blob_algorithm": "sha1",
        "content_hash_algorithm": "sha256",
    }:
        _fail("content Git identity is invalid")
    scanner_identity = _mapping(manifest.get("scanner"), "scanner identity")
    if (
        set(scanner_identity) != {"receipt_mode", "scanner_id", "scope"}
        or scanner_identity.get("scanner_id") != "securecode-python-cwe89@1.0"
    ):
        _fail("scanner identity is invalid")
    _string(manifest.get("purpose"), "purpose")
    oracle = _mapping(manifest.get("oracle"), "oracle")
    rules = _load_rules(root, oracle)
    cases = _list(manifest.get("cases"), "cases")
    frozen_case_ids = _list(manifest.get("frozen_case_ids"), "frozen case IDs")
    if (
        len(cases) != 24
        or len(frozen_case_ids) != 24
        or any(type(item) is not str for item in frozen_case_ids)
    ):
        _fail("development corpus must freeze exactly 24 cases")
    if manifest.get("lineage_groups") != [
        "lineage-authz-v1",
        "lineage-path-v1",
        "lineage-sql-v1",
        "lineage-command-v1",
    ]:
        _fail("lineage membership is invalid")
    if manifest.get("label_stratum_invariants") != {
        "vulnerable_requires": "vulnerable",
        "safe_requires_one_of": ["fixed-safe", "guard-counterevidence"],
        "inter_file_requires_multiple_sources": True,
        "zero_scanner_requires_applicable_completed_zero": True,
        "lineage_split_must_be_development_only": True,
    }:
        _fail("label-stratum invariants are invalid")
    identities: set[str] = set()
    case_ids: list[str] = []
    source_trees: set[tuple[tuple[str, str], ...]] = set()
    case_digests: list[dict[str, str]] = []
    for index, raw_case in enumerate(cases):
        case = _mapping(raw_case, f"cases[{index}]")
        _exact_keys(case, CASE_KEYS, f"cases[{index}]")
        case_id = _string(case.get("case_id"), "case ID")
        if case_id in identities:
            _fail("duplicate case identity")
        identities.add(case_id)
        case_ids.append(case_id)
        if case.get("split") != "development" or case.get("language") != "python":
            _fail("case scope is invalid")
        lineage = _string(case.get("lineage_group"), "lineage group")
        if lineage not in manifest["lineage_groups"] or case.get("root_cause_group") != lineage:
            _fail("case lineage is invalid")
        strata = _list(case.get("strata"), "case strata")
        if (
            not strata
            or any(type(item) is not str or item not in REQUIRED_STRATA for item in strata)
            or len(set(strata)) != len(strata)
        ):
            _fail("case strata are invalid")
        rule = rules.get(case_id)
        if rule is None:
            _fail("case has no oracle rule")
        assert rule is not None
        label = case.get("expected_label")
        if label == "vulnerable":
            if "vulnerable" not in strata:
                _fail("vulnerable label semantics are invalid")
        elif label == "safe":
            if not {"fixed-safe", "guard-counterevidence"}.intersection(strata):
                _fail("safe label semantics are invalid")
        else:
            _fail("case label is invalid")
        if case.get("ground_truth_status") != manifest["ground_truth_status"]:
            _fail("ground truth status is invalid")
        origin = _mapping(case.get("origin"), "origin")
        if (
            set(origin) != {"acquisition", "kind", "license", "provenance", "revision"}
            or origin.get("kind") != "self-authored-educational"
            or origin.get("license") != "CC0-1.0"
            or origin.get("revision") != "self-authored-v1"
        ):
            _fail("case provenance is unresolved")
        _string(origin.get("acquisition"), "origin acquisition")
        _string(origin.get("provenance"), "origin provenance")
        exclusions = _list(case.get("exclusions"), "case exclusions")
        if len(exclusions) != 1 or any(type(item) is not str for item in exclusions):
            _fail("case exclusions are invalid")
        semantics = _mapping(case.get("security_semantics"), "security semantics")
        if (
            set(semantics) != {"policy_invariant", "sink", "untrusted_source"}
            or semantics.get("policy_invariant") != rule["security_property"]
        ):
            _fail("case security semantics are invalid")
        _string(semantics.get("sink"), "security sink")
        _string(semantics.get("untrusted_source"), "security source")
        raw_sources = _list(case.get("sources"), "case sources")
        if not raw_sources:
            _fail("case sources are missing")
        source_paths: set[str] = set()
        sources: list[dict[str, str]] = []
        for raw_source in raw_sources:
            source = _mapping(raw_source, "source")
            _exact_keys(source, SOURCE_KEYS, "source")
            source_path = _string(source.get("path"), "source path")
            if source_path in source_paths:
                _fail("duplicate source identity")
            source_paths.add(source_path)
            data = _corpus_file(root, source_path, "source path").read_bytes()
            if _sha256(data) != _digest(source.get("sha256"), "source hash") or _git_blob_sha1(
                data
            ) != _git_digest(source.get("git_blob_sha1"), "source Git blob"):
                _fail("source identity drift")
            sources.append({"path": source_path, "sha256": source["sha256"]})
        if rule["source_path"] not in source_paths:
            _fail("oracle source is not a case source")
        if "inter-file" in strata and len(sources) < 2:
            _fail("inter-file case lacks multiple sources")
        scanner = _mapping(case.get("scanner_receipt"), "scanner receipt")
        if (
            set(scanner)
            != {
                "applicability",
                "basis",
                "completion",
                "expected_signal_count",
                "observed_signal_count",
                "scanner_id",
                "scanner_source_path",
            }
            or scanner.get("scanner_id") != "securecode-python-cwe89@1.0"
            or scanner.get("scanner_source_path") not in source_paths
        ):
            _fail("scanner receipt identity is invalid")
        applicable = scanner.get("applicability") == "applicable"
        if applicable != (lineage == "lineage-sql-v1") or type(scanner.get("basis")) is not str:
            _fail("scanner applicability is invalid")
        if applicable:
            if (
                scanner.get("completion") != "completed"
                or any(
                    type(scanner.get(field)) is not int or scanner[field] < 0
                    for field in ("expected_signal_count", "observed_signal_count")
                )
                or scanner["expected_signal_count"] != scanner["observed_signal_count"]
            ):
                _fail("applicable scanner receipt is invalid")
        elif (
            scanner.get("applicability") != "not-applicable"
            or scanner.get("completion") != "not-run-not-applicable"
            or scanner.get("expected_signal_count") is not None
            or scanner.get("observed_signal_count") is not None
        ):
            _fail("non-applicable scanner receipt is invalid")
        if "zero-scanner" in strata and (not applicable or scanner["observed_signal_count"] != 0):
            _fail("zero-scanner stratum is not an applicable completed zero")
        case_payload = {key: value for key, value in case.items() if key != "case_content_sha256"}
        expected_case_digest = _canonical_sha256(
            {"case": case_payload, "oracle": {**oracle, "rule": rule}}
        )
        if _digest(case.get("case_content_sha256"), "case digest") != expected_case_digest:
            _fail("case semantic digest drift")
        source_tree = tuple(sorted((source["path"], source["sha256"]) for source in sources))
        if source_tree in source_trees:
            _fail("duplicate source tree identity")
        source_trees.add(source_tree)
        case_digests.append({"case_id": case_id, "case_content_sha256": expected_case_digest})
    if case_ids != frozen_case_ids or set(rules) != identities:
        _fail("frozen case membership is invalid")
    if not any(
        _mapping(case["scanner_receipt"], "scanner receipt")["observed_signal_count"] > 0
        for case in cases
        if _mapping(case["scanner_receipt"], "scanner receipt")["applicability"] == "applicable"
    ):
        _fail("scanner has no nonzero positive control")
    corpus_payload = {
        "manifest": {
            key: value
            for key, value in manifest.items()
            if key not in {"cases", "corpus_content_sha256"}
        },
        "cases": case_digests,
    }
    corpus_digest = _canonical_sha256(corpus_payload)
    if (
        verify_tree_hash
        and _digest(manifest.get("corpus_content_sha256"), "corpus digest") != corpus_digest
    ):
        _fail("corpus semantic digest drift")
    return f"sha256:{corpus_digest}"


def _normal(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if type(value) is dict:
        return {str(key): _normal(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normal(item) for item in value]
    return value


def _assertion(value: object, assertion: dict[str, Any]) -> bool:
    kind = assertion.get("kind")
    expected = assertion.get("expected")
    normal = _normal(value)
    if kind == "equals":
        return normal == expected
    if kind == "inside_root_or_none":
        return normal is None or (
            type(normal) is str
            and Path(normal).resolve().is_relative_to(Path("/sandbox/root").resolve())
        )
    if kind == "db_query_excludes":
        return (
            type(normal) is dict
            and type(normal.get("query")) is str
            and type(expected) is str
            and expected not in normal["query"]
        )
    if kind == "db_bound_input":
        return (
            type(normal) is dict
            and type(normal.get("query")) is str
            and "?" in normal["query"]
            and type(normal.get("parameters")) is list
            and normal["parameters"] == [expected]
            and type(expected) is str
            and expected not in normal["query"]
        )
    if kind == "db_parameterized":
        return type(normal) is dict and normal == expected
    if kind == "shell_safe":
        return (
            type(normal) is dict
            and normal.get("shell") is False
            and type(normal.get("args")) is list
            and type(expected) is str
            and normal["args"].count(expected) == 1
            and "sh" not in normal["args"]
            and "-c" not in normal["args"]
        )
    raise CorpusValidationError("oracle assertion kind is unavailable")


def _cleanup_timed_out_container(container_name: str) -> None:
    try:
        cleanup = subprocess.run(
            ["docker", "rm", "-f", container_name],
            check=False,
            capture_output=True,
            text=True,
            timeout=DOCKER_CLEANUP_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise CorpusValidationError("Docker oracle timeout cleanup failed") from error
    if cleanup.returncode != 0:
        raise CorpusValidationError("Docker oracle timeout cleanup failed")


def run_oracle_in_docker(
    root: Path,
    source_paths: list[str],
    primary_source_path: str,
    call: dict[str, Any],
) -> object:
    """Return one closed worker observation without mounting rules or manifest."""
    development_root = root.resolve(strict=True)
    if not development_root.is_dir() or primary_source_path not in source_paths:
        _fail("Docker oracle source set is invalid")
    worker = _corpus_file(development_root, "corpus/oracle.py", "oracle worker")
    primary = _corpus_file(development_root, primary_source_path, "primary source")
    mounts = [
        "--mount",
        f"type=bind,src={worker},dst=/worker/oracle.py,readonly",
        "--mount",
        f"type=bind,src={primary},dst=/case/case.py,readonly",
    ]
    for path in source_paths:
        if path == primary_source_path:
            continue
        auxiliary = _corpus_file(development_root, path, "auxiliary source")
        if auxiliary.name != "support.py":
            _fail("Docker oracle auxiliary source is invalid")
        mounts.extend(["--mount", f"type=bind,src={auxiliary},dst=/case/support.py,readonly"])
    arguments = call.get("arguments")
    entrypoint = call.get("entrypoint")
    if type(arguments) is not list or type(entrypoint) is not str:
        _fail("Docker oracle call is invalid")
    entrypoint_text = _string(entrypoint, "Docker oracle entrypoint")
    container_name = f"securecode-p76-oracle-{uuid.uuid4().hex}"
    command = [
        "docker",
        "run",
        "--pull",
        "never",
        "--rm",
        "--name",
        container_name,
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "128m",
        "--cpus",
        "0.5",
        "--user",
        "65534:65534",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
        *mounts,
        "--workdir",
        "/case",
        DOCKER_IMAGE,
        "python",
        "/worker/oracle.py",
        "--source",
        "/case/case.py",
        "--entrypoint",
        entrypoint_text,
        "--arguments-json",
        json.dumps(arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=DOCKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        _cleanup_timed_out_container(container_name)
        raise CorpusValidationError("Docker oracle timed out and was terminated") from error
    lines = completed.stdout.splitlines()
    if completed.returncode != 0 or completed.stderr or len(lines) != 1:
        _fail("Docker oracle did not return one closed observation")
    frame = lines[0]
    prefix = "SECURECODE_ORACLE_OBSERVATION_V1:"
    if not frame.startswith(prefix):
        _fail("Docker oracle observation frame is invalid")
    try:
        observation = json.loads(frame.removeprefix(prefix), object_pairs_hook=_no_duplicate_object)
    except (CorpusValidationError, json.JSONDecodeError) as error:
        raise CorpusValidationError("Docker oracle observation is invalid") from error
    observation = _mapping(observation, "Docker oracle observation")
    if set(observation) != {"observation"}:
        _fail("Docker oracle observation keys are invalid")
    return observation["observation"]


def verify_oracles_in_docker(manifest_path: Path) -> dict[str, str]:
    """Evaluate host-retained rules, then cross-check labels only after outcomes."""
    validate_manifest(manifest_path)
    manifest = load_manifest(manifest_path.resolve(strict=True))
    root = manifest_path.parent
    rules = _load_rules(root, _mapping(manifest.get("oracle"), "oracle"))
    outcomes: dict[str, str] = {}
    labels: dict[str, str] = {}
    for raw_case in _list(manifest.get("cases"), "cases"):
        case = _mapping(raw_case, "case")
        case_id = _string(case.get("case_id"), "case ID")
        labels[case_id] = _string(case.get("expected_label"), "case label")
        rule = rules[case_id]
        source_paths = [
            _string(_mapping(item, "source").get("path"), "source path")
            for item in _list(case.get("sources"), "case sources")
        ]
        probes = _list(rule.get("probes"), "oracle probes")
        secure = True
        for raw_probe in probes:
            probe = _mapping(raw_probe, "oracle probe")
            observation = run_oracle_in_docker(
                root,
                source_paths,
                _string(rule.get("source_path"), "oracle source path"),
                _mapping(probe.get("call"), "oracle call"),
            )
            secure = secure and _assertion(
                observation, _mapping(probe.get("secure_assertion"), "oracle assertion")
            )
        outcomes[case_id] = "SECURE_PASS" if secure else "VIOLATION_CONFIRMED"
    expected = {
        case_id: "SECURE_PASS" if label == "safe" else "VIOLATION_CONFIRMED"
        for case_id, label in labels.items()
    }
    if outcomes != expected:
        _fail("Docker oracle outcomes do not cross-check manifest labels")
    return outcomes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest", type=Path, default=Path("evaluation/development/corpus-manifest.yaml")
    )
    parser.add_argument("--print-tree-hash", action="store_true")
    parser.add_argument("--verify-oracles-docker", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        if arguments.verify_oracles_docker:
            if arguments.print_tree_hash:
                _fail("Docker verification and tree-hash output are mutually exclusive")
            verify_oracles_in_docker(arguments.manifest)
            print("DEVELOPMENT_ORACLES=PASS")
            return 0
        digest = validate_manifest(
            arguments.manifest, verify_tree_hash=not arguments.print_tree_hash
        )
    except (CorpusValidationError, OSError):
        print("DEVELOPMENT_CORPUS=FAIL", file=sys.stderr)
        return 1
    print(digest if arguments.print_tree_hash else "DEVELOPMENT_CORPUS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
