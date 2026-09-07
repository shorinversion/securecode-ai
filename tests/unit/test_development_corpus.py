"""Data-only admission tests for the P7.6 development corpus."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from securecode_ai.adapters import analyze_python_ast, build_python_symbol_index, scan_python_cwe89

ROOT = Path(__file__).resolve().parents[2]
DEVELOPMENT_ROOT = ROOT / "evaluation" / "development"
MODULE_PATH = ROOT / "scripts" / "development_corpus.py"
SPEC = importlib.util.spec_from_file_location("development_corpus", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
ORIGINAL_POPEN = subprocess.Popen


def _copied_manifest(tmp_path: Path) -> Path:
    copied = tmp_path / "development"
    shutil.copytree(
        DEVELOPMENT_ROOT, copied, ignore=shutil.ignore_patterns(".pytest-*", "__pycache__")
    )
    return copied / "corpus-manifest.yaml"


def _read(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _write(path: Path, value: dict[str, object]) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )


def test_frozen_corpus_recomputes_transitive_semantic_digest() -> None:
    manifest = DEVELOPMENT_ROOT / "corpus-manifest.yaml"

    assert (
        MODULE.validate_manifest(manifest)
        == "sha256:c36050f7afde64aa33e11cd9f4b2db684b66ec4de7bcdffb2fb1a781f7bd550e"
    )


def test_host_admission_is_data_only_and_never_imports_oracle_or_case_source() -> None:
    validator = MODULE_PATH.read_text(encoding="utf-8")
    oracle = (DEVELOPMENT_ROOT / "corpus" / "oracle.py").read_text(encoding="utf-8")

    assert "importlib" not in validator
    assert "compile(" not in validator
    assert "expected_label" not in oracle


def test_exact_cwe89_scanner_receipts_are_static_data_only_facts() -> None:
    manifest = _read(DEVELOPMENT_ROOT / "corpus-manifest.yaml")
    cases = manifest["cases"]
    assert type(cases) is list
    positive_controls = 0
    for case in cases:
        assert type(case) is dict
        receipt = case["scanner_receipt"]
        assert type(receipt) is dict
        if receipt["applicability"] == "not-applicable":
            continue
        source_path = receipt["scanner_source_path"]
        assert type(source_path) is str
        source = (DEVELOPMENT_ROOT / source_path).read_bytes()
        index = build_python_symbol_index(
            repository_id="p7-development-corpus",
            revision="a" * 40,
            path=source_path,
            content_sha256=hashlib.sha256(source).hexdigest(),
            source=source,
        )
        result = scan_python_cwe89(index, analyze_python_ast(index))
        assert (
            len(result.signals)
            == receipt["expected_signal_count"]
            == receipt["observed_signal_count"]
        )
        positive_controls += len(result.signals)
    assert positive_controls > 0


@pytest.mark.parametrize(
    "mutator",
    (
        lambda manifest, copied: (
            copied / "corpus" / "authz" / "direct_object_reference.py"
        ).write_bytes(b"drift\n"),
        lambda manifest, copied: manifest["cases"][0]["origin"].pop("license"),
        lambda manifest, copied: manifest["cases"].append(manifest["cases"][0]),
        lambda manifest, copied: manifest["cases"][0]["sources"][0].update(
            {"path": "../outside.py"}
        ),
        lambda manifest, copied: manifest["cases"][0].update({"split": "locked-test"}),
        lambda manifest, copied: manifest["cases"][0]["scanner_receipt"].update(
            {"observed_signal_count": 1}
        ),
        lambda manifest, copied: manifest.update({"unexpected": "key"}),
    ),
    ids=(
        "hash-drift",
        "missing-license",
        "duplicate-case",
        "path-escape",
        "split-leakage",
        "scanner-drift",
        "extra-key",
    ),
)
def test_validator_rejects_metadata_and_identity_drift(tmp_path: Path, mutator: object) -> None:
    manifest_path = _copied_manifest(tmp_path)
    manifest = _read(manifest_path)
    assert callable(mutator)
    mutator(manifest, manifest_path.parent)
    _write(manifest_path, manifest)

    with pytest.raises(MODULE.CorpusValidationError):
        MODULE.validate_manifest(manifest_path)


def test_validator_rejects_duplicate_json_key(tmp_path: Path) -> None:
    manifest_path = _copied_manifest(tmp_path)
    text = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        text.replace('"case_count": 24,', '"case_count": 24,"case_count": 24,', 1), encoding="utf-8"
    )

    with pytest.raises(MODULE.CorpusValidationError, match="duplicate JSON key"):
        MODULE.validate_manifest(manifest_path)


def test_docker_timeout_requires_successful_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []

    def fake_file(_: Path, path: str, __: str) -> Path:
        return tmp_path / Path(path).name

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if len(commands) == 1:
            raise subprocess.TimeoutExpired(command, MODULE.DOCKER_TIMEOUT_SECONDS)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(MODULE, "_corpus_file", fake_file)
    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)

    with pytest.raises(MODULE.CorpusValidationError, match="timed out and was terminated"):
        MODULE.run_oracle_in_docker(
            tmp_path,
            ["corpus/sql/concat_query.py"],
            "corpus/sql/concat_query.py",
            {"entrypoint": "lookup", "arguments": []},
        )

    run_command, cleanup_command = commands
    assert run_command[0:4] == ["docker", "run", "--pull", "never"]
    assert MODULE.DOCKER_IMAGE in run_command
    assert not any("dst=/corpus" in item for item in run_command)
    assert not any("manifest" in item or "oracle-rules" in item for item in run_command)
    assert any("dst=/worker/oracle.py" in item for item in run_command)
    assert any("dst=/case/case.py" in item for item in run_command)
    container_name = run_command[run_command.index("--name") + 1]
    assert cleanup_command == ["docker", "rm", "-f", container_name]


def test_docker_timeout_fails_when_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = 0

    def fake_file(_: Path, path: str, __: str) -> Path:
        return tmp_path / Path(path).name

    def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise subprocess.TimeoutExpired(command, MODULE.DOCKER_TIMEOUT_SECONDS)
        return subprocess.CompletedProcess(command, 1, "", "cleanup failed")

    monkeypatch.setattr(MODULE, "_corpus_file", fake_file)
    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)

    with pytest.raises(MODULE.CorpusValidationError, match="timeout cleanup failed"):
        MODULE.run_oracle_in_docker(
            tmp_path,
            ["corpus/sql/concat_query.py"],
            "corpus/sql/concat_query.py",
            {"entrypoint": "lookup", "arguments": []},
        )


@pytest.mark.skipif(
    os.environ.get("SECURECODE_RUN_DOCKER_ORACLE") != "1",
    reason="opt-in: executes untrusted corpus source only in the Docker isolation boundary",
)
def test_docker_only_oracle_verifies_all_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    outcomes = MODULE.verify_oracles_in_docker(DEVELOPMENT_ROOT / "corpus-manifest.yaml")
    assert len(outcomes) == 24
    assert set(outcomes.values()) == {"SECURE_PASS", "VIOLATION_CONFIRMED"}


@pytest.mark.skipif(
    os.environ.get("SECURECODE_RUN_DOCKER_ORACLE") != "1",
    reason="opt-in: runs the malicious source only in Docker",
)
def test_second_sql_probe_rejects_first_payload_only_overfit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    copied_manifest = _copied_manifest(tmp_path)
    root = copied_manifest.parent
    source_path = "corpus/sql/concat_query.py"
    (root / source_path).write_text(
        "def lookup(request, db):\n"
        "    name = request.args.get('name')\n"
        "    if name == \"x' OR '1'='1\":\n"
        '        return db.execute("SELECT * FROM accounts WHERE name = ?", (name,))\n'
        '    return db.execute("SELECT * FROM accounts WHERE name = \'" + name + "\'")\n',
        encoding="utf-8",
    )
    rules = _read(DEVELOPMENT_ROOT / "corpus" / "oracle-rules.json")["rules"]
    assert type(rules) is dict
    rule = rules["dev-sql-concat_query"]
    assert type(rule) is dict
    probes = rule["probes"]
    assert type(probes) is list and len(probes) == 2
    first = probes[0]
    second = probes[1]
    assert type(first) is dict and type(second) is dict
    first_observation = MODULE.run_oracle_in_docker(root, [source_path], source_path, first["call"])
    second_observation = MODULE.run_oracle_in_docker(
        root, [source_path], source_path, second["call"]
    )
    assert MODULE._assertion(first_observation, first["secure_assertion"])
    assert not MODULE._assertion(second_observation, second["secure_assertion"])


@pytest.mark.skipif(
    os.environ.get("SECURECODE_RUN_DOCKER_ORACLE") != "1",
    reason="opt-in: runs the frame-forgery source only in Docker",
)
def test_two_phase_protocol_rejects_forged_frame_then_early_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(subprocess, "Popen", ORIGINAL_POPEN)
    copied_manifest = _copied_manifest(tmp_path)
    root = copied_manifest.parent
    source_path = "corpus/sql/concat_query.py"
    (root / source_path).write_text(
        "import os\n"
        "def lookup(request, db):\n"
        "    print('SECURECODE_ORACLE_OBSERVATION_V1:'\n"
        "          '{\"observation\":{\"parameters\":[\"x\\' OR \\'1\\'=\\'1\"],'\n"
        '          \'"query":"SELECT * FROM accounts WHERE name = ?"}}\', flush=True)\n'
        "    os._exit(0)\n",
        encoding="utf-8",
    )
    rules = _read(DEVELOPMENT_ROOT / "corpus" / "oracle-rules.json")["rules"]
    assert type(rules) is dict
    probe = rules["dev-sql-concat_query"]["probes"][0]

    with pytest.raises(MODULE.CorpusValidationError, match="closed observation"):
        MODULE.run_oracle_in_docker(root, [source_path], source_path, probe["call"])
