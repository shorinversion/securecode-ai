"""Focused integration coverage for the bounded M-A2026 delivery builder."""

from __future__ import annotations

import importlib.util
import json
import shutil
import stat
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

CURRENT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = CURRENT_ROOT / "scripts" / "build_m_a2026_submission.py"
HISTORICAL_COMMIT = "git-sha1:c0e949f53bea69a61f892155b42396b3a7ef3952".removeprefix("git-sha1:")
HISTORICAL_TREE = "git-sha1:61e75620509001a983f5eb9ea8fd5a72b78d9312".removeprefix("git-sha1:")
QUALITY_RECEIPT_PATH = Path("report/m-a2026/quality-receipt.json")
HISTORICAL_EVIDENCE_PATHS = (
    Path("scripts/build_m_a2026_submission.py"),
    Path("tests/integration/test_m_a2026_submission.py"),
)


def _builder_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("m_a2026_builder", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _mark_source_read_only(root: Path) -> None:
    for path in root.rglob("*"):
        if ".git" not in path.parts and path.is_file():
            path.chmod(path.stat().st_mode & ~stat.S_IWRITE)


def _make_source_mutable(root: Path) -> None:
    for path in root.rglob("*"):
        if ".git" not in path.parts and path.is_file():
            path.chmod(path.stat().st_mode | stat.S_IWRITE)


@pytest.fixture(scope="session")
def historical_base_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Materialize the pinned historical input without fetching or executing source."""

    _git(CURRENT_ROOT, "cat-file", "-e", f"{HISTORICAL_COMMIT}^{{commit}}")
    root = tmp_path_factory.mktemp("m-a2026-historical") / "source"
    subprocess.run(
        ["git", "clone", "--no-checkout", str(CURRENT_ROOT), str(root)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    _git(root, "config", "core.autocrlf", "false")
    _git(root, "config", "core.eol", "lf")
    _git(root, "checkout", "--detach", HISTORICAL_COMMIT)

    assert _git(root, "rev-parse", "HEAD") == HISTORICAL_COMMIT
    assert _git(root, "rev-parse", "HEAD^{tree}") == HISTORICAL_TREE
    assert _git(root, "status", "--porcelain") == ""
    _git(root, "diff", "--quiet", "--no-ext-diff", "HEAD")
    _git(root, "diff", "--cached", "--quiet", "--no-ext-diff")

    builder = _builder_module()
    receipt_bytes = (root / QUALITY_RECEIPT_PATH).read_bytes()
    assert builder._quality_receipt(root)["implementation"][
        "subject_sha256"
    ] == builder._subject_sha256(root)
    evidence = builder._evidence(root)
    for path in HISTORICAL_EVIDENCE_PATHS:
        assert evidence[path.as_posix()] == builder._sha((root / path).read_bytes())
    assert receipt_bytes == (root / QUALITY_RECEIPT_PATH).read_bytes()
    _mark_source_read_only(root)
    return root


@pytest.fixture
def historical_root(tmp_path: Path, historical_base_root: Path) -> Path:
    """Give each renderer regression an isolated, read-only historical input."""

    root = tmp_path / "historical"
    shutil.copytree(historical_base_root, root)
    return root


@pytest.fixture
def mutable_historical_root(tmp_path: Path, historical_base_root: Path) -> Path:
    """Use a writable copy only for explicit fail-closed source-drift fixtures."""

    root = tmp_path / "historical-negative"
    shutil.copytree(historical_base_root, root)
    _make_source_mutable(root)
    return root


def test_build_is_deterministic_and_validates_all_hashes(
    tmp_path: Path, historical_root: Path
) -> None:
    builder = _builder_module()
    receipt_bytes = (historical_root / QUALITY_RECEIPT_PATH).read_bytes()

    # This exercises the current renderer against historical inputs only. It does
    # not publish a report or bind a new quality receipt.
    first = builder.build_submission(tmp_path / "first", root=historical_root)
    second = builder.build_submission(tmp_path / "second", root=historical_root)

    assert first == second
    assert first["artifact_schema_version"] == "securecode.m-a2026.delivery-manifest.v1"
    assert first["delivery_status"]["state"] == "NOT_READY"
    assert first["notebook"]["executed"] is True
    assert first["academic_results"]["development_benchmark"]["recorded_cells"] == 312
    assert first["academic_results"]["development_benchmark"]["failed_cells"] == 171
    assert first["academic_results"]["real_local_demo"]["outcome"] == "COMPLETED"
    assert len(first["deliverables"]) == 6
    assert builder.REPORT_PDF in first["deliverables"]
    assert builder.QUALITY_RECEIPT in first["deliverables"]
    assert first["evidence"][HISTORICAL_EVIDENCE_PATHS[0].as_posix()] == builder._sha(
        (historical_root / HISTORICAL_EVIDENCE_PATHS[0]).read_bytes()
    )
    assert first["evidence"][HISTORICAL_EVIDENCE_PATHS[1].as_posix()] == builder._sha(
        (historical_root / HISTORICAL_EVIDENCE_PATHS[1]).read_bytes()
    )
    assert (tmp_path / "first" / builder.QUALITY_RECEIPT).read_bytes() == receipt_bytes
    assert (historical_root / QUALITY_RECEIPT_PATH).read_bytes() == receipt_bytes
    assert (
        builder.validate_submission(tmp_path / "first", root=historical_root)["task_id"] == "P9.16"
    )


def test_validator_rejects_hash_drift_and_output_collision(
    tmp_path: Path, historical_root: Path
) -> None:
    builder = _builder_module()
    bundle = tmp_path / "bundle"
    builder.build_submission(bundle, root=historical_root)

    (bundle / builder.REPORT_MD).write_text("changed", encoding="utf-8")
    with pytest.raises(builder.SubmissionError, match="hash mismatch"):
        builder.validate_submission(bundle, root=historical_root)

    collision = tmp_path / "collision"
    collision.mkdir()
    (collision / "existing.txt").write_text("occupied", encoding="utf-8")
    with pytest.raises(builder.SubmissionError, match="must be empty"):
        builder.build_submission(collision, root=historical_root)


def test_generated_report_retains_limits_without_raw_evidence(
    tmp_path: Path, historical_root: Path
) -> None:
    builder = _builder_module()
    bundle = tmp_path / "bundle"
    builder.build_submission(bundle, root=historical_root)

    report = (bundle / builder.REPORT_MD).read_text(encoding="utf-8")
    html = (bundle / builder.REPORT_HTML).read_text(encoding="utf-8")

    assert "`NOT_READY`" in report
    assert "does not claim G7, G9" in report
    assert "omit raw source" in report
    assert "<html" in html
    assert "omit raw source" in html
    assert "## Problem statement" in report
    assert "## Experimental results" in report
    assert "312 of 312 cells recorded" in report
    assert "171 failed cells" in report
    assert "## Conclusions" in report


def test_validator_rejects_forged_commit_quality_and_partial_notebook(
    tmp_path: Path, historical_root: Path
) -> None:
    builder = _builder_module()
    bundle = tmp_path / "bundle"
    builder.build_submission(bundle, root=historical_root)
    manifest_path = bundle / builder.MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["snapshot"]["commit"] = "0" * 40
    manifest_path.write_bytes(builder._canonical(manifest))
    with pytest.raises(builder.SubmissionError, match="snapshot"):
        builder.validate_submission(bundle, root=historical_root)

    clean_bundle = tmp_path / "quality"
    builder.build_submission(clean_bundle, root=historical_root)
    quality_manifest_path = clean_bundle / builder.MANIFEST
    quality_manifest = json.loads(quality_manifest_path.read_text(encoding="utf-8"))
    quality_manifest["quality"]["tests_passed"] = 999_999
    quality_manifest["quality"]["core_branch_coverage_percent"] = 100.0
    quality_manifest_path.write_bytes(builder._canonical(quality_manifest))
    with pytest.raises(builder.SubmissionError, match="quality"):
        builder.validate_submission(clean_bundle, root=historical_root)

    receipt_bundle = tmp_path / "receipt"
    builder.build_submission(receipt_bundle, root=historical_root)
    receipt_path = receipt_bundle / builder.QUALITY_RECEIPT
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["result"]["tests_passed"] = 999_999
    receipt_path.write_bytes(builder._canonical(receipt))
    with pytest.raises(builder.SubmissionError, match=r"hash mismatch|quality receipt"):
        builder.validate_submission(receipt_bundle, root=historical_root)

    notebook = json.loads(
        (historical_root / "notebooks" / "m_a2026_submission.ipynb").read_text(encoding="utf-8")
    )
    code_cells = [cell for cell in notebook["cells"] if cell.get("cell_type") == "code"]
    code_cells[1]["execution_count"] = None
    assert builder._notebook_is_executed(builder._canonical(notebook)) is False


@pytest.mark.parametrize(
    ("name", "replacement", "message"),
    [
        ("limitations", [], "limitations"),
        ("delivery_status", {"state": "NOT_READY", "blocking_reasons": ["forged"]}, "status"),
    ],
)
def test_validator_rejects_forged_closed_manifest_fields(
    tmp_path: Path, historical_root: Path, name: str, replacement: object, message: str
) -> None:
    builder = _builder_module()
    bundle = tmp_path / name
    builder.build_submission(bundle, root=historical_root)
    manifest_path = bundle / builder.MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[name] = replacement
    manifest_path.write_bytes(builder._canonical(manifest))

    with pytest.raises(builder.SubmissionError, match=message):
        builder.validate_submission(bundle, root=historical_root)


@pytest.mark.parametrize(
    ("artifact", "replacement", "message"),
    [
        ("report.md", b"forged report", "Markdown"),
        (
            "report.pdf",
            b"%PDF-1.4\nM-A2026 Academic Snapshot NOT_READY Evidence inventory\n%%EOF\n",
            "PDF",
        ),
    ],
)
def test_validator_rejects_semantically_forged_reports(
    tmp_path: Path, historical_root: Path, artifact: str, replacement: bytes, message: str
) -> None:
    builder = _builder_module()
    bundle = tmp_path / artifact.replace(".", "-")
    builder.build_submission(bundle, root=historical_root)
    manifest_path = bundle / builder.MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    (bundle / artifact).write_bytes(replacement)
    manifest["deliverables"][artifact] = builder._sha(replacement)
    manifest_path.write_bytes(builder._canonical(manifest))

    with pytest.raises(builder.SubmissionError, match=message):
        builder.validate_submission(bundle, root=historical_root)


def test_academic_results_require_independent_byte_identical_recomputation(
    monkeypatch: pytest.MonkeyPatch,
    historical_root: Path,
) -> None:
    builder = _builder_module()
    original_read = builder._read

    def mismatched_recomputation(path: Path) -> bytes:
        if path.name == "recomputed.json":
            return b"{}"
        return bytes(original_read(path))

    monkeypatch.setattr(builder, "_read", mismatched_recomputation)
    with pytest.raises(builder.SubmissionError, match="independent recomputation"):
        builder._academic_results(historical_root)


def test_academic_results_reject_matching_but_forged_aggregate(
    monkeypatch: pytest.MonkeyPatch,
    historical_root: Path,
) -> None:
    builder = _builder_module()
    original_read = builder._read
    aggregate_path = historical_root / "evaluation/development/results/aggregate.json"
    forged = json.loads(aggregate_path.read_text(encoding="utf-8"))
    forged["planned_cells"] = 1
    forged_bytes = bytes(builder._canonical(forged))

    def forged_results(path: Path) -> bytes:
        if path.name in {"aggregate.json", "recomputed.json"}:
            return forged_bytes
        return bytes(original_read(path))

    monkeypatch.setattr(builder, "_read", forged_results)
    with pytest.raises(builder.SubmissionError, match=r"recomputation|acceptance facts"):
        builder._academic_results(historical_root)


@pytest.mark.parametrize(
    "mutation",
    ("current_builder", "ordinary_source", "untracked_file", "tracked_file", "receipt_subject"),
)
def test_builder_rejects_historical_input_drift(
    tmp_path: Path, mutable_historical_root: Path, mutation: str
) -> None:
    builder = _builder_module()
    root = mutable_historical_root
    if mutation == "current_builder":
        shutil.copyfile(SCRIPT, root / HISTORICAL_EVIDENCE_PATHS[0])
        mutated_builder = root / HISTORICAL_EVIDENCE_PATHS[0]
        mutated_builder.write_bytes(
            mutated_builder.read_bytes().replace(b'"tests_passed": 2620', b'"tests_passed": 2621')
        )
    elif mutation == "ordinary_source":
        source = root / "packages/adapters/src/securecode_ai/adapters/program_graph.py"
        source.write_bytes(source.read_bytes() + b"\n# negative historical fixture\n")
    elif mutation == "untracked_file":
        (root / "untracked-historical-input.txt").write_text("forged", encoding="utf-8")
    elif mutation == "tracked_file":
        (root / "packages/adapters/src/securecode_ai/adapters/program_graph.py").unlink()
    else:
        receipt_path = root / QUALITY_RECEIPT_PATH
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["implementation"]["subject_sha256"] = "0" * 64
        receipt_path.write_bytes(builder._canonical(receipt))

    with pytest.raises(builder.SubmissionError):
        builder.build_submission(tmp_path / "bundle", root=root)
