"""Focused integration coverage for the bounded M-A2026 delivery builder."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "build_m_a2026_submission.py"


def _builder_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("m_a2026_builder", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_is_deterministic_and_validates_all_hashes(tmp_path: Path) -> None:
    builder = _builder_module()

    first = builder.build_submission(tmp_path / "first", root=ROOT)
    second = builder.build_submission(tmp_path / "second", root=ROOT)

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
    assert builder.validate_submission(tmp_path / "first", root=ROOT)["task_id"] == "P9.16"


def test_validator_rejects_hash_drift_and_output_collision(tmp_path: Path) -> None:
    builder = _builder_module()
    bundle = tmp_path / "bundle"
    builder.build_submission(bundle, root=ROOT)

    (bundle / builder.REPORT_MD).write_text("changed", encoding="utf-8")
    with pytest.raises(builder.SubmissionError, match="hash mismatch"):
        builder.validate_submission(bundle, root=ROOT)

    collision = tmp_path / "collision"
    collision.mkdir()
    (collision / "existing.txt").write_text("occupied", encoding="utf-8")
    with pytest.raises(builder.SubmissionError, match="must be empty"):
        builder.build_submission(collision, root=ROOT)


def test_generated_report_retains_limits_without_raw_evidence(tmp_path: Path) -> None:
    builder = _builder_module()
    bundle = tmp_path / "bundle"
    builder.build_submission(bundle, root=ROOT)

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


def test_validator_rejects_forged_commit_quality_and_partial_notebook(tmp_path: Path) -> None:
    builder = _builder_module()
    bundle = tmp_path / "bundle"
    builder.build_submission(bundle, root=ROOT)
    manifest_path = bundle / builder.MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["snapshot"]["commit"] = "0" * 40
    manifest_path.write_bytes(builder._canonical(manifest))
    with pytest.raises(builder.SubmissionError, match="snapshot"):
        builder.validate_submission(bundle, root=ROOT)

    clean_bundle = tmp_path / "quality"
    builder.build_submission(clean_bundle, root=ROOT)
    quality_manifest_path = clean_bundle / builder.MANIFEST
    quality_manifest = json.loads(quality_manifest_path.read_text(encoding="utf-8"))
    quality_manifest["quality"]["tests_passed"] = 999_999
    quality_manifest["quality"]["core_branch_coverage_percent"] = 100.0
    quality_manifest_path.write_bytes(builder._canonical(quality_manifest))
    with pytest.raises(builder.SubmissionError, match="quality"):
        builder.validate_submission(clean_bundle, root=ROOT)

    receipt_bundle = tmp_path / "receipt"
    builder.build_submission(receipt_bundle, root=ROOT)
    receipt_path = receipt_bundle / builder.QUALITY_RECEIPT
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["result"]["tests_passed"] = 999_999
    receipt_path.write_bytes(builder._canonical(receipt))
    with pytest.raises(builder.SubmissionError, match=r"hash mismatch|quality receipt"):
        builder.validate_submission(receipt_bundle, root=ROOT)

    notebook = json.loads(
        (ROOT / "notebooks" / "m_a2026_submission.ipynb").read_text(encoding="utf-8")
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
    tmp_path: Path, name: str, replacement: object, message: str
) -> None:
    builder = _builder_module()
    bundle = tmp_path / name
    builder.build_submission(bundle, root=ROOT)
    manifest_path = bundle / builder.MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[name] = replacement
    manifest_path.write_bytes(builder._canonical(manifest))

    with pytest.raises(builder.SubmissionError, match=message):
        builder.validate_submission(bundle, root=ROOT)


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
    tmp_path: Path, artifact: str, replacement: bytes, message: str
) -> None:
    builder = _builder_module()
    bundle = tmp_path / artifact.replace(".", "-")
    builder.build_submission(bundle, root=ROOT)
    manifest_path = bundle / builder.MANIFEST
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    (bundle / artifact).write_bytes(replacement)
    manifest["deliverables"][artifact] = builder._sha(replacement)
    manifest_path.write_bytes(builder._canonical(manifest))

    with pytest.raises(builder.SubmissionError, match=message):
        builder.validate_submission(bundle, root=ROOT)


def test_academic_results_require_independent_byte_identical_recomputation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _builder_module()
    original_read = builder._read

    def mismatched_recomputation(path: Path) -> bytes:
        if path.name == "recomputed.json":
            return b"{}"
        return bytes(original_read(path))

    monkeypatch.setattr(builder, "_read", mismatched_recomputation)
    with pytest.raises(builder.SubmissionError, match="independent recomputation"):
        builder._academic_results(ROOT)


def test_academic_results_reject_matching_but_forged_aggregate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _builder_module()
    original_read = builder._read
    aggregate_path = ROOT / "evaluation/development/results/aggregate.json"
    forged = json.loads(aggregate_path.read_text(encoding="utf-8"))
    forged["planned_cells"] = 1
    forged_bytes = bytes(builder._canonical(forged))

    def forged_results(path: Path) -> bytes:
        if path.name in {"aggregate.json", "recomputed.json"}:
            return forged_bytes
        return bytes(original_read(path))

    monkeypatch.setattr(builder, "_read", forged_results)
    with pytest.raises(builder.SubmissionError, match=r"recomputation|acceptance facts"):
        builder._academic_results(ROOT)
