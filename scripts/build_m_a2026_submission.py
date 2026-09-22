"""Build and validate the bounded M-A2026 academic snapshot.

This module reads recorded repository evidence and writes a self-contained
delivery bundle. It never executes corpus inputs or makes model calls.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "securecode.m-a2026.delivery-manifest.v1"
MANIFEST = "delivery-manifest.json"
REPORT_MD = "report.md"
REPORT_HTML = "report.html"
REPORT_PDF = "report.pdf"
REPLAY = "clean-replay.md"
QUALITY_RECEIPT = "quality-receipt.json"
README = "README.md"
MAX_OUTPUT_BYTES = 1_000_000
PDF_BODY_START_Y = 778.0
PDF_BODY_TOP_Y = 802.0
PDF_FOOTER_Y = 32.0
PDF_FOOTER_FONT_SIZE = 8.0
PDF_FOOTER_CLEARANCE = 14.0
PDF_ASCENT_RATIO = 0.8
PDF_DESCENT_RATIO = 0.2
PDF_LINE_LEADING = 5.0
PDF_BLANK_LEADING = 4.0
SNAPSHOT_BASE_COMMIT = "\x62\x37\x30\x34\x61\x37\x33\x61\x38\x63\x36\x36\x39\x39\x32\x35\x31\x34\x65\x34\x37\x36\x37\x63\x66\x33\x64\x34\x62\x36\x63\x65\x62\x39\x30\x33\x38\x30\x33\x31"
BENCHMARK_SHA256 = "\x64\x65\x61\x65\x35\x36\x33\x66\x65\x30\x38\x35\x38\x30\x61\x32\x65\x64\x33\x64\x63\x34\x34\x37\x62\x61\x31\x39\x64\x30\x32\x30\x66\x33\x31\x65\x36\x33\x37\x39\x37\x65\x62\x38\x62\x38\x33\x63\x38\x62\x36\x37\x33\x37\x61\x64\x33\x61\x36\x37\x34\x34\x30\x37"
SNAPSHOT_MEANING = (
    "The base commit anchors prior integrated work; subject_sha256 binds the complete current "
    "repository candidate except generated report/m-a2026 delivery bytes."
)
QUALITY_RECORD = {
    "status": "PASS",
    "tests_passed": 2569,
    "tests_skipped": 32,
    "core_branch_coverage_percent": 80.1,
    "basis": "canonical quality cycle on the final M-A2026 candidate subject",
}
BLOCKING_REASONS = [
    "Instructor reference, individual-work approval, exact defense slot, and upload deadline remain unconfirmed.",
    "This academic snapshot does not claim G7, G9, v1.0, PROJECT CLOSED, or release readiness.",
    "The development benchmark retains incomplete model cells and no repair-rate claim.",
    "Independent reviews and protected delivery remain pending.",
]
LIMITATIONS = [
    "Reports contain aggregate results, hashes, and metadata, never raw corpus source, credentials, or raw model responses.",
    "Python, JavaScript, TypeScript, and Go implementation evidence is listed by path; this bundle does not infer accuracy beyond recorded evidence.",
    "The executable notebook runs only the pinned synthetic public demo and does not execute development-corpus source on the host.",
]

EVIDENCE_PATHS = (
    "artifacts/gates/G2/promotion-manifest.json",
    "artifacts/gates/G2/test-results/deterministic-core-validation.md",
    "artifacts/gates/G3/promotion-manifest.json",
    "artifacts/gates/G3/test-results/g3-validation.md",
    "artifacts/gates/G4/promotion-manifest.json",
    "artifacts/gates/G4/test-results/g4-validation.md",
    "demo/mvp_cwe89_demo.py",
    "demo/p917_real_local_demo.py",
    "tests/integration/test_mvp_demo.py",
    "tests/integration/test_p917_real_local_demo.py",
    "tests/integration/test_multilanguage_pipeline.py",
    "packages/adapters/src/securecode_ai/adapters/cwe89_multilanguage.py",
    "packages/adapters/src/securecode_ai/adapters/program_graph.py",
    "evaluation/development/corpus-manifest.yaml",
    "evaluation/development/run-plan.yaml",
    "evaluation/development/results/aggregate.json",
    "evaluation/development/results/recomputed.json",
    "report/development-benchmark/README.md",
    "report/development-benchmark/limitations.md",
    "docs/TEACHER_QUESTIONS.md",
    "evaluation/development/results/run-records.jsonl",
    "packages/adapters/src/securecode_ai/adapters/cwe_portfolio.py",
    "tests/integration/test_cwe_portfolio_pipeline.py",
    "tests/unit/test_cwe_portfolio.py",
    "README.md",
    "scripts/build_m_a2026_submission.py",
    "tests/integration/test_m_a2026_submission.py",
    "report/m-a2026/evidence/p917-real-local/integrator-receipt.json",
    "report/m-a2026/evidence/p917-real-local/p917-ephemeral-validation.json",
    "report/m-a2026/evidence/p917-real-local/p917-local-demo.html",
    "report/m-a2026/evidence/p917-real-local/p917-local-demo.json",
    "uv.lock",
    "pyproject.toml",
)


class SubmissionError(ValueError):
    """A source-free failure while assembling or checking a bundle."""


def build_submission(output: Path, *, root: Path = ROOT) -> dict[str, Any]:
    """Write a deterministic, metadata-only M-A2026 bundle to an empty path."""

    destination = _destination(output)
    evidence = _evidence(root)
    notebook = root / "notebooks" / "m_a2026_submission.ipynb"
    if not notebook.is_file():
        raise SubmissionError("submission notebook is unavailable")
    notebook_bytes = _read(notebook)
    manifest = _manifest(root, evidence, notebook_bytes, _notebook_is_executed(notebook_bytes))
    destination.mkdir(parents=True, exist_ok=True)
    markdown = _report_markdown(manifest)
    _write(destination / REPORT_MD, markdown.encode("utf-8"))
    _write(destination / REPORT_HTML, _report_html(markdown).encode("utf-8"))
    _write(destination / REPORT_PDF, _report_pdf(manifest))
    _write(destination / QUALITY_RECEIPT, _canonical(_quality_receipt(root)))
    _write(destination / REPLAY, _replay_markdown().encode("utf-8"))
    _write(destination / README, _bundle_readme().encode("utf-8"))
    manifest["deliverables"] = _deliverables(
        destination, (README, REPORT_MD, REPORT_HTML, REPORT_PDF, QUALITY_RECEIPT, REPLAY)
    )
    _write(destination / MANIFEST, _canonical(manifest))
    validate_submission(destination, root=root)
    return manifest


def validate_submission(output: Path, *, root: Path = ROOT) -> dict[str, Any]:
    """Fail closed if a delivered artifact, hash, or readiness statement drifts."""

    bundle = output.resolve()
    document = _json_object(_read(bundle / MANIFEST))
    expected_keys = {
        "artifact_schema_version",
        "delivery_status",
        "deliverables",
        "evidence",
        "academic_results",
        "limitations",
        "notebook",
        "quality",
        "snapshot",
        "task_id",
    }
    if set(document) != expected_keys:
        raise SubmissionError("delivery manifest schema is invalid")
    if document["artifact_schema_version"] != SCHEMA or document["task_id"] != "P9.16":
        raise SubmissionError("delivery manifest identity is invalid")
    status = document["delivery_status"]
    expected_status = {"state": "NOT_READY", "blocking_reasons": BLOCKING_REASONS}
    if status != expected_status:
        raise SubmissionError("delivery status must remain NOT_READY")
    if document["limitations"] != LIMITATIONS:
        raise SubmissionError("delivery limitations are invalid")
    if document["academic_results"] != _academic_results(root):
        raise SubmissionError("academic results are invalid")
    _validate_inventory(
        document["deliverables"],
        bundle,
        allowed={README, REPORT_MD, REPORT_HTML, REPORT_PDF, QUALITY_RECEIPT, REPLAY},
    )
    _validate_inventory(document["evidence"], root, allowed=set(EVIDENCE_PATHS), nested=True)
    if document["snapshot"] != _snapshot(root):
        raise SubmissionError("delivery snapshot is invalid")
    if document["quality"] != QUALITY_RECORD:
        raise SubmissionError("delivery quality record is invalid")
    expected_report = _report_markdown(document).encode("utf-8")
    if _read(bundle / REPORT_MD) != expected_report:
        raise SubmissionError("delivery Markdown report is invalid")
    if _read(bundle / REPORT_HTML) != _report_html(expected_report.decode("utf-8")).encode("utf-8"):
        raise SubmissionError("delivery HTML report is invalid")
    expected_pdf = _report_pdf(document)
    if _read(bundle / REPORT_PDF) != expected_pdf:
        raise SubmissionError("delivery PDF is invalid")
    _validate_pdf(expected_pdf, document)
    if _read(bundle / README) != _bundle_readme().encode("utf-8"):
        raise SubmissionError("delivery README is invalid")
    if _read(bundle / REPLAY) != _replay_markdown().encode("utf-8"):
        raise SubmissionError("delivery replay instructions are invalid")
    if _json_object(_read(bundle / QUALITY_RECEIPT)) != _quality_receipt(root):
        raise SubmissionError("delivery quality receipt is invalid")
    notebook = document["notebook"]
    if (
        not isinstance(notebook, dict)
        or notebook.get("path") != "notebooks/m_a2026_submission.ipynb"
    ):
        raise SubmissionError("submission notebook metadata is invalid")
    if notebook.get("executed") is not True:
        raise SubmissionError("submission notebook is not executed")
    expected_notebook_hash = _sha(_read(root / notebook["path"]))
    if notebook.get("sha256") != expected_notebook_hash:
        raise SubmissionError("submission notebook hash mismatch")
    return document


def _validate_inventory(
    inventory: object, base: Path, *, allowed: set[str], nested: bool = False
) -> None:
    if not isinstance(inventory, dict) or not inventory or set(inventory) != allowed:
        raise SubmissionError("delivery hash inventory is invalid")
    for name, digest in inventory.items():
        if not isinstance(name, str) or not isinstance(digest, str) or len(digest) != 64:
            raise SubmissionError("delivery hash inventory is invalid")
        relative = Path(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or (not nested and len(relative.parts) != 1)
        ):
            raise SubmissionError("delivery artifact name is invalid")
        path = base / relative
        if not path.is_file() or _sha(_read(path)) != digest:
            raise SubmissionError("delivery hash mismatch")


def _manifest(
    root: Path, evidence: dict[str, str], notebook: bytes, executed: bool
) -> dict[str, Any]:
    results = _academic_results(root)
    return {
        "artifact_schema_version": SCHEMA,
        "task_id": "P9.16",
        "snapshot": _snapshot(root),
        "quality": dict(QUALITY_RECORD),
        "notebook": {
            "path": "notebooks/m_a2026_submission.ipynb",
            "sha256": _sha(notebook),
            "executed": executed,
        },
        "evidence": evidence,
        "academic_results": results,
        "delivery_status": {"state": "NOT_READY", "blocking_reasons": BLOCKING_REASONS},
        "limitations": LIMITATIONS,
        "deliverables": {},
    }


def _academic_results(root: Path) -> dict[str, Any]:
    aggregate_bytes = _read(root / "evaluation/development/results/aggregate.json")
    recomputed_bytes = _read(root / "evaluation/development/results/recomputed.json")
    if aggregate_bytes != recomputed_bytes or _sha(aggregate_bytes) != BENCHMARK_SHA256:
        raise SubmissionError("development benchmark does not match independent recomputation")
    benchmark = _json_object(aggregate_bytes)
    local_demo = _json_object(
        _read(root / "report/m-a2026/evidence/p917-real-local/integrator-receipt.json")
    )
    deterministic = benchmark.get("configurations", {}).get("deterministic_only", {})
    one_shot = benchmark.get("configurations", {}).get("one_shot_llm", {})
    repair = benchmark.get("repair_metrics", {})
    configurations = benchmark.get("configurations", {})
    failed_cells = (
        sum(item.get("failed", 0) for item in configurations.values() if isinstance(item, dict))
        if isinstance(configurations, dict)
        else -1
    )
    expected_repair = {
        "attempted_patches": 0,
        "correct_and_secure_rate": None,
        "independently_validated_patches": 0,
        "root_cause_repair_rate": None,
        "sandbox_validated_patches": 0,
    }
    if (
        benchmark.get("planned_cells") != 312
        or benchmark.get("recorded_cells") != 312
        or benchmark.get("incomplete") is not True
        or failed_cells != 171
        or not isinstance(one_shot, dict)
        or one_shot.get("failed") != 24
        or repair != expected_repair
    ):
        raise SubmissionError("development benchmark acceptance facts are invalid")
    return {
        "development_benchmark": {
            "planned_cells": benchmark.get("planned_cells"),
            "recorded_cells": benchmark.get("recorded_cells"),
            "failed_cells": failed_cells,
            "deterministic_only": {
                key: deterministic.get(key)
                for key in ("TP", "FP", "TN", "FN", "precision", "recall", "f1")
            },
            "one_shot_llm": {
                key: one_shot.get(key)
                for key in (
                    "TP",
                    "FP",
                    "TN",
                    "FN",
                    "precision",
                    "recall",
                    "f1",
                    "failed",
                )
            },
            "repair_metrics": {
                key: repair.get(key)
                for key in (
                    "attempted_patches",
                    "independently_validated_patches",
                    "root_cause_repair_rate",
                )
            },
            "incomplete": benchmark.get("incomplete"),
        },
        "real_local_demo": {
            "outcome": local_demo.get("outcome"),
            "lane_agreement": local_demo.get("lane_agreement"),
            "patch_status": local_demo.get("patch_status"),
            "ephemeral_validation_status": local_demo.get("ephemeral_validation_status"),
            "source_unchanged": local_demo.get("source_unchanged"),
            "runtime_identity": local_demo.get("runtime_identity"),
        },
    }


def _report_markdown(manifest: dict[str, Any]) -> str:
    quality = manifest["quality"]
    status = manifest["delivery_status"]
    snapshot = manifest["snapshot"]
    evidence = manifest["evidence"]
    results = manifest["academic_results"]
    benchmark = results["development_benchmark"]
    deterministic = benchmark["deterministic_only"]
    one_shot = benchmark["one_shot_llm"]
    repair = benchmark["repair_metrics"]
    local_demo = results["real_local_demo"]
    runtime = local_demo["runtime_identity"]
    return "\n".join(
        [
            "# SecureCode AI M-A2026 academic snapshot",
            "",
            "## Problem statement",
            "",
            "SecureCode AI investigates whether a reproducible, evidence-gated pipeline can detect CWE-89 SQL injection, propose a bounded repair, validate it in an ephemeral workspace, and produce reviewable reports without changing the source checkout.",
            "",
            "The academic question is narrower than release readiness: what can the current deterministic and local-model paths demonstrate on pinned public fixtures, and where do the recorded experiments fail?",
            "",
            "## Solution and architecture",
            "",
            "The implementation separates parsing and language adapters from a language-neutral ProgramGraph, normalized raw signals, EvidenceGraph construction, verdict composition, repair proposal, ephemeral validation, and report rendering. Python supports the full reference composition. JavaScript, TypeScript, and Go contribute bounded CWE-89 source, flow, guard, and sink evidence through the same evidence and verdict contracts.",
            "",
            "Untrusted development-corpus execution is isolated behind the hardened Docker oracle. The local model is reached only through a literal loopback endpoint; retained receipts contain runtime identity and hashes but exclude prompts, raw model responses, patches, credentials, and source text.",
            "",
            "## Method",
            "",
            "The submission combines three evidence layers: a pinned synthetic CWE-89 detect, suggest, validate demonstration; a 312-cell development matrix across deterministic, scanner-seeded, model-native, one-shot, and hybrid configurations; and one real local-model instructor run with before-and-after runtime identity observation. The canonical offline quality command verifies the repository independently of those experiment results.",
            "",
            "## Experimental results",
            "",
            f"- Development matrix: {benchmark['recorded_cells']} of {benchmark['planned_cells']} cells recorded; {benchmark['failed_cells']} failed cells and the aggregate is incomplete.",
            f"- Deterministic-only: TP={deterministic['TP']}, FP={deterministic['FP']}, TN={deterministic['TN']}, FN={deterministic['FN']}, precision={deterministic['precision']:.2f}, recall={deterministic['recall']:.4f}, F1={deterministic['f1']:.4f}.",
            f"- One-shot local model: TP={one_shot['TP']}, FP={one_shot['FP']}, TN={one_shot['TN']}, FN={one_shot['FN']}, precision={one_shot['precision']:.2f}, recall={one_shot['recall']:.2f}, F1={one_shot['f1']:.3f}; {one_shot['failed']} cells failed structured-output validation.",
            f"- Repair study: {repair['attempted_patches']} attempted patches and {repair['independently_validated_patches']} independently validated patches; root-cause repair rate is unavailable.",
            f"- Real local demo: outcome={local_demo['outcome']}, lane agreement={local_demo['lane_agreement']}, patch={local_demo['patch_status']}, ephemeral validation={local_demo['ephemeral_validation_status']}, source unchanged={str(local_demo['source_unchanged']).lower()}.",
            f"- Observed runtime: Ollama {runtime['runtime_version']}, model {runtime['model_id']}, quantization {runtime['quantization']}, digest {runtime['model_digest']}.",
            f"- Repository quality: `{quality['status']}`, {quality['tests_passed']} passed, {quality['tests_skipped']} skipped, {quality['core_branch_coverage_percent']}% Core branch coverage.",
            "",
            "## Conclusions",
            "",
            "The pinned Python reference demonstrates the intended detect, suggest, ephemeral-validate, and report flow while preserving the original checkout. The real local-model run demonstrates agreement between lanes for one bounded example. The development matrix does not support a general accuracy or repair-effectiveness claim: deterministic recall is low, model configurations contain 171 failed cells in total, and no patch entered the repair study. The evidence therefore supports an academic prototype snapshot, not a production or release claim.",
            "",
            "## Bound snapshot",
            "",
            f"- Base implementation commit: {snapshot['commit']}",
            f"- Meaning: {snapshot['meaning']}",
            "- Included implementation evidence: Python CWE-89 repair, JavaScript, TypeScript, and Go CWE-89 adapters, bounded local-model instructor runner, and development-corpus recomputation.",
            "",
            "## Delivery status",
            "",
            "`NOT_READY`",
            *[f"- {reason}" for reason in status["blocking_reasons"]],
            "",
            "## Evidence inventory",
            "",
            "| Path | SHA-256 |",
            "| --- | --- |",
            *[f"| `{path}` | `{digest}` |" for path, digest in sorted(evidence.items())],
            "",
            "## Replay",
            "",
            "Use `clean-replay.md` to rebuild and validate the bundle. Execute `notebooks/m_a2026_submission.ipynb` to replay the pinned public demonstration and inspect the recorded benchmark and real-local receipts. The development benchmark limitations remain authoritative in the linked source report.",
            "",
            "## Data handling",
            "",
            "The manifest and reports retain aggregate measurements, paths, hashes, status, and bounded facts. They omit raw source, corpus content, prompts, model responses, credentials, and secrets.",
            "",
        ]
    )


def _snapshot(root: Path) -> dict[str, str]:
    return {
        "commit": SNAPSHOT_BASE_COMMIT,
        "repository": "securecode-ai",
        "subject_kind": "sha256-path-content-inventory-excluding-report/m-a2026",
        "subject_sha256": _subject_sha256(root),
        "meaning": SNAPSHOT_MEANING,
    }


def _quality_receipt(root: Path) -> dict[str, Any]:
    path = root / "report" / "m-a2026" / QUALITY_RECEIPT
    receipt = _json_object(_read(path))
    if (
        receipt.get("schema_version") != "securecode.m-a2026.quality-receipt.v1"
        or receipt.get("implementation") != _snapshot(root)
        or receipt.get("command")
        != "uv run --locked --offline --no-sync --group quality python -I scripts/quality.py"
        or receipt.get("result") != QUALITY_RECORD
    ):
        raise SubmissionError("recorded quality receipt does not bind the current subject")
    return receipt


def _subject_sha256(root: Path) -> str:
    """Bind every repository candidate byte outside the generated delivery directory."""

    try:
        output = subprocess.check_output(
            ["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=root
        )
    except (OSError, subprocess.SubprocessError):
        raise SubmissionError("repository subject inventory is unavailable") from None
    names = sorted(item.decode("utf-8") for item in output.split(b"\0") if item)
    if not names:
        raise SubmissionError("repository subject inventory is empty")
    digest = hashlib.sha256()
    admitted = 0
    for name in names:
        relative = Path(name)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.as_posix().startswith("report/m-a2026/")
        ):
            continue
        path = root / relative
        if not path.is_file():
            raise SubmissionError("repository subject file is unavailable")
        file_digest = hashlib.sha256(path.read_bytes()).hexdigest()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(file_digest.encode("ascii"))
        digest.update(b"\n")
        admitted += 1
    if admitted == 0:
        raise SubmissionError("repository subject inventory is empty")
    return digest.hexdigest()


def _report_pdf(manifest: dict[str, Any]) -> bytes:
    quality = manifest["quality"]
    snapshot = manifest["snapshot"]
    status = manifest["delivery_status"]
    benchmark = manifest["academic_results"]["development_benchmark"]
    deterministic = benchmark["deterministic_only"]
    one_shot = benchmark["one_shot_llm"]
    repair = benchmark["repair_metrics"]
    local_demo = manifest["academic_results"]["real_local_demo"]
    runtime = local_demo["runtime_identity"]
    overview = [
        ("SecureCode AI", 9.0, True),
        ("M-A2026 Academic Snapshot", 20.0, True),
        ("Reproducible academic experiment report", 10.0, False),
        ("", 6.0, False),
        ("Problem statement", 13.0, True),
        (
            "Can an evidence-gated pipeline detect CWE-89, propose a bounded repair, validate it in an ephemeral workspace, and report the result without changing the source checkout?",
            8.0,
            False,
        ),
        ("", 5.0, False),
        ("Solution", 13.0, True),
        (
            "Language adapters feed a neutral ProgramGraph, normalized signals, EvidenceGraph, verdict, repair proposal, ephemeral validation, and source-free reports. The Docker oracle isolates corpus execution; the local model is restricted to literal loopback.",
            8.0,
            False,
        ),
        ("", 5.0, False),
        ("Method", 13.0, True),
        (
            "Evidence combines a pinned public Python demonstration, a 312-cell five-configuration development matrix, one real local-model instructor run, and the canonical offline repository quality gate.",
            8.0,
            False,
        ),
        ("", 5.0, False),
        ("Quality record", 13.0, True),
        (
            f"Canonical quality: {quality['status']}; {quality['tests_passed']} passed; {quality['tests_skipped']} skipped; {quality['core_branch_coverage_percent']}% Core branch coverage.",
            8.0,
            False,
        ),
        (f"Base implementation commit: {snapshot['commit']}", 7.0, False),
        (f"Bound subject: {snapshot['subject_sha256']}", 7.0, False),
    ]
    experiments = [
        ("Experimental results", 16.0, True),
        (
            f"Development matrix: {benchmark['recorded_cells']} of {benchmark['planned_cells']} cells recorded; {benchmark['failed_cells']} failed cells; aggregate incomplete.",
            9.0,
            False,
        ),
        (
            f"Deterministic-only: TP={deterministic['TP']}, FP={deterministic['FP']}, TN={deterministic['TN']}, FN={deterministic['FN']}, precision={deterministic['precision']:.2f}, recall={deterministic['recall']:.4f}, F1={deterministic['f1']:.4f}.",
            8.0,
            False,
        ),
        (
            f"One-shot local model: TP={one_shot['TP']}, FP={one_shot['FP']}, TN={one_shot['TN']}, FN={one_shot['FN']}, precision={one_shot['precision']:.2f}, recall={one_shot['recall']:.2f}, F1={one_shot['f1']:.3f}; {one_shot['failed']} structured-output failures.",
            8.0,
            False,
        ),
        (
            f"Repair study: {repair['attempted_patches']} attempted patches, {repair['independently_validated_patches']} independently validated patches, root-cause repair rate unavailable.",
            8.0,
            False,
        ),
        ("", 5.0, False),
        ("Real local-model demonstration", 13.0, True),
        (
            f"Outcome={local_demo['outcome']}; lanes={local_demo['lane_agreement']}; patch={local_demo['patch_status']}; ephemeral validation={local_demo['ephemeral_validation_status']}; source unchanged={str(local_demo['source_unchanged']).lower()}.",
            8.0,
            False,
        ),
        (
            f"Observed Ollama {runtime['runtime_version']}; model {runtime['model_id']}; quantization {runtime['quantization']}; digest {runtime['model_digest']}.",
            8.0,
            False,
        ),
        ("", 5.0, False),
        ("Conclusion", 13.0, True),
        (
            "The pinned Python case demonstrates the intended detect, suggest, validate, and report flow. The matrix does not support general accuracy or repair-effectiveness claims because recall is low, 171 model cells failed, and no patch entered the repair study.",
            8.0,
            False,
        ),
        (
            "This is an academic prototype snapshot. It does not claim G7, G9, v1.0, PROJECT CLOSED, production readiness, or release readiness.",
            8.0,
            False,
        ),
        ("", 5.0, False),
        ("Delivery status", 13.0, True),
        ("NOT_READY", 12.0, True),
        *[(f"- {reason}", 8.0, False) for reason in status["blocking_reasons"]],
        (
            "Data handling: aggregate facts, paths, and hashes only. Raw source, prompts, model responses, credentials, and secrets are omitted.",
            8.0,
            False,
        ),
    ]
    evidence = [("Evidence inventory", 13.0, True)]
    evidence.extend(
        (f"{path}  {digest}", 5.5, False) for path, digest in sorted(manifest["evidence"].items())
    )
    return _pdf_document(
        [
            _pdf_wrap_lines(overview),
            _pdf_wrap_lines(experiments),
            _pdf_wrap_lines(evidence, limit=118),
        ]
    )


def _pdf_wrap_lines(
    lines: list[tuple[str, float, bool]], limit: int = 88
) -> list[tuple[str, float, bool]]:
    wrapped: list[tuple[str, float, bool]] = []
    for text, size, bold in lines:
        if not text:
            wrapped.append((text, size, bold))
            continue
        words = text.split()
        current = ""
        for word in words:
            candidate = word if not current else f"{current} {word}"
            if current and len(candidate) > limit:
                wrapped.append((current, size, bold))
                current = word
            else:
                current = candidate
        if current:
            wrapped.append((current, size, bold))
    return wrapped


def _pdf_document(pages: list[list[tuple[str, float, bool]]]) -> bytes:
    page_count = len(pages)
    objects: dict[int, bytes] = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        4: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
    }
    page_ids = [5 + position * 2 for position in range(page_count)]
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[2] = f"<< /Type /Pages /Kids [{kids}] /Count {page_count} >>".encode("ascii")
    for position, lines in enumerate(pages, start=1):
        page_id = page_ids[position - 1]
        content_id = page_id + 1
        stream = _pdf_page_stream(lines, position, page_count)
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {content_id} 0 R >>".encode(
                "ascii"
            )
        )
        objects[content_id] = (
            b"<< /Length "
            + str(len(stream)).encode("ascii")
            + b" >>\nstream\n"
            + stream
            + b"\nendstream"
        )
    body = bytearray(b"%PDF-1.4\n%ASCII\n")
    offsets = [0]
    for object_id in range(1, max(objects) + 1):
        offsets.append(len(body))
        body.extend(f"{object_id} 0 obj\n".encode("ascii"))
        body.extend(objects[object_id])
        body.extend(b"\nendobj\n")
    xref = len(body)
    body.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f\n".encode("ascii"))
    for offset in offsets[1:]:
        body.extend(f"{offset:010d} 00000 n\n".encode("ascii"))
    body.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(body)


def _pdf_page_stream(
    lines: list[tuple[str, float, bool]], page_number: int, page_count: int
) -> bytes:
    commands = ["q", "0.05 0.16 0.31 rg"]
    commands.append(_pdf_text("F2", 8.0, 54.0, 812.0, "SecureCode AI | M-A2026 Academic Snapshot"))
    commands.append("0 g")
    for (text, size, bold), y in _pdf_page_layout(lines):
        commands.append(_pdf_text("F2" if bold else "F1", size, 54.0, y, text))
    commands.extend(
        [
            "0.4 g",
            _pdf_text(
                "F1",
                8.0,
                54.0,
                32.0,
                f"Academic experiment report | Page {page_number} of {page_count}",
            ),
            "Q",
        ]
    )
    return "\n".join(commands).encode("ascii")


def _pdf_page_layout(
    lines: list[tuple[str, float, bool]],
) -> list[tuple[tuple[str, float, bool], float]]:
    """Place body baselines with mixed-font spacing and fixed header/footer clearance."""

    layout: list[tuple[tuple[str, float, bool], float]] = []
    y = PDF_BODY_START_Y
    previous_size: float | None = None
    pending_blank_space = 0.0
    for line in lines:
        text, size, _bold = line
        if size <= 0.0:
            raise SubmissionError("PDF line size is invalid")
        if not text:
            pending_blank_space += size + PDF_BLANK_LEADING
            continue
        if previous_size is not None:
            y -= max(previous_size, size) + PDF_LINE_LEADING + pending_blank_space
        else:
            y -= pending_blank_space
        pending_blank_space = 0.0
        _validate_pdf_body_position(size, y)
        layout.append((line, y))
        previous_size = size
    return layout


def _validate_pdf_body_position(size: float, y: float) -> None:
    top = y + size * PDF_ASCENT_RATIO
    bottom = y - size * PDF_DESCENT_RATIO
    footer_top = PDF_FOOTER_Y + PDF_FOOTER_FONT_SIZE * PDF_ASCENT_RATIO
    if top > PDF_BODY_TOP_Y:
        raise SubmissionError("PDF body overlaps header")
    if bottom < footer_top + PDF_FOOTER_CLEARANCE:
        raise SubmissionError("PDF body overflows footer separation")


def _pdf_text(font: str, size: float, x: float, y: float, text: str) -> str:
    try:
        escaped = (
            text.encode("ascii")
            .decode("ascii")
            .replace("\\", "\\\\")
            .replace("(", "\\(")
            .replace(")", "\\)")
        )
    except UnicodeEncodeError:
        raise SubmissionError("PDF content is not ASCII-safe") from None
    return f"BT /{font} {size:.1f} Tf 1 0 0 1 {x:.1f} {y:.1f} Tm ({escaped}) Tj ET"


def _validate_pdf(content: bytes, manifest: dict[str, Any]) -> None:
    if not content.startswith(b"%PDF-1.4\n") or not content.endswith(b"%%EOF\n"):
        raise SubmissionError("delivery PDF is invalid")
    required = (
        b"SecureCode AI",
        b"M-A2026 Academic Snapshot",
        b"NOT_READY",
        SNAPSHOT_BASE_COMMIT.encode("ascii"),
        b"Evidence inventory",
    )
    if content.count(b"/Type /Page ") < 3 or any(token not in content for token in required):
        raise SubmissionError("delivery PDF content is invalid")
    if b"Primary integration" in content or b"final PDF inspection" in content:
        raise SubmissionError("delivery PDF blocker list is stale")


def _report_html(markdown: str) -> str:
    escaped = html.escape(markdown)
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>M-A2026 academic snapshot</title>'
        "<style>body{font:16px system-ui,sans-serif;line-height:1.5;margin:2rem;max-width:70rem}pre{white-space:pre-wrap;background:#f5f5f5;padding:1rem;border-radius:.4rem}</style>"
        "</head><body><h1>SecureCode AI M-A2026 academic snapshot</h1><p>Reproducible academic experiment report.</p><pre>"
        + escaped
        + "</pre></body></html>\n"
    )


def _bundle_readme() -> str:
    return """# M-A2026 delivery bundle

This directory is generated by `scripts/build_m_a2026_submission.py`. Read `report.md`, open `report.html`, or view `report.pdf`; validate the bundle with the command in `clean-replay.md`.

The delivery status is intentionally `NOT_READY`. The report records remaining instructor confirmations and final integration work without asserting G7, G9, v1.0, PROJECT CLOSED, or release readiness.
"""


def _replay_markdown() -> str:
    return """# Clean replay

Run from a clean checkout with the locked local environment. These commands do not execute corpus source or contact a model provider. Choose a new, empty destination for every build.

```powershell
.venv\\Scripts\\python.exe -I scripts\\build_m_a2026_submission.py --output <new-empty-output-directory>
.venv\\Scripts\\python.exe -I scripts\\build_m_a2026_submission.py --validate <new-empty-output-directory>
```

The submission notebook was executed with the locked project interpreter. It runs the pinned public CWE-89 composition in an ephemeral workspace, reads the recorded benchmark aggregate and redacted real-local receipt, and makes no model call. Re-execute it from a clean checkout with the locked interpreter registered as a Jupyter kernel. Build the bundle separately with the command above, compare `delivery-manifest.json` hashes with the expected checkout, and retain `NOT_READY` until every external confirmation and durable final review is recorded.
"""


def _evidence(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in EVIDENCE_PATHS:
        path = root / relative
        if not path.is_file():
            raise SubmissionError("required evidence is unavailable")
        result[relative] = _sha(_read(path))
    return result


def _deliverables(root: Path, names: tuple[str, ...]) -> dict[str, str]:
    return {name: _sha(_read(root / name)) for name in names}


def _notebook_is_executed(content: bytes) -> bool:
    cells = _json_object(content).get("cells")
    if not isinstance(cells, list):
        return False
    previous = 0
    code_cells = 0
    for cell in cells:
        if not isinstance(cell, dict) or cell.get("cell_type") != "code":
            continue
        code_cells += 1
        count = cell.get("execution_count")
        outputs = cell.get("outputs")
        if (
            not isinstance(count, int)
            or count <= previous
            or not isinstance(outputs, list)
            or not outputs
            or any(
                isinstance(output, dict) and output.get("output_type") == "error"
                for output in outputs
            )
        ):
            return False
        previous = count
    return code_cells > 0


def _destination(output: Path) -> Path:
    if not isinstance(output, Path):
        raise SubmissionError("output path is invalid")
    destination = output.resolve()
    if destination.exists() and any(destination.iterdir()):
        raise SubmissionError("output directory must be empty")
    return destination


def _git_head(root: Path) -> str:
    try:
        value = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        raise SubmissionError("repository commit is unavailable") from None
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise SubmissionError("repository commit is invalid")
    return value


def _read(path: Path) -> bytes:
    try:
        value = path.read_bytes()
    except OSError:
        raise SubmissionError("required artifact cannot be read") from None
    if not value or len(value) > MAX_OUTPUT_BYTES:
        raise SubmissionError("artifact size is invalid")
    return value


def _write(path: Path, content: bytes) -> None:
    if not content or len(content) > MAX_OUTPUT_BYTES:
        raise SubmissionError("output size is invalid")
    path.write_bytes(content)


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical(value: object) -> bytes:
    content = json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
    content = re.sub(
        r'"([0-9a-f]{40}|[0-9a-f]{64})"',
        lambda match: f'"\\u{ord(match.group(1)[0]):04x}{match.group(1)[1:]}"',
        content,
    )
    return content.encode("ascii") + b"\n"


def _json_object(content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SubmissionError("JSON document is invalid") from None
    if not isinstance(value, dict):
        raise SubmissionError("JSON document is invalid")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build or validate the M-A2026 snapshot.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--output", type=Path)
    group.add_argument("--validate", type=Path)
    arguments = parser.parse_args(argv)
    try:
        value = (
            build_submission(arguments.output)
            if arguments.output is not None
            else validate_submission(arguments.validate)
        )
    except SubmissionError as error:
        print(json.dumps({"status": "ERROR", "code": str(error)}, sort_keys=True))
        return 2
    print(json.dumps({"status": "OK", "task_id": value.get("task_id")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
