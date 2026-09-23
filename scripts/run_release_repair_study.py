"""Run the installed product repair path on development-split CVEfixes cases.

The study admits only exact vulnerable case bytes from the frozen manifest,
uses the installed local product scan and repair pipeline, validates proposals
in the configured isolated OCI runtime, and emits source-free JSONL evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

from securecode_ai.adapters.local_product_host import load_local_product_host

from scripts.release_corpus_inventory import inventory_manifest
from scripts.release_repair_study_contracts import RepairStudyError
from scripts.release_repair_study_contracts import sha256 as _sha256
from scripts.release_repair_study_report import atomic_write, study_document
from scripts.release_repair_study_workspace import (
    candidate_commit as resolve_candidate_commit,
)
from scripts.release_repair_study_workspace import (
    repair_case,
)
from scripts.run_release_benchmark import _load_cases, _source

_MAX_CASES = 200


def run(
    *,
    manifest: Path,
    database: Path,
    output: Path,
    split: str,
    limit: int,
) -> dict[str, object]:
    if (
        split not in {"development", "calibration"}
        or type(limit) is not int
        or not 1 <= limit <= _MAX_CASES
        or not manifest.is_file()
        or manifest.is_symlink()
        or not database.is_file()
        or database.is_symlink()
    ):
        raise RepairStudyError("repair study configuration is invalid")
    manifest_bytes = manifest.read_bytes()
    inventory = inventory_manifest(manifest)
    if inventory.get("release_candidate_eligible") is not True:
        raise RepairStudyError("frozen corpus inventory is not eligible")
    document = json.loads(manifest_bytes)
    raw_cases = document["datasets"][0]["cases"]
    metadata = {item["case_id"]: item for item in raw_cases}
    cases = _load_cases(manifest, None)
    selected_ids = {
        case_id
        for case_id, item in metadata.items()
        if item.get("split") == split and item.get("expected_label") == "vulnerable"
    }
    selected = tuple(case for case in cases if case.case_id in selected_ids)[:limit]
    if not selected:
        raise RepairStudyError("no eligible vulnerable cases")

    candidate_commit = resolve_candidate_commit(Path(__file__).resolve().parents[1])
    manifest_sha256 = "sha256:" + _sha256(manifest_bytes)
    host = load_local_product_host()
    plan = {
        "schema_version": "securecode-ai-release-repair-study-plan-1.0",
        "candidate_commit": candidate_commit,
        "corpus_manifest_sha256": manifest_sha256,
        "split": split,
        "filters": {"expected_label": "vulnerable"},
        "limit": limit,
        "host_bundle_sha256": host.approved_bundle_sha256,
        "profile_sha256": host.profile.canonical_content_hash(),
        "artifact_manifest_sha256": host.artifact_manifest_sha256,
    }
    study_plan_sha256 = "sha256:" + _sha256(
        json.dumps(
            plan, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
    )
    git_digest = host.artifact_manifest.get("git_executable_sha256", "")
    from securecode_ai.adapters.local_product_host import verify_local_git_executable

    git_executable = verify_local_git_executable(git_digest)
    environment = dict(os.environ)
    database_uri = database.resolve(strict=True).as_uri() + "?mode=ro&immutable=1"
    records: list[dict[str, object]] = []
    if output.exists() or output.with_name(output.name + ".tmp").exists():
        raise RepairStudyError("repair study output already exists")
    atomic_write(
        output,
        study_document(
            records,
            selected,
            candidate_commit,
            manifest_sha256,
            split,
            "RUNNING",
            study_plan_sha256,
        ),
    )
    with sqlite3.connect(database_uri, uri=True) as connection:
        for case in selected:
            raw = metadata[case.case_id]
            if raw.get("topology") != "single-file":
                records.append(
                    {
                        "schema_version": "securecode-ai-release-repair-study-1.0",
                        "candidate_commit": candidate_commit,
                        "corpus_manifest_sha256": manifest_sha256,
                        "study_plan_sha256": study_plan_sha256,
                        "case_id": case.case_id,
                        "cwe_id": case.cwe_id,
                        "language": case.language,
                        "split": split,
                        "expected_label": case.expected_label,
                        "source_sha256": case.content_sha256,
                        "discovery_state": "not_run",
                        "scan_completed": False,
                        "confirmed_findings": 0,
                        "repair_attempted": False,
                        "proposal_blocked_count": 0,
                        "patches": [],
                        "checkout_unchanged": False,
                        "elapsed_seconds": 0.0,
                        "reason": "UNSUPPORTED_TOPOLOGY",
                    }
                )
                atomic_write(
                    output,
                    study_document(
                        records,
                        selected,
                        candidate_commit,
                        manifest_sha256,
                        split,
                        "RUNNING",
                        study_plan_sha256,
                    ),
                )
                continue
            try:
                source = _source(connection, case)
            except Exception:
                records.append(
                    {
                        "schema_version": "securecode-ai-release-repair-study-1.0",
                        "candidate_commit": candidate_commit,
                        "corpus_manifest_sha256": manifest_sha256,
                        "study_plan_sha256": study_plan_sha256,
                        "case_id": case.case_id,
                        "cwe_id": case.cwe_id,
                        "language": case.language,
                        "split": split,
                        "expected_label": case.expected_label,
                        "source_sha256": case.content_sha256,
                        "discovery_state": "failed",
                        "scan_completed": False,
                        "confirmed_findings": 0,
                        "repair_attempted": False,
                        "proposal_blocked_count": 0,
                        "patches": [],
                        "checkout_unchanged": False,
                        "elapsed_seconds": 0.0,
                        "reason": "FROZEN_SOURCE_UNAVAILABLE",
                    }
                )
                atomic_write(
                    output,
                    study_document(
                        records,
                        selected,
                        candidate_commit,
                        manifest_sha256,
                        split,
                        "RUNNING",
                        study_plan_sha256,
                    ),
                )
                continue
            try:
                records.append(
                    repair_case(
                        case=case,
                        split=split,
                        source=source,
                        host=host,
                        environment=environment.copy(),
                        git_executable=git_executable,
                        candidate_commit=candidate_commit,
                        manifest_sha256=manifest_sha256,
                        study_plan_sha256=study_plan_sha256,
                    )
                )
            except Exception:
                records.append(
                    {
                        "schema_version": "securecode-ai-release-repair-study-1.0",
                        "candidate_commit": candidate_commit,
                        "corpus_manifest_sha256": manifest_sha256,
                        "study_plan_sha256": study_plan_sha256,
                        "case_id": case.case_id,
                        "cwe_id": case.cwe_id,
                        "language": case.language,
                        "split": split,
                        "expected_label": case.expected_label,
                        "source_sha256": case.content_sha256,
                        "discovery_state": "failed",
                        "scan_completed": False,
                        "confirmed_findings": 0,
                        "repair_attempted": False,
                        "proposal_blocked_count": 0,
                        "patches": [],
                        "checkout_unchanged": False,
                        "elapsed_seconds": 0.0,
                        "reason": "PRODUCT_REPAIR_PIPELINE_FAILED",
                    }
                )
            atomic_write(
                output,
                study_document(
                    records,
                    selected,
                    candidate_commit,
                    manifest_sha256,
                    split,
                    "RUNNING",
                    study_plan_sha256,
                ),
            )
    report = study_document(
        records,
        selected,
        candidate_commit,
        manifest_sha256,
        split,
        "COMPLETED" if len(records) == len(selected) else "INCOMPLETE",
        study_plan_sha256,
    )
    atomic_write(output, report)
    summary = report.get("aggregate")
    if type(summary) is not dict:
        raise RepairStudyError("repair study aggregate is invalid")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--split", choices=("development", "calibration"), default="development")
    parser.add_argument("--limit", type=int, default=_MAX_CASES)
    arguments = parser.parse_args(argv)
    try:
        summary = run(
            manifest=arguments.manifest,
            database=arguments.database,
            output=arguments.output,
            split=arguments.split,
            limit=arguments.limit,
        )
    except RepairStudyError:
        print("repair study rejected or incomplete", file=sys.stderr)
        return 5
    except Exception:
        print("repair study could not complete", file=sys.stderr)
        return 5
    print(json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
