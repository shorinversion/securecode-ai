from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from scripts.release_repair_study_report import atomic_write, study_document
from scripts.run_release_benchmark import Case

SHA = "sha256:" + "a" * 64


def _case(case_id: str, language: str, cwe_id: str) -> Case:
    return Case(
        case_id=case_id,
        content_sha256=SHA,
        cwe_id=cwe_id,
        expected_label="vulnerable",
        language=language,
        lineage=case_id.rsplit(":", 1)[0],
    )


def test_study_aggregate_keeps_unrecorded_cases_and_repair_denominators() -> None:
    planned = (
        _case("cvefixes:1:before", "python", "CWE-89"),
        _case("cvefixes:2:before", "go", "CWE-22"),
    )
    patch = {
        "state": "VALIDATED",
        "remediation_data_only": True,
        "remediation_sandbox_validated": True,
        "remediation_oracle_validated": True,
        "remediation_existing_regression_passed": True,
        "remediation_no_new_blocking_regressions": True,
        "checkout_unchanged": True,
    }
    record = {
        "case_id": planned[0].case_id,
        "language": planned[0].language,
        "cwe_id": planned[0].cwe_id,
        "scan_completed": True,
        "discovery_state": "confirmed",
        "repair_attempted": True,
        "proposal_blocked_count": 0,
        "patches": [patch],
        "reason": None,
    }

    report = study_document(
        [record],
        planned,
        "git-sha1:" + "b" * 40,
        SHA,
        "development",
        "INCOMPLETE",
        "sha256:" + "c" * 64,
    )
    aggregate = cast(dict[str, object], report["aggregate"])

    assert aggregate["planned_cases"] == 2
    assert aggregate["recorded_cases"] == 1
    assert aggregate["unrecorded_cases"] == 1
    assert aggregate["scan_completed_cases"] == 1
    assert aggregate["repair_attempted_cases"] == 1
    assert aggregate["proposed_patches"] == 1
    assert aggregate["correct_and_secure_repairs"] == 1
    languages = cast(dict[str, dict[str, object]], aggregate["per_language"])
    cwes = cast(dict[str, dict[str, object]], aggregate["per_cwe"])
    assert languages["go"]["planned_cases"] == 1
    assert languages["go"]["recorded_cases"] == 0
    assert cwes["CWE-22"]["recorded_cases"] == 0


def test_atomic_report_is_deterministic_and_canonical(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    document: dict[str, object] = {"records": [], "state": "RUNNING"}
    atomic_write(target, document)
    first = target.read_bytes()
    atomic_write(target, document)

    assert target.read_bytes() == first
    assert first.endswith(b"\n")
    assert json.loads(first) == document
    assert not target.with_name(target.name + ".tmp").exists()
