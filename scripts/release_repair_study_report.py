"""Source-free, deterministic repair-study reports."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from scripts.release_repair_study_contracts import RepairStudyError
from scripts.release_repair_study_contracts import sha256 as _sha256
from scripts.run_release_benchmark import Case


def study_document(
    records: list[dict[str, object]],
    planned: tuple[Case, ...],
    candidate_commit: str,
    manifest_sha256: str,
    split: str,
    state: str,
    study_plan_sha256: str,
) -> dict[str, object]:
    def metric_counts(selected: list[dict[str, object]]) -> dict[str, object]:
        return {
            "scan_completed_cases": sum(item.get("scan_completed") is True for item in selected),
            "discovery_confirmed_cases": sum(
                item.get("discovery_state") == "confirmed" for item in selected
            ),
            "repair_attempted_cases": sum(
                item.get("repair_attempted") is True for item in selected
            ),
            "proposal_blocked_findings": sum(
                count
                for item in selected
                if type(count := item.get("proposal_blocked_count")) is int and count >= 0
            ),
            "proposed_patches": len(patch_records(selected)),
            "sandbox_validated_patches": patch_count(
                selected, lambda patch: patch.get("remediation_sandbox_validated") is True
            ),
            "oracle_validated_patches": patch_count(
                selected, lambda patch: patch.get("remediation_oracle_validated") is True
            ),
            "existing_regression_passes": patch_count(
                selected,
                lambda patch: patch.get("remediation_existing_regression_passed") is True,
            ),
            "no_new_blocking_regressions": patch_count(
                selected,
                lambda patch: patch.get("remediation_no_new_blocking_regressions") is True,
            ),
            "unsafe_validated_patches": patch_count(
                selected,
                lambda patch: (
                    patch.get("remediation_sandbox_validated") is True
                    and patch.get("remediation_oracle_validated") is False
                ),
            ),
            "regression_patches": patch_count(
                selected,
                lambda patch: (
                    patch.get("remediation_sandbox_validated") is True
                    and (
                        patch.get("remediation_existing_regression_passed") is False
                        or patch.get("remediation_no_new_blocking_regressions") is False
                    )
                ),
            ),
            "correct_and_secure_repairs": patch_count(
                selected,
                lambda patch: all(
                    patch.get(field) is True
                    for field in (
                        "remediation_data_only",
                        "remediation_sandbox_validated",
                        "remediation_oracle_validated",
                        "remediation_existing_regression_passed",
                        "remediation_no_new_blocking_regressions",
                        "checkout_unchanged",
                    )
                ),
            ),
        }

    def partition_counts(key: str, values: set[str]) -> dict[str, dict[str, object]]:
        return {
            value: {
                "planned_cases": sum(getattr(case, key) == value for case in planned),
                "recorded_cases": sum(item.get(key) == value for item in records),
                **metric_counts([item for item in records if item.get(key) == value]),
            }
            for value in sorted(values)
        }

    summary: dict[str, object] = {
        "schema_version": "securecode-ai-release-repair-study-aggregate-1.0",
        "state": state,
        "candidate_commit": candidate_commit,
        "corpus_manifest_sha256": manifest_sha256,
        "study_plan_sha256": study_plan_sha256,
        "split": split,
        "planned_cases": len(planned),
        "recorded_cases": len(records),
        "unrecorded_cases": max(0, len(planned) - len(records)),
        **metric_counts(records),
        "per_language": partition_counts("language", {case.language for case in planned}),
        "per_cwe": partition_counts("cwe_id", {case.cwe_id for case in planned}),
        "reason_counts": {
            reason: sum(item.get("reason") == reason for item in records)
            for reason in sorted(
                {str(item["reason"]) for item in records if item.get("reason") is not None}
            )
        },
        "records_sha256": "sha256:"
        + _sha256(
            b"".join(
                json.dumps(item, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
                for item in records
            )
        ),
    }
    return {"aggregate": summary, "records": records}


def patch_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for record in records:
        patches = record.get("patches")
        if not isinstance(patches, list):
            continue
        results.extend(patch for patch in patches if isinstance(patch, dict))
    return results


def patch_count(
    records: list[dict[str, object]],
    predicate: Any,
) -> int:
    return sum(predicate(patch) for patch in patch_records(records))


def atomic_write(path: Path, document: dict[str, object]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    try:
        payload = (
            json.dumps(
                document,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                indent=2,
            ).encode("ascii")
            + b"\n"
        )
    except (TypeError, ValueError):
        raise RepairStudyError("repair study document is invalid") from None
    if path.is_symlink() or temporary.is_symlink() or len(payload) > 16 * 1024 * 1024:
        raise RepairStudyError("repair study output path is invalid")
    created = False
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("xb") as stream:
            created = True
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    except FileExistsError:
        raise RepairStudyError("repair study output already has a pending write") from None
    except OSError:
        if created:
            temporary.unlink(missing_ok=True)
        raise RepairStudyError("repair study output could not be committed") from None


__all__ = ["atomic_write", "study_document"]
