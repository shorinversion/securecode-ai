"""Run the installed product repair path on development-split CVEfixes cases.

The study admits only exact vulnerable case bytes from the frozen manifest,
uses the installed local product scan and repair pipeline, validates proposals
in the configured isolated OCI runtime, and emits source-free JSONL evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from securecode_ai.adapters.local_product_host import load_local_product_host
from securecode_ai.adapters.local_product_runner_config import _git
from securecode_ai.adapters.local_repair import (
    propose_local_repairs,
    validate_local_repair_artifact,
)
from securecode_ai.adapters.local_repair_contracts import confirmed_blocking_findings
from securecode_ai.adapters.local_repair_validation import (
    FailClosedLocalRepairValidationPort,
)
from securecode_ai.cli.repair import RepairFormat
from securecode_ai.cli.scan import (
    ProductScanArguments,
    execute_installed_product_scan,
)
from securecode_ai.core.classification import FindingSeverity

from scripts.release_corpus_inventory import inventory_manifest
from scripts.run_release_benchmark import Case, _load_cases, _source

_LANGUAGE_SUFFIX = {
    "python": ".py",
    "javascript-typescript": ".ts",
    "go": ".go",
}
_MAX_CASES = 200
_MAX_PATCHES_PER_CASE = 50
_GIT_TIMEOUT_SECONDS = 15


class RepairStudyError(ValueError):
    """Fixed, non-echo failure for an invalid repair-study run."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _candidate_commit(root: Path) -> str:
    try:
        status = subprocess.run(
            ("git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"),
            check=True,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        ).stdout
        value = subprocess.run(
            ("git", "-C", str(root), "rev-parse", "--verify", "HEAD"),
            check=True,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        raise RepairStudyError("candidate revision is unavailable") from None
    if (
        status
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RepairStudyError("candidate revision is invalid")
    return "git-sha1:" + value


def _git_environment() -> dict[str, str]:
    permitted = {"PATH", "SYSTEMROOT", "WINDIR", "HOME", "USERPROFILE", "TMP", "TEMP"}
    values = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in permitted and type(value) is str
    }
    values.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_AUTHOR_NAME": "SecureCode AI Repair Study",
            "GIT_AUTHOR_EMAIL": "repair-study@invalid.local",
            "GIT_COMMITTER_NAME": "SecureCode AI Repair Study",
            "GIT_COMMITTER_EMAIL": "repair-study@invalid.local",
        }
    )
    return values


def _run_git(executable: Path, root: Path, *arguments: str) -> None:
    try:
        subprocess.run(
            (str(executable), "-C", str(root), *arguments),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        raise RepairStudyError("case workspace initialization failed") from None


def _materialize_case(
    *,
    root: Path,
    executable: Path,
    case: Case,
    source: str,
) -> tuple[Path, str]:
    checkout = root / "checkout"
    checkout.mkdir(mode=0o700)
    suffix = _LANGUAGE_SUFFIX.get(case.language)
    if suffix is None:
        raise RepairStudyError("case language is unsupported")
    source_path = checkout / ("case" + suffix)
    source_bytes = source.encode("utf-8", errors="strict")
    if _sha256(source_bytes) != case.content_sha256.removeprefix("sha256:"):
        raise RepairStudyError("case source identity mismatch")
    source_path.write_bytes(source_bytes)
    template = root / "empty-git-template"
    template.mkdir(mode=0o700)
    try:
        subprocess.run(
            (
                str(executable),
                "init",
                "--quiet",
                "--template",
                str(template),
                str(checkout),
            ),
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        raise RepairStudyError("case workspace initialization failed") from None
    _run_git(executable, checkout, "add", "--", source_path.name)
    _run_git(executable, checkout, "commit", "--quiet", "--no-verify", "-m", "frozen case")
    head = _git(checkout, executable, "rev-parse", "--verify", "HEAD")
    return checkout, head


def _checkout_unchanged(checkout: Path, executable: Path, expected_head: str) -> bool:
    try:
        head = _git(checkout, executable, "rev-parse", "--verify", "HEAD")
        status = _git(checkout, executable, "status", "--porcelain", "--untracked-files=all")
    except Exception:
        return False
    return head == expected_head and not status


def _repair_case(
    *,
    case: Case,
    split: str,
    source: str,
    host: Any,
    environment: dict[str, str],
    git_executable: Path,
    candidate_commit: str,
    manifest_sha256: str,
    study_plan_sha256: str,
) -> dict[str, object]:
    started = time.monotonic()
    source_sha256 = _sha256(source.encode("utf-8"))
    base: dict[str, object] = {
        "schema_version": "securecode-ai-release-repair-study-1.0",
        "candidate_commit": candidate_commit,
        "corpus_manifest_sha256": manifest_sha256,
        "study_plan_sha256": study_plan_sha256,
        "host_bundle_sha256": host.approved_bundle_sha256,
        "host_approval_record_sha256": host.approval_record_sha256,
        "artifact_manifest_sha256": host.artifact_manifest_sha256,
        "provider_profile_sha256": host.profile.canonical_content_hash(),
        "provider_kind": host.profile.provider_kind.value,
        "model_id": host.profile.model_id,
        "model_snapshot": host.profile.model_snapshot,
        "provider_timeout_seconds": host.profile.budgets.timeout_seconds,
        "provider_max_attempts": host.profile.budgets.max_attempts,
        "provider_max_total_tokens": host.profile.budgets.max_total_tokens,
        "case_id": case.case_id,
        "cwe_id": case.cwe_id,
        "language": case.language,
        "split": split,
        "expected_label": case.expected_label,
        "source_sha256": "sha256:" + source_sha256,
        "discovery_state": "not_run",
        "scan_completed": False,
        "confirmed_findings": 0,
        "repair_attempted": False,
        "proposal_blocked_count": 0,
        "patches": [],
        "checkout_unchanged": False,
        "elapsed_seconds": 0.0,
        "reason": None,
    }
    with tempfile.TemporaryDirectory(prefix="securecode-repair-study-") as directory:
        root = Path(directory).resolve()
        artifacts = root / "artifacts"
        artifacts.mkdir(mode=0o700)
        checkout, parent_head = _materialize_case(
            root=root,
            executable=git_executable,
            case=case,
            source=source,
        )
        environment["SECURECODE_AI_ARTIFACT_ROOT"] = str(artifacts)
        try:
            scan = execute_installed_product_scan(
                ProductScanArguments(
                    str(checkout), RepairFormat.JSON, None, None, FindingSeverity.HIGH
                ),
                environment=environment,
            )
            scan.require_publication()
            base["scan_completed"] = True
            findings = confirmed_blocking_findings(scan)
            base["confirmed_findings"] = len(findings)
            base["discovery_state"] = "confirmed" if findings else "no_finding"
            if not findings:
                base["reason"] = "NO_CONFIRMED_BLOCKING_FINDINGS"
                base["checkout_unchanged"] = _checkout_unchanged(
                    checkout, git_executable, parent_head
                )
                base["elapsed_seconds"] = float(time.monotonic() - started)
                return base
            base["repair_attempted"] = True
            proposal = propose_local_repairs(
                target=str(checkout),
                host=host,
                scan_result=scan,
                environment=environment,
            )
            blocked = proposal.get("blocked_findings")
            base["proposal_blocked_count"] = len(blocked) if type(blocked) is list else 0
            selectors = proposal.get("artifact_selectors")
            if type(selectors) is not list or len(selectors) > _MAX_PATCHES_PER_CASE:
                base["discovery_state"] = "failed"
                base["reason"] = "PROPOSAL_RESULT_INVALID"
                base["checkout_unchanged"] = _checkout_unchanged(
                    checkout, git_executable, parent_head
                )
                base["elapsed_seconds"] = float(time.monotonic() - started)
                return base
            patches: list[dict[str, object]] = []
            for selector in selectors:
                if type(selector) is not str or len(selector) > 128:
                    patches.append(
                        {
                            "state": "failed",
                            "reason": "PATCH_SELECTOR_INVALID",
                            "checkout_unchanged": _checkout_unchanged(
                                checkout, git_executable, parent_head
                            ),
                        }
                    )
                    continue
                try:
                    validation = validate_local_repair_artifact(
                        target=str(checkout),
                        selector=selector,
                        host=host,
                        environment=environment,
                        validation_port=FailClosedLocalRepairValidationPort(environment),
                    )
                except Exception:
                    patches.append(
                        {
                            "state": "INDETERMINATE",
                            "reason": "VALIDATION_FAILED",
                            "checkout_unchanged": _checkout_unchanged(
                                checkout, git_executable, parent_head
                            ),
                        }
                    )
                    continue
                patches.append(
                    {
                        "state": str(validation.get("validation_outcome", "INDETERMINATE")),
                        "artifact_sha256": validation.get("artifact_sha256"),
                        "validation_result_sha256": validation.get("validation_result_sha256"),
                        "remediation_data_only": validation.get("remediation_data_only"),
                        "remediation_sandbox_receipt_sha256": validation.get(
                            "remediation_sandbox_receipt_sha256"
                        ),
                        "remediation_sandbox_validated": validation.get(
                            "remediation_sandbox_validated"
                        ),
                        "remediation_oracle_validated": validation.get(
                            "remediation_oracle_validated"
                        ),
                        "remediation_existing_regression_passed": validation.get(
                            "remediation_existing_regression_passed"
                        ),
                        "remediation_no_new_blocking_regressions": validation.get(
                            "remediation_no_new_blocking_regressions"
                        ),
                        "runtime_image_digest": validation.get("runtime_image_digest"),
                        "preparation_receipt_sha256": validation.get("preparation_receipt_sha256"),
                        "validation_gates": validation.get("validation_gates", []),
                        "checkout_unchanged": _checkout_unchanged(
                            checkout, git_executable, parent_head
                        ),
                    }
                )
            base["patches"] = patches
            if not selectors:
                base["reason"] = "NO_PATCH_PROPOSAL"
            base["checkout_unchanged"] = _checkout_unchanged(checkout, git_executable, parent_head)
        except Exception:
            base["discovery_state"] = "failed"
            base["reason"] = "PRODUCT_REPAIR_PIPELINE_FAILED"
            base["checkout_unchanged"] = _checkout_unchanged(checkout, git_executable, parent_head)
    base["elapsed_seconds"] = float(time.monotonic() - started)
    return base


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

    candidate_commit = _candidate_commit(Path(__file__).resolve().parents[1])
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
    _atomic_write(
        output,
        _study_document(
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
                _atomic_write(
                    output,
                    _study_document(
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
                _atomic_write(
                    output,
                    _study_document(
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
                    _repair_case(
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
            _atomic_write(
                output,
                _study_document(
                    records,
                    selected,
                    candidate_commit,
                    manifest_sha256,
                    split,
                    "RUNNING",
                    study_plan_sha256,
                ),
            )
    report = _study_document(
        records,
        selected,
        candidate_commit,
        manifest_sha256,
        split,
        "COMPLETED" if len(records) == len(selected) else "INCOMPLETE",
        study_plan_sha256,
    )
    _atomic_write(output, report)
    summary = report.get("aggregate")
    if type(summary) is not dict:
        raise RepairStudyError("repair study aggregate is invalid")
    return summary


def _study_document(
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
            "proposed_patches": len(_patch_records(selected)),
            "sandbox_validated_patches": _patch_count(
                selected, lambda patch: patch.get("remediation_sandbox_validated") is True
            ),
            "oracle_validated_patches": _patch_count(
                selected, lambda patch: patch.get("remediation_oracle_validated") is True
            ),
            "existing_regression_passes": _patch_count(
                selected,
                lambda patch: patch.get("remediation_existing_regression_passed") is True,
            ),
            "no_new_blocking_regressions": _patch_count(
                selected,
                lambda patch: patch.get("remediation_no_new_blocking_regressions") is True,
            ),
            "unsafe_validated_patches": _patch_count(
                selected,
                lambda patch: (
                    patch.get("remediation_sandbox_validated") is True
                    and patch.get("remediation_oracle_validated") is False
                ),
            ),
            "regression_patches": _patch_count(
                selected,
                lambda patch: (
                    patch.get("remediation_sandbox_validated") is True
                    and (
                        patch.get("remediation_existing_regression_passed") is False
                        or patch.get("remediation_no_new_blocking_regressions") is False
                    )
                ),
            ),
            "correct_and_secure_repairs": _patch_count(
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


def _patch_records(records: list[dict[str, object]]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for record in records:
        patches = record.get("patches")
        if not isinstance(patches, list):
            continue
        results.extend(patch for patch in patches if isinstance(patch, dict))
    return results


def _patch_count(
    records: list[dict[str, object]],
    predicate: Any,
) -> int:
    return sum(predicate(patch) for patch in _patch_records(records))


def _atomic_write(path: Path, document: dict[str, object]) -> None:
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
