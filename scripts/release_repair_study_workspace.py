"""Build isolated case checkouts and execute the product repair flow."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from securecode_ai.adapters.local_product_runner_config import _git
from securecode_ai.adapters.local_repair import (
    propose_local_repairs,
    validate_local_repair_artifact,
)
from securecode_ai.adapters.local_repair_contracts import confirmed_blocking_findings
from securecode_ai.adapters.local_repair_validation import FailClosedLocalRepairValidationPort
from securecode_ai.cli.repair import RepairFormat
from securecode_ai.cli.scan import ProductScanArguments, execute_installed_product_scan
from securecode_ai.core.classification import FindingSeverity

from scripts.release_repair_study_contracts import (
    _GIT_TIMEOUT_SECONDS,
    _LANGUAGE_SUFFIX,
    _MAX_PATCHES_PER_CASE,
    RepairStudyError,
)
from scripts.release_repair_study_contracts import (
    sha256 as _sha256,
)
from scripts.run_release_benchmark import Case


def candidate_commit(root: Path) -> str:
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


def repair_case(
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


__all__ = ["candidate_commit", "repair_case"]
