"""Exact-head composition of patch artifacts with the Core OCI validation ladder."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from securecode_ai.contracts import (
    ProducerRef,
    ResourceUsage,
    ValidationGateOutcome,
    ValidationOutcome,
    ValidationResult,
)
from securecode_ai.core.regression import RegressionResult
from securecode_ai.core.sandbox import SandboxProfile
from securecode_ai.core.validation import (
    ValidationLadderResult,
    ValidationLadderRequest,
    ValidationStage,
    run_validation_ladder,
)

from .local_product_host import LocalProductHost, verify_local_git_executable
from .local_product_runner_config import _git
from .oci_sandbox import HardenedOciSandboxDriver, OciRuntime
from .patch_artifact import StoredPatchArtifact


class LocalRepairValidationError(ValueError):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__("local repair validation is unavailable")
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class PreparedLocalOciValidation:
    """Trusted runtime material prepared without touching the inspected checkout."""

    runtime: OciRuntime
    image_digest: str
    command_allowlist: dict[str, tuple[str, ...]]
    seccomp_profile_id: str
    sandbox_profile: SandboxProfile
    fixed_head_sha: str
    fixed_regression: RegressionResult
    stage_resources: tuple[ResourceUsage, ...]
    preparation_receipt_sha256: str | None = None

    def __post_init__(self) -> None:
        if (
            not all(
                callable(getattr(self.runtime, name, None)) for name in ("attest", "run", "cleanup")
            )
            or type(self.command_allowlist) is not dict
            or set(self.command_allowlist) != {stage.value for stage in ValidationStage}
            or type(self.sandbox_profile) is not SandboxProfile
            or type(self.fixed_regression) is not RegressionResult
            or type(self.stage_resources) is not tuple
            or len(self.stage_resources) != len(ValidationStage)
            or any(type(item) is not ResourceUsage for item in self.stage_resources)
            or (
                self.preparation_receipt_sha256 is not None
                and (
                    type(self.preparation_receipt_sha256) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", self.preparation_receipt_sha256) is None
                )
            )
        ):
            raise LocalRepairValidationError("VALIDATION_PREPARATION_INVALID")


class LocalRepairValidationPort(Protocol):
    """Host port that binds immutable Git and patch inputs into an ephemeral OCI runtime.

    The returned runtime must expose the prepared inputs only inside its isolated
    workspace.  It must never mount the inspected checkout read-write and must
    compute ``fixed_head_sha`` from the patched ephemeral tree.
    """

    def prepare(
        self,
        *,
        repository_objects: Path,
        parent_head_sha: str,
        patch: StoredPatchArtifact,
        git_executable: Path,
    ) -> PreparedLocalOciValidation: ...


class FailClosedLocalRepairValidationPort:
    """Installed rootless OCI default which remains closed without pinned runtime input."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = environment

    def prepare(
        self,
        *,
        repository_objects: Path,
        parent_head_sha: str,
        patch: StoredPatchArtifact,
        git_executable: Path,
    ) -> PreparedLocalOciValidation:
        from .local_repair_oci_provider import InstalledLocalOciValidationPort

        return InstalledLocalOciValidationPort(self._environment).prepare(
            repository_objects=repository_objects,
            parent_head_sha=parent_head_sha,
            patch=patch,
            git_executable=git_executable,
        )


def validate_local_patch(
    *,
    target: str,
    host: LocalProductHost,
    patch: StoredPatchArtifact,
    port: LocalRepairValidationPort,
    validated_sink: Callable[[ValidationResult], None] | None = None,
    ladder_sink: Callable[[ValidationLadderResult], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    on_cancel: Callable[[Callable[[], None]], None] | None = None,
) -> dict[str, object]:
    _check_cancelled(cancelled)
    checkout, objects, git, head = _exact_checkout(target, host)
    candidate = patch.architect_result.patch_candidate
    expected_repository_id = "local-" + hashlib.sha256(str(checkout).encode()).hexdigest()[:32]
    if (
        candidate.repository_revision.head_sha != head
        or candidate.repository_revision.repository_id != expected_repository_id
        or candidate.repository_revision.tenant_id != host.policy.tenant_scope
    ):
        raise LocalRepairValidationError("PATCH_HEAD_MISMATCH")
    prepared: PreparedLocalOciValidation | None = None
    result = None
    failure: Exception | None = None
    try:
        prepared = port.prepare(
            repository_objects=objects,
            parent_head_sha=head,
            patch=patch,
            git_executable=git,
        )
        if type(prepared) is not PreparedLocalOciValidation:
            raise LocalRepairValidationError("VALIDATION_PREPARATION_INVALID")
        if on_cancel is not None:
            cancel_runtime = getattr(prepared.runtime, "cancel", None)
            if callable(cancel_runtime):
                on_cancel(cancel_runtime)
        _check_cancelled(cancelled)
        if (
            prepared.fixed_head_sha == head
            or prepared.fixed_regression.descriptor_id != patch.regression.descriptor_id
            or prepared.fixed_regression.evaluated_head_sha != prepared.fixed_head_sha
        ):
            raise LocalRepairValidationError("VALIDATION_IDENTITY_MISMATCH")
        driver = HardenedOciSandboxDriver(
            runtime=prepared.runtime,
            image_digest=prepared.image_digest,
            command_allowlist=prepared.command_allowlist,
            seccomp_profile_id=prepared.seccomp_profile_id,
        )
        producer = ProducerRef(
            schema_version="0.2.0",
            producer_id="installed-local-validator",
            producer_version="1.0.0",
            producer_sha256=prepared.sandbox_profile.profile_sha256,
        )
        result = run_validation_ladder(
            ValidationLadderRequest(
                validation_id="validation-" + candidate.unified_diff_sha256[:48],
                architect_result=patch.architect_result,
                fixed_head_sha=prepared.fixed_head_sha,
                sandbox_profile=prepared.sandbox_profile,
                producer=producer,
                fixed_regression=prepared.fixed_regression,
                stage_resources=prepared.stage_resources,
            ),
            driver,
        )
        _check_cancelled(cancelled)
    except Exception as error:
        failure = error
    finally:
        if prepared is not None:
            close = getattr(prepared.runtime, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as error:
                    if failure is None:
                        failure = error
    after = _read_head(checkout, git)
    if after != head:
        raise LocalRepairValidationError("CHECKOUT_HEAD_CHANGED")
    if failure is not None:
        if isinstance(failure, LocalRepairValidationError):
            raise failure
        raise LocalRepairValidationError("VALIDATION_EXECUTION_FAILED") from None
    if prepared is None or result is None:
        raise LocalRepairValidationError("VALIDATION_EXECUTION_FAILED")
    if ladder_sink is not None:
        ladder_sink(result)
    validation = result.validation
    authoritative_gates = {
        receipt.stage: receipt.gate.gate_outcome
        for receipt in result.stages
        if receipt.authoritative
    }
    oracle_validated = all(
        authoritative_gates.get(stage) is ValidationGateOutcome.PASSED
        for stage in (ValidationStage.SECURITY_POC, ValidationStage.SECURITY_POC_PLUS)
    )
    existing_regression_passed = (
        authoritative_gates.get(ValidationStage.EXISTING_TESTS) is ValidationGateOutcome.PASSED
    )
    no_new_blocking_regressions = all(
        authoritative_gates.get(stage) is ValidationGateOutcome.PASSED
        for stage in (
            ValidationStage.POST_PATCH_SCAN,
            ValidationStage.REGRESSION_SCAN,
            ValidationStage.RESOURCE_POLICY,
        )
    )
    if validation.validation_outcome is ValidationOutcome.VALIDATED and validated_sink is not None:
        validated_sink(validation)
    human_approval_pending = validation.validation_outcome is ValidationOutcome.VALIDATED
    if validation.validation_outcome in {
        ValidationOutcome.VALIDATED,
        ValidationOutcome.FAILED,
        ValidationOutcome.INDETERMINATE,
    }:
        exit_code = 2
    else:
        exit_code = 3
    return {
        "exit_code": exit_code,
        "artifact_selector": patch.selector,
        "artifact_sha256": candidate.unified_diff_sha256,
        "parent_head_sha": head,
        "validated_head_sha": prepared.fixed_head_sha,
        "validation_id": validation.validation_id,
        "validation_outcome": validation.validation_outcome.value,
        "approval_state": "PENDING" if human_approval_pending else None,
        "reason": "HUMAN_APPROVAL_REQUIRED" if human_approval_pending else None,
        "validation_result_sha256": validation.result_sha256,
        "remediation_data_only": True,
        "remediation_sandbox_receipt_sha256": validation.result_sha256,
        "remediation_sandbox_validated": validation.validation_outcome
        is ValidationOutcome.VALIDATED,
        "remediation_oracle_validated": oracle_validated,
        "remediation_existing_regression_passed": existing_regression_passed,
        "remediation_no_new_blocking_regressions": no_new_blocking_regressions,
        "validation_gates": [
            {
                "stage": receipt.stage.value,
                "outcome": receipt.gate.gate_outcome.value,
                "authoritative": receipt.authoritative,
            }
            for receipt in result.stages
        ],
        "runtime_image_digest": prepared.image_digest,
        "preparation_receipt_sha256": prepared.preparation_receipt_sha256,
        "first_failed_stage": result.first_failed_stage.value
        if result.first_failed_stage
        else None,
        "stage_receipt_sha256": [
            stage.sandbox_receipt.receipt_sha256
            for stage in result.stages
            if stage.sandbox_receipt is not None
        ],
    }


def _exact_checkout(target: str, host: LocalProductHost) -> tuple[Path, Path, Path, str]:
    root = Path(target).absolute()
    if not root.is_dir() or root.is_symlink() or "\x00" in target:
        raise LocalRepairValidationError("VALIDATION_TARGET_INVALID")
    try:
        git = verify_local_git_executable(host.artifact_manifest.get("git_executable_sha256", ""))
        checkout = Path(_git(root, git, "rev-parse", "--show-toplevel")).resolve()
        if checkout != root.resolve():
            raise ValueError
        head = _read_head(checkout, git)
        objects = Path(_git(checkout, git, "rev-parse", "--git-path", "objects"))
        if not objects.is_absolute():
            objects = checkout / objects
        objects = objects.absolute()
        if not objects.is_dir() or objects.is_symlink():
            raise ValueError
    except Exception:
        raise LocalRepairValidationError("VALIDATION_GIT_UNAVAILABLE") from None
    return checkout, objects, git, head


def _check_cancelled(cancelled: Callable[[], bool] | None) -> None:
    """Convert cancellation callback failures into a fail-closed validation result."""

    if cancelled is None:
        return
    try:
        requested = cancelled()
    except Exception:
        raise LocalRepairValidationError("VALIDATION_CANCELLATION_UNAVAILABLE") from None
    if requested:
        raise LocalRepairValidationError("VALIDATION_CANCELLED")


def _read_head(checkout: Path, git: Path) -> str:
    try:
        return _git(checkout, git, "rev-parse", "--verify", "HEAD")
    except Exception:
        raise LocalRepairValidationError("VALIDATION_GIT_UNAVAILABLE") from None


__all__ = [
    "FailClosedLocalRepairValidationPort",
    "LocalRepairValidationError",
    "LocalRepairValidationPort",
    "PreparedLocalOciValidation",
    "validate_local_patch",
]
