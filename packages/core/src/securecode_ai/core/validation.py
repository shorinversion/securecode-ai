"""Ordered, fail-closed P4 validation ladder over the P4.5 sandbox port."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    PatchCandidate,
    ProducerRef,
    ResourceUsage,
    ValidationGateOutcome,
    ValidationGateResult,
    ValidationOutcome,
    ValidationResult,
)

from .architect import ArchitectPatchResult, PatchRationaleReceipt
from .regression import (
    RegressionDisposition,
    RegressionResult,
    RegressionRevisionRole,
)
from .sandbox import (
    SandboxAttestation,
    SandboxCommand,
    SandboxDriver,
    SandboxError,
    SandboxErrorCode,
    SandboxExecutionReceipt,
    SandboxObservation,
    SandboxOutcome,
    SandboxProfile,
    SandboxTeardownReceipt,
    run_in_sandbox,
)

_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_SCHEMA_VERSION: Final = "1.0.0"
_HASH_DOMAIN: Final = b"securecode-ai/validation-ladder/v1\x00"


class ValidationLadderErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    RESOURCE_BUDGET_EXCEEDED = "RESOURCE_BUDGET_EXCEEDED"
    SANDBOX_FAILURE = "SANDBOX_FAILURE"


class ValidationLadderError(ValueError):
    """Fixed, source-free contract error."""

    __slots__ = ("code",)

    def __init__(self, code: ValidationLadderErrorCode) -> None:
        if type(code) is not ValidationLadderErrorCode:
            raise TypeError("validation ladder error code is invalid")
        self.code = code
        super().__init__("validation ladder contract validation failed")
        self.__cause__ = None
        self.__context__ = None


class ValidationStage(StrEnum):
    DIFF_PARSE = "validation-diff-parse"
    EPHEMERAL_CHECKOUT = "validation-ephemeral-checkout"
    PATCH_APPLY = "validation-patch-apply"
    LANGUAGE_POLICY = "validation-language-policy"
    COMPILE_TYPES = "validation-compile-types"
    EXISTING_TESTS = "validation-existing-tests"
    SECURITY_POC = "validation-security-poc"
    SECURITY_POC_PLUS = "validation-security-poc-plus"
    POST_PATCH_SCAN = "validation-post-patch-scan"
    REGRESSION_SCAN = "validation-regression-scan"
    RESOURCE_POLICY = "validation-resource-policy"


_STAGES: Final = tuple(ValidationStage)


@dataclass(frozen=True, slots=True)
class ValidationLadderRequest:
    """Metadata-only request; every command is executed only by ``SandboxDriver``."""

    validation_id: str
    architect_result: ArchitectPatchResult
    fixed_head_sha: str
    sandbox_profile: SandboxProfile
    producer: ProducerRef
    fixed_regression: RegressionResult
    stage_resources: tuple[ResourceUsage, ...]
    run_non_authoritative_diagnostics: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.validation_id) is not str
            or _ID.fullmatch(self.validation_id) is None
            or type(self.fixed_head_sha) is not str
            or _COMMIT_SHA.fullmatch(self.fixed_head_sha) is None
            or type(self.architect_result) is not ArchitectPatchResult
            or type(self.sandbox_profile) is not SandboxProfile
            or type(self.producer) is not ProducerRef
            or type(self.fixed_regression) is not RegressionResult
            or type(self.stage_resources) is not tuple
            or len(self.stage_resources) != len(_STAGES)
            or any(type(value) is not ResourceUsage for value in self.stage_resources)
            or type(self.run_non_authoritative_diagnostics) is not bool
        ):
            raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)


@dataclass(frozen=True, slots=True)
class ValidationStageReceipt:
    """One stage receipt preserves sandbox/profile/resource linkage without output bytes."""

    stage: ValidationStage
    gate: ValidationGateResult
    sandbox_receipt: SandboxExecutionReceipt | None
    authoritative: bool

    def __post_init__(self) -> None:
        if (
            type(self.stage) is not ValidationStage
            or type(self.gate) is not ValidationGateResult
            or (
                self.sandbox_receipt is not None
                and type(self.sandbox_receipt) is not SandboxExecutionReceipt
            )
            or type(self.authoritative) is not bool
            or self.gate.ordinal != _STAGES.index(self.stage) + 1
            or self.gate.gate_id != self.stage.value
        ):
            raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)


@dataclass(frozen=True, slots=True)
class ValidationLadderResult:
    """Public ``ValidationResult`` plus internal authoritative-stage provenance."""

    validation: ValidationResult
    stages: tuple[ValidationStageReceipt, ...]
    first_failed_stage: ValidationStage | None

    def __post_init__(self) -> None:
        if (
            type(self.validation) is not ValidationResult
            or type(self.stages) is not tuple
            or len(self.stages) != len(_STAGES)
            or any(type(value) is not ValidationStageReceipt for value in self.stages)
            or tuple(value.stage for value in self.stages) != _STAGES
            or (
                self.first_failed_stage is not None
                and type(self.first_failed_stage) is not ValidationStage
            )
            or self.validation.gates != tuple(value.gate for value in self.stages)
        ):
            raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)
        first_failure = next(
            (
                value.stage
                for value in self.stages
                if (
                    value.authoritative
                    and value.gate.gate_outcome is not ValidationGateOutcome.PASSED
                )
            ),
            None,
        )
        if self.first_failed_stage is not first_failure:
            raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)
        if (
            self.validation.validation_outcome is ValidationOutcome.VALIDATED
            and first_failure is not None
        ):
            raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)


def run_validation_ladder(
    request: ValidationLadderRequest,
    driver: SandboxDriver,
) -> ValidationLadderResult:
    """Run the eleven automated gates, stopping positive authority at first failure.

    The optional later branch retains diagnostics only when explicitly requested;
    those receipts are marked non-authoritative and cannot restore validation.
    """

    checked = _copy_request(request)
    patch, rationale = _copy_architect(checked.architect_result)
    profile = _copy_profile(checked.sandbox_profile)
    regression = _copy_regression(checked.fixed_regression)
    if not _identity_matches(patch, rationale, regression, checked.fixed_head_sha):
        raise ValidationLadderError(ValidationLadderErrorCode.IDENTITY_MISMATCH)
    if any(not callable(getattr(driver, name, None)) for name in ("attest", "execute", "teardown")):
        raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)

    stages: list[ValidationStageReceipt] = []
    first_failed: ValidationStage | None = None
    for ordinal, stage in enumerate(_STAGES, start=1):
        authoritative = first_failed is None
        if not authoritative and not checked.run_non_authoritative_diagnostics:
            stages.append(
                _skipped_stage(
                    stage,
                    ordinal,
                    checked,
                    patch,
                    "EARLIER_MANDATORY_FAILURE",
                )
            )
            continue
        stage_receipt = _run_stage(
            stage,
            ordinal,
            checked,
            patch,
            rationale,
            regression,
            profile,
            driver,
            authoritative=authoritative,
        )
        stages.append(stage_receipt)
        if authoritative and stage_receipt.gate.gate_outcome is not ValidationGateOutcome.PASSED:
            first_failed = stage

    gates = tuple(item.gate for item in stages)
    outcome = ValidationOutcome.VALIDATED if first_failed is None else _outcome_for(stages)
    public = _validation_result(checked, patch, profile, gates, outcome)
    return ValidationLadderResult(public, tuple(stages), first_failed)


def _run_stage(
    stage: ValidationStage,
    ordinal: int,
    request: ValidationLadderRequest,
    patch: PatchCandidate,
    rationale: PatchRationaleReceipt,
    regression: RegressionResult,
    profile: SandboxProfile,
    driver: SandboxDriver,
    *,
    authoritative: bool,
) -> ValidationStageReceipt:
    resource = request.stage_resources[ordinal - 1]
    reason: str | None = _resource_reason(resource, profile)
    gate_outcome = ValidationGateOutcome.FAILED
    sandbox_receipt: SandboxExecutionReceipt | None = None
    if reason is None:
        try:
            capturing_driver = _CapturingDriver(driver)
            sandbox_receipt = run_in_sandbox(profile, SandboxCommand(stage.value), capturing_driver)
        except SandboxError:
            reason = "SANDBOX_CONTRACT_FAILURE"
            gate_outcome = ValidationGateOutcome.INDETERMINATE
        except Exception:
            # A driver is an untrusted integration boundary.  Do not let an
            # adapter exception escape as a successful or partially recorded
            # validation; preserve a bounded fail-closed gate instead.
            reason = "SANDBOX_CONTRACT_FAILURE"
            gate_outcome = ValidationGateOutcome.INDETERMINATE
        else:
            observation = capturing_driver.observation
            if observation is not None:
                resource = observation.resource_usage
                if reason is None:
                    reason = _resource_reason(resource, profile)
            if sandbox_receipt.reason_code is not None or not sandbox_receipt.teardown.completed:
                reason = "SANDBOX_NON_SUCCESS"
                gate_outcome = ValidationGateOutcome.INDETERMINATE
            elif sandbox_receipt.outcome is SandboxOutcome.INDETERMINATE:
                reason = (
                    "VALIDATION_DEPENDENCIES_UNAVAILABLE"
                    if stage in {ValidationStage.COMPILE_TYPES, ValidationStage.EXISTING_TESTS}
                    else "SANDBOX_INDETERMINATE"
                )
                gate_outcome = ValidationGateOutcome.INDETERMINATE
            elif sandbox_receipt.outcome is not SandboxOutcome.SUCCEEDED:
                reason = "SANDBOX_NON_SUCCESS"
                gate_outcome = ValidationGateOutcome.INDETERMINATE
            elif observation is None:
                reason = "OBSERVATION_EVIDENCE_MISSING"
                gate_outcome = ValidationGateOutcome.INDETERMINATE
            elif sandbox_receipt.observation_sha256 != observation.observation_sha256:
                reason = "OBSERVATION_EVIDENCE_MISMATCH"
                gate_outcome = ValidationGateOutcome.INDETERMINATE
    if (
        reason is None
        and stage
        in {
            ValidationStage.SECURITY_POC,
            ValidationStage.SECURITY_POC_PLUS,
        }
        and (
            regression.revision_role is not RegressionRevisionRole.FIXED_CANDIDATE
            or regression.evaluated_head_sha != request.fixed_head_sha
            or regression.disposition is not RegressionDisposition.FIXED_CANDIDATE_PASSED
        )
    ):
        reason = "REGRESSION_NOT_PASSED"

    inputs = tuple(
        sorted(
            (
                patch.unified_diff_sha256,
                rationale.rationale_sha256,
                regression.result_sha256,
            )
        )
    )
    outputs: tuple[str, ...] = ()
    if sandbox_receipt is not None:
        outputs = tuple(
            sorted(
                value
                for value in (sandbox_receipt.receipt_sha256, sandbox_receipt.observation_sha256)
                if value is not None
            )
        )
    gate = ValidationGateResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        ordinal=ordinal,
        gate_id=stage.value,
        gate_outcome=gate_outcome if reason is not None else ValidationGateOutcome.PASSED,
        producer=request.producer,
        input_hashes=inputs,
        output_hashes=outputs if reason is None else (),
        reason_code=reason,
        resource_usage=resource,
    )
    return ValidationStageReceipt(stage, gate, sandbox_receipt, authoritative)


class _CapturingDriver:
    """Snapshots a validated observation before teardown can mutate driver-owned state."""

    def __init__(self, driver: SandboxDriver) -> None:
        self._driver = driver
        self.observation: SandboxObservation | None = None

    def attest(self, profile: SandboxProfile) -> SandboxAttestation:
        return self._driver.attest(profile)

    def execute(self, command: SandboxCommand, profile: SandboxProfile) -> SandboxObservation:
        value = self._driver.execute(command, profile)
        self.observation = _copy_observed_observation(value)
        return self.observation

    def teardown(self) -> SandboxTeardownReceipt:
        return self._driver.teardown()


def _copy_observed_observation(value: SandboxObservation) -> SandboxObservation:
    if type(value) is not SandboxObservation:
        raise SandboxError(SandboxErrorCode.DRIVER_FAILURE)
    try:
        return SandboxObservation(
            value.outcome,
            value.output_sha256,
            value.output_size_bytes,
            ResourceUsage.model_validate(value.resource_usage.model_dump(mode="python")),
            value.observation_sha256,
            value.schema_version,
        )
    except (AttributeError, TypeError, ValueError):
        raise SandboxError(SandboxErrorCode.DRIVER_FAILURE) from None


def _skipped_stage(
    stage: ValidationStage,
    ordinal: int,
    request: ValidationLadderRequest,
    patch: PatchCandidate,
    reason: str,
) -> ValidationStageReceipt:
    gate = ValidationGateResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        ordinal=ordinal,
        gate_id=stage.value,
        gate_outcome=ValidationGateOutcome.SKIPPED,
        producer=request.producer,
        input_hashes=(patch.unified_diff_sha256,),
        reason_code=reason,
        resource_usage=request.stage_resources[ordinal - 1],
    )
    return ValidationStageReceipt(stage, gate, None, False)


def _resource_reason(resource: ResourceUsage, profile: SandboxProfile) -> str | None:
    if (
        resource.elapsed_ms > profile.max_elapsed_ms
        or resource.cpu_time_ms > profile.max_cpu_time_ms
        or resource.peak_memory_bytes > profile.max_memory_bytes
    ):
        return "RESOURCE_BUDGET_EXCEEDED"
    return None


def _outcome_for(stages: list[ValidationStageReceipt]) -> ValidationOutcome:
    failed = next(
        (
            item.gate.gate_outcome
            for item in stages
            if (item.authoritative and item.gate.gate_outcome is not ValidationGateOutcome.PASSED)
        ),
        ValidationGateOutcome.FAILED,
    )
    if failed is ValidationGateOutcome.ERROR:
        return ValidationOutcome.ERROR
    if failed is ValidationGateOutcome.INDETERMINATE:
        return ValidationOutcome.INDETERMINATE
    return ValidationOutcome.FAILED


def _validation_result(
    request: ValidationLadderRequest,
    patch: PatchCandidate,
    profile: SandboxProfile,
    gates: tuple[ValidationGateResult, ...],
    outcome: ValidationOutcome,
) -> ValidationResult:
    pin = ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=profile.profile_id,
        component_version=profile.profile_version,
        content_sha256=profile.profile_sha256,
    )
    material = {
        "gates": [gate.model_dump(mode="json") for gate in gates],
        "head_sha": request.fixed_head_sha,
        "patch_id": patch.patch_id,
        "sandbox_profile": pin.model_dump(mode="json"),
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "tenant_id": patch.repository_revision.tenant_id,
        "validation_id": request.validation_id,
        "validation_outcome": outcome.value,
    }
    digest = hashlib.sha256(
        _HASH_DOMAIN
        + json.dumps(
            material,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    return ValidationResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        validation_id=request.validation_id,
        tenant_id=patch.repository_revision.tenant_id,
        patch_id=patch.patch_id,
        head_sha=request.fixed_head_sha,
        sandbox_profile=pin,
        gates=gates,
        validation_outcome=outcome,
        result_sha256=digest,
    )


def _identity_matches(
    patch: PatchCandidate,
    rationale: PatchRationaleReceipt,
    regression: RegressionResult,
    fixed_head_sha: str,
) -> bool:
    return (
        patch.finding_id == rationale.finding_id
        and regression.descriptor_id == rationale.regression_descriptor_id
        and regression.revision_role is RegressionRevisionRole.FIXED_CANDIDATE
        and regression.evaluated_head_sha == fixed_head_sha
        and fixed_head_sha != patch.repository_revision.head_sha
    )


def _copy_request(value: ValidationLadderRequest) -> ValidationLadderRequest:
    if type(value) is not ValidationLadderRequest:
        raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)
    try:
        return ValidationLadderRequest(
            value.validation_id,
            value.architect_result,
            value.fixed_head_sha,
            value.sandbox_profile,
            ProducerRef.model_validate(value.producer.model_dump(mode="python")),
            value.fixed_regression,
            tuple(
                ResourceUsage.model_validate(item.model_dump(mode="python"))
                for item in value.stage_resources
            ),
            value.run_non_authoritative_diagnostics,
        )
    except (AttributeError, TypeError, ValueError):
        raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID) from None


def _copy_architect(value: ArchitectPatchResult) -> tuple[PatchCandidate, PatchRationaleReceipt]:
    if type(value) is not ArchitectPatchResult:
        raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)
    try:
        patch = PatchCandidate.model_validate(value.patch_candidate.model_dump(mode="python"))
        rationale = PatchRationaleReceipt(
            **{
                name: getattr(value.rationale, name)
                for name in PatchRationaleReceipt.__dataclass_fields__
            }
        )
        return patch, rationale
    except (AttributeError, TypeError, ValueError):
        raise ValidationLadderError(ValidationLadderErrorCode.IDENTITY_MISMATCH) from None


def _copy_profile(value: SandboxProfile) -> SandboxProfile:
    if type(value) is not SandboxProfile:
        raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)
    try:
        return SandboxProfile(
            **{name: getattr(value, name) for name in SandboxProfile.__dataclass_fields__}
        )
    except (AttributeError, TypeError, ValueError):
        raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID) from None


def _copy_regression(value: RegressionResult) -> RegressionResult:
    if type(value) is not RegressionResult:
        raise ValidationLadderError(ValidationLadderErrorCode.REQUEST_INVALID)
    try:
        return RegressionResult(
            **{name: getattr(value, name) for name in RegressionResult.__dataclass_fields__}
        )
    except (AttributeError, TypeError, ValueError):
        raise ValidationLadderError(ValidationLadderErrorCode.IDENTITY_MISMATCH) from None


__all__ = [
    "ValidationLadderError",
    "ValidationLadderErrorCode",
    "ValidationLadderRequest",
    "ValidationLadderResult",
    "ValidationStage",
    "ValidationStageReceipt",
    "run_validation_ladder",
]
