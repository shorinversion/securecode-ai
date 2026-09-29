"""P4.6 ordered validation-ladder contracts."""

from __future__ import annotations

import hashlib

import pytest
import securecode_ai.core.validation as VALIDATION
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    DataClass,
    PatchCandidate,
    PatchStatus,
    ProducerRef,
    RepositoryRevision,
    ResourceUsage,
)
from securecode_ai.core.architect import ArchitectPatchResult, TouchedSymbol, _make_rationale
from securecode_ai.core.regression import (
    RegressionDisposition,
    RegressionResult,
    RegressionRevisionRole,
    _result_hash,
    _unchecked_result,
)
from securecode_ai.core.sandbox import (
    SandboxAttestation,
    SandboxCommand,
    SandboxDriver,
    SandboxExecutionReceipt,
    SandboxObservation,
    SandboxOutcome,
    SandboxProfile,
    SandboxTeardownReceipt,
    _attestation_hash,
    _observation_hash,
    _profile_hash,
    _teardown_hash,
)
from securecode_ai.core.sandbox import (
    run_in_sandbox as validation_run_in_sandbox,
)
from securecode_ai.core.validation import (
    ValidationLadderError,
    ValidationLadderRequest,
    ValidationStage,
    _CapturingDriver,
    run_validation_ladder,
)

HEAD = "a" * 40
FIXED_HEAD = "b" * 40
HASH = "c" * 64


def _producer() -> ProducerRef:
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="validation-ladder",
        producer_version="1.0.0",
        producer_sha256=HASH,
    )


def _profile() -> SandboxProfile:
    value = object.__new__(SandboxProfile)
    for name, item in (
        ("profile_id", "airgap-profile"),
        ("profile_version", "1.0.0"),
        ("network_disabled", True),
        ("credentials_disabled", True),
        ("host_access_disabled", True),
        ("rootless", True),
        ("read_only_root", True),
        ("max_cpu_time_ms", 100),
        ("max_memory_bytes", 1000),
        ("max_processes", 2),
        ("max_disk_bytes", 1000),
        ("max_output_bytes", 1000),
        ("max_elapsed_ms", 100),
        ("profile_sha256", "0" * 64),
        ("schema_version", "1.0.0"),
    ):
        object.__setattr__(value, name, item)
    return SandboxProfile(
        "airgap-profile",
        "1.0.0",
        True,
        True,
        True,
        True,
        True,
        100,
        1000,
        2,
        1000,
        1000,
        100,
        _profile_hash(value),
    )


def _attestation(profile: SandboxProfile) -> SandboxAttestation:
    value = object.__new__(SandboxAttestation)
    for name, item in (
        ("profile_id", profile.profile_id),
        ("profile_version", profile.profile_version),
        ("profile_sha256", profile.profile_sha256),
        ("network_disabled", True),
        ("credentials_disabled", True),
        ("host_access_disabled", True),
        ("rootless", True),
        ("desktop_vm_isolation", False),
        ("read_only_root", True),
        ("attestation_sha256", "0" * 64),
        ("schema_version", "1.0.0"),
    ):
        object.__setattr__(value, name, item)
    return SandboxAttestation(
        profile.profile_id,
        profile.profile_version,
        profile.profile_sha256,
        True,
        True,
        True,
        True,
        True,
        _attestation_hash(value),
    )


def _observation(
    outcome: SandboxOutcome = SandboxOutcome.SUCCEEDED,
    usage: ResourceUsage | None = None,
) -> SandboxObservation:
    value = object.__new__(SandboxObservation)
    resource = (
        ResourceUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            elapsed_ms=1,
            peak_memory_bytes=1,
            cpu_time_ms=1,
        )
        if usage is None
        else usage
    )
    for name, item in (
        ("outcome", outcome),
        ("output_sha256", "d" * 64),
        ("output_size_bytes", 1),
        ("resource_usage", resource),
        ("observation_sha256", "0" * 64),
        ("schema_version", "1.0.0"),
    ):
        object.__setattr__(value, name, item)
    return SandboxObservation(outcome, "d" * 64, 1, resource, _observation_hash(value))


def _teardown() -> SandboxTeardownReceipt:
    value = object.__new__(SandboxTeardownReceipt)
    for name, item in (
        ("attempted", True),
        ("completed", True),
        ("live_workloads", 0),
        ("reusable_volumes", 0),
        ("receipt_sha256", "0" * 64),
        ("schema_version", "1.0.0"),
    ):
        object.__setattr__(value, name, item)
    return SandboxTeardownReceipt(True, True, 0, 0, _teardown_hash(value))


class _Driver:
    def __init__(
        self,
        failure: ValidationStage | None = None,
        observation: SandboxObservation | None = None,
        mutate_on_teardown: bool = False,
    ) -> None:
        self.failure = failure
        self.observation = observation
        self.mutate_on_teardown = mutate_on_teardown
        self.commands: list[str] = []

    def attest(self, profile: SandboxProfile) -> SandboxAttestation:
        return _attestation(profile)

    def execute(self, command: SandboxCommand, profile: SandboxProfile) -> SandboxObservation:
        self.commands.append(command.command_id)
        return self.observation or _observation(
            SandboxOutcome.FAILED
            if self.failure is not None and command.command_id == self.failure.value
            else SandboxOutcome.SUCCEEDED
        )

    def teardown(self) -> SandboxTeardownReceipt:
        if self.mutate_on_teardown and self.observation is not None:
            object.__setattr__(
                self.observation,
                "resource_usage",
                ResourceUsage(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    elapsed_ms=1,
                    peak_memory_bytes=1,
                    cpu_time_ms=1,
                ),
            )
        return _teardown()


def _architect() -> ArchitectPatchResult:
    patch_bytes = b"diff --git a/app.py b/app.py\n"
    patch_hash = hashlib.sha256(patch_bytes).hexdigest()
    revision = RepositoryRevision(
        schema_version=CONTRACT_SCHEMA_VERSION,
        tenant_id="tenant-1",
        scm_provider="git",
        repository_id="repo-1",
        head_sha=HEAD,
    )
    patch = PatchCandidate(
        schema_version=CONTRACT_SCHEMA_VERSION,
        patch_id=f"patch-{patch_hash}",
        finding_id="finding-1",
        repository_revision=revision,
        unified_diff_sha256=patch_hash,
        diff_ref=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            content_id=f"patch-{patch_hash}",
            content_sha256=patch_hash,
            size_bytes=len(patch_bytes),
            data_class=DataClass.CONFIDENTIAL_SOURCE,
        ),
        author=_producer(),
        patch_status=PatchStatus.SUGGESTED,
    )
    symbol = TouchedSymbol("app.py", "function", "get_user", 1, 2, HASH)
    rationale = _make_rationale(
        finding_id="finding-1",
        root_cause_id="root-cause-1",
        invariant_id="CWE-89-PARAMETER-BINDING",
        invariant_version="1.0.0",
        regression_descriptor_id="regression-1",
        touched_symbols=(symbol,),
    )
    return ArchitectPatchResult(patch, rationale)


def _regression(
    disposition: RegressionDisposition = RegressionDisposition.FIXED_CANDIDATE_PASSED,
) -> RegressionResult:
    value = _unchecked_result(
        descriptor_id="regression-1",
        descriptor_sha256=HASH,
        revision_role=RegressionRevisionRole.FIXED_CANDIDATE,
        evaluated_head_sha=FIXED_HEAD,
        disposition=disposition,
        case_result_hashes=("1" * 64,),
        approval_eligible=False,
        result_sha256="0" * 64,
        schema_version="1.0.0",
    )
    return RegressionResult(
        **{
            **{name: getattr(value, name) for name in RegressionResult.__dataclass_fields__},
            "result_sha256": _result_hash(value),
        }
    )


def _request(
    *,
    regression: RegressionResult | None = None,
    resources: tuple[ResourceUsage, ...] | None = None,
    diagnostics: bool = False,
) -> ValidationLadderRequest:
    usage = ResourceUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        elapsed_ms=1,
        peak_memory_bytes=1,
        cpu_time_ms=1,
    )
    return ValidationLadderRequest(
        validation_id="validation-1",
        architect_result=_architect(),
        fixed_head_sha=FIXED_HEAD,
        sandbox_profile=_profile(),
        producer=_producer(),
        fixed_regression=_regression() if regression is None else regression,
        stage_resources=(usage,) * len(tuple(ValidationStage)) if resources is None else resources,
        run_non_authoritative_diagnostics=diagnostics,
    )


def test_all_eleven_automated_stages_pass_in_order_for_a_fixed_candidate() -> None:
    driver = _Driver()
    result = run_validation_ladder(_request(), driver)

    assert result.validation.validation_outcome.value == "VALIDATED"
    assert result.first_failed_stage is None
    assert tuple(item.gate.ordinal for item in result.stages) == tuple(range(1, 12))
    assert all(item.gate.gate_outcome.value == "PASSED" for item in result.stages)
    assert driver.commands == [stage.value for stage in ValidationStage]


def test_first_mandatory_failure_blocks_later_positive_authority() -> None:
    result = run_validation_ladder(_request(), _Driver(ValidationStage.EXISTING_TESTS))

    assert result.first_failed_stage is ValidationStage.EXISTING_TESTS
    assert result.validation.validation_outcome.value == "FAILED"
    assert result.stages[5].gate.gate_outcome.value == "FAILED"
    assert all(item.gate.gate_outcome.value == "SKIPPED" for item in result.stages[6:])
    assert not any(item.authoritative for item in result.stages[6:])


@pytest.mark.parametrize("stage", tuple(ValidationStage))
def test_each_mandatory_stage_failure_never_validates(stage: ValidationStage) -> None:
    result = run_validation_ladder(_request(), _Driver(stage))

    assert result.first_failed_stage is stage
    assert result.validation.validation_outcome.value == "FAILED"
    assert result.stages[tuple(ValidationStage).index(stage)].gate.gate_outcome.value == "FAILED"


def test_poc_only_success_cannot_validate_without_fixed_regression() -> None:
    result = run_validation_ladder(
        _request(regression=_regression(RegressionDisposition.INDETERMINATE)),
        _Driver(),
    )

    assert result.first_failed_stage is ValidationStage.SECURITY_POC
    assert result.stages[6].gate.reason_code == "REGRESSION_NOT_PASSED"
    assert result.validation.validation_outcome.value == "FAILED"


def test_resource_limit_and_stale_head_fail_closed() -> None:
    exceeded = ResourceUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        elapsed_ms=101,
        peak_memory_bytes=1,
        cpu_time_ms=1,
    )
    resources = (exceeded, *_request().stage_resources[1:])
    result = run_validation_ladder(_request(resources=resources), _Driver())
    assert result.first_failed_stage is ValidationStage.DIFF_PARSE
    assert result.stages[0].gate.reason_code == "RESOURCE_BUDGET_EXCEEDED"

    request = _request()
    object.__setattr__(request, "fixed_head_sha", HEAD)
    with pytest.raises(ValidationLadderError):
        run_validation_ladder(request, _Driver())


def test_observed_resources_replace_low_caller_estimate_and_stop_authority() -> None:
    observed = ResourceUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        elapsed_ms=101,
        peak_memory_bytes=1,
        cpu_time_ms=1,
    )
    driver = _Driver(observation=_observation(usage=observed), mutate_on_teardown=True)
    result = run_validation_ladder(_request(), driver)

    assert result.first_failed_stage is ValidationStage.DIFF_PARSE
    assert result.stages[0].gate.resource_usage == observed
    assert result.stages[0].gate.reason_code == "SANDBOX_NON_SUCCESS"
    assert driver.commands == [ValidationStage.DIFF_PARSE.value]


def test_observation_hash_drift_cannot_pass_stage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = validation_run_in_sandbox

    def drift(
        profile: SandboxProfile,
        command: SandboxCommand,
        driver: SandboxDriver,
    ) -> SandboxExecutionReceipt:
        receipt = original(profile, command, driver)
        object.__setattr__(receipt, "observation_sha256", "e" * 64)
        return receipt

    monkeypatch.setattr(VALIDATION, "run_in_sandbox", drift)
    result = run_validation_ladder(_request(), _Driver())

    assert result.first_failed_stage is ValidationStage.DIFF_PARSE
    assert result.stages[0].gate.reason_code == "OBSERVATION_EVIDENCE_MISMATCH"


def test_explicit_non_authoritative_diagnostics_cannot_restore_validation() -> None:
    driver = _Driver(ValidationStage.PATCH_APPLY)
    result = run_validation_ladder(_request(diagnostics=True), driver)

    assert result.first_failed_stage is ValidationStage.PATCH_APPLY
    assert result.validation.validation_outcome.value == "FAILED"
    assert len(driver.commands) == 11
    assert all(not item.authoritative for item in result.stages[3:])


def test_within_limit_observed_usage_replaces_caller_estimate() -> None:
    observed = ResourceUsage(
        schema_version=CONTRACT_SCHEMA_VERSION,
        elapsed_ms=2,
        peak_memory_bytes=3,
        cpu_time_ms=4,
    )
    result = run_validation_ladder(_request(), _Driver(observation=_observation(usage=observed)))

    assert result.validation.validation_outcome.value == "VALIDATED"
    assert all(item.gate.resource_usage == observed for item in result.stages)
    assert observed != _request().stage_resources[0]


def test_missing_observation_evidence_cannot_pass_stage(monkeypatch: pytest.MonkeyPatch) -> None:
    original = validation_run_in_sandbox

    def omit_capture(
        profile: SandboxProfile,
        command: SandboxCommand,
        capturing_driver: _CapturingDriver,
    ) -> SandboxExecutionReceipt:
        return original(profile, command, capturing_driver._driver)

    monkeypatch.setattr(VALIDATION, "run_in_sandbox", omit_capture)
    result = run_validation_ladder(_request(), _Driver())

    assert result.first_failed_stage is ValidationStage.DIFF_PARSE
    assert result.stages[0].gate.reason_code == "OBSERVATION_EVIDENCE_MISSING"
    assert result.validation.validation_outcome.value == "INDETERMINATE"
    assert all(not item.authoritative for item in result.stages[1:])
