"""Focused P4.5 sandbox admission and teardown contracts."""

from __future__ import annotations

import pytest
from securecode_ai.contracts import ResourceUsage
from securecode_ai.core.sandbox import (
    SandboxAttestation,
    SandboxCommand,
    SandboxError,
    SandboxErrorCode,
    SandboxObservation,
    SandboxOutcome,
    SandboxProfile,
    SandboxTeardownReceipt,
    _attestation_hash,
    _observation_hash,
    _profile_hash,
    _teardown_hash,
    run_in_sandbox,
)


def _profile() -> SandboxProfile:
    value = object.__new__(SandboxProfile)
    for name, item in (
        ("profile_id", "local-airgap"),
        ("profile_version", "1.0.0"),
        ("network_disabled", True),
        ("credentials_disabled", True),
        ("host_access_disabled", True),
        ("rootless", True),
        ("read_only_root", True),
        ("max_cpu_time_ms", 1000),
        ("max_memory_bytes", 1024),
        ("max_processes", 4),
        ("max_disk_bytes", 4096),
        ("max_output_bytes", 1024),
        ("max_elapsed_ms", 2000),
        ("schema_version", "1.0.0"),
        ("profile_sha256", "0" * 64),
    ):
        object.__setattr__(value, name, item)
    return SandboxProfile(
        "local-airgap",
        "1.0.0",
        True,
        True,
        True,
        True,
        True,
        1000,
        1024,
        4,
        4096,
        1024,
        2000,
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
        ("schema_version", "1.0.0"),
        ("attestation_sha256", "0" * 64),
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


def _observation(*, usage: ResourceUsage | None = None) -> SandboxObservation:
    resource = (
        ResourceUsage(
            schema_version="0.2.0",
            elapsed_ms=1,
            peak_memory_bytes=1,
            cpu_time_ms=1,
        )
        if usage is None
        else usage
    )
    value = object.__new__(SandboxObservation)
    for name, item in (
        ("outcome", SandboxOutcome.SUCCEEDED),
        ("output_sha256", "a" * 64),
        ("output_size_bytes", 1),
        ("resource_usage", resource),
        ("schema_version", "1.0.0"),
        ("observation_sha256", "0" * 64),
    ):
        object.__setattr__(value, name, item)
    return SandboxObservation(
        SandboxOutcome.SUCCEEDED,
        "a" * 64,
        1,
        resource,
        _observation_hash(value),
    )


def _teardown() -> SandboxTeardownReceipt:
    value = object.__new__(SandboxTeardownReceipt)
    for name, item in (
        ("attempted", True),
        ("completed", True),
        ("live_workloads", 0),
        ("reusable_volumes", 0),
        ("schema_version", "1.0.0"),
        ("receipt_sha256", "0" * 64),
    ):
        object.__setattr__(value, name, item)
    return SandboxTeardownReceipt(True, True, 0, 0, _teardown_hash(value))


class _Driver:
    def __init__(
        self,
        *,
        attestation: SandboxAttestation | None = None,
        fail: bool = False,
        observation: SandboxObservation | None = None,
    ) -> None:
        self.attestation = attestation
        self.fail = fail
        self.observation = observation
        self.teardown_calls = 0

    def attest(self, profile: SandboxProfile) -> SandboxAttestation:
        return self.attestation or _attestation(profile)

    def execute(self, command: SandboxCommand, profile: SandboxProfile) -> SandboxObservation:
        if self.fail:
            raise RuntimeError("driver detail must not escape")
        return self.observation or _observation()

    def teardown(self) -> SandboxTeardownReceipt:
        self.teardown_calls += 1
        return _teardown()


def test_attestation_precedes_execution_and_teardown_is_recorded() -> None:
    driver = _Driver()
    result = run_in_sandbox(_profile(), SandboxCommand("pytest", ("-q",)), driver)
    assert result.outcome is SandboxOutcome.SUCCEEDED
    assert result.teardown.completed
    assert driver.teardown_calls == 1


def test_driver_failure_is_sanitized_and_teardown_still_runs() -> None:
    driver = _Driver(fail=True)
    result = run_in_sandbox(_profile(), SandboxCommand("pytest"), driver)
    assert result.outcome is SandboxOutcome.INDETERMINATE
    assert result.reason_code is SandboxErrorCode.DRIVER_FAILURE
    assert driver.teardown_calls == 1


@pytest.mark.parametrize(
    ("field", "limit", "reported"),
    (
        ("cpu_time_ms", 1000, 1001),
        ("peak_memory_bytes", 1024, 1025),
        ("elapsed_ms", 2000, 2001),
    ),
)
def test_observed_resource_overrun_is_indeterminate_and_tears_down(
    field: str, limit: int, reported: int
) -> None:
    elapsed_ms = reported if field == "elapsed_ms" else 1
    peak_memory_bytes = reported if field == "peak_memory_bytes" else 1
    cpu_time_ms = reported if field == "cpu_time_ms" else 1
    observation = _observation(
        usage=ResourceUsage(
            schema_version="0.2.0",
            elapsed_ms=elapsed_ms,
            peak_memory_bytes=peak_memory_bytes,
            cpu_time_ms=cpu_time_ms,
        )
    )
    driver = _Driver(observation=observation)

    result = run_in_sandbox(_profile(), SandboxCommand("pytest"), driver)

    assert reported == limit + 1
    assert result.outcome is SandboxOutcome.INDETERMINATE
    assert result.reason_code is SandboxErrorCode.RESOURCE_LIMIT
    assert result.observation_sha256 == observation.observation_sha256
    assert driver.teardown_calls == 1


def test_observed_resource_exact_boundary_succeeds() -> None:
    usage = ResourceUsage(
        schema_version="0.2.0", elapsed_ms=2000, peak_memory_bytes=1024, cpu_time_ms=1000
    )
    driver = _Driver(observation=_observation(usage=usage))

    result = run_in_sandbox(_profile(), SandboxCommand("pytest"), driver)

    assert result.outcome is SandboxOutcome.SUCCEEDED
    assert result.reason_code is None


def test_invalid_command_is_rejected_before_driver() -> None:
    with pytest.raises(SandboxError) as error:
        SandboxCommand("bad", ("line\nfeed",))
    assert error.value.code is SandboxErrorCode.REQUEST_INVALID
