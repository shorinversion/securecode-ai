"""Closed public contract oracles for the bounded P1.10 CLI surface."""

from __future__ import annotations

import json
from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError
from securecode_ai.contracts import (
    CLI_ERROR_DEFINITIONS,
    CONTRACT_SCHEMA_VERSION,
    AuditRunOutcome,
    CliCommand,
    CliDiagnosticScope,
    CliDoctorCheck,
    CliDoctorCheckId,
    CliDoctorCheckOutcome,
    CliDoctorOutcome,
    CliDoctorReasonCode,
    CliDoctorResult,
    CliErrorCategory,
    CliErrorCode,
    CliErrorOutcome,
    CliErrorResult,
    CliExitCode,
    CliScanReadiness,
    cli_error_result,
    exit_code_for_audit_outcome,
)


def _doctor_payload() -> dict[str, Any]:
    pairs = (
        (
            CliDoctorCheckId.CONFIGURATION_RESOLUTION,
            CliDoctorReasonCode.CONFIGURATION_VALID,
        ),
        (
            CliDoctorCheckId.FOUNDATION_PROFILE_IDENTITY,
            CliDoctorReasonCode.PROFILE_IDENTITY_VALID,
        ),
        (
            CliDoctorCheckId.SELECTED_EGRESS_MEMBERSHIP,
            CliDoctorReasonCode.EGRESS_MEMBERSHIP_VALID,
        ),
        (
            CliDoctorCheckId.SOURCE_FREE_CAPABILITY_DECLARATION,
            CliDoctorReasonCode.CAPABILITY_DECLARATION_VALID,
        ),
    )
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "command": CliCommand.DOCTOR,
        "diagnostic_scope": CliDiagnosticScope.FOUNDATION_CONFIGURATION_ONLY,
        "cli_outcome": CliDoctorOutcome.DIAGNOSTIC_COMPLETED,
        "exit_code": CliExitCode.COMPLETED,
        "scan_readiness": CliScanReadiness.NOT_EVALUATED,
        "checks": tuple(
            {
                "schema_version": CONTRACT_SCHEMA_VERSION,
                "check_id": check_id,
                "check_outcome": CliDoctorCheckOutcome.READY,
                "reason_code": reason,
            }
            for check_id, reason in pairs
        ),
    }


def test_cli_exit_codes_and_trusted_outcome_mapping_are_exact() -> None:
    assert {member.value for member in CliExitCode} == {0, 2, 3, 4, 5, 6}
    assert {outcome: exit_code_for_audit_outcome(outcome) for outcome in AuditRunOutcome} == {
        AuditRunOutcome.PASS: CliExitCode.COMPLETED,
        AuditRunOutcome.FAIL: CliExitCode.POLICY_FAIL,
        AuditRunOutcome.INDETERMINATE: CliExitCode.INDETERMINATE,
        AuditRunOutcome.ERROR: CliExitCode.OPERATIONAL_ERROR,
        AuditRunOutcome.CANCELLED: CliExitCode.CANCELLED_OR_SUPERSEDED,
        AuditRunOutcome.SUPERSEDED: CliExitCode.CANCELLED_OR_SUPERSEDED,
    }
    assert CliExitCode.INVALID_USAGE_OR_CONFIG not in {
        exit_code_for_audit_outcome(outcome) for outcome in AuditRunOutcome
    }


@pytest.mark.parametrize("untrusted", ["PASS", 0, True, object()])
def test_trusted_outcome_mapping_rejects_raw_or_unknown_values(untrusted: object) -> None:
    with pytest.raises(TypeError):
        exit_code_for_audit_outcome(untrusted)  # type: ignore[arg-type]


@pytest.mark.parametrize("code", list(CliErrorCode))
def test_closed_error_table_round_trips_every_code(code: CliErrorCode) -> None:
    definition = CLI_ERROR_DEFINITIONS[code]
    result = cli_error_result(code, correlation_id="correlation", command=None)
    assert result.cli_outcome is definition.cli_outcome
    assert result.error.category is definition.category
    assert result.error.retryable is definition.retryable
    assert result.error.safe_message is definition.safe_message
    assert result.exit_code is definition.exit_code
    assert result.command is None
    assert result.error.run_id is None
    assert result.error.finding_id is None
    assert result.error.details_ref is None
    assert CliErrorResult.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("cli_outcome",), CliErrorOutcome.POLICY_FAIL),
        (("exit_code",), CliExitCode.COMPLETED),
        (("error", "category"), CliErrorCategory.POLICY),
        (("error", "retryable"), True),
        (("error", "safe_message"), "operation was cancelled"),
    ],
)
def test_error_result_rejects_cartesian_mapping_drift(
    path: tuple[str, ...], replacement: object
) -> None:
    payload = cli_error_result(
        CliErrorCode.INVALID_CONFIG,
        correlation_id="correlation",
        command=CliCommand.DOCTOR,
    ).model_dump(mode="json")
    target: dict[str, Any] = payload
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    with pytest.raises(ValidationError):
        CliErrorResult.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("container", "field"),
    [
        ("root", "command"),
        ("error", "run_id"),
        ("error", "finding_id"),
        ("error", "details_ref"),
        ("error", "retryable"),
    ],
)
def test_error_result_requires_nullable_and_mapping_fields(container: str, field: str) -> None:
    payload = cli_error_result(
        CliErrorCode.INVALID_USAGE,
        correlation_id="correlation",
        command=None,
    ).model_dump(mode="json")
    if container == "root":
        payload.pop(field)
    else:
        payload[container].pop(field)
    with pytest.raises(ValidationError):
        CliErrorResult.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "1.0.0"),
        ("status", "PASS"),
        ("exit_code", True),
        ("command", "unknown"),
    ],
)
def test_error_result_rejects_unknown_versions_fields_enums_and_bool_exit(
    field: str, value: object
) -> None:
    payload = cli_error_result(
        CliErrorCode.INVALID_USAGE,
        correlation_id="correlation",
        command=None,
    ).model_dump(mode="json")
    payload[field] = value
    with pytest.raises(ValidationError):
        CliErrorResult.model_validate_json(json.dumps(payload))


def test_doctor_result_round_trips_only_the_complete_canonical_check_set() -> None:
    result = CliDoctorResult.model_validate(_doctor_payload())
    assert len(result.checks) == 4
    assert all(isinstance(check, CliDoctorCheck) for check in result.checks)
    assert CliDoctorResult.model_validate_json(result.model_dump_json()) == result


@pytest.mark.parametrize("mutation", ["missing", "reordered", "wrong_reason", "extra"])
def test_doctor_result_rejects_noncanonical_check_sets(mutation: str) -> None:
    payload = _doctor_payload()
    checks = list(payload["checks"])
    if mutation == "missing":
        checks.pop()
    elif mutation == "reordered":
        checks[0], checks[1] = checks[1], checks[0]
    elif mutation == "wrong_reason":
        checks[0]["reason_code"] = CliDoctorReasonCode.PROFILE_IDENTITY_VALID
    else:
        checks.append(deepcopy(checks[-1]))
    payload["checks"] = tuple(checks)
    with pytest.raises(ValidationError):
        CliDoctorResult.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("diagnostic_scope", "FULL_SCAN"),
        ("cli_outcome", "PASS"),
        ("exit_code", 2),
        ("scan_readiness", "READY"),
        ("status", "PASS"),
    ],
)
def test_doctor_result_cannot_encode_product_readiness_or_generic_status(
    field: str, value: object
) -> None:
    payload = _doctor_payload()
    payload[field] = value
    with pytest.raises(ValidationError):
        CliDoctorResult.model_validate(payload)
