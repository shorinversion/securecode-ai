"""Versioned, fail-closed contracts for the SecureCode CLI boundary."""

from __future__ import annotations

from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Final, Literal, NamedTuple, Self

from pydantic import Field, field_validator, model_validator

from .base import (
    CONTRACT_SCHEMA_VERSION,
    ClosedModel,
    ContractExtension,
    OpaqueId,
    WireModel,
)
from .domain import ArtifactRef, AuditRunOutcome


class CliExitCode(IntEnum):
    """Stable process exit codes from the accepted CLI contract."""

    COMPLETED = 0
    POLICY_FAIL = 2
    INDETERMINATE = 3
    OPERATIONAL_ERROR = 4
    INVALID_USAGE_OR_CONFIG = 5
    CANCELLED_OR_SUPERSEDED = 6


class CliCommand(StrEnum):
    SCAN = "scan"
    FIX = "fix"
    VALIDATE = "validate"
    APPLY = "apply"
    CI = "ci"
    DOCTOR = "doctor"


class CliErrorOutcome(StrEnum):
    POLICY_FAIL = "POLICY_FAIL"
    INDETERMINATE = "INDETERMINATE"
    OPERATIONAL_ERROR = "OPERATIONAL_ERROR"
    INVALID_USAGE_OR_CONFIG = "INVALID_USAGE_OR_CONFIG"
    CANCELLED_OR_SUPERSEDED = "CANCELLED_OR_SUPERSEDED"


class CliErrorCategory(StrEnum):
    POLICY = "POLICY"
    INDETERMINATE = "INDETERMINATE"
    OPERATIONAL = "OPERATIONAL"
    USAGE_CONFIG = "USAGE_CONFIG"
    CONTROL = "CONTROL"


class CliErrorCode(StrEnum):
    POLICY_BLOCKED = "POLICY_BLOCKED"
    ANALYSIS_INDETERMINATE = "ANALYSIS_INDETERMINATE"
    OPERATIONAL_ERROR = "OPERATIONAL_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    INVALID_USAGE = "INVALID_USAGE"
    INVALID_CONFIG = "INVALID_CONFIG"
    CAPABILITY_INCOMPATIBLE = "CAPABILITY_INCOMPATIBLE"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"


class CliSafeMessage(StrEnum):
    POLICY_BLOCKED = "operation is blocked by policy"
    ANALYSIS_INDETERMINATE = "analysis result is indeterminate"
    OPERATIONAL_ERROR = "operation could not be completed"
    INVALID_USAGE = "command-line usage is invalid"
    INVALID_CONFIG = "configuration is invalid"
    CAPABILITY_INCOMPATIBLE = (
        "provider capabilities are incompatible with this foundation diagnostic"
    )
    CANCELLED = "operation was cancelled"
    SUPERSEDED = "operation was superseded"


class CliErrorDefinition(NamedTuple):
    cli_outcome: CliErrorOutcome
    category: CliErrorCategory
    retryable: bool
    safe_message: CliSafeMessage
    exit_code: CliExitCode


CLI_ERROR_DEFINITIONS: Final = MappingProxyType(
    {
        CliErrorCode.POLICY_BLOCKED: CliErrorDefinition(
            CliErrorOutcome.POLICY_FAIL,
            CliErrorCategory.POLICY,
            False,
            CliSafeMessage.POLICY_BLOCKED,
            CliExitCode.POLICY_FAIL,
        ),
        CliErrorCode.ANALYSIS_INDETERMINATE: CliErrorDefinition(
            CliErrorOutcome.INDETERMINATE,
            CliErrorCategory.INDETERMINATE,
            False,
            CliSafeMessage.ANALYSIS_INDETERMINATE,
            CliExitCode.INDETERMINATE,
        ),
        CliErrorCode.OPERATIONAL_ERROR: CliErrorDefinition(
            CliErrorOutcome.OPERATIONAL_ERROR,
            CliErrorCategory.OPERATIONAL,
            False,
            CliSafeMessage.OPERATIONAL_ERROR,
            CliExitCode.OPERATIONAL_ERROR,
        ),
        CliErrorCode.INTERNAL_ERROR: CliErrorDefinition(
            CliErrorOutcome.OPERATIONAL_ERROR,
            CliErrorCategory.OPERATIONAL,
            False,
            CliSafeMessage.OPERATIONAL_ERROR,
            CliExitCode.OPERATIONAL_ERROR,
        ),
        CliErrorCode.INVALID_USAGE: CliErrorDefinition(
            CliErrorOutcome.INVALID_USAGE_OR_CONFIG,
            CliErrorCategory.USAGE_CONFIG,
            False,
            CliSafeMessage.INVALID_USAGE,
            CliExitCode.INVALID_USAGE_OR_CONFIG,
        ),
        CliErrorCode.INVALID_CONFIG: CliErrorDefinition(
            CliErrorOutcome.INVALID_USAGE_OR_CONFIG,
            CliErrorCategory.USAGE_CONFIG,
            False,
            CliSafeMessage.INVALID_CONFIG,
            CliExitCode.INVALID_USAGE_OR_CONFIG,
        ),
        CliErrorCode.CAPABILITY_INCOMPATIBLE: CliErrorDefinition(
            CliErrorOutcome.INVALID_USAGE_OR_CONFIG,
            CliErrorCategory.USAGE_CONFIG,
            False,
            CliSafeMessage.CAPABILITY_INCOMPATIBLE,
            CliExitCode.INVALID_USAGE_OR_CONFIG,
        ),
        CliErrorCode.CANCELLED: CliErrorDefinition(
            CliErrorOutcome.CANCELLED_OR_SUPERSEDED,
            CliErrorCategory.CONTROL,
            False,
            CliSafeMessage.CANCELLED,
            CliExitCode.CANCELLED_OR_SUPERSEDED,
        ),
        CliErrorCode.SUPERSEDED: CliErrorDefinition(
            CliErrorOutcome.CANCELLED_OR_SUPERSEDED,
            CliErrorCategory.CONTROL,
            False,
            CliSafeMessage.SUPERSEDED,
            CliExitCode.CANCELLED_OR_SUPERSEDED,
        ),
    }
)


class CliDiagnosticScope(StrEnum):
    FOUNDATION_CONFIGURATION_ONLY = "FOUNDATION_CONFIGURATION_ONLY"


class CliDoctorOutcome(StrEnum):
    DIAGNOSTIC_COMPLETED = "DIAGNOSTIC_COMPLETED"


class CliScanReadiness(StrEnum):
    NOT_EVALUATED = "NOT_EVALUATED"


class CliDoctorCheckId(StrEnum):
    CONFIGURATION_RESOLUTION = "CONFIGURATION_RESOLUTION"
    FOUNDATION_PROFILE_IDENTITY = "FOUNDATION_PROFILE_IDENTITY"
    SELECTED_EGRESS_MEMBERSHIP = "SELECTED_EGRESS_MEMBERSHIP"
    SOURCE_FREE_CAPABILITY_DECLARATION = "SOURCE_FREE_CAPABILITY_DECLARATION"


class CliDoctorCheckOutcome(StrEnum):
    READY = "READY"


class CliDoctorReasonCode(StrEnum):
    CONFIGURATION_VALID = "CONFIGURATION_VALID"
    PROFILE_IDENTITY_VALID = "PROFILE_IDENTITY_VALID"
    EGRESS_MEMBERSHIP_VALID = "EGRESS_MEMBERSHIP_VALID"
    CAPABILITY_DECLARATION_VALID = "CAPABILITY_DECLARATION_VALID"


_DOCTOR_CHECKS: Final = (
    (CliDoctorCheckId.CONFIGURATION_RESOLUTION, CliDoctorReasonCode.CONFIGURATION_VALID),
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


class CliErrorEnvelope(ClosedModel):
    error_code: CliErrorCode
    category: CliErrorCategory
    retryable: bool
    safe_message: CliSafeMessage
    correlation_id: OpaqueId
    run_id: OpaqueId | None
    finding_id: OpaqueId | None
    details_ref: ArtifactRef | None
    extensions: tuple[ContractExtension, ...] = Field(default=(), max_length=32)

    @field_validator("extensions")
    @classmethod
    def _canonicalize_extensions(
        cls, value: tuple[ContractExtension, ...]
    ) -> tuple[ContractExtension, ...]:
        return tuple(sorted(value, key=lambda extension: extension.namespace))

    @model_validator(mode="after")
    def _validate_definition(self) -> Self:
        expected = CLI_ERROR_DEFINITIONS[self.error_code]
        if (
            self.category is not expected.category
            or self.retryable is not expected.retryable
            or self.safe_message is not expected.safe_message
        ):
            raise ValueError("CLI error fields do not match the closed error definition")
        namespaces = [extension.namespace for extension in self.extensions]
        if len(namespaces) != len(set(namespaces)):
            raise ValueError("extension namespaces must be unique")
        return self


class CliErrorResult(WireModel):
    command: CliCommand | None
    cli_outcome: CliErrorOutcome
    exit_code: CliExitCode
    error: CliErrorEnvelope

    @model_validator(mode="after")
    def _validate_result_mapping(self) -> Self:
        expected = CLI_ERROR_DEFINITIONS[self.error.error_code]
        if self.cli_outcome is not expected.cli_outcome or self.exit_code is not expected.exit_code:
            raise ValueError("CLI result does not match the closed error definition")
        return self


class CliDoctorCheck(WireModel):
    check_id: CliDoctorCheckId
    check_outcome: Literal[CliDoctorCheckOutcome.READY]
    reason_code: CliDoctorReasonCode

    @model_validator(mode="after")
    def _validate_reason(self) -> Self:
        expected = dict(_DOCTOR_CHECKS)[self.check_id]
        if self.reason_code is not expected:
            raise ValueError("doctor check reason does not match its check ID")
        return self


class CliDoctorResult(WireModel):
    command: Literal[CliCommand.DOCTOR]
    diagnostic_scope: Literal[CliDiagnosticScope.FOUNDATION_CONFIGURATION_ONLY]
    cli_outcome: Literal[CliDoctorOutcome.DIAGNOSTIC_COMPLETED]
    exit_code: Literal[CliExitCode.COMPLETED]
    scan_readiness: Literal[CliScanReadiness.NOT_EVALUATED]
    checks: tuple[CliDoctorCheck, ...] = Field(min_length=4, max_length=4)

    @field_validator("checks")
    @classmethod
    def _validate_checks(cls, value: tuple[CliDoctorCheck, ...]) -> tuple[CliDoctorCheck, ...]:
        actual = tuple((check.check_id, check.reason_code) for check in value)
        if actual != _DOCTOR_CHECKS:
            raise ValueError("doctor checks must be complete and in canonical order")
        return value


def exit_code_for_audit_outcome(outcome: AuditRunOutcome) -> CliExitCode:
    """Map an already trusted domain outcome; never derive policy or analysis state."""

    if not isinstance(outcome, AuditRunOutcome):
        raise TypeError("outcome must be an AuditRunOutcome")
    return {
        AuditRunOutcome.PASS: CliExitCode.COMPLETED,
        AuditRunOutcome.FAIL: CliExitCode.POLICY_FAIL,
        AuditRunOutcome.INDETERMINATE: CliExitCode.INDETERMINATE,
        AuditRunOutcome.ERROR: CliExitCode.OPERATIONAL_ERROR,
        AuditRunOutcome.CANCELLED: CliExitCode.CANCELLED_OR_SUPERSEDED,
        AuditRunOutcome.SUPERSEDED: CliExitCode.CANCELLED_OR_SUPERSEDED,
    }[outcome]


def cli_error_result(
    code: CliErrorCode,
    *,
    correlation_id: str,
    command: CliCommand | None,
) -> CliErrorResult:
    """Build a safe result only from the closed table; no caller message is accepted."""

    definition = CLI_ERROR_DEFINITIONS[code]
    return CliErrorResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        command=command,
        cli_outcome=definition.cli_outcome,
        exit_code=definition.exit_code,
        error=CliErrorEnvelope(
            error_code=code,
            category=definition.category,
            retryable=definition.retryable,
            safe_message=definition.safe_message,
            correlation_id=correlation_id,
            run_id=None,
            finding_id=None,
            details_ref=None,
        ),
    )


PUBLIC_CLI_ROOT_MODELS: Final[dict[str, type[WireModel]]] = {
    "cli-doctor-result": CliDoctorResult,
    "cli-error-result": CliErrorResult,
}


__all__ = [
    "CLI_ERROR_DEFINITIONS",
    "PUBLIC_CLI_ROOT_MODELS",
    "CliCommand",
    "CliDiagnosticScope",
    "CliDoctorCheck",
    "CliDoctorCheckId",
    "CliDoctorCheckOutcome",
    "CliDoctorOutcome",
    "CliDoctorReasonCode",
    "CliDoctorResult",
    "CliErrorCategory",
    "CliErrorCode",
    "CliErrorEnvelope",
    "CliErrorOutcome",
    "CliErrorResult",
    "CliExitCode",
    "CliSafeMessage",
    "CliScanReadiness",
    "cli_error_result",
    "exit_code_for_audit_outcome",
]
