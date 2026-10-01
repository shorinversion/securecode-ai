"""Fail-closed CLI foundation with explicit non-product diagnostic composition."""

from __future__ import annotations

import ctypes
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol

from securecode_ai.adapters import ProviderProfileRegistry, resolve_configuration
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CliCommand,
    CliDiagnosticScope,
    CliDoctorCheck,
    CliDoctorCheckId,
    CliDoctorCheckOutcome,
    CliDoctorOutcome,
    CliDoctorReasonCode,
    CliDoctorResult,
    CliExitCode,
    CliScanReadiness,
    ProviderProfile,
)
from securecode_ai.core import CONTRACT_SCHEMA_VERSION as CORE_CONTRACT_SCHEMA_VERSION

from .diagnostic import (
    DiagnosticFormat,
)

CLI_VERSION: Final = "1.1.0"
FOUNDATION_PROFILE_SELECTOR: Final = "securecode-foundation-fake@0.2.0"
FOUNDATION_PROFILE_CONTENT_SHA256: Final = "\x31\x33\x61\x35\x65\x65\x32\x32\x64\x37\x31\x62\x39\x63\x63\x66\x33\x33\x64\x34\x30\x35\x37\x30\x35\x30\x65\x62\x66\x31\x39\x65\x31\x33\x38\x62\x33\x37\x32\x37\x66\x35\x61\x63\x34\x30\x30\x31\x35\x38\x31\x37\x38\x62\x31\x38\x33\x66\x32\x37\x33\x39\x34\x39"
FOUNDATION_DEFAULTS: Final = {
    "provider_profile": FOUNDATION_PROFILE_SELECTOR,
    "policy_profile": "foundation-advisory",
    "egress_profile": "air_gap",
}
_HUMAN_SUCCESS: Final = (
    "foundation configuration diagnostics completed; scan readiness was not evaluated"
)
_HUMAN_DIAGNOSTIC_SUCCESS: Final = (
    "deterministic diagnostic completed; product scan outcome was not evaluated"
)
_WIN_INVALID_HANDLE: Final = ctypes.c_void_p(-1).value
_WIN_GENERIC_WRITE: Final = 0x40000000
_WIN_CREATE_NEW: Final = 1
_WIN_FILE_ATTRIBUTE_NORMAL: Final = 0x80
_WIN_FILE_FLAG_OPEN_REPARSE_POINT: Final = 0x00200000


class Doctor(Protocol):
    def run(self, environment: Mapping[str, str]) -> CliDoctorResult: ...


class FoundationConfigurationError(ValueError):
    """Safe closed signal; never stores or renders rejected configuration."""


class FoundationCapabilityError(ValueError):
    """Safe closed signal for declaration-only capability incompatibility."""


@dataclass(frozen=True, slots=True)
class _DiagnosticScanArguments:
    target: str
    report_format: DiagnosticFormat
    output: Path | None


def build_foundation_profile() -> ProviderProfile:
    return ProviderProfile.model_validate(
        {
            "schema_version": "0.2.0",
            "profile_id": "securecode-foundation-fake",
            "profile_version": "0.2.0",
            "provider_kind": "fake",
            "api_dialect": "fake",
            "endpoint": {
                "base_url": "fake://local",
                "authority": "local",
                "allowed_ports": [1],
                "follow_redirects": False,
                "local_plaintext_exception": False,
            },
            "execution_boundary": "local_runner",
            "model_id": "securecode-foundation-fake",
            "model_snapshot": "0.2.0",
            "protocol_framing_token_upper_bound": None,
            "capabilities": {
                "structured_output": True,
                "native_refusal_signal": True,
                "native_incomplete_signal": True,
                "tool_calling": False,
                "source_code_analysis": True,
                "repository_tool_calls": False,
                "repository_tools": [],
                "max_context_tokens": 32768,
                "max_output_tokens": 4096,
            },
            "data_terms": {
                "evidence_status": "not_applicable_local",
                "residency": ["local"],
                "retention_seconds": 0,
                "training_use": "not_applicable_local",
                "zero_data_retention": True,
                "maximum_input_data_class": "DC3_CONFIDENTIAL_SOURCE",
                "allowed_purposes": ["model_native_discovery"],
                "evidence_ref": None,
            },
            "credential_ref": None,
            "egress_profiles": ["air_gap"],
            "budgets": {
                "timeout_seconds": 30,
                "max_attempts": 1,
                "max_total_tokens": 32768,
            },
        }
    )


class FoundationDoctor:
    """Run exactly four source-free structural diagnostics with no provider call."""

    __slots__ = ("_defaults", "_profile", "_repository", "_user")

    def __init__(
        self,
        *,
        profile: ProviderProfile | None = None,
        defaults: Mapping[str, object] | None = None,
        user: Mapping[str, object] | None = None,
        repository: Mapping[str, object] | None = None,
    ) -> None:
        self._profile = profile or build_foundation_profile()
        self._defaults = dict(FOUNDATION_DEFAULTS if defaults is None else defaults)
        self._user = dict(user or {})
        self._repository = dict(repository or {})

    def run(self, environment: Mapping[str, str]) -> CliDoctorResult:
        profile = self._profile
        capabilities = profile.capabilities
        if not all(
            (
                capabilities.structured_output,
                capabilities.native_refusal_signal,
                capabilities.native_incomplete_signal,
                capabilities.source_code_analysis,
            )
        ):
            raise FoundationCapabilityError
        if (
            profile.selector != FOUNDATION_PROFILE_SELECTOR
            or profile.canonical_content_hash() != FOUNDATION_PROFILE_CONTENT_SHA256
            or CORE_CONTRACT_SCHEMA_VERSION != CONTRACT_SCHEMA_VERSION
        ):
            raise FoundationConfigurationError

        registry = ProviderProfileRegistry((profile,))
        configuration = resolve_configuration(
            registry=registry,
            defaults=self._defaults,
            user=self._user,
            repository=self._repository,
            environment=environment,
        )
        if (
            configuration.provider_profile.selector != FOUNDATION_PROFILE_SELECTOR
            or configuration.provider_profile.canonical_content_hash()
            != FOUNDATION_PROFILE_CONTENT_SHA256
            or configuration.egress_profile not in configuration.provider_profile.egress_profiles
        ):
            raise FoundationConfigurationError

        checks = (
            CliDoctorCheck(
                schema_version=CONTRACT_SCHEMA_VERSION,
                check_id=CliDoctorCheckId.CONFIGURATION_RESOLUTION,
                check_outcome=CliDoctorCheckOutcome.READY,
                reason_code=CliDoctorReasonCode.CONFIGURATION_VALID,
            ),
            CliDoctorCheck(
                schema_version=CONTRACT_SCHEMA_VERSION,
                check_id=CliDoctorCheckId.FOUNDATION_PROFILE_IDENTITY,
                check_outcome=CliDoctorCheckOutcome.READY,
                reason_code=CliDoctorReasonCode.PROFILE_IDENTITY_VALID,
            ),
            CliDoctorCheck(
                schema_version=CONTRACT_SCHEMA_VERSION,
                check_id=CliDoctorCheckId.SELECTED_EGRESS_MEMBERSHIP,
                check_outcome=CliDoctorCheckOutcome.READY,
                reason_code=CliDoctorReasonCode.EGRESS_MEMBERSHIP_VALID,
            ),
            CliDoctorCheck(
                schema_version=CONTRACT_SCHEMA_VERSION,
                check_id=CliDoctorCheckId.SOURCE_FREE_CAPABILITY_DECLARATION,
                check_outcome=CliDoctorCheckOutcome.READY,
                reason_code=CliDoctorReasonCode.CAPABILITY_DECLARATION_VALID,
            ),
        )
        return CliDoctorResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            command=CliCommand.DOCTOR,
            diagnostic_scope=CliDiagnosticScope.FOUNDATION_CONFIGURATION_ONLY,
            cli_outcome=CliDoctorOutcome.DIAGNOSTIC_COMPLETED,
            exit_code=CliExitCode.COMPLETED,
            scan_readiness=CliScanReadiness.NOT_EVALUATED,
            checks=checks,
        )
