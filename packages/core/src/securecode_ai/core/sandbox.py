"""Typed Core port for credential-free, no-network sandbox execution.

The Core owns admission and receipts; an injected driver owns the actual
platform isolation.  This module never starts a subprocess, opens a socket, or
accesses the host filesystem.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from securecode_ai.contracts import ResourceUsage

_SCHEMA_VERSION: Final = "1.0.0"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_ARGS: Final = 64
_MAX_OUTPUT_BYTES: Final = 131_072
_HASH_DOMAIN: Final = b"securecode-ai/sandbox-receipt/v1\x00"


class SandboxErrorCode(StrEnum):
    REQUEST_INVALID = "REQUEST_INVALID"
    PROFILE_INVALID = "PROFILE_INVALID"
    ATTESTATION_FAILED = "ATTESTATION_FAILED"
    DRIVER_FAILURE = "DRIVER_FAILURE"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    TEARDOWN_FAILED = "TEARDOWN_FAILED"


class SandboxOutcome(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"
    ERROR = "ERROR"


class SandboxError(ValueError):
    """Fixed, non-echoing sandbox boundary failure."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: SandboxErrorCode) -> None:
        if type(code) is not SandboxErrorCode:
            raise TypeError("sandbox error code is invalid")
        self.code = code
        self.safe_message = "sandbox contract validation failed"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class SandboxProfile:
    """Closed required isolation and resource policy for one execution."""

    profile_id: str
    profile_version: str
    network_disabled: bool
    credentials_disabled: bool
    host_access_disabled: bool
    rootless: bool
    read_only_root: bool
    max_cpu_time_ms: int
    max_memory_bytes: int
    max_processes: int
    max_disk_bytes: int
    max_output_bytes: int
    max_elapsed_ms: int
    profile_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        limits = (
            self.max_cpu_time_ms,
            self.max_memory_bytes,
            self.max_processes,
            self.max_disk_bytes,
            self.max_output_bytes,
            self.max_elapsed_ms,
        )
        if (
            self.schema_version != _SCHEMA_VERSION
            or _ID.fullmatch(self.profile_id) is None
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.profile_version)
            or any(
                type(value) is not bool or not value
                for value in (
                    self.network_disabled,
                    self.credentials_disabled,
                    self.host_access_disabled,
                    self.rootless,
                    self.read_only_root,
                )
            )
            or any(type(value) is not int or value < 1 for value in limits)
            or self.max_output_bytes > _MAX_OUTPUT_BYTES
            or _SHA256.fullmatch(self.profile_sha256) is None
            or self.profile_sha256 != _profile_hash(self)
        ):
            raise SandboxError(SandboxErrorCode.PROFILE_INVALID)


@dataclass(frozen=True, slots=True)
class SandboxCommand:
    """Typed command identity; no shell expression or host path is accepted."""

    command_id: str
    arguments: tuple[str, ...] = ()
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or _ID.fullmatch(self.command_id) is None
            or type(self.arguments) is not tuple
            or len(self.arguments) > _MAX_ARGS
            or any(
                type(value) is not str
                or not value
                or len(value) > 4096
                or any(ord(char) < 32 or char in "\r\n\x00" for char in value)
                for value in self.arguments
            )
        ):
            raise SandboxError(SandboxErrorCode.REQUEST_INVALID)


@dataclass(frozen=True, slots=True)
class SandboxAttestation:
    profile_id: str
    profile_version: str
    profile_sha256: str
    network_disabled: bool
    credentials_disabled: bool
    host_access_disabled: bool
    rootless: bool
    read_only_root: bool
    attestation_sha256: str
    schema_version: str = _SCHEMA_VERSION
    desktop_vm_isolation: bool = False

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or _ID.fullmatch(self.profile_id) is None
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.profile_version)
            or _SHA256.fullmatch(self.profile_sha256) is None
            or any(
                type(value) is not bool
                for value in (
                    self.network_disabled,
                    self.credentials_disabled,
                    self.host_access_disabled,
                    self.rootless,
                    self.desktop_vm_isolation,
                    self.read_only_root,
                )
            )
            or not all(
                (self.network_disabled, self.credentials_disabled, self.host_access_disabled)
            )
            or self.rootless == self.desktop_vm_isolation
            or not self.read_only_root
            or _SHA256.fullmatch(self.attestation_sha256) is None
            or self.attestation_sha256 != _attestation_hash(self)
        ):
            raise SandboxError(SandboxErrorCode.ATTESTATION_FAILED)


@dataclass(frozen=True, slots=True)
class SandboxObservation:
    outcome: SandboxOutcome
    output_sha256: str | None
    output_size_bytes: int
    resource_usage: ResourceUsage
    observation_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or type(self.outcome) is not SandboxOutcome
            or (self.output_sha256 is not None and _SHA256.fullmatch(self.output_sha256) is None)
            or type(self.output_size_bytes) is not int
            or not 0 <= self.output_size_bytes <= _MAX_OUTPUT_BYTES
            or type(self.resource_usage) is not ResourceUsage
            or _SHA256.fullmatch(self.observation_sha256) is None
            or self.observation_sha256 != _observation_hash(self)
        ):
            raise SandboxError(SandboxErrorCode.DRIVER_FAILURE)


@dataclass(frozen=True, slots=True)
class SandboxTeardownReceipt:
    attempted: bool
    completed: bool
    live_workloads: int
    reusable_volumes: int
    receipt_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or self.attempted is not True
            or type(self.completed) is not bool
            or type(self.live_workloads) is not int
            or type(self.reusable_volumes) is not int
            or self.live_workloads < 0
            or self.reusable_volumes < 0
            or (self.completed and (self.live_workloads or self.reusable_volumes))
            or _SHA256.fullmatch(self.receipt_sha256) is None
            or self.receipt_sha256 != _teardown_hash(self)
        ):
            raise SandboxError(SandboxErrorCode.TEARDOWN_FAILED)


@dataclass(frozen=True, slots=True)
class SandboxExecutionReceipt:
    command_id: str
    profile_id: str
    profile_sha256: str
    attestation_sha256: str | None
    outcome: SandboxOutcome
    observation_sha256: str | None
    teardown: SandboxTeardownReceipt
    reason_code: SandboxErrorCode | None
    receipt_sha256: str
    schema_version: str = _SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            self.schema_version != _SCHEMA_VERSION
            or _ID.fullmatch(self.command_id) is None
            or _ID.fullmatch(self.profile_id) is None
            or _SHA256.fullmatch(self.profile_sha256) is None
            or (
                self.attestation_sha256 is not None
                and _SHA256.fullmatch(self.attestation_sha256) is None
            )
            or type(self.outcome) is not SandboxOutcome
            or (
                self.observation_sha256 is not None
                and _SHA256.fullmatch(self.observation_sha256) is None
            )
            or type(self.teardown) is not SandboxTeardownReceipt
            or (self.reason_code is not None and type(self.reason_code) is not SandboxErrorCode)
            or _SHA256.fullmatch(self.receipt_sha256) is None
            or self.receipt_sha256 != _receipt_hash(self)
        ):
            raise SandboxError(SandboxErrorCode.DRIVER_FAILURE)


class SandboxDriver(Protocol):
    """Narrow injected platform port; implementations live outside Core."""

    def attest(self, profile: SandboxProfile) -> SandboxAttestation: ...

    def execute(self, command: SandboxCommand, profile: SandboxProfile) -> SandboxObservation: ...

    def teardown(self) -> SandboxTeardownReceipt: ...


def run_in_sandbox(
    profile: SandboxProfile,
    command: SandboxCommand,
    driver: SandboxDriver,
) -> SandboxExecutionReceipt:
    """Attest isolation before execution and always request teardown."""

    checked_profile = _copy_profile(profile)
    checked_command = _copy_command(command)
    if any(not callable(getattr(driver, name, None)) for name in ("attest", "execute", "teardown")):
        raise SandboxError(SandboxErrorCode.REQUEST_INVALID)
    attestation: SandboxAttestation | None = None
    observation: SandboxObservation | None = None
    reason: SandboxErrorCode | None = None
    try:
        attestation = _copy_attestation(driver.attest(checked_profile))
        if not _attestation_matches(attestation, checked_profile):
            reason = SandboxErrorCode.ATTESTATION_FAILED
        else:
            observation = _copy_observation(driver.execute(checked_command, checked_profile))
            if (
                observation.output_size_bytes > checked_profile.max_output_bytes
                or _observed_resource_exceeded(observation.resource_usage, checked_profile)
            ):
                reason = SandboxErrorCode.RESOURCE_LIMIT
    except Exception:
        reason = SandboxErrorCode.DRIVER_FAILURE
    finally:
        try:
            teardown = _copy_teardown(driver.teardown())
        except Exception:
            teardown = _failed_teardown()
            reason = SandboxErrorCode.TEARDOWN_FAILED
    outcome = (
        observation.outcome
        if observation is not None and reason is None
        else SandboxOutcome.INDETERMINATE
    )
    return _make_receipt(
        checked_command, checked_profile, attestation, observation, teardown, outcome, reason
    )


def _copy_profile(value: SandboxProfile) -> SandboxProfile:
    if type(value) is not SandboxProfile:
        raise SandboxError(SandboxErrorCode.PROFILE_INVALID)
    try:
        return SandboxProfile(
            **{name: getattr(value, name) for name in SandboxProfile.__dataclass_fields__}
        )
    except (AttributeError, TypeError, ValueError):
        raise SandboxError(SandboxErrorCode.PROFILE_INVALID) from None


def _copy_command(value: SandboxCommand) -> SandboxCommand:
    if type(value) is not SandboxCommand:
        raise SandboxError(SandboxErrorCode.REQUEST_INVALID)
    try:
        return SandboxCommand(value.command_id, tuple(value.arguments), value.schema_version)
    except (AttributeError, TypeError, ValueError):
        raise SandboxError(SandboxErrorCode.REQUEST_INVALID) from None


def _copy_attestation(value: SandboxAttestation) -> SandboxAttestation:
    if type(value) is not SandboxAttestation:
        raise SandboxError(SandboxErrorCode.ATTESTATION_FAILED)
    try:
        return SandboxAttestation(
            **{name: getattr(value, name) for name in SandboxAttestation.__dataclass_fields__}
        )
    except (AttributeError, TypeError, ValueError):
        raise SandboxError(SandboxErrorCode.ATTESTATION_FAILED) from None


def _copy_observation(value: SandboxObservation) -> SandboxObservation:
    if type(value) is not SandboxObservation:
        raise SandboxError(SandboxErrorCode.DRIVER_FAILURE)
    try:
        return SandboxObservation(
            **{name: getattr(value, name) for name in SandboxObservation.__dataclass_fields__}
        )
    except (AttributeError, TypeError, ValueError):
        raise SandboxError(SandboxErrorCode.DRIVER_FAILURE) from None


def _copy_teardown(value: SandboxTeardownReceipt) -> SandboxTeardownReceipt:
    if type(value) is not SandboxTeardownReceipt:
        raise SandboxError(SandboxErrorCode.TEARDOWN_FAILED)
    try:
        return SandboxTeardownReceipt(
            **{name: getattr(value, name) for name in SandboxTeardownReceipt.__dataclass_fields__}
        )
    except (AttributeError, TypeError, ValueError):
        raise SandboxError(SandboxErrorCode.TEARDOWN_FAILED) from None


def _attestation_matches(value: SandboxAttestation, profile: SandboxProfile) -> bool:
    return (
        value.profile_id == profile.profile_id
        and value.profile_version == profile.profile_version
        and value.profile_sha256 == profile.profile_sha256
        and value.network_disabled == profile.network_disabled
        and value.credentials_disabled == profile.credentials_disabled
        and value.host_access_disabled == profile.host_access_disabled
        and (value.rootless or value.desktop_vm_isolation) == profile.rootless
        and value.read_only_root == profile.read_only_root
    )


def _observed_resource_exceeded(value: ResourceUsage, profile: SandboxProfile) -> bool:
    return (
        value.elapsed_ms > profile.max_elapsed_ms
        or value.cpu_time_ms > profile.max_cpu_time_ms
        or value.peak_memory_bytes > profile.max_memory_bytes
    )


def _profile_material(value: SandboxProfile) -> dict[str, object]:
    return {
        name: getattr(value, name)
        for name in SandboxProfile.__dataclass_fields__
        if name not in {"profile_sha256"}
    }


def _profile_hash(value: SandboxProfile) -> str:
    return _hash(_profile_material(value))


def _attestation_hash(value: SandboxAttestation) -> str:
    return _hash(
        {
            name: getattr(value, name)
            for name in SandboxAttestation.__dataclass_fields__
            if name not in {"attestation_sha256"}
        }
    )


def _observation_hash(value: SandboxObservation) -> str:
    return _hash(
        {
            "outcome": value.outcome.value,
            "output_sha256": value.output_sha256,
            "output_size_bytes": value.output_size_bytes,
            "resource_usage": value.resource_usage.model_dump(mode="json"),
            "schema_version": value.schema_version,
        }
    )


def _teardown_hash(value: SandboxTeardownReceipt) -> str:
    return _hash(
        {
            "attempted": value.attempted,
            "completed": value.completed,
            "live_workloads": value.live_workloads,
            "reusable_volumes": value.reusable_volumes,
            "schema_version": value.schema_version,
        }
    )


def _receipt_hash(value: SandboxExecutionReceipt) -> str:
    return _hash(
        {
            "attestation_sha256": value.attestation_sha256,
            "command_id": value.command_id,
            "observation_sha256": value.observation_sha256,
            "outcome": value.outcome.value,
            "profile_id": value.profile_id,
            "profile_sha256": value.profile_sha256,
            "reason_code": value.reason_code.value if value.reason_code else None,
            "schema_version": value.schema_version,
            "teardown": value.teardown.receipt_sha256,
        }
    )


def _hash(material: dict[str, object]) -> str:
    return hashlib.sha256(
        _HASH_DOMAIN
        + json.dumps(
            material, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()


def _failed_teardown() -> SandboxTeardownReceipt:
    value = object.__new__(SandboxTeardownReceipt)
    for name, item in {
        "attempted": True,
        "completed": False,
        "live_workloads": 1,
        "reusable_volumes": 1,
        "schema_version": _SCHEMA_VERSION,
        "receipt_sha256": "0" * 64,
    }.items():
        object.__setattr__(value, name, item)
    return SandboxTeardownReceipt(True, False, 1, 1, _teardown_hash(value))


def _make_receipt(
    command: SandboxCommand,
    profile: SandboxProfile,
    attestation: SandboxAttestation | None,
    observation: SandboxObservation | None,
    teardown: SandboxTeardownReceipt,
    outcome: SandboxOutcome,
    reason: SandboxErrorCode | None,
) -> SandboxExecutionReceipt:
    value = object.__new__(SandboxExecutionReceipt)
    fields = {
        "command_id": command.command_id,
        "profile_id": profile.profile_id,
        "profile_sha256": profile.profile_sha256,
        "attestation_sha256": attestation.attestation_sha256 if attestation else None,
        "outcome": outcome,
        "observation_sha256": observation.observation_sha256 if observation else None,
        "teardown": teardown,
        "reason_code": reason,
        "schema_version": _SCHEMA_VERSION,
        "receipt_sha256": "0" * 64,
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return SandboxExecutionReceipt(
        command_id=command.command_id,
        profile_id=profile.profile_id,
        profile_sha256=profile.profile_sha256,
        attestation_sha256=attestation.attestation_sha256 if attestation else None,
        outcome=outcome,
        observation_sha256=observation.observation_sha256 if observation else None,
        teardown=teardown,
        reason_code=reason,
        receipt_sha256=_receipt_hash(value),
        schema_version=_SCHEMA_VERSION,
    )


__all__ = [
    "SandboxAttestation",
    "SandboxCommand",
    "SandboxDriver",
    "SandboxError",
    "SandboxErrorCode",
    "SandboxExecutionReceipt",
    "SandboxObservation",
    "SandboxOutcome",
    "SandboxProfile",
    "SandboxTeardownReceipt",
    "run_in_sandbox",
]
