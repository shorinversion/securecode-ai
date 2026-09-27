"""Hardened OCI sandbox driver with an injected container runtime port."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Final, Protocol, cast

from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, ResourceUsage
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
    _teardown_hash,
)

_IMAGE_DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_ABS_CONTAINER_PATH: Final = re.compile(r"/[A-Za-z0-9][A-Za-z0-9._/-]{0,1023}\Z")


@dataclass(frozen=True, slots=True)
class OciRuntimeAttestation:
    runtime_id: str
    runtime_version: str
    rootless_engine: bool
    user_namespace_enabled: bool
    seccomp_enabled: bool
    apparmor_or_selinux_enabled: bool
    cgroup_limits_enabled: bool
    host_socket_mounted: bool
    runtime_sha256: str
    image_digest: str
    attestation_sha256: str
    desktop_vm_isolation: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.runtime_id) is not str
            or _ID.fullmatch(self.runtime_id) is None
            or type(self.runtime_version) is not str
            or _ID.fullmatch(self.runtime_version) is None
            or any(
                type(value) is not bool
                for value in (
                    self.rootless_engine,
                    self.user_namespace_enabled,
                    self.desktop_vm_isolation,
                    self.seccomp_enabled,
                    self.apparmor_or_selinux_enabled,
                    self.cgroup_limits_enabled,
                    self.host_socket_mounted,
                )
            )
            or type(self.runtime_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.runtime_sha256) is None
            or type(self.image_digest) is not str
            or _IMAGE_DIGEST.fullmatch(self.image_digest) is None
            or type(self.attestation_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.attestation_sha256) is None
            or self.rootless_engine != self.user_namespace_enabled
            or self.desktop_vm_isolation == self.rootless_engine
            or self.attestation_sha256 != _runtime_attestation_hash(self)
        ):
            raise SandboxError(SandboxErrorCode.ATTESTATION_FAILED)


@dataclass(frozen=True, slots=True)
class OciLaunchSpec:
    workload_id: str
    image_digest: str
    argv: tuple[str, ...]
    user: str
    working_directory: str
    network_mode: str
    read_only_root: bool
    rootless: bool
    no_new_privileges: bool
    capability_drop: tuple[str, ...]
    seccomp_profile_id: str
    writable_tmpfs: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    cpu_time_ms: int
    memory_bytes: int
    pids_limit: int
    disk_bytes: int
    output_bytes: int
    elapsed_ms: int


@dataclass(frozen=True, slots=True)
class OciRuntimeResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    elapsed_ms: int
    cpu_time_ms: int
    peak_memory_bytes: int
    disk_bytes: int
    processes_peak: int
    network_packets: int
    oom_killed: bool
    timed_out: bool
    cancelled: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.exit_code) is not int
            or type(self.stdout) is not bytes
            or type(self.stderr) is not bytes
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.elapsed_ms,
                    self.cpu_time_ms,
                    self.peak_memory_bytes,
                    self.disk_bytes,
                    self.processes_peak,
                    self.network_packets,
                )
            )
            or type(self.oom_killed) is not bool
            or type(self.timed_out) is not bool
            or type(self.cancelled) is not bool
        ):
            raise SandboxError(SandboxErrorCode.DRIVER_FAILURE)


@dataclass(frozen=True, slots=True)
class OciCleanupResult:
    attempted: bool
    completed: bool
    live_workloads: int
    reusable_volumes: int


class OciRuntime(Protocol):
    def attest(self) -> OciRuntimeAttestation: ...

    def run(self, spec: OciLaunchSpec) -> OciRuntimeResult: ...

    def cleanup(self, workload_id: str) -> OciCleanupResult: ...


class HardenedOciSandboxDriver:
    """Translate a Core sandbox request into a closed OCI launch spec."""

    __slots__ = (
        "_commands",
        "_image_digest",
        "_last_workload_id",
        "_runtime",
        "_seccomp_profile_id",
    )

    def __init__(
        self,
        *,
        runtime: object,
        image_digest: str,
        command_allowlist: dict[str, tuple[str, ...]],
        seccomp_profile_id: str,
    ) -> None:
        if (
            not _runtime_like(runtime)
            or type(image_digest) is not str
            or _IMAGE_DIGEST.fullmatch(image_digest) is None
            or type(command_allowlist) is not dict
            or not command_allowlist
            or type(seccomp_profile_id) is not str
            or _ID.fullmatch(seccomp_profile_id) is None
        ):
            raise SandboxError(SandboxErrorCode.REQUEST_INVALID)
        copied: dict[str, tuple[str, ...]] = {}
        for command_id, argv in command_allowlist.items():
            if (
                type(command_id) is not str
                or _ID.fullmatch(command_id) is None
                or type(argv) is not tuple
                or not argv
                or any(not _safe_argument(value) for value in argv)
            ):
                raise SandboxError(SandboxErrorCode.REQUEST_INVALID)
            copied[command_id] = argv
        self._runtime = cast(OciRuntime, runtime)
        self._image_digest = image_digest
        self._commands = copied
        self._seccomp_profile_id = seccomp_profile_id
        self._last_workload_id: str | None = None

    def attest(self, profile: SandboxProfile) -> SandboxAttestation:
        if type(profile) is not SandboxProfile:
            raise SandboxError(SandboxErrorCode.PROFILE_INVALID)
        try:
            runtime = self._runtime.attest()
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception as error:
            raise SandboxError(SandboxErrorCode.ATTESTATION_FAILED) from error
        if type(runtime) is not OciRuntimeAttestation:
            raise SandboxError(SandboxErrorCode.ATTESTATION_FAILED)
        rootless = runtime.rootless_engine and runtime.user_namespace_enabled
        desktop = runtime.desktop_vm_isolation and not (
            runtime.rootless_engine or runtime.user_namespace_enabled
        )
        if (
            not (rootless or desktop)
            or not runtime.seccomp_enabled
            or not runtime.apparmor_or_selinux_enabled
            or not runtime.cgroup_limits_enabled
            or runtime.host_socket_mounted
            or runtime.image_digest != self._image_digest
        ):
            raise SandboxError(SandboxErrorCode.ATTESTATION_FAILED)
        value = object.__new__(SandboxAttestation)
        fields = {
            "profile_id": profile.profile_id,
            "profile_version": profile.profile_version,
            "profile_sha256": profile.profile_sha256,
            "network_disabled": True,
            "credentials_disabled": True,
            "host_access_disabled": True,
            "rootless": rootless,
            "desktop_vm_isolation": desktop,
            "read_only_root": True,
            "attestation_sha256": "0" * 64,
            "schema_version": "1.0.0",
        }
        for name, item in fields.items():
            object.__setattr__(value, name, item)
        return SandboxAttestation(
            profile_id=profile.profile_id,
            profile_version=profile.profile_version,
            profile_sha256=profile.profile_sha256,
            network_disabled=True,
            credentials_disabled=True,
            host_access_disabled=True,
            rootless=rootless,
            desktop_vm_isolation=desktop,
            read_only_root=True,
            attestation_sha256=_attestation_hash(value),
        )

    def execute(self, command: SandboxCommand, profile: SandboxProfile) -> SandboxObservation:
        if type(command) is not SandboxCommand or type(profile) is not SandboxProfile:
            raise SandboxError(SandboxErrorCode.REQUEST_INVALID)
        prefix = self._commands.get(command.command_id)
        if prefix is None:
            raise SandboxError(SandboxErrorCode.REQUEST_INVALID)
        workload_id = (
            "sandbox-"
            + hashlib.sha256(
                (profile.profile_sha256 + "\x00" + command.command_id).encode("ascii")
            ).hexdigest()[:40]
        )
        self._last_workload_id = workload_id
        spec = OciLaunchSpec(
            workload_id=workload_id,
            image_digest=self._image_digest,
            argv=prefix + tuple(command.arguments),
            user="65532:65532",
            working_directory="/workspace",
            network_mode="none",
            read_only_root=True,
            rootless=True,
            no_new_privileges=True,
            capability_drop=("ALL",),
            seccomp_profile_id=self._seccomp_profile_id,
            writable_tmpfs=("/tmp", "/scratch"),
            environment=(("HOME", "/tmp"), ("TMPDIR", "/tmp")),
            cpu_time_ms=profile.max_cpu_time_ms,
            memory_bytes=profile.max_memory_bytes,
            pids_limit=profile.max_processes,
            disk_bytes=profile.max_disk_bytes,
            output_bytes=profile.max_output_bytes,
            elapsed_ms=profile.max_elapsed_ms,
        )
        try:
            result = self._runtime.run(spec)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception as error:
            raise SandboxError(SandboxErrorCode.DRIVER_FAILURE) from error
        if type(result) is not OciRuntimeResult:
            raise SandboxError(SandboxErrorCode.DRIVER_FAILURE)
        if result.cancelled:
            raise SandboxError(SandboxErrorCode.DRIVER_FAILURE)
        output = result.stdout + result.stderr
        exceeded = (
            len(output) > profile.max_output_bytes
            or result.elapsed_ms > profile.max_elapsed_ms
            or result.cpu_time_ms > profile.max_cpu_time_ms
            or result.peak_memory_bytes > profile.max_memory_bytes
            or result.disk_bytes > profile.max_disk_bytes
            or result.processes_peak > profile.max_processes
            or result.network_packets != 0
            or result.oom_killed
            or result.timed_out
        )
        outcome = (
            SandboxOutcome.INDETERMINATE
            if exceeded or result.exit_code == 78
            else SandboxOutcome.SUCCEEDED
            if result.exit_code == 0
            else SandboxOutcome.FAILED
        )
        retained_output = output[: profile.max_output_bytes]
        output_sha = hashlib.sha256(retained_output).hexdigest()
        usage = ResourceUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            elapsed_ms=result.elapsed_ms,
            peak_memory_bytes=result.peak_memory_bytes,
            cpu_time_ms=result.cpu_time_ms,
        )
        value = object.__new__(SandboxObservation)
        fields = {
            "outcome": outcome,
            "output_sha256": output_sha,
            "output_size_bytes": len(retained_output),
            "resource_usage": usage,
            "observation_sha256": "0" * 64,
            "schema_version": "1.0.0",
        }
        for name, item in fields.items():
            object.__setattr__(value, name, item)
        return SandboxObservation(
            outcome=outcome,
            output_sha256=output_sha,
            output_size_bytes=len(retained_output),
            resource_usage=usage,
            observation_sha256=_observation_hash(value),
        )

    def teardown(self) -> SandboxTeardownReceipt:
        workload_id = self._last_workload_id
        if workload_id is None:
            return _teardown_receipt(True, True, 0, 0)
        try:
            result = self._runtime.cleanup(workload_id)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception as error:
            raise SandboxError(SandboxErrorCode.TEARDOWN_FAILED) from error
        finally:
            self._last_workload_id = None
        if type(result) is not OciCleanupResult:
            raise SandboxError(SandboxErrorCode.TEARDOWN_FAILED)
        return _teardown_receipt(
            result.attempted,
            result.completed,
            result.live_workloads,
            result.reusable_volumes,
        )


def _teardown_receipt(
    attempted: bool,
    completed: bool,
    live_workloads: int,
    reusable_volumes: int,
) -> SandboxTeardownReceipt:
    value = object.__new__(SandboxTeardownReceipt)
    fields = {
        "attempted": attempted,
        "completed": completed,
        "live_workloads": live_workloads,
        "reusable_volumes": reusable_volumes,
        "receipt_sha256": "0" * 64,
        "schema_version": "1.0.0",
    }
    for name, item in fields.items():
        object.__setattr__(value, name, item)
    return SandboxTeardownReceipt(
        attempted=attempted,
        completed=completed,
        live_workloads=live_workloads,
        reusable_volumes=reusable_volumes,
        receipt_sha256=_teardown_hash(value),
    )


def _runtime_attestation_hash(value: OciRuntimeAttestation) -> str:
    material = "\x00".join(
        str(getattr(value, name))
        for name in OciRuntimeAttestation.__dataclass_fields__
        if name != "attestation_sha256"
    ).encode("utf-8")
    return hashlib.sha256(b"securecode-ai/oci-runtime-attestation/v1\x00" + material).hexdigest()


def _required_mac_security_opt(options: tuple[str, ...]) -> str | None:
    if any("apparmor" in item for item in options):
        return "apparmor=docker-default"
    if any("selinux" in item for item in options):
        return "label=type:container_t"
    return None


def _oci_security_options(value: object) -> tuple[str, ...]:
    if type(value) is not list:
        return ()
    return tuple(
        item.lower() if type(item) is str else json.dumps(item, sort_keys=True).lower()
        for item in value
        if type(item) in (str, dict)
    )


def _safe_oci_image_environment(value: object, sensitive: re.Pattern[str]) -> bool:
    if value is None:
        return True
    return type(value) is list and all(
        type(item) is str
        and len(item) <= 4096
        and "=" in item
        and sensitive.search(item.partition("=")[0]) is None
        for item in value
    )


def _container_mac_enforced(inspected: dict[str, object], security_opt: str) -> bool:
    host_config = inspected.get("HostConfig")
    configured = host_config.get("SecurityOpt") if type(host_config) is dict else None
    if type(configured) is not list or security_opt not in configured:
        return False
    kind, _, policy = security_opt.partition("=")
    if kind == "apparmor":
        return inspected.get("AppArmorProfile") == policy
    process_label = inspected.get("ProcessLabel")
    return (
        kind == "label"
        and type(process_label) is str
        and f":{policy.removeprefix('type:')}:" in process_label
    )


def _runtime_like(value: object) -> bool:
    return all(callable(getattr(value, name, None)) for name in ("attest", "run", "cleanup"))


def _safe_argument(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 4096
        and all(ord(character) >= 32 and character not in "\r\n\x00" for character in value)
    )


__all__ = [
    "HardenedOciSandboxDriver",
    "OciCleanupResult",
    "OciLaunchSpec",
    "OciRuntime",
    "OciRuntimeAttestation",
    "OciRuntimeResult",
]
