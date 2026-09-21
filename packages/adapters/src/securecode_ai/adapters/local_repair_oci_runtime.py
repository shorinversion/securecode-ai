"""Rootless Docker CLI adapter for the local repair child-container protocol."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Any, Final, cast

from securecode_ai.core.sandbox import SandboxProfile

from .local_repair_oci_isolation import (
    container_has_required_hardening,
    daemon_has_desktop_vm_isolation,
    verified_container_not_found,
)
from .local_repair_oci_protocol import (
    LocalRepairOciProtocolError,
    OciPreparationReceipt,
    image_digest,
    parse_preparation_receipt,
    parse_stage_receipt,
)
from .oci_sandbox import (
    OciCleanupResult,
    OciLaunchSpec,
    OciRuntimeAttestation,
    OciRuntimeResult,
    _container_mac_enforced,
    _oci_security_options,
    _required_mac_security_opt,
    _runtime_attestation_hash,
    _safe_oci_image_environment,
)

_CHILD_PREFIX: Final = (
    "/usr/local/bin/python",
    "-I",
    "-m",
    "securecode_ai.adapters.local_repair_oci_child",
)
_SAFE_CONTAINER: Final = re.compile(r"[a-z0-9][a-z0-9_.-]{0,62}\Z")
_MAX_DOCKER_OUTPUT: Final = 1024 * 1024
_CREATE_NO_WINDOW: Final[int] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_SENSITIVE_ENV: Final = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|API_KEY|ACCESS_KEY)", re.IGNORECASE
)


class LocalRepairOciRuntimeError(ValueError):
    def __init__(self, reason: str = "OCI_RUNTIME_UNAVAILABLE") -> None:
        self.reason = reason
        super().__init__("local repair OCI runtime is unavailable")
        self.__cause__ = None
        self.__context__ = None


class DockerCliOciRuntime:
    """Execute only the pinned validator protocol in a verified rootless engine."""

    __slots__ = (
        "_active",
        "_attestation",
        "_bundle_root",
        "_bundle_sha256",
        "_closed",
        "_desktop_vm_isolation",
        "_docker",
        "_docker_sha256",
        "_environment",
        "_fixed_head_sha",
        "_image_digest",
        "_image_reference",
        "_mac_security_opt",
        "_on_close",
        "_parent_head_sha",
        "_patch_sha256",
        "_profile",
    )

    def __init__(
        self,
        *,
        docker_executable: Path,
        docker_executable_sha256: str,
        image_reference: str,
        bundle_root: Path,
        bundle_sha256: str,
        parent_head_sha: str,
        patch_sha256: str,
        profile: SandboxProfile,
        environment: dict[str, str],
        on_close: Callable[[], None],
    ) -> None:
        if (
            not isinstance(docker_executable, Path)
            or not docker_executable.is_absolute()
            or not docker_executable.is_file()
            or docker_executable.is_symlink()
            or type(docker_executable_sha256) is not str
            or _SHA256.fullmatch(docker_executable_sha256) is None
            or not isinstance(bundle_root, Path)
            or not bundle_root.is_absolute()
            or not bundle_root.is_dir()
            or bundle_root.is_symlink()
            or type(profile) is not SandboxProfile
            or type(environment) is not dict
            or not callable(on_close)
        ):
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_CONFIGURATION_INVALID")
        try:
            digest = image_digest(image_reference)
        except LocalRepairOciProtocolError as error:
            raise LocalRepairOciRuntimeError(error.reason) from None
        if not all(
            re.fullmatch(r"[0-9a-f]+", item)
            for item in (bundle_sha256, parent_head_sha, patch_sha256)
        ):
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_CONFIGURATION_INVALID")
        self._docker = docker_executable
        self._docker_sha256 = docker_executable_sha256
        self._desktop_vm_isolation = False
        self._image_reference = image_reference
        self._image_digest = digest
        self._mac_security_opt: str | None = None
        self._bundle_root = bundle_root
        self._bundle_sha256 = bundle_sha256
        self._parent_head_sha = parent_head_sha
        self._patch_sha256 = patch_sha256
        self._profile = profile
        self._environment = dict(environment)
        self._on_close = on_close
        self._attestation: OciRuntimeAttestation | None = None
        self._fixed_head_sha: str | None = None
        self._active: dict[str, str] = {}
        self._closed = False

    @property
    def command_prefix(self) -> tuple[str, ...]:
        return _CHILD_PREFIX

    @property
    def image_digest(self) -> str:
        return self._image_digest

    def attest(self) -> OciRuntimeAttestation:
        self._ensure_open()
        self._verify_docker_executable()
        if self._attestation is not None:
            return self._attestation
        info_value = self._docker_json(("info", "--format", "{{json .}}"), timeout=10)
        version_value = self._docker_json(("version", "--format", "{{json .Server}}"), timeout=10)
        image = self._docker_json(("image", "inspect", self._image_reference), timeout=10)
        if (
            type(info_value) is not dict
            or type(version_value) is not dict
            or type(image) is not list
            or len(image) != 1
            or type(image[0]) is not dict
        ):
            raise LocalRepairOciRuntimeError("OCI_IMAGE_UNAVAILABLE")
        info = cast(dict[str, Any], info_value)
        version = cast(dict[str, Any], version_value)
        inspected = cast(dict[str, Any], image[0])
        repo_digests = inspected.get("RepoDigests")
        image_id = inspected.get("Id")
        config = inspected.get("Config")
        digests = repo_digests if type(repo_digests) is list else []
        if (
            not (
                image_id == self._image_digest
                or any(
                    type(item) is str and item.endswith("@" + self._image_digest)
                    for item in digests
                )
            )
            or type(config) is not dict
            or config.get("Volumes") not in (None, {})
            or not _safe_oci_image_environment(config.get("Env"), _SENSITIVE_ENV)
        ):
            raise LocalRepairOciRuntimeError("OCI_IMAGE_ATTESTATION_FAILED")
        options = _oci_security_options(info.get("SecurityOptions"))
        rootless = any("rootless" in item for item in options)
        desktop_vm = daemon_has_desktop_vm_isolation(info, options, windows_host=os.name == "nt")
        seccomp = any("seccomp" in item for item in options)
        mac_security_opt = _required_mac_security_opt(options)
        cgroups = info.get("CgroupVersion") in (1, 2, "1", "2")
        server_version = version.get("Version")
        if (
            rootless == desktop_vm
            or not seccomp
            or mac_security_opt is None
            or not cgroups
            or type(server_version) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}", server_version) is None
        ):
            raise LocalRepairOciRuntimeError("OCI_ISOLATION_PROFILE_UNAVAILABLE")
        self._mac_security_opt = mac_security_opt
        self._desktop_vm_isolation = desktop_vm
        seed = object.__new__(OciRuntimeAttestation)
        fields = {
            "runtime_id": "docker-rootless" if rootless else "docker-desktop-eci",
            "runtime_version": server_version.replace("+", "."),
            "rootless_engine": rootless,
            "user_namespace_enabled": rootless,
            "desktop_vm_isolation": desktop_vm,
            "seccomp_enabled": True,
            "apparmor_or_selinux_enabled": True,
            "cgroup_limits_enabled": True,
            "host_socket_mounted": False,
            "runtime_sha256": self._docker_sha256,
            "image_digest": self._image_digest,
            "attestation_sha256": "0" * 64,
        }
        for name, value in fields.items():
            object.__setattr__(seed, name, value)
        self._attestation = OciRuntimeAttestation(
            runtime_id="docker-rootless" if rootless else "docker-desktop-eci",
            runtime_version=server_version.replace("+", "."),
            rootless_engine=rootless,
            user_namespace_enabled=rootless,
            desktop_vm_isolation=desktop_vm,
            seccomp_enabled=True,
            apparmor_or_selinux_enabled=True,
            cgroup_limits_enabled=True,
            host_socket_mounted=False,
            runtime_sha256=self._docker_sha256,
            image_digest=self._image_digest,
            attestation_sha256=_runtime_attestation_hash(seed),
        )
        return self._attestation

    def validation_receipt_sha256(self, child_receipt_sha256: str) -> str:
        if _SHA256.fullmatch(child_receipt_sha256) is None:
            raise LocalRepairOciRuntimeError("OCI_RECEIPT_INVALID")
        attestation = self.attest()
        material = "\x00".join(
            (
                child_receipt_sha256,
                attestation.runtime_id,
                attestation.runtime_version,
                attestation.runtime_sha256,
                attestation.image_digest,
                attestation.attestation_sha256,
            )
        ).encode("ascii")
        return hashlib.sha256(
            b"securecode-ai/local-repair-validation-receipt/v1\x00" + material
        ).hexdigest()

    def prepare(self, *, expected_case_ids: tuple[str, ...]) -> OciPreparationReceipt:
        self.attest()
        name = self._container_name("prepare")
        argv = (*_CHILD_PREFIX, "prepare", "/securecode/input/manifest.json")
        try:
            raw, state, timed_out, _ = self._execute_container(
                name=name,
                argv=argv,
                elapsed_ms=self._profile.max_elapsed_ms,
                output_bytes=self._profile.max_output_bytes,
            )
            if timed_out or state.get("OOMKilled") is True or state.get("ExitCode") != 0:
                raise LocalRepairOciRuntimeError("OCI_PREPARATION_FAILED")
            receipt = parse_preparation_receipt(
                raw.strip(),
                parent_head_sha=self._parent_head_sha,
                patch_sha256=self._patch_sha256,
                bundle_sha256=self._bundle_sha256,
                expected_image_digest=self._image_digest,
                expected_case_ids=expected_case_ids,
            )
            self._fixed_head_sha = receipt.fixed_head_sha
            return receipt
        except LocalRepairOciProtocolError as error:
            raise LocalRepairOciRuntimeError(error.reason) from None
        finally:
            self._remove(name)

    def run(self, spec: OciLaunchSpec) -> OciRuntimeResult:
        self.attest()
        fixed = self._fixed_head_sha
        if fixed is None or not self._valid_spec(spec):
            raise LocalRepairOciRuntimeError("OCI_LAUNCH_SPEC_INVALID")
        name = self._container_name(spec.workload_id)
        if spec.workload_id in self._active:
            raise LocalRepairOciRuntimeError("OCI_WORKLOAD_COLLISION")
        self._active[spec.workload_id] = name
        raw, state, timed_out, host_elapsed = self._execute_container(
            name=name,
            argv=spec.argv,
            elapsed_ms=spec.elapsed_ms,
            output_bytes=spec.output_bytes,
        )
        oom = state.get("OOMKilled") is True
        if timed_out or oom:
            return OciRuntimeResult(
                exit_code=124 if timed_out else 137,
                stdout=b"",
                stderr=b"",
                elapsed_ms=min(host_elapsed, spec.elapsed_ms + 1),
                cpu_time_ms=0,
                peak_memory_bytes=0,
                disk_bytes=0,
                processes_peak=0,
                network_packets=0,
                oom_killed=oom,
                timed_out=timed_out,
            )
        stage_id = spec.argv[-2]
        try:
            receipt = parse_stage_receipt(
                raw.strip(),
                stage_id=stage_id,
                parent_head_sha=self._parent_head_sha,
                fixed_head_sha=fixed,
                patch_sha256=self._patch_sha256,
                bundle_sha256=self._bundle_sha256,
                expected_image_digest=self._image_digest,
            )
        except LocalRepairOciProtocolError as error:
            raise LocalRepairOciRuntimeError(error.reason) from None
        if state.get("ExitCode") != receipt.exit_code:
            raise LocalRepairOciRuntimeError("OCI_STAGE_EXIT_MISMATCH")
        return OciRuntimeResult(
            exit_code=receipt.exit_code,
            stdout=receipt.public_bytes(),
            stderr=b"",
            elapsed_ms=max(receipt.elapsed_ms, host_elapsed),
            cpu_time_ms=receipt.cpu_time_ms,
            peak_memory_bytes=receipt.peak_memory_bytes,
            disk_bytes=receipt.disk_bytes,
            processes_peak=receipt.processes_peak,
            network_packets=receipt.network_packets,
            oom_killed=receipt.oom_killed,
            timed_out=receipt.timed_out,
        )

    def cleanup(self, workload_id: str) -> OciCleanupResult:
        name = self._active.get(workload_id)
        if name is None:
            return OciCleanupResult(True, True, 0, 0)
        completed = self._remove(name)
        live = 1 if self._container_exists(name) else 0
        if completed and live == 0:
            self._active.pop(workload_id, None)
        return OciCleanupResult(True, completed and live == 0, live, 0)

    def close(self) -> None:
        if self._closed:
            return
        failure: Exception | None = None
        for workload_id in tuple(self._active):
            try:
                result = self.cleanup(workload_id)
                if not result.completed:
                    raise LocalRepairOciRuntimeError("OCI_CLEANUP_FAILED")
            except Exception as error:
                failure = error
        if failure is not None or self._active:
            raise LocalRepairOciRuntimeError("OCI_CLEANUP_FAILED") from failure
        self._closed = True
        self._on_close()

    def _valid_spec(self, spec: OciLaunchSpec) -> bool:
        return (
            type(spec) is OciLaunchSpec
            and spec.image_digest == self._image_digest
            and spec.argv[: len(_CHILD_PREFIX)] == _CHILD_PREFIX
            and len(spec.argv) == len(_CHILD_PREFIX) + 3
            and spec.argv[-3] == "stage"
            and spec.argv[-1] == "/securecode/input/manifest.json"
            and spec.user == "65532:65532"
            and spec.working_directory == "/workspace"
            and spec.network_mode == "none"
            and spec.read_only_root
            and spec.rootless
            and spec.no_new_privileges
            and spec.capability_drop == ("ALL",)
            and spec.seccomp_profile_id == "runtime-default"
            and spec.writable_tmpfs == ("/tmp", "/scratch")
            and spec.environment == (("HOME", "/tmp"), ("TMPDIR", "/tmp"))
            and spec.cpu_time_ms == self._profile.max_cpu_time_ms
            and spec.memory_bytes == self._profile.max_memory_bytes
            and spec.pids_limit == self._profile.max_processes
            and spec.disk_bytes == self._profile.max_disk_bytes
            and spec.output_bytes == self._profile.max_output_bytes
            and spec.elapsed_ms == self._profile.max_elapsed_ms
        )

    def _execute_container(
        self, *, name: str, argv: tuple[str, ...], elapsed_ms: int, output_bytes: int
    ) -> tuple[bytes, dict[str, object], bool, int]:
        if argv[: len(_CHILD_PREFIX)] != _CHILD_PREFIX:
            raise LocalRepairOciRuntimeError("OCI_CHILD_COMMAND_INVALID")
        self._create(name=name, argv=argv, output_bytes=output_bytes)
        started = time.monotonic()
        self._docker_bytes(("start", name), timeout=10)
        deadline = started + elapsed_ms / 1000
        state: dict[str, object] = {}
        timed_out = False
        while True:
            state = self._state(name)
            if state.get("Running") is False:
                break
            if time.monotonic() >= deadline:
                timed_out = True
                with suppress(LocalRepairOciRuntimeError):
                    self._docker_bytes(("kill", name), timeout=5)
                state = self._state(name)
                break
            time.sleep(0.05)
        host_elapsed = max(0, int((time.monotonic() - started) * 1000))
        raw = self._docker_bytes(("logs", name), timeout=10, limit=output_bytes)
        return raw, state, timed_out, host_elapsed

    def _create(self, *, name: str, argv: tuple[str, ...], output_bytes: int) -> None:
        mac_security_opt = self._mac_security_opt
        if mac_security_opt is None:
            raise LocalRepairOciRuntimeError("OCI_ISOLATION_PROFILE_UNAVAILABLE")
        disk = self._profile.max_disk_bytes
        tmp_size = max(1_048_576, min(disk // 8, 64 * 1024 * 1024))
        workspace_size = max(1_048_576, disk - 2 * tmp_size)
        log_kib = max(1, (output_bytes + 1023) // 1024)
        mount = f"type=bind,src={self._bundle_root},dst=/securecode/input,readonly"
        command = (
            "create",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--user",
            "65532:65532",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges=true",
            "--security-opt",
            mac_security_opt,
            "--pids-limit",
            str(self._profile.max_processes),
            "--memory",
            str(self._profile.max_memory_bytes),
            "--memory-swap",
            str(self._profile.max_memory_bytes),
            "--cpus",
            "1.0",
            "--ulimit",
            "nofile=256:256",
            "--stop-timeout",
            "1",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={tmp_size}",
            "--tmpfs",
            f"/scratch:rw,noexec,nosuid,nodev,size={tmp_size}",
            "--tmpfs",
            f"/workspace:rw,nosuid,nodev,size={workspace_size}",
            "--mount",
            mount,
            "--workdir",
            "/workspace",
            "--env",
            "HOME=/tmp",
            "--env",
            "TMPDIR=/tmp",
            "--log-driver",
            "local",
            "--log-opt",
            f"max-size={log_kib}k",
            "--log-opt",
            "max-file=1",
            "--entrypoint",
            _CHILD_PREFIX[0],
            self._image_reference,
            *argv[1:],
        )
        self._docker_bytes(command, timeout=20)
        self._verify_container_mac(name, mac_security_opt)

    def _verify_container_mac(self, name: str, security_opt: str) -> None:
        value = self._docker_json(("container", "inspect", name), timeout=5)
        if type(value) is not list or len(value) != 1 or type(value[0]) is not dict:
            raise LocalRepairOciRuntimeError("OCI_ISOLATION_PROFILE_UNAVAILABLE")
        inspected = cast(dict[str, Any], value[0])
        if not _container_mac_enforced(
            inspected, security_opt
        ) or not container_has_required_hardening(inspected):
            raise LocalRepairOciRuntimeError("OCI_ISOLATION_PROFILE_UNAVAILABLE")

    def _state(self, name: str) -> dict[str, object]:
        value = self._docker_json(("inspect", "--format", "{{json .State}}", name), timeout=5)
        if type(value) is not dict:
            raise LocalRepairOciRuntimeError("OCI_STATE_INVALID")
        return value

    def _remove(self, name: str) -> bool:
        try:
            self._docker_bytes(("rm", "--force", "--volumes", name), timeout=10)
        except LocalRepairOciRuntimeError:
            return not self._container_exists(name)
        return not self._container_exists(name)

    def _container_exists(self, name: str) -> bool:
        try:
            self._docker_bytes(("container", "inspect", name), timeout=5)
        except LocalRepairOciRuntimeError as error:
            if error.reason == "OCI_CONTAINER_NOT_FOUND":
                return False
            raise
        return True

    def _docker_json(self, arguments: tuple[str, ...], *, timeout: int) -> object:
        raw = self._docker_bytes(arguments, timeout=timeout)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_RESPONSE_INVALID") from None

    def _docker_bytes(
        self, arguments: tuple[str, ...], *, timeout: int, limit: int = _MAX_DOCKER_OUTPUT
    ) -> bytes:
        self._ensure_open()
        self._verify_docker_executable()
        argv = (str(self._docker), *arguments)
        flags = _CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                process = subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    env=self._environment,
                    creationflags=flags,
                )
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
                    raise LocalRepairOciRuntimeError("OCI_RUNTIME_TIMEOUT") from None
                stdout.seek(0)
                stderr.seek(0)
                output = stdout.read(limit + 1)
                errors = stderr.read(min(limit, 4096) + 1)
            if code != 0:
                if verified_container_not_found(arguments, errors):
                    raise LocalRepairOciRuntimeError("OCI_CONTAINER_NOT_FOUND")
                raise LocalRepairOciRuntimeError("OCI_RUNTIME_COMMAND_FAILED")
            if len(output) > limit or len(errors) > min(limit, 4096):
                raise LocalRepairOciRuntimeError("OCI_RUNTIME_COMMAND_FAILED")
            return output
        except LocalRepairOciRuntimeError:
            raise
        except (OSError, subprocess.SubprocessError):
            raise LocalRepairOciRuntimeError() from None

    def _container_name(self, purpose: str) -> str:
        digest = hashlib.sha256(
            (self._bundle_sha256 + "\x00" + purpose).encode("ascii")
        ).hexdigest()[:32]
        name = "securecode-repair-" + digest
        if _SAFE_CONTAINER.fullmatch(name) is None:
            raise LocalRepairOciRuntimeError("OCI_WORKLOAD_ID_INVALID")
        return name

    def _verify_docker_executable(self) -> None:
        try:
            path = self._docker.resolve(strict=True)
            observed = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_UNAVAILABLE") from None
        if (
            path != self._docker
            or not path.is_file()
            or path.is_symlink()
            or observed != self._docker_sha256
        ):
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_MISMATCH")

    def _ensure_open(self) -> None:
        if self._closed:
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_CLOSED")


__all__ = ["DockerCliOciRuntime", "LocalRepairOciRuntimeError"]
