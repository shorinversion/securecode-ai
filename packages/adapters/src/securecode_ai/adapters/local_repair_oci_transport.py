"""Bounded Unix-socket transport for the trusted local repair OCI broker."""

from __future__ import annotations

import base64
import hashlib
import re
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, cast

from .local_repair_oci_protocol import (
    LocalRepairOciProtocolError,
    OciPreparationReceipt,
    canonical_json,
    closed_json,
    parse_preparation_receipt,
)
from .local_repair_oci_runtime import LocalRepairOciRuntimeError
from .oci_sandbox import (
    OciCleanupResult,
    OciLaunchSpec,
    OciRuntimeAttestation,
    OciRuntimeResult,
)

_PROTOCOL_VERSION: Final = "1.0.0"
_CHILD_PREFIX: Final = (
    "/usr/local/bin/python",
    "-I",
    "-m",
    "securecode_ai.adapters.local_repair_oci_child",
)
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT: Final = re.compile(r"[0-9a-f]{40}\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_IDENTITY: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_MAX_REQUEST_BYTES: Final = 256 * 1024
_MAX_RESPONSE_BYTES: Final = 512 * 1024
_MAX_RECEIPT_BYTES: Final = 256 * 1024


def _closed_wire_json(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_REQUEST_BYTES:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
    try:
        value = closed_json(raw)
    except LocalRepairOciProtocolError:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID") from None
    return value


def _from_wire_b64(value: object, *, limit: int) -> bytes:
    if type(value) is not str or len(value) > ((limit + 2) // 3) * 4 + 4:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID") from None
    if len(decoded) > limit:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
    return decoded


def _attestation_from_wire(value: object) -> OciRuntimeAttestation:
    if type(value) is not dict:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_ATTESTATION_INVALID")
    expected = {
        "runtime_id",
        "runtime_version",
        "rootless_engine",
        "user_namespace_enabled",
        "seccomp_enabled",
        "apparmor_or_selinux_enabled",
        "cgroup_limits_enabled",
        "host_socket_mounted",
        "runtime_sha256",
        "image_digest",
        "attestation_sha256",
        "desktop_vm_isolation",
    }
    if set(value) != expected:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_ATTESTATION_INVALID")
    try:
        return OciRuntimeAttestation(**cast(dict[str, Any], value))
    except Exception:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_ATTESTATION_INVALID") from None


class ValidatorBrokerOciRuntime:
    """Client-side runtime port backed by a trusted broker Unix socket."""

    __slots__ = (
        "_attestation",
        "_bundle_root",
        "_bundle_sha256",
        "_closed",
        "_docker_endpoint",
        "_docker_sha256",
        "_docker_socket_uid",
        "_expected_case_ids",
        "_expected_image_digest",
        "_fixed_head_sha",
        "_identity",
        "_on_close",
        "_parent_head_sha",
        "_patch_sha256",
        "_session_id",
        "_socket_path",
    )

    def __init__(
        self,
        *,
        socket_path: Path,
        bundle_root: Path,
        bundle_sha256: str,
        parent_head_sha: str,
        patch_sha256: str,
        image_digest: str,
        identity: str,
        docker_socket: Path,
        docker_socket_uid: int,
        docker_executable_sha256: str,
        on_close: Callable[[], None],
    ) -> None:
        if (
            not isinstance(socket_path, Path)
            or not socket_path.is_absolute()
            or socket_path.is_symlink()
            or not isinstance(bundle_root, Path)
            or not bundle_root.is_absolute()
            or bundle_root.is_symlink()
            or not bundle_root.is_dir()
            or not _SHA256.fullmatch(bundle_sha256)
            or not _COMMIT.fullmatch(parent_head_sha)
            or not _SHA256.fullmatch(patch_sha256)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest)
            or not _IDENTITY.fullmatch(identity)
            or not isinstance(docker_socket, Path)
            or not docker_socket.is_absolute()
            or docker_socket.is_symlink()
            or type(docker_socket_uid) is not int
            or not 0 < docker_socket_uid < 2**32
            or not _SHA256.fullmatch(docker_executable_sha256)
            or not callable(on_close)
        ):
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_CONFIGURATION_INVALID")
        if "," in str(bundle_root):
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_CONFIGURATION_INVALID")
        self._socket_path = socket_path
        self._bundle_root = bundle_root
        self._bundle_sha256 = bundle_sha256
        self._parent_head_sha = parent_head_sha
        self._patch_sha256 = patch_sha256
        self._expected_image_digest = image_digest
        self._identity = identity
        self._docker_endpoint = "unix://" + str(docker_socket)
        self._docker_socket_uid = docker_socket_uid
        self._docker_sha256 = docker_executable_sha256
        self._on_close = on_close
        self._expected_case_ids: tuple[str, ...] = ()
        self._attestation: OciRuntimeAttestation | None = None
        self._session_id: str | None = None
        self._fixed_head_sha: str | None = None
        self._closed = False

    @property
    def command_prefix(self) -> tuple[str, ...]:
        return _CHILD_PREFIX

    @property
    def image_digest(self) -> str:
        return self._expected_image_digest

    def attest(self) -> OciRuntimeAttestation:
        self._ensure_open()
        if self._attestation is not None:
            return self._attestation
        result = self._request("attest")
        expected = {
            "attestation",
            "broker_identity",
            "broker_uid",
            "docker_endpoint",
            "docker_executable_sha256",
            "docker_socket_mode",
            "docker_socket_uid",
        }
        if set(result) != expected:
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_ATTESTATION_INVALID")
        if (
            result.get("broker_identity") != self._identity
            or result.get("broker_uid") != self._docker_socket_uid
            or result.get("docker_endpoint") != self._docker_endpoint
            or result.get("docker_executable_sha256") != self._docker_sha256
            or result.get("docker_socket_uid") != self._docker_socket_uid
            or type(result.get("docker_socket_mode")) is not int
            or result["docker_socket_mode"] & 0o007
            or result["docker_socket_mode"] & 0o600 != 0o600
        ):
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_ATTESTATION_INVALID")
        attestation = _attestation_from_wire(result.get("attestation"))
        if (
            not attestation.rootless_engine
            or not attestation.user_namespace_enabled
            or attestation.desktop_vm_isolation
            or attestation.host_socket_mounted
            or attestation.image_digest != self._expected_image_digest
            or attestation.runtime_sha256 != self._docker_sha256
        ):
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_ATTESTATION_FAILED")
        self._attestation = attestation
        return attestation

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
        self._ensure_open()
        self.attest()
        if self._session_id is not None:
            raise LocalRepairOciRuntimeError("OCI_WORKLOAD_COLLISION")
        if (
            type(expected_case_ids) is not tuple
            or not expected_case_ids
            or any(
                type(item) is not str or _ID.fullmatch(item) is None for item in expected_case_ids
            )
            or len(set(expected_case_ids)) != len(expected_case_ids)
        ):
            raise LocalRepairOciRuntimeError("OCI_PREPARATION_REQUEST_INVALID")
        result = self._request(
            "prepare",
            bundle_path=str(self._bundle_root),
            bundle_sha256=self._bundle_sha256,
            parent_head_sha=self._parent_head_sha,
            patch_sha256=self._patch_sha256,
            image_digest=self._expected_image_digest,
            expected_case_ids=list(expected_case_ids),
        )
        expected = {"receipt", "session_id"}
        if set(result) != expected or type(result.get("session_id")) is not str:
            raise LocalRepairOciRuntimeError("OCI_PREPARATION_RESPONSE_INVALID")
        session_id = cast(str, result["session_id"])
        if re.fullmatch(r"[0-9a-f]{32}", session_id) is None:
            raise LocalRepairOciRuntimeError("OCI_PREPARATION_RESPONSE_INVALID")
        raw = _from_wire_b64(result.get("receipt"), limit=_MAX_RECEIPT_BYTES)
        try:
            receipt = parse_preparation_receipt(
                raw,
                parent_head_sha=self._parent_head_sha,
                patch_sha256=self._patch_sha256,
                bundle_sha256=self._bundle_sha256,
                expected_image_digest=self._expected_image_digest,
                expected_case_ids=expected_case_ids,
            )
        except LocalRepairOciProtocolError as error:
            raise LocalRepairOciRuntimeError(error.reason) from None
        self._session_id = session_id
        self._expected_case_ids = expected_case_ids
        self._fixed_head_sha = receipt.fixed_head_sha
        return receipt

    def run(self, spec: OciLaunchSpec) -> OciRuntimeResult:
        self._ensure_open()
        self.attest()
        session_id = self._session_id
        if session_id is None or type(spec) is not OciLaunchSpec:
            raise LocalRepairOciRuntimeError("OCI_LAUNCH_SPEC_INVALID")
        result = self._request("run", session_id=session_id, spec=_spec_to_wire(spec))
        expected = {
            "cancelled",
            "cpu_time_ms",
            "disk_bytes",
            "elapsed_ms",
            "exit_code",
            "network_packets",
            "oom_killed",
            "peak_memory_bytes",
            "processes_peak",
            "stderr",
            "stdout",
            "timed_out",
        }
        if set(result) != expected:
            raise LocalRepairOciRuntimeError("OCI_STAGE_RESPONSE_INVALID")
        stdout = _from_wire_b64(result.get("stdout"), limit=131_072)
        stderr = _from_wire_b64(result.get("stderr"), limit=131_072)
        try:
            return OciRuntimeResult(
                exit_code=_wire_int(result.get("exit_code"), minimum=0, maximum=255),
                stdout=stdout,
                stderr=stderr,
                elapsed_ms=_wire_int(result.get("elapsed_ms"), minimum=0),
                cpu_time_ms=_wire_int(result.get("cpu_time_ms"), minimum=0),
                peak_memory_bytes=_wire_int(result.get("peak_memory_bytes"), minimum=0),
                disk_bytes=_wire_int(result.get("disk_bytes"), minimum=0),
                processes_peak=_wire_int(result.get("processes_peak"), minimum=0),
                network_packets=_wire_int(result.get("network_packets"), minimum=0),
                oom_killed=_wire_bool(result.get("oom_killed")),
                timed_out=_wire_bool(result.get("timed_out")),
                cancelled=_wire_bool(result.get("cancelled")),
            )
        except ValueError:
            raise LocalRepairOciRuntimeError("OCI_STAGE_RESPONSE_INVALID") from None

    def cleanup(self, workload_id: str) -> OciCleanupResult:
        self._ensure_open()
        session_id = self._session_id
        if session_id is None:
            return OciCleanupResult(True, True, 0, 0)
        if type(workload_id) is not str or _ID.fullmatch(workload_id) is None:
            raise LocalRepairOciRuntimeError("OCI_WORKLOAD_ID_INVALID")
        result = self._request("cleanup", session_id=session_id, workload_id=workload_id)
        if set(result) != {"attempted", "completed", "live_workloads", "reusable_volumes"}:
            raise LocalRepairOciRuntimeError("OCI_CLEANUP_RESPONSE_INVALID")
        try:
            return OciCleanupResult(
                attempted=_wire_bool(result.get("attempted")),
                completed=_wire_bool(result.get("completed")),
                live_workloads=_wire_int(result.get("live_workloads"), minimum=0),
                reusable_volumes=_wire_int(result.get("reusable_volumes"), minimum=0),
            )
        except ValueError:
            raise LocalRepairOciRuntimeError("OCI_CLEANUP_RESPONSE_INVALID") from None

    def cancel(self) -> None:
        self._ensure_open()
        if self._session_id is None:
            return
        result = self._request("cancel", session_id=self._session_id)
        if set(result) != {"cancelled"} or result.get("cancelled") is not True:
            raise LocalRepairOciRuntimeError("OCI_CANCEL_RESPONSE_INVALID")

    def close(self) -> None:
        if self._closed:
            return
        if self._session_id is not None:
            result = self._request("close", session_id=self._session_id)
            if result:
                raise LocalRepairOciRuntimeError("OCI_CLEANUP_RESPONSE_INVALID")
        self._closed = True
        self._on_close()

    def _request(self, operation: str, **payload: object) -> dict[str, Any]:
        if type(operation) is not str or _ID.fullmatch(operation) is None:
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
        request = {"operation": operation, "schema_version": _PROTOCOL_VERSION, **payload}
        try:
            raw = canonical_json(request)
        except LocalRepairOciProtocolError:
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID") from None
        if len(raw) > _MAX_REQUEST_BYTES:
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
        timeout = (
            130.0 if operation in {"prepare", "run"} else 5.0 if operation == "cancel" else 30.0
        )
        # AF_UNIX brokers are Linux-only; fail closed instead of AttributeError.
        unix_family = getattr(socket, "AF_UNIX", None)
        if unix_family is None:
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_BROKER_UNAVAILABLE")
        try:
            with socket.socket(unix_family, socket.SOCK_STREAM) as connection:
                connection.settimeout(timeout)
                connection.connect(str(self._socket_path))
                connection.sendall(raw + b"\n")
                connection.shutdown(socket.SHUT_WR)
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = connection.recv(65_536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > _MAX_RESPONSE_BYTES:
                        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
                    chunks.append(chunk)
                    if b"\n" in chunk:
                        break
        except LocalRepairOciRuntimeError:
            raise
        except (OSError, TimeoutError):
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_BROKER_UNAVAILABLE") from None
        raw_response = b"".join(chunks)
        line, separator, _ = raw_response.partition(b"\n")
        if not separator:
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
        response = _closed_wire_json(line)
        if response.get("schema_version") != _PROTOCOL_VERSION or response.get("ok") is not True:
            reason = response.get("reason")
            if (
                set(response) == {"schema_version", "ok", "reason"}
                and type(reason) is str
                and re.fullmatch(r"[A-Z0-9_]{1,96}", reason) is not None
            ):
                raise LocalRepairOciRuntimeError(reason)
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
        if (
            set(response) != {"schema_version", "ok", "result"}
            or type(response.get("result")) is not dict
        ):
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
        return cast(dict[str, Any], response["result"])

    def _ensure_open(self) -> None:
        if self._closed:
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_CLOSED")


def _spec_to_wire(spec: OciLaunchSpec) -> dict[str, object]:
    return {
        "argv": list(spec.argv),
        "capability_drop": list(spec.capability_drop),
        "cpu_time_ms": spec.cpu_time_ms,
        "disk_bytes": spec.disk_bytes,
        "elapsed_ms": spec.elapsed_ms,
        "environment": [list(item) for item in spec.environment],
        "image_digest": spec.image_digest,
        "memory_bytes": spec.memory_bytes,
        "network_mode": spec.network_mode,
        "no_new_privileges": spec.no_new_privileges,
        "output_bytes": spec.output_bytes,
        "pids_limit": spec.pids_limit,
        "read_only_root": spec.read_only_root,
        "rootless": spec.rootless,
        "seccomp_profile_id": spec.seccomp_profile_id,
        "user": spec.user,
        "workload_id": spec.workload_id,
        "working_directory": spec.working_directory,
        "writable_tmpfs": list(spec.writable_tmpfs),
    }


def _wire_int(value: object, *, minimum: int, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError
    return value


def _wire_bool(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError
    return value


__all__ = ["ValidatorBrokerOciRuntime"]
