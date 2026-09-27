"""Trusted rootless Docker broker for isolated local repair validation."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import signal
import socket
import socketserver
import stat
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from .local_repair_oci_protocol import (
    LocalRepairOciProtocolError,
    build_preparation_document,
    canonical_json,
    closed_json,
    image_digest,
)
from .local_repair_oci_provider import _sandbox_profile
from .local_repair_oci_runtime import DockerCliOciRuntime, LocalRepairOciRuntimeError
from .oci_sandbox import OciLaunchSpec, OciRuntimeAttestation

_PROTOCOL_VERSION: Final = "1.0.0"
_IDENTITY: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SESSION: Final = re.compile(r"[0-9a-f]{32}\Z")
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT: Final = re.compile(r"[0-9a-f]{40}\Z")
_MAX_REQUEST_BYTES: Final = 256 * 1024
_MAX_RESPONSE_BYTES: Final = 512 * 1024
_MAX_IDLE_SECONDS: Final = 15 * 60
_MAX_SESSIONS: Final = 8
_MAX_BROKER_CONNECTIONS: Final = 4
_BROKER_BACKLOG: Final = 4
_WORKER_PROTOCOL_GID: Final = 65532


@dataclass(frozen=True, slots=True)
class ValidatorBrokerConfiguration:
    protocol_socket: Path
    protocol_gid: int
    bundle_root: Path
    docker_socket: Path
    docker_socket_uid: int
    docker_executable: Path
    docker_executable_sha256: str
    image_reference: str
    identity: str

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> ValidatorBrokerConfiguration:
        try:
            values = {name: _required(environment, name) for name in (
                "SECURECODE_AI_VALIDATOR_MODE",
                "SECURECODE_AI_VALIDATOR_SOCKET",
                "SECURECODE_AI_VALIDATOR_PROTOCOL_GID",
                "SECURECODE_AI_VALIDATOR_BUNDLE_ROOT",
                "SECURECODE_AI_VALIDATOR_DOCKER_SOCKET",
                "SECURECODE_AI_VALIDATOR_DOCKER_SOCKET_UID",
                "SECURECODE_AI_VALIDATOR_DOCKER_EXECUTABLE",
                "SECURECODE_AI_VALIDATOR_DOCKER_EXECUTABLE_SHA256",
                "SECURECODE_AI_VALIDATION_IMAGE",
                "SECURECODE_AI_VALIDATOR_IDENTITY",
            )}
            socket_uid = int(values["SECURECODE_AI_VALIDATOR_DOCKER_SOCKET_UID"], 10)
            protocol_gid = int(values["SECURECODE_AI_VALIDATOR_PROTOCOL_GID"], 10)
        except (KeyError, TypeError, ValueError):
            raise ValueError from None
        if (
            values["SECURECODE_AI_VALIDATOR_MODE"] != "broker"
            or not 0 < socket_uid < 2**32
            or not 0 <= protocol_gid < 2**32
            or not hasattr(os, "getuid")
            or os.getuid() != socket_uid
            or not hasattr(os, "getgid")
            or os.getgid() != protocol_gid
            or protocol_gid != _WORKER_PROTOCOL_GID
        ):
            raise ValueError
        protocol_socket = _absolute_path(values["SECURECODE_AI_VALIDATOR_SOCKET"])
        bundle_root = _absolute_path(values["SECURECODE_AI_VALIDATOR_BUNDLE_ROOT"])
        docker_socket = _absolute_path(values["SECURECODE_AI_VALIDATOR_DOCKER_SOCKET"])
        docker_executable = _absolute_path(values["SECURECODE_AI_VALIDATOR_DOCKER_EXECUTABLE"])
        executable_sha256 = values["SECURECODE_AI_VALIDATOR_DOCKER_EXECUTABLE_SHA256"]
        identity = values["SECURECODE_AI_VALIDATOR_IDENTITY"]
        if (
            protocol_socket == docker_socket
            or not _SHA256.fullmatch(executable_sha256)
            or not _IDENTITY.fullmatch(identity)
        ):
            raise ValueError
        selected_image = values["SECURECODE_AI_VALIDATION_IMAGE"]
        image_digest(selected_image)
        _require_directory(bundle_root)
        _require_socket(docker_socket, socket_uid)
        _require_executable(docker_executable, executable_sha256)
        if protocol_socket.exists() and not protocol_socket.is_socket():
            raise ValueError
        if protocol_socket.is_symlink() or not protocol_socket.parent.is_dir():
            raise ValueError
        _require_protocol_directory(protocol_socket.parent, protocol_gid)
        return cls(
            protocol_socket=protocol_socket,
            protocol_gid=protocol_gid,
            bundle_root=bundle_root,
            docker_socket=docker_socket,
            docker_socket_uid=socket_uid,
            docker_executable=docker_executable,
            docker_executable_sha256=executable_sha256,
            image_reference=selected_image,
            identity=identity,
        )


@dataclass(slots=True)
class _BrokerSession:
    runtime: DockerCliOciRuntime
    last_used: float


class ValidatorBroker:
    """Own the engine authority and expose only the fixed repair protocol."""

    def __init__(self, configuration: ValidatorBrokerConfiguration) -> None:
        self._configuration = configuration
        self._sessions: dict[str, _BrokerSession] = {}
        self._lock = threading.RLock()

    def dispatch(self, request: dict[str, Any]) -> dict[str, object]:
        if (
            set(request) != {"operation", "schema_version"}
            and not set(request).issuperset({"operation", "schema_version"})
        ):
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
        if request.get("schema_version") != _PROTOCOL_VERSION:
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
        operation = request.get("operation")
        if type(operation) is not str or _ID.fullmatch(operation) is None:
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
        if operation == "attest":
            if set(request) != {"operation", "schema_version"}:
                raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
            return self._attest()
        if operation == "prepare":
            return self._prepare(request)
        if operation == "run":
            return self._run(request)
        if operation == "cleanup":
            return self._cleanup(request)
        if operation == "cancel":
            return self._cancel(request)
        if operation == "close":
            return self._close(request)
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_OPERATION_UNSUPPORTED")

    def close_all(self) -> None:
        with self._lock:
            sessions = tuple(self._sessions.items())
        for session_id, session in sessions:
            try:
                session.runtime.close()
            except Exception:
                pass
            with self._lock:
                self._sessions.pop(session_id, None)

    def reap_idle(self) -> None:
        now = time.monotonic()
        with self._lock:
            stale = [
                (session_id, session)
                for session_id, session in self._sessions.items()
                if now - session.last_used > _MAX_IDLE_SECONDS
            ]
        for session_id, session in stale:
            try:
                session.runtime.close()
            except Exception:
                pass
            with self._lock:
                self._sessions.pop(session_id, None)

    def _attest(self) -> dict[str, object]:
        runtime = self._new_runtime(
            bundle_root=self._configuration.bundle_root,
            bundle_sha256="0" * 64,
            parent_head_sha="0" * 40,
            patch_sha256="0" * 64,
        )
        try:
            attestation = runtime.attest()
            self._validate_attestation(attestation)
        finally:
            with suppress(Exception):
                runtime.close()
        return self._attestation_wire(attestation)

    def _prepare(self, request: dict[str, Any]) -> dict[str, object]:
        expected = {
            "operation",
            "schema_version",
            "bundle_path",
            "bundle_sha256",
            "parent_head_sha",
            "patch_sha256",
            "image_digest",
            "expected_case_ids",
        }
        if set(request) != expected:
            raise LocalRepairOciRuntimeError("OCI_PREPARATION_REQUEST_INVALID")
        bundle_path = self._validate_bundle_path(request.get("bundle_path"))
        bundle_sha256 = _sha(request.get("bundle_sha256"))
        parent_head_sha = _commit(request.get("parent_head_sha"))
        patch_sha256 = _sha(request.get("patch_sha256"))
        selected_image = request.get("image_digest")
        if selected_image != image_digest(self._configuration.image_reference):
            raise LocalRepairOciRuntimeError("OCI_IMAGE_ATTESTATION_FAILED")
        expected_case_ids = request.get("expected_case_ids")
        if (
            type(expected_case_ids) is not list
            or not expected_case_ids
            or any(type(item) is not str or _ID.fullmatch(item) is None for item in expected_case_ids)
            or len(set(expected_case_ids)) != len(expected_case_ids)
        ):
            raise LocalRepairOciRuntimeError("OCI_PREPARATION_REQUEST_INVALID")
        with self._lock:
            if len(self._sessions) >= _MAX_SESSIONS:
                raise LocalRepairOciRuntimeError("OCI_VALIDATOR_CAPACITY_EXCEEDED")
        runtime = self._new_runtime(
            bundle_root=bundle_path,
            bundle_sha256=bundle_sha256,
            parent_head_sha=parent_head_sha,
            patch_sha256=patch_sha256,
        )
        try:
            self._validate_attestation(runtime.attest())
            receipt = runtime.prepare(expected_case_ids=tuple(expected_case_ids))
            document = build_preparation_document(
                parent_head_sha=receipt.parent_head_sha,
                fixed_head_sha=receipt.fixed_head_sha,
                patch_sha256=receipt.patch_sha256,
                bundle_sha256=receipt.bundle_sha256,
                selected_image_digest=receipt.image_digest,
                observations=receipt.observations,
            )
            session_id = os.urandom(16).hex()
            with self._lock:
                if len(self._sessions) >= _MAX_SESSIONS:
                    raise LocalRepairOciRuntimeError("OCI_VALIDATOR_CAPACITY_EXCEEDED")
                self._sessions[session_id] = _BrokerSession(
                    runtime=runtime,
                    last_used=time.monotonic(),
                )
            return {"receipt": base64.b64encode(document).decode("ascii"), "session_id": session_id}
        except Exception:
            with suppress(Exception):
                runtime.close()
            raise

    def _run(self, request: dict[str, Any]) -> dict[str, object]:
        if set(request) != {"operation", "schema_version", "session_id", "spec"}:
            raise LocalRepairOciRuntimeError("OCI_STAGE_REQUEST_INVALID")
        session_id = _session(request.get("session_id"))
        session = self._session(session_id)
        spec = _spec_from_wire(request.get("spec"))
        result = session.runtime.run(spec)
        self._touch(session_id)
        return {
            "cancelled": result.cancelled,
            "cpu_time_ms": result.cpu_time_ms,
            "disk_bytes": result.disk_bytes,
            "elapsed_ms": result.elapsed_ms,
            "exit_code": result.exit_code,
            "network_packets": result.network_packets,
            "oom_killed": result.oom_killed,
            "peak_memory_bytes": result.peak_memory_bytes,
            "processes_peak": result.processes_peak,
            "stderr": base64.b64encode(result.stderr).decode("ascii"),
            "stdout": base64.b64encode(result.stdout).decode("ascii"),
            "timed_out": result.timed_out,
        }

    def _cleanup(self, request: dict[str, Any]) -> dict[str, object]:
        if set(request) != {"operation", "schema_version", "session_id", "workload_id"}:
            raise LocalRepairOciRuntimeError("OCI_CLEANUP_REQUEST_INVALID")
        session_id = _session(request.get("session_id"))
        workload_id = _identifier(request.get("workload_id"))
        session = self._session(session_id)
        result = session.runtime.cleanup(workload_id)
        self._touch(session_id)
        return {
            "attempted": result.attempted,
            "completed": result.completed,
            "live_workloads": result.live_workloads,
            "reusable_volumes": result.reusable_volumes,
        }

    def _cancel(self, request: dict[str, Any]) -> dict[str, object]:
        if set(request) != {"operation", "schema_version", "session_id"}:
            raise LocalRepairOciRuntimeError("OCI_CANCEL_REQUEST_INVALID")
        session_id = _session(request.get("session_id"))
        session = self._session(session_id)
        session.runtime.cancel()
        self._touch(session_id)
        return {"cancelled": True}

    def _close(self, request: dict[str, Any]) -> dict[str, object]:
        if set(request) != {"operation", "schema_version", "session_id"}:
            raise LocalRepairOciRuntimeError("OCI_CLEANUP_REQUEST_INVALID")
        session_id = _session(request.get("session_id"))
        session = self._session(session_id)
        session.runtime.close()
        with self._lock:
            self._sessions.pop(session_id, None)
        return {}

    def _new_runtime(
        self,
        *,
        bundle_root: Path,
        bundle_sha256: str,
        parent_head_sha: str,
        patch_sha256: str,
    ) -> DockerCliOciRuntime:
        self._verify_endpoint()
        return DockerCliOciRuntime(
            docker_executable=self._configuration.docker_executable,
            docker_executable_sha256=self._configuration.docker_executable_sha256,
            image_reference=self._configuration.image_reference,
            bundle_root=bundle_root,
            bundle_sha256=bundle_sha256,
            parent_head_sha=parent_head_sha,
            patch_sha256=patch_sha256,
            profile=_sandbox_profile(),
            environment={
                "DOCKER_HOST": "unix://" + str(self._configuration.docker_socket),
                "HOME": "/tmp",
                "PATH": "/usr/local/bin:/usr/bin:/bin",
                "TMPDIR": "/tmp",
            },
            on_close=lambda: None,
        )

    def _validate_attestation(self, attestation: OciRuntimeAttestation) -> None:
        if (
            type(attestation) is not OciRuntimeAttestation
            or not attestation.rootless_engine
            or not attestation.user_namespace_enabled
            or attestation.desktop_vm_isolation
            or not attestation.seccomp_enabled
            or not attestation.apparmor_or_selinux_enabled
            or not attestation.cgroup_limits_enabled
            or attestation.host_socket_mounted
            or attestation.image_digest != image_digest(self._configuration.image_reference)
            or attestation.runtime_sha256 != self._configuration.docker_executable_sha256
        ):
            raise LocalRepairOciRuntimeError("OCI_VALIDATOR_ATTESTATION_FAILED")

    def _attestation_wire(self, attestation: OciRuntimeAttestation) -> dict[str, object]:
        endpoint = self._verify_endpoint()
        return {
            "attestation": {
                "apparmor_or_selinux_enabled": attestation.apparmor_or_selinux_enabled,
                "attestation_sha256": attestation.attestation_sha256,
                "cgroup_limits_enabled": attestation.cgroup_limits_enabled,
                "desktop_vm_isolation": attestation.desktop_vm_isolation,
                "host_socket_mounted": attestation.host_socket_mounted,
                "image_digest": attestation.image_digest,
                "rootless_engine": attestation.rootless_engine,
                "runtime_id": attestation.runtime_id,
                "runtime_sha256": attestation.runtime_sha256,
                "runtime_version": attestation.runtime_version,
                "seccomp_enabled": attestation.seccomp_enabled,
                "user_namespace_enabled": attestation.user_namespace_enabled,
            },
            "broker_identity": self._configuration.identity,
            "broker_uid": os.getuid(),
            "docker_endpoint": endpoint[0],
            "docker_executable_sha256": self._configuration.docker_executable_sha256,
            "docker_socket_mode": endpoint[2],
            "docker_socket_uid": endpoint[1],
        }

    def _verify_endpoint(self) -> tuple[str, int, int]:
        try:
            _require_socket(self._configuration.docker_socket, self._configuration.docker_socket_uid)
        except ValueError:
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_UNAVAILABLE") from None
        try:
            details = self._configuration.docker_socket.stat()
        except OSError:
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_UNAVAILABLE") from None
        mode = stat.S_IMODE(details.st_mode)
        if mode & 0o007 or mode & 0o600 != 0o600:
            raise LocalRepairOciRuntimeError("OCI_RUNTIME_AUTHORITY_UNAVAILABLE")
        return (
            "unix://" + str(self._configuration.docker_socket),
            details.st_uid,
            mode,
        )

    def _validate_bundle_path(self, value: object) -> Path:
        if type(value) is not str or not value or "\x00" in value or "," in value:
            raise LocalRepairOciRuntimeError("OCI_BUNDLE_INVALID")
        path = Path(value)
        if not path.is_absolute() or path.parent != self._configuration.bundle_root:
            raise LocalRepairOciRuntimeError("OCI_BUNDLE_INVALID")
        if _ID.fullmatch(path.name) is None or path.is_symlink() or not path.is_dir():
            raise LocalRepairOciRuntimeError("OCI_BUNDLE_INVALID")
        for name in ("manifest.json", "patch.diff", "source"):
            item = path / name
            if item.is_symlink() or not item.exists():
                raise LocalRepairOciRuntimeError("OCI_BUNDLE_INVALID")
        return path

    def _session(self, session_id: str) -> _BrokerSession:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise LocalRepairOciRuntimeError("OCI_SESSION_INVALID")
        return session

    def _touch(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is not None:
                session.last_used = time.monotonic()


class _ThreadingUnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = _BROKER_BACKLOG
    allow_reuse_address = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._connection_slots = threading.BoundedSemaphore(_MAX_BROKER_CONNECTIONS)
        super().__init__(*args, **kwargs)

    def process_request(self, request: socket.socket, client_address: object) -> None:
        if not self._connection_slots.acquire(blocking=False):
            with suppress(OSError):
                request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class _BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(135.0)
        raw = self.rfile.readline(_MAX_REQUEST_BYTES + 1)
        if not raw or len(raw) > _MAX_REQUEST_BYTES or not raw.endswith(b"\n"):
            self._reply_failure("OCI_VALIDATOR_PROTOCOL_INVALID")
            return
        try:
            request = closed_json(raw[:-1])
            result = cast(ValidatorBroker, self.server.broker).dispatch(request)
            response: dict[str, object] = {
                "ok": True,
                "result": result,
                "schema_version": _PROTOCOL_VERSION,
            }
        except LocalRepairOciRuntimeError as error:
            response = {
                "ok": False,
                "reason": error.reason,
                "schema_version": _PROTOCOL_VERSION,
            }
        except LocalRepairOciProtocolError:
            response = {
                "ok": False,
                "reason": "OCI_VALIDATOR_PROTOCOL_INVALID",
                "schema_version": _PROTOCOL_VERSION,
            }
        except Exception:
            response = {
                "ok": False,
                "reason": "OCI_VALIDATOR_BROKER_FAILURE",
                "schema_version": _PROTOCOL_VERSION,
            }
        try:
            body = canonical_json(response) + b"\n"
            if len(body) > _MAX_RESPONSE_BYTES:
                body = canonical_json(
                    {
                        "ok": False,
                        "reason": "OCI_VALIDATOR_PROTOCOL_INVALID",
                        "schema_version": _PROTOCOL_VERSION,
                    }
                ) + b"\n"
            self.wfile.write(body)
            self.wfile.flush()
        except (OSError, ValueError):
            return

    def _reply_failure(self, reason: str) -> None:
        with suppress(OSError, ValueError):
            self.wfile.write(
                canonical_json(
                    {"ok": False, "reason": reason, "schema_version": _PROTOCOL_VERSION}
                )
                + b"\n"
            )
            self.wfile.flush()


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError
    return value


def _absolute_path(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or "\x00" in value:
        raise ValueError
    return path


def _require_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError


def _require_protocol_directory(path: Path, expected_gid: int) -> None:
    try:
        details = path.stat()
    except OSError:
        raise ValueError from None
    mode = stat.S_IMODE(details.st_mode)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_gid != expected_gid
        or mode & 0o070 != 0o070
    ):
        raise ValueError


def _require_socket(path: Path, expected_uid: int) -> None:
    if path.is_symlink():
        raise ValueError
    try:
        details = path.stat()
    except OSError:
        raise ValueError from None
    if (
        not stat.S_ISSOCK(details.st_mode)
        or details.st_uid != expected_uid
        or not hasattr(os, "getuid")
        or details.st_uid != os.getuid()
    ):
        raise ValueError


def _require_executable(path: Path, expected_sha256: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError
    try:
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        raise ValueError from None
    if observed != expected_sha256:
        raise ValueError


def _sha(value: object) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
    return value


def _commit(value: object) -> str:
    if type(value) is not str or _COMMIT.fullmatch(value) is None:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
    return value


def _identifier(value: object) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise LocalRepairOciRuntimeError("OCI_VALIDATOR_PROTOCOL_INVALID")
    return value


def _session(value: object) -> str:
    if type(value) is not str or _SESSION.fullmatch(value) is None:
        raise LocalRepairOciRuntimeError("OCI_SESSION_INVALID")
    return value


def _spec_from_wire(value: object) -> OciLaunchSpec:
    if type(value) is not dict:
        raise LocalRepairOciRuntimeError("OCI_LAUNCH_SPEC_INVALID")
    expected = {
        "argv",
        "capability_drop",
        "cpu_time_ms",
        "disk_bytes",
        "elapsed_ms",
        "environment",
        "image_digest",
        "memory_bytes",
        "network_mode",
        "no_new_privileges",
        "output_bytes",
        "pids_limit",
        "read_only_root",
        "rootless",
        "seccomp_profile_id",
        "user",
        "workload_id",
        "working_directory",
        "writable_tmpfs",
    }
    if set(value) != expected:
        raise LocalRepairOciRuntimeError("OCI_LAUNCH_SPEC_INVALID")
    try:
        argv = _strings(value["argv"])
        capability_drop = _strings(value["capability_drop"])
        environment = tuple(tuple(item) for item in value["environment"])
        writable_tmpfs = _strings(value["writable_tmpfs"])
        if any(
            type(item) is not tuple
            or len(item) != 2
            or any(type(part) is not str for part in item)
            for item in environment
        ):
            raise ValueError
        return OciLaunchSpec(
            argv=argv,
            capability_drop=capability_drop,
            cpu_time_ms=_integer(value["cpu_time_ms"]),
            disk_bytes=_integer(value["disk_bytes"]),
            elapsed_ms=_integer(value["elapsed_ms"]),
            environment=environment,
            image_digest=_string(value["image_digest"]),
            memory_bytes=_integer(value["memory_bytes"]),
            network_mode=_string(value["network_mode"]),
            no_new_privileges=_boolean(value["no_new_privileges"]),
            output_bytes=_integer(value["output_bytes"]),
            pids_limit=_integer(value["pids_limit"]),
            read_only_root=_boolean(value["read_only_root"]),
            rootless=_boolean(value["rootless"]),
            seccomp_profile_id=_string(value["seccomp_profile_id"]),
            user=_string(value["user"]),
            workload_id=_string(value["workload_id"]),
            working_directory=_string(value["working_directory"]),
            writable_tmpfs=writable_tmpfs,
        )
    except (KeyError, TypeError, ValueError):
        raise LocalRepairOciRuntimeError("OCI_LAUNCH_SPEC_INVALID") from None


def _strings(value: object) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ValueError
    return tuple(cast(list[str], value))


def _string(value: object) -> str:
    if type(value) is not str:
        raise ValueError
    return value


def _integer(value: object) -> int:
    if type(value) is not int or value < 0:
        raise ValueError
    return value


def _boolean(value: object) -> bool:
    if type(value) is not bool:
        raise ValueError
    return value


def _serve(configuration: ValidatorBrokerConfiguration) -> int:
    broker = ValidatorBroker(configuration)
    socket_path = configuration.protocol_socket
    if socket_path.exists():
        if socket_path.is_symlink() or not socket_path.is_socket():
            return 1
        with suppress(OSError):
            socket_path.unlink()
    server = _ThreadingUnixServer(str(socket_path), _BrokerHandler)
    server.broker = broker
    with suppress(OSError):
        socket_path.chmod(0o660)
    stop = threading.Event()
    reaper_stop = threading.Event()

    def reap() -> None:
        while not reaper_stop.wait(30.0):
            broker.reap_idle()

    reaper = threading.Thread(target=reap, name="securecode-validator-reaper", daemon=True)
    reaper.start()
    shutdown_thread: threading.Thread | None = None

    def request_shutdown(_signum: int, _frame: object) -> None:
        nonlocal shutdown_thread
        if shutdown_thread is None:
            shutdown_thread = threading.Thread(target=server.shutdown, daemon=True)
            shutdown_thread.start()
        stop.set()

    previous: dict[int, Any] = {}
    for value in (getattr(signal, "SIGTERM", None), getattr(signal, "SIGINT", None)):
        if value is not None:
            previous[value] = signal.getsignal(value)
            signal.signal(value, request_shutdown)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        reaper_stop.set()
        reaper.join(timeout=2.0)
        broker.close_all()
        server.server_close()
        with suppress(OSError):
            socket_path.unlink()
        for value, handler in previous.items():
            with suppress(ValueError):
                signal.signal(value, handler)
    return 0


def main() -> int:
    try:
        configuration = ValidatorBrokerConfiguration.from_environment(os.environ)
        return _serve(configuration)
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["ValidatorBroker", "ValidatorBrokerConfiguration", "main"]
