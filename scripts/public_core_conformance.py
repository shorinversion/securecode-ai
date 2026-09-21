"""Public Core preflight or pinned local execution with source-free diagnostics.

Run mode owns a temporary loopback gateway; neither mode admits a provider.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from securecode_ai.adapters.local_provider_gateway import GatewayPolicy
    from securecode_ai.adapters.public_core_execution import BackendIdentity, BackendObservation

_MAX_INPUT_BYTES = 1024 * 1024


def _terminal_document(document: dict[str, object]) -> bytes:
    """Encode the already-whitelisted terminal document identically for stdout and a receipt."""
    return (
        json.dumps(document, ensure_ascii=True, allow_nan=False, sort_keys=True).encode("ascii")
        + b"\n"
    )


def _persist_terminal_receipt(path: Path, document: dict[str, object]) -> None:
    """Atomically retain only the source-free terminal document at a caller-selected path."""
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("receipt path is unavailable")
    encoded = _terminal_document(document)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".checkpoint",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        temporary.unlink()
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_host_input(path: Path) -> bytes:
    with path.open("rb") as handle:
        content = handle.read(_MAX_INPUT_BYTES + 1)
    if not content or len(content) > _MAX_INPUT_BYTES:
        raise ValueError("public Core host input is invalid")
    return content


def _observe_listener(port: int) -> tuple[int, str]:
    """Bind the literal backend listener to its actual executable, without source output."""
    import hashlib
    import os
    import subprocess

    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("backend listener is invalid")
    if os.name == "nt":
        command = (
            "$connections = @(Get-NetTCPConnection -State Listen -LocalPort "
            + str(port)
            + " -ErrorAction Stop); "
            "if ($connections.Count -ne 1 -or $connections[0].LocalAddress -ne '127.0.0.1') "
            "{ throw 'invalid listener' }; "
            "$backendProcess = Get-Process -Id $connections[0].OwningProcess -ErrorAction Stop; "
            "$stream = [IO.File]::OpenRead($backendProcess.Path); "
            "try { if ($stream.Length -gt 268435456) { throw 'oversized executable' }; "
            "$hasher = [Security.Cryptography.SHA256]::Create(); "
            "try { $digest = [BitConverter]::ToString($hasher.ComputeHash($stream))"
            ".Replace('-', '').ToLowerInvariant() } finally { $hasher.Dispose() } "
            "} finally { $stream.Dispose() }; "
            "[pscustomobject]@{pid=$backendProcess.Id; sha256=$digest} | ConvertTo-Json -Compress"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            timeout=10,
            check=True,
        )
        if len(result.stdout) > 4096:
            raise ValueError("backend observation exceeds bounds")
        document = json.loads(result.stdout)
        pid, digest = document["pid"], document["sha256"]
    else:
        proc = Path("/proc")
        inodes = set()
        for table in ("tcp", "tcp6"):
            for line in (proc / "net" / table).read_text(encoding="ascii").splitlines()[1:]:
                fields = line.split()
                address, raw_port = fields[1].split(":")
                if fields[3] == "0A" and int(raw_port, 16) == port:
                    if table != "tcp" or address != "0100007F":
                        raise ValueError("backend listener is not literal loopback")
                    inodes.add(fields[9])
        if len(inodes) != 1:
            raise ValueError("backend listener is ambiguous")
        target = "socket:[" + next(iter(inodes)) + "]"
        owners = set()
        for entry in proc.iterdir():
            if not entry.name.isdecimal():
                continue
            try:
                if any(str(fd.readlink()) == target for fd in (entry / "fd").iterdir()):
                    owners.add(int(entry.name))
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue
        if len(owners) != 1:
            raise ValueError("backend process is not observable")
        pid = next(iter(owners))
        executable = proc / str(pid) / "exe"
        with executable.open("rb") as handle:
            content = handle.read(256 * 1024 * 1024 + 1)
        if len(content) > 256 * 1024 * 1024:
            raise ValueError("backend executable exceeds bounds")
        digest = hashlib.sha256(content).hexdigest()
    if type(pid) is not int or pid <= 0 or type(digest) is not str:
        raise ValueError("backend process observation is invalid")
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("backend executable observation is invalid")
    return pid, digest


def _observe_backend(
    expected: BackendIdentity, gateway_policy: GatewayPolicy
) -> BackendObservation:
    """Observe current literal-loopback metadata and loaded execution artifacts."""
    import hashlib
    import http.client
    import socket
    import threading
    import time
    from contextlib import suppress
    from dataclasses import replace

    from securecode_ai.adapters import local_provider_gateway, openai_compatible_local
    from securecode_ai.adapters.public_core_execution import BackendObservation

    def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("duplicate metadata field")
            document[key] = value
        return document

    def read_metadata(path: str, maximum: int) -> Any:
        deadline = time.monotonic() + 5
        connection = http.client.HTTPConnection("127.0.0.1", expected.backend_port, timeout=5)
        expired = threading.Event()
        active_socket: list[socket.socket] = []

        def expire() -> None:
            expired.set()
            for current in active_socket:
                with suppress(OSError):
                    current.shutdown(socket.SHUT_RDWR)
                current.close()
            connection.close()

        def remaining() -> float:
            budget = deadline - time.monotonic()
            if expired.is_set() or budget <= 0:
                raise TimeoutError("local metadata deadline exceeded")
            return budget

        watchdog = threading.Timer(5, expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            connection.connect()
            transport_socket = connection.sock
            if transport_socket is None:
                raise ValueError("local metadata socket unavailable")
            active_socket.append(transport_socket)
            transport_socket.settimeout(remaining())
            connection.request("GET", path)
            transport_socket.settimeout(remaining())
            response = connection.getresponse()
            remaining()
            body = response.read(maximum + 1)
            remaining()
            if response.status != 200 or len(body) > maximum:
                raise ValueError("local metadata unavailable")
            return json.loads(body, object_pairs_hook=closed_object)
        finally:
            watchdog.cancel()
            connection.close()

    pid, executable_sha256 = _observe_listener(expected.backend_port)
    version = read_metadata("/api/version", 65536)
    tags = read_metadata("/api/tags", 1024 * 1024)
    if type(version) is not dict or set(version) != {"version"}:
        raise ValueError("local version metadata is invalid")
    if type(tags) is not dict or set(tags) != {"models"}:
        raise ValueError("local model metadata is invalid")
    models = tags["models"]
    if type(models) is not list or len(models) > 4096:
        raise ValueError("local model inventory is invalid")
    matches = []
    for model in models:
        if type(model) is not dict:
            raise ValueError("local model entry is invalid")
        if model.get("name") == expected.model_id or model.get("model") == expected.model_id:
            matches.append(model)
    if (
        len(matches) != 1
        or matches[0].get("name") != expected.model_id
        or matches[0].get("model") != expected.model_id
    ):
        raise ValueError("local model identity is ambiguous")
    if _observe_listener(expected.backend_port) != (pid, executable_sha256):
        raise ValueError("local backend changed during observation")
    model_digest = matches[0].get("digest")
    if type(model_digest) is not str:
        raise ValueError("local model digest is invalid")
    identity = replace(
        expected,
        model_manifest_sha256=model_digest,
        backend_version=version["version"],
        backend_executable_sha256=executable_sha256,
        gateway_source_sha256=hashlib.sha256(
            Path(local_provider_gateway.__file__).read_bytes()
        ).hexdigest(),
        connector_source_sha256=hashlib.sha256(
            Path(openai_compatible_local.__file__).read_bytes()
        ).hexdigest(),
        gateway_policy_sha256=gateway_policy.content_sha256,
    )
    return BackendObservation(identity, pid, executable_sha256)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Explicit public Core preflight or local diagnostic"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--backend-pins", type=Path)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--gateway-port", type=int, default=11435)
    parser.add_argument("--public-cpu-calibration", action="store_true")
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    if args.receipt is not None and not args.run:
        print("PUBLIC_CORE_PREFLIGHT_INPUT_OR_EVALUATION_FAILED", file=sys.stderr)
        return 3
    try:
        from securecode_ai.adapters.local_provider_admission import CoreCase
        from securecode_ai.adapters.public_core_runner import (
            load_public_core_inputs,
            preflight_public_core_case,
        )
        from securecode_ai.contracts import PreflightEligibility

        case = CoreCase(args.case)
        inputs = load_public_core_inputs(
            profile_bytes=_read_host_input(args.profile),
            policy_bytes=_read_host_input(args.policy),
            artifacts_bytes=_read_host_input(args.artifacts),
            gateway_port=args.gateway_port,
        )
        result = preflight_public_core_case(case=case, inputs=inputs)
        if args.run and result.eligibility is PreflightEligibility.ELIGIBLE:
            import threading

            from securecode_ai.adapters.local_provider_gateway import (
                GatewayBudgetMode,
                GatewayPolicy,
                LoopbackOllamaBackend,
                create_gateway_server,
            )
            from securecode_ai.adapters.public_core_execution import (
                BackendIdentity,
                execute_public_core_case,
                source_free_execution_document,
            )

            if args.backend_pins is None:
                raise ValueError("explicit backend pins required")
            expected = BackendIdentity(**json.loads(_read_host_input(args.backend_pins)))
            if (
                expected.gateway_port != args.gateway_port
                or expected.model_id != inputs.profile.model_id
                or expected.model_manifest_sha256 != inputs.profile.model_snapshot
            ):
                raise ValueError("backend profile binding failed")
            gateway_policy = GatewayPolicy(
                expected.model_id,
                expected.model_manifest_sha256,
                backend_port=expected.backend_port,
                backend_version=expected.backend_version,
                timeout_seconds=60.0 if args.public_cpu_calibration else 30.0,
                budget_mode=(
                    GatewayBudgetMode.PUBLIC_CPU_CALIBRATION
                    if args.public_cpu_calibration
                    else GatewayBudgetMode.ORDINARY
                ),
            )
            if gateway_policy.content_sha256 != expected.gateway_policy_sha256:
                raise ValueError("gateway policy pin mismatch")
            initial = _observe_backend(expected, gateway_policy)
            if initial.identity != expected:
                raise ValueError("backend identity mismatch")
            from securecode_ai.adapters.public_gateway_observation import (
                PublicGatewayExchangeRecorder,
            )

            gateway_recorder = PublicGatewayExchangeRecorder(gateway_policy)
            backend = LoopbackOllamaBackend(gateway_policy, observer=gateway_recorder.observe)
            server = create_gateway_server(
                gateway_policy,
                port=expected.gateway_port,
                backend=backend,
                normalization_observer=gateway_recorder.observe_normalization,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                measured = execute_public_core_case(
                    case=case,
                    inputs=inputs,
                    expected_backend=expected,
                    observe_backend=lambda: _observe_backend(expected, gateway_policy),
                )
                document = source_free_execution_document(measured)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            document["gateway_observation"] = gateway_recorder.snapshot_document()
            if args.receipt is not None:
                _persist_terminal_receipt(args.receipt, document)
            sys.stdout.write(_terminal_document(document).decode("ascii"))
            return (
                0
                if measured.measurement_valid
                and measured.run is not None
                and measured.run.completed
                else 2
            )
        document = {
            "case": case.value,
            "mode": "OFFLINE_PREFLIGHT",
            "model_invocations": 0,
            "production_admitted": False,
            "product_outcome": "NOT_EVALUATED",
            "preflight": result.model_dump(mode="json"),
        }
        sys.stdout.write(_terminal_document(document).decode("ascii"))
        return 0 if result.eligibility is PreflightEligibility.ELIGIBLE else 2
    except Exception:
        # Host documents and validation exceptions can contain sensitive fields.
        print("PUBLIC_CORE_PREFLIGHT_INPUT_OR_EVALUATION_FAILED", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
