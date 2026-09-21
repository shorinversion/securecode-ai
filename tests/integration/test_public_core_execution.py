"""Independent execution CLI host observation controls."""

from __future__ import annotations

import json
import os
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from securecode_ai.adapters.local_provider_gateway import GatewayExchangeObservation, GatewayPolicy
from securecode_ai.adapters.public_core_execution import (
    BackendIdentity,
    PublicCoreExecutionResult,
)
from securecode_ai.adapters.public_core_runner import PublicCoreHostInputs

from scripts.public_core_conformance import _observe_listener


def _mapping(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return value


@pytest.mark.parametrize("port", [True, 0, 65536, "11434"])
def test_listener_rejects_invalid_ports_before_process_probe(
    monkeypatch: pytest.MonkeyPatch, port: int
) -> None:
    def unexpected(*args: object, **kwargs: object) -> None:
        pytest.fail("invalid port reached process probe")

    monkeypatch.setattr(subprocess, "run", unexpected)
    with pytest.raises(ValueError):
        _observe_listener(port)


@pytest.mark.skipif(os.name != "nt", reason="Windows process probe contract")
@pytest.mark.parametrize(
    "pid,digest", [(True, "a" * 64), (0, "a" * 64), (42, "A" * 64), (42, "a" * 63)]
)
def test_listener_rejects_invalid_process_identity(
    monkeypatch: pytest.MonkeyPatch, pid: int, digest: str
) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout=json.dumps({"pid": pid, "sha256": digest}).encode()),
    )
    with pytest.raises(ValueError):
        _observe_listener(11434)


@pytest.mark.skipif(os.name != "nt", reason="Windows process probe contract")
def test_listener_binds_hash_without_returning_executable_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[list[str], dict[str, object]]] = []

    def probe(command: list[str], **kwargs: object) -> SimpleNamespace:
        observed.append((command, kwargs))
        return SimpleNamespace(stdout=json.dumps({"pid": 42, "sha256": "a" * 64}).encode())

    monkeypatch.setattr(subprocess, "run", probe)
    assert _observe_listener(11434) == (42, "a" * 64)
    assert "127.0.0.1" in observed[0][0][-1]
    assert "11434" in observed[0][0][-1]
    assert observed[0][1]["timeout"] == 10
    assert observed[0][1]["capture_output"] is True


@pytest.mark.parametrize(
    "fault", [None, "manifest", "duplicate", "listener", "deadline_race", "connect_expiration"]
)
def test_backend_observation_derives_current_metadata_without_generation(
    monkeypatch: pytest.MonkeyPatch, fault: str | None
) -> None:
    import hashlib
    import http.client
    from pathlib import Path

    from securecode_ai.adapters import local_provider_gateway, openai_compatible_local
    from securecode_ai.adapters.local_provider_gateway import GatewayPolicy
    from securecode_ai.adapters.public_core_execution import BackendIdentity

    import scripts.public_core_conformance as cli

    policy = GatewayPolicy("approved-local-model", "b" * 64)
    expected = BackendIdentity(
        "approved-local-model",
        "b" * 64,
        "0.16.2",
        "a" * 64,
        hashlib.sha256(Path(local_provider_gateway.__file__).read_bytes()).hexdigest(),
        policy.content_sha256,
        hashlib.sha256(Path(openai_compatible_local.__file__).read_bytes()).hexdigest(),
        "127.0.0.1",
        11434,
        11435,
    )
    observations = iter([(42, "a" * 64), (43 if fault == "listener" else 42, "a" * 64)])
    monkeypatch.setattr(cli, "_observe_listener", lambda port: next(observations))
    requests: list[str] = []
    expiration: list[Callable[[], object]] = []
    if fault in {"deadline_race", "connect_expiration"}:
        import threading

        class Watchdog:
            def __init__(self, delay: float, callback: Callable[[], object]) -> None:
                del delay
                expiration.append(callback)

            def start(self) -> None:
                pass

            def cancel(self) -> None:
                pass

        monkeypatch.setattr(threading, "Timer", Watchdog)

    class Reply:
        status = 200

        def __init__(self, body: bytes):
            self.body = body

        def read(self, maximum: int) -> bytes:
            return self.body[:maximum]

    class Socket:
        def settimeout(self, timeout: float) -> None:
            assert 0 < timeout <= 5

        def shutdown(self, how: int) -> None:
            pass

        def close(self) -> None:
            pass

    class Connection:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            assert (host, port, timeout) == ("127.0.0.1", 11434, 5)
            self.sock: Socket | None = None
            self.path = ""

        def connect(self) -> None:
            self.sock = Socket()
            if fault == "connect_expiration":
                expiration[0]()

        def request(self, method: str, path: str) -> None:
            assert method == "GET"
            self.path = path
            requests.append(path)
            if fault == "deadline_race":
                expiration[0]()

        def getresponse(self) -> Reply:
            if self.path == "/api/version":
                return Reply(
                    b'{"version":"0.16.2","version":"0.16.2"}'
                    if fault == "duplicate"
                    else b'{"version":"0.16.2"}'
                )
            return Reply(
                json.dumps(
                    {
                        "models": [
                            {
                                "name": "approved-local-model",
                                "model": "approved-local-model",
                                "digest": ("c" if fault == "manifest" else "b") * 64,
                            }
                        ]
                    }
                ).encode()
            )

        def close(self) -> None:
            self.sock = None

    monkeypatch.setattr(http.client, "HTTPConnection", Connection)
    if fault in {"duplicate", "listener", "deadline_race", "connect_expiration"}:
        with pytest.raises((ValueError, TimeoutError)):
            cli._observe_backend(expected, policy)
    else:
        actual = cli._observe_backend(expected, policy)
        assert (actual.identity == expected) is (fault is None)
        assert actual.listener_pid == 42
    assert set(requests) <= {"/api/version", "/api/tags"}


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_metadata_absolute_deadline_stops_real_loopback_trickle(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    import hashlib
    import socket
    import threading
    import time
    from contextlib import suppress
    from pathlib import Path

    from securecode_ai.adapters import local_provider_gateway, openai_compatible_local
    from securecode_ai.adapters.local_provider_gateway import GatewayPolicy
    from securecode_ai.adapters.public_core_execution import BackendIdentity

    import scripts.public_core_conformance as cli

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    policy = GatewayPolicy("approved-local-model", "b" * 64, backend_port=port)
    expected = BackendIdentity(
        "approved-local-model",
        "b" * 64,
        "0.16.2",
        "a" * 64,
        hashlib.sha256(Path(local_provider_gateway.__file__).read_bytes()).hexdigest(),
        policy.content_sha256,
        hashlib.sha256(Path(openai_compatible_local.__file__).read_bytes()).hexdigest(),
        "127.0.0.1",
        port,
        11435 if port != 11435 else 11436,
    )
    monkeypatch.setattr(cli, "_observe_listener", lambda port: (42, "a" * 64))
    stop = threading.Event()

    def serve() -> None:
        try:
            connection, _ = listener.accept()
            with connection:
                connection.recv(4096)
                body = b'{"version":"0.16.2"}'
                headers = (
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\nConnection: close\r\n\r\n"
                )
                if phase == "body":
                    connection.sendall(headers)
                for byte in headers if phase == "headers" else body:
                    if stop.wait(0.35):
                        break
                    connection.sendall(bytes([byte]))
        except OSError:
            pass

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    started = time.monotonic()
    try:
        with pytest.raises((OSError, ValueError)):
            cli._observe_backend(expected, policy)
        assert time.monotonic() - started < 7
    finally:
        stop.set()
        with suppress(OSError):
            listener.close()
        worker.join(timeout=2)
    assert not worker.is_alive()


def test_failed_discovery_reconciliation_preserves_flow_and_safe_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import securecode_ai.adapters.public_core_runner as runner
    from securecode_ai.adapters.local_provider_admission import CoreCase
    from securecode_ai.adapters.public_core_execution import (
        execute_public_core_case,
        source_free_execution_document,
    )

    from tests.unit.test_public_core_execution import (
        _CompletedZeroTransport,
        _identity,
        _inputs,
        _observation,
    )

    def reject(self: object, outcome: object) -> None:
        raise ValueError("private-shaped diagnostic canary must not be retained")

    monkeypatch.setattr(runner.PublicDiscoveryObservationRecorder, "finalize", reject)
    expected = _identity()
    transport = _CompletedZeroTransport()
    measured = execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=_inputs(),
        expected_backend=expected,
        observe_backend=lambda: _observation(expected),
        simulated_transport=transport,
    )
    document = source_free_execution_document(measured)
    assert measured.run is not None and measured.run.flow_constructed
    assert not document["core_completed"]
    assert document["core_failure_code"] == "DISCOVERY_RECONCILIATION_FAILED"
    assert _mapping(document["discovery"])["state"] == "SUCCEEDED"
    assert document["discovery_observation"] is None
    assert transport.calls == 3
    assert "private-shaped diagnostic canary" not in json.dumps(document)


def test_completed_core_serializes_bound_discovery_observation() -> None:
    from securecode_ai.adapters.local_provider_admission import CoreCase
    from securecode_ai.adapters.public_core_execution import (
        execute_public_core_case,
        source_free_execution_document,
    )

    from tests.unit.test_public_core_execution import (
        _CompletedZeroTransport,
        _identity,
        _inputs,
        _observation,
    )

    expected = _identity()
    transport = _CompletedZeroTransport()
    measured = execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=_inputs(),
        expected_backend=expected,
        observe_backend=lambda: _observation(expected),
        simulated_transport=transport,
    )
    document = source_free_execution_document(measured)
    assert document["core_completed"] is True
    assert document["core_failure_code"] is None
    observation = document["discovery_observation"]
    observation_document = _mapping(observation)
    assert _mapping(observation_document["before_collection"])["model_call_status"] == "SUCCEEDED"
    final_receipt = _mapping(observation_document["final_core_receipt"])
    assert final_receipt["model_call_status"] == "SUCCEEDED"
    request_sha256 = observation_document["request_sha256"]
    call_hashes = observation_document["repository_view_call_hashes"]
    assert isinstance(request_sha256, str) and len(request_sha256) == 64
    assert isinstance(call_hashes, list) and len(call_hashes) == 1
    assert final_receipt["repository_calls_used"] == 1
    assert document["production_admitted"] is False
    assert transport.calls == 3


def test_cli_collects_gateway_snapshot_after_owned_service_cleanup(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import securecode_ai.adapters.local_provider_gateway as gateway
    import securecode_ai.adapters.public_core_execution as execution
    import securecode_ai.adapters.public_core_runner as runner
    import securecode_ai.adapters.public_gateway_observation as observation
    from securecode_ai.adapters.local_provider_admission import CoreCase

    import scripts.public_core_conformance as cli
    from tests.unit.test_public_core_execution import (
        _CompletedZeroTransport,
        _identity,
        _inputs,
        _observation,
    )

    inputs = _inputs()
    assert inputs.profile.model_snapshot is not None
    expected = _identity(
        gateway_policy_sha256=gateway.GatewayPolicy(
            inputs.profile.model_id, inputs.profile.model_snapshot
        ).content_sha256
    )
    measured = execution.execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=inputs,
        expected_backend=expected,
        observe_backend=lambda: _observation(expected),
        simulated_transport=_CompletedZeroTransport(),
    )
    events: list[str] = []
    monkeypatch.setattr(runner, "load_public_core_inputs", lambda **kwargs: inputs)
    monkeypatch.setattr(
        cli,
        "_read_host_input",
        lambda path: (
            json.dumps(
                {name: getattr(expected, name) for name in expected.__dataclass_fields__}
            ).encode()
            if str(path) == "pins.json"
            else b"{}"
        ),
    )
    monkeypatch.setattr(cli, "_observe_backend", lambda *args: _observation(expected))
    monkeypatch.setattr(execution, "execute_public_core_case", lambda **kwargs: measured)
    original = observation.PublicGatewayExchangeRecorder.snapshot_document

    def snapshot(
        self: observation.PublicGatewayExchangeRecorder,
    ) -> dict[str, object]:
        events.append("snapshot")
        return original(self)

    monkeypatch.setattr(observation.PublicGatewayExchangeRecorder, "snapshot_document", snapshot)

    class Server:
        def serve_forever(self) -> None:
            pass

        def shutdown(self) -> None:
            events.append("shutdown")

        def server_close(self) -> None:
            events.append("close")

    def create(policy: GatewayPolicy, **kwargs: object) -> Server:
        del policy
        assert isinstance(kwargs["backend"], gateway.LoopbackOllamaBackend)
        return Server()

    monkeypatch.setattr(gateway, "create_gateway_server", create)
    code = cli.main(
        [
            "--run",
            "--profile",
            "profile.json",
            "--policy",
            "policy.json",
            "--artifacts",
            "artifacts.json",
            "--backend-pins",
            "pins.json",
            "--case",
            "python_safe",
        ]
    )
    assert code == 0
    assert events == ["shutdown", "close", "snapshot"]
    document = json.loads(capsys.readouterr().out)
    assert document["production_admitted"] is False
    assert document["origin"] == "SIMULATED"
    assert document["gateway_observation"]["coverage"] == "BACKEND_EXCHANGES_ONLY"
    assert document["gateway_observation"]["client_delivery_known"] is False


def _configure_simulated_cli_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    inputs: PublicCoreHostInputs,
    expected: BackendIdentity,
    measured: PublicCoreExecutionResult,
) -> tuple[ModuleType, list[str]]:
    import securecode_ai.adapters.local_provider_gateway as gateway
    import securecode_ai.adapters.public_core_execution as execution
    import securecode_ai.adapters.public_core_runner as runner

    import scripts.public_core_conformance as cli
    from tests.unit.test_public_core_execution import _observation

    events: list[str] = []
    monkeypatch.setattr(runner, "load_public_core_inputs", lambda **kwargs: inputs)
    monkeypatch.setattr(
        cli,
        "_read_host_input",
        lambda path: (
            json.dumps(
                {name: getattr(expected, name) for name in expected.__dataclass_fields__}
            ).encode()
            if str(path) == "pins.json"
            else b"{}"
        ),
    )
    monkeypatch.setattr(cli, "_observe_backend", lambda *args: _observation(expected))
    monkeypatch.setattr(execution, "execute_public_core_case", lambda **kwargs: measured)

    class Server:
        def serve_forever(self) -> None:
            pass

        def shutdown(self) -> None:
            events.append("shutdown")

        def server_close(self) -> None:
            events.append("close")

    def create(policy: GatewayPolicy, **kwargs: object) -> Server:
        del policy
        assert isinstance(kwargs["backend"], gateway.LoopbackOllamaBackend)
        return Server()

    monkeypatch.setattr(gateway, "create_gateway_server", create)
    return cli, events


def _simulated_run(
    measured_transport: object | None = None,
) -> tuple[PublicCoreHostInputs, BackendIdentity, PublicCoreExecutionResult]:
    import securecode_ai.adapters.local_provider_gateway as gateway
    import securecode_ai.adapters.public_core_execution as execution
    from securecode_ai.adapters.local_provider_admission import CoreCase

    from tests.unit.test_public_core_execution import (
        _CompletedZeroTransport,
        _identity,
        _inputs,
        _observation,
    )

    inputs = _inputs()
    assert inputs.profile.model_snapshot is not None
    expected = _identity(
        gateway_policy_sha256=gateway.GatewayPolicy(
            inputs.profile.model_id, inputs.profile.model_snapshot
        ).content_sha256
    )
    measured = execution.execute_public_core_case(
        case=CoreCase.PYTHON_SAFE,
        inputs=inputs,
        expected_backend=expected,
        observe_backend=lambda: _observation(expected),
        simulated_transport=measured_transport or _CompletedZeroTransport(),
    )
    return inputs, expected, measured


def _run_arguments(receipt: Path) -> list[str]:
    return [
        "--run",
        "--profile",
        "profile.json",
        "--policy",
        "policy.json",
        "--artifacts",
        "artifacts.json",
        "--backend-pins",
        "pins.json",
        "--case",
        "python_safe",
        "--receipt",
        str(receipt),
    ]


def test_cli_run_atomically_persists_the_exact_terminal_document(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    inputs, expected, measured = _simulated_run()
    cli, events = _configure_simulated_cli_run(
        monkeypatch, inputs=inputs, expected=expected, measured=measured
    )
    receipt = tmp_path / "terminal-receipt.json"

    assert cli.main(_run_arguments(receipt)) == 0
    captured = capsys.readouterr()
    assert events == ["shutdown", "close"]
    assert receipt.read_bytes() == captured.out.encode("ascii")
    assert json.loads(captured.out)["origin"] == "SIMULATED"
    assert not list(tmp_path.glob(".terminal-receipt.json.*.checkpoint"))


def test_cli_receipt_excludes_raw_model_sentinel(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    from tests.unit.test_public_core_execution import _reply, _ScriptedTransport

    sentinel = "raw-model-payload-sentinel-must-not-persist"
    inputs, expected, measured = _simulated_run(
        _ScriptedTransport([_reply({"candidates": [], "untrusted": sentinel})])
    )
    cli, _events = _configure_simulated_cli_run(
        monkeypatch, inputs=inputs, expected=expected, measured=measured
    )
    receipt = tmp_path / "source-free-receipt.json"

    assert cli.main(_run_arguments(receipt)) == 2
    captured = capsys.readouterr()
    assert sentinel not in captured.out
    assert sentinel not in captured.err
    assert sentinel not in receipt.read_text(encoding="ascii")


def test_cli_receipt_publication_race_is_non_success_and_preserves_destination(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    inputs, expected, measured = _simulated_run()
    cli, _events = _configure_simulated_cli_run(
        monkeypatch, inputs=inputs, expected=expected, measured=measured
    )
    sentinel = "receipt-publication-race-sentinel"
    receipt = tmp_path / "publication-race-receipt.json"
    existing = b"pre-existing-receipt-bytes"

    def race_publish(
        temporary: Path,
        destination: Path,
        *args: object,
        **kwargs: object,
    ) -> None:
        del temporary, args, kwargs
        assert destination == receipt
        receipt.write_bytes(existing)
        raise FileExistsError(sentinel)

    monkeypatch.setattr(cli.os, "link", race_publish)
    assert cli.main(_run_arguments(receipt)) == 3
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "PUBLIC_CORE_PREFLIGHT_INPUT_OR_EVALUATION_FAILED\n"
    assert sentinel not in captured.err
    assert receipt.read_bytes() == existing
    assert not list(tmp_path.glob(".publication-race-receipt.json.*.checkpoint"))


def test_cli_preflight_rejects_a_receipt_path_without_reading_host_inputs(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    from scripts.public_core_conformance import main

    marker = "preflight-receipt-path-must-not-appear"
    assert (
        main(
            [
                "--preflight",
                "--profile",
                "profile.json",
                "--policy",
                "policy.json",
                "--artifacts",
                "artifacts.json",
                "--case",
                "python_safe",
                "--receipt",
                str(tmp_path / marker),
            ]
        )
        == 3
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "PUBLIC_CORE_PREFLIGHT_INPUT_OR_EVALUATION_FAILED\n"
    assert marker not in captured.err


@pytest.mark.parametrize("phase", ["HEADERS", "BODY"])
def test_actual_backend_deadline_shutdown_records_active_phase_without_raw_data(phase: str) -> None:
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from securecode_ai.adapters.local_provider_gateway import (
        GatewayPolicy,
        LoopbackOllamaBackend,
    )

    stop = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_POST(self) -> None:
            self.rfile.read(int(self.headers["Content-Length"]))
            if phase == "BODY":
                self.send_response(200)
                self.send_header("Content-Length", "100")
                self.end_headers()
                self.wfile.write(b"x")
                self.wfile.flush()
            stop.wait(2)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    captured: list[GatewayExchangeObservation] = []
    backend = LoopbackOllamaBackend(
        GatewayPolicy("approved-local-model", "b" * 64, backend_port=server.server_port),
        observer=captured.append,
    )
    try:
        reply = backend._exchange(
            "POST",
            "/v1/chat/completions",
            b"public-fixture-canary",
            deadline=time.monotonic() + 0.25,
            max_bytes=4096,
            dispatched=True,
        )
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert not worker.is_alive()
    assert reply.status in (502, 504)
    assert len(captured) == 1
    observation = captured[0]
    assert observation.operation.value == "GENERATION"
    assert observation.phase.value == phase
    if phase == "BODY":
        assert observation.observed_http_status == 200
        assert observation.received_bytes == 1
    assert observation.deadline_expired is True
    assert observation.backend_dispatched is True
    assert "public-fixture-canary" not in repr(observation)


def test_clean_actual_exchange_is_observed_after_transport_close() -> None:
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from securecode_ai.adapters.local_provider_gateway import (
        GatewayExchangeOperation,
        GatewayExchangePhase,
        GatewayPolicy,
        LoopbackOllamaBackend,
    )

    observations: list[GatewayExchangeObservation] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            body = b'{"version":"0.16.2"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    policy = GatewayPolicy("qwen-test", "a" * 64, backend_port=server.server_port)
    try:
        reply = LoopbackOllamaBackend(policy, observer=observations.append)._exchange(
            "GET",
            "/api/version",
            None,
            deadline=time.monotonic() + 2,
            max_bytes=65536,
            dispatched=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert reply.status == 200 and not reply.backend_dispatched
    assert len(observations) == 1
    observation = observations[0]
    assert observation.operation is GatewayExchangeOperation.VERSION
    assert observation.phase is GatewayExchangePhase.COMPLETE
    assert observation.observed_http_status == 200
    assert observation.elapsed_known and observation.received_bytes == len(b'{"version":"0.16.2"}')


def test_timer_shutdown_keeps_original_failure_mapping_and_records_header_phase() -> None:
    import socket
    import threading
    import time

    from securecode_ai.adapters.local_provider_gateway import (
        GatewayExchangePhase,
        GatewayPolicy,
        LoopbackOllamaBackend,
    )

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    observations: list[GatewayExchangeObservation] = []
    finished = threading.Event()

    def stall() -> None:
        peer = None
        try:
            peer, _ = listener.accept()
            peer.recv(65536)
            finished.wait(1)
        except OSError:
            pass
        finally:
            if peer is not None:
                peer.close()
            finished.set()

    worker = threading.Thread(target=stall, daemon=True)
    worker.start()
    policy = GatewayPolicy(
        "qwen-test", "a" * 64, backend_port=listener.getsockname()[1], timeout_seconds=0.1
    )
    try:
        reply = LoopbackOllamaBackend(policy, observer=observations.append)._exchange(
            "GET",
            "/api/version",
            None,
            deadline=time.monotonic() + 0.1,
            max_bytes=65536,
            dispatched=False,
        )
    finally:
        finished.set()
        listener.close()
        worker.join(timeout=2)
    assert reply.status in (502, 504)
    assert len(observations) == 1
    observation = observations[0]
    assert observation.phase is GatewayExchangePhase.HEADERS
    assert observation.deadline_expired
    assert observation.mapped_status == reply.status


def test_observer_fault_downgrades_only_a_successful_exchange() -> None:
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from securecode_ai.adapters.local_provider_gateway import (
        GatewayPolicy,
        LoopbackOllamaBackend,
    )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            body = b'{"version":"0.16.2"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    policy = GatewayPolicy("qwen-test", "a" * 64, backend_port=server.server_port)
    try:
        reply = LoopbackOllamaBackend(
            policy, observer=lambda _: (_ for _ in ()).throw(RuntimeError())
        )._exchange(
            "GET",
            "/api/version",
            None,
            deadline=time.monotonic() + 2,
            max_bytes=65536,
            dispatched=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
    assert reply.status == 502 and reply.body == b'{"error":"gateway_request_unavailable"}'


def test_exchange_observer_runs_after_connection_close_and_timer_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    import securecode_ai.adapters.local_provider_gateway as gateway

    timers: list[threading.Timer] = []
    original_timer = gateway.threading.Timer

    def timer(
        interval: float,
        function: Callable[..., object],
        args: tuple[object, ...] | None = None,
        kwargs: dict[str, object] | None = None,
    ) -> threading.Timer:
        value = original_timer(interval, function, args=args, kwargs=kwargs)
        timers.append(value)
        return value

    monkeypatch.setattr(gateway.threading, "Timer", timer)

    class Channel:
        def settimeout(self, value: float) -> None:
            pass

        def shutdown(self, how: int) -> None:
            pass

    class Response:
        status = 200
        data = b"public metadata"

        def isclosed(self) -> bool:
            return False

        def read1(self, maximum: int) -> bytes:
            value, self.data = self.data[:maximum], self.data[maximum:]
            return value

    class Connection:
        sock = Channel()
        closed = False

        def connect(self) -> None:
            pass

        def request(self, *args: object, **kwargs: object) -> None:
            pass

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    monkeypatch.setattr(gateway.http.client, "HTTPConnection", lambda *args, **kwargs: connection)
    captured: list[GatewayExchangeObservation] = []

    def observe(value: GatewayExchangeObservation) -> None:
        assert connection.closed
        assert len(timers) == 1 and timers[0].finished.is_set()
        captured.append(value)

    reply = gateway.LoopbackOllamaBackend(
        gateway.GatewayPolicy("approved-local-model", "b" * 64),
        observer=observe,
    )._exchange(
        "GET",
        "/api/version",
        None,
        deadline=time.monotonic() + 2,
        max_bytes=4096,
        dispatched=False,
    )
    assert reply.status == 200
    assert len(captured) == 1
    assert captured[0].received_bytes == len(b"public metadata")
