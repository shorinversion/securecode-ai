"""Real gateway HTTP events with zero underlying model inference."""

import http.client
import json
import socket
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from securecode_ai.adapters.local_provider_gateway import (
    LoopbackOllamaBackend,
    create_gateway_server,
    handle_gateway_request,
)
from securecode_ai.adapters.model import ProviderAttempt, ProviderStreamState
from securecode_ai.contracts import DataClass, ModelCallStatus, ModelPurpose

from tests.unit.test_local_provider_gateway import (
    POLICY,
    SpyBackend,
    _validated_native_post_tool_request,
    request,
)
from tests.unit.test_openai_compatible_local import _profile_for
from tests.unit.test_provider_normalization import _binding, _normalize, _validator
from tests.unit.test_provider_preflight import _policy
from tests.unit.test_provider_preflight import _request as _scoped_request


def test_real_http_native_provider_refusal_has_zero_backend_dispatch() -> None:
    backend = SpyBackend()
    server = create_gateway_server(POLICY, port=0, backend=backend)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        connection.request(
            "POST",
            "/v1/chat/completions",
            body=request(DataClass.RESTRICTED.value),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        body = response.read(65536)
        assert response.status == 200 and backend.calls == []
        assert json.loads(body)["choices"][0]["message"]["refusal"] == "RESTRICTED_DATA_POLICY"
        model_request = _scoped_request(
            _profile_for(server.server_port),
            _policy("egress.valid.private-model-source.json"),
            ModelPurpose.MODEL_NATIVE_DISCOVERY,
        )
        normalized = _normalize(
            model_request,
            ProviderAttempt(
                dialect=model_request.api_dialect,
                http_status=response.status,
                response_bytes=body,
                transport_failure=None,
                stream_state=ProviderStreamState.COMPLETE,
                binding=_binding(model_request),
                elapsed_ms=1,
            ),
            _validator(model_request),
        )
        assert normalized.result.status is ModelCallStatus.REFUSED
        assert normalized.payload is None
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()


@pytest.mark.parametrize(
    "partial",
    [
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\n",
        b"POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx",
    ],
)
def test_absolute_ingress_deadline_releases_single_worker(partial: bytes) -> None:
    backend = SpyBackend()
    server = create_gateway_server(replace(POLICY, timeout_seconds=0.2), port=0, backend=backend)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
    try:
        client.sendall(partial)
        # EOF proves the actual stalled socket is closed, rather than a status flag.
        assert client.recv(65536) == b""
        assert backend.calls == []
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
        try:
            connection.request(
                "POST", "/v1/chat/completions", body=request(DataClass.RESTRICTED.value)
            )
            response = connection.getresponse()
            assert response.status == 200
            assert json.loads(response.read())["choices"][0]["message"]["refusal"]
        finally:
            connection.close()
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()


def test_backend_header_trickle_cannot_hold_gateway_worker() -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(2)
    finished = threading.Event()

    def trickle() -> None:
        peer = None
        try:
            peer, _ = listener.accept()
            peer.settimeout(2)
            peer.recv(65536)
            for byte in b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n":
                peer.sendall(bytes([byte]))
                if finished.wait(0.025):
                    break
        except OSError:
            pass
        finally:
            if peer is not None:
                peer.close()
            finished.set()

    backend_thread = threading.Thread(target=trickle, daemon=True)
    backend_thread.start()
    policy = replace(POLICY, backend_port=listener.getsockname()[1], timeout_seconds=0.2)
    server = create_gateway_server(policy, port=0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    first = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    second = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        first.request("POST", "/v1/chat/completions", body=request())
        # Both actual sockets expire; gateway does not wait for a complete header.
        with pytest.raises((http.client.RemoteDisconnected, ConnectionResetError)):
            first.getresponse()
        second.request("POST", "/v1/chat/completions", body=request(DataClass.RESTRICTED.value))
        response = second.getresponse()
        assert response.status == 200
        assert json.loads(response.read())["choices"][0]["message"]["refusal"]
        assert finished.wait(1)
    finally:
        first.close()
        second.close()
        finished.set()
        listener.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        backend_thread.join(timeout=5)
    assert not worker.is_alive() and not backend_thread.is_alive()


@pytest.mark.parametrize(
    "change", ["none", "pre_digest", "pre_version", "duplicate", "post_digest", "post_version"]
)
def test_live_metadata_pins_before_and_after_generation(change: str) -> None:
    observed: list[tuple[str, bytes | None]] = []

    class BackendHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            observed.append((self.path, None))
            after = any(path == "/api/chat" for path, _ in observed)
            document: object
            if self.path == "/api/version":
                changed = change == "pre_version" or (change == "post_version" and after)
                document = {"version": "0.0.1" if changed else POLICY.backend_version}
            else:
                changed = change == "pre_digest" or (change == "post_digest" and after)
                model = {
                    "name": POLICY.model_id,
                    "model": POLICY.model_id,
                    "digest": "b" * 64 if changed else POLICY.model_manifest_sha256,
                }
                document = {"models": [model, model] if change == "duplicate" else [model]}
            self._send(json.dumps(document).encode())

        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            observed.append((self.path, body))
            document = {
                "created_at": "2026-09-18T00:00:00Z",
                "done": True,
                "done_reason": "stop",
                "eval_count": 3,
                "eval_duration": 1,
                "load_duration": 1,
                "message": {"role": "assistant", "content": "{}"},
                "model": POLICY.model_id,
                "prompt_eval_cached_count": 0,
                "prompt_eval_count": 4,
                "prompt_eval_duration": 1,
                "total_duration": 1,
            }
            self._send(json.dumps(document).encode())

        def _send(self, body: bytes) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), BackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    policy = replace(POLICY, backend_port=server.server_port, timeout_seconds=2)
    body = request()
    try:
        reply = handle_gateway_request(body, policy=policy, backend=LoopbackOllamaBackend(policy))
        generation: list[tuple[str, bytes]] = []
        for path, content in observed:
            if content is not None:
                generation.append((path, content))
        if change in ("pre_digest", "pre_version", "duplicate"):
            assert reply.status == 502 and not reply.backend_dispatched
            assert generation == []
        else:
            assert len(generation) == 1 and generation[0][0] == "/api/chat"
            assert json.loads(generation[0][1]) == {
                "model": POLICY.model_id,
                "messages": json.loads(body)["messages"],
                "stream": False,
                "think": True,
                "options": {"num_predict": 32},
                "format": "json",
            }
            assert reply.backend_dispatched
            assert reply.status == (200 if change == "none" else 502)
            if change == "none":
                assert [path for path, _ in observed] == [
                    "/api/version",
                    "/api/tags",
                    "/api/chat",
                    "/api/version",
                    "/api/tags",
                ]
        assert not reply.native_policy_refusal
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()


def test_loopback_native_post_tool_turn_sends_json_format_only_after_validated_history() -> None:
    observed: list[dict[str, object]] = []

    class BackendHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            if self.path == "/api/version":
                self._send(json.dumps({"version": POLICY.backend_version}).encode())
            else:
                self._send(
                    json.dumps(
                        {
                            "models": [
                                {
                                    "name": POLICY.model_id,
                                    "model": POLICY.model_id,
                                    "digest": POLICY.model_manifest_sha256,
                                }
                            ]
                        }
                    ).encode()
                )

        def do_POST(self) -> None:
            observed.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self._send(
                json.dumps(
                    {
                        "created_at": "2026-09-18T00:00:00Z",
                        "done": True,
                        "done_reason": "stop",
                        "eval_count": 3,
                        "eval_duration": 1,
                        "load_duration": 1,
                        "message": {"role": "assistant", "content": "{}"},
                        "model": POLICY.model_id,
                        "prompt_eval_cached_count": 0,
                        "prompt_eval_count": 4,
                        "prompt_eval_duration": 1,
                        "total_duration": 1,
                    }
                ).encode()
            )

        def _send(self, body: bytes) -> None:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), BackendHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    policy = replace(POLICY, backend_port=server.server_port, timeout_seconds=2)
    try:
        reply = handle_gateway_request(
            json.dumps(_validated_native_post_tool_request()).encode(),
            policy=policy,
            backend=LoopbackOllamaBackend(policy),
        )
        assert reply.status == 200 and reply.backend_dispatched
        assert len(observed) == 1 and observed[0]["format"] == "json"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    assert not thread.is_alive()


def test_actual_public_core_native_http_accepts_canonical_source_locations() -> None:
    import base64
    from pathlib import Path

    from securecode_ai.adapters.local_provider_admission import CoreCase
    from securecode_ai.adapters.local_provider_gateway import GatewayPolicy, GatewayReply
    from securecode_ai.adapters.public_core_runner import (
        load_public_core_inputs,
        run_public_core_case,
    )
    from securecode_ai.contracts import EgressPolicyDocument

    root = Path(__file__).resolve().parents[2]
    policy = GatewayPolicy("approved-local-model", "a" * 64)
    body = json.dumps(
        {
            "id": "chatcmpl_codec_test",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": '{"candidates":[]}', "refusal": None},
                }
            ],
            "usage": {"prompt_tokens": 4, "completion_tokens": 3},
        }
    ).encode()
    backend = SpyBackend(GatewayReply(200, body))
    server = create_gateway_server(policy, port=0, backend=backend)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        profile = json.loads(
            (
                root / "specs/contracts/provider-fixtures/valid.local-openai-compatible.json"
            ).read_bytes()
        )
        profile["endpoint"].update(
            base_url=f"http://127.0.0.1:{server.server_port}/v1", allowed_ports=[server.server_port]
        )
        profile["model_snapshot"] = policy.model_manifest_sha256
        profile_bytes = json.dumps(profile).encode()
        egress = json.loads(
            (
                root / "specs/contracts/policy/fixtures/egress.valid.private-model-source.json"
            ).read_bytes()
        )
        egress["tenant_scope"] = "synthetic-public-development"
        egress["rules"][0]["data_classes"].append(DataClass.PUBLIC.value)
        egress["rules"][0]["purposes"].append("candidate_investigation")
        policy_bytes = EgressPolicyDocument.model_validate_json(
            json.dumps(egress)
        ).canonical_bytes()
        artifacts = {
            "stage_catalogue": (root / "specs/behavior/stage-catalogue.yaml").read_bytes(),
            "workflow": (root / "specs/behavior/workflows.md").read_bytes(),
            "policy": policy_bytes,
            "configuration": profile_bytes,
            "tool_policy": b"reviewed test tool policy",
            "repository_scope": b"fixed public Python safe scope",
            "repository_view_policy": b"bounded public source view",
            "producer": (
                root / "packages/adapters/src/securecode_ai/adapters/product_runtime.py"
            ).read_bytes(),
        }
        inputs = load_public_core_inputs(
            profile_bytes=profile_bytes,
            policy_bytes=policy_bytes,
            artifacts_bytes=json.dumps(
                {k: base64.b64encode(v).decode() for k, v in artifacts.items()}
            ).encode(),
            gateway_port=server.server_port,
        )
        result = run_public_core_case(case=CoreCase.PYTHON_SAFE, inputs=inputs)
        # This peer returns a terminal response before a required native tool
        # inspection.  Source-location acceptance remains observable at the
        # gateway, while the existing Core guard correctly keeps the run open.
        assert not result.completed and result.production_admitted is False
        assert len(backend.calls) == 1
        forwarded = json.loads(backend.calls[0][0])
        context = json.loads(forwarded["messages"][0]["content"])
        assert context["untrusted_source_locations"]
        assert context["untrusted_source_locations"][0]["location"]["extensions"] == []
        assert "tools" in forwarded
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
    assert not worker.is_alive()
