"""Local-only transport tests for the P3.12 OpenAI-compatible connector."""

from __future__ import annotations

import json
import socket
import threading
import time

import pytest
from securecode_ai.adapters import (
    AuthorizedProviderHarness,
    EndpointAuthorizationIssuer,
    HmacContentIdentifier,
    JsonObjectValidator,
    ProviderProfileRegistry,
)
from securecode_ai.adapters.model import ModelBoundaryExecution, ProviderAttemptBinding
from securecode_ai.adapters.openai_compatible_local import OpenAICompatibleLocalHttpConnector
from securecode_ai.contracts import (
    DataClass,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ProviderProfile,
)

from .test_endpoint_policy import ScriptedResolver, _remote_context
from .test_provider_preflight import (
    _issuer,
    _policy,
    _preflight_request,
    _profile,
    _request,
    _semantic_cases,
)


def _success_body(*, refusal: str | None = None) -> bytes:
    return json.dumps(
        {
            "id": "local-safe-id",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": '{"candidates":[]}', "refusal": refusal},
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _ollama_success_body(*, extra_choice_control: bool = False) -> bytes:
    choice: dict[str, object] = {
        "index": 0,
        "message": {"role": "assistant", "content": '{"candidates":[]}'},
        "finish_reason": "stop",
    }
    if extra_choice_control:
        choice["logprobs"] = None
    return json.dumps(
        {
            "id": "chatcmpl-ollama-safe-id",
            "object": "chat.completion",
            "created": 1,
            "model": "approved-local-model",
            "system_fingerprint": "fp_ollama",
            "choices": [choice],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
            },
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


class _ScriptedSocket:
    def __init__(self, endpoint: _LocalEndpoint) -> None:
        self._endpoint = endpoint
        self._remaining = bytearray(endpoint.response)
        self._closed = False
        self.timeouts: list[float] = []
        self.connect_addresses: list[tuple[str, int]] = []

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def connect(self, address: tuple[str, int]) -> None:
        self.connect_addresses.append(address)
        if address != ("127.0.0.1", self._endpoint.port):
            raise OSError("scripted peer rejected")

    def getpeername(self) -> tuple[str, int]:
        return "127.0.0.1", self._endpoint.port

    def sendall(self, request: bytes) -> None:
        self._endpoint._record_request(request)

    def recv(self, maximum: int) -> bytes:
        if self._endpoint.times_out:
            raise TimeoutError
        if not self._remaining:
            return b""
        chunk = bytes(self._remaining[:maximum])
        del self._remaining[:maximum]
        return chunk

    def shutdown(self, how: int) -> None:
        del how

    def close(self) -> None:
        self._closed = True


class _LocalEndpoint:
    def __init__(self, *, status: int, body: bytes, times_out: bool = False) -> None:
        self.status = status
        self.body = body
        self.times_out = times_out
        self.port = 11434
        self.requests: list[tuple[str, dict[str, str], bytes]] = []
        self.sockets: list[_ScriptedSocket] = []
        self.response = (
            f"HTTP/1.1 {status} scripted\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(socket, "socket", self._socket_factory)

    def _socket_factory(
        self,
        family: int,
        kind: int,
        proto: int = 0,
        fileno: int | None = None,
    ) -> _ScriptedSocket:
        if family != socket.AF_INET or kind != socket.SOCK_STREAM:
            raise OSError("scripted socket family rejected")
        if proto != 0 or fileno is not None:
            raise OSError("scripted socket options rejected")
        connection = _ScriptedSocket(self)
        self.sockets.append(connection)
        return connection

    def _record_request(self, request: bytes) -> None:
        raw_headers, body = request.split(b"\r\n\r\n", 1)
        lines = raw_headers.decode("ascii", "strict").split("\r\n")
        method, path, version = lines[0].split(" ")
        if method != "POST" or version != "HTTP/1.1":
            raise OSError("scripted request line rejected")
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            headers[name] = value.strip()
        self.requests.append((path, headers, body))


def _profile_for(port: int) -> ProviderProfile:
    data = _profile("valid.local-openai-compatible.json").model_dump(mode="json")
    data["endpoint"] = {
        "base_url": f"http://127.0.0.1:{port}/v1",
        "authority": "127.0.0.1",
        "allowed_ports": [port],
        "follow_redirects": False,
        "local_plaintext_exception": True,
    }
    return ProviderProfile.model_validate(data)


def _execute(
    *, profile: ProviderProfile, connector: OpenAICompatibleLocalHttpConnector
) -> tuple[ModelBoundaryExecution, ModelRequest]:
    policy = _policy("egress.valid.private-model-source.json")
    request = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    case = dict(_semantic_cases()[0])
    issuer = _issuer(profile, policy)
    return (
        AuthorizedProviderHarness(
            model_issuer=issuer,
            endpoint_issuer=EndpointAuthorizationIssuer(
                provider_registry=ProviderProfileRegistry((profile,))
            ),
        ).execute_remote(
            preflight=_preflight_request(request, case),
            profile=profile,
            policy=policy,
            context_builder=lambda: _remote_context(request),
            resolver=ScriptedResolver(),
            connector=connector,
            credential_supplier=lambda selected: None,
            validator=JsonObjectValidator(
                validator=request.output_schema,
                data_class=DataClass.CONFIDENTIAL_SECURITY,
                content_identifier=HmacContentIdentifier(b"p" * 32),
                required_keys=("candidates",),
            ),
            now=100.0,
        ),
        request,
    )


def test_local_connector_uses_authorized_peer_and_normalizes_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    endpoint = _LocalEndpoint(status=200, body=_success_body())
    endpoint.install(monkeypatch)
    profile = _profile_for(endpoint.port)
    outcome, _ = _execute(
        profile=profile,
        connector=OpenAICompatibleLocalHttpConnector(profile=profile),
    )
    assert outcome.result is not None
    assert outcome.result.status is ModelCallStatus.SUCCEEDED
    assert len(endpoint.requests) == 1
    path, headers, request_body = endpoint.requests[0]
    assert path == "/v1/chat/completions"
    assert headers["Host"] == f"127.0.0.1:{endpoint.port}"
    assert "Proxy-Authorization" not in headers
    assert json.loads(request_body)["response_format"] == {"type": "json_object"}


def test_local_connector_sends_explicit_sampling_controls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = _LocalEndpoint(status=200, body=_success_body())
    endpoint.install(monkeypatch)
    profile = _profile_for(endpoint.port)
    outcome, _ = _execute(
        profile=profile,
        connector=OpenAICompatibleLocalHttpConnector(
            profile=profile,
            temperature=0.0,
            seed=42,
        ),
    )
    assert outcome.result is not None
    assert outcome.result.status is ModelCallStatus.SUCCEEDED
    body = json.loads(endpoint.requests[0][2])
    assert body["temperature"] == 0.0
    assert body["seed"] == 42


@pytest.mark.parametrize(
    ("kwargs", "code"),
    [
        ({"temperature": -0.1}, "LOCAL_CONNECTOR_TEMPERATURE_REJECTED"),
        ({"temperature": 2.1}, "LOCAL_CONNECTOR_TEMPERATURE_REJECTED"),
        ({"temperature": True}, "LOCAL_CONNECTOR_TEMPERATURE_REJECTED"),
        ({"seed": -1}, "LOCAL_CONNECTOR_SEED_REJECTED"),
        ({"seed": True}, "LOCAL_CONNECTOR_SEED_REJECTED"),
    ],
)
def test_local_connector_rejects_invalid_sampling_controls(
    kwargs: dict[str, object], code: str
) -> None:
    with pytest.raises(ValueError, match=code):
        OpenAICompatibleLocalHttpConnector(profile=_profile_for(11434), **kwargs)  # type: ignore[arg-type]


def test_http_200_refusal_stays_a_typed_non_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = _LocalEndpoint(status=200, body=_success_body(refusal="declined"))
    endpoint.install(monkeypatch)
    profile = _profile_for(endpoint.port)
    outcome, _ = _execute(
        profile=profile,
        connector=OpenAICompatibleLocalHttpConnector(profile=profile),
    )
    assert outcome.result is not None
    assert outcome.result.status is ModelCallStatus.REFUSED
    assert outcome.payload is None


def test_ollama_0162_envelope_is_canonicalized_before_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = _LocalEndpoint(status=200, body=_ollama_success_body())
    endpoint.install(monkeypatch)
    profile = _profile_for(endpoint.port)
    outcome, _ = _execute(
        profile=profile,
        connector=OpenAICompatibleLocalHttpConnector(profile=profile),
    )
    assert outcome.result is not None
    assert outcome.result.status is ModelCallStatus.SUCCEEDED


def test_ollama_envelope_drift_is_rejected_without_retaining_native_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = _LocalEndpoint(
        status=200,
        body=_ollama_success_body(extra_choice_control=True),
    )
    endpoint.install(monkeypatch)
    profile = _profile_for(endpoint.port)
    connector = OpenAICompatibleLocalHttpConnector(profile=profile)
    channel = connector.connect(
        ip_address="127.0.0.1",
        port=endpoint.port,
        server_name="127.0.0.1",
        timeout_ms=1000,
    )
    attempt = connector.send(
        channel,
        credential=None,
        payload=b'{"bounded":"source"}',
        model_id=profile.model_id,
        timeout_ms=1000,
        binding=_binding(),
    )
    assert attempt.response_bytes is None
    assert attempt.transport_failure is not None
    assert attempt.transport_failure.value == "PROVIDER_ERROR"


def test_cancelled_transport_returns_cancelled_without_a_http_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancelled = threading.Event()
    endpoint = _LocalEndpoint(status=200, body=_success_body())
    endpoint.install(monkeypatch)
    profile = _profile_for(endpoint.port)
    connector = OpenAICompatibleLocalHttpConnector(
        profile=profile,
        cancelled=cancelled.is_set,
    )
    channel = connector.connect(
        ip_address="127.0.0.1",
        port=endpoint.port,
        server_name="127.0.0.1",
        timeout_ms=1000,
    )
    cancelled.set()
    attempt = connector.send(
        channel,
        credential=None,
        payload=b'{"bounded":"source"}',
        model_id=profile.model_id,
        timeout_ms=1000,
        binding=_binding(),
    )
    assert attempt.transport_failure is not None
    assert attempt.transport_failure.value == "CANCELLED"
    assert endpoint.requests == []


def test_timeout_and_redirect_are_non_success_without_followup_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = _LocalEndpoint(status=200, body=_success_body(), times_out=True)
    endpoint.install(monkeypatch)
    timestamps = iter((0.0, 0.0, 0.1, 0.1))
    profile = _profile_for(endpoint.port)
    connector = OpenAICompatibleLocalHttpConnector(profile=profile)
    channel = connector.connect(
        ip_address="127.0.0.1",
        port=endpoint.port,
        server_name="127.0.0.1",
        timeout_ms=1000,
    )
    with monkeypatch.context() as clock_patch:
        clock_patch.setattr(time, "monotonic", lambda: next(timestamps))
        timeout = connector.send(
            channel,
            credential=None,
            payload=b'{"bounded":"source"}',
            model_id=profile.model_id,
            timeout_ms=50,
            binding=_binding(),
        )
    assert timeout.transport_failure is not None
    assert timeout.transport_failure.value == "TIMEOUT"
    assert len(endpoint.requests) == 1

    redirect_endpoint = _LocalEndpoint(status=302, body=b"{}")
    redirect_endpoint.install(monkeypatch)
    profile = _profile_for(redirect_endpoint.port)
    connector = OpenAICompatibleLocalHttpConnector(profile=profile)
    channel = connector.connect(
        ip_address="127.0.0.1",
        port=redirect_endpoint.port,
        server_name="127.0.0.1",
        timeout_ms=1000,
    )
    redirect = connector.send(
        channel,
        credential=None,
        payload=b'{"bounded":"source"}',
        model_id=profile.model_id,
        timeout_ms=1000,
        binding=_binding(),
    )
    assert redirect.redirected is True
    assert len(redirect_endpoint.requests) == 1


def test_oversized_response_is_rejected_without_retaining_its_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = _LocalEndpoint(status=200, body=b"x" * (1024 * 1024 + 1))
    endpoint.install(monkeypatch)
    profile = _profile_for(endpoint.port)
    connector = OpenAICompatibleLocalHttpConnector(profile=profile)
    channel = connector.connect(
        ip_address="127.0.0.1",
        port=endpoint.port,
        server_name="127.0.0.1",
        timeout_ms=1000,
    )
    attempt = connector.send(
        channel,
        credential=None,
        payload=b'{"bounded":"source"}',
        model_id=profile.model_id,
        timeout_ms=1000,
        binding=_binding(),
    )
    assert attempt.response_bytes is None
    assert attempt.transport_failure is not None
    assert attempt.transport_failure.value == "PROVIDER_ERROR"


def _binding() -> ProviderAttemptBinding:
    return ProviderAttemptBinding(
        request_hash="a" * 64,
        profile_hash="b" * 64,
        policy_hash="c" * 64,
        manifest_hash="d" * 64,
        attempt=1,
    )
