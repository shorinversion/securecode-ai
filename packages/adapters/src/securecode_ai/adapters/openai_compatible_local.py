"""Bounded direct HTTP transport for an approved local OpenAI-compatible profile.

The connector deliberately receives only the endpoint proof supplied by the
existing provider harness.  It does not resolve names, consult proxy
configuration, follow redirects, or construct an authorization chain.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import time
from contextlib import suppress
from dataclasses import dataclass
from typing import Final, Protocol
from urllib.parse import urlsplit

from securecode_ai.core import ApiDialect, ProviderKind, ProviderProfile

from .model import (
    ConnectedChannel,
    ProviderAttempt,
    ProviderAttemptBinding,
    ProviderStreamState,
    TransportFailure,
)

_MAX_HEADER_BYTES: Final = 16 * 1024
_MAX_RESPONSE_BYTES: Final = 1024 * 1024
_MAX_WIRE_INT: Final = 9_007_199_254_740_991
_CANCEL_POLL_SECONDS: Final = 0.05


class CancellationProbe(Protocol):
    """A non-blocking cancellation signal owned by the caller."""

    def __call__(self) -> bool: ...


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response member")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    del value
    raise ValueError("invalid response constant")


def _wire_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_WIRE_INT:
        raise ValueError("invalid response integer")
    return value


def _canonicalize_ollama_envelope(response: bytes, *, expected_model_id: str) -> bytes:
    """Translate only the observed Ollama chat envelope into the closed dialect.

    The generic OpenAI-compatible normalizer deliberately accepts a smaller
    envelope. This adapter discards Ollama metadata only after validating its
    complete control surface; a drifted native response never reaches a
    ``ProviderAttempt`` with provider-owned bytes attached.
    """

    document = json.loads(
        response,
        object_pairs_hook=_closed_json_object,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(document, dict):
        raise ValueError("response root is invalid")
    if set(document) == {"id", "choices", "usage"}:
        return response
    if set(document) != {
        "id",
        "object",
        "created",
        "model",
        "system_fingerprint",
        "choices",
        "usage",
    }:
        raise ValueError("response control surface is invalid")
    if (
        not isinstance(document["id"], str)
        or document["object"] != "chat.completion"
        or document["model"] != expected_model_id
        or document["system_fingerprint"] != "fp_ollama"
    ):
        raise ValueError("response metadata is invalid")
    _wire_int(document["created"])

    choices = document["choices"]
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise ValueError("response choices are invalid")
    choice = choices[0]
    if set(choice) != {"index", "message", "finish_reason"} or _wire_int(choice["index"]) != 0:
        raise ValueError("response choice control surface is invalid")
    finish_reason = choice["finish_reason"]
    if finish_reason not in {
        "stop",
        "incomplete",
        "length",
        "context_length",
        "content_filter",
        "guardrail",
        "unknown_terminal",
    }:
        raise ValueError("response finish reason is invalid")

    message = choice["message"]
    if (
        not isinstance(message, dict)
        or set(message) != {"role", "content"}
        or message["role"] != "assistant"
        or (message["content"] is not None and not isinstance(message["content"], str))
    ):
        raise ValueError("response message control surface is invalid")

    usage = document["usage"]
    if not isinstance(usage, dict) or set(usage) != {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
    }:
        raise ValueError("response usage control surface is invalid")
    prompt_tokens = _wire_int(usage["prompt_tokens"])
    completion_tokens = _wire_int(usage["completion_tokens"])
    total_tokens = _wire_int(usage["total_tokens"])
    if total_tokens != prompt_tokens + completion_tokens:
        raise ValueError("response usage is inconsistent")

    return json.dumps(
        {
            "id": document["id"],
            "choices": [
                {
                    "finish_reason": finish_reason,
                    "message": {
                        "role": "assistant",
                        "content": message["content"],
                        "refusal": None,
                    },
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
            },
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


@dataclass(slots=True, repr=False)
class _LocalHttpChannel:
    _socket: socket.socket
    _peer_ip: str
    _closed: bool = False

    @property
    def peer_ip(self) -> str:
        return self._peer_ip

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        with suppress(OSError):
            self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()

    def __repr__(self) -> str:
        return "LocalHttpChannel(<redacted>)"


class OpenAICompatibleLocalHttpConnector:
    """A local-only, single-request connector for ``AuthorizedProviderHarness``.

    The profile is retained solely as immutable endpoint/model configuration.
    Caller-supplied connect arguments are checked against it so a connector
    cannot be reused to reach another local service.
    """

    __slots__ = (
        "_cancelled",
        "_endpoint_path",
        "_port",
        "_profile",
        "_seed",
        "_server_ip",
        "_socket_address",
        "_socket_family",
        "_temperature",
    )

    def __init__(
        self,
        *,
        profile: ProviderProfile,
        cancelled: CancellationProbe | None = None,
        temperature: float | None = None,
        seed: int | None = None,
    ) -> None:
        if temperature is not None and (
            isinstance(temperature, bool)
            or not isinstance(temperature, (int, float))
            or not 0.0 <= float(temperature) <= 2.0
        ):
            raise ValueError("LOCAL_CONNECTOR_TEMPERATURE_REJECTED")
        if seed is not None and (
            isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= 2_147_483_647
        ):
            raise ValueError("LOCAL_CONNECTOR_SEED_REJECTED")
        parsed = urlsplit(profile.endpoint.base_url)
        if (
            profile.provider_kind is not ProviderKind.OPENAI_COMPATIBLE_LOCAL
            or profile.api_dialect is not ApiDialect.OPENAI_COMPATIBLE
            or profile.execution_boundary.value != "local_runner"
            or not profile.endpoint.local_plaintext_exception
            or parsed.scheme != "http"
            or parsed.hostname != profile.endpoint.authority
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("LOCAL_CONNECTOR_PROFILE_REJECTED")
        try:
            configured_ip = ipaddress.ip_address(profile.endpoint.authority)
        except ValueError:
            raise ValueError("LOCAL_CONNECTOR_LITERAL_REQUIRED") from None
        if not configured_ip.is_loopback:
            raise ValueError("LOCAL_CONNECTOR_SCOPE_REJECTED")
        port = parsed.port or 80
        if port not in profile.endpoint.allowed_ports:
            raise ValueError("LOCAL_CONNECTOR_PORT_REJECTED")
        base_path = parsed.path.rstrip("/")
        self._endpoint_path = f"{base_path}/chat/completions" if base_path else "/chat/completions"
        self._port = port
        self._profile = profile
        self._temperature = None if temperature is None else float(temperature)
        self._seed = seed
        self._server_ip = configured_ip.compressed
        if configured_ip.version == 4:
            self._socket_family = socket.AF_INET
            self._socket_address: tuple[str, int] | tuple[str, int, int, int] = (
                self._server_ip,
                self._port,
            )
        else:
            self._socket_family = socket.AF_INET6
            self._socket_address = (self._server_ip, self._port, 0, 0)
        self._cancelled = cancelled

    def __repr__(self) -> str:
        return "OpenAICompatibleLocalHttpConnector(<redacted>)"

    def _is_cancelled(self) -> bool:
        try:
            return self._cancelled is not None and self._cancelled()
        except Exception:
            return True

    def _valid_connect_arguments(
        self, *, ip_address: str, port: int, server_name: str, timeout_ms: int
    ) -> bool:
        if (
            not isinstance(ip_address, str)
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not isinstance(server_name, str)
            or not isinstance(timeout_ms, int)
            or isinstance(timeout_ms, bool)
            or timeout_ms < 1
            or timeout_ms > self._profile.budgets.timeout_seconds * 1000
            or port != self._port
            or server_name != self._profile.endpoint.authority
        ):
            return False
        try:
            return ipaddress.ip_address(ip_address).compressed == self._server_ip
        except ValueError:
            return False

    def connect(
        self,
        *,
        ip_address: str,
        port: int,
        server_name: str,
        timeout_ms: int,
    ) -> ConnectedChannel:
        if self._is_cancelled() or not self._valid_connect_arguments(
            ip_address=ip_address,
            port=port,
            server_name=server_name,
            timeout_ms=timeout_ms,
        ):
            raise ValueError("LOCAL_CONNECTOR_CONNECT_REJECTED")
        try:
            connection = socket.socket(self._socket_family, socket.SOCK_STREAM)
        except OSError:
            raise ValueError("LOCAL_CONNECTOR_CONNECT_FAILED") from None
        try:
            connection.settimeout(timeout_ms / 1000)
            connection.connect(self._socket_address)
        except OSError:
            with suppress(OSError):
                connection.close()
            raise ValueError("LOCAL_CONNECTOR_CONNECT_FAILED") from None
        try:
            peer = ipaddress.ip_address(connection.getpeername()[0]).compressed
            if peer != self._server_ip or self._is_cancelled():
                raise ValueError("LOCAL_CONNECTOR_PEER_REJECTED")
            return _LocalHttpChannel(connection, peer)
        except Exception:
            connection.close()
            raise

    def _attempt(
        self,
        *,
        started: float,
        binding: ProviderAttemptBinding,
        http_status: int | None = None,
        response_bytes: bytes | None = None,
        transport_failure: TransportFailure | None = None,
        redirected: bool = False,
    ) -> ProviderAttempt:
        elapsed_ms = min(max(0, int((time.monotonic() - started) * 1000)), 9_007_199_254_740_991)
        return ProviderAttempt(
            dialect=ApiDialect.OPENAI_COMPATIBLE,
            http_status=http_status,
            response_bytes=response_bytes,
            transport_failure=transport_failure,
            stream_state=ProviderStreamState.COMPLETE,
            binding=binding,
            elapsed_ms=elapsed_ms,
            redirected=redirected,
        )

    @staticmethod
    def _content_length(headers: bytes) -> int | None:
        try:
            lines = headers.decode("ascii", "strict").split("\r\n")
        except UnicodeDecodeError:
            return None
        values: list[str] = []
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                return None
            name, value = line.split(":", 1)
            if name.lower() == "content-length":
                values.append(value.strip())
            if name.lower() == "transfer-encoding" and value.strip().lower() != "identity":
                return None
        if len(values) != 1 or not values[0].isdigit():
            return None
        length = int(values[0])
        return length if length <= _MAX_RESPONSE_BYTES else None

    def _read_response(
        self,
        channel: _LocalHttpChannel,
        *,
        deadline: float,
    ) -> tuple[int | None, bytes | None, TransportFailure | None, bool]:
        received = bytearray()
        while b"\r\n\r\n" not in received:
            if self._is_cancelled():
                return None, None, TransportFailure.CANCELLED, False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, None, TransportFailure.TIMEOUT, False
            channel._socket.settimeout(min(remaining, _CANCEL_POLL_SECONDS))
            try:
                chunk = channel._socket.recv(4096)
            except TimeoutError:
                continue
            except OSError:
                return None, None, TransportFailure.PROVIDER_ERROR, False
            if not chunk:
                return None, None, TransportFailure.PROVIDER_ERROR, False
            received.extend(chunk)
            if len(received) > _MAX_HEADER_BYTES:
                return None, None, TransportFailure.PROVIDER_ERROR, False

        raw_headers, body = bytes(received).split(b"\r\n\r\n", 1)
        try:
            status_parts = raw_headers.decode("ascii", "strict").split("\r\n", 1)[0].split()
            if len(status_parts) != 3 or not status_parts[0].startswith("HTTP/"):
                raise ValueError
            status = int(status_parts[1])
            if not 100 <= status <= 599:
                raise ValueError
        except (UnicodeDecodeError, ValueError):
            return None, None, TransportFailure.PROVIDER_ERROR, False
        content_length = self._content_length(raw_headers)
        if content_length is None:
            return status, None, TransportFailure.PROVIDER_ERROR, 300 <= status < 400
        while len(body) < content_length:
            if self._is_cancelled():
                return None, None, TransportFailure.CANCELLED, False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, None, TransportFailure.TIMEOUT, False
            channel._socket.settimeout(min(remaining, _CANCEL_POLL_SECONDS))
            try:
                chunk = channel._socket.recv(min(4096, content_length - len(body)))
            except TimeoutError:
                continue
            except OSError:
                return None, None, TransportFailure.PROVIDER_ERROR, False
            if not chunk:
                return None, None, TransportFailure.PROVIDER_ERROR, False
            body += chunk
        return status, body, None, 300 <= status < 400

    def send(
        self,
        channel: ConnectedChannel,
        *,
        credential: str | None,
        payload: bytes,
        model_id: str,
        timeout_ms: int,
        binding: ProviderAttemptBinding,
    ) -> ProviderAttempt:
        started = time.monotonic()
        if (
            not isinstance(channel, _LocalHttpChannel)
            or channel._closed
            or credential is not None
            or not isinstance(payload, bytes)
            or not payload
            or len(payload) > _MAX_RESPONSE_BYTES
            or model_id != self._profile.model_id
            or not isinstance(timeout_ms, int)
            or isinstance(timeout_ms, bool)
            or timeout_ms < 1
            or timeout_ms > self._profile.budgets.timeout_seconds * 1000
            or not isinstance(binding, ProviderAttemptBinding)
        ):
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.PROVIDER_ERROR,
            )
        if self._is_cancelled():
            channel.close()
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.CANCELLED,
            )
        try:
            prompt = payload.decode("utf-8", "strict")
            request_payload: dict[str, object] = {
                "model": model_id,
                "messages": [{"role": "user", "content": prompt}],
                "response_format": {"type": "json_object"},
            }
            if self._temperature is not None:
                request_payload["temperature"] = self._temperature
            if self._seed is not None:
                request_payload["seed"] = self._seed
            request_body = json.dumps(
                request_payload,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("ascii")
            if len(request_body) > _MAX_RESPONSE_BYTES:
                raise ValueError
            request = (
                f"POST {self._endpoint_path} HTTP/1.1\r\n"
                f"Host: {self._profile.endpoint.authority}:{self._port}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(request_body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii") + request_body
        except (UnicodeDecodeError, ValueError):
            channel.close()
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.PROVIDER_ERROR,
            )
        deadline = started + timeout_ms / 1000
        try:
            if self._is_cancelled():
                return self._attempt(
                    started=started,
                    binding=binding,
                    transport_failure=TransportFailure.CANCELLED,
                )
            channel._socket.settimeout(max(0.001, deadline - time.monotonic()))
            channel._socket.sendall(request)
            status, body, failure, redirected = self._read_response(channel, deadline=deadline)
            if failure is None and status is not None and 200 <= status < 300 and body is not None:
                try:
                    body = _canonicalize_ollama_envelope(
                        body,
                        expected_model_id=self._profile.model_id,
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
                    body = None
                    failure = TransportFailure.PROVIDER_ERROR
            return self._attempt(
                started=started,
                binding=binding,
                http_status=status,
                response_bytes=body,
                transport_failure=failure,
                redirected=redirected,
            )
        except TimeoutError:
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.TIMEOUT,
            )
        except OSError:
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.PROVIDER_ERROR,
            )
        finally:
            channel.close()


__all__ = ["CancellationProbe", "OpenAICompatibleLocalHttpConnector"]
