"""Pinned HTTPS transport for approved remote OpenAI-compatible providers.

The connector opens a TLS socket only to an address authorized by the model
boundary.  It has no proxy support, performs no DNS lookup, and treats every
redirect, oversized response or unexpected envelope as a provider failure.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import urlsplit

from securecode_ai.core import ApiDialect, ProviderKind, ProviderProfile

from .model import (
    ConnectedChannel,
    ProviderAttempt,
    ProviderAttemptBinding,
    ProviderStreamState,
    TransportFailure,
)
from .openai_compatible_local_codec import (
    _MAX_RESPONSE_BYTES,
    _closed_json_object,
    _reject_json_constant,
)
from .remote_provider_budget import (
    RemoteProviderBudgetError,
    RemoteProviderBudgetPort,
    RemoteProviderCallContext,
    RemoteProviderSpendLease,
    RemoteProviderSpendRequest,
    RemoteProviderSpendUsage,
)


@dataclass(slots=True)
class _RemoteHttpsChannel:
    _socket: ssl.SSLSocket
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
        return "RemoteHttpsChannel(<redacted>)"


class OpenAICompatibleRemoteHttpsConnector:
    """A single-request HTTPS connector for an approved remote profile."""

    __slots__ = ("_endpoint_path", "_max_output_tokens", "_port", "_profile", "_spend_budget")

    def __init__(
        self,
        *,
        profile: ProviderProfile,
        max_output_tokens: int | None = None,
        spend_budget: RemoteProviderBudgetPort | None = None,
    ) -> None:
        parsed = urlsplit(profile.endpoint.base_url)
        if (
            profile.provider_kind is not ProviderKind.OPENAI_COMPATIBLE_REMOTE
            or profile.api_dialect is not ApiDialect.OPENAI_COMPATIBLE
            or parsed.scheme != "https"
            or parsed.hostname != profile.endpoint.authority
            or parsed.query
            or parsed.fragment
            or profile.endpoint.local_plaintext_exception
        ):
            raise ValueError("REMOTE_CONNECTOR_PROFILE_REJECTED")
        port = parsed.port or 443
        if port not in profile.endpoint.allowed_ports:
            raise ValueError("REMOTE_CONNECTOR_PORT_REJECTED")
        if max_output_tokens is not None and (
            type(max_output_tokens) is not int
            or not 1 <= max_output_tokens <= profile.capabilities.max_output_tokens
        ):
            raise ValueError("REMOTE_CONNECTOR_OUTPUT_LIMIT_REJECTED")
        self._endpoint_path = (parsed.path.rstrip("/") + "/chat/completions") or "/chat/completions"
        self._max_output_tokens = (
            profile.capabilities.max_output_tokens
            if max_output_tokens is None
            else max_output_tokens
        )
        self._port = port
        self._profile = profile
        self._spend_budget = spend_budget

    def __repr__(self) -> str:
        return "OpenAICompatibleRemoteHttpsConnector(<redacted>)"

    def _valid_connect_arguments(
        self, *, ip_address: str, port: int, server_name: str, timeout_ms: int
    ) -> bool:
        if (
            not isinstance(ip_address, str)
            or type(port) is not int
            or not isinstance(server_name, str)
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= self._profile.budgets.timeout_seconds * 1000
            or port != self._port
            or server_name != self._profile.endpoint.authority
        ):
            return False
        try:
            return ipaddress.ip_address(ip_address).is_global
        except ValueError:
            return False

    def connect(
        self, *, ip_address: str, port: int, server_name: str, timeout_ms: int
    ) -> ConnectedChannel:
        if not self._valid_connect_arguments(
            ip_address=ip_address, port=port, server_name=server_name, timeout_ms=timeout_ms
        ):
            raise ValueError("REMOTE_CONNECTOR_CONNECT_REJECTED")
        raw: socket.socket | None = None
        try:
            raw = socket.create_connection((ip_address, port), timeout=timeout_ms / 1000)
            context = ssl.create_default_context()
            secured = context.wrap_socket(raw, server_hostname=server_name)
            peer = ipaddress.ip_address(secured.getpeername()[0]).compressed
            if peer != ipaddress.ip_address(ip_address).compressed:
                secured.close()
                raise ValueError("REMOTE_CONNECTOR_PEER_REJECTED")
            return _RemoteHttpsChannel(secured, peer)
        except Exception:
            if raw is not None:
                with suppress(OSError):
                    raw.close()
            raise ValueError("REMOTE_CONNECTOR_CONNECT_FAILED") from None

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
        return ProviderAttempt(
            dialect=ApiDialect.OPENAI_COMPATIBLE,
            http_status=http_status,
            response_bytes=response_bytes,
            transport_failure=transport_failure,
            stream_state=ProviderStreamState.COMPLETE,
            binding=binding,
            elapsed_ms=min(max(0, int((time.monotonic() - started) * 1000)), 9_007_199_254_740_991),
            redirected=redirected,
        )

    def send(
        self,
        channel: ConnectedChannel,
        *,
        credential: str | None,
        payload: bytes,
        model_id: str,
        timeout_ms: int,
        binding: ProviderAttemptBinding,
        call_budget: RemoteProviderCallContext,
    ) -> ProviderAttempt:
        started = time.monotonic()
        if (
            not isinstance(channel, _RemoteHttpsChannel)
            or channel._closed
            or not isinstance(credential, str)
            or not credential
            or not all(0x21 <= ord(character) <= 0x7E for character in credential)
            or not isinstance(payload, bytes)
            or not payload
            or len(payload) > _MAX_RESPONSE_BYTES
            or model_id != self._profile.model_id
            or type(timeout_ms) is not int
            or not 1 <= timeout_ms <= self._profile.budgets.timeout_seconds * 1000
            or not isinstance(binding, ProviderAttemptBinding)
            or type(call_budget) is not RemoteProviderCallContext
        ):
            return self._attempt(
                started=started, binding=binding, transport_failure=TransportFailure.PROVIDER_ERROR
            )
        budget = self._spend_budget
        if budget is None or not _valid_budget_port(budget):
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.BUDGET_EXHAUSTED,
            )
        lease: RemoteProviderSpendLease | None = None
        send_attempted = False
        try:
            prompt = payload.decode("utf-8", "strict")
            body = json.dumps(
                {
                    "model": model_id,
                    "messages": [{"role": "user", "content": prompt}],
                    "response_format": {"type": "json_object"},
                    "max_tokens": min(self._max_output_tokens, call_budget.max_output_tokens),
                    "temperature": 0,
                    "thinking": {"type": "disabled"},
                    "reasoning_effort": "none",
                },
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("ascii")
            if len(body) > _MAX_RESPONSE_BYTES:
                raise ValueError
            request = (
                f"POST {self._endpoint_path} HTTP/1.1\r\n"
                f"Host: {self._profile.endpoint.authority}:{self._port}\r\n"
                "Content-Type: application/json\r\n"
                f"Authorization: Bearer {credential}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii") + body
            try:
                lease = budget.reserve(
                    RemoteProviderSpendRequest(
                        tenant_id=call_budget.tenant_id,
                        model_id=model_id,
                        request_id=call_budget.request_id,
                        attempt=call_budget.attempt,
                        max_input_tokens=call_budget.max_input_tokens,
                        max_output_tokens=call_budget.max_output_tokens,
                    )
                )
            except Exception:
                return self._attempt(
                    started=started,
                    binding=binding,
                    transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                )
            if (
                type(lease) is not RemoteProviderSpendLease
                or lease.tenant_id != call_budget.tenant_id
                or lease.model_id != model_id
                or lease.request_id != call_budget.request_id
                or lease.attempt != call_budget.attempt
                or lease.max_input_tokens != call_budget.max_input_tokens
                or lease.max_output_tokens != call_budget.max_output_tokens
            ):
                if type(lease) is RemoteProviderSpendLease:
                    with suppress(Exception):
                        budget.release(lease)
                lease = None
                return self._attempt(
                    started=started,
                    binding=binding,
                    transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                )
            channel._socket.settimeout(timeout_ms / 1000)
            send_attempted = True
            channel._socket.sendall(request)
            response = http.client.HTTPResponse(channel._socket)
            response.begin()
            if response.getheader("Content-Encoding") not in (None, "identity"):
                raise ValueError
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise ValueError
            status = response.status
            if not 200 <= status < 300:
                budget.charge_maximum(lease)
                lease = None
                return self._attempt(
                    started=started,
                    binding=binding,
                    http_status=status,
                    response_bytes=raw,
                    redirected=300 <= status < 400,
                )
            canonical, input_tokens, output_tokens = _canonicalize_remote_envelope_with_usage(
                raw, expected_model_id=model_id
            )
            budget.settle(
                lease,
                RemoteProviderSpendUsage(input_tokens=input_tokens, output_tokens=output_tokens),
            )
            lease = None
            return self._attempt(
                started=started,
                binding=binding,
                http_status=status,
                response_bytes=canonical,
            )
        except TimeoutError:
            if lease is not None and send_attempted:
                try:
                    budget.charge_maximum(lease)
                except Exception:
                    return self._attempt(
                        started=started,
                        binding=binding,
                        transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                    )
                lease = None
            return self._attempt(
                started=started, binding=binding, transport_failure=TransportFailure.TIMEOUT
            )
        except RemoteProviderBudgetError:
            if lease is not None and send_attempted:
                with suppress(Exception):
                    budget.charge_maximum(lease)
                lease = None
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.BUDGET_EXHAUSTED,
            )
        except Exception:
            if lease is not None and send_attempted:
                try:
                    budget.charge_maximum(lease)
                except Exception:
                    return self._attempt(
                        started=started,
                        binding=binding,
                        transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                    )
                lease = None
            return self._attempt(
                started=started, binding=binding, transport_failure=TransportFailure.PROVIDER_ERROR
            )
        finally:
            if lease is not None and not send_attempted:
                with suppress(Exception):
                    budget.release(lease)
            channel.close()


def _canonicalize_remote_envelope(response: bytes, *, expected_model_id: str) -> bytes:
    """Accept the public OpenAI-compatible subset and strip provider metadata."""
    canonical, _, _ = _canonicalize_remote_envelope_with_usage(
        response, expected_model_id=expected_model_id
    )
    return canonical


def _canonicalize_remote_envelope_with_usage(
    response: bytes, *, expected_model_id: str
) -> tuple[bytes, int, int]:
    """Return the bounded public envelope and validated provider usage."""
    document = json.loads(
        response, object_pairs_hook=_closed_json_object, parse_constant=_reject_json_constant
    )
    if not isinstance(document, dict) or document.get("model") != expected_model_id:
        raise ValueError("remote response metadata is invalid")
    choices = document.get("choices")
    usage = document.get("usage")
    if (
        not isinstance(document.get("id"), str)
        or not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(choices[0], dict)
        or not isinstance(choices[0].get("message"), dict)
        or choices[0]["message"].get("role") != "assistant"
        or not isinstance(choices[0]["message"].get("content"), str)
        or choices[0].get("finish_reason") not in {"stop", "length", "content_filter"}
        or not isinstance(usage, dict)
        or type(usage.get("prompt_tokens")) is not int
        or type(usage.get("completion_tokens")) is not int
        or not 0 <= usage["prompt_tokens"] <= 1_000_000_000
        or not 0 <= usage["completion_tokens"] <= 1_000_000_000
    ):
        raise ValueError("remote response envelope is invalid")
    canonical = json.dumps(
        {
            "id": document["id"],
            "choices": [
                {
                    "finish_reason": choices[0]["finish_reason"],
                    "message": {
                        "role": "assistant",
                        "content": choices[0]["message"]["content"],
                        "refusal": None,
                    },
                }
            ],
            "usage": {
                "prompt_tokens": usage["prompt_tokens"],
                "completion_tokens": usage["completion_tokens"],
            },
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return canonical, usage["prompt_tokens"], usage["completion_tokens"]


def _valid_budget_port(value: object) -> bool:
    try:
        return all(
            callable(getattr(value, name, None))
            for name in ("reserve", "settle", "charge_maximum", "release")
        )
    except Exception:
        return False
