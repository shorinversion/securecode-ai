"""Pinned HTTPS transport for approved remote OpenAI-compatible providers.

The connector opens a TLS socket only to an address authorized by the model
boundary.  It has no proxy support, performs no DNS lookup, and treats every
redirect, oversized response or unexpected envelope as a provider failure.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from contextlib import suppress
from dataclasses import dataclass
from email.message import Message
from typing import Final
from urllib.parse import urlsplit

from securecode_ai.core import ApiDialect, ProviderKind, ProviderProfile

from .model import (
    ConnectedChannel,
    ProviderAttempt,
    ProviderAttemptBinding,
    ProviderStreamState,
    TransportFailure,
)
from .native_repository_tools import NATIVE_REPOSITORY_TOOLS_JSON, parse_native_tool_calls
from .openai_compatible_local_codec import (
    _MAX_RESPONSE_BYTES,
    _closed_json_object,
    _reject_json_constant,
)
from .remote_provider_budget import (
    RemoteProviderBudgetError,
    RemoteProviderBudgetPort,
    RemoteProviderCallContext,
    RemoteProviderCostReceipt,
    RemoteProviderSpendLease,
    RemoteProviderSpendRequest,
    RemoteProviderSpendUsage,
)

_MAX_RESPONSE_HEADER_BYTES = 16 * 1024
_MAX_RESPONSE_READ_CHUNK_BYTES = 64 * 1024
_MAX_SLOT_TIMEOUT_MS = 86_400_000
_POST_SEND_SLOT_GRACE_MS = 5_000
_HEAD_SHA = re.compile(r"[0-9a-f]{40}\Z")


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

    __slots__ = (
        "_endpoint_path",
        "_max_output_tokens",
        "_port",
        "_profile",
        "_reasoning_effort",
        "_spend_budget",
    )

    def __init__(
        self,
        *,
        profile: ProviderProfile,
        max_output_tokens: int | None = None,
        spend_budget: RemoteProviderBudgetPort | None = None,
        reasoning_effort: str = "none",
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
            or type(profile.protocol_framing_token_upper_bound) is not int
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
        if reasoning_effort not in REASONING_EFFORTS:
            raise ValueError("REMOTE_CONNECTOR_REASONING_REJECTED")
        self._endpoint_path = (parsed.path.rstrip("/") + "/chat/completions") or "/chat/completions"
        self._max_output_tokens = (
            profile.capabilities.max_output_tokens
            if max_output_tokens is None
            else max_output_tokens
        )
        self._port = port
        self._profile = profile
        self._spend_budget = spend_budget
        self._reasoning_effort = reasoning_effort

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
        deadline = time.monotonic() + timeout_ms / 1000
        try:
            raw = socket.create_connection((ip_address, port), timeout=_remaining_timeout(deadline))
            raw.settimeout(_remaining_timeout(deadline))
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
        cost_receipt: RemoteProviderCostReceipt | None = None,
        cost_receipt_required: bool = False,
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
            cost_receipt=cost_receipt,
            cost_receipt_required=cost_receipt_required,
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
            or (
                isinstance(binding, ProviderAttemptBinding)
                and isinstance(call_budget, RemoteProviderCallContext)
                and binding.attempt != call_budget.attempt
            )
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
        lease_transition_started = False
        cost_receipt: RemoteProviderCostReceipt | None = None
        try:
            prompt = payload.decode("utf-8", "strict")
            framing_bound = self._profile.protocol_framing_token_upper_bound
            if type(framing_bound) is not int:
                return self._attempt(
                    started=started,
                    binding=binding,
                    transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                )
            # SealedRepositoryView defines UTF-8 byte count as a conservative
            # token ceiling.  The profile's framing bound covers the fixed
            # JSON/protocol wrapper.  Never infer a tokenizer ratio here.
            input_token_upper_bound = len(prompt.encode("utf-8")) + framing_bound
            if (
                type(call_budget.input_token_upper_bound) is not int
                or call_budget.input_token_upper_bound != input_token_upper_bound
                or input_token_upper_bound > call_budget.max_input_tokens
                or input_token_upper_bound > self._profile.capabilities.max_context_tokens
                or input_token_upper_bound + call_budget.max_output_tokens
                > self._profile.budgets.max_total_tokens
            ):
                return self._attempt(
                    started=started,
                    binding=binding,
                    transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                )
            native_frame = _parse_native_frame(prompt, tenant_id=call_budget.tenant_id)
            native = native_frame is not None
            body = json.dumps(
                _request_payload(
                    model_id=model_id,
                    prompt=prompt,
                    native_frame=native_frame,
                    max_tokens=min(self._max_output_tokens, call_budget.max_output_tokens),
                    reasoning_effort=self._reasoning_effort,
                ),
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
                slot_timeout_ms = max(
                    1,
                    min(
                        _MAX_SLOT_TIMEOUT_MS,
                        timeout_ms
                        + _POST_SEND_SLOT_GRACE_MS
                        - int((time.monotonic() - started) * 1000),
                    ),
                )
                lease = budget.reserve(
                    RemoteProviderSpendRequest(
                        run_id=call_budget.run_id,
                        tenant_id=call_budget.tenant_id,
                        model_id=model_id,
                        request_id=call_budget.request_id,
                        attempt=call_budget.attempt,
                        max_input_tokens=call_budget.max_input_tokens,
                        max_output_tokens=call_budget.max_output_tokens,
                        slot_timeout_ms=slot_timeout_ms,
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
                or lease.run_id != call_budget.run_id
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
            deadline = started + timeout_ms / 1000
            _set_socket_deadline(channel._socket, deadline)
            send_attempted = True
            channel._socket.sendall(request)
            response = http.client.HTTPResponse(channel._socket)
            _set_socket_deadline(channel._socket, deadline)
            response.begin()
            header_bytes = sum(len(name) + len(value) + 4 for name, value in response.getheaders())
            if header_bytes > _MAX_RESPONSE_HEADER_BYTES:
                raise ValueError
            status = response.status
            if not 200 <= status < 300:
                lease_transition_started = True
                cost_receipt = _validated_receipt(
                    budget.charge_maximum(lease), lease, maximum_charged=True
                )
                lease = None
                return self._attempt(
                    started=started,
                    binding=binding,
                    http_status=status,
                    response_bytes=b"",
                    redirected=300 <= status < 400,
                    cost_receipt=cost_receipt,
                    cost_receipt_required=True,
                )
            content_type = response.getheader("Content-Type")
            if content_type is None:
                raise ValueError
            media_type = Message()
            media_type["content-type"] = content_type
            if (
                media_type.get_content_type().lower() != "application/json"
                or media_type.get_content_charset() not in (None, "utf-8")
            ):
                raise ValueError
            if response.getheader("Content-Encoding") not in (None, "identity"):
                raise ValueError
            raw = _read_response_body(response, channel._socket, deadline)
            canonical, input_tokens, output_tokens = _canonicalize_remote_envelope_with_usage(
                raw,
                expected_model_id=model_id,
                native=native,
                expected_head_sha=None if native_frame is None else native_frame[2],
            )
            lease_transition_started = True
            cost_receipt = _validated_receipt(
                budget.settle(
                    lease,
                    RemoteProviderSpendUsage(
                        input_tokens=input_tokens, output_tokens=output_tokens
                    ),
                ),
                lease,
                maximum_charged=False,
            )
            lease = None
            return self._attempt(
                started=started,
                binding=binding,
                http_status=status,
                response_bytes=canonical,
                cost_receipt=cost_receipt,
                cost_receipt_required=True,
            )
        except TimeoutError:
            if lease is not None and send_attempted:
                receipt = _try_charge_maximum(budget, lease)
                if receipt is None:
                    return self._attempt(
                        started=started,
                        binding=binding,
                        transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                        cost_receipt_required=True,
                    )
                lease_transition_started = True
                cost_receipt = receipt
                lease = None
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.TIMEOUT,
                cost_receipt=cost_receipt,
                cost_receipt_required=True,
            )
        except RemoteProviderBudgetError as error:
            if error.cost_receipt is not None:
                if lease is None or not send_attempted or not lease_transition_started:
                    return self._attempt(
                        started=started,
                        binding=binding,
                        transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                        cost_receipt_required=True,
                    )
                try:
                    cost_receipt = _validated_receipt(
                        error.cost_receipt, lease, maximum_charged=False
                    )
                except Exception:
                    return self._attempt(
                        started=started,
                        binding=binding,
                        transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                        cost_receipt_required=True,
                    )
                lease = None
            elif lease is not None and send_attempted:
                receipt = _try_charge_maximum(budget, lease)
                if receipt is not None:
                    lease_transition_started = True
                    cost_receipt = receipt
                    lease = None
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                cost_receipt=cost_receipt,
                cost_receipt_required=True,
            )
        except Exception:
            if lease is not None and send_attempted:
                receipt = _try_charge_maximum(budget, lease)
                if receipt is None:
                    return self._attempt(
                        started=started,
                        binding=binding,
                        transport_failure=TransportFailure.BUDGET_EXHAUSTED,
                        cost_receipt=cost_receipt,
                        cost_receipt_required=True,
                    )
                lease_transition_started = True
                cost_receipt = receipt
                lease = None
            return self._attempt(
                started=started,
                binding=binding,
                transport_failure=TransportFailure.PROVIDER_ERROR,
                cost_receipt=cost_receipt,
                cost_receipt_required=True,
            )
        finally:
            if lease is not None and not send_attempted:
                with suppress(Exception):
                    budget.release(lease)
            channel.close()


# DeepSeek reasoning effort levels; "none" disables thinking mode.
REASONING_EFFORTS: Final = frozenset({"none", "low", "high", "max"})


def _request_payload(
    *,
    model_id: str,
    prompt: str,
    native_frame: tuple[dict[str, object], list[object], str] | None,
    max_tokens: int,
    reasoning_effort: str = "none",
) -> dict[str, object]:
    payload: dict[str, object] = {"model": model_id, "max_tokens": max_tokens}
    if reasoning_effort == "none":
        payload.update(temperature=0, thinking={"type": "disabled"}, reasoning_effort="none")
    else:
        # Thinking mode ignores sampling parameters, so none are sent.
        payload.update(thinking={"type": "enabled"}, reasoning_effort=reasoning_effort)
    if native_frame is None:
        payload["messages"] = [{"role": "user", "content": prompt}]
        payload["response_format"] = {"type": "json_object"}
        return payload
    initial_context, history, _ = native_frame
    payload["messages"] = [
        {
            "role": "user",
            "content": json.dumps(
                initial_context,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ),
        },
        *history,
    ]
    payload["tools"] = json.loads(NATIVE_REPOSITORY_TOOLS_JSON)
    # The first native turn must be allowed to emit a tool call. Once the
    # transcript contains tool results, JSON mode is restored for the final
    # structured candidate response.
    if history:
        payload["response_format"] = {"type": "json_object"}
    return payload


def _parse_native_frame(
    prompt: str, *, tenant_id: str
) -> tuple[dict[str, object], list[object], str] | None:
    """Recognize and validate the internal native-discovery frame.

    Ordinary product contexts remain ordinary user messages. A frame is
    translated only when its closed top-level shape is exact; all transcript
    messages and tool arguments are checked before any remote bytes are sent.
    """

    if (
        not prompt.startswith("{")
        or not prompt.endswith("}")
        or '"initial_context"' not in prompt
        or '"tool_history"' not in prompt
    ):
        return None
    try:
        document = json.loads(
            prompt,
            object_pairs_hook=_closed_json_object,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValueError("native frame is invalid") from None
    if not isinstance(document, dict):
        return None
    native_keys = {"initial_context", "tool_history"}
    if not native_keys.intersection(document):
        return None
    if set(document) != native_keys:
        raise ValueError("native frame shape is invalid")
    initial_context = document["initial_context"]
    history = document["tool_history"]
    if (
        not isinstance(initial_context, dict)
        or set(initial_context)
        != {"trusted_controls", "untrusted_evidence", "untrusted_source_locations"}
        or not isinstance(history, list)
        or len(history) > 32
    ):
        raise ValueError("native frame is invalid")
    controls = initial_context["trusted_controls"]
    if (
        not isinstance(controls, dict)
        or set(controls)
        != {"role", "instructions", "output_schema", "allowed_rule_ids", "source_revision"}
        or controls["role"] != "discovery"
    ):
        raise ValueError("native frame controls are invalid")
    revision = controls["source_revision"]
    if (
        not isinstance(revision, dict)
        or set(revision) != {"tenant_id", "head_sha"}
        or revision["tenant_id"] != tenant_id
        or not isinstance(revision["head_sha"], str)
        or _HEAD_SHA.fullmatch(revision["head_sha"]) is None
    ):
        raise ValueError("native frame revision is invalid")
    _validate_native_history(history, head_sha=revision["head_sha"])
    return initial_context, history, revision["head_sha"]


def _validate_native_history(history: list[object], *, head_sha: str) -> None:
    cursor = 0
    seen_ids: set[str] = set()
    while cursor < len(history):
        assistant = history[cursor]
        if (
            not isinstance(assistant, dict)
            or set(assistant) != {"role", "content", "tool_calls"}
            or assistant["role"] != "assistant"
            or assistant["content"] is not None
        ):
            raise ValueError("native transcript is invalid")
        calls = parse_native_tool_calls(assistant["tool_calls"], head_sha=head_sha, max_calls=4)
        for call in calls:
            if call.call_id in seen_ids:
                raise ValueError("native transcript is invalid")
            seen_ids.add(call.call_id)
        cursor += 1
        for call in calls:
            if cursor >= len(history):
                raise ValueError("native transcript is invalid")
            result = history[cursor]
            if (
                not isinstance(result, dict)
                or set(result) != {"role", "tool_call_id", "content"}
                or result["role"] != "tool"
                or result["tool_call_id"] != call.call_id
                or not isinstance(result["content"], str)
                or not 1 <= len(result["content"].encode("utf-8")) <= _MAX_RESPONSE_BYTES
            ):
                raise ValueError("native transcript is invalid")
            cursor += 1


def _canonicalize_remote_envelope(response: bytes, *, expected_model_id: str) -> bytes:
    """Accept the public OpenAI-compatible subset and strip provider metadata."""
    canonical, _, _ = _canonicalize_remote_envelope_with_usage(
        response, expected_model_id=expected_model_id
    )
    return canonical


# Accounting detail fields real providers add to ``usage`` (DeepSeek reports cache hits and
# misses).  They are validated and dropped: billing uses prompt and completion tokens only.
_USAGE_DETAIL_KEYS: Final = frozenset(
    {
        "prompt_tokens_details",
        "completion_tokens_details",
        "prompt_cache_hit_tokens",
        "prompt_cache_miss_tokens",
    }
)


def _valid_usage_details(usage: dict[str, object]) -> bool:
    for key in ("prompt_tokens_details", "completion_tokens_details"):
        details = usage.get(key)
        if details is not None and (
            not isinstance(details, dict)
            or not all(
                isinstance(name, str) and type(value) is int and value >= 0
                for name, value in details.items()
            )
        ):
            return False
    cache = [usage.get(key) for key in ("prompt_cache_hit_tokens", "prompt_cache_miss_tokens")]
    if any(value is not None for value in cache):
        if any(type(value) is not int or value < 0 for value in cache):
            return False
        if cache[0] + cache[1] != usage.get("prompt_tokens"):  # type: ignore[operator]
            return False
    return True


def _canonicalize_remote_envelope_with_usage(
    response: bytes,
    *,
    expected_model_id: str,
    native: bool = False,
    expected_head_sha: str | None = None,
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
        or not document["id"]
        or not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(choices[0], dict)
        or set(choices[0]) - {"index", "message", "finish_reason", "logprobs"}
        or ("index" in choices[0] and choices[0]["index"] != 0)
        or choices[0].get("logprobs") is not None
        or not isinstance(choices[0].get("message"), dict)
        or choices[0]["message"].get("role") != "assistant"
        or not isinstance(usage, dict)
        or set(usage) - {"prompt_tokens", "completion_tokens", "total_tokens"} - _USAGE_DETAIL_KEYS
        or not _valid_usage_details(usage)
        or type(usage.get("prompt_tokens")) is not int
        or type(usage.get("completion_tokens")) is not int
        or not 0 <= usage["prompt_tokens"] <= 1_000_000_000
        or not 0 <= usage["completion_tokens"] <= 1_000_000_000
        or (
            "total_tokens" in usage
            and (
                type(usage["total_tokens"]) is not int
                or usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]
            )
        )
    ):
        raise ValueError("remote response envelope is invalid")
    choice = choices[0]
    message = choice["message"]
    tool_calls: list[object] | None = None
    if native and "tool_calls" in message:
        if (
            set(message)
            not in (
                {"role", "content", "tool_calls"},
                {"role", "content", "tool_calls", "refusal"},
                {"role", "content", "tool_calls", "reasoning_content"},
                {"role", "content", "tool_calls", "refusal", "reasoning_content"},
            )
            or message["content"] not in (None, "")
            or ("refusal" in message and message["refusal"] is not None)
            or choice.get("finish_reason") != "tool_calls"
            or expected_head_sha is None
            or _HEAD_SHA.fullmatch(expected_head_sha) is None
            or not isinstance(message["tool_calls"], list)
        ):
            raise ValueError("remote native response envelope is invalid")
        tool_calls = message["tool_calls"]
        try:
            parse_native_tool_calls(tool_calls, head_sha=expected_head_sha, max_calls=4)
        except (TypeError, ValueError):
            raise ValueError("remote native response tool calls are invalid") from None
    else:
        if (
            set(message) - {"role", "content", "refusal", "reasoning_content"}
            or not isinstance(message.get("reasoning_content", ""), (str, type(None)))
            or not isinstance(message.get("content"), str)
            or message.get("refusal") is not None
            or choice.get("finish_reason") not in {"stop", "length", "content_filter"}
        ):
            raise ValueError("remote response envelope is invalid")
    canonical_message: dict[str, object]
    if tool_calls is None:
        canonical_message = {
            "role": "assistant",
            "content": message["content"],
            "refusal": None,
        }
    else:
        canonical_message = {
            "role": "assistant",
            "content": None,
            "refusal": None,
            "tool_calls": tool_calls,
        }
    canonical = json.dumps(
        {
            "id": document["id"],
            "choices": [
                {
                    "finish_reason": choices[0]["finish_reason"],
                    "message": canonical_message,
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


def _remaining_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining


def _set_socket_deadline(sock: socket.socket, deadline: float) -> None:
    sock.settimeout(_remaining_timeout(deadline))


def _read_response_body(
    response: http.client.HTTPResponse, sock: socket.socket, deadline: float
) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total <= _MAX_RESPONSE_BYTES:
        _set_socket_deadline(sock, deadline)
        chunk = response.read1(min(_MAX_RESPONSE_READ_CHUNK_BYTES, _MAX_RESPONSE_BYTES + 1 - total))
        if time.monotonic() >= deadline:
            raise TimeoutError
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > _MAX_RESPONSE_BYTES:
            raise ValueError
    return b"".join(chunks)


def _validated_receipt(
    value: object,
    lease: RemoteProviderSpendLease,
    *,
    maximum_charged: bool,
) -> RemoteProviderCostReceipt:
    if (
        type(value) is not RemoteProviderCostReceipt
        or value.run_id != lease.run_id
        or value.tenant_id != lease.tenant_id
        or value.model_id != lease.model_id
        or value.request_id != lease.request_id
        or value.attempt != lease.attempt
        or value.maximum_charged is not maximum_charged
    ):
        raise RemoteProviderBudgetError("INVALID_STATE")
    return value


def _try_charge_maximum(
    budget: RemoteProviderBudgetPort, lease: RemoteProviderSpendLease
) -> RemoteProviderCostReceipt | None:
    """Charge an admitted send after transport failure without losing the lease.

    Budget implementations commit the charge transaction before returning the
    receipt.  A malformed receipt or a transient budget error is retried once:
    implementations make maximum charging idempotent, so a committed charge
    can be read back without releasing the financial reservation or sending a
    second provider request.
    """
    for _ in range(2):
        try:
            return _validated_receipt(budget.charge_maximum(lease), lease, maximum_charged=True)
        except Exception:
            continue
    return None
