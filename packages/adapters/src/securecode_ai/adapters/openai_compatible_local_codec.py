"""Bounded direct HTTP transport for an approved local OpenAI-compatible profile.

The connector deliberately receives only the endpoint proof supplied by the
existing provider harness.  It does not resolve names, consult proxy
configuration, follow redirects, or construct an authorization chain.
"""

from __future__ import annotations

import json
from typing import Final, Protocol

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
        choices = document["choices"]
        usage = document["usage"]
        if (
            not isinstance(document["id"], str)
            or not isinstance(choices, list)
            or len(choices) != 1
            or not isinstance(choices[0], dict)
            or set(choices[0]) != {"finish_reason", "message"}
            or choices[0]["finish_reason"] not in {"stop", "length"}
            or not isinstance(choices[0]["message"], dict)
            or set(choices[0]["message"]) != {"role", "content"}
            or choices[0]["message"]["role"] != "assistant"
            or (
                choices[0]["message"]["content"] is not None
                and not isinstance(choices[0]["message"]["content"], str)
            )
            or not isinstance(usage, dict)
            or set(usage) != {"prompt_tokens", "completion_tokens"}
        ):
            return response
        prompt_tokens = _wire_int(usage["prompt_tokens"])
        completion_tokens = _wire_int(usage["completion_tokens"])
        return json.dumps(
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
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                },
            },
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
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
    if (
        not isinstance(usage, dict)
        or not {
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
        }.issubset(usage)
        or set(usage)
        - {
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "prompt_tokens_details",
        }
    ):
        raise ValueError("response usage control surface is invalid")
    prompt_tokens = _wire_int(usage["prompt_tokens"])
    completion_tokens = _wire_int(usage["completion_tokens"])
    total_tokens = _wire_int(usage["total_tokens"])
    if total_tokens != prompt_tokens + completion_tokens:
        raise ValueError("response usage is inconsistent")
    if "prompt_tokens_details" in usage:
        details = usage["prompt_tokens_details"]
        if (
            not isinstance(details, dict)
            or set(details) != {"cached_tokens"}
            or _wire_int(details["cached_tokens"]) > prompt_tokens
        ):
            raise ValueError("response prompt token details are invalid")

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
