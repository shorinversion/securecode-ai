"""Local provider boundary with actual policy refusal and bounded backend I/O.

Refusal belongs to this gateway provider, not to the underlying model. No
capability registry is promoted by starting this service or handling a request.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable

from securecode_ai.contracts import DataClass, SourceLocation

from .local_provider_gateway_transforms import (
    _canonicalize_native_reply,
    _failure,
    _validate_native_transcript,
)
from .local_provider_gateway_types import (
    _MAX_RESPONSE_BYTES,
    GatewayBackend,
    GatewayBudgetMode,
    GatewayNativeArgumentsShape,
    GatewayNativeEnvelopeShape,
    GatewayNormalizationObservation,
    GatewayPolicy,
    GatewayReply,
    GatewayResponseNormalization,
    _decode,
    _NativeEnvelopeRejection,
    _valid_id,
)
from .native_repository_tools import (
    NATIVE_REPOSITORY_TOOLS_JSON,
    NativeToolCallRejection,
)
from .openai_compatible_local_codec import _canonicalize_ollama_envelope
from .product_model import AUDITOR_WIRE_SCHEMA_JSON, MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON


def handle_gateway_request(
    body: bytes,
    *,
    policy: GatewayPolicy,
    backend: GatewayBackend,
    deadline: float | None = None,
    normalization_observer: Callable[[GatewayNormalizationObservation], None] | None = None,
) -> GatewayReply:
    """Refuse actual restricted audit requests without any backend dispatch."""
    if normalization_observer is not None and not callable(normalization_observer):
        raise ValueError("invalid gateway normalization observer")
    request_sha256 = hashlib.sha256(body).hexdigest()

    def observed(
        status: GatewayResponseNormalization,
        native_shape: GatewayNativeEnvelopeShape = GatewayNativeEnvelopeShape.NOT_APPLICABLE,
        native_arguments_shape: GatewayNativeArgumentsShape = GatewayNativeArgumentsShape.NOT_APPLICABLE,
        native_arguments_rejection: NativeToolCallRejection = NativeToolCallRejection.NOT_APPLICABLE,
    ) -> bool:
        if normalization_observer is None:
            return True
        try:
            normalization_observer(
                GatewayNormalizationObservation(
                    policy.content_sha256,
                    request_sha256,
                    status,
                    native_shape,
                    native_arguments_shape,
                    native_arguments_rejection,
                )
            )
        except Exception:
            return False
        return True

    request_deadline = min(
        time.monotonic() + policy.timeout_seconds,
        deadline if deadline is not None else math.inf,
    )
    try:
        if type(body) is not bytes or not body or len(body) > policy.max_request_bytes:
            return _failure(413)
        request = _decode(body)
        required = {"model", "messages", "response_format", "max_tokens"}
        if not required <= set(request) or set(request) - required - {
            "temperature",
            "seed",
            "tools",
        }:
            raise ValueError("invalid gateway request fields")
        if request["model"] != policy.model_id or request["response_format"] != {
            "type": "json_object"
        }:
            raise ValueError("invalid gateway model or format")
        tokens = request["max_tokens"]
        if type(tokens) is not int or not 1 <= tokens <= policy.max_output_tokens:
            raise ValueError("invalid gateway output budget")
        if "temperature" in request:
            temperature = request["temperature"]
            if (
                not isinstance(temperature, (int, float))
                or isinstance(temperature, bool)
                or not 0 <= temperature <= 2
                or not math.isfinite(temperature)
            ):
                raise ValueError("invalid gateway temperature")
        if "seed" in request and (
            type(request["seed"]) is not int or not 0 <= request["seed"] <= 2**32 - 1
        ):
            raise ValueError("invalid gateway seed")
        native_tools = "tools" in request
        if native_tools and request["tools"] != json.loads(NATIVE_REPOSITORY_TOOLS_JSON):
            raise ValueError("invalid native repository tool schemas")
        messages = request["messages"]
        if (
            not isinstance(messages, list)
            or not 1 <= len(messages) <= (33 if native_tools else 1)
            or not isinstance(messages[0], dict)
        ):
            raise ValueError("invalid gateway messages")
        message = messages[0]
        if (
            set(message) != {"role", "content"}
            or message["role"] != "user"
            or not isinstance(message["content"], str)
        ):
            raise ValueError("invalid gateway message")
        context = _decode(message["content"].encode())
        if set(context) != {"trusted_controls", "untrusted_evidence", "untrusted_source_locations"}:
            raise ValueError("invalid gateway audit context")
        controls = context["trusted_controls"]
        if not isinstance(controls, dict) or set(controls) != {
            "role",
            "instructions",
            "output_schema",
            "allowed_rule_ids",
            "source_revision",
        }:
            raise ValueError("invalid gateway controls")
        schemas = {
            "discovery": json.loads(MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON),
            "auditor": json.loads(AUDITOR_WIRE_SCHEMA_JSON),
        }
        role = controls["role"]
        if (
            not isinstance(role, str)
            or role not in schemas
            or controls["output_schema"] != schemas[role]
        ):
            raise ValueError("invalid gateway role schema")
        if (
            not isinstance(controls["instructions"], str)
            or not 1 <= len(controls["instructions"].encode()) <= 4096
        ):
            raise ValueError("invalid gateway instructions")
        rules = controls["allowed_rule_ids"]
        if (
            not isinstance(rules, list)
            or len(rules) > 256
            or any(not _valid_id(rule) for rule in rules)
            or len(set(rules)) != len(rules)
        ):
            raise ValueError("invalid gateway rules")
        revision = controls["source_revision"]
        if (
            not isinstance(revision, dict)
            or set(revision) != {"tenant_id", "head_sha"}
            or not _valid_id(revision["tenant_id"])
            or not isinstance(revision["head_sha"], str)
            or re.fullmatch(r"[0-9a-f]{40}", revision["head_sha"]) is None
        ):
            raise ValueError("invalid gateway revision")
        evidence = context["untrusted_evidence"]
        if not isinstance(evidence, list) or not 1 <= len(evidence) <= 4096:
            raise ValueError("invalid gateway evidence")
        validated_post_tool_turn = native_tools and len(messages) > 1
        restricted = (
            _validate_native_transcript(
                messages,
                head_sha=revision["head_sha"],
                public_only=policy.budget_mode is GatewayBudgetMode.PUBLIC_CPU_CALIBRATION,
            )
            if native_tools
            else False
        )
        admitted_aliases: set[str] = set()
        for item in evidence:
            if (
                not isinstance(item, dict)
                or set(item)
                != {
                    "evidence_id",
                    "evidence_ids",
                    "instruction_authority",
                    "data_class",
                    "content",
                }
                or item["instruction_authority"] != "NONE"
                or not isinstance(item["content"], str)
            ):
                raise ValueError("invalid gateway evidence fields")
            aliases = item["evidence_ids"]
            if (
                not isinstance(aliases, list)
                or not 1 <= len(aliases) <= 4096
                or any(not _valid_id(alias) for alias in aliases)
                or len(set(aliases)) != len(aliases)
                or item["evidence_id"] != aliases[0]
                or admitted_aliases.intersection(aliases)
            ):
                raise ValueError("invalid gateway aliases")
            admitted_aliases.update(aliases)
            if len(admitted_aliases) > 4096:
                raise ValueError("gateway alias budget exceeded")
            if item["data_class"] not in tuple(value.value for value in DataClass):
                raise ValueError("invalid gateway classification")
            if (
                policy.budget_mode is GatewayBudgetMode.PUBLIC_CPU_CALIBRATION
                and item["data_class"] != DataClass.PUBLIC.value
            ):
                raise ValueError("calibration requires public data")
            restricted = restricted or item["data_class"] == DataClass.RESTRICTED.value
        locations = context["untrusted_source_locations"]
        if not isinstance(locations, list) or len(locations) > 4096:
            raise ValueError("invalid gateway locations")
        located_aliases = set()
        for entry in locations:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"evidence_id", "content_id", "instruction_authority", "location"}
                or entry["evidence_id"] not in admitted_aliases
                or entry["evidence_id"] in located_aliases
                or not _valid_id(entry["content_id"])
                or entry["instruction_authority"] != "NONE"
            ):
                raise ValueError("invalid gateway location alias")
            SourceLocation.model_validate_json(
                json.dumps(entry["location"], ensure_ascii=True, allow_nan=False)
            )
            located_aliases.add(entry["evidence_id"])

    except (ValueError, TypeError, UnicodeError, RecursionError):
        return _failure(400)
    if time.monotonic() >= request_deadline:
        return _failure(504)
    if restricted:
        response = {
            "id": "gateway-refusal-" + policy.content_sha256,
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "refusal": "RESTRICTED_DATA_POLICY",
                    },
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0},
        }
        return GatewayReply(
            200, json.dumps(response, separators=(",", ":")).encode(), native_policy_refusal=True
        )
    try:
        remaining = request_deadline - time.monotonic()
        if remaining <= 0:
            return _failure(504)
        upstream_body = body
        if native_tools and not validated_post_tool_turn:
            # Ollama's JSON content grammar suppresses native tool delimiters.
            # The fully validated transcript retains it for the final turn.
            upstream_request = dict(request)
            upstream_request.pop("response_format")
            upstream_body = json.dumps(
                upstream_request, separators=(",", ":"), ensure_ascii=False
            ).encode()
            if len(upstream_body) > policy.max_request_bytes:
                return _failure(413)
        reply = backend.dispatch(upstream_body, timeout_seconds=remaining)
        if time.monotonic() > request_deadline:
            return _failure(
                504, dispatched=reply.backend_dispatched if type(reply) is GatewayReply else True
            )
        if type(reply) is not GatewayReply or reply.status != 200:
            return _failure(
                reply.status if type(reply) is GatewayReply else 502,
                dispatched=reply.backend_dispatched if type(reply) is GatewayReply else True,
            )
        if type(reply.body) is not bytes or len(reply.body) > _MAX_RESPONSE_BYTES:
            return _failure(502, dispatched=True)
        try:
            canonical = (
                _canonicalize_native_reply(
                    reply.body, model_id=policy.model_id, head_sha=revision["head_sha"]
                )
                if native_tools
                else _canonicalize_ollama_envelope(reply.body, expected_model_id=policy.model_id)
            )
        except _NativeEnvelopeRejection as error:
            observed(
                GatewayResponseNormalization.REJECTED,
                error.shape,
                error.arguments_shape,
                error.arguments_rejection,
            )
            return _failure(502, dispatched=True)
        except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
            observed(GatewayResponseNormalization.REJECTED)
            return _failure(502, dispatched=True)
        if not observed(
            GatewayResponseNormalization.NATIVE
            if native_tools
            else GatewayResponseNormalization.STANDARD
        ):
            return _failure(502, dispatched=True)
        return GatewayReply(200, canonical, backend_dispatched=True)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return _failure(502, dispatched=True)
