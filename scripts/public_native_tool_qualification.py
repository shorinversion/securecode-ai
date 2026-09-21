"""Bounded public-only qualification for native repository tool selections.

This script is deliberately a release-checkpoint diagnostic.  It uses one
synthetic public Git snapshot, never stores model output or tool arguments, and
never changes a production capability flag.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final

from securecode_ai.adapters.git_snapshot import GitObjectReader
from securecode_ai.adapters.local_provider_gateway import (
    GatewayBackend,
    GatewayPolicy,
    GatewayReply,
    LoopbackOllamaBackend,
    _canonicalize_native_reply,
    handle_gateway_request,
)
from securecode_ai.adapters.native_repository_tools import (
    NATIVE_REPOSITORY_TOOLS_JSON,
    NativeRepositoryToolCall,
    parse_native_tool_calls,
)
from securecode_ai.adapters.native_sources import (
    NativeSourceCatalogue,
    build_native_source_catalogue,
)
from securecode_ai.adapters.product_model import MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON
from securecode_ai.adapters.product_runtime import dispatch_native_repository_calls
from securecode_ai.contracts import RepositoryTool
from securecode_ai.core.model_discovery import RepositoryToolSession
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryToolBudget,
    RepositoryToolGuard,
    RepositoryToolRequest,
    RepositoryToolScope,
)

_QUALIFIABLE_MODELS: Final = frozenset(
    {
        "qwen3:4b-instruct-2507-q4_K_M",
        "qwen2.5-coder:7b-instruct-q4_K_M",
        "nemotron-mini:4b-instruct-q5_1",
        "llama3.1:8b-instruct-q3_K_M",
    }
)
_QWEN25_MODEL_ID: Final = "qwen2.5-coder:7b-instruct-q4_K_M"
_QWEN25_MANIFEST_SHA256: Final = "".join(
    (
        "dae161e2",
        "7b0e90dd",
        "1856c8bb",
        "3209201f",
        "d6736d8e",
        "b66298e7",
        "5ed87571",
        "486f4364",
    )
)
_NEMOTRON_MODEL_ID: Final = "nemotron-mini:4b-instruct-q5_1"
_NEMOTRON_MANIFEST_SHA256: Final = "".join(
    (
        "8c244be1",
        "3dfec917",
        "0d3df056",
        "611f2f9a",
        "db9c7db5",
        "a965f874",
        "b8ca71ae",
        "6af0a8a1",
    )
)
_LLAMA31_MODEL_ID: Final = "llama3.1:8b-instruct-q3_K_M"
_LLAMA31_MANIFEST_SHA256: Final = "".join(
    (
        "4faa21fc",
        "a5a2734f",
        "3ae8994b",
        "c9d12e6b",
        "f7d642bd",
        "cc35c45e",
        "65df5d12",
        "ca4bd90b",
    )
)
_PUBLIC_SOURCE: Final = b"def public_symbol(value: str) -> str:\n    return value\n"
_PUBLIC_PATH: Final = "public_fixture.py"
_TENANT: Final = "public-native-qualification"
_REPOSITORY: Final = "public-native-fixture"
_PRODUCER: Final = "public-native-qualification"
_SHA256: Final = re.compile(r"[0-9a-f]{64}\Z")
_OPAQUE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_LIVE: Final = "LIVE"
_SIMULATED: Final = "SIMULATED"
_QUALIFICATION_OLLAMA_VERSION: Final = "0.34.2"
_SHOW_KEYS: Final = frozenset(
    {
        "capabilities",
        "details",
        "license",
        "model_info",
        "modelfile",
        "modified_at",
        "parameters",
        "template",
        "tensors",
    }
)
_SHOW_DETAIL_KEYS: Final = frozenset(
    {
        "families",
        "family",
        "format",
        "parameter_size",
        "parent_model",
        "quantization_level",
    }
)
_QWEN25_SHOW_KEYS: Final = frozenset(
    {
        "capabilities",
        "details",
        "license",
        "model_info",
        "modelfile",
        "modified_at",
        "system",
        "template",
    }
)
_NEMOTRON_SHOW_KEYS: Final = frozenset(
    {
        "capabilities",
        "details",
        "license",
        "model_info",
        "modelfile",
        "modified_at",
        "template",
    }
)
_LLAMA31_SHOW_KEYS: Final = frozenset(
    {
        "capabilities",
        "details",
        "license",
        "model_info",
        "modelfile",
        "modified_at",
        "parameters",
        "template",
    }
)
_MAX_OBSERVED_USAGE: Final = 2**31 - 1
_FAIL_PHASES: Final = frozenset(
    {"COMPLETE", "LOCAL_METADATA", "GATEWAY", "SELECTION_VALIDATION", "GUARD"}
)
_NATIVE_FINISHES: Final = frozenset({"TOOL_CALLS", "MISSING", "OTHER", "INVALID"})


class QualificationError(ValueError):
    """A closed qualification precondition or response check failed."""


def _qualification_policy(
    model_id: str, manifest_sha256: str, *, port: int, timeout_seconds: float
) -> GatewayPolicy:
    """Create the public qualifier's exact, observed loopback policy."""
    return GatewayPolicy(
        model_id,
        manifest_sha256,
        backend_port=port,
        timeout_seconds=timeout_seconds,
        max_output_tokens=512,
        backend_version=_QUALIFICATION_OLLAMA_VERSION,
    )


class _FixtureReader(GitObjectReader):
    """In-memory Git object database for the fixed public fixture only."""

    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], bytes] = {}

    def add(self, kind: str, content: bytes) -> str:
        oid = hashlib.sha1(
            f"{kind} {len(content)}\0".encode("ascii") + content,
            usedforsecurity=False,
        ).hexdigest()
        self._objects[(kind, oid)] = content
        return oid

    def read(self, kind: str, oid: str, *, max_bytes: int) -> bytes:
        if kind not in {"blob", "tree", "commit"} or type(max_bytes) is not int or max_bytes < 0:
            raise ValueError("invalid public fixture object request")
        content = self._objects.get((kind, oid))
        if content is None or len(content) > max_bytes:
            raise ValueError("public fixture object unavailable")
        return content


@dataclass(frozen=True, slots=True)
class PublicFixture:
    catalogue: NativeSourceCatalogue = field(repr=False)
    head_sha: str
    path: str
    symbol: str


@dataclass(frozen=True, slots=True)
class NativeToolProbe:
    name: str
    expected_request: RepositoryToolRequest = field(repr=False)
    prompt: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or self.name not in {item.value for item in RepositoryTool}
            or type(self.expected_request) is not RepositoryToolRequest
            or self.expected_request.tool.value != self.name
            or type(self.prompt) is not str
            or not 1 <= len(self.prompt.encode("utf-8")) <= 1024
        ):
            raise QualificationError("invalid public native probe")


@dataclass(frozen=True, slots=True)
class NativeSelection:
    calls: tuple[NativeRepositoryToolCall, ...] = field(repr=False)
    prompt_tokens: int
    completion_tokens: int


@dataclass(frozen=True, slots=True)
class ProbeReceipt:
    tool: str
    origin: str
    reason_code: str
    provider_status: int
    native_terminal: bool
    native_call_count: int
    prompt_tokens: int
    completion_tokens: int
    observed_prompt_tokens: int | None
    observed_completion_tokens: int | None
    observed_metadata_valid: bool
    observed_native_finish: str
    observed_native_call_count: int | None
    observed_strict_head_match: bool | None
    elapsed_seconds: float
    local_metadata_seconds: float
    gateway_seconds: float
    backend_seconds: float
    core_guard_seconds: float
    failure_phase: str
    prompt_sha256: str
    guard_receipt_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        durations = (
            self.elapsed_seconds,
            self.local_metadata_seconds,
            self.gateway_seconds,
            self.backend_seconds,
            self.core_guard_seconds,
        )
        counters = (
            self.native_call_count,
            self.prompt_tokens,
            self.completion_tokens,
        )
        observed_counters = (
            self.observed_prompt_tokens,
            self.observed_completion_tokens,
            self.observed_native_call_count,
        )
        if (
            self.tool not in {item.value for item in RepositoryTool}
            or self.origin not in {_LIVE, _SIMULATED}
            or self.reason_code not in _REASON_CODES
            or type(self.provider_status) is not int
            or not 0 <= self.provider_status <= 599
            or type(self.native_terminal) is not bool
            or any(
                type(value) is not int or not 0 <= value <= _MAX_OBSERVED_USAGE
                for value in counters
            )
            or any(
                value is not None
                and (type(value) is not int or not 0 <= value <= _MAX_OBSERVED_USAGE)
                for value in observed_counters
            )
            or type(self.observed_metadata_valid) is not bool
            or self.observed_native_finish not in _NATIVE_FINISHES
            or (
                self.observed_strict_head_match is not None
                and type(self.observed_strict_head_match) is not bool
            )
            or any(
                type(value) not in {float, int} or not math.isfinite(value) or value < 0
                for value in durations
            )
            or self.failure_phase not in _FAIL_PHASES
            or (self.reason_code == "QUALIFIED") != (self.failure_phase == "COMPLETE")
            or _SHA256.fullmatch(self.prompt_sha256) is None
            or type(self.guard_receipt_hashes) is not tuple
            or any(
                type(value) is not str or _SHA256.fullmatch(value) is None
                for value in self.guard_receipt_hashes
            )
        ):
            raise QualificationError("invalid public qualification receipt")


@dataclass(frozen=True, slots=True)
class BackendObservation:
    elapsed_seconds: float
    metadata_valid: bool
    native_finish: str
    native_call_count: int | None
    strict_head_match: bool | None
    prompt_tokens: int | None
    completion_tokens: int | None


@dataclass(slots=True)
class _ProbeTiming:
    started: float
    local_metadata_seconds: float = 0.0
    gateway_seconds: float = 0.0
    backend_seconds: float = 0.0
    core_guard_seconds: float = 0.0

    def elapsed_seconds(self) -> float:
        return _duration(self.started)


_REASON_CODES: Final = frozenset(
    {
        "QUALIFIED",
        "LOCAL_MODEL_UNVERIFIED",
        "GATEWAY_UNAVAILABLE",
        "NON_TERMINAL_NATIVE_RESPONSE",
        "MISSING_NATIVE_TOOL_CALLS",
        "INVALID_NATIVE_SELECTION",
        "UNEXPECTED_NATIVE_TOOL",
        "INVALID_NATIVE_ARGUMENTS",
        "GUARD_DISPATCH_FAILED",
    }
)


def _json_object(value: bytes) -> dict[str, object]:
    def no_constant(_: str) -> object:
        raise QualificationError("non-finite JSON is invalid")

    def no_duplicate(pairs: list[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, item in pairs:
            if key in output:
                raise QualificationError("duplicate JSON key")
            output[key] = item
        return output

    try:
        result = json.loads(value, object_pairs_hook=no_duplicate, parse_constant=no_constant)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise QualificationError("invalid JSON response") from exc
    if type(result) is not dict:
        raise QualificationError("response root is invalid")
    return result


def _duration(started: float) -> float:
    elapsed = time.monotonic() - started
    if not math.isfinite(elapsed) or elapsed < 0:
        raise QualificationError("invalid observed clock")
    return elapsed


def _wire_integer(value: object) -> int | None:
    if type(value) is not int or not 0 <= value <= _MAX_OBSERVED_USAGE:
        return None
    return value


def _backend_observation(
    reply: GatewayReply, *, model_id: str, head_sha: str, elapsed_seconds: float
) -> BackendObservation:
    """Extract only closed, source-free metadata from a backend reply."""
    default = BackendObservation(elapsed_seconds, False, "INVALID", None, None, None, None)
    if type(reply) is not GatewayReply or reply.status != 200 or type(reply.body) is not bytes:
        return default
    try:
        document = _json_object(reply.body)
        full = set(document) == {
            "id",
            "object",
            "created",
            "model",
            "system_fingerprint",
            "choices",
            "usage",
        }
        compact = set(document) == {"id", "choices", "usage"}
        if not full and not compact:
            return default
        response_id = document.get("id")
        if type(response_id) is not str or _OPAQUE.fullmatch(response_id) is None:
            return default
        if full and (
            document["object"] != "chat.completion"
            or document["model"] != model_id
            or document["system_fingerprint"] != "fp_ollama"
            or _wire_integer(document["created"]) is None
        ):
            return default
        choices = document["choices"]
        if (
            type(choices) is not list
            or len(choices) != 1
            or type(choices[0]) is not dict
            or set(choices[0])
            not in ({"index", "message", "finish_reason"}, {"message", "finish_reason"})
            or (full and "index" not in choices[0])
            or ("index" in choices[0] and _wire_integer(choices[0]["index"]) != 0)
            or type(choices[0]["message"]) is not dict
        ):
            return default
        message = choices[0]["message"]
        if (
            message.get("role") != "assistant"
            or set(message) - {"role", "content", "refusal", "tool_calls"}
            or (message.get("content") is not None and type(message.get("content")) is not str)
            or (message.get("refusal") is not None and type(message.get("refusal")) is not str)
        ):
            return default
        usage = document["usage"]
        expected_usage = (
            {"prompt_tokens", "completion_tokens", "total_tokens"}
            if full
            else {
                "prompt_tokens",
                "completion_tokens",
            }
        )
        if type(usage) is not dict or set(usage) != expected_usage:
            return default
        prompt_tokens = _wire_integer(usage["prompt_tokens"])
        completion_tokens = _wire_integer(usage["completion_tokens"])
        if prompt_tokens is None or completion_tokens is None:
            return default
        if full and _wire_integer(usage["total_tokens"]) != prompt_tokens + completion_tokens:
            return default
        finish = choices[0]["finish_reason"]
        if finish == "tool_calls":
            native_finish = "TOOL_CALLS"
        elif finish is None:
            native_finish = "MISSING"
        elif type(finish) is str:
            native_finish = "OTHER"
        else:
            native_finish = "INVALID"
        calls = message.get("tool_calls")
        if calls is None:
            return BackendObservation(
                elapsed_seconds,
                True,
                native_finish,
                0,
                None,
                prompt_tokens,
                completion_tokens,
            )
        if type(calls) is not list or len(calls) > 4:
            return BackendObservation(
                elapsed_seconds,
                True,
                native_finish,
                None,
                False,
                prompt_tokens,
                completion_tokens,
            )
        try:
            _canonicalize_native_reply(reply.body, model_id=model_id, head_sha=head_sha)
            head_match = True
        except ValueError:
            head_match = False
        return BackendObservation(
            elapsed_seconds,
            True,
            native_finish,
            len(calls),
            head_match,
            prompt_tokens,
            completion_tokens,
        )
    except QualificationError:
        return default


class _ObservedBackend:
    """Time one already-authorized backend call without retaining its body."""

    def __init__(self, backend: GatewayBackend, *, model_id: str, head_sha: str) -> None:
        self._backend = backend
        self._model_id = model_id
        self._head_sha = head_sha
        self.observation = BackendObservation(0.0, False, "INVALID", None, None, None, None)

    def dispatch(self, body: bytes, *, timeout_seconds: float) -> GatewayReply:
        started = time.monotonic()
        try:
            reply = self._backend.dispatch(body, timeout_seconds=timeout_seconds)
        except Exception:
            self.observation = BackendObservation(
                _duration(started), False, "INVALID", None, None, None, None
            )
            raise
        self.observation = _backend_observation(
            reply,
            model_id=self._model_id,
            head_sha=self._head_sha,
            elapsed_seconds=_duration(started),
        )
        return reply


def build_public_fixture() -> PublicFixture:
    """Build the one fixed public Git closure through the production catalogue."""
    reader = _FixtureReader()
    blob = reader.add("blob", _PUBLIC_SOURCE)
    tree = reader.add(
        "tree", b"100644 " + _PUBLIC_PATH.encode("ascii") + b"\0" + bytes.fromhex(blob)
    )
    head = reader.add(
        "commit", f"tree {tree}\n\npublic native tool qualification\n".encode("ascii")
    )
    catalogue = build_native_source_catalogue(
        reader=reader,
        head_sha=head,
        tenant_id=_TENANT,
        repository_id=_REPOSITORY,
        content_key=b"public-native-qualification-key" * 2,
    )
    return PublicFixture(
        catalogue=catalogue, head_sha=head, path=_PUBLIC_PATH, symbol="public_symbol"
    )


def public_probes(fixture: PublicFixture) -> tuple[NativeToolProbe, ...]:
    if type(fixture) is not PublicFixture or not fixture.catalogue.anchors:
        raise QualificationError("public fixture is invalid")
    common = {"schema_version": TOOL_ARGUMENT_SCHEMA_VERSION, "head_sha": fixture.head_sha}
    evidence_id = fixture.catalogue.anchors[0].evidence_id
    requests = (
        RepositoryToolRequest(
            RepositoryTool.LIST_PATHS,
            ListPathsArguments(**common, prefix=fixture.path, max_entries=4),
        ),
        RepositoryToolRequest(
            RepositoryTool.LOOKUP_SYMBOL,
            LookupSymbolArguments(**common, symbol=fixture.symbol, path=fixture.path),
        ),
        RepositoryToolRequest(
            RepositoryTool.READ_RANGE,
            ReadRangeArguments(**common, path=fixture.path, start_line=1, end_line=2),
        ),
        RepositoryToolRequest(
            RepositoryTool.READ_EVIDENCE, ReadEvidenceArguments(**common, evidence_id=evidence_id)
        ),
    )
    prompts = (
        "Call exactly list_paths with prefix public_fixture.py and max_entries 4. Do not answer with text.",
        "Call exactly lookup_symbol for public_symbol at public_fixture.py. Do not answer with text.",
        "Call exactly read_range for public_fixture.py lines 1 through 2. Do not answer with text.",
        "Call exactly read_evidence for the first declared evidence id. Do not answer with text.",
    )
    return tuple(
        NativeToolProbe(item.tool.value, item, prompt)
        for item, prompt in zip(requests, prompts, strict=True)
    )


def render_probe_instructions(fixture: PublicFixture, probe: NativeToolProbe) -> str:
    """Render a public tool-selection phase through admitted trusted instructions.

    The final discovery schema remains an input contract, but it applies only
    after a tool result.  Native function schemas validate shape, while the
    host supplies this turn's exact already-admitted revision and alias values.
    """
    if type(fixture) is not PublicFixture or type(probe) is not NativeToolProbe:
        raise QualificationError("public probe inputs are invalid")
    arguments = asdict(probe.expected_request.arguments)
    if arguments.get("head_sha") != fixture.head_sha:
        raise QualificationError("public probe revision is invalid")
    exact_arguments = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    )
    rendered = (
        "This is a native repository-tool selection turn. Invoke exactly one native function "
        "and return no assistant content, candidates, or final discovery payload. The discovery "
        "output schema applies only after a successful tool result. Use only the function "
        f"{probe.name} and exactly this JSON argument object: {exact_arguments}. "
        "The schema_version and head_sha values are host-admitted controls."
    )
    if not 1 <= len(rendered.encode("utf-8")) <= 4096:
        raise QualificationError("public probe instructions exceed budget")
    return rendered


def _context(fixture: PublicFixture, probe: NativeToolProbe) -> dict[str, object]:
    anchors = fixture.catalogue.anchors
    return {
        "trusted_controls": {
            "role": "discovery",
            "instructions": render_probe_instructions(fixture, probe),
            "output_schema": json.loads(MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON),
            "allowed_rule_ids": ["public-rule"],
            "source_revision": {"tenant_id": _TENANT, "head_sha": fixture.head_sha},
        },
        "untrusted_evidence": [
            {
                "evidence_id": anchor.evidence_id,
                "evidence_ids": [anchor.evidence_id],
                "instruction_authority": "NONE",
                "data_class": "DC3_CONFIDENTIAL_SOURCE",
                "content": _PUBLIC_SOURCE.decode("ascii"),
            }
            for anchor in anchors
        ],
        "untrusted_source_locations": [
            {
                "evidence_id": anchor.evidence_id,
                "content_id": anchor.read_artifact.content_id,
                "instruction_authority": "NONE",
                # The gateway decodes JSON into Python containers before its
                # strict model validation.  Omit empty tuple defaults rather
                # than serializing them as JSON arrays.
                "location": anchor.location.model_dump(mode="json", exclude_defaults=True),
            }
            for anchor in anchors
        ],
    }


def build_probe_request(
    policy: GatewayPolicy, fixture: PublicFixture, probe: NativeToolProbe
) -> bytes:
    """Construct the exact pinned native gateway request for one public probe."""
    if (
        type(policy) is not GatewayPolicy
        or type(fixture) is not PublicFixture
        or type(probe) is not NativeToolProbe
    ):
        raise QualificationError("public probe inputs are invalid")
    body = {
        "model": policy.model_id,
        "max_tokens": min(512, policy.max_output_tokens),
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "user", "content": json.dumps(_context(fixture, probe), separators=(",", ":"))}
        ],
        "tools": json.loads(NATIVE_REPOSITORY_TOOLS_JSON),
        "temperature": 0,
        "seed": 7,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def validate_native_response(
    body: bytes,
    *,
    head_sha: str,
    expected_tool: RepositoryTool,
    expected_request: RepositoryToolRequest | None = None,
) -> NativeSelection:
    """Accept only one terminal provider-native call, never textual JSON content."""
    if type(expected_tool) is not RepositoryTool or (
        expected_request is not None and type(expected_request) is not RepositoryToolRequest
    ):
        raise QualificationError("expected native tool is invalid")
    document = _json_object(body)
    if (
        set(document) != {"id", "choices", "usage"}
        or not isinstance(document["id"], str)
        or _OPAQUE.fullmatch(document["id"]) is None
    ):
        raise QualificationError("native response envelope is invalid")
    choices = document["choices"]
    if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
        raise QualificationError("native response is non-terminal")
    choice = choices[0]
    if set(choice) != {"finish_reason", "message"} or choice["finish_reason"] != "tool_calls":
        raise QualificationError("native response is non-terminal")
    message = choice["message"]
    if (
        type(message) is not dict
        or set(message) != {"role", "content", "refusal", "tool_calls"}
        or message["role"] != "assistant"
        or message["content"] is not None
        or message["refusal"] is not None
        or type(message["tool_calls"]) is not list
        or not message["tool_calls"]
    ):
        raise QualificationError("native tool calls are absent")
    usage = document["usage"]
    if (
        type(usage) is not dict
        or set(usage) != {"prompt_tokens", "completion_tokens"}
        or any(type(item) is not int or item <= 0 for item in usage.values())
    ):
        raise QualificationError("native usage is unmeasured")
    try:
        calls = parse_native_tool_calls(message["tool_calls"], head_sha=head_sha, max_calls=1)
    except ValueError as exc:
        raise QualificationError("native arguments are invalid") from exc
    if len(calls) != 1 or calls[0].request.tool is not expected_tool:
        raise QualificationError("native tool is unexpected")
    if expected_request is not None and calls[0].request != expected_request:
        raise QualificationError("native arguments are invalid")
    return NativeSelection(calls, usage["prompt_tokens"], usage["completion_tokens"])


def _session(fixture: PublicFixture) -> RepositoryToolSession:
    scope = RepositoryToolScope(
        _TENANT,
        _REPOSITORY,
        fixture.head_sha,
        (fixture.path,),
        tuple(sorted(anchor.evidence_id for anchor in fixture.catalogue.anchors)),
    )
    return RepositoryToolSession(
        guard=RepositoryToolGuard(scope=scope, budget=RepositoryToolBudget(1, 65536, 65536)),
        backend=fixture.catalogue.repository_view(),
    )


def _local_show_is_local(policy: GatewayPolicy, backend: LoopbackOllamaBackend) -> bool:
    """Reject cloud aliases before any source-bearing POST without retaining show output."""
    deadline = time.monotonic() + policy.timeout_seconds
    reply = backend._exchange(
        "POST",
        "/api/show",
        json.dumps({"name": policy.model_id}, separators=(",", ":")).encode("ascii"),
        deadline=deadline,
        max_bytes=1024 * 1024,
        dispatched=False,
    )
    if reply.status != 200:
        return False
    try:
        document = _json_object(reply.body)
    except QualificationError:
        return False
    details = document.get("details")
    model_info = document.get("model_info")
    capabilities = document.get("capabilities")
    # This additional local shape is positively observed, not inferred from a
    # capability label. Actual calls and guard receipts still qualify tools.
    observed_qwen3 = (
        policy.backend_version == _QUALIFICATION_OLLAMA_VERSION
        and policy.model_id == "qwen3:4b-instruct-2507-q4_K_M"
        and type(details) is dict
        and details.get("family") == "qwen3"
        and details.get("families") == ["qwen3"]
        and details.get("format") == "gguf"
        and details.get("parameter_size") == "4.0B"
        and details.get("quantization_level") == "Q4_K_M"
        and type(model_info) is dict
        and model_info.get("general.architecture") == "qwen3"
        and model_info.get("general.file_type") == 15
        and type(capabilities) is list
        and len(capabilities) == 3
        and all(type(item) is str for item in capabilities)
        and set(capabilities) == {"completion", "tools", "thinking"}
        and set(document) in (_SHOW_KEYS, _SHOW_KEYS - {"tensors"})
    )
    observed_qwen25 = (
        policy.backend_version == _QUALIFICATION_OLLAMA_VERSION
        and policy.model_id == _QWEN25_MODEL_ID
        and policy.model_manifest_sha256 == _QWEN25_MANIFEST_SHA256
        and type(details) is dict
        and details.get("parent_model") == ""
        and details.get("family") == "qwen2"
        and details.get("families") == ["qwen2"]
        and details.get("format") == "gguf"
        and details.get("parameter_size") == "7.6B"
        and details.get("quantization_level") == "Q4_K_M"
        and type(model_info) is dict
        and model_info.get("general.architecture") == "qwen2"
        and model_info.get("general.file_type") == 15
        and type(capabilities) is list
        and len(capabilities) == 3
        and all(type(item) is str for item in capabilities)
        and capabilities == ["completion", "tools", "insert"]
        and set(document) == _QWEN25_SHOW_KEYS
    )
    observed_nemotron = (
        policy.backend_version == _QUALIFICATION_OLLAMA_VERSION
        and policy.model_id == _NEMOTRON_MODEL_ID
        and policy.model_manifest_sha256 == _NEMOTRON_MANIFEST_SHA256
        and type(details) is dict
        and details.get("parent_model") == ""
        and details.get("family") == "nemotron"
        and details.get("families") == ["nemotron"]
        and details.get("format") == "gguf"
        and details.get("parameter_size") == "4.2B"
        and details.get("quantization_level") == "Q5_1"
        and type(model_info) is dict
        and model_info.get("general.architecture") == "nemotron"
        and model_info.get("general.file_type") == 9
        and type(capabilities) is list
        and len(capabilities) == 2
        and all(type(item) is str for item in capabilities)
        and capabilities == ["completion", "tools"]
        and set(document) == _NEMOTRON_SHOW_KEYS
    )
    observed_llama31 = (
        policy.backend_version == _QUALIFICATION_OLLAMA_VERSION
        and policy.model_id == _LLAMA31_MODEL_ID
        and policy.model_manifest_sha256 == _LLAMA31_MANIFEST_SHA256
        and type(details) is dict
        and details.get("parent_model") == ""
        and details.get("family") == "llama"
        and details.get("families") == ["llama"]
        and details.get("format") == "gguf"
        and details.get("parameter_size") == "8.0B"
        and details.get("quantization_level") == "Q3_K_M"
        and type(model_info) is dict
        and model_info.get("general.architecture") == "llama"
        and model_info.get("general.file_type") == 12
        and type(capabilities) is list
        and len(capabilities) == 2
        and all(type(item) is str for item in capabilities)
        and capabilities == ["completion", "tools"]
        and set(document) == _LLAMA31_SHOW_KEYS
    )
    legacy_shape = (
        policy.model_id not in {_QWEN25_MODEL_ID, _NEMOTRON_MODEL_ID, _LLAMA31_MODEL_ID}
        and set(document) == _SHOW_KEYS
        and capabilities == ["completion", "tools"]
    )
    if not (
        legacy_shape or observed_qwen3 or observed_qwen25 or observed_nemotron or observed_llama31
    ):
        return False
    if (
        type(details) is not dict
        or set(details) != _SHOW_DETAIL_KEYS
        or type(details.get("families")) is not list
        or not details["families"]
        or any(type(item) is not str or not item for item in details["families"])
        or any(type(details.get(key)) is not str for key in _SHOW_DETAIL_KEYS - {"families"})
    ):
        return False
    if (
        type(model_info) is not dict
        or not model_info
        or type(model_info.get("general.architecture")) is not str
        or not model_info["general.architecture"]
        or type(model_info.get("general.file_type")) is not int
        or type(document.get("modelfile")) is not str
        or type(document.get("template")) is not str
        or (
            type(document.get("parameters")) is not str
            and not (observed_qwen25 or observed_nemotron)
        )
        or (observed_qwen25 and type(document.get("system")) is not str)
        or type(document.get("license")) is not str
        or type(document.get("modified_at")) is not str
        or ("tensors" in document and type(document["tensors"]) is not list)
        or (
            "tensors" not in document
            and not (observed_qwen3 or observed_qwen25 or observed_nemotron or observed_llama31)
        )
    ):
        return False

    def remotely_backed(value: object) -> bool:
        if type(value) is dict:
            for key, child in value.items():
                if key in {"remote_host", "remote_model"} and child not in (None, ""):
                    return True
                if remotely_backed(child):
                    return True
        elif type(value) is list:
            return any(remotely_backed(child) for child in value)
        return False

    return not remotely_backed(document)


def _reason(exc: QualificationError) -> str:
    text = str(exc)
    if "non-terminal" in text:
        return "NON_TERMINAL_NATIVE_RESPONSE"
    if "absent" in text:
        return "MISSING_NATIVE_TOOL_CALLS"
    if "unexpected" in text:
        return "UNEXPECTED_NATIVE_TOOL"
    if "arguments" in text:
        return "INVALID_NATIVE_ARGUMENTS"
    return "INVALID_NATIVE_SELECTION"


def run_public_probe(
    policy: GatewayPolicy,
    fixture: PublicFixture,
    probe: NativeToolProbe,
    backend: GatewayBackend | None = None,
) -> ProbeReceipt:
    """Run one real native selection and its single Core guarded dispatch."""
    if policy.model_id not in _QUALIFIABLE_MODELS:
        raise QualificationError("model is not an approved local qualification candidate")
    timing = _ProbeTiming(time.monotonic())
    rendered_prompt_sha256 = hashlib.sha256(
        render_probe_instructions(fixture, probe).encode("utf-8")
    ).hexdigest()
    active_backend: GatewayBackend
    origin: str
    observation = BackendObservation(0.0, False, "INVALID", None, None, None, None)
    if backend is None:
        local = LoopbackOllamaBackend(policy)
        metadata_started = time.monotonic()
        if not _local_show_is_local(policy, local):
            timing.local_metadata_seconds = _duration(metadata_started)
            return _receipt(
                probe,
                _LIVE,
                "LOCAL_MODEL_UNVERIFIED",
                0,
                False,
                0,
                0,
                0,
                rendered_prompt_sha256,
                (),
                timing,
                observation,
                "LOCAL_METADATA",
            )
        timing.local_metadata_seconds = _duration(metadata_started)
        active_backend = local
        origin = _LIVE
    else:
        active_backend = backend
        # An injected transport is a test seam. It cannot establish endpoint,
        # manifest, or local-execution provenance, even if it returns success.
        origin = _SIMULATED
    request = build_probe_request(policy, fixture, probe)
    observed_backend = _ObservedBackend(
        active_backend, model_id=policy.model_id, head_sha=fixture.head_sha
    )
    gateway_started = time.monotonic()
    reply = handle_gateway_request(request, policy=policy, backend=observed_backend)
    timing.gateway_seconds = _duration(gateway_started)
    observation = observed_backend.observation
    timing.backend_seconds = observation.elapsed_seconds
    if reply.status != 200 or not reply.backend_dispatched or reply.native_policy_refusal:
        return _receipt(
            probe,
            origin,
            "GATEWAY_UNAVAILABLE",
            reply.status,
            False,
            0,
            0,
            0,
            rendered_prompt_sha256,
            (),
            timing,
            observation,
            "GATEWAY",
        )
    try:
        selection = validate_native_response(
            reply.body,
            head_sha=fixture.head_sha,
            expected_tool=probe.expected_request.tool,
            expected_request=probe.expected_request,
        )
    except QualificationError as exc:
        return _receipt(
            probe,
            origin,
            _reason(exc),
            reply.status,
            False,
            0,
            0,
            0,
            rendered_prompt_sha256,
            (),
            timing,
            observation,
            "SELECTION_VALIDATION",
        )
    session = _session(fixture)
    guard_started = time.monotonic()
    try:
        wire = _json_object(reply.body)["choices"][0]["message"]["tool_calls"]  # type: ignore[index]
        batch = dispatch_native_repository_calls(wire, head_sha=fixture.head_sha, tools=session)
    except (ValueError, TypeError, QualificationError):
        timing.core_guard_seconds = _duration(guard_started)
        return _receipt(
            probe,
            origin,
            "GUARD_DISPATCH_FAILED",
            reply.status,
            True,
            1,
            selection.prompt_tokens,
            selection.completion_tokens,
            rendered_prompt_sha256,
            (),
            timing,
            observation,
            "GUARD",
        )
    timing.core_guard_seconds = _duration(guard_started)
    if not batch.is_complete or session.calls_used != 1:
        return _receipt(
            probe,
            origin,
            "GUARD_DISPATCH_FAILED",
            reply.status,
            True,
            1,
            selection.prompt_tokens,
            selection.completion_tokens,
            rendered_prompt_sha256,
            session.call_hashes,
            timing,
            observation,
            "GUARD",
        )
    return _receipt(
        probe,
        origin,
        "QUALIFIED",
        reply.status,
        True,
        1,
        selection.prompt_tokens,
        selection.completion_tokens,
        rendered_prompt_sha256,
        session.call_hashes,
        timing,
        observation,
        "COMPLETE",
    )


def _receipt(
    probe: NativeToolProbe,
    origin: str,
    reason_code: str,
    provider_status: int,
    native_terminal: bool,
    native_call_count: int,
    prompt_tokens: int,
    completion_tokens: int,
    prompt_sha256: str,
    guard_receipt_hashes: tuple[str, ...],
    timing: _ProbeTiming,
    observation: BackendObservation,
    failure_phase: str,
) -> ProbeReceipt:
    if (
        origin not in {_LIVE, _SIMULATED}
        or reason_code not in _REASON_CODES
        or _SHA256.fullmatch(prompt_sha256) is None
        or type(timing) is not _ProbeTiming
        or type(observation) is not BackendObservation
        or failure_phase not in _FAIL_PHASES
        or (reason_code == "QUALIFIED") != (failure_phase == "COMPLETE")
    ):
        raise QualificationError("invalid qualification reason")
    return ProbeReceipt(
        tool=probe.name,
        origin=origin,
        reason_code=reason_code,
        provider_status=provider_status,
        native_terminal=native_terminal,
        native_call_count=native_call_count,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        observed_prompt_tokens=observation.prompt_tokens,
        observed_completion_tokens=observation.completion_tokens,
        observed_metadata_valid=observation.metadata_valid,
        observed_native_finish=observation.native_finish,
        observed_native_call_count=observation.native_call_count,
        observed_strict_head_match=observation.strict_head_match,
        elapsed_seconds=timing.elapsed_seconds(),
        local_metadata_seconds=timing.local_metadata_seconds,
        gateway_seconds=timing.gateway_seconds,
        backend_seconds=timing.backend_seconds,
        core_guard_seconds=timing.core_guard_seconds,
        failure_phase=failure_phase,
        prompt_sha256=prompt_sha256,
        guard_receipt_hashes=guard_receipt_hashes,
    )


def summarize_qualification(
    policy: GatewayPolicy, receipts: tuple[ProbeReceipt, ...]
) -> dict[str, object]:
    if type(policy) is not GatewayPolicy or type(receipts) is not tuple or len(receipts) != 4:
        raise QualificationError("qualification receipt set is invalid")
    names = tuple(item.tool for item in receipts)
    expected = tuple(item.value for item in RepositoryTool)
    if names != expected or any(type(item) is not ProbeReceipt for item in receipts):
        raise QualificationError("qualification probes are incomplete")
    origins = {item.origin for item in receipts}
    if len(origins) != 1 or not origins <= {_LIVE, _SIMULATED}:
        raise QualificationError("qualification provenance is mixed or invalid")
    origin = next(iter(origins))
    live = origin == _LIVE
    conformant = live and all(item.reason_code == "QUALIFIED" for item in receipts)
    return {
        "schema": "securecode.release-checkpoint.v1",
        "kind": "public_native_tool_qualification",
        "backend_origin": f"http://127.0.0.1:{policy.backend_port}",
        "backend_version": policy.backend_version,
        "model_id": policy.model_id,
        "model_manifest_sha256": policy.model_manifest_sha256,
        "gateway_policy_sha256": policy.content_sha256,
        "native_tool_schema_sha256": hashlib.sha256(NATIVE_REPOSITORY_TOOLS_JSON).hexdigest(),
        "probe_origin": origin,
        "public_native_tools_conformant": conformant,
        "overall_production_admitted": False,
        "limitations": [
            "public synthetic native-tool qualification only",
            "does not qualify discovery quality, repair, full Core, or other capabilities",
            "does not alter production provider profiles or capability flags",
        ],
        "probes": [
            {
                "tool": item.tool,
                "origin": item.origin,
                "reason_code": item.reason_code,
                "provider_status": item.provider_status,
                "native_terminal": item.native_terminal,
                "native_call_count": item.native_call_count,
                "prompt_tokens": item.prompt_tokens,
                "completion_tokens": item.completion_tokens,
                "observed_prompt_tokens": item.observed_prompt_tokens,
                "observed_completion_tokens": item.observed_completion_tokens,
                "observed_metadata_valid": item.observed_metadata_valid,
                "observed_native_finish": item.observed_native_finish,
                "observed_native_call_count": item.observed_native_call_count,
                "observed_strict_head_match": item.observed_strict_head_match,
                "elapsed_seconds": item.elapsed_seconds,
                "local_metadata_seconds": item.local_metadata_seconds,
                "gateway_seconds": item.gateway_seconds,
                "backend_seconds": item.backend_seconds,
                "core_guard_seconds": item.core_guard_seconds,
                "failure_phase": item.failure_phase,
                "prompt_sha256": item.prompt_sha256,
                "guard_receipt_hashes": list(item.guard_receipt_hashes),
            }
            for item in receipts
        ],
    }


def _write_receipt(path: Path, document: dict[str, object]) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or path.parent.is_symlink():
        raise QualificationError("receipt path is unavailable")
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
            "ascii"
        )
        + b"\n"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                raise OSError("receipt write failed")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, choices=sorted(_QUALIFIABLE_MODELS))
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--port", type=int, default=11434)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if _SHA256.fullmatch(args.manifest_sha256) is None:
        parser.error("--manifest-sha256 must be lowercase SHA-256")
    try:
        policy = _qualification_policy(
            args.model, args.manifest_sha256, port=args.port, timeout_seconds=args.timeout
        )
        fixture = build_public_fixture()
        receipts = tuple(
            run_public_probe(policy, fixture, probe) for probe in public_probes(fixture)
        )
        _write_receipt(args.output, summarize_qualification(policy, receipts))
    except (OSError, QualificationError, ValueError) as exc:
        print(f"public native qualification failed: {type(exc).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
