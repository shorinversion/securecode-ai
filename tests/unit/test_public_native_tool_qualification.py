"""Native qualification cannot promote textual or incomplete model replies."""

import hashlib
import json
import time
from dataclasses import asdict, replace
from typing import TypedDict, cast

import pytest
from securecode_ai.adapters.local_provider_gateway import (
    GatewayPolicy,
    GatewayReply,
    LoopbackOllamaBackend,
)
from securecode_ai.core.tool_policy import RepositoryTool

import scripts.public_native_tool_qualification as qualifier
from scripts.public_native_tool_qualification import validate_native_response

HEAD = "a" * 40


def _object(document: dict[str, object], key: str) -> dict[str, object]:
    value = document[key]
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _strings(document: dict[str, object], key: str) -> list[str]:
    value = document[key]
    assert isinstance(value, list) and all(isinstance(item, str) for item in value)
    return cast(list[str], value)


class _NativeFunction(TypedDict):
    name: str
    arguments: str


class _NativeToolCall(TypedDict):
    id: str
    type: str
    function: _NativeFunction


class _NativeMessage(TypedDict):
    role: str
    content: str | None
    refusal: str | None
    tool_calls: list[_NativeToolCall]


class _NativeChoice(TypedDict):
    finish_reason: str | None
    message: _NativeMessage


class _NativeUsage(TypedDict):
    prompt_tokens: int
    completion_tokens: int


class _NativeBody(TypedDict):
    id: str
    choices: list[_NativeChoice]
    usage: _NativeUsage


def observed_qwen3_show() -> dict[str, object]:
    """Source-free shape independently observed on local Ollama0.34.2."""
    return {
        "license": "public fixture",
        "modelfile": "FROM /local/model",
        "parameters": "",
        "template": "local template",
        "modified_at": "2026-09-18T00:00:00Z",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "qwen3",
            "families": ["qwen3"],
            "parameter_size": "4.0B",
            "quantization_level": "Q4_K_M",
        },
        "model_info": {"general.architecture": "qwen3", "general.file_type": 15},
        "capabilities": ["tools", "thinking", "completion"],
    }


def observed_qwen25_show() -> dict[str, object]:
    """Source-free Qwen2.5-Coder shape observed on local Ollama0.34.2."""
    return {
        "license": "public fixture",
        "modelfile": "FROM /local/model",
        "system": "",
        "template": "local template",
        "modified_at": "2026-09-18T00:00:00Z",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "qwen2",
            "families": ["qwen2"],
            "parameter_size": "7.6B",
            "quantization_level": "Q4_K_M",
        },
        "model_info": {"general.architecture": "qwen2", "general.file_type": 15},
        "capabilities": ["completion", "tools", "insert"],
    }


def observed_nemotron_show() -> dict[str, object]:
    """Source-free Nemotron Mini shape observed on local Ollama0.34.2."""
    return {
        "license": "public fixture",
        "modelfile": "FROM /local/model",
        "template": "local template",
        "modified_at": "2026-09-18T00:00:00Z",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "nemotron",
            "families": ["nemotron"],
            "parameter_size": "4.2B",
            "quantization_level": "Q5_1",
        },
        "model_info": {"general.architecture": "nemotron", "general.file_type": 9},
        "capabilities": ["completion", "tools"],
    }


def observed_llama31_show() -> dict[str, object]:
    """Source-free Llama 3.1 shape observed on local Ollama0.34.2."""
    return {
        "license": "public fixture",
        "modelfile": "FROM /local/model",
        "parameters": "",
        "template": "local template",
        "modified_at": "2026-09-18T00:00:00Z",
        "details": {
            "parent_model": "",
            "format": "gguf",
            "family": "llama",
            "families": ["llama"],
            "parameter_size": "8.0B",
            "quantization_level": "Q3_K_M",
        },
        "model_info": {"general.architecture": "llama", "general.file_type": 12},
        "capabilities": ["completion", "tools"],
    }


def check_show(
    document: dict[str, object],
    *,
    version: str = "0.34.2",
    model: str = "qwen3:4b-instruct-2507-q4_K_M",
    digest: str = "a" * 64,
) -> bool:
    class ShowBackend:
        def _exchange(self, *args: object, **kwargs: object) -> GatewayReply:
            return GatewayReply(200, json.dumps(document).encode())

    return qualifier._local_show_is_local(
        GatewayPolicy(model, digest, backend_version=version),
        cast(LoopbackOllamaBackend, ShowBackend()),
    )


def test_qualification_policy_uses_the_exact_observed_ollama_version() -> None:
    policy = qualifier._qualification_policy(
        "qwen3:4b-instruct-2507-q4_K_M", "a" * 64, port=11434, timeout_seconds=30.0
    )
    assert policy.backend_version == "0.34.2"


@pytest.mark.parametrize("tensors", [None, []])
def test_observed_local_qwen3_metadata_is_compatible_without_tool_admission(
    tensors: list[object] | None,
) -> None:
    document = observed_qwen3_show()
    if tensors is not None:
        document["tensors"] = tensors
    assert check_show(document)


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "missing_tools",
        "duplicate",
        "unknown_capability",
        "tensors",
        "remote",
        "family",
        "architecture",
        "format",
        "size",
        "quantization",
        "file_type",
    ],
)
def test_observed_qwen3_variant_keeps_local_metadata_boundary_closed(fault: str) -> None:
    document = observed_qwen3_show()
    if fault == "unknown":
        document["extra"] = "x"
    elif fault == "missing_tools":
        _strings(document, "capabilities").remove("tools")
    elif fault == "duplicate":
        _strings(document, "capabilities").append("tools")
    elif fault == "unknown_capability":
        _strings(document, "capabilities").append("insert")
    elif fault == "tensors":
        document["tensors"] = {}
    elif fault == "remote":
        _object(document, "model_info")["nested"] = {"remote_model": "cloud-model"}
    elif fault == "architecture":
        _object(document, "model_info")["general.architecture"] = "qwen2"
    elif fault == "file_type":
        _object(document, "model_info")["general.file_type"] = True
    else:
        key = {"size": "parameter_size", "quantization": "quantization_level"}.get(fault, fault)
        _object(document, "details")[key] = "unexpected"
    assert not check_show(document)


def test_observed_qwen3_variant_is_version_and_model_pinned() -> None:
    assert not check_show(observed_qwen3_show(), version="0.34.3")
    assert not check_show(observed_qwen3_show(), model="qwen2.5-coder:7b-instruct-q4_K_M")


def test_observed_local_qwen25_metadata_is_exactly_pinned_without_tool_admission() -> None:
    assert check_show(
        observed_qwen25_show(),
        model=qualifier._QWEN25_MODEL_ID,
        digest=qualifier._QWEN25_MANIFEST_SHA256,
    )


def test_observed_local_nemotron_metadata_is_exactly_pinned_without_tool_admission() -> None:
    assert check_show(
        observed_nemotron_show(),
        model=qualifier._NEMOTRON_MODEL_ID,
        digest=qualifier._NEMOTRON_MANIFEST_SHA256,
    )


def test_observed_local_llama31_metadata_is_exactly_pinned_without_tool_admission() -> None:
    assert check_show(
        observed_llama31_show(),
        model=qualifier._LLAMA31_MODEL_ID,
        digest=qualifier._LLAMA31_MANIFEST_SHA256,
    )


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "version",
        "digest",
        "suffixed_id",
        "parent_model",
        "family",
        "families",
        "format",
        "size",
        "quantization",
        "architecture",
        "file_type",
        "capabilities",
        "reordered_capabilities",
        "extra_top_level",
    ],
)
def test_observed_llama31_variant_stays_unverified_before_generation(fault: str) -> None:
    document = observed_llama31_show()
    model = qualifier._LLAMA31_MODEL_ID
    digest = qualifier._LLAMA31_MANIFEST_SHA256
    if fault == "unknown":
        _object(document, "details")["unknown"] = "x"
    elif fault == "version":
        assert not check_show(document, model=model, digest=digest, version="0.34.3")
        return
    elif fault == "digest":
        digest = "a" * 64
    elif fault == "suffixed_id":
        model = f"{model}:latest"
    elif fault == "parent_model":
        _object(document, "details")["parent_model"] = "llama3.1:base"
    elif fault == "family":
        _object(document, "details")["family"] = "qwen3"
    elif fault == "families":
        _object(document, "details")["families"] = ["llama", "qwen3"]
    elif fault == "format":
        _object(document, "details")["format"] = "safetensors"
    elif fault == "size":
        _object(document, "details")["parameter_size"] = "8B"
    elif fault == "quantization":
        _object(document, "details")["quantization_level"] = "Q4_K_M"
    elif fault == "architecture":
        _object(document, "model_info")["general.architecture"] = "qwen3"
    elif fault == "file_type":
        _object(document, "model_info")["general.file_type"] = 15
    elif fault == "capabilities":
        _strings(document, "capabilities").append("thinking")
    elif fault == "reordered_capabilities":
        document["capabilities"] = ["tools", "completion"]
    else:
        document["extra"] = "x"
    assert not check_show(document, model=model, digest=digest)


@pytest.mark.parametrize("fault", ["metadata", "digest", "version", "suffixed_id"])
def test_llama31_rejection_stops_before_native_post(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    fixture = qualifier.build_public_fixture()
    policy = GatewayPolicy(
        qualifier._LLAMA31_MODEL_ID,
        qualifier._LLAMA31_MANIFEST_SHA256,
        backend_version="0.34.2",
    )
    document = observed_llama31_show()
    if fault == "metadata":
        _object(document, "details")["family"] = "qwen3"
    elif fault == "digest":
        policy = GatewayPolicy(policy.model_id, "a" * 64, backend_version=policy.backend_version)
    elif fault == "version":
        policy = GatewayPolicy(
            policy.model_id, policy.model_manifest_sha256, backend_version="0.34.3"
        )
    else:
        policy = GatewayPolicy(
            f"{policy.model_id}:latest",
            policy.model_manifest_sha256,
            backend_version=policy.backend_version,
        )
    paths = []

    class MetadataOnlyBackend:
        def __init__(self, _policy: GatewayPolicy) -> None:
            pass

        def _exchange(
            self, _method: str, path: str, *_args: object, **_kwargs: object
        ) -> GatewayReply:
            paths.append(path)
            return GatewayReply(200, json.dumps(document).encode())

    monkeypatch.setattr(qualifier, "LoopbackOllamaBackend", MetadataOnlyBackend)
    if fault == "suffixed_id":
        with pytest.raises(
            qualifier.QualificationError, match="approved local qualification candidate"
        ):
            qualifier.run_public_probe(policy, fixture, qualifier.public_probes(fixture)[0])
        assert paths == []
        return
    receipt = qualifier.run_public_probe(policy, fixture, qualifier.public_probes(fixture)[0])
    assert receipt.reason_code == "LOCAL_MODEL_UNVERIFIED"
    assert receipt.failure_phase == "LOCAL_METADATA"
    assert receipt.native_call_count == 0
    assert paths == ["/api/show"]


def test_nemotron_legacy_metadata_shape_stays_unverified_before_generation() -> None:
    document = observed_nemotron_show()
    document["parameters"] = ""
    document["tensors"] = []
    assert not check_show(
        document,
        model=qualifier._NEMOTRON_MODEL_ID,
        digest=qualifier._NEMOTRON_MANIFEST_SHA256,
    )


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "version",
        "digest",
        "model",
        "parent_model",
        "family",
        "families",
        "format",
        "size",
        "quantization",
        "architecture",
        "file_type",
        "capabilities",
        "reordered_capabilities",
        "missing_tools",
        "extra_top_level",
    ],
)
def test_observed_nemotron_variant_stays_unverified_before_generation(fault: str) -> None:
    document = observed_nemotron_show()
    model = qualifier._NEMOTRON_MODEL_ID
    digest = qualifier._NEMOTRON_MANIFEST_SHA256
    if fault == "unknown":
        _object(document, "details")["unknown"] = "x"
    elif fault == "version":
        assert not check_show(document, model=model, digest=digest, version="0.34.3")
        return
    elif fault == "digest":
        digest = "a" * 64
    elif fault == "model":
        model = "qwen3:4b-instruct-2507-q4_K_M"
    elif fault == "parent_model":
        _object(document, "details")["parent_model"] = "nemotron:base"
    elif fault == "family":
        _object(document, "details")["family"] = "qwen3"
    elif fault == "families":
        _object(document, "details")["families"] = ["nemotron", "qwen3"]
    elif fault == "format":
        _object(document, "details")["format"] = "safetensors"
    elif fault == "size":
        _object(document, "details")["parameter_size"] = "4B"
    elif fault == "quantization":
        _object(document, "details")["quantization_level"] = "Q4_K_M"
    elif fault == "architecture":
        _object(document, "model_info")["general.architecture"] = "qwen3"
    elif fault == "file_type":
        _object(document, "model_info")["general.file_type"] = 15
    elif fault == "capabilities":
        _strings(document, "capabilities").append("insert")
    elif fault == "reordered_capabilities":
        document["capabilities"] = ["tools", "completion"]
    elif fault == "missing_tools":
        _strings(document, "capabilities").remove("tools")
    else:
        document["extra"] = "x"
    assert not check_show(document, model=model, digest=digest)


@pytest.mark.parametrize(
    "fault",
    [
        "unknown",
        "version",
        "digest",
        "model",
        "family",
        "families",
        "format",
        "size",
        "quantization",
        "parent_model",
        "reordered_capabilities",
        "missing_tools",
        "unknown_capability",
        "architecture",
        "file_type",
        "system",
    ],
)
def test_observed_qwen25_variant_stays_unverified_before_generation(fault: str) -> None:
    document = observed_qwen25_show()
    model = qualifier._QWEN25_MODEL_ID
    digest = qualifier._QWEN25_MANIFEST_SHA256
    if fault == "unknown":
        document["extra"] = "x"
    elif fault == "version":
        return_value = check_show(document, model=model, digest=digest, version="0.34.3")
        assert not return_value
        return
    elif fault == "digest":
        digest = "a" * 64
    elif fault == "model":
        model = "qwen3:4b-instruct-2507-q4_K_M"
    elif fault == "families":
        _object(document, "details")["families"] = ["qwen2", "qwen3"]
    elif fault == "missing_tools":
        _strings(document, "capabilities").remove("tools")
    elif fault == "parent_model":
        _object(document, "details")["parent_model"] = "qwen2:base"
    elif fault == "reordered_capabilities":
        document["capabilities"] = ["tools", "completion", "insert"]
    elif fault == "unknown_capability":
        _strings(document, "capabilities").append("thinking")
    elif fault == "system":
        document["system"] = None
    elif fault == "architecture":
        _object(document, "model_info")["general.architecture"] = "qwen3"
    elif fault == "file_type":
        _object(document, "model_info")["general.file_type"] = True
    else:
        key = {"size": "parameter_size", "quantization": "quantization_level"}.get(fault, fault)
        _object(document, "details")[key] = "unexpected"
    assert not check_show(document, model=model, digest=digest)


def test_qwen25_digest_mismatch_stops_before_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = qualifier.build_public_fixture()
    policy = GatewayPolicy(
        qualifier._QWEN25_MODEL_ID,
        "a" * 64,
        backend_version="0.34.2",
    )
    probe = qualifier.public_probes(fixture)[0]
    paths = []

    class MetadataOnlyBackend:
        def __init__(self, _policy: GatewayPolicy) -> None:
            pass

        def _exchange(
            self, _method: str, path: str, *_args: object, **_kwargs: object
        ) -> GatewayReply:
            paths.append(path)
            return GatewayReply(200, json.dumps(observed_qwen25_show()).encode())

    monkeypatch.setattr(qualifier, "LoopbackOllamaBackend", MetadataOnlyBackend)
    receipt = qualifier.run_public_probe(policy, fixture, probe)
    assert receipt.reason_code == "LOCAL_MODEL_UNVERIFIED"
    assert receipt.failure_phase == "LOCAL_METADATA"
    assert receipt.native_call_count == 0
    assert paths == ["/api/show"]


@pytest.mark.parametrize("mutation", ["parent_model", "reordered_capabilities"])
def test_qwen25_metadata_mutation_stops_before_generation(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    fixture = qualifier.build_public_fixture()
    policy = GatewayPolicy(
        qualifier._QWEN25_MODEL_ID,
        qualifier._QWEN25_MANIFEST_SHA256,
        backend_version="0.34.2",
    )
    probe = qualifier.public_probes(fixture)[0]
    document = observed_qwen25_show()
    if mutation == "parent_model":
        _object(document, "details")["parent_model"] = "qwen2:base"
    else:
        document["capabilities"] = ["tools", "completion", "insert"]
    paths = []

    class MetadataOnlyBackend:
        def __init__(self, _policy: GatewayPolicy) -> None:
            pass

        def _exchange(
            self, _method: str, path: str, *_args: object, **_kwargs: object
        ) -> GatewayReply:
            paths.append(path)
            return GatewayReply(200, json.dumps(document).encode())

    monkeypatch.setattr(qualifier, "LoopbackOllamaBackend", MetadataOnlyBackend)
    receipt = qualifier.run_public_probe(policy, fixture, probe)
    assert receipt.reason_code == "LOCAL_MODEL_UNVERIFIED"
    assert receipt.failure_phase == "LOCAL_METADATA"
    assert receipt.native_call_count == 0
    assert paths == ["/api/show"]


def test_qwen25_legacy_shape_stops_before_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = qualifier.build_public_fixture()
    policy = GatewayPolicy(
        qualifier._QWEN25_MODEL_ID,
        qualifier._QWEN25_MANIFEST_SHA256,
        backend_version="0.34.2",
    )
    probe = qualifier.public_probes(fixture)[0]
    legacy = observed_qwen25_show()
    legacy.pop("system")
    legacy["parameters"] = ""
    legacy["tensors"] = []
    legacy["capabilities"] = ["completion", "tools"]
    paths = []

    class MetadataOnlyBackend:
        def __init__(self, _policy: GatewayPolicy) -> None:
            pass

        def _exchange(
            self, _method: str, path: str, *_args: object, **_kwargs: object
        ) -> GatewayReply:
            paths.append(path)
            return GatewayReply(200, json.dumps(legacy).encode())

    monkeypatch.setattr(qualifier, "LoopbackOllamaBackend", MetadataOnlyBackend)
    receipt = qualifier.run_public_probe(policy, fixture, probe)
    assert receipt.reason_code == "LOCAL_MODEL_UNVERIFIED"
    assert receipt.failure_phase == "LOCAL_METADATA"
    assert receipt.native_call_count == 0
    assert paths == ["/api/show"]


def native_reply() -> _NativeBody:
    return {
        "id": "native-probe-1",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "refusal": None,
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "type": "function",
                            "function": {
                                "name": "read_evidence",
                                "arguments": json.dumps(
                                    {
                                        "schema_version": "0.1.0",
                                        "head_sha": HEAD,
                                        "evidence_id": "source-a",
                                    }
                                ),
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {"prompt_tokens": 8, "completion_tokens": 2},
    }


def test_accepts_only_genuine_closed_native_selection() -> None:
    result = validate_native_response(
        json.dumps(native_reply()).encode(),
        head_sha=HEAD,
        expected_tool=RepositoryTool.READ_EVIDENCE,
    )
    assert result.calls[0].request.tool is RepositoryTool.READ_EVIDENCE
    assert (result.prompt_tokens, result.completion_tokens) == (8, 2)


@pytest.mark.parametrize(
    "invalid",
    [
        "terminal",
        "text",
        "empty",
        "head",
        "unknown",
        "zero_usage",
        "boolean_usage",
        "refusal",
        "mixed",
    ],
)
def test_invalid_native_probe_reply_never_qualifies(invalid: str) -> None:
    body = native_reply()
    choice = body["choices"][0]
    message = choice["message"]
    if invalid == "terminal":
        choice["finish_reason"] = None
    elif invalid == "text":
        message["content"] = '{"name":"read_evidence","arguments":{}}'
        cast(dict[str, object], message).pop("tool_calls")
        choice["finish_reason"] = "stop"
    elif invalid == "empty":
        message["tool_calls"] = []
    elif invalid == "head":
        arguments = json.loads(message["tool_calls"][0]["function"]["arguments"])
        arguments["head_sha"] = "b" * 40
        message["tool_calls"][0]["function"]["arguments"] = json.dumps(arguments)
    elif invalid == "unknown":
        message["tool_calls"][0]["function"]["name"] = "shell"
    elif invalid == "zero_usage":
        body["usage"]["prompt_tokens"] = 0
    elif invalid == "boolean_usage":
        body["usage"]["completion_tokens"] = True
    elif invalid == "refusal":
        message["refusal"] = "provider-policy"
    else:
        message["content"] = "ordinary content with tool selection"
    with pytest.raises(ValueError):
        validate_native_response(
            json.dumps(body).encode(), head_sha=HEAD, expected_tool=RepositoryTool.READ_EVIDENCE
        )


def test_other_valid_tool_is_not_the_requested_qualification_cell() -> None:
    with pytest.raises(ValueError):
        validate_native_response(
            json.dumps(native_reply()).encode(),
            head_sha=HEAD,
            expected_tool=RepositoryTool.LOOKUP_SYMBOL,
        )


class ScriptedBackend:
    def __init__(self, probe: qualifier.NativeToolProbe) -> None:
        body = native_reply()
        call = body["choices"][0]["message"]["tool_calls"][0]
        call["function"] = {
            "name": probe.name,
            "arguments": json.dumps(asdict(probe.expected_request.arguments)),
        }
        self.reply = GatewayReply(200, json.dumps(body).encode(), backend_dispatched=True)
        self.calls = 0

    def dispatch(self, body: bytes, *, timeout_seconds: float) -> GatewayReply:
        self.calls += 1
        return self.reply


def test_four_simulated_guarded_probes_cannot_qualify_a_live_model() -> None:
    fixture = qualifier.build_public_fixture()
    policy = GatewayPolicy("qwen3:4b-instruct-2507-q4_K_M", "a" * 64)
    receipts = []
    for probe in qualifier.public_probes(fixture):
        backend = ScriptedBackend(probe)
        receipt = qualifier.run_public_probe(policy, fixture, probe, backend=backend)
        assert receipt.reason_code == "QUALIFIED", receipt.tool
        assert len(receipt.guard_receipt_hashes) == 1
        assert backend.calls == 1
        request = json.loads(qualifier.build_probe_request(policy, fixture, probe))
        context = json.loads(request["messages"][0]["content"])
        instructions = context["trusted_controls"]["instructions"]
        assert receipt.prompt_sha256 == hashlib.sha256(instructions.encode()).hexdigest()
        receipts.append(receipt)
    summary = qualifier.summarize_qualification(policy, tuple(receipts))
    assert summary["public_native_tools_conformant"] is False
    assert summary["overall_production_admitted"] is False
    mixed = (replace(receipts[0], origin="LIVE"), *receipts[1:])
    with pytest.raises(ValueError, match="provenance"):
        qualifier.summarize_qualification(policy, mixed)
    with pytest.raises(ValueError):
        qualifier.summarize_qualification(policy, tuple(receipts[:-1]))


@pytest.mark.parametrize(
    "show",
    [{}, {"model": "unverified"}, {"details": {}}, {"remote_host": "https://remote.invalid"}],
)
def test_missing_or_remote_local_model_metadata_never_verifies(
    show: dict[str, object],
) -> None:
    class ShowBackend:
        def _exchange(self, *args: object, **kwargs: object) -> GatewayReply:
            return GatewayReply(200, json.dumps(show).encode())

    policy = GatewayPolicy("qwen3:4b-instruct-2507-q4_K_M", "a" * 64)
    assert not qualifier._local_show_is_local(policy, cast(LoopbackOllamaBackend, ShowBackend()))


def test_wrong_native_arguments_stop_before_core_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = qualifier.build_public_fixture()
    policy = GatewayPolicy("qwen3:4b-instruct-2507-q4_K_M", "a" * 64)
    probe = qualifier.public_probes(fixture)[-1]
    backend = ScriptedBackend(probe)
    body = json.loads(backend.reply.body)
    call = body["choices"][0]["message"]["tool_calls"][0]
    args = json.loads(call["function"]["arguments"])
    args["evidence_id"] = "foreign-evidence"
    call["function"]["arguments"] = json.dumps(args)
    backend.reply = GatewayReply(200, json.dumps(body).encode(), backend_dispatched=True)

    def forbidden_dispatch(*args: object, **kwargs: object) -> None:
        pytest.fail("invalid selection reached Core dispatch")

    monkeypatch.setattr(qualifier, "dispatch_native_repository_calls", forbidden_dispatch)
    receipt = qualifier.run_public_probe(policy, fixture, probe, backend=backend)
    assert receipt.reason_code == "INVALID_NATIVE_ARGUMENTS"
    assert receipt.guard_receipt_hashes == ()


def test_failed_probe_retains_observed_time_without_claiming_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = qualifier.build_public_fixture()
    policy = GatewayPolicy("qwen3:4b-instruct-2507-q4_K_M", "a" * 64)
    probe = qualifier.public_probes(fixture)[-1]
    now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])

    class DelayedFailure:
        def dispatch(self, body: bytes, *, timeout_seconds: float) -> GatewayReply:
            now[0] += 1.25
            return GatewayReply(502, b"{}", backend_dispatched=True)

    receipt = qualifier.run_public_probe(policy, fixture, probe, backend=DelayedFailure())
    assert receipt.reason_code == "GATEWAY_UNAVAILABLE"
    assert receipt.elapsed_seconds >= 1.25
    assert receipt.failure_phase == "GATEWAY"
    assert receipt.native_terminal is False
    assert receipt.guard_receipt_hashes == ()
    assert receipt.observed_prompt_tokens is None
    assert receipt.observed_completion_tokens is None


def test_rejected_native_arguments_do_not_discard_measured_backend_usage() -> None:
    fixture = qualifier.build_public_fixture()
    policy = GatewayPolicy("qwen3:4b-instruct-2507-q4_K_M", "a" * 64)
    probe = qualifier.public_probes(fixture)[-1]
    backend = ScriptedBackend(probe)
    body = json.loads(backend.reply.body)
    call = body["choices"][0]["message"]["tool_calls"][0]
    args = json.loads(call["function"]["arguments"])
    args["head_sha"] = "b" * 40
    call["function"]["arguments"] = json.dumps(args)
    backend.reply = GatewayReply(200, json.dumps(body).encode(), backend_dispatched=True)
    receipt = qualifier.run_public_probe(policy, fixture, probe, backend=backend)
    assert receipt.reason_code == "GATEWAY_UNAVAILABLE"
    assert receipt.observed_prompt_tokens == 8
    assert receipt.observed_completion_tokens == 2
    assert receipt.native_terminal is False
    assert receipt.guard_receipt_hashes == ()


def test_observation_validates_the_actual_ollama_index_dialect() -> None:
    fixture = qualifier.build_public_fixture()
    probe = qualifier.public_probes(fixture)[-1]
    backend = ScriptedBackend(probe)
    body = json.loads(backend.reply.body)
    body.update(
        object="chat.completion", created=1, model="public-model", system_fingerprint="fp_ollama"
    )
    body["usage"]["total_tokens"] = 10
    body["choices"][0]["index"] = 0
    body["choices"][0]["message"]["tool_calls"][0]["index"] = 0
    observed = qualifier._backend_observation(
        GatewayReply(200, json.dumps(body).encode(), backend_dispatched=True),
        model_id="public-model",
        head_sha=fixture.head_sha,
        elapsed_seconds=1.0,
    )
    assert observed.metadata_valid is True
    assert observed.strict_head_match is True


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0])
def test_invalid_observed_clock_cannot_be_reported_as_zero_time(
    monkeypatch: pytest.MonkeyPatch, value: float
) -> None:
    monkeypatch.setattr(time, "monotonic", lambda: value)
    with pytest.raises(ValueError):
        qualifier._duration(0.0)


def test_core_guard_failure_preserves_native_usage_and_distinct_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = qualifier.build_public_fixture()
    policy = GatewayPolicy("qwen3:4b-instruct-2507-q4_K_M", "a" * 64)
    probe = qualifier.public_probes(fixture)[-1]
    now = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])

    def rejected_guard(*args: object, **kwargs: object) -> None:
        now[0] += 0.75
        raise ValueError("guard rejected")

    monkeypatch.setattr(qualifier, "dispatch_native_repository_calls", rejected_guard)
    receipt = qualifier.run_public_probe(policy, fixture, probe, backend=ScriptedBackend(probe))
    assert receipt.reason_code == "GUARD_DISPATCH_FAILED"
    assert receipt.failure_phase == "GUARD"
    assert receipt.core_guard_seconds == 0.75
    assert receipt.elapsed_seconds >= receipt.core_guard_seconds
    assert receipt.native_terminal is True
    assert receipt.prompt_tokens == receipt.observed_prompt_tokens == 8
    assert receipt.completion_tokens == receipt.observed_completion_tokens == 2
    assert receipt.guard_receipt_hashes == ()
    assert receipt.origin == "SIMULATED"
