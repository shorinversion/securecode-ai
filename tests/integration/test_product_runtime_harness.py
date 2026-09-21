"""Product ports exercised through real authorization/egress/transport harness."""

import hashlib
import json
from collections.abc import Callable
from typing import Protocol, cast

import pytest
from securecode_ai.adapters import (
    AuthorizedProviderHarness,
    EndpointAuthorizationIssuer,
    ProviderProfileRegistry,
)
from securecode_ai.adapters.openai_compatible_local import OpenAICompatibleLocalHttpConnector
from securecode_ai.adapters.product_model import MODEL_NATIVE_DISCOVERY_WIRE_PIN
from securecode_ai.adapters.product_runtime import (
    PRODUCT_DISCOVERY_PROMPT_PIN,
    AuthorizedLocalModelExecutor,
    DiscoveryEvidence,
    ProductAuditorInvocationObservation,
    ProductAuditorInvoker,
    ProductDiscoveryBackend,
    ResolvedModelEvidence,
)
from securecode_ai.adapters.repository_view import SealedRepositoryView
from securecode_ai.contracts import (
    ArtifactRef,
    DataClass,
    ModelCallResult,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    SourceLocation,
)
from securecode_ai.core.evidence_package import EvidencePackage
from securecode_ai.core.model_discovery import RepositoryToolSession
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ReadRangeArguments,
    RepositoryTool,
    RepositoryToolBudget,
    RepositoryToolGuard,
    RepositoryToolRequest,
    RepositoryToolScope,
)

from tests.unit.test_cst_adapter import _build
from tests.unit.test_endpoint_policy import ScriptedResolver
from tests.unit.test_openai_compatible_local import _LocalEndpoint, _success_body
from tests.unit.test_provider_preflight import (
    _issuer,
    _policy,
    _preflight_request,
    _profile,
    _request,
    _semantic_cases,
)


@pytest.mark.parametrize(
    "path,source",
    [
        ("a.py", b"execute(value)\n"),
        ("a.js", b"execute(value);\n"),
        ("a.ts", b"execute(value);\n"),
        ("a.go", b"package main\nfunc main() { execute(value) }\n"),
    ],
)
def test_git_bound_native_catalogue_through_actual_core_and_provider_harness(
    monkeypatch: pytest.MonkeyPatch, path: str, source: bytes
) -> None:
    from securecode_ai.adapters.native_sources import build_native_source_catalogue
    from securecode_ai.contracts import PreflightEligibility, ProducerRef
    from securecode_ai.core.evidence_package import build_evidence_package
    from securecode_ai.core.model_discovery import (
        ModelNativeDiscoveryPlan,
        run_model_native_discovery,
    )

    from tests.unit.test_native_sources import repository

    reader, head, _ = repository(path, source)
    backend, _, request, _, _ = _composition(monkeypatch)
    catalogue = build_native_source_catalogue(
        reader=reader,
        head_sha=head,
        tenant_id=request.tenant_id,
        repository_id="repo-a",
        content_key=b"p" * 32,
    )
    root = catalogue.anchors[-1]
    body = json.loads(_success_body())
    body["choices"][0]["message"]["content"] = json.dumps(
        {
            "candidates": [
                {
                    "rule_id": "rule-sqli",
                    "root_evidence_id": root.evidence_id,
                    "evidence_ids": [root.evidence_id],
                }
            ]
        }
    )
    backend, _, request, endpoint, _ = _composition(monkeypatch, body=json.dumps(body).encode())
    data = request.model_dump(mode="json")
    data["head_sha"] = head
    from securecode_ai.contracts import RepositoryRevision, RunExecutionIdentity

    identity = request.execution_identity
    revision = identity.repository_revision.model_dump(mode="json")
    revision["head_sha"] = head
    rebuilt = RunExecutionIdentity.build(
        repository_revision=RepositoryRevision.model_validate_json(json.dumps(revision)),
        **{
            name: getattr(identity, name)
            for name in (
                "stage_catalogue",
                "workflow",
                "policy",
                "configuration",
                "provider_profile",
                "capability_profile",
                "egress_profile",
            )
        },
    )
    data["execution_identity"] = rebuilt.model_dump(mode="json")
    request = ModelRequest.model_validate_json(json.dumps(data))
    backend = ProductDiscoveryBackend(
        executor=backend._executor,
        catalogue=catalogue.anchors,
        rule_ids=frozenset({"rule-sqli"}),
        content_key=b"p" * 32,
    )
    producer = ProducerRef(
        schema_version="0.2.0",
        producer_id="model-native-discovery",
        producer_version="1.0.0",
        producer_sha256="a" * 64,
    )
    plan = ModelNativeDiscoveryPlan(
        receipt_id="native-receipt",
        request=request,
        preflight_eligibility=PreflightEligibility.ELIGIBLE,
        scope=RepositoryToolScope(
            request.tenant_id,
            "repo-a",
            head,
            (path,),
            tuple(sorted(anchor.evidence_id for anchor in catalogue.anchors)),
        ),
        tool_budget=RepositoryToolBudget(
            request.budget.max_repository_calls,
            request.budget.max_context_bytes,
            request.budget.max_input_tokens,
        ),
        producer=producer,
    )
    outcome = run_model_native_discovery(
        plan, repository=catalogue.repository_view(), backend=backend
    )
    assert outcome.receipt.model_call_status is ModelCallStatus.SUCCEEDED
    assert outcome.receipt.budget_usage.repository_calls_used == 1
    assert len(outcome.candidates) == 1
    assert len(endpoint.requests) == 1
    graph = catalogue.evidence_graph(
        graph_id="native-graph", candidates=outcome.candidates, producer=producer
    )
    assert len(graph.evidence) == 1
    assert graph.evidence[0].location == root.location
    package = build_evidence_package(graph, outcome.candidates[0].candidate_id)
    assert package.selected[0].evidence_sha256 == graph.evidence[0].evidence_sha256


DiscoveryComposition = tuple[
    ProductDiscoveryBackend,
    RepositoryToolSession,
    ModelRequest,
    _LocalEndpoint,
    ScriptedResolver,
]


class _MutableObservation(Protocol):
    package: EvidencePackage


def _composition(
    monkeypatch: pytest.MonkeyPatch,
    *,
    policy_name: str = "egress.valid.private-model-source.json",
    body: bytes | None = None,
) -> DiscoveryComposition:
    endpoint = _LocalEndpoint(status=200, body=_success_body() if body is None else body)
    endpoint.install(monkeypatch)
    profile = _profile("valid.local-openai-compatible.json")
    policy = _policy(policy_name)
    original = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    material = original.model_dump(mode="json")
    material["output_schema"] = MODEL_NATIVE_DISCOVERY_WIRE_PIN.model_dump(mode="json")
    material["prompt"] = PRODUCT_DISCOVERY_PROMPT_PIN.model_dump(mode="json")
    request = ModelRequest.model_validate_json(json.dumps(material))
    registry = ProviderProfileRegistry((profile,))
    resolver = ScriptedResolver(*(("127.0.0.1",),) * 8)
    executor = AuthorizedLocalModelExecutor(
        harness=AuthorizedProviderHarness(
            model_issuer=_issuer(profile, policy),
            endpoint_issuer=EndpointAuthorizationIssuer(provider_registry=registry),
        ),
        registry=registry,
        profile=profile,
        policy=policy,
        resolver=resolver,
        connector=OpenAICompatibleLocalHttpConnector(profile=profile),
        preflight=lambda selected: _preflight_request(selected, dict(_semantic_cases()[0])),
        now=lambda: 100.0,
    )
    source = b"# public source fixture\n"
    index = _build(source, repository_id="repo-a")
    artifact = ArtifactRef(
        schema_version="0.2.0",
        tenant_id=request.tenant_id,
        content_id="kid:public-source-a",
        content_sha256=hashlib.sha256(source).hexdigest(),
        size_bytes=len(source),
        data_class=DataClass.CONFIDENTIAL_SOURCE,
    )
    location = SourceLocation.model_validate(
        {
            "schema_version": "0.2.0",
            "path": index.path,
            "start": {"schema_version": "0.2.0", "line": 1, "column": 1},
            "end": {"schema_version": "0.2.0", "line": 1, "column": 20},
            "content_sha256": artifact.content_sha256,
        }
    )
    anchor = DiscoveryEvidence(
        evidence_id="evidence-a",
        tenant_id=request.tenant_id,
        head_sha=request.head_sha,
        location=location,
        source_artifact=artifact,
        read_artifact=artifact,
        request=RepositoryToolRequest(
            RepositoryTool.READ_RANGE,
            ReadRangeArguments(TOOL_ARGUMENT_SCHEMA_VERSION, request.head_sha, index.path, 1, 1),
        ),
    )
    guard = RepositoryToolGuard(
        scope=RepositoryToolScope(
            request.tenant_id, "repo-a", request.head_sha, (index.path,), ("evidence-a",)
        ),
        budget=RepositoryToolBudget(8, 65536, 3072),
    )
    tools = RepositoryToolSession(guard=guard, backend=SealedRepositoryView((index,)))
    backend = ProductDiscoveryBackend(
        executor=executor,
        catalogue=(anchor,),
        rule_ids=frozenset({"rule-sqli"}),
        content_key=b"p" * 32,
    )
    return backend, tools, request, endpoint, resolver


def test_real_harness_completed_zero_retains_valid_success(monkeypatch: pytest.MonkeyPatch) -> None:
    backend, tools, request, endpoint, _ = _composition(monkeypatch)
    result = backend.discover(request=request, tools=tools)
    assert result.model_result.status is ModelCallStatus.SUCCEEDED
    assert result.candidates == ()
    assert result.model_result.usage.repository_calls == 1
    assert len(endpoint.requests) == 1
    assert (
        ModelCallResult.model_validate_json(result.model_result.model_dump_json())
        == result.model_result
    )


def test_runtime_sends_invocation_output_ceiling_without_mutating_shared_connector(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, tools, request, endpoint, _ = _composition(monkeypatch)
    original = backend._executor._connector
    assert isinstance(original, OpenAICompatibleLocalHttpConnector)
    data = request.model_dump(mode="json")
    data["budget"]["max_output_tokens"] = 8
    request = ModelRequest.model_validate_json(json.dumps(data))
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.SUCCEEDED
    assert json.loads(endpoint.requests[0][2])["max_tokens"] == 8
    assert backend._executor._connector is original
    assert original._max_output_tokens == 4096


def test_real_harness_native_candidate_is_host_derived(monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.loads(_success_body())
    body["choices"][0]["message"]["content"] = json.dumps(
        {
            "candidates": [
                {
                    "rule_id": "rule-sqli",
                    "root_evidence_id": "evidence-a",
                    "evidence_ids": ["evidence-a"],
                }
            ]
        }
    )
    backend, tools, request, endpoint, _ = _composition(monkeypatch, body=json.dumps(body).encode())
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.SUCCEEDED
    assert len(outcome.candidates) == 1
    assert outcome.candidates[0].candidate_id.startswith("candidate:")
    assert outcome.candidates[0].evidence_ids == ("evidence-a",)
    assert len(endpoint.requests) == 1


@pytest.mark.parametrize("status", [ModelCallStatus.INVALID_SCHEMA, ModelCallStatus.REFUSED])
def test_real_harness_non_success_retains_no_candidates_or_provenance(
    monkeypatch: pytest.MonkeyPatch, status: ModelCallStatus
) -> None:
    body = json.loads(
        _success_body(refusal="refused" if status is ModelCallStatus.REFUSED else None)
    )
    if status is ModelCallStatus.INVALID_SCHEMA:
        body["choices"][0]["message"]["content"] = '{"candidates":"bad"}'
    backend, tools, request, _, _ = _composition(monkeypatch, body=json.dumps(body).encode())
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is status
    assert outcome.candidates == ()
    assert outcome.model_result.content_provenance is None
    assert (
        ModelCallResult.model_validate_json(outcome.model_result.model_dump_json())
        == outcome.model_result
    )


def test_real_harness_preflight_denial_has_zero_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    backend, tools, request, endpoint, resolver = _composition(
        monkeypatch, policy_name="egress.valid.air-gap.json"
    )
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.GUARDRAIL_BLOCKED
    assert tools.calls_used == 0
    assert endpoint.requests == []
    assert endpoint.sockets == []
    assert resolver.calls == []


def test_wrong_output_pin_is_rejected_before_harness_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, tools, request, endpoint, resolver = _composition(monkeypatch)
    material = json.loads(request.model_dump_json())
    material["output_schema"]["component_id"] = "unapproved-wire"
    wrong = ModelRequest.model_validate_json(json.dumps(material))
    with pytest.raises(ValueError, match="bindings"):
        backend.discover(request=wrong, tools=tools)
    assert tools.calls_used == 0
    assert endpoint.requests == []
    assert endpoint.sockets == []
    assert resolver.calls == []


def _auditor_composition(
    monkeypatch: pytest.MonkeyPatch,
    *,
    resolution: str = "valid",
    wrong_pin: bool = False,
    request_calls: int = 8,
    factory_delay: bool = False,
    observer: Callable[[ProductAuditorInvocationObservation], None] | None = None,
    body: bytes | None = None,
) -> tuple[ProductAuditorInvoker, EvidencePackage, _LocalEndpoint, RepositoryToolSession]:
    from dataclasses import replace

    from securecode_ai.adapters.product_model import AUDITOR_WIRE_PIN
    from securecode_ai.adapters.product_runtime import PRODUCT_AUDITOR_PROMPT_PIN
    from securecode_ai.contracts import EgressPolicyDocument, Evidence
    from securecode_ai.core.evidence_package import EvidenceContextRef
    from securecode_ai.core.tool_policy import ReadEvidenceArguments

    from tests.unit.test_product_model import _package
    from tests.unit.test_product_runtime import _evidence

    response_body = json.loads(_success_body()) if body is None else json.loads(body)
    response_body["choices"][0]["message"]["content"] = json.dumps(
        {
            "finding_verdict": "CONFIRMED",
            "cited_evidence_ids": ["evidence-a"],
            "rationale": "The selected source supports this public fixture.",
        }
    )
    discovery, _, base, endpoint, resolver = _composition(
        monkeypatch, body=json.dumps(response_body).encode()
    )
    profile = discovery._executor._profile
    policy_data = discovery._executor._policy.model_dump(mode="json")
    policy_data["policy_version"] = "1.0.1"
    policy_data["rules"][0]["purposes"].append(ModelPurpose.CANDIDATE_INVESTIGATION.value)
    policy = EgressPolicyDocument.model_validate_json(json.dumps(policy_data))
    original = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    content = b"# public auditor evidence\n"
    evidence_data = _evidence(content).model_dump(mode="json")
    evidence_data["tenant_id"] = base.tenant_id
    evidence_data["artifact_ref"]["tenant_id"] = base.tenant_id
    evidence_data["artifact_ref"]["content_id"] = "kid:auditor-source-a"
    evidence_data["evidence_kind"] = "source_location"
    evidence = Evidence.model_validate_json(json.dumps(evidence_data))
    artifact = evidence.artifact_ref
    assert artifact is not None
    selected = EvidenceContextRef(
        evidence_id=evidence.evidence_id,
        content_id=artifact.content_id,
        data_class=artifact.data_class,
        evidence_sha256=evidence.evidence_sha256,
        producer_id=evidence.producer.producer_id,
        producer_version=evidence.producer.producer_version,
        producer_sha256=evidence.producer.producer_sha256,
        context_bytes=len(content),
        estimated_tokens=1,
    )
    package = replace(
        _package(), tenant_id=base.tenant_id, selected=(selected,), total_context_bytes=len(content)
    )
    index = _build(content, repository_id="repo-a")
    tools = RepositoryToolSession(
        guard=RepositoryToolGuard(
            scope=RepositoryToolScope(
                base.tenant_id, "repo-a", base.head_sha, (index.path,), ("evidence-a",)
            ),
            budget=RepositoryToolBudget(8, 65536, 3072),
        ),
        backend=SealedRepositoryView(
            (index,), evidence=(("evidence-a", content, artifact.content_sha256),)
        ),
    )

    class Resolver:
        @property
        def calls_used(self) -> int:
            return tools.calls_used

        def resolve(
            self, selected_package: EvidencePackage, *, max_calls: int
        ) -> tuple[ResolvedModelEvidence, ...]:
            initial = tools.calls_used
            for _ in range(2 if resolution == "two_reads" else 1):
                if tools.calls_used - initial >= max_calls:
                    from securecode_ai.adapters.product_runtime import (
                        RepositoryContextBudgetExhausted,
                    )

                    raise RepositoryContextBudgetExhausted("resolver tool ceiling exhausted")
                output = tools.dispatch(
                    RepositoryToolRequest(
                        RepositoryTool.READ_EVIDENCE,
                        ReadEvidenceArguments(
                            TOOL_ARGUMENT_SCHEMA_VERSION, selected_package.head_sha, "evidence-a"
                        ),
                    )
                ).output
                assert output is not None
            assert output is not None
            item = ResolvedModelEvidence(evidence, output.content.encode())
            if resolution == "duplicate":
                return (item, item)
            if resolution == "missing":
                return ()
            return (item,)

    registry = ProviderProfileRegistry((profile,))
    case = dict(_semantic_cases()[0])
    case["required_purpose"] = ModelPurpose.CANDIDATE_INVESTIGATION.value
    executor = AuthorizedLocalModelExecutor(
        harness=AuthorizedProviderHarness(
            model_issuer=_issuer(profile, policy),
            endpoint_issuer=EndpointAuthorizationIssuer(provider_registry=registry),
        ),
        registry=registry,
        profile=profile,
        policy=policy,
        resolver=resolver,
        connector=OpenAICompatibleLocalHttpConnector(profile=profile),
        preflight=lambda request: _preflight_request(request, case),
        now=lambda: 100.0,
    )

    clock = [100.0]
    if factory_delay:
        executor._now = lambda: clock[0]

    def request_factory(
        selected_package: EvidencePackage, attempt: int, pin: object
    ) -> ModelRequest:
        if factory_delay:
            clock[0] += 6.0
        data = original.model_dump(mode="json")
        data.update(
            role="auditor",
            mode=ModelPurpose.CANDIDATE_INVESTIGATION.value,
            attempt=attempt,
            evidence=[ref.model_dump(mode="json") for ref in selected_package.model_evidence],
            prompt=PRODUCT_AUDITOR_PROMPT_PIN.model_dump(mode="json"),
            output_schema=AUDITOR_WIRE_PIN.model_dump(mode="json"),
        )
        data["budget"]["max_repository_calls"] = request_calls
        if wrong_pin:
            data["prompt"]["component_id"] = "wrong-prompt"
        return ModelRequest.model_validate_json(json.dumps(data))

    invoker = ProductAuditorInvoker(
        executor=executor,
        resolver=Resolver(),
        evidence_catalogue=(evidence,),
        content_key=b"a" * 32,
        request_factory=request_factory,
        **({"observer": observer} if observer is not None else {}),
    )
    return invoker, package, endpoint, tools


def test_real_auditor_harness_distinct_record_and_artifact_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoker, package, endpoint, tools = _auditor_composition(monkeypatch)
    catalogue_artifact = invoker._catalogue["evidence-a"].artifact_ref
    assert catalogue_artifact is not None
    assert package.selected[0].evidence_sha256 != catalogue_artifact.content_sha256
    result = invoker.invoke(package, attempt=1)
    assert result.response.model_call_status is ModelCallStatus.SUCCEEDED
    assert result.tool_calls == tools.calls_used == 1
    assert result.tokens_used == 15
    assert len(endpoint.requests) == 1


def test_actual_auditor_context_requests_compact_exact_json_instance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters.product_model import AUDITOR_WIRE_PIN, AUDITOR_WIRE_SCHEMA_JSON
    from securecode_ai.adapters.product_runtime import (
        _AUDITOR_INSTRUCTIONS,
        PRODUCT_AUDITOR_PROMPT_PIN,
    )

    invoker, package, endpoint, tools = _auditor_composition(monkeypatch)
    result = invoker.invoke(package, attempt=1)

    assert result.response.model_call_status is ModelCallStatus.SUCCEEDED
    assert result.response.schema_valid_result is True
    assert result.response.verdict is not None
    assert result.response.verdict.cited_evidence_ids == ("evidence-a",)
    assert result.tool_calls == tools.calls_used == 1
    context = json.loads(json.loads(endpoint.requests[0][2])["messages"][0]["content"])
    controls = context["trusted_controls"]
    assert controls["role"] == "auditor"
    assert controls["instructions"] == _AUDITOR_INSTRUCTIONS
    assert "one compact JSON object instance" in controls["instructions"]
    assert "exactly finding_verdict, cited_evidence_ids, and rationale" in controls["instructions"]
    assert (
        "schema definitions, metadata, source excerpts, Markdown, or extra text"
        in controls["instructions"]
    )
    assert "one rationale sentence of at most 20 words" in controls["instructions"]
    assert controls["output_schema"] == json.loads(AUDITOR_WIRE_SCHEMA_JSON)
    assert AUDITOR_WIRE_PIN.content_sha256 == hashlib.sha256(AUDITOR_WIRE_SCHEMA_JSON).hexdigest()
    template = {key: controls[key] for key in ("role", "instructions", "output_schema")}
    encoded = json.dumps(
        template, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    assert hashlib.sha256(encoded).hexdigest() == PRODUCT_AUDITOR_PROMPT_PIN.content_sha256


def test_auditor_scripted_length_remains_truncated_and_not_evaluated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = json.loads(_success_body())
    body["choices"][0]["finish_reason"] = "length"
    invoker, package, endpoint, tools = _auditor_composition(
        monkeypatch, body=json.dumps(body).encode()
    )

    result = invoker.invoke(package, attempt=1)

    assert result.response.model_call_status is ModelCallStatus.TRUNCATED
    assert result.response.schema_valid_result is False
    assert result.response.verdict is None
    assert result.tool_calls == tools.calls_used == 1
    assert len(endpoint.requests) == 1


def test_real_auditor_uses_production_guarded_evidence_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters.product_runtime import GuardedEvidenceResolver

    invoker, package, endpoint, tools = _auditor_composition(monkeypatch)
    invoker._resolver = GuardedEvidenceResolver(
        tools=tools, evidence=tuple(invoker._catalogue.values())
    )
    result = invoker.invoke(package, attempt=1)
    assert result.response.model_call_status is ModelCallStatus.SUCCEEDED
    assert result.tool_calls == tools.calls_used == 1
    assert len(endpoint.requests) == 1


def test_production_resolver_rejects_wrong_package_binding_before_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from securecode_ai.adapters.product_runtime import GuardedEvidenceResolver

    invoker, package, endpoint, tools = _auditor_composition(monkeypatch)
    resolver = GuardedEvidenceResolver(tools=tools, evidence=tuple(invoker._catalogue.values()))
    selected = replace(package.selected[0], evidence_sha256="f" * 64)
    altered = replace(package, selected=(selected,))
    with pytest.raises(ValueError, match="bindings"):
        resolver.resolve(altered, max_calls=1)
    assert tools.calls_used == 0
    assert endpoint.requests == []


@pytest.mark.parametrize("resolution", ["missing", "duplicate"])
def test_auditor_incomplete_resolution_sends_no_bytes(
    monkeypatch: pytest.MonkeyPatch, resolution: str
) -> None:
    invoker, package, endpoint, tools = _auditor_composition(monkeypatch, resolution=resolution)
    result = invoker.invoke(package, attempt=1)
    assert result.response.model_call_status is ModelCallStatus.PROVIDER_ERROR
    assert result.tool_calls == tools.calls_used == 1
    assert endpoint.requests == []


def test_auditor_wrong_prompt_factory_has_zero_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    invoker, package, endpoint, tools = _auditor_composition(monkeypatch, wrong_pin=True)
    with pytest.raises(ValueError, match="bindings"):
        invoker.invoke(package, attempt=1)
    assert tools.calls_used == 0
    assert endpoint.requests == []


class ContextDelayClock:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return 100.0 if self.calls <= 3 else 106.0


def test_discovery_context_deadline_stops_before_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    backend, tools, request, endpoint, _ = _composition(monkeypatch)
    backend._executor._now = ContextDelayClock()
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.BUDGET_EXHAUSTED
    assert outcome.model_result.usage.elapsed_ms == 6000
    assert outcome.model_result.usage.repository_calls == 1
    assert endpoint.requests == []
    assert endpoint.sockets == []


def test_auditor_context_deadline_counts_real_guard_read(monkeypatch: pytest.MonkeyPatch) -> None:
    invoker, package, endpoint, tools = _auditor_composition(monkeypatch)
    invoker._executor._now = ContextDelayClock()
    outcome = invoker.invoke(package, attempt=1)
    assert outcome.response.model_call_status is ModelCallStatus.BUDGET_EXHAUSTED
    assert outcome.elapsed_ms == 6000
    assert outcome.tool_calls == tools.calls_used == 1
    assert endpoint.requests == []
    assert endpoint.sockets == []


def test_actual_sent_context_separates_pinned_controls_from_untrusted_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, tools, request, endpoint, _ = _composition(monkeypatch)
    assert (
        backend.discover(request=request, tools=tools).model_result.status
        is ModelCallStatus.SUCCEEDED
    )
    native_payload = json.loads(endpoint.requests[0][2])
    context = json.loads(native_payload["messages"][0]["content"])
    controls = context["trusted_controls"]
    assert controls["allowed_rule_ids"] == ["rule-sqli"]
    assert "Independently inspect" in controls["instructions"]
    template = {key: controls[key] for key in ("role", "instructions", "output_schema")}
    encoded = json.dumps(
        template, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    assert hashlib.sha256(encoded).hexdigest() == request.prompt.content_sha256
    assert context["untrusted_evidence"][0]["instruction_authority"] == "NONE"


def test_candidate_ids_do_not_collide_on_admitted_delimiters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    from securecode_ai.adapters.product_model import ModelNativeDiscoveryWireCandidate
    from securecode_ai.adapters.product_runtime import _draft

    backend, _, request, _, _ = _composition(monkeypatch)
    original = backend._catalogue[0]
    catalogue = {
        "c": replace(original, evidence_id="c"),
        "b:c": replace(original, evidence_id="b:c"),
    }
    first = _draft(ModelNativeDiscoveryWireCandidate("a:b", "c", ("c",)), catalogue, request)
    second = _draft(ModelNativeDiscoveryWireCandidate("a", "b:c", ("b:c",)), catalogue, request)
    assert first.candidate_id != second.candidate_id
    assert first.source_id != second.source_id


def test_factory_deadline_expires_before_reads_sockets_or_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoker, package, endpoint, tools = _auditor_composition(monkeypatch, factory_delay=True)
    outcome = invoker.invoke(package, attempt=1)
    assert outcome.response.model_call_status is ModelCallStatus.BUDGET_EXHAUSTED
    assert outcome.elapsed_ms == 6000
    assert tools.calls_used == outcome.tool_calls == 0
    assert endpoint.sockets == []
    assert endpoint.requests == []


def test_narrow_discovery_tool_budget_denies_second_read_and_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    backend, tools, request, endpoint, _ = _composition(monkeypatch)
    original = backend._catalogue[0]
    empty = original.read_artifact.model_dump(mode="json")
    empty.update(
        content_id="kid:empty-window", content_sha256=hashlib.sha256(b"").hexdigest(), size_bytes=0
    )
    location = original.location.model_dump(mode="json")
    location["start"].update(line=2, column=1)
    location["end"].update(line=2, column=1)
    backend._catalogue += (
        replace(
            original,
            evidence_id="evidence-b",
            read_artifact=ArtifactRef.model_validate_json(json.dumps(empty)),
            location=SourceLocation.model_validate_json(json.dumps(location)),
            request=RepositoryToolRequest(
                RepositoryTool.READ_RANGE,
                ReadRangeArguments(
                    TOOL_ARGUMENT_SCHEMA_VERSION, request.head_sha, original.location.path, 2, 2
                ),
            ),
        ),
    )
    data = json.loads(request.model_dump_json())
    data["budget"]["max_repository_calls"] = 1
    request = ModelRequest.model_validate_json(json.dumps(data))
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.BUDGET_EXHAUSTED
    assert outcome.model_result.usage.repository_calls == tools.calls_used == 1
    assert endpoint.sockets == []
    assert endpoint.requests == []


def test_narrow_auditor_tool_allowance_binds_actual_guard_before_second_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invoker, package, endpoint, tools = _auditor_composition(
        monkeypatch, resolution="two_reads", request_calls=1
    )
    outcome = invoker.invoke(package, attempt=1)
    assert outcome.response.model_call_status is ModelCallStatus.BUDGET_EXHAUSTED
    assert outcome.tool_calls == tools.calls_used == 1
    assert endpoint.sockets == []
    assert endpoint.requests == []


def test_shared_window_aliases_use_one_guard_read_and_one_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    backend, tools, request, endpoint, _ = _composition(monkeypatch)
    backend._catalogue += (replace(backend._catalogue[0], evidence_id="evidence-b"),)
    data = json.loads(request.model_dump_json())
    data["budget"]["max_repository_calls"] = 1
    request = ModelRequest.model_validate_json(json.dumps(data))
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.SUCCEEDED
    assert outcome.model_result.usage.repository_calls == tools.calls_used == 1
    sent = json.loads(endpoint.requests[0][2])
    context = json.loads(sent["messages"][0]["content"])
    assert len(context["untrusted_evidence"]) == 1
    assert context["untrusted_evidence"][0]["evidence_ids"] == ["evidence-a", "evidence-b"]


def test_discovery_context_binds_each_alias_to_source_geometry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    backend, tools, request, endpoint, _ = _composition(monkeypatch)
    original = backend._catalogue[0]
    changed = original.location.model_dump(mode="json")
    changed["start"]["column"] = 2
    second = SourceLocation.model_validate_json(json.dumps(changed))
    backend._catalogue += (replace(original, evidence_id="evidence-b", location=second),)
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.SUCCEEDED
    assert tools.calls_used == 1
    sent = json.loads(endpoint.requests[0][2])
    context = json.loads(sent["messages"][0]["content"])
    locations = context["untrusted_source_locations"]
    assert [item["evidence_id"] for item in locations] == ["evidence-a", "evidence-b"]
    assert all(item["instruction_authority"] == "NONE" for item in locations)
    assert all(item["content_id"] == original.read_artifact.content_id for item in locations)
    assert locations[0]["location"] == original.location.model_dump(mode="json")
    assert locations[1]["location"] == second.model_dump(mode="json")


def test_conflicting_content_identity_stops_before_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    backend, tools, request, endpoint, _ = _composition(monkeypatch)
    original = backend._catalogue[0]
    empty = original.read_artifact.model_dump(mode="json")
    empty.update(
        content_id=original.read_artifact.content_id,
        content_sha256=hashlib.sha256(b"").hexdigest(),
        size_bytes=0,
    )
    location = original.location.model_dump(mode="json")
    location["start"].update(line=2, column=1)
    location["end"].update(line=2, column=1)
    backend._catalogue += (
        replace(
            original,
            evidence_id="evidence-b",
            read_artifact=ArtifactRef.model_validate_json(json.dumps(empty)),
            location=SourceLocation.model_validate_json(json.dumps(location)),
            request=RepositoryToolRequest(
                RepositoryTool.READ_RANGE,
                ReadRangeArguments(
                    TOOL_ARGUMENT_SCHEMA_VERSION, request.head_sha, original.location.path, 2, 2
                ),
            ),
        ),
    )
    data = json.loads(request.model_dump_json())
    data["budget"]["max_repository_calls"] = 8
    request = ModelRequest.model_validate_json(json.dumps(data))
    outcome = backend.discover(request=request, tools=tools)
    assert outcome.model_result.status is ModelCallStatus.PROVIDER_ERROR
    assert outcome.model_result.usage.repository_calls == tools.calls_used == 2
    assert endpoint.sockets == []
    assert endpoint.requests == []


def test_auditor_observation_binds_actual_request_package_and_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations: list[ProductAuditorInvocationObservation] = []
    invoker, package, endpoint, tools = _auditor_composition(
        monkeypatch, observer=observations.append
    )
    result = invoker.invoke(package, attempt=1)
    assert len(observations) == 1
    observation = observations[0]
    assert observation.request.evidence == package.model_evidence
    assert observation.package == package
    assert observation.package is not package
    assert (
        observation.usage_before_collection.input_tokens
        + observation.usage_before_collection.output_tokens
        == result.tokens_used
    )
    assert (
        observation.usage_before_collection.repository_calls
        == result.tool_calls
        == tools.calls_used
    )
    assert observation.usage_before_collection.elapsed_ms == result.elapsed_ms
    assert observation.model_call_status_before_collection == result.response.model_call_status
    assert observation.schema_valid_result_before_collection == result.response.schema_valid_result
    assert "public auditor evidence" not in repr(observation)
    assert "selected source supports" not in repr(observation)
    assert len(endpoint.requests) == 1
    with pytest.raises(AttributeError):
        cast(_MutableObservation, observation).package = package


def test_auditor_observation_failure_is_non_success_with_measured_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations: list[ProductAuditorInvocationObservation] = []

    def failing_sink(observation: ProductAuditorInvocationObservation) -> None:
        observations.append(observation)
        raise RuntimeError("collector failed")

    invoker, package, _, tools = _auditor_composition(monkeypatch, observer=failing_sink)
    result = invoker.invoke(package, attempt=1)
    assert result.response.model_call_status is ModelCallStatus.GUARDRAIL_BLOCKED
    assert result.response.schema_valid_result is False
    assert result.tokens_used == 15
    assert result.tool_calls == tools.calls_used == 1
    assert result.elapsed_ms == observations[0].usage_before_collection.elapsed_ms


def test_invalid_auditor_request_creates_no_observation_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations: list[ProductAuditorInvocationObservation] = []
    invoker, package, endpoint, tools = _auditor_composition(
        monkeypatch, wrong_pin=True, observer=observations.append
    )
    with pytest.raises(ValueError, match="bindings"):
        invoker.invoke(package, attempt=1)
    assert observations == []
    assert endpoint.requests == []
    assert tools.calls_used == 0


def test_failed_auditor_context_observation_retains_real_guard_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observations: list[ProductAuditorInvocationObservation] = []
    invoker, package, endpoint, tools = _auditor_composition(
        monkeypatch, resolution="duplicate", observer=observations.append
    )
    result = invoker.invoke(package, attempt=1)
    assert result.response.model_call_status is not ModelCallStatus.SUCCEEDED
    assert observations[0].model_call_status_before_collection == result.response.model_call_status
    assert observations[0].schema_valid_result_before_collection is False
    assert (
        observations[0].usage_before_collection.repository_calls
        == result.tool_calls
        == tools.calls_used
        == 1
    )
    assert endpoint.requests == []


def test_noncallable_auditor_observer_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValueError, match="invoker"):
        _auditor_composition(
            monkeypatch,
            observer=cast(Callable[[ProductAuditorInvocationObservation], None], 1),
        )


def test_auditor_observer_runs_after_ephemeral_payload_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters.model import EphemeralStructuredPayload

    closed_payloads: list[EphemeralStructuredPayload] = []
    observed: list[ProductAuditorInvocationObservation] = []
    original_close = EphemeralStructuredPayload.close

    def record_close(payload: EphemeralStructuredPayload) -> None:
        original_close(payload)
        closed_payloads.append(payload)

    def sink(observation: ProductAuditorInvocationObservation) -> None:
        assert closed_payloads
        for payload in closed_payloads:
            with pytest.raises(ValueError, match="closed"):
                payload.reveal_for(observation.request.request_id)
        observed.append(observation)

    monkeypatch.setattr(EphemeralStructuredPayload, "close", record_close)
    invoker, package, _, _ = _auditor_composition(monkeypatch, observer=sink)
    result = invoker.invoke(package, attempt=1)
    assert result.response.model_call_status is ModelCallStatus.SUCCEEDED
    assert len(observed) == 1


@pytest.mark.parametrize(
    ("delay", "raises", "expected"),
    [
        (0.25, False, ModelCallStatus.SUCCEEDED),
        (0.25, True, ModelCallStatus.GUARDRAIL_BLOCKED),
        (6.0, False, ModelCallStatus.BUDGET_EXHAUSTED),
        (6.0, True, ModelCallStatus.BUDGET_EXHAUSTED),
    ],
)
def test_auditor_collector_time_is_counted_and_deadline_enforced(
    monkeypatch: pytest.MonkeyPatch,
    delay: float,
    raises: bool,
    expected: ModelCallStatus,
) -> None:
    clock = [100.0]
    observations: list[ProductAuditorInvocationObservation] = []

    def sink(observation: ProductAuditorInvocationObservation) -> None:
        observations.append(observation)
        clock[0] += delay
        if raises:
            raise RuntimeError("collector failed after work")

    invoker, package, _, tools = _auditor_composition(monkeypatch, observer=sink)
    invoker._executor._now = lambda: clock[0]
    result = invoker.invoke(package, attempt=1)
    assert result.response.model_call_status is expected
    assert result.elapsed_ms == int(delay * 1000)
    assert observations[0].usage_before_collection.elapsed_ms == 0
    assert result.tokens_used == 15
    assert result.tool_calls == tools.calls_used == 1
