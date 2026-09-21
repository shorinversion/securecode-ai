"""Product candidate flow through real Core/harness with scripted sockets only."""

import json
from collections.abc import Callable
from typing import TypedDict

import pytest
from securecode_ai.adapters.native_sources import (
    NativeSourceCatalogue,
    build_native_source_catalogue,
)
from securecode_ai.adapters.product_runtime import (
    GuardedEvidenceResolver,
    ProductAuditorInvoker,
    ProductDiscoveryBackend,
)
from securecode_ai.adapters.product_scan import (
    ProductCandidateFlow,
    ProductCompositionFailure,
    run_product_candidate_flow,
)
from securecode_ai.adapters.product_scanner import (
    ProductDeterministicScanResult,
    build_product_auditor_tools,
)
from securecode_ai.contracts import (
    AuditRunOutcome,
    ModelCallStatus,
    ModelRequest,
    PreflightEligibility,
    ProducerRef,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.evidence_package import EvidencePackage
from securecode_ai.core.investigation import AuditorInvestigationReceipt, InvestigationBudget
from securecode_ai.core.model_discovery import ModelNativeDiscoveryPlan, RepositoryToolSession
from securecode_ai.core.tool_policy import (
    RepositoryToolBudget,
    RepositoryToolScope,
)

from tests.integration.test_product_runtime_harness import _auditor_composition, _composition
from tests.unit.test_endpoint_policy import ScriptedResolver
from tests.unit.test_native_sources import repository
from tests.unit.test_openai_compatible_local import _LocalEndpoint, _success_body


class _FlowObserved(TypedDict):
    scanner_calls: int
    factory_calls: int
    auditor_endpoint: _LocalEndpoint | None
    auditor_tools: RepositoryToolSession | None


ProductScanner = Callable[
    [NativeSourceCatalogue, ProducerRef], EvidenceGraph | ProductDeterministicScanResult
]


def _bind_head(request: ModelRequest, head: str) -> ModelRequest:
    data = request.model_dump(mode="json")
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
    data.update(head_sha=head, execution_identity=rebuilt.model_dump(mode="json"))
    return ModelRequest.model_validate_json(json.dumps(data))


def _flow(
    monkeypatch: pytest.MonkeyPatch,
    *,
    count: int = 1,
    native_fault: bool = False,
    auditor_fault: bool = False,
    scanner_fault: bool = False,
    factory_fault: bool = False,
    idempotency_collision: bool = False,
    scanner: ProductScanner | None = None,
) -> tuple[ProductCandidateFlow | ProductCompositionFailure, _LocalEndpoint, _FlowObserved]:
    reader, head, _ = repository("a.py", b"execute(value)\n")
    initial, _, request, _, _ = _composition(monkeypatch)
    catalogue = build_native_source_catalogue(
        reader=reader,
        head_sha=head,
        tenant_id=request.tenant_id,
        repository_id="repo-a",
        content_key=b"p" * 32,
    )
    body = json.loads(_success_body())
    body["choices"][0]["message"]["content"] = json.dumps(
        {
            "candidates": [
                {
                    "rule_id": "rule-sqli",
                    "root_evidence_id": anchor.evidence_id,
                    "evidence_ids": [anchor.evidence_id],
                }
                for anchor in catalogue.anchors[:count]
            ]
        }
    )
    if native_fault:
        body["choices"][0]["message"]["content"] = '{"candidates":"invalid"}'
    initial, _, request, native_endpoint, _ = _composition(
        monkeypatch, body=json.dumps(body).encode()
    )
    request = _bind_head(request, head)
    backend = ProductDiscoveryBackend(
        executor=initial._executor,
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
    scope = RepositoryToolScope(
        request.tenant_id,
        "repo-a",
        head,
        ("a.py",),
        tuple(sorted(anchor.evidence_id for anchor in catalogue.anchors)),
    )
    plan = ModelNativeDiscoveryPlan(
        receipt_id="product-native-receipt",
        request=request,
        preflight_eligibility=PreflightEligibility.ELIGIBLE,
        scope=scope,
        tool_budget=RepositoryToolBudget(
            request.budget.max_repository_calls,
            request.budget.max_context_bytes,
            request.budget.max_input_tokens,
        ),
        producer=producer,
    )
    observed = _FlowObserved(
        scanner_calls=0,
        factory_calls=0,
        auditor_endpoint=None,
        auditor_tools=None,
    )
    scanner_result: ProductDeterministicScanResult | None = None

    def deterministic(
        source: NativeSourceCatalogue,
    ) -> EvidenceGraph | ProductDeterministicScanResult:
        nonlocal scanner_result
        observed["scanner_calls"] += 1
        assert source is catalogue
        if scanner_fault:
            raise RuntimeError("untrusted scanner detail is not retained")
        if scanner is not None:
            result = scanner(catalogue, producer)
            if isinstance(result, ProductDeterministicScanResult):
                scanner_result = result
            return result
        return EvidenceGraph(
            graph_id="deterministic-zero",
            tenant_id=request.tenant_id,
            head_sha=head,
            candidates=(),
            evidence=(),
            edges=(),
        )

    def auditor_factory(graph: EvidenceGraph) -> ProductAuditorInvoker:
        observed["factory_calls"] += 1
        if factory_fault:
            raise RuntimeError("unavailable profile")
        invoker, _, endpoint, _ = _auditor_composition(monkeypatch)
        # Each authorized invocation rechecks DNS at multiple boundaries.
        # Provision the scripted resolver for all candidates, not just one call.
        scripted_resolver = invoker._executor._resolver
        assert isinstance(scripted_resolver, ScriptedResolver)
        scripted_resolver.answers = [("127.0.0.1",)] * 64
        observed["auditor_endpoint"] = endpoint
        invoker._catalogue = {record.evidence_id: record for record in graph.evidence}
        tools = build_product_auditor_tools(
            catalogue,
            graph,
            budget=RepositoryToolBudget(8, 65536, 65536),
            deterministic=scanner_result,
        )
        observed["auditor_tools"] = tools
        invoker._resolver = GuardedEvidenceResolver(tools=tools, evidence=graph.evidence)
        prior = invoker._request_factory

        def factory(package: EvidencePackage, attempt: int, pin: object) -> ModelRequest:
            candidate_request = _bind_head(prior(package, attempt, pin), head)
            data = candidate_request.model_dump(mode="json")
            data["request_id"] = "auditor-" + package.candidate_id + "-" + str(attempt)
            data["idempotency_key"] = (
                "conflicting-public-fixture" if idempotency_collision else data["request_id"]
            )
            candidate_request = ModelRequest.model_validate_json(json.dumps(data))
            reply = json.loads(_success_body())
            reply["choices"][0]["message"]["content"] = json.dumps(
                {
                    "finding_verdict": "CONFIRMED",
                    "cited_evidence_ids": [item.evidence_id for item in package.selected],
                    "rationale": "public fixture source is selected",
                }
            )
            if auditor_fault:
                reply["choices"][0]["message"]["content"] = '{"finding_verdict":"invented"}'
            endpoint.response = _LocalEndpoint(status=200, body=json.dumps(reply).encode()).response
            return candidate_request

        invoker._request_factory = factory

        return invoker

    result = run_product_candidate_flow(
        catalogue=catalogue,
        model_plan=plan,
        model_backend=backend,
        deterministic_scanner=deterministic,
        auditor_factory=auditor_factory,
        investigation_budget=InvestigationBudget(2, 8192, 64, 60000),
    )
    return result, native_endpoint, observed


def _require_flow(
    result: ProductCandidateFlow | ProductCompositionFailure,
) -> ProductCandidateFlow:
    assert isinstance(result, ProductCandidateFlow)
    return result


def _candidate_flow(
    monkeypatch: pytest.MonkeyPatch, *, count: int
) -> tuple[ProductCandidateFlow, _LocalEndpoint, _FlowObserved]:
    result, endpoint, observed = _flow(monkeypatch, count=count)
    return _require_flow(result), endpoint, observed


def test_zero_scanner_does_not_skip_native_or_any_candidate_auditor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, native_endpoint, observed = _flow(monkeypatch, count=2)
    result = _require_flow(result)
    assert observed["scanner_calls"] == 1
    assert len(native_endpoint.requests) == 1
    assert len(result.graph.candidates) == len(result.investigations) == 2
    assert all(not receipt.is_indeterminate for receipt in result.investigations)
    tools = observed["auditor_tools"]
    endpoint = observed["auditor_endpoint"]
    assert tools is not None and tools.calls_used == 2
    assert endpoint is not None and len(endpoint.requests) == 2
    assert result.required_terminal_outcome is None  # Stage completeness never publishes PASS.


def test_completed_zero_still_executes_both_lanes_and_has_no_orphans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, endpoint, observed = _flow(monkeypatch, count=0)
    result = _require_flow(result)
    assert result.discovery.is_completed_zero
    assert observed["scanner_calls"] == 1
    assert observed["factory_calls"] == 0
    assert len(endpoint.requests) == 1
    assert result.graph.evidence == ()
    assert result.graph.candidates == ()
    assert result.investigations == ()
    assert result.required_terminal_outcome is None


def test_conflicting_candidate_idempotency_retains_both_receipts_without_second_send(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, _, observed = _flow(monkeypatch, count=2, idempotency_collision=True)
    result = _require_flow(result)
    assert len(result.investigations) == len(result.graph.candidates) == 2
    first, second = result.investigations
    assert isinstance(first, AuditorInvestigationReceipt)
    assert isinstance(second, AuditorInvestigationReceipt)
    assert first.final_model_call_status is ModelCallStatus.SUCCEEDED
    assert second.final_model_call_status is ModelCallStatus.PROVIDER_ERROR
    assert result.required_terminal_outcome is AuditRunOutcome.INDETERMINATE
    endpoint = observed["auditor_endpoint"]
    tools = observed["auditor_tools"]
    assert endpoint is not None and tools is not None
    assert len(endpoint.requests) == tools.calls_used == 1


def test_package_budget_failure_keeps_identity_and_continues_next_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters import product_scan
    from securecode_ai.adapters.product_scan import ProductCandidatePreparationFailure
    from securecode_ai.core.evidence_package import EvidencePackageLimits
    from securecode_ai.core.evidence_package import build_evidence_package as original

    calls: list[str] = []

    def constrained_first(graph: EvidenceGraph, candidate_id: str) -> EvidencePackage:
        calls.append(candidate_id)
        if len(calls) == 1:
            return original(graph, candidate_id, limits=EvidencePackageLimits(max_context_bytes=1))
        return original(graph, candidate_id)

    monkeypatch.setattr(product_scan, "build_evidence_package", constrained_first)
    result, _, observed = _flow(monkeypatch, count=2)
    result = _require_flow(result)
    assert len(calls) == len(result.investigations) == len(result.graph.candidates) == 2
    assert type(result.investigations[0]) is ProductCandidatePreparationFailure
    second = result.investigations[1]
    assert isinstance(second, AuditorInvestigationReceipt)
    assert second.final_model_call_status is ModelCallStatus.SUCCEEDED
    assert result.required_terminal_outcome is AuditRunOutcome.INDETERMINATE
    endpoint = observed["auditor_endpoint"]
    assert endpoint is not None and len(endpoint.requests) == 1


def test_merge_collision_retains_lane_candidates_and_explicit_indeterminate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters.product_scan import ProductCompositionFailure
    from securecode_ai.contracts import CandidateOrigin, DiscoveryCandidate, Evidence

    from tests.unit.test_product_scan import lane

    def scanner(catalogue: NativeSourceCatalogue, producer: ProducerRef) -> EvidenceGraph:
        graph = lane(CandidateOrigin.DETERMINISTIC, evidence_id=catalogue.anchors[0].evidence_id)
        tenant = catalogue.anchors[0].tenant_id
        candidate = graph.candidates[0].model_dump(mode="json")
        candidate.update(tenant_id=tenant, head_sha=catalogue.snapshot.head_sha)
        record = graph.evidence[0].model_dump(mode="json")
        record.update(tenant_id=tenant, head_sha=catalogue.snapshot.head_sha)
        record["artifact_ref"]["tenant_id"] = tenant
        return EvidenceGraph(
            graph_id=graph.graph_id,
            tenant_id=tenant,
            head_sha=catalogue.snapshot.head_sha,
            candidates=(DiscoveryCandidate.model_validate_json(json.dumps(candidate)),),
            evidence=(Evidence.model_validate_json(json.dumps(record)),),
            edges=graph.edges,
        )

    result, endpoint, observed = _flow(monkeypatch, scanner=scanner)
    assert type(result) is ProductCompositionFailure
    assert result.required_terminal_outcome is AuditRunOutcome.INDETERMINATE
    assert len(result.native.candidates) == len(result.deterministic.candidates) == 1
    assert len(endpoint.requests) == observed["scanner_calls"] == 1
    assert observed["factory_calls"] == 0


@pytest.mark.parametrize(
    "fault", ["native_fault", "auditor_fault", "scanner_fault", "factory_fault"]
)
def test_mandatory_faults_never_become_clean_stage(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    result, endpoint, observed = _flow(
        monkeypatch,
        native_fault=fault == "native_fault",
        auditor_fault=fault == "auditor_fault",
        scanner_fault=fault == "scanner_fault",
        factory_fault=fault == "factory_fault",
    )
    result = _require_flow(result)
    assert len(endpoint.requests) == 1
    assert observed["scanner_calls"] == 1
    assert result.required_terminal_outcome is AuditRunOutcome.INDETERMINATE
    assert len(result.investigations) == len(result.graph.candidates)
    if fault == "native_fault":
        assert result.discovery.receipt.model_call_status is ModelCallStatus.INVALID_SCHEMA
    elif fault == "factory_fault":
        first = result.investigations[0]
        assert isinstance(first, AuditorInvestigationReceipt)
        assert first.final_model_call_status is ModelCallStatus.PROVIDER_ERROR
        assert observed["auditor_endpoint"] is None
