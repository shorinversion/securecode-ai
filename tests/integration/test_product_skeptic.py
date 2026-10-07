"""Skeptic review port exercised through the authorized provider harness."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace

import pytest
from securecode_ai.adapters import (
    AuthorizedProviderHarness,
    EndpointAuthorizationIssuer,
    ProviderProfileRegistry,
)
from securecode_ai.adapters.model import (
    EphemeralStructuredPayload,
    ModelBoundaryExecution,
    PreparedModelContext,
)
from securecode_ai.adapters.product_review import run_product_candidate_review
from securecode_ai.adapters.product_runtime import (
    AuthorizedLocalModelExecutor,
    EvidenceResolver,
    GuardedEvidenceResolver,
    ResolvedModelEvidence,
)
from securecode_ai.adapters.product_scan import ProductCandidateFlow
from securecode_ai.adapters.product_skeptic import (
    PRODUCT_SKEPTIC_PROMPT_PIN,
    ProductSkepticReviewPort,
)
from securecode_ai.contracts import (
    ComponentPin,
    EgressPolicyDocument,
    FindingVerdict,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
)
from securecode_ai.core import StructuredPayloadValidator
from securecode_ai.core.classification import FindingSeverity
from securecode_ai.core.evidence_package import EvidencePackage, build_evidence_package
from securecode_ai.core.model_discovery import RepositoryToolSession
from securecode_ai.core.skeptic import AuditorSnapshot, SkepticObjectionKind, SkepticOutput

from tests.integration.test_product_runtime_harness import _auditor_composition
from tests.integration.test_product_scan_flow import _bind_head, _flow
from tests.unit.test_endpoint_policy import ScriptedResolver
from tests.unit.test_openai_compatible_local import _LocalEndpoint, _success_body
from tests.unit.test_provider_preflight import (
    _issuer,
    _preflight_request,
    _request,
    _semantic_cases,
)


def _snapshot(package: EvidencePackage, *, auditor_identity: str = "auditor-a") -> AuditorSnapshot:
    return AuditorSnapshot(
        candidate_id=package.candidate_id,
        candidate_version=package.candidate_version,
        head_sha=package.head_sha,
        auditor_identity=auditor_identity,
        auditor_output_sha256="a" * 64,
        model_call_status=ModelCallStatus.SUCCEEDED,
        finding_verdict=FindingVerdict.CONFIRMED,
        evidence_ids=tuple(item.evidence_id for item in package.selected),
    )


def _composition(
    monkeypatch: pytest.MonkeyPatch,
    *,
    payload: object | None = None,
    refusal: str | None = None,
    resolver_wrapper: Callable[[GuardedEvidenceResolver], EvidenceResolver] | None = None,
) -> tuple[
    ProductSkepticReviewPort,
    EvidencePackage,
    _LocalEndpoint,
    RepositoryToolSession,
    AuthorizedLocalModelExecutor,
]:
    invoker, package, endpoint, tools = _auditor_composition(monkeypatch)
    profile = invoker._executor._profile
    policy_data = invoker._executor._policy.model_dump(mode="json")
    policy_data["policy_version"] = "1.0.2"
    policy_data["rules"][0]["purposes"].append(ModelPurpose.SKEPTIC_REVIEW.value)
    policy = EgressPolicyDocument.model_validate_json(json.dumps(policy_data))
    registry = ProviderProfileRegistry((profile,))
    case = dict(_semantic_cases()[0])
    case["required_purpose"] = ModelPurpose.SKEPTIC_REVIEW.value
    executor = AuthorizedLocalModelExecutor(
        harness=AuthorizedProviderHarness(
            model_issuer=_issuer(profile, policy),
            endpoint_issuer=EndpointAuthorizationIssuer(provider_registry=registry),
        ),
        registry=registry,
        profile=profile,
        policy=policy,
        resolver=ScriptedResolver(*(("127.0.0.1",),) * 8),
        connector=invoker._executor._connector,
        preflight=lambda request: _preflight_request(request, case),
        now=lambda: 100.0,
    )
    base = _request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY)
    body = json.loads(_success_body(refusal=refusal))
    body["choices"][0]["message"]["content"] = json.dumps(
        payload
        if payload is not None
        else {
            "finding_verdict": FindingVerdict.REJECTED_WITH_EVIDENCE.value,
            "objections": [
                {
                    "kind": SkepticObjectionKind.CONTRADICTORY_EVIDENCE.value,
                    "evidence_ids": [package.selected[0].evidence_id],
                }
            ],
        }
    )
    endpoint.response = _LocalEndpoint(status=200, body=json.dumps(body).encode()).response
    guarded_resolver = GuardedEvidenceResolver(
        tools=tools, evidence=tuple(invoker._catalogue.values())
    )
    resolver: EvidenceResolver = guarded_resolver
    if resolver_wrapper is not None:
        resolver = resolver_wrapper(guarded_resolver)

    def request_factory(
        snapshot: AuditorSnapshot,
        selected_package: EvidencePackage,
        attempt: int,
        pin: ComponentPin,
    ) -> ModelRequest:
        assert snapshot.candidate_id == selected_package.candidate_id
        data = base.model_dump(mode="json")
        data.update(
            request_id="skeptic-" + selected_package.candidate_id,
            idempotency_key="skeptic-" + selected_package.candidate_id,
            role=ModelRole.SKEPTIC.value,
            mode=ModelPurpose.SKEPTIC_REVIEW.value,
            attempt=attempt,
            evidence=[item.model_dump(mode="json") for item in selected_package.model_evidence],
            prompt=PRODUCT_SKEPTIC_PROMPT_PIN.model_dump(mode="json"),
            output_schema=pin.model_dump(mode="json"),
        )
        return ModelRequest.model_validate_json(json.dumps(data))

    port = ProductSkepticReviewPort(
        executor=executor,
        resolver=resolver,
        evidence_catalogue=tuple(invoker._catalogue.values()),
        content_key=b"s" * 32,
        skeptic_identity="skeptic-runtime",
        tenant_id=package.tenant_id,
        package_for=lambda snapshot: package,
        request_factory=request_factory,
    )
    return port, package, endpoint, tools, executor


def test_real_harness_reviews_selected_artifact_and_auditor_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port, package, endpoint, tools, _ = _composition(monkeypatch)

    result = port.review(_snapshot(package))

    assert result.model_call_status is ModelCallStatus.SUCCEEDED
    assert isinstance(result.output, SkepticOutput)
    assert result.output.objections[0].evidence_ids == ("evidence-a",)
    assert tools.calls_used == 1 and len(endpoint.requests) == 1
    context = json.loads(json.loads(endpoint.requests[0][2])["messages"][0]["content"])
    assert context["trusted_controls"]["role"] == "skeptic"
    assert context["untrusted_auditor_metadata"]["instruction_authority"] == "NONE"
    assert context["untrusted_evidence"][0]["instruction_authority"] == "NONE"


@pytest.mark.parametrize(
    "payload",
    [
        {"finding_verdict": "CONFIRMED", "objections": [], "prose": "no"},
        {
            "finding_verdict": "CONFIRMED",
            "objections": [
                {"kind": "CONTRADICTORY_EVIDENCE", "evidence_ids": ["foreign-evidence"]}
            ],
        },
    ],
)
def test_real_harness_malformed_or_foreign_output_is_non_success(
    monkeypatch: pytest.MonkeyPatch, payload: object
) -> None:
    port, package, endpoint, tools, _ = _composition(monkeypatch, payload=payload)

    result = port.review(_snapshot(package))

    # A malformed answer is asked again twice; evidence is read only once.
    assert result.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert result.output is None
    assert tools.calls_used == 1 and len(endpoint.requests) == 3


def test_same_identity_or_wrong_tenant_never_reaches_source_or_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port, package, endpoint, tools, _ = _composition(monkeypatch)

    same = port.review(_snapshot(package, auditor_identity="skeptic-runtime"))
    port._package_for = lambda snapshot: replace(package, tenant_id="tenant-b")
    foreign_tenant = port.review(_snapshot(package))

    assert same.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert foreign_tenant.model_call_status is ModelCallStatus.INVALID_SCHEMA
    assert tools.calls_used == 0 and endpoint.requests == []


def test_source_record_hash_substitution_is_non_success_before_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port, package, endpoint, tools, _ = _composition(monkeypatch)
    selected = replace(package.selected[0], evidence_sha256="f" * 64)
    port._package_for = lambda snapshot: replace(package, selected=(selected,))

    result = port.review(_snapshot(package))

    assert result.model_call_status is ModelCallStatus.PROVIDER_ERROR
    assert result.output is None
    assert tools.calls_used == 0 and endpoint.requests == []


def test_preflight_denial_and_factory_deadline_read_no_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port, package, endpoint, tools, executor = _composition(monkeypatch)
    denied_case = dict(_semantic_cases()[0])
    denied_case["required_purpose"] = ModelPurpose.CANDIDATE_INVESTIGATION.value
    executor._preflight = lambda request: _preflight_request(request, denied_case)
    denied = port.review(_snapshot(package))

    assert denied.model_call_status is not ModelCallStatus.SUCCEEDED
    assert tools.calls_used == 0 and endpoint.requests == []

    port, package, endpoint, tools, executor = _composition(monkeypatch)
    clock = [100.0]
    executor._now = lambda: clock[0]
    factory = port._request_factory

    def delayed(
        snapshot: AuditorSnapshot,
        selected_package: EvidencePackage,
        attempt: int,
        pin: ComponentPin,
    ) -> ModelRequest:
        clock[0] += 6.0
        return factory(snapshot, selected_package, attempt, pin)

    port._request_factory = delayed
    expired = port.review(_snapshot(package))

    assert expired.model_call_status is ModelCallStatus.BUDGET_EXHAUSTED
    assert tools.calls_used == 0 and endpoint.requests == []


def test_refusal_is_never_reduced_to_success(monkeypatch: pytest.MonkeyPatch) -> None:
    port, package, endpoint, tools, _ = _composition(monkeypatch, refusal="REFUSED")

    result = port.review(_snapshot(package))

    assert result.model_call_status is ModelCallStatus.REFUSED
    assert result.output is None
    assert tools.calls_used == 1 and len(endpoint.requests) == 1


def test_real_skeptic_port_reaches_existing_candidate_review_and_finding_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, _, observed = _flow(monkeypatch, count=1)
    assert isinstance(flow, ProductCandidateFlow)
    candidate = flow.graph.candidates[0]
    package = build_evidence_package(flow.graph, candidate.candidate_id)
    port, _, endpoint, _, _ = _composition(monkeypatch)
    port._catalogue = {record.evidence_id: record for record in flow.graph.evidence}
    auditor_tools = observed["auditor_tools"]
    assert isinstance(auditor_tools, RepositoryToolSession)
    port._resolver = GuardedEvidenceResolver(tools=auditor_tools, evidence=flow.graph.evidence)
    port._package_for = lambda snapshot: package
    factory = port._request_factory
    port._request_factory = lambda snapshot, selected, attempt, pin: _bind_head(
        factory(snapshot, selected, attempt, pin), flow.graph.head_sha
    )
    reply = json.loads(_success_body())
    reply["choices"][0]["message"]["content"] = json.dumps(
        {
            "finding_verdict": FindingVerdict.REJECTED_WITH_EVIDENCE.value,
            "objections": [
                {
                    "kind": SkepticObjectionKind.CONTRADICTORY_EVIDENCE.value,
                    "evidence_ids": [package.selected[0].evidence_id],
                }
            ],
        }
    )
    endpoint.response = _LocalEndpoint(status=200, body=json.dumps(reply).encode()).response

    result = run_product_candidate_review(
        flow,
        auditor_identity_for=lambda candidate, receipt: "auditor-runtime",
        severity_for=lambda candidate: FindingSeverity.HIGH,
        skeptic=port,
    )

    outcome = result.outcomes[0]
    assert outcome.skeptic_review is not None
    assert outcome.skeptic_review.model_call_status is ModelCallStatus.SUCCEEDED
    assert outcome.finding_gate is not None
    assert outcome.finding_gate.skeptic_effective_verdict is FindingVerdict.CONFLICTING


def test_payload_is_closed_when_post_provider_call_accounting_faults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[EphemeralStructuredPayload] = []

    class LateFailingResolver:
        def __init__(self, inner: GuardedEvidenceResolver) -> None:
            self.inner = inner
            self.fail = False

        @property
        def calls_used(self) -> int:
            if self.fail:
                raise RuntimeError("host accounting failed")
            return self.inner.calls_used

        def resolve(
            self, package: EvidencePackage, *, max_calls: int
        ) -> tuple[ResolvedModelEvidence, ...]:
            return self.inner.resolve(package, max_calls=max_calls)

    original_close = EphemeralStructuredPayload.close

    def record_close(payload: EphemeralStructuredPayload) -> None:
        original_close(payload)
        closed.append(payload)

    monkeypatch.setattr(EphemeralStructuredPayload, "close", record_close)
    port, package, endpoint, tools, _executor = _composition(
        monkeypatch, resolver_wrapper=LateFailingResolver
    )
    late_resolver = port._resolver
    assert isinstance(late_resolver, LateFailingResolver)
    original_execute = AuthorizedLocalModelExecutor.execute

    def execute_then_fail(
        self: AuthorizedLocalModelExecutor,
        *,
        request: ModelRequest,
        validator: StructuredPayloadValidator,
        context_builder: Callable[[], PreparedModelContext],
        started_at: float | None = None,
    ) -> ModelBoundaryExecution:
        outcome = original_execute(
            self,
            request=request,
            validator=validator,
            context_builder=context_builder,
            started_at=started_at,
        )
        late_resolver.fail = True
        return outcome

    monkeypatch.setattr(AuthorizedLocalModelExecutor, "execute", execute_then_fail)
    result = port.review(_snapshot(package))

    assert result.model_call_status is not ModelCallStatus.SUCCEEDED
    assert result.output is None
    assert closed and tools.calls_used == 1 and len(endpoint.requests) == 1


def test_malformed_skeptic_answer_is_asked_again(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    port, package, endpoint, tools, _ = _composition(
        monkeypatch, payload={"finding_verdict": "CONFIRMED", "objections": [], "prose": "no"}
    )
    malformed = endpoint.response
    valid_port, _, valid_endpoint, _, _ = _composition(monkeypatch)
    del valid_port
    valid = valid_endpoint.response
    factory = endpoint._socket_factory

    def scripted(family: int, kind: int, proto: int = 0, fileno: int | None = None) -> object:
        endpoint.response = malformed if not endpoint.sockets else valid
        return factory(family, kind, proto, fileno)

    monkeypatch.setattr(socket, "socket", scripted)

    result = port.review(_snapshot(package))

    assert result.model_call_status is ModelCallStatus.SUCCEEDED
    assert result.output is not None
    assert tools.calls_used == 1 and len(endpoint.requests) == 2
