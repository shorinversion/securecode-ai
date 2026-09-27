"""Actual guarded flow and conservative public audit composition controls."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from securecode_ai.adapters import (
    AuthorizedProviderHarness,
    EndpointAuthorizationIssuer,
    ProviderProfileRegistry,
)
from securecode_ai.adapters.native_sources import (
    NativeSourceCatalogue,
    build_native_source_catalogue,
)
from securecode_ai.adapters.openai_compatible_local import OpenAICompatibleLocalHttpConnector
from securecode_ai.adapters.product_audit import (
    ProductAuditComposition,
    ProductAuditFindingMetadata,
    ProductAuditHostInputs,
    ProductAuditObstacle,
    compose_product_audit,
    model_discovery_candidate_mappings,
)
from securecode_ai.adapters.product_model import MODEL_NATIVE_DISCOVERY_WIRE_PIN
from securecode_ai.adapters.product_review import ProductReviewResult, run_product_candidate_review
from securecode_ai.adapters.product_runtime import (
    PRODUCT_AUDITOR_PROMPT_PIN,
    PRODUCT_DISCOVERY_PROMPT_PIN,
    AuthorizedLocalModelExecutor,
    GuardedEvidenceResolver,
    ProductAuditorInvocationObservation,
    ProductAuditorInvoker,
    ProductDiscoveryBackend,
)
from securecode_ai.adapters.product_scan import ProductCandidateFlow, run_product_candidate_flow
from securecode_ai.adapters.product_scanner import (
    ProductDeterministicScanResult,
    build_product_auditor_tools,
    scan_product_sources,
)
from securecode_ai.adapters.product_skeptic import (
    PRODUCT_SKEPTIC_PROMPT_PIN,
    ProductSkepticReviewPort,
)
from securecode_ai.contracts import (
    ArtifactRef,
    AuditRun,
    CandidateOrigin,
    ComponentPin,
    CoverageStatus,
    DataClass,
    EgressPolicyDocument,
    ModelCallStatus,
    ModelPreflightRequest,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    PreflightEligibility,
    ProducerRef,
    RunExecutionIdentity,
)
from securecode_ai.contracts.domain import ACCEPTED_STAGE_CATALOGUE_PIN
from securecode_ai.core.classification import FindingSeverity
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.evidence_package import EvidencePackage, build_evidence_package
from securecode_ai.core.investigation import AuditorInvestigationReceipt, InvestigationBudget
from securecode_ai.core.model_discovery import ModelNativeDiscoveryPlan
from securecode_ai.core.skeptic import AuditorSnapshot
from securecode_ai.core.tool_policy import RepositoryToolBudget, RepositoryToolScope

from tests.integration.test_product_scan_flow import _bind_head
from tests.unit.test_endpoint_policy import ScriptedResolver
from tests.unit.test_native_sources import repository
from tests.unit.test_openai_compatible_local import _LocalEndpoint, _success_body
from tests.unit.test_provider_preflight import (
    _issuer,
    _policy,
    _preflight_request,
    _profile,
    _request,
    _semantic_cases,
)

NOW = datetime(2026, 9, 18, tzinfo=UTC)
SOURCE_CANARY = "AUDIT_SOURCE_PRIVATE_CANARY"
RATIONALE_CANARY = "AUDIT_RATIONALE_PRIVATE_CANARY"
IDENTITY_FIELDS = (
    "repository_revision",
    "stage_catalogue",
    "workflow",
    "policy",
    "configuration",
    "provider_profile",
    "capability_profile",
    "egress_profile",
)


def _reply(
    endpoint: _LocalEndpoint,
    payload: dict[str, object],
    *,
    refusal: str | None = None,
) -> None:
    body = json.loads(_success_body(refusal=refusal))
    body["choices"][0]["message"]["content"] = json.dumps(payload)
    endpoint.response = _LocalEndpoint(status=200, body=json.dumps(body).encode()).response


def _actual_flow(
    monkeypatch: pytest.MonkeyPatch,
    *,
    count: int = 1,
    hybrid: bool = False,
    ssrf: bool = False,
    source: bytes | None = None,
    path: str = "a.py",
    cwe_id: str | None = None,
    severity: FindingSeverity = FindingSeverity.HIGH,
    collector_failure: bool = False,
    scanner_failure: bool = False,
    discovery_failure: bool = False,
    skeptic_refusal: bool = False,
    idempotency_collision: bool = False,
) -> tuple[ProductCandidateFlow, ProductReviewResult, ProductAuditHostInputs, _LocalEndpoint, str]:
    """Prepare common host identity and real policy admission before any send."""
    default_source = (
        b'def get_user(request, db):\n user_id = request.args.get("user_id")\n'
        b' return db.execute(f"SELECT * FROM users WHERE id = {user_id}").fetchone()\n'
        if hybrid
        else f"# {SOURCE_CANARY}\nexecute(value)\n".encode()
    )
    if ssrf:
        assert hybrid
        default_source = (
            b"import requests\ndef check(request):\n requests.get(request.args.get('url'))\n"
        )
        cwe_id = "CWE-918"
    source = default_source if source is None else source
    reader, head, _ = repository(path, source)
    profile = _profile("valid.local-openai-compatible.json")
    values = _policy("egress.valid.private-model-source.json").model_dump(mode="json")
    values["policy_version"] = "1.0.3"
    values["rules"][0]["purposes"].extend(
        [ModelPurpose.CANDIDATE_INVESTIGATION.value, ModelPurpose.SKEPTIC_REVIEW.value]
    )
    policy = EgressPolicyDocument.model_validate_json(json.dumps(values))
    base = _bind_head(_request(profile, policy, ModelPurpose.MODEL_NATIVE_DISCOVERY), head)
    base_data = base.model_dump(mode="json")
    base_data["budget"]["max_repository_calls"] = 16
    base = ModelRequest.model_validate_json(json.dumps(base_data))
    fields = {name: getattr(base.execution_identity, name) for name in IDENTITY_FIELDS}
    fields["stage_catalogue"] = ComponentPin(
        schema_version="0.2.0",
        component_id=ACCEPTED_STAGE_CATALOGUE_PIN[0],
        component_version=ACCEPTED_STAGE_CATALOGUE_PIN[1],
        content_sha256=ACCEPTED_STAGE_CATALOGUE_PIN[2],
    )
    identity = RunExecutionIdentity.build(**fields)
    values = base.model_dump(mode="json")
    values.update(
        execution_identity=identity.model_dump(mode="json"),
        prompt=PRODUCT_DISCOVERY_PROMPT_PIN.model_dump(mode="json"),
        output_schema=MODEL_NATIVE_DISCOVERY_WIRE_PIN.model_dump(mode="json"),
    )
    request = ModelRequest.model_validate_json(json.dumps(values))
    catalogue = build_native_source_catalogue(
        reader=reader,
        head_sha=head,
        tenant_id=request.tenant_id,
        repository_id="repo-a",
        content_key=b"p" * 32,
    )
    # Genuine isolated first-party scanner execution retained by the host.
    scan = scan_product_sources(catalogue, tenant_id=request.tenant_id)
    assert scan.is_complete
    roots, rule = catalogue.anchors[:count], "rule-sqli"
    if cwe_id in {"CWE-78", "CWE-22", "CWE-639", "CWE-918", "CWE-862"}:
        rule = "portfolio-" + cwe_id.lower()
    if hybrid:
        assert len(scan.graph.candidates) == 1
        signal = scan.receipts[0].signals[0]
        roots = tuple(anchor for anchor in catalogue.anchors if anchor.location == signal.location)
        assert len(roots) == 1
        rule = signal.rule_id
    endpoint = _LocalEndpoint(status=200, body=_success_body())
    endpoint.install(monkeypatch)
    payload: dict[str, object] = {
        "candidates": [
            {
                "rule_id": rule,
                "root_evidence_id": root.evidence_id,
                "evidence_ids": [root.evidence_id],
            }
            for root in roots
        ]
    }
    _reply(endpoint, {"candidates": "invalid"} if discovery_failure else payload)
    registry = ProviderProfileRegistry((profile,))

    def preflight(selected: ModelRequest) -> ModelPreflightRequest:
        case = dict(_semantic_cases()[0])
        case["required_purpose"] = selected.mode.value
        return _preflight_request(selected, case)

    executor = AuthorizedLocalModelExecutor(
        harness=AuthorizedProviderHarness(
            model_issuer=_issuer(profile, policy),
            endpoint_issuer=EndpointAuthorizationIssuer(provider_registry=registry),
        ),
        registry=registry,
        profile=profile,
        policy=policy,
        resolver=ScriptedResolver(*(("127.0.0.1",),) * 128),
        connector=OpenAICompatibleLocalHttpConnector(profile=profile),
        preflight=preflight,
        now=lambda: 100.0,
    )
    producer = ProducerRef(
        schema_version="0.2.0",
        producer_id="model-native-discovery",
        producer_version="1.0.0",
        producer_sha256="a" * 64,
    )
    plan = ModelNativeDiscoveryPlan(
        receipt_id="product-native-receipt",
        request=request,
        preflight_eligibility=PreflightEligibility.ELIGIBLE,
        scope=RepositoryToolScope(
            request.tenant_id,
            "repo-a",
            head,
            (path,),
            tuple(sorted(anchor.evidence_id for anchor in catalogue.anchors)),
        ),
        tool_budget=RepositoryToolBudget(8, 65536, 3072),
        producer=producer,
    )
    observations: list[ProductAuditorInvocationObservation] = []

    def role_request(
        package: EvidencePackage,
        attempt: int,
        pin: ComponentPin,
        role: ModelRole,
        purpose: ModelPurpose,
        prompt: ComponentPin,
    ) -> ModelRequest:
        data = request.model_dump(mode="json")
        identifier = role.value + "-" + package.candidate_id + "-" + str(attempt)
        data.update(
            request_id=identifier,
            idempotency_key=identifier,
            attempt=attempt,
            role=role.value,
            mode=purpose.value,
            evidence=[item.model_dump(mode="json") for item in package.model_evidence],
            prompt=prompt.model_dump(mode="json"),
            output_schema=pin.model_dump(mode="json"),
        )
        if idempotency_collision and role is ModelRole.AUDITOR:
            data["idempotency_key"] = "auditor-shared-collision"
        return ModelRequest.model_validate_json(json.dumps(data))

    def collect(observation: ProductAuditorInvocationObservation) -> None:
        observations.append(observation)
        if collector_failure and len(observations) == 2:
            raise RuntimeError(RATIONALE_CANARY)

    def auditor_factory(graph: EvidenceGraph) -> ProductAuditorInvoker:
        tools = build_product_auditor_tools(
            catalogue,
            graph,
            budget=RepositoryToolBudget(16, 65536, 65536),
            deterministic=scan,
        )

        def factory(package: EvidencePackage, attempt: int, pin: object) -> ModelRequest:
            _reply(
                endpoint,
                {
                    "finding_verdict": "CONFIRMED",
                    "cited_evidence_ids": [item.evidence_id for item in package.selected],
                    "rationale": RATIONALE_CANARY,
                },
            )
            return role_request(
                package,
                attempt,
                ComponentPin.model_validate(pin),
                ModelRole.AUDITOR,
                ModelPurpose.CANDIDATE_INVESTIGATION,
                PRODUCT_AUDITOR_PROMPT_PIN,
            )

        return ProductAuditorInvoker(
            executor=executor,
            resolver=GuardedEvidenceResolver(tools=tools, evidence=graph.evidence),
            evidence_catalogue=graph.evidence,
            content_key=b"a" * 32,
            request_factory=factory,
            observer=collect,
        )

    def deterministic(_catalogue: NativeSourceCatalogue) -> ProductDeterministicScanResult:
        if scanner_failure:
            raise RuntimeError(SOURCE_CANARY)
        return scan

    flow = run_product_candidate_flow(
        catalogue=catalogue,
        model_plan=plan,
        model_backend=ProductDiscoveryBackend(
            executor=executor,
            catalogue=catalogue.anchors,
            rule_ids=frozenset({rule}),
            content_key=b"p" * 32,
        ),
        deterministic_scanner=deterministic,
        auditor_factory=auditor_factory,
        investigation_budget=InvestigationBudget(2, 8192, 64, 60000),
    )
    assert type(flow) is ProductCandidateFlow
    discovery_bytes = flow.discovery.receipt.model_dump_json()
    tools = build_product_auditor_tools(
        catalogue,
        flow.graph,
        budget=RepositoryToolBudget(16, 65536, 65536),
        deterministic=scan,
    )

    def skeptic_factory(
        _snapshot: AuditorSnapshot,
        package: EvidencePackage,
        attempt: int,
        pin: ComponentPin,
    ) -> ModelRequest:
        _reply(
            endpoint,
            {"finding_verdict": "CONFIRMED", "objections": []},
            refusal="REFUSED" if skeptic_refusal else None,
        )
        return role_request(
            package,
            attempt,
            pin,
            ModelRole.SKEPTIC,
            ModelPurpose.SKEPTIC_REVIEW,
            PRODUCT_SKEPTIC_PROMPT_PIN,
        )

    skeptic = (
        ProductSkepticReviewPort(
            executor=executor,
            resolver=GuardedEvidenceResolver(tools=tools, evidence=flow.graph.evidence),
            evidence_catalogue=flow.graph.evidence,
            content_key=b"s" * 32,
            skeptic_identity="skeptic-product-audit",
            tenant_id=request.tenant_id,
            package_for=lambda snapshot: build_evidence_package(flow.graph, snapshot.candidate_id),
            request_factory=skeptic_factory,
        )
        if flow.graph.evidence
        else object()
    )
    review = run_product_candidate_review(
        flow,
        auditor_identity_for=lambda _candidate, _receipt: "auditor-product-audit",
        severity_for=lambda _candidate: severity,
        skeptic=skeptic,
    )
    graph_ref = ArtifactRef(
        schema_version="0.2.0",
        tenant_id=request.tenant_id,
        content_id=flow.graph.graph_id,
        content_sha256=flow.graph.graph_sha256,
        size_bytes=0,
        data_class=DataClass.INTERNAL_METADATA,
    )
    host = ProductAuditHostInputs(
        run_id=request.run_id,
        execution_identity=identity,
        discovery_request=request,
        auditor=ComponentPin(
            schema_version="0.2.0",
            component_id="product-auditor-runtime",
            component_version="1.0.0",
            content_sha256="a" * 64,
        ),
        source_catalogue=catalogue,
        created_at=NOW,
        completed_at=NOW,
        auditor_observations=tuple(observations),
        deterministic_scan=scan,
        finding_metadata=tuple(
            ProductAuditFindingMetadata(
                candidate_id=outcome.candidate_id,
                candidate_version=outcome.candidate_version,
                finding_id="finding-" + str(index),
                cwe_id=cwe_id or "CWE-89",
                evidence_graph_ref=graph_ref,
                rule_id=rule
                if cwe_id in {"CWE-78", "CWE-22", "CWE-639", "CWE-918", "CWE-862"}
                else None,
                root_cause_fingerprint=(
                    flow.graph.candidates[index].root_cause_fingerprint
                    if cwe_id in {"CWE-78", "CWE-22", "CWE-639", "CWE-918", "CWE-862"}
                    else None
                ),
            )
            for index, outcome in enumerate(review.outcomes)
            if outcome.has_known_blocking_finding
        ),
    )
    return flow, review, host, endpoint, discovery_bytes


def test_actual_nonzero_flow_preserves_original_discovery_id_and_renders_exact_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, review, host, endpoint, original = _actual_flow(monkeypatch)
    mappings = model_discovery_candidate_mappings(flow)
    assert type(mappings) is tuple
    assert mappings[0].receipt_candidate_id != mappings[0].current_candidate_id
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert not result.run.coverage_manifest.coverage_complete
    assert result.run.audit_outcome.value == "FAIL"
    assert result.report.run == result.run
    assert AuditRun.model_validate_json(result.run.model_dump_json()) == result.run
    assert flow.discovery.receipt.model_dump_json() == original
    assert len(endpoint.requests) == 3
    assert result.html_report.startswith(b"<!doctype html>")
    assert result.run.run_id == json.loads(result.json_report)["run_id"]
    for canary in (SOURCE_CANARY, RATIONALE_CANARY):
        assert canary.encode() not in result.json_report + result.html_report


def test_actual_ssrf_portfolio_flow_renders_rule_bound_product_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P7.56 red oracle: the pre-existing guarded SSRF flow must be reportable."""

    flow, review, host, endpoint, _ = _actual_flow(monkeypatch, hybrid=True, ssrf=True)
    assert flow.graph.candidates[0].candidate_origin is CandidateOrigin.HYBRID
    assert review.has_known_blocking_finding
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert result.report.findings[0].classification.cwe_id == "CWE-918"
    assert result.report.findings[0].classification.owasp_category == "A10:2021"
    assert result.report.findings[0].classification.severity is FindingSeverity.HIGH
    assert result.report.findings[0].classification.confidence.value == "UNSCORED"
    assert len(endpoint.requests) == 3


def test_extended_cwe_rejects_host_gate_severity_that_disagrees_with_rule_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, review, host, _, _ = _actual_flow(
        monkeypatch, hybrid=True, ssrf=True, severity=FindingSeverity.MEDIUM
    )

    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditObstacle
    assert result.code == "PRODUCT_AUDIT_INPUT_INVALID"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rule_id", "portfolio-cwe-78"),
        ("root_cause_fingerprint", "0" * 64),
    ],
)
def test_extended_cwe_rejects_mismatched_host_rule_or_root_fingerprint(
    monkeypatch: pytest.MonkeyPatch, field: str, value: str
) -> None:
    flow, review, host, _, _ = _actual_flow(monkeypatch, hybrid=True, ssrf=True)
    metadata = (
        replace(host.finding_metadata[0], rule_id=value)
        if field == "rule_id"
        else replace(host.finding_metadata[0], root_cause_fingerprint=value)
    )

    result = compose_product_audit(flow, review, host=replace(host, finding_metadata=(metadata,)))
    assert type(result) is ProductAuditObstacle
    assert result.code == "PRODUCT_AUDIT_INPUT_INVALID"


def test_unknown_product_cwe_remains_a_closed_classification_obstacle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, review, host, _, _ = _actual_flow(monkeypatch, hybrid=True, ssrf=True)
    metadata = replace(host.finding_metadata[0], cwe_id="CWE-9999")

    result = compose_product_audit(flow, review, host=replace(host, finding_metadata=(metadata,)))
    assert type(result) is ProductAuditObstacle
    assert result.code == "FINDING_CLASSIFICATION_UNSUPPORTED"


@pytest.mark.parametrize(
    ("severity", "metadata_updates"),
    [
        (FindingSeverity.HIGH, {"cwe_id": "CWE-89"}),
        (
            FindingSeverity.HIGH,
            {"cwe_id": "CWE-89", "rule_id": None, "root_cause_fingerprint": None},
        ),
        (FindingSeverity.MEDIUM, {"cwe_id": "CWE-89"}),
        (
            FindingSeverity.MEDIUM,
            {"cwe_id": "CWE-89", "rule_id": None, "root_cause_fingerprint": None},
        ),
    ],
)
def test_recognized_portfolio_root_cannot_be_downgraded_to_legacy_cwe89(
    monkeypatch: pytest.MonkeyPatch,
    severity: FindingSeverity,
    metadata_updates: dict[str, object],
) -> None:
    flow, review, host, _, _ = _actual_flow(monkeypatch, hybrid=True, ssrf=True, severity=severity)
    original_metadata = host.finding_metadata[0]
    metadata = replace(
        original_metadata,
        cwe_id=str(metadata_updates["cwe_id"]),
        rule_id=(None if "rule_id" in metadata_updates else original_metadata.rule_id),
        root_cause_fingerprint=(
            None
            if "root_cause_fingerprint" in metadata_updates
            else original_metadata.root_cause_fingerprint
        ),
    )

    result = compose_product_audit(flow, review, host=replace(host, finding_metadata=(metadata,)))
    assert type(result) is ProductAuditObstacle
    assert result.code == "PRODUCT_AUDIT_INPUT_INVALID"


def test_recognized_native_portfolio_root_cannot_be_downgraded_to_legacy_cwe89(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, review, host, _, _ = _actual_flow(
        monkeypatch,
        source=(
            b"import requests\ndef check(request):\n requests.get('https://api.example.test')\n"
        ),
        path="native-ssrf.py",
        cwe_id="CWE-918",
    )
    assert flow.graph.candidates[0].candidate_origin is CandidateOrigin.MODEL_NATIVE
    metadata = replace(
        host.finding_metadata[0],
        cwe_id="CWE-89",
        rule_id=None,
        root_cause_fingerprint=None,
    )

    result = compose_product_audit(flow, review, host=replace(host, finding_metadata=(metadata,)))
    assert type(result) is ProductAuditObstacle
    assert result.code == "PRODUCT_AUDIT_INPUT_INVALID"


def test_known_blocking_finding_retains_fail_when_later_auditor_is_downgraded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, review, host, endpoint, _ = _actual_flow(monkeypatch, count=2, collector_failure=True)
    assert review.has_known_blocking_finding
    assert (
        host.auditor_observations[1].model_call_status_before_collection
        is ModelCallStatus.SUCCEEDED
    )
    second = flow.investigations[1]
    assert isinstance(second, AuditorInvestigationReceipt)
    assert second.final_model_call_status is ModelCallStatus.GUARDRAIL_BLOCKED
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert result.run.audit_outcome.value == "FAIL"
    assert result.run.analysis_health.value == "DEGRADED"
    receipt = result.run.coverage_manifest.candidate_interpretation_receipts[1]
    assert receipt.model_call_status is ModelCallStatus.GUARDRAIL_BLOCKED
    assert len(endpoint.requests) == 4


def test_actual_zero_flow_stays_indeterminate_without_atomic_receipts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, review, host, endpoint, _ = _actual_flow(monkeypatch, count=0)
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert result.run.audit_outcome.value == "INDETERMINATE"
    assert not result.run.coverage_manifest.coverage_complete
    assert len(endpoint.requests) == 1
    skipped = {
        unit.stage_id
        for unit in result.run.coverage_manifest.units
        if unit.coverage_status is CoverageStatus.SKIPPED
    }
    assert {"intake", "language_discovery", "coverage_guard", "reporting"} <= skipped


def test_actual_candidate_idempotency_failure_preserves_the_other_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, review, host, endpoint, _ = _actual_flow(monkeypatch, count=2, idempotency_collision=True)
    second = flow.investigations[1]
    assert isinstance(second, AuditorInvestigationReceipt)
    assert second.final_model_call_status is ModelCallStatus.PROVIDER_ERROR
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert result.run.audit_outcome.value == "FAIL"
    assert len(endpoint.requests) == 3


def test_successful_scanner_substitution_cannot_mask_actual_scanner_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    flow, review, host, _, _ = _actual_flow(monkeypatch, scanner_failure=True)
    assert host.deterministic_scan is not None
    assert host.deterministic_scan.is_complete and flow.deterministic_failed
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert result.run.audit_outcome.value == "FAIL"
    skipped = {
        unit.stage_id
        for unit in result.run.coverage_manifest.units
        if unit.coverage_status is CoverageStatus.SKIPPED
    }
    assert {"deterministic_analysis", "normalization", "evidence_graph"} <= skipped


def test_actual_preparation_failure_returns_missing_observation_obstacle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.adapters import product_scan
    from securecode_ai.core.evidence_package import EvidencePackageLimits

    original = build_evidence_package
    monkeypatch.setattr(
        product_scan,
        "build_evidence_package",
        lambda graph, candidate_id: original(
            graph, candidate_id, limits=EvidencePackageLimits(max_context_bytes=1)
        ),
    )
    flow, review, host, endpoint, _ = _actual_flow(monkeypatch)
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditObstacle
    assert result.code == "AUDITOR_OBSERVATION_MISSING"
    assert host.auditor_observations == ()
    assert len(endpoint.requests) == 1


@pytest.mark.parametrize("fault", ["discovery_failure", "skeptic_refusal"])
def test_actual_mandatory_model_fault_never_yields_clean(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    flow, review, host, _, _ = _actual_flow(
        monkeypatch,
        discovery_failure=fault == "discovery_failure",
        skeptic_refusal=fault == "skeptic_refusal",
    )
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditComposition
    assert result.run.audit_outcome.value == "INDETERMINATE"


@pytest.mark.parametrize(
    "fault", ["missing", "duplicate", "extra", "version", "run", "identity", "tenant", "head"]
)
def test_foreign_or_missing_actual_observations_are_rejected(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    flow, review, host, _, _ = _actual_flow(monkeypatch)
    observation = host.auditor_observations[0]
    if fault == "missing":
        host = replace(host, auditor_observations=())
    elif fault == "duplicate":
        host = replace(host, auditor_observations=(observation, observation))
    elif fault in {"extra", "version"}:
        package = (
            replace(observation.package, candidate_id="foreign-candidate")
            if fault == "extra"
            else replace(observation.package, candidate_version=2)
        )
        host = replace(host, auditor_observations=(replace(observation, package=package),))
    else:
        values_dict: dict[str, object] = observation.request.model_dump(mode="json")
        values: dict[str, object] | None = values_dict
        if fault == "run":
            values_dict["run_id"] = "foreign-run"
        elif fault == "identity":
            fields = {
                name: getattr(observation.request.execution_identity, name)
                for name in IDENTITY_FIELDS
            }
            fields["configuration"] = ComponentPin(
                schema_version="0.2.0",
                component_id="foreign-config",
                component_version="1.0.0",
                content_sha256="b" * 64,
            )
            values_dict["execution_identity"] = RunExecutionIdentity.build(**fields).model_dump(
                mode="json"
            )
        else:
            # Corrupt a frozen observation to exercise the trust boundary.
            object.__setattr__(
                observation.request,
                "tenant_id" if fault == "tenant" else "head_sha",
                "foreign-tenant" if fault == "tenant" else "b" * 40,
            )
            values = None
        if values is not None:
            host = replace(
                host,
                auditor_observations=(
                    replace(
                        observation, request=ModelRequest.model_validate_json(json.dumps(values))
                    ),
                ),
            )
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditObstacle
    assert result.code == "PRODUCT_AUDIT_INPUT_INVALID"


@pytest.mark.parametrize(
    "field,value",
    [
        ("graph_id", "foreign-graph"),
        ("graph_sha256", "b" * 64),
        ("content_id", "kid:foreign-artifact"),
        ("evidence_sha256", "b" * 64),
        ("producer_id", "foreign-producer"),
        ("producer_version", "9.9.9"),
        ("producer_sha256", "b" * 64),
        ("data_class", DataClass.PUBLIC),
    ],
)
def test_foreign_graph_or_selected_record_is_rejected_under_coherent_identity(
    monkeypatch: pytest.MonkeyPatch, field: str, value: str | DataClass
) -> None:
    flow, review, host, _, _ = _actual_flow(monkeypatch)
    observation = host.auditor_observations[0]
    if field in {"graph_id", "graph_sha256"}:
        package = (
            replace(observation.package, graph_id=str(value))
            if field == "graph_id"
            else replace(observation.package, graph_sha256=str(value))
        )
    else:
        original_selected = observation.package.selected[0]
        if field == "data_class":
            assert isinstance(value, DataClass)
            selected = replace(original_selected, data_class=value)
        elif field == "content_id":
            selected = replace(original_selected, content_id=str(value))
        elif field == "evidence_sha256":
            selected = replace(original_selected, evidence_sha256=str(value))
        elif field == "producer_id":
            selected = replace(original_selected, producer_id=str(value))
        elif field == "producer_version":
            selected = replace(original_selected, producer_version=str(value))
        else:
            selected = replace(original_selected, producer_sha256=str(value))
        package = replace(observation.package, selected=(selected,))
    host = replace(host, auditor_observations=(replace(observation, package=package),))
    assert host.auditor_observations[0].request.execution_identity == host.execution_identity
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditObstacle
    assert result.code == "PRODUCT_AUDIT_INPUT_INVALID"


@pytest.mark.parametrize("field", ["prompt", "output_schema", "provider_profile"])
def test_foreign_actual_auditor_component_pin_is_rejected(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    flow, review, host, _, _ = _actual_flow(monkeypatch)
    observation = host.auditor_observations[0]
    pin = getattr(observation.request, field).model_copy(update={"component_version": "9.9.9"})
    object.__setattr__(observation.request, field, pin)
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditObstacle
    assert result.code == "PRODUCT_AUDIT_INPUT_INVALID"


@pytest.mark.parametrize("fault", ["duplicate_selected", "omission", "context_size"])
def test_corrupted_observed_package_shape_is_rejected(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    flow, review, host, _, _ = _actual_flow(monkeypatch)
    package = host.auditor_observations[0].package
    if fault == "duplicate_selected":
        object.__setattr__(package, "selected", (package.selected[0], package.selected[0]))
    elif fault == "omission":
        object.__setattr__(package, "omitted_evidence_ids", ("foreign-evidence",))
    else:
        object.__setattr__(package, "total_context_bytes", 1)
    result = compose_product_audit(flow, review, host=host)
    assert type(result) is ProductAuditObstacle
    assert result.code == "PRODUCT_AUDIT_INPUT_INVALID"
