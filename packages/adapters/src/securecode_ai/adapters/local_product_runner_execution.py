"""Installed private-source Core composition through the OS approval loader."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock

from securecode_ai.contracts import (
    AuditRunOutcome,
    DataClass,
    EvidenceInputRef,
    ModelCallBudget,
    ModelPreflightRequest,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ModelUsage,
    PreflightEligibility,
    ProducerRef,
    RepositoryRevision,
    RunExecutionIdentity,
    WorkflowCancelRequest,
    WorkflowOperation,
    WorkflowSnapshot,
    WorkflowSnapshotRequest,
    WorkflowStartRequest,
)
from securecode_ai.core import EgressPolicyRegistry, ModelAuthorizationIssuer
from securecode_ai.core.classification import classify_product_cwe
from securecode_ai.core.evidence_graph import EvidenceGraph
from securecode_ai.core.evidence_package import build_evidence_package
from securecode_ai.core.investigation import InvestigationBudget
from securecode_ai.core.model_discovery import ModelNativeDiscoveryPlan, RepositoryToolSession
from securecode_ai.core.reports import ReportFormat, render_report
from securecode_ai.core.runtime import (
    DEFAULT_STAGE_CATALOGUE_PIN,
    WorkflowDefinitionRegistry,
    build_default_workflow_definition,
)
from securecode_ai.core.tool_policy import RepositoryToolBudget, RepositoryToolScope

from .config import EffectiveConfiguration
from .dependency_scanning import ApprovedOsvScanner
from .dependency_scanning_osv import BoundedOsvScanner
from .endpoint import EndpointAuthorizationIssuer, Resolver
from .git_snapshot import OfflineGitObjectReader as OfflineGitObjectReader
from .local_product_host import (
    LocalProductHost,
    load_local_product_host,
)
from .local_product_host import (
    verify_local_git_executable as verify_local_git_executable,
)
from .local_product_runner_cancellation import LocalProductCancellationGuard
from .local_product_runner_config import (
    LocalProductCancelledError,
    LocalProductConfigurationError,
    LocalProductScanResult,
    LocalProductSupersededError,
    LocalProductUnavailableError,
    _hash,
    _LiteralLoopbackResolver,
    _pin,
    _retain_evidence_graph,
)
from .local_product_runner_config import (
    _git as _git,
)
from .local_product_runner_execution_family import _candidate_family
from .local_product_runner_execution_types import _GitCommand, _ReaderFactory
from .local_product_runner_identity import select_run_id, select_run_identity
from .local_product_runner_roles import build_role_request
from .model import AuthorizedProviderHarness
from .native_repository_tools import NATIVE_REPOSITORY_TOOLS_JSON
from .native_sources import build_native_source_catalogue
from .openai_compatible_local import OpenAICompatibleLocalHttpConnector
from .product_audit import (
    GitProductAuditStateProbe,
    ProductAuditFindingMetadata,
    ProductAuditHostInputs,
    ProductAuditObstacle,
    execute_product_audit,
)
from .product_model import AUDITOR_WIRE_PIN, MODEL_NATIVE_DISCOVERY_WIRE_PIN
from .product_provider_runtime import ProductProviderRuntime
from .product_review import ProductReviewResult, run_product_candidate_review
from .product_rule_catalogue import PRODUCT_RULE_CWE as _RULES
from .product_runtime import (
    PRODUCT_AUDITOR_PROMPT_PIN,
    PRODUCT_DISCOVERY_PROMPT_PIN,
    AuthorizedLocalModelExecutor,
    GuardedEvidenceResolver,
    ProductAuditorInvocationObservation,
    ProductAuditorInvoker,
    ProductDiscoveryBackend,
)
from .product_scan import ProductCandidateFlow
from .product_skeptic import PRODUCT_SKEPTIC_PROMPT_PIN, SKEPTIC_WIRE_PIN, ProductSkepticReviewPort
from .remote_provider_budget import RemoteProviderCostReceipt
from .runtime import LocalWorkflowRuntime
from .secret_detection import SecretFingerprintKey

_RUNTIME_CANCEL_LOCK_TIMEOUT_SECONDS = 5.0


def _run_git_command(
    git_command: _GitCommand,
    checkout: Path,
    executable: Path,
    *arguments: str,
    cancellation: LocalProductCancellationGuard,
) -> str:
    cancellation.checkpoint()
    if git_command is _git:
        return _git(checkout, executable, *arguments, cancelled=cancellation)
    result = git_command(checkout, executable, *arguments)
    cancellation.checkpoint()
    return result


def _run_local_product_scan(
    host: LocalProductHost,
    target: str,
    report_format: ReportFormat,
    configuration: EffectiveConfiguration,
    *,
    execution_identity: RunExecutionIdentity | None = None,
    run_id: str | None = None,
    cancelled: Callable[[], bool] | None = None,
    on_cancel: Callable[[Callable[[], None]], None] | None = None,
    usage_observer: Callable[[ModelUsage], None] | None = None,
    cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    dependency_scanner: ApprovedOsvScanner | None = None,
    git_verifier: Callable[[str], Path] = verify_local_git_executable,
    git_command: _GitCommand = _git,
    reader_factory: _ReaderFactory = OfflineGitObjectReader,
    provider_runtime: ProductProviderRuntime | None = None,
    authority_loader: Callable[[], LocalProductHost] | None = None,
) -> LocalProductScanResult:
    cancellation = LocalProductCancellationGuard(cancelled)
    cancellation.checkpoint()
    selected_runtime = provider_runtime
    if selected_runtime is None:
        profile, policy = host.profile, host.policy
        registry = host.registry
        resolver: Resolver = _LiteralLoopbackResolver()
        local_provider = True
    else:
        profile, policy = selected_runtime.profile, selected_runtime.policy
        registry = selected_runtime.registry
        resolver = selected_runtime.resolver
        local_provider = False
    # Freeze exact authority bindings, independently of the mutable manifest
    # mapping and subsequent fresh loader results. Never adopt a replacement.
    original_authority = (
        host.approval_record_sha256,
        host.artifact_manifest_sha256,
        host.approved_bundle_sha256,
        host.profile.canonical_content_hash(),
        host.policy.canonical_content_hash(),
        _hash(host.artifact_manifest),
    )
    registry.require_registered(profile)
    if (
        configuration.provider_profile != profile
        or configuration.policy_profile_id != policy.policy_id
        or configuration.egress_profile is not policy.profile
    ):
        raise LocalProductConfigurationError()
    # Local execution is deliberately literal loopback, with no DNS authority.
    if local_provider and not ipaddress.ip_address(profile.endpoint.authority).is_loopback:
        raise LocalProductUnavailableError()
    policy_pin = _pin(policy.policy_id, policy.policy_version, policy.canonical_content_hash())
    workflow = build_default_workflow_definition(policy_pin=policy_pin)
    expected = {
        "workflow_sha256": workflow.component_pin.content_sha256,
        "stage_catalogue_sha256": DEFAULT_STAGE_CATALOGUE_PIN.content_sha256,
        "discovery_prompt_sha256": PRODUCT_DISCOVERY_PROMPT_PIN.content_sha256,
        "auditor_prompt_sha256": PRODUCT_AUDITOR_PROMPT_PIN.content_sha256,
        "skeptic_prompt_sha256": PRODUCT_SKEPTIC_PROMPT_PIN.content_sha256,
        "skeptic_schema_sha256": SKEPTIC_WIRE_PIN.content_sha256,
    }
    if {
        key: value
        for key, value in host.artifact_manifest.items()
        if key != "git_executable_sha256"
    } != expected:
        raise LocalProductUnavailableError()
    root = Path(target).absolute()
    if root.is_symlink() or not root.is_dir() or "\x00" in target:
        raise LocalProductConfigurationError()
    git = git_verifier(host.artifact_manifest.get("git_executable_sha256", ""))
    checkout = Path(
        _run_git_command(
            git_command,
            root,
            git,
            "rev-parse",
            "--show-toplevel",
            cancellation=cancellation,
        )
    ).resolve()
    if checkout != root.resolve():
        raise LocalProductConfigurationError()
    head = _run_git_command(
        git_command,
        checkout,
        git,
        "rev-parse",
        "--verify",
        "HEAD",
        cancellation=cancellation,
    )
    local_repository_id = "local-" + hashlib.sha256(str(checkout).encode()).hexdigest()[:32]
    scm_provider = "git"
    base_sha = None
    repository_id = local_repository_id
    if execution_identity is not None:
        supplied_revision = execution_identity.repository_revision
        if (
            supplied_revision.tenant_id != policy.tenant_scope
            or supplied_revision.head_sha != head
            or supplied_revision.scm_provider not in {"git", "github", "gitlab"}
            or not supplied_revision.repository_id
        ):
            raise LocalProductConfigurationError()
        # Connected jobs carry the server's SCM identity.  Keep that identity
        # when deriving local scanner indexes; the checkout path is only a
        # fallback for standalone CLI scans and is not a repository identity.
        repository_id = supplied_revision.repository_id
        scm_provider = supplied_revision.scm_provider
        base_sha = supplied_revision.base_sha
    provider_pin = _pin(
        profile.profile_id, profile.profile_version, profile.canonical_content_hash()
    )
    derived_identity = RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version="0.2.0",
            tenant_id=policy.tenant_scope,
            scm_provider=scm_provider,
            repository_id=repository_id,
            head_sha=head,
            base_sha=base_sha,
        ),
        stage_catalogue=DEFAULT_STAGE_CATALOGUE_PIN,
        workflow=workflow.component_pin,
        policy=policy_pin,
        configuration=_pin("local-config", "1.0.0", configuration.canonical_content_hash()),
        provider_profile=provider_pin,
        capability_profile=_pin(
            "local-capabilities", "1.0.0", _hash(profile.capabilities.model_dump(mode="json"))
        ),
        egress_profile=_pin(
            policy.profile.value, policy.policy_version, policy.canonical_content_hash()
        ),
    )
    identity = select_run_identity(derived_identity, execution_identity)
    run_id = select_run_id(run_id, "local-" + uuid.uuid4().hex)
    # A small local model keeps a tight 8K/2K window.  A remote provider gets room for
    # its reasoning trace and the whole bounded repository view: its connector counts
    # UTF-8 bytes plus protocol framing as tokens.
    max_output = min(
        2048 if local_provider else 32768,
        profile.capabilities.max_output_tokens,
        profile.budgets.max_total_tokens // 2,
    )
    max_input = min(
        8192 if local_provider else 131072,
        profile.capabilities.max_context_tokens,
        profile.budgets.max_total_tokens - max_output,
    )
    budget = ModelCallBudget(
        schema_version="0.2.0",
        max_input_tokens=max_input,
        max_output_tokens=max_output,
        max_repository_calls=16,
        max_context_bytes=65536,
        timeout_ms=profile.budgets.timeout_seconds * 1000,
    )
    scope_pin = _pin(
        "whole-revision-scope", "1.0.0", _hash(identity.repository_revision.model_dump(mode="json"))
    )
    request = ModelRequest(
        schema_version="0.2.0",
        request_id=run_id + "-discovery",
        run_id=run_id,
        tenant_id=policy.tenant_scope,
        idempotency_key=run_id + "-discovery",
        attempt=1,
        execution_identity=identity,
        head_sha=head,
        role=ModelRole.DISCOVERY,
        mode=ModelPurpose.MODEL_NATIVE_DISCOVERY,
        provider_profile=provider_pin,
        api_dialect=profile.api_dialect,
        model_id=profile.model_id,
        prompt=PRODUCT_DISCOVERY_PROMPT_PIN,
        output_schema=MODEL_NATIVE_DISCOVERY_WIRE_PIN,
        tool_policy=_pin(
            "native-repository-tools",
            "1.0.0",
            hashlib.sha256(NATIVE_REPOSITORY_TOOLS_JSON).hexdigest(),
        ),
        repository_scope=scope_pin,
        repository_view_policy=_pin(
            "bounded-repository-view",
            "1.0.0",
            _hash({"class": "DC3", "scope": "immutable", "blocked_content": "deny"}),
        ),
        budget=budget,
    )
    issuer = ModelAuthorizationIssuer(
        provider_registry=registry, policy_registry=EgressPolicyRegistry((policy,))
    )

    def preflight(selected: ModelRequest) -> ModelPreflightRequest:
        return ModelPreflightRequest(
            schema_version="0.2.0",
            model_request=selected,
            required_execution_boundary=profile.execution_boundary,
            required_data_class=DataClass.CONFIDENTIAL_SOURCE,
            required_purpose=selected.mode,
            planned_transforms=("bounded_repository_view",),
            required_max_bytes=selected.budget.max_context_bytes,
        )

    # Three-purpose source-free admission precedes object DB/source/context access.
    for role, purpose, prompt, schema in (
        (
            ModelRole.DISCOVERY,
            ModelPurpose.MODEL_NATIVE_DISCOVERY,
            PRODUCT_DISCOVERY_PROMPT_PIN,
            MODEL_NATIVE_DISCOVERY_WIRE_PIN,
        ),
        (
            ModelRole.AUDITOR,
            ModelPurpose.CANDIDATE_INVESTIGATION,
            PRODUCT_AUDITOR_PROMPT_PIN,
            AUDITOR_WIRE_PIN,
        ),
        (
            ModelRole.SKEPTIC,
            ModelPurpose.SKEPTIC_REVIEW,
            PRODUCT_SKEPTIC_PROMPT_PIN,
            SKEPTIC_WIRE_PIN,
        ),
    ):
        data = request.model_dump(mode="json")
        data.update(
            role=role.value,
            mode=purpose.value,
            prompt=prompt.model_dump(mode="json"),
            output_schema=schema.model_dump(mode="json"),
            evidence=[]
            if role is ModelRole.DISCOVERY
            else [
                EvidenceInputRef(
                    schema_version="0.2.0",
                    evidence_id="planned-private-source",
                    content_id="planned-private-source",
                    data_class=DataClass.CONFIDENTIAL_SOURCE,
                ).model_dump(mode="json")
            ],
        )
        planned = ModelRequest.model_validate_json(json.dumps(data))
        if (
            issuer.authorize_pre_context(
                preflight(planned), profile=profile, policy=policy
            ).result.eligibility
            is not PreflightEligibility.ELIGIBLE
        ):
            raise LocalProductUnavailableError()
        cancellation.checkpoint()
    objects = Path(
        _run_git_command(
            git_command,
            checkout,
            git,
            "rev-parse",
            "--git-path",
            "objects",
            cancellation=cancellation,
        )
    )
    if not objects.is_absolute():
        objects = checkout / objects
    reader = reader_factory(objects_dir=objects.absolute(), git_executable=git)
    content_key = os.urandom(32)
    catalogue = build_native_source_catalogue(
        reader=reader,
        head_sha=head,
        tenant_id=policy.tenant_scope,
        repository_id=repository_id,
        content_key=content_key,
    )
    cancellation.checkpoint()
    runtime = LocalWorkflowRuntime(registry=WorkflowDefinitionRegistry((workflow,)))
    started = runtime.start(
        WorkflowStartRequest(
            schema_version="0.2.0",
            operation=WorkflowOperation.START,
            request_id=run_id + "-start",
            run_id=run_id,
            tenant_id=policy.tenant_scope,
            execution_identity=identity,
            idempotency_key=run_id + "-start",
        )
    )
    if started.snapshot is None:
        raise LocalProductUnavailableError()
    latest = [started.snapshot]
    runtime_state_lock = Lock()

    def snapshot_for(
        selected_run: str, selected_identity: RunExecutionIdentity
    ) -> WorkflowSnapshot:
        with runtime_state_lock:
            previous = latest[0]
            observed = runtime.snapshot(
                WorkflowSnapshotRequest(
                    schema_version="0.2.0",
                    operation=WorkflowOperation.SNAPSHOT,
                    request_id=run_id + "-state",
                    run_id=selected_run,
                    tenant_id=policy.tenant_scope,
                    execution_identity=selected_identity,
                    expected_sequence=previous.journal_sequence,
                    expected_journal_head_sha256=previous.journal_head_sha256,
                    expected_state_sha256=previous.state_sha256,
                )
            )
            if observed.snapshot is None:
                raise LocalProductUnavailableError()
            latest[0] = observed.snapshot
            return observed.snapshot

    def reporting_policy(snapshot: WorkflowSnapshot) -> bool:
        if snapshot.execution_identity != identity:
            return False
        try:
            # Includes opened-object protection, exact anchored bytes, installed
            # pins, and real review/admit on every reporting/publication probe.
            current = (authority_loader or load_local_product_host)()
            current_authority = (
                current.approval_record_sha256,
                current.artifact_manifest_sha256,
                current.approved_bundle_sha256,
                current.profile.canonical_content_hash(),
                current.policy.canonical_content_hash(),
                _hash(current.artifact_manifest),
            )
            return current_authority == original_authority
        except Exception:
            return False

    probe = GitProductAuditStateProbe(
        checkout=checkout,
        git_executable=git,
        snapshot_for=snapshot_for,
        reporting_policy=reporting_policy,
    )

    runtime_cancelled = False

    def cancel() -> None:
        nonlocal runtime_cancelled
        if not runtime_state_lock.acquire(timeout=_RUNTIME_CANCEL_LOCK_TIMEOUT_SECONDS):
            raise LocalProductUnavailableError()
        try:
            if runtime_cancelled:
                return
            previous = latest[0]
            cancelled = runtime.cancel(
                WorkflowCancelRequest(
                    schema_version="0.2.0",
                    operation=WorkflowOperation.CANCEL,
                    request_id=run_id + "-cancel",
                    run_id=run_id,
                    tenant_id=policy.tenant_scope,
                    execution_identity=identity,
                    idempotency_key=run_id + "-cancel",
                    expected_sequence=previous.journal_sequence,
                    expected_journal_head_sha256=previous.journal_head_sha256,
                    expected_state_sha256=previous.state_sha256,
                )
            )
            if cancelled.snapshot is None:
                raise LocalProductUnavailableError()
            latest[0] = cancelled.snapshot
            runtime_cancelled = True
        finally:
            runtime_state_lock.release()

    if on_cancel is not None:
        on_cancel(cancel)
    cancellation.checkpoint()

    model_usage: list[ModelUsage] = []

    def observe_usage(usage: ModelUsage) -> None:
        model_usage.append(usage)
        if usage_observer is not None:
            usage_observer(usage)

    executor = AuthorizedLocalModelExecutor(
        harness=AuthorizedProviderHarness(
            model_issuer=issuer,
            endpoint_issuer=EndpointAuthorizationIssuer(provider_registry=registry),
        ),
        registry=registry,
        profile=profile,
        policy=policy,
        resolver=resolver,
        connector=(
            selected_runtime.connector
            if selected_runtime is not None
            else OpenAICompatibleLocalHttpConnector(profile=profile, cancelled=cancellation)
        ),
        preflight=preflight,
        credential_supplier=(
            selected_runtime.credential_supplier if selected_runtime is not None else None
        ),
        usage_observer=observe_usage,
        cost_observer=cost_observer,
    )
    tools_budget = RepositoryToolBudget(16, 65536, max_input)
    plan = ModelNativeDiscoveryPlan(
        receipt_id=run_id + "-native-receipt",
        request=request,
        preflight_eligibility=PreflightEligibility.ELIGIBLE,
        scope=RepositoryToolScope(
            policy.tenant_scope,
            repository_id,
            head,
            tuple(item.path for item in catalogue.snapshot.files),
            tuple(sorted(anchor.evidence_id for anchor in catalogue.anchors)),
        ),
        tool_budget=tools_budget,
        producer=ProducerRef(
            schema_version="0.2.0",
            producer_id="installed-local-discovery",
            producer_version="1.0.0",
            producer_sha256=PRODUCT_DISCOVERY_PROMPT_PIN.content_sha256,
        ),
    )
    observations: list[ProductAuditorInvocationObservation] = []

    def auditor_factory(
        graph: EvidenceGraph, tools: RepositoryToolSession
    ) -> ProductAuditorInvoker:
        return ProductAuditorInvoker(
            executor=executor,
            resolver=GuardedEvidenceResolver(tools=tools, evidence=graph.evidence),
            evidence_catalogue=graph.evidence,
            content_key=os.urandom(32),
            request_factory=lambda package, attempt, schema: build_role_request(
                request,
                package,
                attempt,
                schema,
                ModelRole.AUDITOR,
                ModelPurpose.CANDIDATE_INVESTIGATION,
                PRODUCT_AUDITOR_PROMPT_PIN,
            ),
            observer=observations.append,
        )

    def review_factory(
        flow: ProductCandidateFlow, tools: RepositoryToolSession
    ) -> ProductReviewResult:
        if not flow.graph.candidates:
            # There is no candidate-local Skeptic obligation. Core still decides
            # the whole-run outcome from actual discovery/coverage observations.
            return run_product_candidate_review(
                flow,
                auditor_identity_for=lambda candidate, receipt: "installed-local-auditor",
                severity_for=lambda candidate: (
                    classify_product_cwe(_candidate_family(candidate, flow.graph)[1]).severity
                ),
                skeptic=None,
            )
        skeptic = ProductSkepticReviewPort(
            executor=executor,
            resolver=GuardedEvidenceResolver(tools=tools, evidence=flow.graph.evidence),
            evidence_catalogue=flow.graph.evidence,
            content_key=os.urandom(32),
            skeptic_identity="installed-local-skeptic",
            tenant_id=policy.tenant_scope,
            package_for=lambda snapshot: build_evidence_package(flow.graph, snapshot.candidate_id),
            request_factory=lambda snapshot, package, attempt, schema: build_role_request(
                request,
                package,
                attempt,
                schema,
                ModelRole.SKEPTIC,
                ModelPurpose.SKEPTIC_REVIEW,
                PRODUCT_SKEPTIC_PROMPT_PIN,
            ),
        )
        return run_product_candidate_review(
            flow,
            auditor_identity_for=lambda candidate, receipt: "installed-local-auditor",
            severity_for=lambda candidate: (
                classify_product_cwe(_candidate_family(candidate, flow.graph)[1]).severity
            ),
            skeptic=skeptic,
        )

    retained_graph: list[bytes] = []

    def finalize_host(
        flow: ProductCandidateFlow, review: ProductReviewResult, bound: ProductAuditHostInputs
    ) -> ProductAuditHostInputs:
        graph_bytes, graph_ref = _retain_evidence_graph(
            graph=flow.graph,
            tenant_id=policy.tenant_scope,
            head_sha=identity.repository_revision.head_sha,
        )
        retained_graph.append(graph_bytes)
        candidates = {(c.candidate_id, c.candidate_version): c for c in flow.graph.candidates}
        metadata = []
        for outcome in review.outcomes:
            if outcome.has_known_blocking_finding:
                candidate = candidates[outcome.candidate_id, outcome.candidate_version]
                rule, cwe = _candidate_family(candidate, flow.graph)
                metadata.append(
                    ProductAuditFindingMetadata(
                        candidate.candidate_id,
                        candidate.candidate_version,
                        "finding-" + candidate.candidate_id,
                        cwe,
                        graph_ref,
                        rule,
                        candidate.root_cause_fingerprint,
                    )
                )
        return replace(
            bound,
            auditor_observations=tuple(observations),
            finding_metadata=tuple(metadata),
            completed_at=datetime.now(UTC),
        )

    now = datetime.now(UTC)
    inputs = ProductAuditHostInputs(
        run_id=run_id,
        execution_identity=identity,
        discovery_request=request,
        auditor=_pin("installed-local-auditor", "1.0.0", PRODUCT_AUDITOR_PROMPT_PIN.content_sha256),
        source_catalogue=catalogue,
        created_at=now,
        completed_at=now,
        state_probe=probe,
    )
    cancellation.checkpoint()
    selected_dependency_scanner = dependency_scanner
    if selected_dependency_scanner is None:
        selected_dependency_scanner = BoundedOsvScanner(
            timeout_seconds=min(15.0, float(profile.budgets.timeout_seconds)),
            cancelled=cancellation,
        )
    result = execute_product_audit(
        reader=reader,
        host=inputs,
        content_key=content_key,
        fingerprint_key=SecretFingerprintKey("local-ephemeral", os.urandom(32)),
        dependency_scanner=selected_dependency_scanner,
        model_plan=plan,
        model_backend=ProductDiscoveryBackend(
            executor=executor,
            catalogue=catalogue.anchors,
            rule_ids=frozenset(_RULES),
            content_key=content_key,
        ),
        auditor_factory=auditor_factory,
        review_factory=review_factory,
        finalize_host=finalize_host,
        investigation_budget=InvestigationBudget(
            min(2, profile.budgets.max_attempts),
            profile.budgets.max_total_tokens,
            32,
            profile.budgets.timeout_seconds * 1000,
        ),
        tool_budget=tools_budget,
    )
    cancellation.checkpoint()
    if isinstance(result, ProductAuditObstacle):
        if result.code == "PRODUCT_AUDIT_CANCELLED":
            raise LocalProductCancelledError()
        if result.code == "PRODUCT_AUDIT_SUPERSEDED":
            raise LocalProductSupersededError()
        raise LocalProductUnavailableError()
    rendered = render_report(result.report, report_format)
    sarif_rendered = render_report(result.report, ReportFormat.SARIF)
    outcome = LocalProductScanResult(
        result,
        rendered,
        sarif_rendered,
        2
        if result.run.audit_outcome is AuditRunOutcome.FAIL
        else 0
        if result.run.audit_outcome is AuditRunOutcome.PASS
        else 3,
        probe,
        retained_graph[0],
        sum(item.input_tokens + item.output_tokens for item in model_usage),
        0,
        cancel,
    )
    outcome.require_publication()
    return outcome
