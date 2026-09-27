"""Mandatory discovery and Auditor composition over one admitted Git revision.

This stage cannot publish a product PASS. Remaining policy, coverage, Skeptic,
repair and report stages retain their own acceptance requirements.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from securecode_ai.contracts import AuditRunOutcome, CandidateOrigin, DiscoveryCandidate, Evidence
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)
from securecode_ai.core.evidence_package import EvidencePackage, build_evidence_package
from securecode_ai.core.investigation import (
    AuditorInvestigationReceipt,
    AuditorInvocation,
    AuditorInvoker,
    InvestigationBudget,
    ReadOnlyEvidenceContext,
    run_auditor_investigation,
)
from securecode_ai.core.model_discovery import (
    ModelNativeDiscoveryBackend,
    ModelNativeDiscoveryOutcome,
    ModelNativeDiscoveryPlan,
    run_model_native_discovery,
)
from securecode_ai.core.normalization import normalize_signals

from .native_sources import NativeSourceCatalogue
from .product_execution import (
    ProductDeterministicExecution,
    RestrictedProductDiscoveryView,
    execution_fact_graph,
)
from .product_scanner import ProductDeterministicScanResult, scanner_facts_match_receipts


def _snapshot_graph(graph: EvidenceGraph) -> EvidenceGraph:
    if type(graph) is not EvidenceGraph:
        raise ValueError("product graph input is invalid")
    return EvidenceGraph(
        graph_id=graph.graph_id,
        tenant_id=graph.tenant_id,
        head_sha=graph.head_sha,
        candidates=graph.candidates,
        evidence=graph.evidence,
        edges=graph.edges,
        schema_version=graph.schema_version,
    )


def _deterministic_completion_is_bound(
    catalogue: NativeSourceCatalogue,
    result: ProductDeterministicScanResult,
    *,
    repository_id: str,
) -> bool:
    """Accept completion only with the scanner's source-free receipt proof."""

    if type(result) is not ProductDeterministicScanResult or result.is_complete is not True:
        return False
    return scanner_facts_match_receipts(
        catalogue,
        result,
        repository_id=repository_id,
    )


def merge_product_lane_graphs(
    *,
    graph_id: str,
    deterministic: EvidenceGraph,
    native: EvidenceGraph,
) -> EvidenceGraph:
    """Merge exact fingerprints, preserving every producer and cited source."""
    deterministic, native = _snapshot_graph(deterministic), _snapshot_graph(native)
    if (
        deterministic.tenant_id != native.tenant_id
        or deterministic.head_sha != native.head_sha
        or any(
            c.candidate_origin is not CandidateOrigin.DETERMINISTIC
            for c in deterministic.candidates
        )
        or any(c.candidate_origin is not CandidateOrigin.MODEL_NATIVE for c in native.candidates)
    ):
        raise ValueError("product lane identity is invalid")
    candidates = normalize_signals(
        discovery_candidates=(*deterministic.candidates, *native.candidates)
    )
    evidence: dict[str, Evidence] = {}
    for record in (*deterministic.evidence, *native.evidence):
        if record.evidence_id in evidence and evidence[record.evidence_id] != record:
            raise ValueError("product evidence identity collision")
        evidence[record.evidence_id] = record
    edges = {
        edge
        for edge in (*deterministic.edges, *native.edges)
        if edge.kind is EvidenceEdgeKind.EVIDENCE_DERIVED_FROM
    }
    for candidate in candidates:
        for evidence_id in candidate.evidence_ids:
            edges.add(
                EvidenceGraphEdge(
                    EvidenceEdgeKind.CANDIDATE_EVIDENCE,
                    EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
                    EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
                )
            )
    return EvidenceGraph(
        graph_id=graph_id,
        tenant_id=native.tenant_id,
        head_sha=native.head_sha,
        candidates=candidates,
        evidence=tuple(evidence.values()),
        edges=tuple(edges),
    )


class _ClosedGraphContext:
    def next_package(self, package: EvidencePackage, *, attempt: int) -> EvidencePackage | None:
        # No new evidence is fabricated to make a NEEDS_MORE_EVIDENCE verdict pass.
        return None


class _UnavailableAuditor:
    def invoke(self, package: EvidencePackage, *, attempt: int) -> AuditorInvocation:
        raise RuntimeError("product Auditor dependency unavailable")


@dataclass(frozen=True, slots=True)
class ProductCandidatePreparationFailure:
    """An identity-bound unavailable result, never a fabricated Auditor receipt."""

    candidate: DiscoveryCandidate
    tenant_id: str
    head_sha: str

    @property
    def candidate_id(self) -> str:
        return self.candidate.candidate_id

    @property
    def candidate_version(self) -> int:
        return self.candidate.candidate_version

    @property
    def is_indeterminate(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class ProductCompositionFailure:
    """Keep both lane outcomes when no trustworthy merged graph can be built."""

    discovery: ModelNativeDiscoveryOutcome
    deterministic: EvidenceGraph
    native: EvidenceGraph
    deterministic_failed: bool

    @property
    def required_terminal_outcome(self) -> AuditRunOutcome:
        return AuditRunOutcome.INDETERMINATE


@dataclass(frozen=True, slots=True)
class ProductCandidateFlow:
    discovery: ModelNativeDiscoveryOutcome
    graph: EvidenceGraph
    investigations: tuple[AuditorInvestigationReceipt | ProductCandidatePreparationFailure, ...]
    deterministic_failed: bool
    required_terminal_outcome: AuditRunOutcome | None

    def __post_init__(self) -> None:
        if (
            type(self.discovery) is not ModelNativeDiscoveryOutcome
            or type(self.graph) is not EvidenceGraph
            or type(self.investigations) is not tuple
            or type(self.deterministic_failed) is not bool
            or any(
                type(receipt)
                not in (AuditorInvestigationReceipt, ProductCandidatePreparationFailure)
                for receipt in self.investigations
            )
        ):
            raise ValueError("product candidate flow is invalid")
        keys = tuple((c.candidate_id, c.candidate_version) for c in self.graph.candidates)
        actual = tuple((r.candidate_id, r.candidate_version) for r in self.investigations)
        if keys != actual or any(
            r.tenant_id != self.graph.tenant_id or r.head_sha != self.graph.head_sha
            for r in self.investigations
        ):
            raise ValueError("product candidate interpretation coverage is invalid")
        incomplete = (
            self.deterministic_failed
            or self.discovery.required_terminal_outcome is not None
            or any(receipt.is_indeterminate for receipt in self.investigations)
        )
        expected = AuditRunOutcome.INDETERMINATE if incomplete else None
        if self.required_terminal_outcome is not expected:
            raise ValueError("product candidate terminal requirement is invalid")


def run_product_candidate_flow(
    *,
    catalogue: NativeSourceCatalogue,
    model_plan: ModelNativeDiscoveryPlan,
    model_backend: ModelNativeDiscoveryBackend,
    deterministic_scanner: Callable[
        [NativeSourceCatalogue], EvidenceGraph | ProductDeterministicScanResult
    ],
    auditor_factory: Callable[[EvidenceGraph], AuditorInvoker],
    investigation_budget: InvestigationBudget,
    context_factory: Callable[[EvidenceGraph], ReadOnlyEvidenceContext] | None = None,
    deterministic_execution: ProductDeterministicExecution | None = None,
) -> ProductCandidateFlow | ProductCompositionFailure:
    """Run both mandatory lanes and retain a bounded receipt for each candidate.

    Ports are host-owned dependencies. The scanner receives retained admitted
    source, never provider-created candidates. A deterministic fault cannot skip
    the independent model lane or become completed-zero coverage.
    """
    if (
        type(catalogue) is not NativeSourceCatalogue
        or type(model_plan) is not ModelNativeDiscoveryPlan
        or type(investigation_budget) is not InvestigationBudget
    ):
        raise ValueError("product scan bindings are invalid")
    expected_repository_id = (
        model_plan.request.execution_identity.repository_revision.repository_id
    )
    if (
        catalogue.snapshot.head_sha != model_plan.request.head_sha
        or any(
            index.repository_id != expected_repository_id
            or index.revision != model_plan.request.head_sha
            for index in catalogue.indexes
        )
        or any(anchor.tenant_id != model_plan.request.tenant_id for anchor in catalogue.anchors)
    ):
        raise ValueError("product scan bindings are invalid")
    if deterministic_execution is not None and (
        type(deterministic_execution) is not ProductDeterministicExecution
        or deterministic_execution.catalogue.snapshot != catalogue.snapshot
        or deterministic_execution.repository_id != expected_repository_id
    ):
        raise ValueError("product discovery execution binding is invalid")
    discovery = run_model_native_discovery(
        model_plan,
        repository=RestrictedProductDiscoveryView(deterministic_execution)
        if deterministic_execution is not None
        else catalogue.repository_view(),
        backend=model_backend,
    )
    native = catalogue.evidence_graph(
        graph_id="product-native", candidates=discovery.candidates, producer=model_plan.producer
    )
    deterministic_failed = False
    try:
        lane_result: EvidenceGraph | ProductDeterministicScanResult
        if deterministic_execution is not None:
            if (
                type(deterministic_execution) is not ProductDeterministicExecution
                or deterministic_execution.catalogue.snapshot != catalogue.snapshot
            ):
                raise ValueError("deterministic execution binding is invalid")
            lane_result = execution_fact_graph(deterministic_execution, tenant_id=native.tenant_id)
            deterministic_failed = not deterministic_execution.is_complete
        else:
            lane_result = deterministic_scanner(catalogue)
        if type(lane_result) is ProductDeterministicScanResult:
            if type(lane_result.is_complete) is not bool:
                raise ValueError("deterministic completion is invalid")
            deterministic_failed = not _deterministic_completion_is_bound(
                catalogue,
                lane_result,
                repository_id=expected_repository_id,
            )
            deterministic = _snapshot_graph(lane_result.graph)
        elif isinstance(lane_result, EvidenceGraph):
            # Only the explicit execution path carries a separately validated
            # completion receipt; arbitrary bare graphs remain indeterminate.
            if deterministic_execution is None:
                deterministic_failed = True
            deterministic = _snapshot_graph(lane_result)
        else:
            raise ValueError("deterministic lane result is invalid")
        if (
            deterministic.tenant_id != native.tenant_id
            or deterministic.head_sha != native.head_sha
            or any(
                c.candidate_origin is not CandidateOrigin.DETERMINISTIC
                for c in deterministic.candidates
            )
        ):
            raise ValueError("deterministic lane binding is invalid")
    except Exception:
        deterministic_failed = True
        deterministic = EvidenceGraph(
            graph_id="product-deterministic-unavailable",
            tenant_id=native.tenant_id,
            head_sha=native.head_sha,
            candidates=(),
            evidence=(),
            edges=(),
        )
    try:
        graph = merge_product_lane_graphs(
            graph_id="product-converged", deterministic=deterministic, native=native
        )
    except Exception:
        return ProductCompositionFailure(discovery, deterministic, native, deterministic_failed)
    investigations: tuple[
        AuditorInvestigationReceipt | ProductCandidatePreparationFailure, ...
    ] = ()
    if graph.candidates:
        try:
            auditor = auditor_factory(graph)
            context = (
                context_factory(graph) if context_factory is not None else _ClosedGraphContext()
            )
            if not callable(getattr(auditor, "invoke", None)) or not callable(
                getattr(context, "next_package", None)
            ):
                raise ValueError("product interpretation dependencies unavailable")
        except Exception:
            auditor = _UnavailableAuditor()
            context = _ClosedGraphContext()
        results: list[AuditorInvestigationReceipt | ProductCandidatePreparationFailure] = []
        for candidate in graph.candidates:
            result: AuditorInvestigationReceipt | ProductCandidatePreparationFailure
            try:
                package = build_evidence_package(graph, candidate.candidate_id)
                result = run_auditor_investigation(
                    package, budget=investigation_budget, auditor=auditor, context=context
                )
            except Exception:
                result = ProductCandidatePreparationFailure(
                    candidate, graph.tenant_id, graph.head_sha
                )
            results.append(result)
        investigations = tuple(results)
    incomplete = (
        deterministic_failed
        or discovery.required_terminal_outcome is not None
        or any(receipt.is_indeterminate for receipt in investigations)
    )
    return ProductCandidateFlow(
        discovery,
        graph,
        investigations,
        deterministic_failed,
        AuditRunOutcome.INDETERMINATE if incomplete else None,
    )
