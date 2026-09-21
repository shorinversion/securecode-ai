"""Actual catalogue children over admitted Git bytes.

This module is an in-progress execution boundary, not a complete audit or a
publication authority. Child results alone cannot authorize a product PASS.
"""

from __future__ import annotations

import hashlib
import json

from securecode_ai.contracts import (
    ArtifactRef,
    DataClass,
    DiscoveryCandidate,
    Evidence,
    EvidenceKind,
    ProducerRef,
    RawSignal,
    SourceLocation,
    SourcePosition,
    TrustLabel,
)
from securecode_ai.core import SourceRange
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)
from securecode_ai.core.normalization import normalize_signals
from securecode_ai.core.tool_policy import (
    ListPathsArguments,
    LookupSymbolArguments,
    ReadEvidenceArguments,
    ReadRangeArguments,
    RepositoryToolOutput,
    RepositoryToolWindow,
)

from .product_execution_orchestration import ProductChildFacts, child_fact_graph
from .product_execution_stages import (
    ProductDeterministicExecution,
    ProductSecretStageResult,
)


def child_fact_catalogue(
    execution: ProductDeterministicExecution, *, tenant_id: str
) -> ProductChildFacts:
    """Retain every secret/advisory fact as a candidate, never as a verdict.

    Secret metadata remains DC4, so the existing evidence-package boundary
    explicitly refuses model interpretation. No matched secret or source bytes
    are present in this graph. Advisory metadata is independent of repository
    source and retains its exact immutable manifest location.
    """
    if any(anchor.tenant_id != tenant_id for anchor in execution.catalogue.anchors):
        raise ValueError("PRODUCT_CHILD_FACT_TENANT_INVALID")
    producer = ProducerRef(
        schema_version="0.2.0",
        producer_id="securecode-child-facts",
        producer_version="1.0.0",
        producer_sha256=_child_producer_sha256(),
    )
    facts: list[tuple[str, str, str, SourceRange, str, DataClass, dict[str, object]]] = []
    if execution.secrets is not None:
        for result in execution.secrets.results:
            for candidate in result.candidates:
                facts.append(
                    (
                        "secret-" + candidate.kind.value,
                        candidate.path,
                        candidate.content_sha256,
                        candidate.location,
                        candidate.fingerprint_sha256,
                        DataClass.RESTRICTED,
                        {
                            "kind": candidate.kind.value,
                            "redaction": candidate.redaction,
                            "producer": candidate.producer.value,
                        },
                    )
                )
    if execution.dependencies is not None:
        for dependency_result in execution.dependencies.results:
            for advisory in dependency_result.advisories:
                coordinate = advisory.coordinate
                facts.append(
                    (
                        "dependency-advisory",
                        coordinate.manifest_path,
                        coordinate.manifest_sha256,
                        coordinate.location,
                        advisory.advisory_sha256,
                        DataClass.INTERNAL_METADATA,
                        {
                            "advisory_id": advisory.advisory_id,
                            "aliases": advisory.aliases,
                            "purl": coordinate.purl,
                            "producer": advisory.producer,
                        },
                    )
                )
    signals = []
    evidence = []
    artifacts = []
    for ordinal, (rule, path, source_hash, span, digest, data_class, detail) in enumerate(facts):
        location = SourceLocation(
            schema_version="0.2.0",
            path=path,
            content_sha256=source_hash,
            start=SourcePosition(
                schema_version="0.2.0",
                line=span.start_point.row + 1,
                column=span.start_point.column + 1,
            ),
            end=SourcePosition(
                schema_version="0.2.0",
                line=span.end_point.row + 1,
                column=span.end_point.column + 1,
            ),
        )
        payload = json.dumps(
            {
                "rule_id": rule,
                "path": path,
                "source_sha256": source_hash,
                "fact_sha256": digest,
                "detail": detail,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        payload_hash = hashlib.sha256(payload).hexdigest()
        artifact = ArtifactRef(
            schema_version="0.2.0",
            tenant_id=tenant_id,
            content_id="child-fact-" + payload_hash,
            content_sha256=payload_hash,
            size_bytes=len(payload),
            data_class=data_class,
        )
        artifacts.append((artifact.content_id, payload))
        signal_id = f"child-fact-{ordinal}-{digest}"
        signals.append(
            RawSignal(
                schema_version="0.2.0",
                raw_signal_id=signal_id,
                tenant_id=tenant_id,
                head_sha=execution.catalogue.snapshot.head_sha,
                producer=producer,
                rule_id=rule,
                location=location,
                payload_classification=data_class,
                payload_ref=artifact,
                signal_sha256=payload_hash,
            )
        )
        evidence.append(
            Evidence(
                schema_version="0.2.0",
                evidence_id=signal_id,
                tenant_id=tenant_id,
                head_sha=execution.catalogue.snapshot.head_sha,
                evidence_kind=EvidenceKind.SCANNER_SIGNAL,
                producer=producer,
                trust_label=TrustLabel.UNTRUSTED_TOOL_OUTPUT,
                data_class=data_class,
                evidence_sha256=payload_hash,
                location=location,
                artifact_ref=artifact,
            )
        )
    candidates = []
    for normalized in normalize_signals(raw_signals=tuple(signals)):
        data = normalized.model_dump(mode="json")
        ids = sorted({sid for lineage in normalized.lineage for sid in lineage.input_signal_ids})
        data["evidence_ids"] = ids
        for lineage in data["lineage"]:
            lineage["evidence_ids"] = lineage["input_signal_ids"]
        candidates.append(DiscoveryCandidate.model_validate_json(json.dumps(data)))
    edges = tuple(
        EvidenceGraphEdge(
            EvidenceEdgeKind.CANDIDATE_EVIDENCE,
            EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
            EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
        )
        for candidate in candidates
        for evidence_id in candidate.evidence_ids
    )
    graph = EvidenceGraph(
        graph_id="product-child-facts",
        tenant_id=tenant_id,
        head_sha=execution.catalogue.snapshot.head_sha,
        candidates=tuple(candidates),
        evidence=tuple(evidence),
        edges=edges,
    )

    return ProductChildFacts(graph, tuple(artifacts))


def _child_producer_sha256() -> str:
    from pathlib import Path

    root = Path(__file__).resolve().parent
    manifest = [
        (name, hashlib.sha256((root / name).read_bytes()).hexdigest())
        for name in ("product_execution.py", "secret_detection.py", "dependency_scanning.py")
    ]
    return hashlib.sha256(json.dumps(manifest, separators=(",", ":")).encode()).hexdigest()


def execution_fact_graph(
    execution: ProductDeterministicExecution, *, tenant_id: str
) -> EvidenceGraph:
    """Merge retained static and child facts without consuming model authority."""
    child = child_fact_graph(execution, tenant_id=tenant_id)
    static = execution.scan.graph
    if static.tenant_id != tenant_id or static.head_sha != child.head_sha:
        raise ValueError("PRODUCT_CHILD_FACT_IDENTITY_INVALID")
    candidates = normalize_signals(discovery_candidates=(*static.candidates, *child.candidates))
    records = {record.evidence_id: record for record in static.evidence}
    for record in child.evidence:
        if record.evidence_id in records and records[record.evidence_id] != record:
            raise ValueError("PRODUCT_CHILD_FACT_COLLISION")
        records[record.evidence_id] = record
    edges = tuple(
        EvidenceGraphEdge(
            EvidenceEdgeKind.CANDIDATE_EVIDENCE,
            EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
            EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
        )
        for candidate in candidates
        for evidence_id in candidate.evidence_ids
    )
    return EvidenceGraph(
        graph_id="product-deterministic-union",
        tenant_id=tenant_id,
        head_sha=child.head_sha,
        candidates=candidates,
        evidence=tuple(records.values()),
        edges=edges,
    )


def restricted_product_source_paths(execution: ProductDeterministicExecution) -> tuple[str, ...]:
    """Unverified secret coverage cannot grant any model raw-source capability."""
    snapshot = execution.catalogue.snapshot
    all_paths = tuple(file.path for file in snapshot.files)
    try:
        secrets = execution.secrets
        if type(secrets) is not ProductSecretStageResult or secrets.head_sha != snapshot.head_sha:
            return all_paths
        if tuple(
            (r.path, r.content_sha256, r.source_size_bytes, r.repository_id, r.revision)
            for r in secrets.results
        ) != tuple(
            (f.path, f.content_sha256, len(f.content), execution.repository_id, snapshot.head_sha)
            for f in snapshot.files
        ):
            return all_paths
        for result in secrets.results:
            result.__post_init__()
        material = [
            "product-secret-stage-v1",
            execution.repository_id,
            snapshot.head_sha,
            snapshot.tree_oid,
            [(r.path, r.content_sha256, r.scan_sha256) for r in secrets.results],
        ]
        digest = hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).hexdigest()
        if secrets.output_sha256 != digest:
            return all_paths
        return tuple(result.path for result in secrets.results if result.candidates)
    except Exception:
        return all_paths


class RestrictedProductDiscoveryView:
    """Deny raw secret-file capabilities without altering discovery contracts."""

    def __init__(self, execution: ProductDeterministicExecution):
        self._backend = execution.catalogue.repository_view()
        self._paths = set(restricted_product_source_paths(execution))
        self._evidence = {
            anchor.evidence_id
            for anchor in execution.catalogue.anchors
            if anchor.location.path in self._paths
        }

    def read_range(
        self, arguments: ReadRangeArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        if arguments.path in self._paths:
            raise ValueError("PRODUCT_DISCOVERY_RESTRICTED_SOURCE")
        return self._backend.read_range(arguments, window=window)

    def read_evidence(
        self, arguments: ReadEvidenceArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        if arguments.evidence_id in self._evidence:
            raise ValueError("PRODUCT_DISCOVERY_RESTRICTED_SOURCE")
        return self._backend.read_evidence(arguments, window=window)

    def list_paths(
        self, arguments: ListPathsArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        if self._paths:
            raise ValueError("PRODUCT_DISCOVERY_RESTRICTED_SOURCE")
        return self._backend.list_paths(arguments, window=window)

    def lookup_symbol(
        self, arguments: LookupSymbolArguments, *, window: RepositoryToolWindow
    ) -> RepositoryToolOutput:
        if arguments.path in self._paths or (arguments.path is None and self._paths):
            raise ValueError("PRODUCT_DISCOVERY_RESTRICTED_SOURCE")
        return self._backend.lookup_symbol(arguments, window=window)
