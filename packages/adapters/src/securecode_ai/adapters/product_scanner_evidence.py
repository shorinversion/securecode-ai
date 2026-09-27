"""Evidence graph assembly for deterministic scanner facts."""

from __future__ import annotations

import hashlib
import json
from typing import cast

from securecode_ai.adapters.cwe89_contracts import Cwe89ScanResult, Cwe89Signal
from securecode_ai.adapters.cwe89_multilanguage_models import (
    MultilanguageCwe89ScanResult,
    MultilanguageCwe89Signal,
)
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
from securecode_ai.core.program_graph import ProgramGraph
from securecode_ai.core.tool_policy import ReadRangeArguments

from . import cwe89, cwe89_multilanguage, cwe_portfolio, python_ast
from .native_sources import NativeSourceCatalogue


def _scanner_graph_from_signals(
    catalogue: NativeSourceCatalogue,
    signals: tuple[RawSignal, ...],
    tenant_id: str,
    producer: ProducerRef,
    *,
    program_graph: ProgramGraph | None = None,
) -> tuple[EvidenceGraph, tuple[tuple[str, bytes, str], ...]]:
    indexes = {index.path: index for index in catalogue.indexes}
    if len(indexes) != len(catalogue.indexes):
        raise ValueError("scanner source paths are ambiguous")
    if len({signal.raw_signal_id for signal in signals}) != len(signals):
        raise ValueError("scanner receipt contains duplicate signal identities")
    for signal in signals:
        index = indexes.get(signal.location.path)
        if (
            index is None
            or signal.tenant_id != tenant_id
            or signal.producer != producer
            or signal.head_sha != catalogue.snapshot.head_sha
            or index.revision != catalogue.snapshot.head_sha
            or signal.location.content_sha256 != index.content_sha256
            or hashlib.sha256(index.source).hexdigest() != index.content_sha256
            or not _location_within_source(index.source, signal.location)
        ):
            raise ValueError("scanner signal is outside its admitted source identity")
    candidates = normalize_signals(raw_signals=tuple(signals))
    records = []
    aliases = []
    signal_by_id = {signal.raw_signal_id: signal for signal in signals}
    flow_records, flow_edges, flow_ids_by_signal, flow_aliases = _scanner_sql_flow_evidence(
        catalogue, signal_by_id, tenant_id, producer
    )
    command_records, command_edges, command_ids_by_signal, command_aliases = (
        _scanner_command_flow_evidence(catalogue, signal_by_id, tenant_id, producer)
    )
    flow_records = (*flow_records, *command_records)
    flow_edges = (*flow_edges, *command_edges)
    flow_ids_by_signal = {**flow_ids_by_signal, **command_ids_by_signal}
    flow_aliases = (*flow_aliases, *command_aliases)
    if program_graph is not None:
        (
            portfolio_records,
            portfolio_edges,
            portfolio_ids_by_signal,
            portfolio_aliases,
        ) = _scanner_portfolio_flow_evidence(
            catalogue, signal_by_id, tenant_id, producer, program_graph=program_graph
        )
        flow_records = (*flow_records, *portfolio_records)
        flow_edges = (*flow_edges, *portfolio_edges)
        flow_ids_by_signal = {**flow_ids_by_signal, **portfolio_ids_by_signal}
        flow_aliases = (*flow_aliases, *portfolio_aliases)
    for signal in signals:
        windows = [
            anchor
            for anchor in catalogue.anchors
            if isinstance(anchor.request.arguments, ReadRangeArguments)
            and anchor.location.path == signal.location.path
            and anchor.location.content_sha256 == signal.location.content_sha256
            and anchor.request.arguments.start_line <= signal.location.start.line
            and anchor.request.arguments.end_line >= signal.location.end.line
        ]
        if not windows:
            raise ValueError("scanner root has no admitted source window")
        anchor = min(windows, key=lambda item: (item.read_artifact.size_bytes, item.evidence_id))
        content = catalogue._window_bytes(anchor)
        record = Evidence(
            schema_version="0.2.0",
            evidence_id=signal.raw_signal_id,
            tenant_id=tenant_id,
            head_sha=catalogue.snapshot.head_sha,
            evidence_kind=EvidenceKind.SCANNER_SIGNAL,
            producer=producer,
            trust_label=TrustLabel.UNTRUSTED_TOOL_OUTPUT,
            data_class=anchor.read_artifact.data_class,
            evidence_sha256=signal.signal_sha256,
            location=signal.location,
            artifact_ref=anchor.read_artifact,
        )
        records.append(record)
        aliases.append((record.evidence_id, content, anchor.read_artifact.content_sha256))
    records.extend(_bind_derived_artifact_content_ids(tuple(flow_records), tuple(flow_aliases)))
    aliases.extend(flow_aliases)
    bound = []
    for candidate in candidates:
        data = candidate.model_dump(mode="json")
        ids = sorted({sid for lineage in candidate.lineage for sid in lineage.input_signal_ids})
        derived_ids = sorted(
            {
                evidence_id
                for signal_id in ids
                for evidence_id in flow_ids_by_signal.get(signal_id, ())
            }
        )
        data["evidence_ids"] = sorted((*ids, *derived_ids))
        for lineage in data["lineage"]:
            lineage["evidence_ids"] = sorted(
                {
                    *lineage["input_signal_ids"],
                    *(
                        evidence_id
                        for signal_id in lineage["input_signal_ids"]
                        for evidence_id in flow_ids_by_signal.get(signal_id, ())
                    ),
                }
            )
        bound.append(DiscoveryCandidate.model_validate_json(json.dumps(data)))
    candidate_edges = tuple(
        EvidenceGraphEdge(
            EvidenceEdgeKind.CANDIDATE_EVIDENCE,
            EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
            EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
        )
        for candidate in bound
        for evidence_id in candidate.evidence_ids
    )
    graph = EvidenceGraph(
        graph_id="product-deterministic",
        tenant_id=tenant_id,
        head_sha=catalogue.snapshot.head_sha,
        candidates=tuple(bound),
        evidence=tuple(records),
        edges=(*candidate_edges, *flow_edges),
    )
    return graph, tuple(aliases)


def _bind_derived_artifact_content_ids(
    records: tuple[Evidence, ...],
    aliases: tuple[tuple[str, bytes, str], ...],
) -> tuple[Evidence, ...]:
    """Bind generated metadata to source scope and the conservative source class."""
    payload_by_evidence_id = {
        evidence_id: (payload, payload_sha256) for evidence_id, payload, payload_sha256 in aliases
    }
    if len(payload_by_evidence_id) != len(aliases):
        raise ValueError("scanner artifact aliases are ambiguous")
    bound = []
    for record in records:
        artifact = record.artifact_ref
        alias = payload_by_evidence_id.get(record.evidence_id)
        if artifact is None or alias is None:
            raise ValueError("scanner artifact binding is incomplete")
        payload, payload_sha256 = alias
        if hashlib.sha256(payload).hexdigest() != payload_sha256:
            raise ValueError("scanner artifact digest is invalid")
        data = record.model_dump(mode="json")
        artifact_data = data["artifact_ref"]
        if type(artifact_data) is not dict or artifact_data["content_sha256"] != payload_sha256:
            raise ValueError("scanner artifact binding is invalid")
        artifact_data["content_id"] = "kid:" + payload_sha256
        bound.append(Evidence.model_validate_json(json.dumps(data)))
    return tuple(bound)


def _scanner_command_flow_evidence(
    catalogue: NativeSourceCatalogue,
    signals: dict[str, RawSignal],
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[
    tuple[Evidence, ...],
    tuple[EvidenceGraphEdge, ...],
    dict[str, tuple[str, ...]],
    tuple[tuple[str, bytes, str], ...],
]:
    """Retain exact Python CWE-78 operation/source/sink bindings."""

    records: dict[str, Evidence] = {}
    edges: set[EvidenceGraphEdge] = set()
    by_signal: dict[str, tuple[str, ...]] = {}
    aliases: dict[str, tuple[bytes, str]] = {}
    indexes = {index.path: index for index in catalogue.indexes}
    for signal in signals.values():
        binding = signal.command_operation_evidence
        if binding is None:
            continue
        index = indexes.get(binding.sink.path)
        if (
            signal.producer != producer
            or signal.tenant_id != tenant_id
            or signal.head_sha != catalogue.snapshot.head_sha
            or signal.rule_id != "portfolio-cwe-78"
            or index is None
            or binding.scanner_signal_id != signal.raw_signal_id
            or binding.sink != signal.location
            or binding.source.path != index.path
            or binding.sink.path != index.path
            or binding.source.content_sha256 != index.content_sha256
            or binding.sink.content_sha256 != index.content_sha256
            or not _location_within_source(index.source, binding.source)
            or not _location_within_source(index.source, binding.sink)
        ):
            raise ValueError("CWE-78 command endpoints do not match scanner receipt")
        endpoints: list[str] = []
        for role, location in (("source", binding.source), ("sink", binding.sink)):
            material = {
                "detail": binding.detail,
                "location": location.model_dump(mode="json"),
                "operation": binding.operation.value,
                "raw_signal_id": signal.raw_signal_id,
                "role": role,
                "signal_sha256": signal.signal_sha256,
            }
            digest = hashlib.sha256(
                json.dumps(material, sort_keys=True, separators=(",", ":")).encode("ascii")
            ).hexdigest()
            endpoint_id = f"command-{role}-{digest}"
            payload = json.dumps(
                {**material, "evidence_id": endpoint_id},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            payload_sha256 = hashlib.sha256(payload).hexdigest()
            artifact = ArtifactRef(
                schema_version="0.2.0",
                tenant_id=tenant_id,
                content_id="product-command-endpoint-artifact-" + payload_sha256,
                content_sha256=payload_sha256,
                size_bytes=len(payload),
                data_class=DataClass.INTERNAL_METADATA,
            )
            records[endpoint_id] = Evidence(
                schema_version="0.2.0",
                evidence_id=endpoint_id,
                tenant_id=tenant_id,
                head_sha=catalogue.snapshot.head_sha,
                evidence_kind=EvidenceKind.SOURCE_LOCATION,
                producer=producer,
                trust_label=TrustLabel.UNTRUSTED_TOOL_OUTPUT,
                data_class=DataClass.INTERNAL_METADATA,
                evidence_sha256=digest,
                location=location,
                artifact_ref=artifact,
            )
            aliases[endpoint_id] = (payload, payload_sha256)
            edges.add(
                EvidenceGraphEdge(
                    EvidenceEdgeKind.EVIDENCE_DERIVED_FROM,
                    EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, endpoint_id),
                    EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, signal.raw_signal_id),
                )
            )
            endpoints.append(endpoint_id)
        flow_material = {
            "detail": binding.detail,
            "operation": binding.operation.value,
            "raw_signal_id": signal.raw_signal_id,
            "signal_sha256": signal.signal_sha256,
            "sink_location_id": endpoints[1],
            "source_location_id": endpoints[0],
        }
        flow_digest = hashlib.sha256(
            json.dumps(flow_material, sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        flow_id = f"command-flow-{flow_digest}"
        flow_payload = json.dumps(
            {**flow_material, "flow_id": flow_id},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        flow_artifact_sha256 = hashlib.sha256(flow_payload).hexdigest()
        flow_artifact = ArtifactRef(
            schema_version="0.2.0",
            tenant_id=tenant_id,
            content_id="product-command-flow-artifact-" + flow_artifact_sha256,
            content_sha256=flow_artifact_sha256,
            size_bytes=len(flow_payload),
            data_class=DataClass.INTERNAL_METADATA,
        )
        records[flow_id] = Evidence(
            schema_version="0.2.0",
            evidence_id=flow_id,
            tenant_id=tenant_id,
            head_sha=catalogue.snapshot.head_sha,
            evidence_kind=EvidenceKind.DATA_FLOW,
            producer=producer,
            trust_label=TrustLabel.UNTRUSTED_TOOL_OUTPUT,
            data_class=DataClass.INTERNAL_METADATA,
            evidence_sha256=flow_digest,
            artifact_ref=flow_artifact,
        )
        aliases[flow_id] = (flow_payload, flow_artifact_sha256)
        for evidence_id in (*endpoints, signal.raw_signal_id):
            edges.add(
                EvidenceGraphEdge(
                    EvidenceEdgeKind.EVIDENCE_DERIVED_FROM,
                    EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, flow_id),
                    EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
                )
            )
        by_signal[signal.raw_signal_id] = (*endpoints, flow_id)
    return (
        tuple(records.values()),
        tuple(edges),
        by_signal,
        tuple((evidence_id, payload, digest) for evidence_id, (payload, digest) in aliases.items()),
    )


def _location_within_source(source: bytes, location: SourceLocation) -> bool:
    lines = source.splitlines()
    if not lines or location.start.line > len(lines) or location.end.line > len(lines):
        return False
    return (
        1 <= location.start.line <= location.end.line
        and location.start.column >= 1
        and location.end.column >= 1
        and location.start.column <= len(lines[location.start.line - 1]) + 1
        and location.end.column <= len(lines[location.end.line - 1]) + 1
        and (
            location.start.line < location.end.line or location.start.column <= location.end.column
        )
    )


def _scanner_sql_flow_evidence(
    catalogue: NativeSourceCatalogue,
    signals: dict[str, RawSignal],
    tenant_id: str,
    producer: ProducerRef,
) -> tuple[
    tuple[Evidence, ...],
    tuple[EvidenceGraphEdge, ...],
    dict[str, tuple[str, ...]],
    tuple[tuple[str, bytes, str], ...],
]:
    """Retain typed CWE-89 flow only when it exactly matches a scanner signal."""
    records: dict[str, Evidence] = {}
    edges: set[EvidenceGraphEdge] = set()
    by_signal: dict[str, tuple[str, ...]] = {}
    aliases: dict[str, tuple[bytes, str]] = {}
    for index in catalogue.indexes:
        if not any(
            signal.rule_id == "cwe-89-sql-interpolation"
            and signal.location.path == index.path
            and signal.head_sha == index.revision
            for signal in signals.values()
        ):
            continue
        result: Cwe89ScanResult | MultilanguageCwe89ScanResult
        if index.language == "python":
            analysis = python_ast.analyze_python_ast(index)
            result = cwe89.scan_python_cwe89(index, analysis)
        elif index.language in {"javascript", "typescript", "go"}:
            scanner = {
                "javascript": cwe89_multilanguage.scan_javascript_cwe89,
                "typescript": cwe89_multilanguage.scan_typescript_cwe89,
                "go": cwe89_multilanguage.scan_go_cwe89,
            }[index.language]
            result = scanner(index)
        else:
            continue
        for ordinal, flow_value in enumerate(result.signals):
            flow = cast(Cwe89Signal | MultilanguageCwe89Signal, flow_value)
            material = [
                "product-sql-fact-v1",
                tenant_id,
                index.repository_id,
                index.revision,
                result.scan_sha256,
                ordinal,
                producer.model_dump(mode="json"),
            ]
            digest = hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()
            signal_id = "product-sql-" + digest
            signal = signals.get(signal_id)
            if (
                signal is None
                or signal.producer != producer
                or signal.tenant_id != tenant_id
                or signal.head_sha != index.revision
                or signal.rule_id != "cwe-89-sql-interpolation"
                or signal.location.path != flow.path
                or signal.location.content_sha256 != flow.content_sha256
                or signal.location.start.line != flow.sink.start_point.row + 1
                or signal.location.start.column != flow.sink.start_point.column + 1
                or signal.location.end.line != flow.sink.end_point.row + 1
                or signal.location.end.column != flow.sink.end_point.column + 1
            ):
                raise ValueError("CWE-89 evidence is not covered by its scanner receipt")
            flow_source_ids = []
            for role, location_range in (
                ("source", flow.source),
                ("interpolation", flow.interpolation),
                ("sink", flow.sink),
            ):
                location = SourceLocation(
                    schema_version="0.2.0",
                    path=flow.path,
                    start=SourcePosition(
                        schema_version="0.2.0",
                        line=location_range.start_point.row + 1,
                        column=location_range.start_point.column + 1,
                    ),
                    end=SourcePosition(
                        schema_version="0.2.0",
                        line=location_range.end_point.row + 1,
                        column=location_range.end_point.column + 1,
                    ),
                    content_sha256=flow.content_sha256,
                )
                location_material = {
                    "raw_signal_id": signal_id,
                    "role": role,
                    "location": location.model_dump(mode="json"),
                }
                location_digest = hashlib.sha256(
                    json.dumps(location_material, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                evidence_id = "sql-location-" + location_digest
                payload = json.dumps(
                    location_material,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                payload_sha256 = hashlib.sha256(payload).hexdigest()
                artifact = ArtifactRef(
                    schema_version="0.2.0",
                    tenant_id=tenant_id,
                    content_id="product-sql-location-artifact-" + location_digest,
                    content_sha256=payload_sha256,
                    size_bytes=len(payload),
                    data_class=DataClass.INTERNAL_METADATA,
                )
                records[evidence_id] = Evidence(
                    schema_version="0.2.0",
                    evidence_id=evidence_id,
                    tenant_id=tenant_id,
                    head_sha=catalogue.snapshot.head_sha,
                    evidence_kind=EvidenceKind.SOURCE_LOCATION,
                    producer=producer,
                    trust_label=TrustLabel.UNTRUSTED_TOOL_OUTPUT,
                    data_class=DataClass.INTERNAL_METADATA,
                    evidence_sha256=location_digest,
                    location=location,
                    artifact_ref=artifact,
                )
                aliases[evidence_id] = (payload, payload_sha256)
                flow_source_ids.append(evidence_id)
                edges.add(
                    EvidenceGraphEdge(
                        EvidenceEdgeKind.EVIDENCE_DERIVED_FROM,
                        EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
                        EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, signal_id),
                    )
                )
            flow_material = {
                "raw_signal_id": signal_id,
                "signal_sha256": signal.signal_sha256,
                "source_location_ids": flow_source_ids,
                "detector": flow.detector,
                "cwe": flow.cwe,
            }
            flow_digest = hashlib.sha256(
                json.dumps(flow_material, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            flow_id = "sql-data-flow-" + flow_digest
            flow_location = SourceLocation(
                schema_version="0.2.0",
                path=flow.path,
                start=SourcePosition(
                    schema_version="0.2.0",
                    line=flow.sink.start_point.row + 1,
                    column=flow.sink.start_point.column + 1,
                ),
                end=SourcePosition(
                    schema_version="0.2.0",
                    line=flow.sink.end_point.row + 1,
                    column=flow.sink.end_point.column + 1,
                ),
                content_sha256=flow.content_sha256,
            )
            flow_payload = json.dumps(
                {
                    "cwe": flow.cwe,
                    "detector": flow.detector,
                    "flow_id": flow_id,
                    "location": flow_location.model_dump(mode="json"),
                    "raw_signal_id": signal_id,
                    "source_location_ids": flow_source_ids,
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            flow_artifact_sha256 = hashlib.sha256(flow_payload).hexdigest()
            flow_artifact = ArtifactRef(
                schema_version="0.2.0",
                tenant_id=tenant_id,
                content_id="product-sql-flow-artifact-" + flow_artifact_sha256,
                content_sha256=flow_artifact_sha256,
                size_bytes=len(flow_payload),
                data_class=DataClass.INTERNAL_METADATA,
            )
            records[flow_id] = Evidence(
                schema_version="0.2.0",
                evidence_id=flow_id,
                tenant_id=tenant_id,
                head_sha=catalogue.snapshot.head_sha,
                evidence_kind=EvidenceKind.DATA_FLOW,
                producer=producer,
                trust_label=TrustLabel.UNTRUSTED_TOOL_OUTPUT,
                data_class=DataClass.INTERNAL_METADATA,
                evidence_sha256=flow_digest,
                location=flow_location,
                artifact_ref=flow_artifact,
            )
            aliases[flow_id] = (flow_payload, flow_artifact_sha256)
            for evidence_id in (*flow_source_ids, signal_id):
                edges.add(
                    EvidenceGraphEdge(
                        EvidenceEdgeKind.EVIDENCE_DERIVED_FROM,
                        EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, flow_id),
                        EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
                    )
                )
            by_signal[signal_id] = (*flow_source_ids, flow_id)
    return (
        tuple(records.values()),
        tuple(edges),
        by_signal,
        tuple((evidence_id, payload, digest) for evidence_id, (payload, digest) in aliases.items()),
    )


def _scanner_portfolio_flow_evidence(
    catalogue: NativeSourceCatalogue,
    signals: dict[str, RawSignal],
    tenant_id: str,
    producer: ProducerRef,
    *,
    program_graph: ProgramGraph,
) -> tuple[
    tuple[Evidence, ...],
    tuple[EvidenceGraphEdge, ...],
    dict[str, tuple[str, ...]],
    tuple[tuple[str, bytes, str], ...],
]:
    """Preserve the exact recognized source and sink endpoints of portfolio facts."""
    records: dict[str, Evidence] = {}
    edges: set[EvidenceGraphEdge] = set()
    by_signal: dict[str, tuple[str, ...]] = {}
    aliases: dict[str, tuple[bytes, str]] = {}
    for index in catalogue.indexes:
        result = cwe_portfolio.scan_cwe_portfolio(index)
        expected = cwe_portfolio.portfolio_signals_to_raw_signals(
            result, tenant_id=tenant_id, producer=producer
        )
        for fact, expected_signal in zip(result.signals, expected, strict=True):
            signal = signals.get(expected_signal.raw_signal_id)
            if (
                signal != expected_signal
                or fact.repository_id != index.repository_id
                or fact.revision != index.revision
                or fact.path != index.path
                or fact.content_sha256 != index.content_sha256
                or fact.source_size_bytes != index.source_byte_length
                or fact.source.end_byte > len(index.source)
                or fact.sink.end_byte > len(index.source)
                or program_graph.repository_id != index.repository_id
                or program_graph.revision != index.revision
            ):
                raise ValueError("CWE portfolio endpoints do not match scanner receipt")
            endpoints = []
            for role, span in (("source", fact.source), ("sink", fact.sink)):
                location = SourceLocation(
                    schema_version="0.2.0",
                    path=fact.path,
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
                    content_sha256=fact.content_sha256,
                )
                material = {
                    "raw_signal_id": signal.raw_signal_id,
                    "signal_sha256": signal.signal_sha256,
                    "role": role,
                    "detector": fact.detector,
                    "location": location.model_dump(mode="json"),
                    "program_graph_sha256": program_graph.graph_sha256,
                }
                digest = hashlib.sha256(
                    json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                endpoint_id = f"portfolio-{role}-{hashlib.sha256(signal.raw_signal_id.encode()).hexdigest()[:16]}"
                payload = json.dumps(
                    {**material, "evidence_id": endpoint_id},
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("ascii")
                payload_sha256 = hashlib.sha256(payload).hexdigest()
                artifact = ArtifactRef(
                    schema_version="0.2.0",
                    tenant_id=tenant_id,
                    content_id="product-portfolio-endpoint-artifact-" + payload_sha256,
                    content_sha256=payload_sha256,
                    size_bytes=len(payload),
                    data_class=DataClass.INTERNAL_METADATA,
                )
                records[endpoint_id] = Evidence(
                    schema_version="0.2.0",
                    evidence_id=endpoint_id,
                    tenant_id=tenant_id,
                    head_sha=catalogue.snapshot.head_sha,
                    evidence_kind=EvidenceKind.SOURCE_LOCATION,
                    producer=producer,
                    trust_label=TrustLabel.UNTRUSTED_TOOL_OUTPUT,
                    data_class=DataClass.INTERNAL_METADATA,
                    evidence_sha256=digest,
                    location=location,
                    artifact_ref=artifact,
                )
                aliases[endpoint_id] = (payload, payload_sha256)
                edges.add(
                    EvidenceGraphEdge(
                        EvidenceEdgeKind.EVIDENCE_DERIVED_FROM,
                        EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, endpoint_id),
                        EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, signal.raw_signal_id),
                    )
                )
                endpoints.append(endpoint_id)
            flow_material = {
                "raw_signal_id": signal.raw_signal_id,
                "signal_sha256": signal.signal_sha256,
                "source_location_id": endpoints[0],
                "sink_location_id": endpoints[1],
                "source": _source_range_payload(fact.source),
                "sink": _source_range_payload(fact.sink),
                "content_sha256": fact.content_sha256,
                "repository_id": fact.repository_id,
                "revision": fact.revision,
                "detector": fact.detector,
                "cwe": fact.cwe,
                "relation": "recognized_source_to_sink_endpoints",
            }
            digest = hashlib.sha256(
                json.dumps(flow_material, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            flow_id = f"portfolio-flow-{digest}"
            payload = json.dumps(
                {**flow_material, "flow_id": flow_id},
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            payload_sha256 = hashlib.sha256(payload).hexdigest()
            artifact = ArtifactRef(
                schema_version="0.2.0",
                tenant_id=tenant_id,
                content_id="product-portfolio-flow-artifact-" + payload_sha256,
                content_sha256=payload_sha256,
                size_bytes=len(payload),
                data_class=DataClass.INTERNAL_METADATA,
            )
            records[flow_id] = Evidence(
                schema_version="0.2.0",
                evidence_id=flow_id,
                tenant_id=tenant_id,
                head_sha=catalogue.snapshot.head_sha,
                evidence_kind=EvidenceKind.DATA_FLOW,
                producer=producer,
                trust_label=TrustLabel.UNTRUSTED_TOOL_OUTPUT,
                data_class=DataClass.INTERNAL_METADATA,
                evidence_sha256=digest,
                artifact_ref=artifact,
            )
            aliases[flow_id] = (payload, payload_sha256)
            for evidence_id in (*endpoints, signal.raw_signal_id):
                edges.add(
                    EvidenceGraphEdge(
                        EvidenceEdgeKind.EVIDENCE_DERIVED_FROM,
                        EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, flow_id),
                        EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, evidence_id),
                    )
                )
            by_signal[signal.raw_signal_id] = (*endpoints, flow_id)
    return (
        tuple(records.values()),
        tuple(edges),
        by_signal,
        tuple((evidence_id, payload, digest) for evidence_id, (payload, digest) in aliases.items()),
    )


def _source_range_payload(location: SourceRange) -> dict[str, object]:
    return {
        "start_byte": location.start_byte,
        "end_byte": location.end_byte,
        "start_point": [location.start_point.row, location.start_point.column],
        "end_point": [location.end_point.row, location.end_point.column],
    }
