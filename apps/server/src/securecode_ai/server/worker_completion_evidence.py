"""Independent verification of artifacts required for terminal worker outcomes."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from securecode_ai.contracts import (
    ArtifactRef,
    AuditRun,
    ComponentPin,
    CoverageManifest,
    DataClass,
    DiscoveryCandidate,
    Evidence,
    FindingCase,
    RepositoryRevision,
    RunExecutionIdentity,
    SourceLocation,
)
from securecode_ai.core.classification import classify_product_cwe
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)

from .worker_findings import WorkerFindingRecord
from .worker_queue_models import WorkerQueueConflict, identity_document

_MAX_ARTIFACT_BYTES: Final = 16_777_216
_REPORT_KEYS: Final = frozenset(
    {
        "analysis_health",
        "coverage_manifest",
        "execution_identity",
        "execution_identity_hash",
        "findings",
        "model_profile",
        "outcome",
        "policy",
        "report_version",
        "repository_revision",
        "run_id",
        "schema_version",
        "tools",
        "workflow",
    }
)
_REPORT_FINDING_KEYS: Final = frozenset(
    {
        "blocking",
        "candidate_id",
        "candidate_origin",
        "confidence",
        "cwe_id",
        "evidence_graph_ref",
        "evidence_ids",
        "finding_id",
        "locations",
        "mapping_provenance",
        "owasp_category",
        "patch_refs",
        "producer_lineage",
        "root_cause_fingerprint",
        "severity",
        "validation_refs",
        "verdict",
    }
)
_GRAPH_KEYS: Final = frozenset(
    {"candidates", "edges", "evidence", "head_sha", "schema_version", "tenant_id"}
)


def verify_terminal_evidence(
    *,
    connection: sqlite3.Connection,
    artifact_root: Path,
    tenant_id: str,
    run_id: str,
    execution_identity_hash: str,
    outcome: str,
    findings: tuple[WorkerFindingRecord, ...],
) -> None:
    """Require canonical report and graph bytes before accepting PASS or FAIL."""

    load_verified_terminal_audit_run(
        connection=connection,
        artifact_root=artifact_root,
        tenant_id=tenant_id,
        run_id=run_id,
        execution_identity_hash=execution_identity_hash,
        outcome=outcome,
        findings=findings,
    )


def load_verified_terminal_audit_run(
    *,
    connection: sqlite3.Connection,
    artifact_root: Path,
    tenant_id: str,
    run_id: str,
    execution_identity_hash: str,
    outcome: str,
    findings: tuple[WorkerFindingRecord, ...],
    include_graph: bool = False,
    include_findings: bool = False,
) -> AuditRun | tuple[AuditRun, EvidenceGraph] | tuple[AuditRun, EvidenceGraph, tuple[FindingCase, ...]] | None:
    """Load an AuditRun only after validating its stored terminal evidence."""

    if outcome not in {"PASS", "FAIL"}:
        return None
    if not isinstance(connection, sqlite3.Connection) or not isinstance(artifact_root, Path):
        raise WorkerQueueConflict()
    row = connection.execute(
        """SELECT execution_identity_json FROM worker_run_queue
           WHERE tenant_id=? AND run_id=?""",
        (tenant_id, run_id),
    ).fetchone()
    if row is None:
        raise WorkerQueueConflict()
    try:
        expected_identity = identity_document(row["execution_identity_json"])
    except (KeyError, TypeError, ValueError):
        raise WorkerQueueConflict() from None
    if expected_identity.execution_identity_hash != execution_identity_hash:
        raise WorkerQueueConflict()

    artifacts = connection.execute(
        """SELECT metadata_json FROM run_artifacts
           WHERE tenant_id=? AND run_id=?
             AND purpose IN ('audit-report', 'audit-run', 'evidence-graph')
           ORDER BY purpose, content_sha256""",
        (tenant_id, run_id),
    ).fetchall()
    selected: dict[str, dict[str, object]] = {}
    for artifact_row in artifacts:
        metadata = _closed_json_text(artifact_row["metadata_json"])
        purpose = metadata.get("purpose")
        if purpose not in {"audit-report", "audit-run", "evidence-graph"} or purpose in selected:
            raise WorkerQueueConflict()
        selected[str(purpose)] = metadata
    if set(selected) != {"audit-report", "audit-run", "evidence-graph"}:
        raise WorkerQueueConflict()

    report_bytes = _payload(artifact_root, tenant_id, selected["audit-report"])
    run_bytes = _payload(artifact_root, tenant_id, selected["audit-run"])
    graph_bytes = _payload(artifact_root, tenant_id, selected["evidence-graph"])
    report = _canonical_document(report_bytes, newline=True)
    _canonical_document(run_bytes, newline=False)
    graph_document = _canonical_document(graph_bytes, newline=False)
    graph_digest = str(selected["evidence-graph"]["content_sha256"])
    graph = _validated_graph(graph_document, graph_digest)
    try:
        audit_run = AuditRun.model_validate_json(run_bytes)
    except (TypeError, ValueError):
        raise WorkerQueueConflict() from None
    report_findings = _validate_report(
        report,
        expected_identity=expected_identity,
        tenant_id=tenant_id,
        run_id=run_id,
        outcome=outcome,
        findings=findings,
        graph=graph,
        graph_digest=graph_digest,
        audit_run=audit_run,
    )
    if include_findings:
        if not include_graph:
            raise WorkerQueueConflict()
        return audit_run, graph, report_findings
    return (audit_run, graph) if include_graph else audit_run


def load_verified_evidence_graph(
    *,
    artifact_root: Path,
    tenant_id: str,
    metadata: Mapping[str, object],
) -> EvidenceGraph:
    """Load and verify one content-addressed source-free EvidenceGraph artifact."""

    if metadata.get("purpose") != "evidence-graph":
        raise WorkerQueueConflict()
    payload = _payload(artifact_root, tenant_id, metadata)
    document = _closed_json_bytes(payload)
    digest = metadata.get("content_sha256")
    if type(digest) is not str:
        raise WorkerQueueConflict()
    return _validated_graph(document, digest)


def _validate_report(
    document: dict[str, Any],
    *,
    expected_identity: RunExecutionIdentity,
    tenant_id: str,
    run_id: str,
    outcome: str,
    findings: tuple[WorkerFindingRecord, ...],
    graph: EvidenceGraph,
    graph_digest: str,
    audit_run: AuditRun,
) -> tuple[FindingCase, ...]:
    try:
        if (
            set(document) != _REPORT_KEYS
            or document["schema_version"] != "0.2.0"
            or document["report_version"] != "1.0.0"
            or document["run_id"] != run_id
            or document["outcome"] != outcome
            or document["execution_identity_hash"] != expected_identity.execution_identity_hash
            or audit_run.run_id != run_id
            or audit_run.execution_identity != expected_identity
            or audit_run.current_head_sha != expected_identity.repository_revision.head_sha
            or audit_run.audit_outcome.value != outcome
        ):
            raise ValueError
        identity = RunExecutionIdentity.model_validate_json(
            _json_value(document["execution_identity"])
        )
        revision = RepositoryRevision.model_validate_json(
            _json_value(document["repository_revision"])
        )
        coverage = CoverageManifest.model_validate_json(_json_value(document["coverage_manifest"]))
        tools_value = document["tools"]
        if type(tools_value) is not list:
            raise ValueError
        tools = tuple(ComponentPin.model_validate_json(_json_value(item)) for item in tools_value)
        authoritative_tools = _authoritative_report_tools(expected_identity, coverage)
        if (
            identity != expected_identity
            or revision != identity.repository_revision
            or revision.tenant_id != tenant_id
            or graph.tenant_id != revision.tenant_id
            or graph.head_sha != revision.head_sha
            or document["model_profile"] != identity.provider_profile.model_dump(mode="json")
            or document["policy"] != identity.policy.model_dump(mode="json")
            or document["workflow"] != identity.workflow.model_dump(mode="json")
            or coverage.execution_identity_hash != identity.execution_identity_hash
            or coverage.catalogue != identity.stage_catalogue
            or tuple(coverage.discovery_candidates) != graph.candidates
            or coverage != audit_run.coverage_manifest
            or document["analysis_health"] != audit_run.analysis_health.value
            or tools != authoritative_tools
        ):
            raise ValueError
        report_findings = document["findings"]
        if type(report_findings) is not list or len(report_findings) != len(findings):
            raise ValueError
        finding_ids = tuple(item.finding_id for item in findings)
        blocking_ids = tuple(item.finding_id for item in findings if item.blocking)
        if (
            finding_ids != audit_run.finding_ids
            or blocking_ids != audit_run.blocking_finding_ids
            or (outcome == "PASS" and not audit_run.publication_preconditions_met)
        ):
            raise ValueError
        validated_findings = tuple(
            _validate_finding(reported, finding, graph, graph_digest)
            for reported, finding in zip(report_findings, findings, strict=True)
        )
        return validated_findings
    except (KeyError, TypeError, ValueError):
        raise WorkerQueueConflict() from None


def _authoritative_report_tools(
    identity: RunExecutionIdentity,
    coverage: CoverageManifest,
) -> tuple[ComponentPin, ...]:
    """Return only tool claims authorized by the admitted identity.

    The current execution identity has no tool-manifest field.  Its catalogue
    pin authorizes coverage semantics, not arbitrary executable tool pins, so
    the only safe report tool set is empty until such a manifest is admitted as
    part of the identity hash.
    """

    if coverage.catalogue != identity.stage_catalogue:
        raise ValueError
    return ()


def _validate_finding(
    value: object,
    finding: WorkerFindingRecord,
    graph: EvidenceGraph,
    graph_digest: str,
) -> FindingCase:
    if not isinstance(value, Mapping) or set(value) != _REPORT_FINDING_KEYS:
        raise ValueError
    finding_case = FindingCase.model_validate_json(_json_value(value))
    reference = ArtifactRef.model_validate_json(_json_value(value["evidence_graph_ref"]))
    locations_value = value["locations"]
    if type(locations_value) is not list:
        raise ValueError
    locations = tuple(
        SourceLocation.model_validate_json(_json_value(item)) for item in locations_value
    )
    projected_locations = tuple((item.path, item.start.line, item.end.line) for item in locations)
    expected_locations = tuple(
        (item.path, item.start_line, item.end_line) for item in finding.locations
    )
    candidate = next(
        (item for item in graph.candidates if item.candidate_id == value.get("candidate_id")),
        None,
    )
    evidence_by_id = {item.evidence_id: item for item in graph.evidence}
    canonical_locations = (
        ()
        if candidate is None
        else tuple(
            sorted(
                {
                    record.location
                    for evidence_id in candidate.evidence_ids
                    if (record := evidence_by_id.get(evidence_id)) is not None
                    and record.location is not None
                },
                key=lambda item: (item.path, item.start.line, item.start.column),
            )
        )
    )
    classification = classify_product_cwe(finding.cwe_id)
    provenance = classification.provenance
    expected_provenance = {
        "calibration_record_id": provenance.calibration_record_id,
        "confidence_basis": provenance.confidence_basis,
        "mapping_id": provenance.mapping_id,
        "mapping_sha256": provenance.mapping_sha256,
        "mapping_version": provenance.mapping_version,
        "severity_basis": provenance.severity_basis,
    }
    if (
        candidate is None
        or value["finding_id"] != finding.finding_id
        or value["cwe_id"] != finding.cwe_id
        or value["severity"] != finding.severity
        or value["confidence"] != finding.confidence
        or value["verdict"] != finding.verdict
        or value["blocking"] is not finding.blocking
        or value["root_cause_fingerprint"] != finding.root_cause_fingerprint
        or projected_locations != expected_locations
        or reference != finding.evidence_graph_ref
        or reference.data_class is not DataClass.CONFIDENTIAL_SECURITY
        or reference.content_sha256 != graph_digest
        or value["candidate_origin"] != candidate.candidate_origin.value
        or value["root_cause_fingerprint"] != candidate.root_cause_fingerprint
        or value["producer_lineage"] != [item.model_dump(mode="json") for item in candidate.lineage]
        or value["evidence_ids"] != list(candidate.evidence_ids)
        or locations != canonical_locations
        or value["owasp_category"] != classification.owasp_category
        or value["severity"] != classification.severity.value
        or value["confidence"] != classification.confidence.value
        or value["mapping_provenance"] != expected_provenance
        or value["patch_refs"] != []
        or value["validation_refs"] != []
    ):
        raise ValueError
    return finding_case


def _validated_graph(document: dict[str, Any], digest: str) -> EvidenceGraph:
    try:
        if set(document) != _GRAPH_KEYS or document["schema_version"] != "1.0.0":
            raise ValueError
        candidates_value = document["candidates"]
        evidence_value = document["evidence"]
        edges_value = document["edges"]
        if not all(
            type(value) is list for value in (candidates_value, evidence_value, edges_value)
        ):
            raise ValueError
        graph = EvidenceGraph(
            graph_id="completion-" + digest[:48],
            tenant_id=document["tenant_id"],
            head_sha=document["head_sha"],
            candidates=tuple(
                DiscoveryCandidate.model_validate_json(_json_value(item))
                for item in candidates_value
            ),
            evidence=tuple(
                Evidence.model_validate_json(_json_value(item)) for item in evidence_value
            ),
            edges=tuple(_edge(item) for item in edges_value),
        )
        if graph.canonical_payload != document or graph.graph_sha256 != digest:
            raise ValueError
        return graph
    except (KeyError, TypeError, ValueError):
        raise WorkerQueueConflict() from None


def _edge(value: object) -> EvidenceGraphEdge:
    if not isinstance(value, Mapping) or set(value) != {"kind", "source", "target"}:
        raise ValueError
    source = value["source"]
    target = value["target"]
    if (
        not isinstance(source, Mapping)
        or not isinstance(target, Mapping)
        or set(source) != {"kind", "node_id"}
        or set(target) != {"kind", "node_id"}
    ):
        raise ValueError
    return EvidenceGraphEdge(
        EvidenceEdgeKind(value["kind"]),
        EvidenceNodeRef(EvidenceNodeKind(source["kind"]), source["node_id"]),
        EvidenceNodeRef(EvidenceNodeKind(target["kind"]), target["node_id"]),
    )


def _payload(root: Path, tenant_id: str, metadata: Mapping[str, object]) -> bytes:
    digest = metadata.get("content_sha256")
    size = metadata.get("size_bytes")
    if (
        type(digest) is not str
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or type(size) is not int
        or not 1 <= size <= _MAX_ARTIFACT_BYTES
    ):
        raise WorkerQueueConflict()
    target = root / tenant_id / digest[:2] / digest / "payload"
    _plain_chain(root, target.parent)
    descriptor = -1
    try:
        descriptor = os.open(
            target,
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size != size:
            raise WorkerQueueConflict()
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            content = stream.read(_MAX_ARTIFACT_BYTES + 1)
        if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
            raise WorkerQueueConflict()
        return content
    except OSError:
        raise WorkerQueueConflict() from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _plain_chain(root: Path, target: Path) -> None:
    try:
        resolved = root.resolve(strict=True)
        if target != resolved and resolved not in target.parents:
            raise ValueError
        current = resolved
        details = current.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or bool(getattr(details, "st_reparse_tag", 0))
        ):
            raise ValueError
        for part in target.relative_to(resolved).parts:
            current /= part
            details = current.lstat()
            if (
                not stat.S_ISDIR(details.st_mode)
                or stat.S_ISLNK(details.st_mode)
                or bool(getattr(details, "st_reparse_tag", 0))
            ):
                raise ValueError
    except (OSError, ValueError):
        raise WorkerQueueConflict() from None


def _canonical_document(value: bytes, *, newline: bool) -> dict[str, Any]:
    document = _closed_json_bytes(value)
    canonical = json.dumps(
        document,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + (b"\n" if newline else b"")
    if value != canonical:
        raise WorkerQueueConflict()
    return document


def _closed_json_bytes(value: bytes) -> dict[str, Any]:
    try:
        document = json.loads(value.decode("utf-8"), object_pairs_hook=_closed_object)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise WorkerQueueConflict() from None
    if type(document) is not dict:
        raise WorkerQueueConflict()
    return document


def _closed_json_text(value: object) -> dict[str, object]:
    if type(value) is not str:
        raise WorkerQueueConflict()
    return _closed_json_bytes(value.encode("utf-8"))


def _json_value(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


__all__ = [
    "load_verified_evidence_graph",
    "load_verified_terminal_audit_run",
    "verify_terminal_evidence",
]
