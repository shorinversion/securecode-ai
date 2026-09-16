"""P7.1/P7.2 multi-file deterministic-fact ingress into the common pipeline."""

from __future__ import annotations

import hashlib

import pytest
from securecode_ai.adapters import (
    build_go_symbol_index,
    build_javascript_symbol_index,
    build_program_graph,
    build_typescript_symbol_index,
    multilanguage_cwe89_signals_to_raw_signals,
    scan_go_cwe89,
    scan_javascript_cwe89,
    scan_typescript_cwe89,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    AuditRun,
    CandidateOrigin,
    DataClass,
    DiscoveryCandidate,
    Evidence,
    EvidenceKind,
    FindingCase,
    FindingVerdict,
    ProducerRef,
    SourceLocation,
    SourcePosition,
    TrustLabel,
)
from securecode_ai.core.classification import classify_cwe
from securecode_ai.core.evidence_graph import (
    EvidenceEdgeKind,
    EvidenceGraph,
    EvidenceGraphEdge,
    EvidenceNodeKind,
    EvidenceNodeRef,
)
from securecode_ai.core.normalization import normalize_signals
from securecode_ai.core.reports import (
    ReportFinding,
    ReportFormat,
    build_deterministic_report,
    render_report,
)

from tests.unit.test_reports import _pin as _report_pin
from tests.unit.test_reports import _run as _report_run

HEAD = "a" * 40
TENANT = "tenant-1"


@pytest.mark.parametrize("language", ["javascript", "typescript", "go"])
def test_js_ts_positive_and_safe_multifile_facts_enter_common_normalization(
    language: str,
) -> None:
    repository = _report_run().execution_identity.repository_revision
    assert repository.tenant_id == TENANT and repository.head_sha == HEAD
    javascript = b"const id = req.query.id;\nconst sql = `SELECT ${id}`;\ndb.query(sql);\n"
    typescript = (
        b"const id: string = request.query.id;\nconst sql = `SELECT ${id}`;\ndb.execute(sql);\n"
    )
    go = b'package api\nimport "fmt"\nfunc lookup(r *Request, db DB) {\n id := r.URL.Query().Get("id")\n sql := fmt.Sprintf("SELECT %s", id)\n db.Query(sql)\n}\n'
    go_safe = b'package api\nfunc lookup(r *Request, db DB) {\n id := r.URL.Query().Get("id")\n db.Query("SELECT ?", id)\n}\n'
    safe = b"const id = req.query.id;\ndb.query('SELECT ?', [id]);\n"
    js_index = build_javascript_symbol_index(
        repository_id=repository.repository_id,
        revision=HEAD,
        path="api/lookup.js",
        content_sha256=hashlib.sha256(javascript).hexdigest(),
        source=javascript,
    )
    ts_index = build_typescript_symbol_index(
        repository_id=repository.repository_id,
        revision=HEAD,
        path="api/lookup.ts",
        content_sha256=hashlib.sha256(typescript).hexdigest(),
        source=typescript,
    )
    safe_index = build_javascript_symbol_index(
        repository_id=repository.repository_id,
        revision=HEAD,
        path="api/safe.js",
        content_sha256=hashlib.sha256(safe).hexdigest(),
        source=safe,
    )
    go_index = build_go_symbol_index(
        repository_id=repository.repository_id,
        revision=HEAD,
        path="api/lookup.go",
        content_sha256=hashlib.sha256(go).hexdigest(),
        source=go,
    )
    go_safe_index = build_go_symbol_index(
        repository_id=repository.repository_id,
        revision=HEAD,
        path="api/safe.go",
        content_sha256=hashlib.sha256(go_safe).hexdigest(),
        source=go_safe,
    )
    js_scan = scan_javascript_cwe89(js_index)
    ts_scan = scan_typescript_cwe89(ts_index)
    go_scan = scan_go_cwe89(go_index)
    program_graph = build_program_graph(
        (js_index, ts_index, go_index),
        (js_scan, ts_scan, go_scan),
    )
    assert len(js_scan.signals) == len(ts_scan.signals) == len(go_scan.signals) == 1
    assert {node.language for node in program_graph.nodes} == {
        "javascript",
        "typescript",
        "go",
    }
    assert scan_javascript_cwe89(safe_index).signals == ()
    assert scan_go_cwe89(go_safe_index).signals == ()

    ts_safe_index = build_typescript_symbol_index(
        repository_id=repository.repository_id,
        revision=HEAD,
        path="api/safe.ts",
        content_sha256=hashlib.sha256(safe).hexdigest(),
        source=safe,
    )
    safe_indexes = (safe_index, ts_safe_index, go_safe_index)
    safe_scans = (
        scan_javascript_cwe89(safe_index),
        scan_typescript_cwe89(ts_safe_index),
        scan_go_cwe89(go_safe_index),
    )
    for safe_item, safe_scan in zip(safe_indexes, safe_scans, strict=True):
        assert (
            multilanguage_cwe89_signals_to_raw_signals(
                safe_item,
                safe_scan,
                tenant_id=TENANT,
                producer=ProducerRef(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    producer_id=f"securecode-{safe_item.language}-cwe89",
                    producer_version="1.0.0",
                    producer_sha256="b" * 64,
                ),
            )
            == ()
        )

    scans = (js_scan, ts_scan, go_scan)
    indexes = (js_index, ts_index, go_index)
    converted = {
        index.language: multilanguage_cwe89_signals_to_raw_signals(
            index,
            scan,
            tenant_id=TENANT,
            producer=ProducerRef(
                schema_version=CONTRACT_SCHEMA_VERSION,
                producer_id=f"securecode-{index.language}-cwe89",
                producer_version="1.0.0",
                producer_sha256="b" * 64,
            ),
        )[0]
        for index, scan in zip(indexes, scans, strict=True)
    }
    candidates = normalize_signals(raw_signals=tuple(converted.values()))
    assert len(candidates) == 3
    assert all(candidate.candidate_origin.value == "deterministic" for candidate in candidates)
    assert all(candidate.evidence_ids == () for candidate in candidates)

    # The shared report boundary receives source-free FindingCase metadata, not
    # scanner bytes. Bind the exact scanner-derived identity/location through a
    # deterministic EvidenceGraph and the FindingCase verdict/report objects.
    selected_raw = converted[language]
    selected_scan = next(scan for scan in scans if scan.language == language)
    sink = selected_scan.signals[0].sink
    location = SourceLocation(
        schema_version=CONTRACT_SCHEMA_VERSION,
        path=selected_scan.path,
        start=SourcePosition(
            schema_version=CONTRACT_SCHEMA_VERSION,
            line=sink.start_point.row + 1,
            column=sink.start_point.column + 1,
        ),
        end=SourcePosition(
            schema_version=CONTRACT_SCHEMA_VERSION,
            line=sink.end_point.row + 1,
            column=sink.end_point.column + 1,
        ),
        content_sha256=selected_scan.content_sha256,
    )
    deterministic_candidate = next(
        item
        for item in candidates
        if any(selected_raw.raw_signal_id in lineage.input_signal_ids for lineage in item.lineage)
    )
    model_candidate_data = (
        _report_run().coverage_manifest.discovery_candidates[0].model_dump(mode="python")
    )
    model_candidate_data["candidate_id"] = "model-source-1"
    model_candidate_data["candidate_origin"] = CandidateOrigin.MODEL_NATIVE
    model_candidate_data["root_cause_fingerprint"] = deterministic_candidate.root_cause_fingerprint
    model_candidate_data["lineage"] = (model_candidate_data["lineage"][-1],)
    model_candidate_data["lineage"][0]["root_cause_fingerprint"] = (
        deterministic_candidate.root_cause_fingerprint
    )
    candidate = normalize_signals(
        raw_signals=(selected_raw,),
        discovery_candidates=(DiscoveryCandidate.model_validate(model_candidate_data),),
    )[0]
    evidence_id = "evidence-p7-go-sink"
    model_evidence_id = "evidence-p7-model"
    candidate_data = candidate.model_dump(mode="python")
    candidate_data["evidence_ids"] = (evidence_id, model_evidence_id)
    for lineage in candidate_data["lineage"]:
        lineage["evidence_ids"] = (
            (evidence_id,)
            if selected_raw.raw_signal_id in lineage["input_signal_ids"]
            else (model_evidence_id,)
        )
    bound_candidate = DiscoveryCandidate.model_validate(candidate_data)
    evidence = Evidence(
        schema_version=CONTRACT_SCHEMA_VERSION,
        evidence_id=evidence_id,
        tenant_id=TENANT,
        head_sha=HEAD,
        evidence_kind=EvidenceKind.SOURCE_LOCATION,
        producer=selected_raw.producer,
        trust_label=TrustLabel.TRUSTED_DETERMINISTIC,
        data_class=DataClass.INTERNAL_METADATA,
        evidence_sha256=hashlib.sha256(selected_scan.scan_sha256.encode("ascii")).hexdigest(),
        location=location,
    )
    model_evidence = Evidence(
        schema_version=CONTRACT_SCHEMA_VERSION,
        evidence_id=model_evidence_id,
        tenant_id=TENANT,
        head_sha=HEAD,
        evidence_kind=EvidenceKind.MODEL_ANALYSIS,
        producer=bound_candidate.lineage[-1].producer,
        trust_label=TrustLabel.MODEL_GENERATED,
        data_class=DataClass.INTERNAL_METADATA,
        evidence_sha256=hashlib.sha256(b"p7-model-evidence").hexdigest(),
        location=None,
    )
    graph = EvidenceGraph(
        graph_id="graph-p7-go",
        tenant_id=TENANT,
        head_sha=HEAD,
        candidates=(bound_candidate,),
        evidence=(evidence, model_evidence),
        edges=tuple(
            EvidenceGraphEdge(
                EvidenceEdgeKind.CANDIDATE_EVIDENCE,
                EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, bound_candidate.candidate_id),
                EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, item.evidence_id),
            )
            for item in (evidence, model_evidence)
        ),
    )
    finding = FindingCase(
        schema_version=CONTRACT_SCHEMA_VERSION,
        finding_id="finding-1",
        candidate_id=bound_candidate.candidate_id,
        candidate_version=bound_candidate.candidate_version,
        repository_revision=_report_run().execution_identity.repository_revision,
        root_cause_fingerprint=bound_candidate.root_cause_fingerprint,
        candidate_origin=bound_candidate.candidate_origin,
        producer_lineage=bound_candidate.lineage,
        locations=(location,),
        cwe_id="CWE-89",
        evidence_graph_ref=ArtifactRef(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=TENANT,
            content_id=graph.graph_id,
            content_sha256=graph.graph_sha256,
            size_bytes=0,
            data_class=DataClass.INTERNAL_METADATA,
        ),
        evidence_ids=graph.candidates[0].evidence_ids,
        interpretation_receipt_id="interpretation-receipt",
        finding_verdict=FindingVerdict.CONFIRMED,
        verdict_evidence_ids=(evidence_id,),
        blocking=True,
    )
    report_run_data = _report_run().model_dump(mode="python")
    manifest_data = report_run_data["coverage_manifest"]
    manifest_data["discovery_candidates"] = (bound_candidate.model_dump(mode="python"),)
    manifest_data["model_discovery_receipts"][0]["candidate_ids"] = (bound_candidate.candidate_id,)
    manifest_data["candidate_interpretation_receipts"][0]["candidate_id"] = (
        bound_candidate.candidate_id
    )
    manifest_data["candidate_interpretation_receipts"][0]["candidate_version"] = (
        bound_candidate.candidate_version
    )
    for unit in manifest_data["units"]:
        if unit["subject_id"] == "candidate-1":
            unit["subject_id"] = bound_candidate.candidate_id
    report_run = AuditRun.model_validate(report_run_data)
    report = build_deterministic_report(
        report_run,
        (ReportFinding(finding, classify_cwe("CWE-89")),),
        (_report_pin("p7.2-go"),),
    )
    rendered = render_report(report, ReportFormat.JSON)
    assert selected_scan.path.encode() in rendered
    assert evidence.location == finding.locations[0] == location
    assert graph.candidates[0].evidence_ids == finding.evidence_ids
    assert graph.candidates[0].candidate_origin is CandidateOrigin.HYBRID
    assert selected_raw.location == finding.locations[0]
    assert selected_raw.producer == bound_candidate.lineage[0].producer
    assert selected_raw.rule_id == "cwe-89-sql-interpolation"
    assert selected_raw.tenant_id == TENANT
    assert selected_raw.head_sha == HEAD
    assert (
        selected_scan.content_sha256
        == selected_raw.location.content_sha256
        == finding.locations[0].content_sha256
    )
    assert selected_scan.repository_id == finding.repository_revision.repository_id
    assert b"api/safe.js" not in rendered
    assert b"api/safe.ts" not in rendered
    assert b"api/safe.go" not in rendered
