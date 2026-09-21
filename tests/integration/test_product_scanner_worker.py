"""Actual spawn worker on retained public Git fixtures, never repository execution."""

import pytest
from securecode_ai.adapters.native_sources import NativeSourceCatalogue
from securecode_ai.adapters.product_scan import ProductCandidateFlow
from securecode_ai.adapters.product_scanner import (
    ProductDeterministicScanResult,
    scan_product_sources,
)
from securecode_ai.contracts import ProducerRef
from securecode_ai.core.investigation import AuditorInvestigationReceipt
from securecode_ai.core.scanning import ScannerIsolationMode, ScannerRunStatus

from tests.unit.test_native_sources import build, repository
from tests.unit.test_product_scanner import SOURCES

SQL_SOURCES = [
    (
        "a.py",
        b'def lookup(request, db):\n id = request.args.get("id")\n db.execute(f"SELECT * FROM users WHERE id = {id}")\n',
    ),
    (
        "a.js",
        b"const id = req.query.id;\nconst sql = `SELECT * FROM users WHERE id = ${id}`;\ndb.query(sql);\n",
    ),
    (
        "a.ts",
        b"const id: string = request.query.id;\nconst sql = `SELECT * FROM users WHERE id = ${id}`;\ndb.execute(sql);\n",
    ),
    (
        "a.go",
        b'package api\nimport "fmt"\nfunc lookup(r *Request, db DB) {\n id := r.URL.Query().Get("id")\n sql := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)\n db.Query(sql)\n}\n',
    ),
]


@pytest.mark.parametrize("path,source", SOURCES)
def test_actual_isolated_first_party_worker_returns_bound_facts(path: str, source: bytes) -> None:
    reader, head, _ = repository(path, source)
    result = scan_product_sources(build(reader, head), tenant_id="tenant-a")
    assert result.is_complete, tuple(r.status for r in result.receipts)
    assert len(result.receipts) == len(result.graph.candidates) == 1
    receipt = result.receipts[0]
    assert receipt.status is ScannerRunStatus.SUCCEEDED
    assert receipt.isolation is ScannerIsolationMode.APPROVED_ISOLATED_WORKER
    assert receipt.signals[0].head_sha == head


@pytest.mark.parametrize("path,source", SQL_SOURCES)
def test_actual_worker_sql_facts_are_normalized_with_source_evidence(
    path: str, source: bytes
) -> None:
    reader, head, _ = repository(path, source)
    result = scan_product_sources(build(reader, head), tenant_id="tenant-a")
    assert result.is_complete
    assert len(result.graph.candidates) == len(result.graph.evidence) == 1
    assert result.receipts[0].signals[0].rule_id == "cwe-89-sql-interpolation"


def test_partial_scanner_status_requires_indeterminate_and_keeps_native_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from securecode_ai.contracts import AuditRunOutcome
    from securecode_ai.core.evidence_graph import EvidenceGraph

    from tests.integration.test_product_scan_flow import _flow

    def incomplete(
        catalogue: NativeSourceCatalogue,
        producer: ProducerRef,
    ) -> ProductDeterministicScanResult:
        del producer
        graph = EvidenceGraph(
            graph_id="incomplete-static",
            tenant_id=catalogue.anchors[0].tenant_id,
            head_sha=catalogue.snapshot.head_sha,
            candidates=(),
            evidence=(),
            edges=(),
        )
        return ProductDeterministicScanResult(graph, (), False, ())

    result, endpoint, observed = _flow(monkeypatch, count=2, scanner=incomplete)
    assert isinstance(result, ProductCandidateFlow)
    assert result.deterministic_failed
    assert result.required_terminal_outcome is AuditRunOutcome.INDETERMINATE
    assert len(result.graph.candidates) == len(result.investigations) == 2
    assert all(
        isinstance(receipt, AuditorInvestigationReceipt) for receipt in result.investigations
    )
    investigations = tuple(
        receipt
        for receipt in result.investigations
        if isinstance(receipt, AuditorInvestigationReceipt)
    )
    assert all(not receipt.is_indeterminate for receipt in investigations), [
        (r.final_model_call_status, r.stop_reason, r.tool_calls) for r in investigations
    ]
    assert len(endpoint.requests) == 1
    auditor_endpoint = observed["auditor_endpoint"]
    assert auditor_endpoint is not None and len(auditor_endpoint.requests) == 2


def test_actual_worker_candidates_receive_core_auditor_with_guarded_source_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.integration import test_product_scan_flow as flow_fixture

    captured_catalogue: NativeSourceCatalogue | None = None
    captured_scan: ProductDeterministicScanResult | None = None

    def scanner(
        catalogue: NativeSourceCatalogue,
        producer: ProducerRef,
    ) -> ProductDeterministicScanResult:
        nonlocal captured_catalogue, captured_scan
        del producer
        result = scan_product_sources(catalogue, tenant_id=catalogue.anchors[0].tenant_id)
        captured_catalogue = catalogue
        captured_scan = result
        return result

    monkeypatch.setattr(
        flow_fixture, "repository", lambda path, source: repository(*SQL_SOURCES[0])
    )
    result, native_endpoint, observed = flow_fixture._flow(monkeypatch, scanner=scanner)
    assert isinstance(result, ProductCandidateFlow)
    assert captured_catalogue is not None
    assert captured_scan is not None and captured_scan.is_complete
    assert len(captured_scan.graph.candidates) == 1
    assert len(result.graph.candidates) == len(result.investigations) == 2
    assert all(
        isinstance(receipt, AuditorInvestigationReceipt) for receipt in result.investigations
    )
    investigations = tuple(
        receipt
        for receipt in result.investigations
        if isinstance(receipt, AuditorInvestigationReceipt)
    )
    assert all(not receipt.is_indeterminate for receipt in investigations), [
        (r.final_model_call_status, r.stop_reason, r.tool_calls) for r in investigations
    ]
    assert len(native_endpoint.requests) == 1
    auditor_endpoint = observed["auditor_endpoint"]
    auditor_tools = observed["auditor_tools"]
    assert auditor_endpoint is not None and auditor_tools is not None
    assert len(auditor_endpoint.requests) == auditor_tools.calls_used == 2
    assert result.required_terminal_outcome is None  # No final product PASS is authorized here.
