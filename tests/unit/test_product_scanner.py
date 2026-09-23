"""Host scanner binding and exact source evidence without spawning a worker."""

import hashlib
from pathlib import Path

import pytest
from securecode_ai.adapters import product_scanner
from securecode_ai.adapters.scanner_plugin import ScannerPluginBinding
from securecode_ai.core.scanning import (
    ScannerBudget,
    ScannerExecution,
    ScannerFailureCode,
    ScannerRequest,
    ScannerRunStatus,
    raw_signal_digest,
    raw_signal_payload_bytes,
)
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ReadEvidenceArguments,
    RepositoryToolWindow,
)

from tests.unit.test_native_sources import build, repository

SOURCES = [
    ("a.py", b"import requests\ndef check(request):\n requests.get(request.args.get('url'))\n"),
    ("a.js", b"function check(req) { fetch(req.query.url); }\n"),
    ("a.ts", b"function check(req: Request) { fetch(req.query.url); }\n"),
    ("a.mts", b"function check(req: Request) { fetch(req.query.url); }\n"),
    ("a.cts", b"function check(req: Request) { fetch(req.query.url); }\n"),
    ("a.go", b'package api\nfunc check(r *Request) { http.Get(r.URL.Query().Get("url")) }\n'),
]


def scripted_worker(
    binding: ScannerPluginBinding,
    request: ScannerRequest,
    *,
    budget: ScannerBudget,
) -> ScannerExecution:
    del budget
    output = product_scanner.FirstPartyStaticWorker().scan(request)
    signals = output.signals
    return ScannerExecution(
        request.request_id,
        binding.identity,
        binding.isolation,
        ScannerRunStatus.SUCCEEDED,
        1,
        len(request.source),
        sum(raw_signal_payload_bytes(s) for s in signals),
        signals,
        raw_signal_digest(signals),
        None,
    )


@pytest.mark.parametrize("path,source", SOURCES)
def test_detector_graph_has_exact_guarded_source_and_host_provenance(
    monkeypatch: pytest.MonkeyPatch, path: str, source: bytes
) -> None:
    monkeypatch.setattr(product_scanner, "run_scanner_plugin", scripted_worker)
    reader, head, blob = repository(path, source)
    catalogue = build(reader, head)
    reader.contents[("blob", blob)] = b"mutated checkout equivalent"
    result = product_scanner.scan_product_sources(catalogue, tenant_id="tenant-a")
    assert result.is_complete
    assert len(result.graph.candidates) == len(result.graph.evidence) == 1
    record = result.graph.evidence[0]
    assert record.location is not None
    assert record.artifact_ref is not None
    assert record.location.content_sha256 == hashlib.sha256(source).hexdigest()
    assert record.producer == product_scanner.first_party_scanner_producer()
    assert result.graph.candidates[0].evidence_ids == (record.evidence_id,)
    output = result.repository_view(catalogue).read_evidence(
        ReadEvidenceArguments(
            TOOL_ARGUMENT_SCHEMA_VERSION,
            head,
            record.evidence_id,
        ),
        window=RepositoryToolWindow(4096, 4096),
    )
    assert output.content in source.decode()
    assert hashlib.sha256(output.content.encode()).hexdigest() == record.artifact_ref.content_sha256


def test_safe_control_emits_completed_zero_without_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(product_scanner, "run_scanner_plugin", scripted_worker)
    reader, head, _ = repository("a.py", b"import requests\nrequests.get('https://example.com')\n")
    result = product_scanner.scan_product_sources(build(reader, head), tenant_id="tenant-a")
    assert result.is_complete and len(result.receipts) == 1
    assert result.graph.candidates == ()
    assert result.graph.evidence == ()
    assert result.source_aliases == ()


def test_scanner_producer_pin_covers_transitive_rule_sources(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(product_scanner, "__file__", str(tmp_path / "product_scanner.py"))
    for name in product_scanner._FIRST_PARTY_SCANNER_SOURCES:
        (tmp_path / name).write_bytes(name.encode("ascii"))

    before = product_scanner.first_party_scanner_producer()
    (tmp_path / "cwe89_multilanguage_scanner.py").write_bytes(b"changed scanner semantics")
    after = product_scanner.first_party_scanner_producer()

    assert before.producer_sha256 != after.producer_sha256


def test_worker_fault_is_incomplete_not_completed_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed(
        binding: ScannerPluginBinding,
        request: ScannerRequest,
        *,
        budget: ScannerBudget,
    ) -> ScannerExecution:
        del budget
        return ScannerExecution(
            request.request_id,
            binding.identity,
            binding.isolation,
            ScannerRunStatus.CRASHED,
            1,
            len(request.source),
            0,
            (),
            raw_signal_digest(()),
            ScannerFailureCode.PLUGIN_CRASHED,
        )

    monkeypatch.setattr(product_scanner, "run_scanner_plugin", failed)
    reader, head, _ = repository(*SOURCES[0])
    result = product_scanner.scan_product_sources(build(reader, head), tenant_id="tenant-a")
    assert not result.is_complete and result.receipts[0].status is ScannerRunStatus.CRASHED


@pytest.mark.parametrize("budget", [True, 0, -1, 60_000_000_001])
def test_invalid_global_budget_rejects_before_workers(budget: int) -> None:
    reader, head, _ = repository(*SOURCES[0])
    with pytest.raises(ValueError, match="request"):
        product_scanner.scan_product_sources(
            build(reader, head), tenant_id="tenant-a", total_budget_ns=budget
        )


def test_wrong_tenant_rejects_before_workers() -> None:
    reader, head, _ = repository(*SOURCES[0])
    with pytest.raises(ValueError, match="tenant"):
        product_scanner.scan_product_sources(build(reader, head), tenant_id="tenant-b")


@pytest.mark.parametrize("observations", [(0, 1, 11, 12), (0, 1, 2, 11)])
def test_final_worker_or_projection_overrun_retains_candidates_and_is_incomplete(
    monkeypatch: pytest.MonkeyPatch, observations: tuple[int, ...]
) -> None:
    clock = iter(observations)
    monkeypatch.setattr(product_scanner, "monotonic_ns", lambda: next(clock))
    monkeypatch.setattr(product_scanner, "run_scanner_plugin", scripted_worker)
    reader, head, _ = repository(*SOURCES[0])
    result = product_scanner.scan_product_sources(
        build(reader, head), tenant_id="tenant-a", total_budget_ns=10
    )
    assert not result.is_complete
    assert len(result.graph.candidates) == len(result.receipts) == 1
    assert result.receipts[0].status is ScannerRunStatus.SUCCEEDED


def test_source_view_rejects_different_head_and_tampered_alias_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    monkeypatch.setattr(product_scanner, "run_scanner_plugin", scripted_worker)
    reader, head, _ = repository(*SOURCES[0])
    catalogue = build(reader, head)
    result = product_scanner.scan_product_sources(catalogue, tenant_id="tenant-a")
    other, other_head, _ = repository("a.py", b"x = 1\n")
    with pytest.raises(ValueError, match="binding"):
        result.repository_view(build(other, other_head))
    alias = result.source_aliases[0]
    tampered = replace(result, source_aliases=((alias[0], b"forged source", alias[2]),))
    with pytest.raises(ValueError, match="bytes"):
        tampered.repository_view(catalogue)


def test_auditor_rejects_unadmitted_scanner_alias_before_tool_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import json

    from securecode_ai.contracts import DiscoveryCandidate, Evidence
    from securecode_ai.core.evidence_graph import (
        EvidenceEdgeKind,
        EvidenceGraph,
        EvidenceGraphEdge,
        EvidenceNodeKind,
        EvidenceNodeRef,
    )
    from securecode_ai.core.tool_policy import RepositoryToolBudget

    monkeypatch.setattr(product_scanner, "run_scanner_plugin", scripted_worker)
    reader, head, _ = repository(*SOURCES[0])
    catalogue = build(reader, head)
    result = product_scanner.scan_product_sources(catalogue, tenant_id="tenant-a")
    record = result.graph.evidence[0].model_dump(mode="json")
    record["evidence_id"] = "unadmitted-alias"
    material = result.graph.candidates[0].model_dump(mode="json")
    material["evidence_ids"] = [record["evidence_id"]]
    for lineage in material["lineage"]:
        lineage["evidence_ids"] = [record["evidence_id"]]
    candidate = DiscoveryCandidate.model_validate_json(json.dumps(material))
    graph = EvidenceGraph(
        graph_id="unadmitted-alias-graph",
        tenant_id="tenant-a",
        head_sha=head,
        candidates=(candidate,),
        evidence=(Evidence.model_validate_json(json.dumps(record)),),
        edges=(
            EvidenceGraphEdge(
                EvidenceEdgeKind.CANDIDATE_EVIDENCE,
                EvidenceNodeRef(EvidenceNodeKind.CANDIDATE, candidate.candidate_id),
                EvidenceNodeRef(EvidenceNodeKind.EVIDENCE, record["evidence_id"]),
            ),
        ),
    )
    with pytest.raises(ValueError, match="not admitted"):
        product_scanner.build_product_auditor_tools(
            catalogue,
            graph,
            budget=RepositoryToolBudget(8, 65536, 65536),
            deterministic=result,
        )
