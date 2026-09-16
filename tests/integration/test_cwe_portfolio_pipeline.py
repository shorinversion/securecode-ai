"""P7.4 ingress into common RawSignal normalization."""

from __future__ import annotations

import hashlib

from securecode_ai.adapters import (
    build_javascript_symbol_index,
    portfolio_signals_to_raw_signals,
    scan_cwe_portfolio,
)
from securecode_ai.contracts import CONTRACT_SCHEMA_VERSION, CandidateOrigin, ProducerRef
from securecode_ai.core.normalization import normalize_signals


def test_portfolio_facts_enter_the_existing_source_free_normalization_boundary() -> None:
    source = (
        b"function check(req, repo) {\n"
        b" exec(req.query.cmd); fs.readFile(path.join(root, req.query.file));\n"
        b" fetch(req.query.url); repo.get(req.params.id);\n"
        b"}\n"
    )
    index = build_javascript_symbol_index(
        repository_id="example/p7",
        revision="a" * 40,
        path="api/portfolio.js",
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )
    result = scan_cwe_portfolio(index)
    producer = ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="p7.4-portfolio",
        producer_version="1.0.0",
        producer_sha256="b" * 64,
    )
    raw_signals = portfolio_signals_to_raw_signals(result, tenant_id="tenant-1", producer=producer)
    candidates = normalize_signals(raw_signals=raw_signals)

    assert len(raw_signals) == len(candidates) == 4
    assert all(signal.payload_ref is None for signal in raw_signals)
    assert all(
        signal.payload_classification.value == "DC1_INTERNAL_METADATA" for signal in raw_signals
    )
    assert all(
        candidate.candidate_origin is CandidateOrigin.DETERMINISTIC for candidate in candidates
    )
    assert all(source not in repr(item).encode("utf-8") for item in (*raw_signals, *candidates))


def test_raw_signal_ids_are_unique_across_distinct_scanner_results() -> None:
    producer = ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="p7.4-portfolio",
        producer_version="1.0.0",
        producer_sha256="b" * 64,
    )
    source = b"function check(req) { fetch(req.query.url); }\n"
    results = tuple(
        scan_cwe_portfolio(
            build_javascript_symbol_index(
                repository_id="example/p7",
                revision="a" * 40,
                path=path,
                content_sha256=hashlib.sha256(source).hexdigest(),
                source=source,
            )
        )
        for path in ("api/first.js", "api/second.js")
    )
    identifiers = tuple(
        signal.raw_signal_id
        for result in results
        for signal in portfolio_signals_to_raw_signals(
            result, tenant_id="tenant-1", producer=producer
        )
    )
    assert len(identifiers) == len(set(identifiers)) == 2
