"""Focused contracts for bounded JavaScript, TypeScript, and Go CWE-89 facts."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from securecode_ai.adapters import (
    MultilanguageCwe89ScanError,
    MultilanguageCwe89ScanErrorCode,
    MultilanguageCwe89ScanLimits,
    build_go_symbol_index,
    build_javascript_symbol_index,
    build_typescript_symbol_index,
    multilanguage_cwe89_signals_to_raw_signals,
    scan_go_cwe89,
    scan_javascript_cwe89,
    scan_typescript_cwe89,
)
from securecode_ai.core import CONTRACT_SCHEMA_VERSION, ProducerRef, SymbolIndex

REPOSITORY_ID = "example/secure-repository"
REVISION = "1" * 40


@pytest.mark.parametrize(
    ("builder", "scanner", "path", "source"),
    [
        (
            build_javascript_symbol_index,
            scan_javascript_cwe89,
            "api/lookup.js",
            b"const id = req.query.id;\nconst sql = `SELECT * FROM users WHERE id = ${id}`;\ndb.query(sql);\n",
        ),
        (
            build_typescript_symbol_index,
            scan_typescript_cwe89,
            "api/lookup.ts",
            b"const id: string = request.query.id;\nconst sql = `SELECT * FROM users WHERE id = ${id}`;\ndb.execute(sql);\n",
        ),
        (
            build_go_symbol_index,
            scan_go_cwe89,
            "api/lookup.go",
            b'package api\nimport "fmt"\nfunc lookup(r *Request, db DB) {\n id := r.URL.Query().Get("id")\n sql := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)\n db.Query(sql)\n}\n',
        ),
    ],
)
def test_source_interpolation_sink_fact_is_deterministic(
    builder: object, scanner: object, path: str, source: bytes
) -> None:
    index = builder(  # type: ignore[operator]
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path=path,
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )
    first = scanner(index)  # type: ignore[operator]
    second = scanner(index)  # type: ignore[operator]
    assert first == second
    assert len(first.signals) == 1
    signal = first.signals[0]
    assert signal.cwe == "CWE-89"
    source_slice = source[signal.source.start_byte : signal.source.end_byte]
    assert (
        source_slice.endswith(b'.Get("id")')
        if path.endswith(".go")
        else source_slice.endswith(b".id")
    )
    assert b"SELECT" in source[signal.interpolation.start_byte : signal.interpolation.end_byte]
    assert b"db." in source[signal.sink.start_byte : signal.sink.end_byte]


@pytest.mark.parametrize(
    ("builder", "scanner", "path", "source"),
    [
        (
            build_javascript_symbol_index,
            scan_javascript_cwe89,
            "api/safe.js",
            b"const id = req.query.id;\ndb.query('SELECT * FROM users WHERE id = ?', [id]);\n",
        ),
        (
            build_typescript_symbol_index,
            scan_typescript_cwe89,
            "api/safe.ts",
            b"const id: string = request.query.id;\ndb.execute('SELECT * FROM users WHERE id = ?', [id]);\n",
        ),
        (
            build_go_symbol_index,
            scan_go_cwe89,
            "api/safe.go",
            b'package api\nfunc lookup(r *Request, db DB) {\n id := r.URL.Query().Get("id")\n db.Query("SELECT * FROM users WHERE id = ?", id)\n}\n',
        ),
    ],
)
def test_parameterized_controls_emit_no_semantic_fact(
    builder: object, scanner: object, path: str, source: bytes
) -> None:
    index = builder(  # type: ignore[operator]
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path=path,
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )
    assert scanner(index).signals == ()  # type: ignore[operator]


def test_recovered_parse_and_resource_exhaustion_fail_closed() -> None:
    malformed = b"const id = req.query.id;\nconst sql = `SELECT ${id}`;\ndb.query(sql\n"
    index = build_javascript_symbol_index(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path="api/broken.js",
        content_sha256=hashlib.sha256(malformed).hexdigest(),
        source=malformed,
    )
    with pytest.raises(MultilanguageCwe89ScanError) as recovered:
        scan_javascript_cwe89(index)
    assert recovered.value.code is MultilanguageCwe89ScanErrorCode.ANALYSIS_UNAVAILABLE

    source = b"const id = req.query.id;\nconst sql = `SELECT ${id}`;\ndb.query(sql);\n"
    valid = build_javascript_symbol_index(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path="api/limited.js",
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )
    with pytest.raises(MultilanguageCwe89ScanError) as limited:
        scan_javascript_cwe89(valid, limits=MultilanguageCwe89ScanLimits(max_source_bytes=1))
    assert limited.value.code is MultilanguageCwe89ScanErrorCode.SOURCE_LIMIT


def test_forged_index_is_not_a_clean_scan() -> None:
    source = b"const id = req.query.id;\nconst sql = `SELECT ${id}`;\ndb.query(sql);\n"
    index = build_javascript_symbol_index(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path="api/forged.js",
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )
    with pytest.raises(ValueError):
        replace(index, source=b"const safe = true;\n")


def test_go_recovered_parse_and_binary_interpolation_are_not_clean() -> None:
    malformed = b"package api\nfunc broken( {\n"
    index = build_go_symbol_index(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path="api/broken.go",
        content_sha256=hashlib.sha256(malformed).hexdigest(),
        source=malformed,
    )
    with pytest.raises(MultilanguageCwe89ScanError) as recovered:
        scan_go_cwe89(index)
    assert recovered.value.code is MultilanguageCwe89ScanErrorCode.ANALYSIS_UNAVAILABLE

    source = b'package api\nfunc lookup(r *Request, db DB) {\n id := r.URL.Query().Get("id")\n sql := "SELECT " + id\n db.Exec(sql)\n}\n'
    index = build_go_symbol_index(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path="api/concat.go",
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )
    assert len(scan_go_cwe89(index).signals) == 1
    with pytest.raises(MultilanguageCwe89ScanError) as limited:
        scan_go_cwe89(index, limits=MultilanguageCwe89ScanLimits(max_source_bytes=1))
    assert limited.value.code is MultilanguageCwe89ScanErrorCode.SOURCE_LIMIT


@pytest.mark.parametrize(
    ("builder", "scanner", "path", "source"),
    [
        (
            build_javascript_symbol_index,
            scan_javascript_cwe89,
            "api/scopes.js",
            b"function first() { const id = req.query.id; }\nfunction second() { const sql = `SELECT ${id}`; db.query(sql); }\n",
        ),
        (
            build_go_symbol_index,
            scan_go_cwe89,
            "api/scopes.go",
            b'package api\nimport "fmt"\nfunc first(r *Request) { id := r.URL.Query().Get("id"); _ = id }\nfunc second(db DB) { sql := fmt.Sprintf("SELECT %s", id); db.Query(sql) }\n',
        ),
    ],
)
def test_tainted_locals_do_not_leak_between_callable_scopes(
    builder: object, scanner: object, path: str, source: bytes
) -> None:
    index = builder(  # type: ignore[operator]
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path=path,
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )
    assert scanner(index).signals == ()  # type: ignore[operator]


@pytest.mark.parametrize(
    ("builder", "scanner", "path", "source"),
    [
        (
            build_javascript_symbol_index,
            scan_javascript_cwe89,
            "ui/lookup.jsx",
            b"const View = () => <div/>; const f = function() { db.query(`SELECT ${req.query.id}`); };",
        ),
        (
            build_typescript_symbol_index,
            scan_typescript_cwe89,
            "ui/lookup.tsx",
            b"const View = () => <div/>; const f = function() { db.query(`SELECT ${req.query.id}`); };",
        ),
    ],
)
def test_jsx_tsx_function_expression_scans_use_matching_grammar(
    builder: object,
    scanner: object,
    path: str,
    source: bytes,
) -> None:
    index = builder(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path=path,  # type: ignore[operator]
        content_sha256=hashlib.sha256(source).hexdigest(),
        source=source,
    )
    assert len(scanner(index).signals) == 1  # type: ignore[operator]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            b'const id = req.query.id; const f = function() { const id = "safe"; }; db.query(`SELECT ${id}`);',
            1,
        ),
        (
            b'const id = "safe"; const f = function() { const id = req.query.id; }; db.query(`SELECT ${id}`);',
            0,
        ),
    ],
)
def test_function_expression_scope_does_not_overwrite_outer_bindings(
    source: bytes,
    expected: int,
) -> None:
    index = build_javascript_symbol_index(
        repository_id=REPOSITORY_ID,
        revision=REVISION,
        path="api/lookup.js",
        source=source,
        content_sha256=hashlib.sha256(source).hexdigest(),
    )
    assert len(scan_javascript_cwe89(index).signals) == expected


def _conversion_index(repository_id: str = REPOSITORY_ID, *, safe: bool = False) -> SymbolIndex:
    source = b"const id = req.query.id; db.query(`SELECT ${id}`);"
    if safe:
        source = b"const id = req.query.id; db.query('SELECT ?', [id]);"
    return build_javascript_symbol_index(
        repository_id=repository_id,
        revision=REVISION,
        path="api/lookup.js",
        source=source,
        content_sha256=hashlib.sha256(source).hexdigest(),
    )


def _conversion_producer() -> ProducerRef:
    return ProducerRef(
        schema_version=CONTRACT_SCHEMA_VERSION,
        producer_id="securecode-javascript-cwe89",
        producer_version="1.0.0",
        producer_sha256="b" * 64,
    )


def test_production_conversion_preserves_and_digests_exact_bindings() -> None:
    index = _conversion_index()
    result = scan_javascript_cwe89(index)
    producer = _conversion_producer()
    raw = multilanguage_cwe89_signals_to_raw_signals(
        index, result, tenant_id="tenant-a", producer=producer
    )[0]
    assert (
        raw
        == multilanguage_cwe89_signals_to_raw_signals(
            index, result, tenant_id="tenant-a", producer=producer
        )[0]
    )
    signal = result.signals[0]
    assert raw.tenant_id == "tenant-a"
    assert raw.head_sha == index.revision
    assert raw.producer == producer
    assert raw.rule_id == "cwe-89-sql-interpolation"
    assert raw.location.path == index.path
    assert raw.location.content_sha256 == index.content_sha256
    assert (raw.location.start.line, raw.location.start.column) == (
        signal.sink.start_point.row + 1,
        signal.sink.start_point.column + 1,
    )
    assert (raw.location.end.line, raw.location.end.column) == (
        signal.sink.end_point.row + 1,
        signal.sink.end_point.column + 1,
    )
    assert raw.payload_ref is None
    assert index.source.decode() not in raw.model_dump_json()
    changed_tenant = multilanguage_cwe89_signals_to_raw_signals(
        index, result, tenant_id="tenant-b", producer=producer
    )[0]
    changed_producer = multilanguage_cwe89_signals_to_raw_signals(
        index,
        result,
        tenant_id="tenant-a",
        producer=producer.model_copy(update={"producer_sha256": "c" * 64}),
    )[0]
    other_index = _conversion_index("another/repository")
    changed_repository = multilanguage_cwe89_signals_to_raw_signals(
        other_index, scan_javascript_cwe89(other_index), tenant_id="tenant-a", producer=producer
    )[0]
    assert (
        len(
            {
                item.signal_sha256
                for item in (raw, changed_tenant, changed_producer, changed_repository)
            }
        )
        == 4
    )
    assert (
        len(
            {
                item.raw_signal_id
                for item in (raw, changed_tenant, changed_producer, changed_repository)
            }
        )
        == 4
    )


@pytest.mark.parametrize("field", ["producer_id", "producer_version", "producer_sha256"])
def test_conversion_rejects_forged_producer_without_echo(field: str) -> None:
    index = _conversion_index()
    producer = _conversion_producer().model_copy(update={field: "invalid-producer-canary"})
    with pytest.raises(MultilanguageCwe89ScanError) as caught:
        multilanguage_cwe89_signals_to_raw_signals(
            index, scan_javascript_cwe89(index), tenant_id="tenant-a", producer=producer
        )
    assert caught.value.code is MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
    assert "canary" not in str(caught.value)


@pytest.mark.parametrize(
    "field", ["repository_id", "revision", "path", "content_sha256", "scan_sha256"]
)
def test_conversion_rejects_forged_scanner_identity(field: str) -> None:
    index = _conversion_index()
    result = scan_javascript_cwe89(index)
    object.__setattr__(result, field, "forged-canary")
    with pytest.raises(MultilanguageCwe89ScanError) as caught:
        multilanguage_cwe89_signals_to_raw_signals(
            index, result, tenant_id="tenant-a", producer=_conversion_producer()
        )
    assert caught.value.code is MultilanguageCwe89ScanErrorCode.INTEGRITY_FAILURE
    assert "canary" not in str(caught.value)


def test_conversion_rejects_forged_sink_and_validates_empty_result_tenant() -> None:
    index = _conversion_index()
    result = scan_javascript_cwe89(index)
    signal = result.signals[0]
    object.__setattr__(signal, "sink", signal.interpolation)
    with pytest.raises(MultilanguageCwe89ScanError):
        multilanguage_cwe89_signals_to_raw_signals(
            index, result, tenant_id="tenant-a", producer=_conversion_producer()
        )
    safe = _conversion_index(safe=True)
    scan = scan_javascript_cwe89(safe)
    assert (
        multilanguage_cwe89_signals_to_raw_signals(
            safe, scan, tenant_id="tenant-a", producer=_conversion_producer()
        )
        == ()
    )
    for tenant in ("", "bad/tenant", "x" * 129):
        with pytest.raises(MultilanguageCwe89ScanError):
            multilanguage_cwe89_signals_to_raw_signals(
                safe, scan, tenant_id=tenant, producer=_conversion_producer()
            )
