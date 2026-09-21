"""Git-bound independent source coverage and negative intake checks."""

import hashlib

import pytest
from securecode_ai.adapters.native_sources import (
    NativeSourceCatalogue,
    build_native_source_catalogue,
)
from securecode_ai.core.tool_policy import ReadRangeArguments, RepositoryToolWindow

from tests.unit.test_git_snapshot import Objects


def repository(path: str, source: bytes) -> tuple[Objects, str, str]:
    reader = Objects()
    blob = reader.add("blob", source)
    tree = reader.add("tree", b"100644 " + path.encode() + b"\0" + bytes.fromhex(blob))
    head = reader.add("commit", f"tree {tree}\n\npublic fixture\n".encode())
    return reader, head, blob


def build(
    reader: Objects,
    head: str,
    *,
    window_lines: int = 100,
    max_anchors: int = 4096,
) -> NativeSourceCatalogue:
    return build_native_source_catalogue(
        reader=reader,
        head_sha=head,
        tenant_id="tenant-a",
        repository_id="repo-a",
        content_key=b"n" * 32,
        window_lines=window_lines,
        max_anchors=max_anchors,
    )


@pytest.mark.parametrize(
    "path,source",
    [
        ("a.py", b"result = execute(value)\r\n"),
        ("a.js", b"const result = execute(value);\n"),
        ("a.ts", b"const result: string = execute(value);\n"),
        ("a.go", b"package main\nfunc main() { execute(value) }\n"),
    ],
)
def test_all_languages_have_generic_call_roots_and_exact_windows(path: str, source: bytes) -> None:
    reader, head, blob = repository(path, source)
    catalogue = build(reader, head)
    assert len(catalogue.anchors) >= 2
    assert all(anchor.head_sha == head for anchor in catalogue.anchors)
    assert all(
        anchor.location.content_sha256 == hashlib.sha256(source).hexdigest()
        for anchor in catalogue.anchors
    )
    reader.contents[("blob", blob)] = b"mutated checkout equivalent"
    view = catalogue.repository_view()
    for anchor in catalogue.anchors:
        assert isinstance(anchor.request.arguments, ReadRangeArguments)
        output = view.read_range(
            anchor.request.arguments, window=RepositoryToolWindow(65536, 65536)
        )
        assert output.content_sha256 == anchor.read_artifact.content_sha256
        assert output.byte_count == anchor.read_artifact.size_bytes

    assert catalogue.snapshot.files[0].content == source


def test_host_source_records_and_cited_graph_closure() -> None:
    import json

    from securecode_ai.contracts import (
        CandidateOrigin,
        DiscoveryCandidate,
        DiscoveryLane,
        EvidenceKind,
        LineageRef,
        ProducerRef,
        TrustLabel,
    )
    from securecode_ai.core.evidence_package import build_evidence_package
    from securecode_ai.core.tool_policy import TOOL_ARGUMENT_SCHEMA_VERSION, ReadEvidenceArguments

    reader, head, _ = repository("a.py", b"execute(value)\n")
    catalogue = build(reader, head)
    producer = ProducerRef(
        schema_version="0.2.0",
        producer_id="model-native-discovery",
        producer_version="1.0.0",
        producer_sha256="a" * 64,
    )
    records = catalogue.evidence_records(producer)
    assert records == catalogue.evidence_records(producer)
    view = catalogue.repository_view()
    for record in records:
        assert record.artifact_ref is not None
        assert record.evidence_kind is EvidenceKind.SOURCE_LOCATION
        assert record.trust_label is TrustLabel.UNTRUSTED_REPOSITORY
        assert record.evidence_sha256 != record.artifact_ref.content_sha256
        material = record.model_dump(mode="json", exclude={"evidence_sha256"})
        encoded = json.dumps(
            ["native-source-record-v1", material],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        assert record.evidence_sha256 == hashlib.sha256(encoded).hexdigest()
        output = view.read_evidence(
            ReadEvidenceArguments(TOOL_ARGUMENT_SCHEMA_VERSION, head, record.evidence_id),
            window=RepositoryToolWindow(65536, 65536),
        )
        assert output.content_sha256 == record.artifact_ref.content_sha256
        assert output.byte_count == record.artifact_ref.size_bytes
    evidence_id = records[0].evidence_id
    candidate = DiscoveryCandidate(
        schema_version="0.2.0",
        candidate_id="candidate-a",
        tenant_id="tenant-a",
        candidate_version=1,
        head_sha=head,
        root_cause_fingerprint="b" * 64,
        candidate_origin=CandidateOrigin.MODEL_NATIVE,
        lineage=(
            LineageRef(
                schema_version="0.2.0",
                lineage_id="lineage-a",
                lane=DiscoveryLane.MODEL_NATIVE,
                producer=producer,
                root_cause_fingerprint="b" * 64,
                input_candidate_ids=("source-a",),
                evidence_ids=(evidence_id,),
            ),
        ),
        evidence_ids=(evidence_id,),
    )
    graph = catalogue.evidence_graph(graph_id="graph-a", candidates=(candidate,), producer=producer)
    assert len(graph.evidence) == 1 < len(records)
    package = build_evidence_package(graph, "candidate-a")
    assert records[0].artifact_ref is not None
    assert package.selected[0].evidence_sha256 == records[0].evidence_sha256
    assert package.model_evidence[0].content_id == records[0].artifact_ref.content_id
    empty = catalogue.evidence_graph(graph_id="graph-zero", candidates=(), producer=producer)
    assert not empty.evidence
    assert not empty.candidates
    assert not empty.edges
    bad = candidate.model_dump(mode="json")
    bad["head_sha"] = "1" * 40
    with pytest.raises(ValueError):
        catalogue.evidence_graph(
            graph_id="graph-stale",
            candidates=(DiscoveryCandidate.model_validate_json(json.dumps(bad)),),
            producer=producer,
        )
    bad["head_sha"] = head
    bad["lineage"][0]["producer"]["producer_id"] = "other-producer"
    with pytest.raises(ValueError):
        catalogue.evidence_graph(
            graph_id="graph-producer",
            candidates=(DiscoveryCandidate.model_validate_json(json.dumps(bad)),),
            producer=producer,
        )
    assert catalogue.snapshot.files[0].content == b"execute(value)\n"


def test_zero_call_file_has_independent_full_coverage() -> None:
    reader, head, _ = repository("a.py", b"# public safe fixture\n")
    catalogue = build(reader, head, window_lines=1)
    assert len(catalogue.anchors) == 2
    assert [a.location.start.line for a in catalogue.anchors] == [1, 2]


def test_production_resolver_enforces_invocation_ceiling_before_second_guard_read() -> None:
    from securecode_ai.adapters.product_runtime import (
        GuardedEvidenceResolver,
        RepositoryContextBudgetExhausted,
    )
    from securecode_ai.contracts import (
        CandidateOrigin,
        DiscoveryCandidate,
        DiscoveryLane,
        LineageRef,
    )
    from securecode_ai.core.evidence_package import build_evidence_package
    from securecode_ai.core.model_discovery import RepositoryToolSession
    from securecode_ai.core.tool_policy import (
        RepositoryToolBudget,
        RepositoryToolGuard,
        RepositoryToolScope,
    )

    from tests.unit.test_evidence_package import _producer

    reader, head, _ = repository("a.py", b"execute(value)\n")
    catalogue = build(reader, head)
    records = catalogue.evidence_records(_producer())
    assert len(records) == 2
    ids = tuple(record.evidence_id for record in records)
    candidate = DiscoveryCandidate(
        schema_version="0.2.0",
        candidate_id="candidate-a",
        tenant_id="tenant-a",
        candidate_version=1,
        head_sha=head,
        root_cause_fingerprint="b" * 64,
        candidate_origin=CandidateOrigin.MODEL_NATIVE,
        evidence_ids=ids,
        lineage=(
            LineageRef(
                schema_version="0.2.0",
                lineage_id="lineage-a",
                lane=DiscoveryLane.MODEL_NATIVE,
                producer=_producer(),
                root_cause_fingerprint="b" * 64,
                input_candidate_ids=("source-a",),
                evidence_ids=ids,
            ),
        ),
    )
    graph = catalogue.evidence_graph(
        graph_id="graph-a", candidates=(candidate,), producer=_producer()
    )
    package = build_evidence_package(graph, "candidate-a")
    tools = RepositoryToolSession(
        guard=RepositoryToolGuard(
            scope=RepositoryToolScope(
                "tenant-a",
                "repo-a",
                head,
                ("a.py",),
                tuple(sorted(record.evidence_id for record in records)),
            ),
            budget=RepositoryToolBudget(8, 65536, 65536),
        ),
        backend=catalogue.repository_view(),
    )
    resolver = GuardedEvidenceResolver(tools=tools, evidence=records)
    with pytest.raises(RepositoryContextBudgetExhausted):
        resolver.resolve(package, max_calls=1)
    assert tools.calls_used == 1


def test_anchor_budget_rejects_partial_coverage() -> None:
    reader, head, _ = repository("a.py", b"first()\nsecond()\n")
    with pytest.raises(ValueError, match="coverage exceeds"):
        build(reader, head, max_anchors=1)


def test_invalid_parse_is_not_clean_coverage() -> None:
    reader, head, _ = repository("a.py", b"def broken(:\n")
    with pytest.raises(ValueError, match="coverage is incomplete"):
        build(reader, head)


def test_forged_git_bytes_rejected_before_anchor_creation() -> None:
    reader, head, blob = repository("a.py", b"execute(value)\n")
    reader.contents[("blob", blob)] = b"forged()\n"
    with pytest.raises(ValueError, match="hash mismatch"):
        build(reader, head)


def test_interfile_safe_control_retains_both_files_and_tenant_bound_content() -> None:
    reader = Objects()
    entries = []
    for path, content in [
        ("a.py", b"from b import value\nresult = value\n"),
        ("b.py", "value = 'public РїСЂРёРјРµСЂ'\r\n".encode()),
    ]:
        blob = reader.add("blob", content)
        entries.append(b"100644 " + path.encode() + b"\0" + bytes.fromhex(blob))
    tree = reader.add("tree", b"".join(entries))
    head = reader.add("commit", f"tree {tree}\n\nsafe interfile fixture\n".encode())
    first = build(reader, head)
    second = build_native_source_catalogue(
        reader=reader,
        head_sha=head,
        tenant_id="tenant-b",
        repository_id="repo-a",
        content_key=b"n" * 32,
    )
    assert {a.location.path for a in first.anchors} == {"a.py", "b.py"}
    assert len(first.anchors) == 2
    assert [a.evidence_id for a in first.anchors] != [a.evidence_id for a in second.anchors]
    assert [a.read_artifact.content_id for a in first.anchors] != [
        a.read_artifact.content_id for a in second.anchors
    ]


@pytest.mark.parametrize("source", [b"a = 1\nb = 2\n", b"a = 1\r\nb = 2\r\n", b"a = 1\nb = 2"])
def test_every_nonterminal_window_matches_actual_view_bytes(source: bytes) -> None:
    reader, head, _ = repository("a.py", source)
    catalogue = build(reader, head, window_lines=1)
    view = catalogue.repository_view()
    for anchor in catalogue.anchors:
        assert isinstance(anchor.request.arguments, ReadRangeArguments)
        output = view.read_range(
            anchor.request.arguments, window=RepositoryToolWindow(65536, 65536)
        )
        assert output.content_sha256 == anchor.read_artifact.content_sha256
        assert output.byte_count == anchor.read_artifact.size_bytes
