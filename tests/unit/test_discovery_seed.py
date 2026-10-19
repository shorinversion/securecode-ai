"""The windows a small local model reads in Discovery (scanner seed)."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any, cast

import pytest
from securecode_ai.adapters.product_runtime_contracts import DiscoveryEvidence
from securecode_ai.adapters.product_runtime_discovery import ProductDiscoveryBackend
from securecode_ai.adapters.product_runtime_seed import SeedBudget, select_discovery_seed
from securecode_ai.contracts import ArtifactRef, DataClass, SourceLocation
from securecode_ai.core.tool_policy import (
    TOOL_ARGUMENT_SCHEMA_VERSION,
    ReadEvidenceArguments,
    RepositoryTool,
    RepositoryToolRequest,
)

HEAD = "a" * 40


def _artifact(content: bytes, size: int | None = None) -> ArtifactRef:
    return ArtifactRef(
        schema_version="0.2.0",
        tenant_id="tenant-a",
        content_id="artifact-" + hashlib.sha256(content).hexdigest()[:12],
        content_sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=size if size is not None else len(content),
        data_class=DataClass.CONFIDENTIAL_SOURCE,
    )


def _anchor(name: str, path: str, first: int, last: int, size: int = 1000) -> DiscoveryEvidence:
    source = _artifact(path.encode())
    location = SourceLocation.model_validate(
        {
            "schema_version": "0.2.0",
            "path": path,
            "start": {"schema_version": "0.2.0", "line": first, "column": 1},
            "end": {"schema_version": "0.2.0", "line": last, "column": 1},
            "content_sha256": source.content_sha256,
        }
    )
    return DiscoveryEvidence(
        evidence_id=name,
        tenant_id="tenant-a",
        head_sha=HEAD,
        location=location,
        source_artifact=source,
        read_artifact=_artifact(name.encode(), size),
        request=RepositoryToolRequest(
            tool=RepositoryTool.READ_EVIDENCE,
            arguments=ReadEvidenceArguments(TOOL_ARGUMENT_SCHEMA_VERSION, HEAD, name),
        ),
    )


def _graph(*cited: tuple[str, int, int]) -> Any:
    """A scan graph whose evidence cites ``(path, first line, last line)`` places."""

    def record(path: str, first: int, last: int) -> SimpleNamespace:
        def position(line: int) -> SimpleNamespace:
            return SimpleNamespace(line=line)

        return SimpleNamespace(
            location=SimpleNamespace(path=path, start=position(first), end=position(last))
        )

    return SimpleNamespace(
        evidence=(
            *(record(*place) for place in cited),
            SimpleNamespace(location=None),
        )
    )


ANCHORS = (
    _anchor("a1", "a.py", 1, 100),
    _anchor("a2", "a.py", 101, 200),
    _anchor("b1", "b.py", 1, 100),
    _anchor("b2", "b.py", 101, 200),
    _anchor("c1", "c.py", 1, 100),
)


def test_windows_with_a_scanner_hit_come_first_then_path_order() -> None:
    graph = _graph(("b.py", 150, 150), ("c.py", 3, 4))

    seed = select_discovery_seed(ANCHORS, scan_graph=graph, budget=SeedBudget(3, 10_000))

    assert seed == frozenset({"b2", "c1", "a1"})


def test_the_window_count_and_byte_budgets_cut_the_seed() -> None:
    graph = _graph(("a.py", 1, 1))

    by_count = select_discovery_seed(ANCHORS, scan_graph=graph, budget=SeedBudget(2, 10_000))
    by_bytes = select_discovery_seed(ANCHORS, scan_graph=graph, budget=SeedBudget(5, 2_500))

    assert by_count == frozenset({"a1", "a2"})
    assert by_bytes == frozenset({"a1", "a2"})


def test_a_window_that_does_not_fit_is_skipped_for_a_smaller_one() -> None:
    anchors = (_anchor("big", "a.py", 1, 100, size=900), _anchor("small", "b.py", 1, 100, size=100))
    graph = _graph(("a.py", 1, 1))

    # The hit window is taken first and uses the budget; the smaller one still fits after it.
    assert select_discovery_seed(
        anchors, scan_graph=graph, budget=SeedBudget(5, 1_000)
    ) == frozenset({"big", "small"})
    assert select_discovery_seed(anchors, scan_graph=graph, budget=SeedBudget(5, 950)) == frozenset(
        {"big"}
    )


def test_at_least_one_window_is_read_even_if_it_exceeds_the_byte_budget() -> None:
    seed = select_discovery_seed(
        (_anchor("huge", "a.py", 1, 100, size=50_000),),
        scan_graph=_graph(),
        budget=SeedBudget(4, 100),
    )

    assert seed == frozenset({"huge"})


@pytest.mark.parametrize("windows, size", [(0, 1), (1, 0), (-1, 5)])
def test_budget_must_be_positive(windows: int, size: int) -> None:
    with pytest.raises(ValueError, match="budget"):
        SeedBudget(windows, size)


def test_no_anchors_is_refused() -> None:
    with pytest.raises(ValueError, match="seed request"):
        select_discovery_seed((), scan_graph=_graph(), budget=SeedBudget(1, 1))


def _backend() -> ProductDiscoveryBackend:
    backend = object.__new__(ProductDiscoveryBackend)
    for name in ProductDiscoveryBackend.__slots__:
        object.__setattr__(backend, name, None)
    object.__setattr__(backend, "_catalogue", ANCHORS)
    return backend


def test_with_seed_keeps_the_selected_windows_in_their_order() -> None:
    narrowed = _backend().with_seed(frozenset({"c1", "a2"}))

    assert [item.evidence_id for item in cast(Any, narrowed)._catalogue] == ["a2", "c1"]


def test_with_seed_of_every_window_changes_nothing() -> None:
    backend = _backend()

    assert backend.with_seed(frozenset(item.evidence_id for item in ANCHORS)) is backend


@pytest.mark.parametrize("seed", [frozenset(), frozenset({"unknown"}), frozenset({"a1", "x"})])
def test_with_seed_refuses_an_empty_or_unknown_seed(seed: frozenset[str]) -> None:
    with pytest.raises(ValueError, match="discovery seed"):
        _backend().with_seed(seed)
