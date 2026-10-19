"""Which source windows a small local model reads in Discovery.

Discovery reads every window of the revision in one request. A local model with an 8K
context fits a few windows, so on a repository of any size the request overflowed its
budget and Discovery ended without a result (``BUDGET_EXHAUSTED``). In the ``scanner``
seed mode the host picks the windows that fit: first those a scanner located something in,
then the rest in path order, until the window and byte budgets are used. Discovery stays
mandatory and real; it just reads fewer windows, and the report says how many (D-123).
"""

from __future__ import annotations

from dataclasses import dataclass

from securecode_ai.core.evidence_graph import EvidenceGraph

from .product_runtime_contracts import DiscoveryEvidence


@dataclass(frozen=True, slots=True)
class SeedBudget:
    """Ceilings of one Discovery request: reads of windows and bytes of their text."""

    max_windows: int
    max_bytes: int

    def __post_init__(self) -> None:
        if (
            type(self.max_windows) is not int
            or type(self.max_bytes) is not int
            or self.max_windows < 1
            or self.max_bytes < 1
        ):
            raise ValueError("discovery seed budget is invalid")


def select_discovery_seed(
    anchors: tuple[DiscoveryEvidence, ...],
    *,
    scan_graph: EvidenceGraph,
    budget: SeedBudget,
) -> frozenset[str]:
    """The evidence ids of the windows Discovery reads; at least one when there are anchors.

    Windows that overlap a location the deterministic scan cited come first, then the
    others by ``(path, first line)``; a window that no longer fits the byte budget is
    skipped so a smaller one after it can still be taken.
    """

    if type(anchors) is not tuple or not anchors or type(budget) is not SeedBudget:
        raise ValueError("discovery seed request is invalid")
    cited: dict[str, list[tuple[int, int]]] = {}
    for record in scan_graph.evidence:
        location = record.location
        if location is not None:
            cited.setdefault(location.path, []).append((location.start.line, location.end.line))

    def hit(anchor: DiscoveryEvidence) -> bool:
        first, last = anchor.location.start.line, anchor.location.end.line
        return any(
            start <= last and first <= end for start, end in cited.get(anchor.location.path, ())
        )

    ordered = sorted(
        anchors,
        key=lambda anchor: (
            not hit(anchor),
            anchor.location.path,
            anchor.location.start.line,
            anchor.evidence_id,
        ),
    )
    chosen: list[str] = []
    used = 0
    for anchor in ordered:
        size = anchor.read_artifact.size_bytes
        if len(chosen) >= budget.max_windows:
            break
        if chosen and used + size > budget.max_bytes:
            continue
        chosen.append(anchor.evidence_id)
        used += size
    return frozenset(chosen)


__all__ = ["SeedBudget", "select_discovery_seed"]
