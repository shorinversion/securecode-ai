from __future__ import annotations

import pytest
from securecode_ai.core.release_provenance import release_ready
from securecode_ai.core.supply_chain import (
    DependencyPolicy,
    SbomComponent,
    SupplyChainConflict,
    canonical_sbom,
)


def test_unresolved_component_fails_closed() -> None:
    item = SbomComponent("x", "1", None, "registry", "a" * 64, "unresolved")
    with pytest.raises(SupplyChainConflict):
        canonical_sbom((item,), DependencyPolicy(frozenset({"MIT"}), frozenset()))
    assert not release_ready(sbom=None, provenance=None, signature=None)
