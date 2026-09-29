"""Dependency policy admission and canonical SBOM serialization."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from securecode_ai.core.supply_chain import (
    DependencyPolicy,
    SbomComponent,
    SupplyChainConflict,
    canonical_sbom,
)

DIGEST = "a" * 64
POLICY = DependencyPolicy(frozenset({"MIT", "Apache-2.0"}), frozenset({"left-pad"}))


def _component(
    name: str = "requests", version: str = "2.32.0", **overrides: object
) -> SbomComponent:
    values: dict[str, object] = {
        "name": name,
        "version": version,
        "license": "MIT",
        "source": "https://pypi.org/simple",
        "content_sha256": DIGEST,
        "vulnerability_status": "resolved",
        **overrides,
    }
    return SbomComponent(**values)  # type: ignore[arg-type]


def test_canonical_sbom_is_sorted_compact_ascii_json() -> None:
    payload = canonical_sbom((_component("zlib", "1.0"), _component("attrs", "23.1")), POLICY)

    document = json.loads(payload)
    assert [item["name"] for item in document] == ["attrs", "zlib"]
    assert set(document[0]) == {
        "content_sha256",
        "license",
        "name",
        "source",
        "version",
        "vulnerability_status",
    }
    assert payload.isascii() and b", " not in payload and b": " not in payload


def test_serialization_is_independent_of_input_order() -> None:
    first = (_component("a", "1"), _component("b", "1"))
    assert canonical_sbom(first, POLICY) == canonical_sbom(tuple(reversed(first)), POLICY)


@pytest.mark.parametrize(
    "component",
    [
        _component("left-pad"),
        _component(license=None),
        _component(license="GPL-3.0-only"),
        _component(vulnerability_status="unresolved"),
        _component(vulnerability_status="unknown"),
    ],
)
def test_components_violating_policy_are_rejected(component: SbomComponent) -> None:
    with pytest.raises(SupplyChainConflict, match="violates dependency policy"):
        canonical_sbom((component,), POLICY)


def test_duplicate_component_identity_is_rejected() -> None:
    with pytest.raises(SupplyChainConflict, match="duplicate"):
        canonical_sbom((_component(), _component(source="https://mirror.example")), POLICY)


@pytest.mark.parametrize("components", [(), [], None])
def test_empty_or_non_tuple_sbom_is_rejected(components: object) -> None:
    with pytest.raises(SupplyChainConflict, match="SBOM is empty"):
        canonical_sbom(components, POLICY)  # type: ignore[arg-type]


def test_foreign_policy_and_component_types_are_rejected() -> None:
    with pytest.raises(SupplyChainConflict, match="policy is invalid"):
        canonical_sbom((_component(),), object())  # type: ignore[arg-type]
    with pytest.raises(SupplyChainConflict, match="component type"):
        canonical_sbom((object(),), POLICY)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": ""},
        {"version": " 1.0"},
        {"source": "x" * 513},
        {"license": " MIT"},
        {"content_sha256": "A" * 64},
        {"content_sha256": "short"},
        {"vulnerability_status": "fixed"},
    ],
)
def test_component_fields_are_validated(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        _component(**overrides)  # type: ignore[arg-type]


def test_policy_fields_are_validated() -> None:
    with pytest.raises(ValueError, match="policy is invalid"):
        DependencyPolicy(frozenset(), frozenset())
    with pytest.raises(ValueError, match="policy is invalid"):
        DependencyPolicy({"MIT"}, frozenset())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="policy is invalid"):
        DependencyPolicy(frozenset({"MIT"}), frozenset({"bad\nname"}))


def test_policy_permits_rejects_foreign_objects() -> None:
    assert POLICY.permits(_component())
    assert not POLICY.permits(object())  # type: ignore[arg-type]
    assert not POLICY.permits(replace(_component(), license=None))
