"""Checks for fixed synthetic public Core development fixture metadata."""

from __future__ import annotations

from dataclasses import replace

import pytest
from securecode_ai.adapters.local_provider_admission import CoreCase
from securecode_ai.adapters.public_core_fixtures import (
    FixtureProvenance,
    PublicCoreFixtureError,
    _FixtureReader,
    build_public_core_fixture,
)
from securecode_ai.contracts import DataClass

_SUPPORTED = (
    CoreCase.PYTHON_VULNERABLE,
    CoreCase.PYTHON_SAFE,
    CoreCase.PYTHON_INTERFILE,
    CoreCase.PYTHON_SAFE_INTERFILE,
    CoreCase.JAVASCRIPT_VULNERABLE,
    CoreCase.JAVASCRIPT_SAFE,
    CoreCase.JAVASCRIPT_INTERFILE,
    CoreCase.JAVASCRIPT_SAFE_INTERFILE,
    CoreCase.TYPESCRIPT_VULNERABLE,
    CoreCase.TYPESCRIPT_SAFE,
    CoreCase.TYPESCRIPT_INTERFILE,
    CoreCase.TYPESCRIPT_SAFE_INTERFILE,
    CoreCase.GO_VULNERABLE,
    CoreCase.GO_SAFE,
    CoreCase.GO_INTERFILE,
    CoreCase.GO_SAFE_INTERFILE,
)


@pytest.mark.parametrize("case", _SUPPORTED)
def test_fixed_fixture_is_deterministic_sealed_and_source_free_in_repr(case: CoreCase) -> None:
    first = build_public_core_fixture(case)
    second = build_public_core_fixture(case)

    assert first == second
    assert first.case is case
    assert first.provenance is FixtureProvenance.SYNTHETIC_DEVELOPMENT
    assert first.head_sha == first.catalogue.snapshot.head_sha
    assert first.paths == tuple(item.path for item in first.catalogue.snapshot.files)
    assert tuple(
        (item.path, item.content_sha256) for item in first.source_manifest_hashes
    ) == tuple((item.path, item.content_sha256) for item in first.catalogue.snapshot.files)
    assert first.catalogue.anchors
    assert all(anchor.head_sha == first.head_sha for anchor in first.catalogue.anchors)
    assert all(
        anchor.source_artifact.data_class is DataClass.PUBLIC
        and anchor.read_artifact.data_class is DataClass.PUBLIC
        for anchor in first.catalogue.anchors
    )
    assert "SELECT" not in repr(first)


@pytest.mark.parametrize(
    ("vulnerable", "safe", "paths"),
    [
        (CoreCase.PYTHON_VULNERABLE, CoreCase.PYTHON_SAFE, 1),
        (CoreCase.PYTHON_INTERFILE, CoreCase.PYTHON_SAFE_INTERFILE, 2),
        (CoreCase.JAVASCRIPT_VULNERABLE, CoreCase.JAVASCRIPT_SAFE, 1),
        (CoreCase.JAVASCRIPT_INTERFILE, CoreCase.JAVASCRIPT_SAFE_INTERFILE, 2),
        (CoreCase.TYPESCRIPT_VULNERABLE, CoreCase.TYPESCRIPT_SAFE, 1),
        (CoreCase.TYPESCRIPT_INTERFILE, CoreCase.TYPESCRIPT_SAFE_INTERFILE, 2),
        (CoreCase.GO_VULNERABLE, CoreCase.GO_SAFE, 1),
        (CoreCase.GO_INTERFILE, CoreCase.GO_SAFE_INTERFILE, 2),
    ],
)
def test_vulnerable_and_safe_controls_have_equal_topology_but_distinct_snapshots(
    vulnerable: CoreCase, safe: CoreCase, paths: int
) -> None:
    vulnerable_fixture = build_public_core_fixture(vulnerable)
    safe_fixture = build_public_core_fixture(safe)

    assert vulnerable_fixture.paths == safe_fixture.paths
    assert len(vulnerable_fixture.paths) == paths
    assert vulnerable_fixture.head_sha != safe_fixture.head_sha
    assert vulnerable_fixture.source_manifest_hashes != safe_fixture.source_manifest_hashes


@pytest.mark.parametrize(
    ("vulnerable", "safe"),
    [
        (CoreCase.PYTHON_INTERFILE, CoreCase.PYTHON_SAFE_INTERFILE),
        (CoreCase.JAVASCRIPT_INTERFILE, CoreCase.JAVASCRIPT_SAFE_INTERFILE),
        (CoreCase.TYPESCRIPT_INTERFILE, CoreCase.TYPESCRIPT_SAFE_INTERFILE),
        (CoreCase.GO_INTERFILE, CoreCase.GO_SAFE_INTERFILE),
    ],
)
def test_interfile_recipes_keep_sql_construction_and_sink_in_distinct_files(
    vulnerable: CoreCase, safe: CoreCase
) -> None:
    for case in (vulnerable, safe):
        fixture = build_public_core_fixture(case)
        source_paths = {
            item.path for item in fixture.catalogue.snapshot.files if b"SELECT" in item.content
        }
        sink_paths = {
            item.path
            for item in fixture.catalogue.snapshot.files
            if any(marker in item.content for marker in (b".execute", b".query", b".Query"))
        }
        assert source_paths and sink_paths and source_paths.isdisjoint(sink_paths)


@pytest.mark.parametrize(
    "case",
    (
        CoreCase.ZERO_SCANNER_NATIVE_FINDING,
        CoreCase.NATIVE_COMPLETED_ZERO,
        CoreCase.AUDITOR_ALL_CANDIDATES,
        CoreCase.PROVIDER_FAULT,
        CoreCase.TOOL_FAULT,
        CoreCase.NATIVE_CYCLE,
    ),
)
def test_operational_cases_and_non_enum_inputs_are_rejected(case: CoreCase) -> None:
    with pytest.raises(PublicCoreFixtureError, match=r"^public Core fixture is invalid$"):
        build_public_core_fixture(case)
    with pytest.raises(PublicCoreFixtureError, match=r"^public Core fixture is invalid$"):
        build_public_core_fixture(case.value)  # type: ignore[arg-type]


def test_in_memory_git_reader_checks_kind_identity_and_read_bounds() -> None:
    reader = _FixtureReader()
    oid = reader.add("blob", b"public")

    assert reader.read("blob", oid, max_bytes=6) == b"public"
    for kind, object_id, max_bytes in (
        ("blob", oid, 5),
        ("tree", oid, 6),
        ("blob", "0" * 40, 6),
        ("unknown", oid, 6),
    ):
        with pytest.raises(ValueError):
            reader.read(kind, object_id, max_bytes=max_bytes)
    with pytest.raises(ValueError):
        reader.read([], oid, max_bytes=6)  # type: ignore[arg-type]
    with pytest.raises(PublicCoreFixtureError):
        reader.add("unknown", b"public")
    with pytest.raises(PublicCoreFixtureError):
        reader.add([], b"public")  # type: ignore[arg-type]


def test_public_fixture_rejects_malformed_language_without_echoing_fixture_content() -> None:
    fixture = build_public_core_fixture(CoreCase.PYTHON_VULNERABLE)

    with pytest.raises(PublicCoreFixtureError, match=r"^public Core fixture is invalid$"):
        replace(fixture, language=[])  # type: ignore[arg-type]
