"""Public development snapshots through actual sealed catalogue admission."""

from __future__ import annotations

import hashlib

import pytest
from securecode_ai.adapters.local_provider_admission import CoreCase
from securecode_ai.adapters.public_core_fixtures import build_public_core_fixture

_CASES = tuple(
    case
    for case in CoreCase
    if case.value.startswith(("python_", "javascript_", "typescript_", "go_"))
)


@pytest.mark.parametrize("case", _CASES)
def test_public_snapshot_parses_and_binds_every_source_window(case: CoreCase) -> None:
    fixture = build_public_core_fixture(case)
    catalogue = fixture.catalogue
    assert catalogue.snapshot.head_sha == fixture.head_sha
    assert catalogue.snapshot.files
    assert len(catalogue.indexes) == len(catalogue.snapshot.files)
    assert catalogue.anchors
    files = {item.path: item for item in catalogue.snapshot.files}
    for index in catalogue.indexes:
        assert not index.diagnostics
    for anchor in catalogue.anchors:
        source = files[anchor.location.path]
        assert anchor.head_sha == fixture.head_sha
        assert source.content_sha256 == hashlib.sha256(source.content).hexdigest()
        assert anchor.location.content_sha256 == source.content_sha256
        window = catalogue._window_bytes(anchor)
        assert hashlib.sha256(window).hexdigest() == anchor.read_artifact.content_sha256
        assert len(window) == anchor.read_artifact.size_bytes
    # This constructs only the sealed read-only product view; source is not executed.
    assert catalogue.repository_view() is not None


@pytest.mark.parametrize("language", ["python", "javascript", "typescript", "go"])
@pytest.mark.parametrize("interfile", [False, True])
def test_public_vulnerable_and_safe_controls_have_matching_file_topology(
    language: str, interfile: bool
) -> None:
    vulnerable_name = "interfile" if interfile else "vulnerable"
    safe_name = "safe_interfile" if interfile else "safe"
    vulnerable = build_public_core_fixture(CoreCase(f"{language}_{vulnerable_name}"))
    safe = build_public_core_fixture(CoreCase(f"{language}_{safe_name}"))
    vulnerable_paths = tuple(item.path for item in vulnerable.catalogue.snapshot.files)
    safe_paths = tuple(item.path for item in safe.catalogue.snapshot.files)
    assert vulnerable_paths == safe_paths
    assert len(vulnerable_paths) == (2 if interfile else 1)
    assert vulnerable.head_sha != safe.head_sha


@pytest.mark.parametrize("language", ["python", "javascript", "typescript", "go"])
@pytest.mark.parametrize("safe", [False, True])
def test_interfile_query_construction_and_database_sink_are_in_distinct_files(
    language: str, safe: bool
) -> None:
    suffix = "safe_interfile" if safe else "interfile"
    fixture = build_public_core_fixture(CoreCase(f"{language}_{suffix}"))
    files = fixture.catalogue.snapshot.files
    sql_paths = {item.path for item in files if b"SELECT * FROM users" in item.content}
    sink_paths = {
        item.path
        for item in files
        if any(marker in item.content for marker in (b".execute(", b".query(", b".Query("))
    }
    assert len(sql_paths) == len(sink_paths) == 1
    assert sql_paths.isdisjoint(sink_paths)
