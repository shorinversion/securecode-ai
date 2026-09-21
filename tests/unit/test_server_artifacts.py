"""P6.4 artifact metadata and immutable local storage contracts."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from securecode_ai.server.artifact_store import LocalArtifactStore
from securecode_ai.server.artifacts import ArtifactConflict, ArtifactMetadata


def _metadata(data: bytes) -> ArtifactMetadata:
    return ArtifactMetadata(
        "tenant-a",
        "repo-a",
        "run-a",
        "a" * 64,
        hashlib.sha256(data).hexdigest(),
        len(data),
        "DC1_INTERNAL_METADATA",
        "report",
        datetime(2026, 9, 19, tzinfo=UTC),
    )


def test_store_replays_exact_metadata_and_revalidates_read(tmp_path: Path) -> None:
    store, data = LocalArtifactStore(tmp_path), b"safe receipt"
    metadata = _metadata(data)
    assert store.put(metadata, [data], "key") == metadata
    assert store.put(metadata, [data], "key") == metadata
    loaded, chunks = store.get(tenant_id="tenant-a", content_sha256=metadata.content_sha256)
    assert loaded == metadata and b"".join(chunks) == data


def test_wrong_hash_and_cross_tenant_read_fail_closed(tmp_path: Path) -> None:
    store, data = LocalArtifactStore(tmp_path), b"receipt"
    metadata = _metadata(data)
    with pytest.raises(ArtifactConflict):
        store.put(metadata, [b"tampered"], "key")
    store.put(metadata, [data], "key")
    with pytest.raises(ArtifactConflict):
        store.get(tenant_id="tenant-b", content_sha256=metadata.content_sha256)
