"""Regressions for server bugs surfaced by the mypy quality gate."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from securecode_ai.server import artifact_upload, bootstrap


def test_maintenance_cli_imports_waiver_policy_helper() -> None:
    module = importlib.import_module("securecode_ai.server.maintenance_cli")

    assert callable(module._waivers_cover_run_policy)


def test_orphan_object_removal_rejects_unexpected_entries(tmp_path: Path) -> None:
    target = tmp_path / "object"
    target.mkdir()
    (target / "payload").write_bytes(b"x")
    (target / "unexpected").write_bytes(b"y")

    with pytest.raises(artifact_upload.ArtifactUploadConflict):
        artifact_upload._remove_orphan_object(target)
    assert (target / "payload").exists()


def test_orphan_object_removal_deletes_expected_entries(tmp_path: Path) -> None:
    target = tmp_path / "object"
    target.mkdir()
    (target / "payload").write_bytes(b"x")
    (target / "receipt.json").write_bytes(b"{}")

    artifact_upload._remove_orphan_object(target)

    assert not (target / "payload").exists()
    assert not (target / "receipt.json").exists()


def test_waiver_refresh_adapter_calls_keyword_only_publisher() -> None:
    calls: list[tuple[str, str, str]] = []
    receipt = object()

    class _Publisher:
        def refresh_after_waiver(
            self, *, tenant_id: str, run_id: str, execution_identity_hash: str
        ) -> object:
            calls.append((tenant_id, run_id, execution_identity_hash))
            return receipt

    refresh = bootstrap._waiver_verdict_refresher(_Publisher())  # type: ignore[arg-type]

    assert refresh("tenant-a", "run-1", "a" * 64) is receipt
    assert calls == [("tenant-a", "run-1", "a" * 64)]
