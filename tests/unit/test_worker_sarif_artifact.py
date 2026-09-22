"""P5.9 canonical SARIF artifact publication contracts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKER_SOURCE = ROOT / "apps" / "worker" / "src"
if str(WORKER_SOURCE) not in sys.path:
    sys.path.insert(0, str(WORKER_SOURCE))

from securecode_ai.adapters.local_product_runner_config import (  # noqa: E402
    LocalProductScanResult,
)
from securecode_ai.worker.execution import _artifacts  # noqa: E402
from securecode_ai.worker.protocol import ProtocolError, WorkerArtifact  # noqa: E402

SARIF = b'{"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0"}\n'
REPORT = b'{"outcome":"PASS"}\n'
GRAPH = b'{"tenant_id":"tenant-1"}'


class _Run:
    execution_identity = SimpleNamespace(repository_revision=SimpleNamespace(tenant_id="tenant-1"))

    @staticmethod
    def model_dump(*, mode: str) -> dict[str, str]:
        assert mode == "json"
        return {"run_id": "run-1"}


def _scan() -> LocalProductScanResult:
    return cast(
        LocalProductScanResult,
        SimpleNamespace(
            composition=SimpleNamespace(run=_Run()),
            rendered=REPORT,
            sarif_rendered=SARIF,
            graph_artifact=GRAPH,
        ),
    )


def test_worker_emits_canonical_sarif_as_a_content_addressed_artifact() -> None:
    artifacts = _artifacts(_scan())
    sarif = next(item for item in artifacts if item.purpose == "sarif-report")

    assert sarif.content == SARIF
    assert json.loads(sarif.content)["version"] == "2.1.0"
    assert sarif.reference.tenant_id == "tenant-1"
    assert sarif.reference.content_sha256 == hashlib.sha256(SARIF).hexdigest()
    assert sarif.reference.size_bytes == len(SARIF)


def test_sarif_publication_reference_is_stable_for_safe_retries() -> None:
    first = next(item for item in _artifacts(_scan()) if item.purpose == "sarif-report")
    retry = next(item for item in _artifacts(_scan()) if item.purpose == "sarif-report")

    assert retry == first
    assert retry.reference.content_id == f"worker-sarif-{hashlib.sha256(SARIF).hexdigest()[:32]}"


def test_worker_artifact_rejects_unregistered_purposes() -> None:
    valid = next(item for item in _artifacts(_scan()) if item.purpose == "sarif-report")

    with pytest.raises(ProtocolError):
        WorkerArtifact(reference=valid.reference, purpose="unreviewed", content=valid.content)
