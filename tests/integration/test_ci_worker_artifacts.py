"""P5.12 cross-boundary check for persisted worker metadata."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKER_SOURCE = ROOT / "apps" / "worker" / "src"
if str(WORKER_SOURCE) not in sys.path:
    sys.path.insert(0, str(WORKER_SOURCE))

from securecode_ai.contracts import DataClass  # noqa: E402
from securecode_ai.worker import (  # noqa: E402
    CiWorkerRequest,
    canonical_ci_worker_result_json,
    run_ci_worker,
    write_ci_worker_artifact,
)


def _unit_contract_module() -> Any:
    path = ROOT / "tests" / "unit" / "test_ci_worker.py"
    specification = importlib.util.spec_from_file_location("p5_11_worker_unit_contract", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


@pytest.mark.skipif(os.name != "posix", reason="P5.12 is Linux-only")
def test_artifact_boundary_stores_only_the_exact_machine_result(tmp_path: Path) -> None:
    fixture = _unit_contract_module()
    request = CiWorkerRequest(audit_run=fixture._admitted_run())
    result = run_ci_worker(request)

    reference = write_ci_worker_artifact(tmp_path, request, result)
    stored = list((tmp_path / "tenants").glob("*/*.json"))

    assert len(stored) == 1
    assert stored[0].read_bytes() == canonical_ci_worker_result_json(result).encode("ascii")
    assert reference.tenant_id == request.audit_run.execution_identity.repository_revision.tenant_id
    assert reference.data_class is DataClass.INTERNAL_METADATA
