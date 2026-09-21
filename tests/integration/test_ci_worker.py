"""P5.11 cross-boundary machine-result checks for the offline CI worker."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
WORKER_SOURCE = ROOT / "apps" / "worker" / "src"
if str(WORKER_SOURCE) not in sys.path:
    sys.path.insert(0, str(WORKER_SOURCE))

from securecode_ai.contracts import AuditRunOutcome, CliExitCode  # noqa: E402
from securecode_ai.worker import (  # noqa: E402
    CiWorkerRequest,
    canonical_ci_worker_result_json,
    run_ci_worker,
)


def _unit_contract_module() -> object:
    path = ROOT / "tests" / "unit" / "test_ci_worker.py"
    specification = importlib.util.spec_from_file_location("p5_11_worker_unit_contract", path)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_ci_entrypoint_preserves_admitted_core_identity_without_side_effects() -> None:
    fixture: Any = _unit_contract_module()
    audit_run = fixture._admitted_run(outcome=AuditRunOutcome.PASS)

    result = run_ci_worker(CiWorkerRequest(audit_run=audit_run))
    document = json.loads(canonical_ci_worker_result_json(result))

    assert result.audit_outcome is AuditRunOutcome.PASS
    assert result.exit_code is CliExitCode.COMPLETED
    assert (
        document["execution_identity_hash"] == audit_run.execution_identity.execution_identity_hash
    )
    assert document["revision"] == audit_run.execution_identity.repository_revision.head_sha
    assert document["network_attempts"] == 0
    assert document["scm_write_attempts"] == 0
    assert all(value not in document for value in ("source", "credentials", "secret", "token"))
