from __future__ import annotations

from securecode_ai.server.assurance_repository import AssuranceRecord, AssuranceRepository
from securecode_ai.server.assurance_service import AssuranceService


def test_failed_record_stays_in_denominator() -> None:
    repo = AssuranceRepository.in_memory()
    record = repo.append(
        AssuranceRecord("t", "r", "a" * 64, "id", "unit", "FAILED", "verifier", "b" * 64, {})
    )
    result = AssuranceService(repo).report_inputs(
        tenant_id="t",
        repository_id="r",
        execution_identity_hash="a" * 64,
    )
    assert result["denominator"] == 1 and not result["complete"] and record.sequence == 1
