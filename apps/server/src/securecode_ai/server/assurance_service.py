"""Tenant-scoped facade for source-free assurance attempt accounting."""

from __future__ import annotations

from typing import Final

from .assurance_repository import AssuranceRecord, AssuranceRepository

_SUCCESS_OUTCOMES: Final = frozenset({"CONFIRMED", "EXECUTED", "PASS"})


class AssuranceService:
    def __init__(self, repository: AssuranceRepository) -> None:
        if type(repository) is not AssuranceRepository:
            raise TypeError("repository must be an AssuranceRepository")
        self._repository = repository

    def append_attempt(
        self,
        value: AssuranceRecord,
        *,
        expected_sequence: int | None = None,
    ) -> AssuranceRecord:
        return self._repository.append(value, expected_sequence=expected_sequence)

    def report_inputs(
        self,
        *,
        tenant_id: str,
        repository_id: str,
        execution_identity_hash: str,
    ) -> dict[str, object]:
        values = self._repository.list(
            tenant_id,
            repository_id,
            execution_identity_hash,
        )
        records = tuple(
            {
                "record_id": value.record_id,
                "kind": value.kind,
                "outcome": value.outcome,
                "sequence": value.sequence,
                "previous_hash": value.previous_hash,
                "record_hash": value.record_hash,
                "verifier_id": value.verifier_id,
                "verifier_sha256": value.verifier_sha256,
            }
            for value in values
        )
        failures = sum(value.outcome not in _SUCCESS_OUTCOMES for value in values)
        return {
            "tenant_id": tenant_id,
            "repository_id": repository_id,
            "execution_identity_hash": execution_identity_hash,
            "records": records,
            "denominator": len(values),
            "successful": len(values) - failures,
            "failed_or_incomplete": failures,
            "ledger_head_sha256": values[-1].record_hash if values else "0" * 64,
            "complete": bool(values) and failures == 0,
            "authority": "SUPPORTING_EVIDENCE_ONLY",
        }


__all__ = ["AssuranceService"]
