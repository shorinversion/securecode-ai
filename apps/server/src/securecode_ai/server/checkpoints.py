"""Metadata-only SQLite checkpoints for restart-safe server workflow orchestration."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass

from .migrations import apply_schema


class CheckpointConflict(Exception):
    pass


@dataclass(frozen=True, slots=True)
class WorkflowCheckpoint:
    tenant_id: str
    run_id: str
    execution_identity_hash: str
    state: str
    version: int
    metadata: dict[str, object]


class SqliteCheckpointStore:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        apply_schema(connection)

    @classmethod
    def in_memory(cls) -> SqliteCheckpointStore:
        return cls(sqlite3.connect(":memory:"))

    def load(self, tenant_id: str, run_id: str) -> WorkflowCheckpoint | None:
        row = self._connection.execute(
            "SELECT identity_hash,state,version,metadata_json FROM workflow_checkpoints WHERE tenant_id=? AND run_id=?",
            (tenant_id, run_id),
        ).fetchone()
        if row is None:
            return None
        return WorkflowCheckpoint(tenant_id, run_id, row[0], row[1], row[2], json.loads(row[3]))

    def save(
        self, checkpoint: WorkflowCheckpoint, expected_version: int | None
    ) -> WorkflowCheckpoint:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            current = self.load(checkpoint.tenant_id, checkpoint.run_id)
            if current is None:
                if expected_version is not None or checkpoint.version != 1:
                    raise CheckpointConflict()
                self._connection.execute(
                    "INSERT INTO workflow_checkpoints VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        checkpoint.tenant_id,
                        checkpoint.run_id,
                        checkpoint.execution_identity_hash,
                        checkpoint.state,
                        checkpoint.version,
                        _json(checkpoint.metadata),
                    ),
                )
            else:
                if (
                    expected_version != current.version
                    or checkpoint.version != current.version + 1
                    or checkpoint.execution_identity_hash != current.execution_identity_hash
                ):
                    raise CheckpointConflict()
                self._connection.execute(
                    "UPDATE workflow_checkpoints SET state=?,version=?,metadata_json=? WHERE tenant_id=? AND run_id=? AND version=?",
                    (
                        checkpoint.state,
                        checkpoint.version,
                        _json(checkpoint.metadata),
                        checkpoint.tenant_id,
                        checkpoint.run_id,
                        expected_version,
                    ),
                )
            self._connection.commit()
            return checkpoint
        except Exception:
            self._connection.rollback()
            raise


def _json(value: dict[str, object]) -> str:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
    )
