"""Schema for restart-safe SCM webhook run state and receipt history."""

from __future__ import annotations

from typing import Final

SCM_STATE_SCHEMA_STATEMENTS: Final = (
    """CREATE TABLE IF NOT EXISTS scm_run_states (
        tenant_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        provider TEXT NOT NULL CHECK (provider IN ('github', 'gitlab')),
        provider_installation_id TEXT NOT NULL,
        installation_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        change_id TEXT NOT NULL,
        head_sha TEXT NOT NULL,
        execution_identity_hash TEXT NOT NULL,
        execution_identity_json TEXT NOT NULL,
        lifecycle TEXT NOT NULL CHECK (
            lifecycle IN ('ADMITTED', 'COMPLETED', 'SUPERSEDED')
        ),
        outcome TEXT CHECK (
            outcome IS NULL OR outcome IN (
                'PASS', 'FAIL', 'INDETERMINATE', 'ERROR', 'CANCELLED',
                'SUPERSEDED'
            )
        ),
        state_version INTEGER NOT NULL CHECK (state_version >= 1),
        created_sequence INTEGER NOT NULL CHECK (created_sequence >= 1),
        PRIMARY KEY (tenant_id, run_id),
        UNIQUE (
            tenant_id, installation_id, repository_id,
            execution_identity_hash
        ),
        UNIQUE (tenant_id, created_sequence),
        CHECK (length(head_sha) = 40),
        CHECK (length(provider_installation_id) BETWEEN 1 AND 128),
        CHECK (length(change_id) BETWEEN 1 AND 128),
        CHECK (length(execution_identity_hash) = 64),
        CHECK (length(execution_identity_json) BETWEEN 2 AND 32768),
        CHECK (
            (lifecycle = 'ADMITTED' AND outcome IS NULL)
            OR (lifecycle = 'COMPLETED' AND outcome IS NOT NULL
                AND outcome <> 'SUPERSEDED')
            OR (lifecycle = 'SUPERSEDED' AND outcome = 'SUPERSEDED')
        )
    )""",
    """CREATE INDEX IF NOT EXISTS scm_run_states_scope_idx
       ON scm_run_states (
           tenant_id, installation_id, repository_id, lifecycle, head_sha
       )""",
    """CREATE TABLE IF NOT EXISTS scm_head_scopes (
        tenant_id TEXT NOT NULL,
        installation_id TEXT NOT NULL,
        repository_id TEXT NOT NULL,
        current_head_sha TEXT NOT NULL CHECK (length(current_head_sha) = 40),
        state_version INTEGER NOT NULL CHECK (state_version >= 1),
        PRIMARY KEY (tenant_id, installation_id, repository_id)
    )""",
    """CREATE TABLE IF NOT EXISTS scm_delivery_receipts (
        tenant_id TEXT NOT NULL,
        delivery_id TEXT NOT NULL,
        request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
        run_id TEXT NOT NULL,
        receipt_json TEXT NOT NULL CHECK (length(receipt_json) BETWEEN 2 AND 32768),
        created_sequence INTEGER NOT NULL CHECK (created_sequence >= 1),
        PRIMARY KEY (tenant_id, delivery_id),
        UNIQUE (tenant_id, created_sequence)
    )""",
    """CREATE INDEX IF NOT EXISTS scm_delivery_receipts_run_idx
       ON scm_delivery_receipts (tenant_id, run_id)""",
    """CREATE TABLE IF NOT EXISTS scm_run_receipt_history (
        tenant_id TEXT NOT NULL,
        run_id TEXT NOT NULL,
        receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 64),
        receipt_kind TEXT NOT NULL CHECK (
            receipt_kind IN ('ADMISSION', 'PUBLICATION')
        ),
        state_version INTEGER NOT NULL CHECK (state_version >= 0),
        receipt_json TEXT NOT NULL CHECK (length(receipt_json) BETWEEN 2 AND 32768),
        PRIMARY KEY (tenant_id, run_id, receipt_sha256)
    )""",
    """CREATE INDEX IF NOT EXISTS scm_run_receipt_history_order_idx
       ON scm_run_receipt_history (
           tenant_id, run_id, state_version, receipt_kind, receipt_sha256
       )""",
    """CREATE TABLE IF NOT EXISTS scm_run_supersessions (
        tenant_id TEXT NOT NULL,
        superseded_run_id TEXT NOT NULL,
        superseding_run_id TEXT,
        superseding_head_sha TEXT NOT NULL CHECK (length(superseding_head_sha) = 40),
        superseded_state_version INTEGER NOT NULL CHECK (
            superseded_state_version >= 1
        ),
        PRIMARY KEY (
            tenant_id, superseded_run_id, superseded_state_version
        )
    )""",
)


__all__ = ["SCM_STATE_SCHEMA_STATEMENTS"]
