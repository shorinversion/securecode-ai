"""P6.6 session and capability binding controls."""

from __future__ import annotations

import pytest
from securecode_ai.server.identity import Principal, Role
from securecode_ai.server.sessions import SessionError, SessionStore


def test_role_and_repository_grants_are_least_privilege() -> None:
    principal = Principal("user", "tenant", frozenset({Role.AUDITOR}), frozenset({"repo"}))
    assert principal.allows(action="runs.create", repository_id="repo")
    assert not principal.allows(action="runs.create", repository_id="other")
    assert not principal.allows(action="worker_sessions.complete", repository_id="repo")


def test_capability_is_hash_stored_single_use_and_identity_bound() -> None:
    store = SessionStore()
    principal = Principal("worker", "tenant", frozenset({Role.WORKER}), frozenset({"repo"}))
    token, receipt = store.issue_capability(
        principal,
        repository_id="repo",
        run_id="run",
        action="worker_sessions.complete",
        execution_identity_hash="a" * 64,
    )
    assert token not in repr(receipt)
    assert (
        store.consume_capability(
            token,
            tenant_id="tenant",
            repository_id="repo",
            run_id="run",
            action="worker_sessions.complete",
            execution_identity_hash="a" * 64,
        )
        == receipt
    )
    with pytest.raises(SessionError):
        store.consume_capability(
            token,
            tenant_id="tenant",
            repository_id="repo",
            run_id="run",
            action="worker_sessions.complete",
            execution_identity_hash="a" * 64,
        )
