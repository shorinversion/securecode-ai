"""Focused P6.2 persistence contracts; execution is deferred by the code-first plan."""

from __future__ import annotations

import hashlib

import pytest
from securecode_ai.server.persistence import (
    ConflictError,
    DevelopmentRepository,
    NotFoundError,
    PreconditionError,
    StoredResponse,
)

TENANT = "tenant-a"
RUN = "run-a"
REPOSITORY = "repository-a"
BASE = "a" * 40
HEAD = "b" * 40
IDENTITY = "c" * 64
REQUEST = "d" * 64


def _create(
    repository: DevelopmentRepository,
    *,
    key: str = "key-0001",
    digest: str = REQUEST,
) -> StoredResponse:
    return repository.create_run(
        tenant_id=TENANT,
        run_id=RUN,
        repository_id=REPOSITORY,
        execution_identity_hash=IDENTITY,
        base_sha=BASE,
        head_sha=HEAD,
        metadata={"policy_id": "policy-a"},
        idempotency_key=key,
        request_sha256=digest,
    )


def test_exact_idempotency_replay_returns_the_original_response_once() -> None:
    repository = DevelopmentRepository.in_memory()
    first = _create(repository)
    replay = _create(repository)

    assert first == replay
    assert first.status == 201
    assert repository.get_run(TENANT, RUN)["execution_identity_hash"] == IDENTITY


def test_divergent_idempotency_key_conflicts_without_cross_tenant_lookup() -> None:
    repository = DevelopmentRepository.in_memory()
    _create(repository)

    with pytest.raises(ConflictError):
        _create(repository, digest=hashlib.sha256(b"different").hexdigest())
    with pytest.raises(NotFoundError):
        repository.get_run("tenant-b", RUN)


def test_cancel_binds_tenant_and_exact_version_precondition() -> None:
    repository = DevelopmentRepository.in_memory()
    _create(repository)

    with pytest.raises(PreconditionError):
        repository.cancel_run(
            tenant_id=TENANT,
            run_id=RUN,
            precondition=2,
            idempotency_key="key-0002",
            request_sha256="e" * 64,
        )
    result = repository.cancel_run(
        tenant_id=TENANT,
        run_id=RUN,
        precondition=1,
        idempotency_key="key-0002",
        request_sha256="e" * 64,
    )

    assert result.status == 202
    assert result.document["state"] == "CANCEL_REQUESTED"
    assert result.document["version"] == 2


def test_empty_lists_are_source_free_and_have_opaque_cursor_shape() -> None:
    repository = DevelopmentRepository.in_memory()
    _create(repository)

    events = repository.list_events(TENANT, RUN, None, 50)
    findings = repository.list_findings(TENANT, RUN, None, 50)

    assert events == {"items": [], "next_cursor": None}
    assert findings == {"items": [], "next_cursor": None}
