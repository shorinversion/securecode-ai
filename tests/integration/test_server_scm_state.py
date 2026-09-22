"""P6.2/P6.3 durable SCM run state: replay, supersession, tenancy, restart."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AuditRunOutcome,
    ComponentPin,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.contracts.domain import ACCEPTED_STAGE_CATALOGUE_PIN
from securecode_ai.core.scm_run_state import (
    AdmissionDisposition,
    PublicationDisposition,
    SCMRunAdmissionRequest,
    SCMRunStateError,
    SCMRunStateErrorCode,
)
from securecode_ai.server.scm_state import SCMProviderTarget, SqliteSCMRunState

TENANT = "tenant-1"
OTHER_TENANT = "tenant-2"
REPOSITORY = "repo-1"
PROVIDER = "gitlab"
CHANGE_ID = "7"
HEAD = "a" * 40
BASE = "b" * 40
OTHER_HEAD = "c" * 40
HASH_A = "a" * 64


def _pin(name: str, digest: str) -> ComponentPin:
    if name == "catalogue":
        component_id, version, accepted = ACCEPTED_STAGE_CATALOGUE_PIN
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=component_id,
            component_version=version,
            content_sha256=accepted,
        )
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _identity(
    *,
    tenant_id: str = TENANT,
    head_sha: str = HEAD,
    base_sha: str | None = BASE,
) -> RunExecutionIdentity:
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id=tenant_id,
            scm_provider=PROVIDER,
            repository_id=REPOSITORY,
            head_sha=head_sha,
            base_sha=base_sha,
        ),
        stage_catalogue=_pin("catalogue", HASH_A),
        workflow=_pin("workflow", HASH_A),
        policy=_pin("policy", "c" * 64),
        configuration=_pin("configuration", "d" * 64),
        provider_profile=_pin("provider", "e" * 64),
        capability_profile=_pin("capability", "f" * 64),
        egress_profile=_pin("egress", "1" * 64),
    )


def _request(
    *,
    delivery_id: str = "delivery-0001",
    identity: RunExecutionIdentity | None = None,
    head_sha: str = HEAD,
) -> SCMRunAdmissionRequest:
    identity = identity or _identity(head_sha=head_sha)
    return SCMRunAdmissionRequest(
        delivery_id=delivery_id,
        installation_id=f"{PROVIDER}:{REPOSITORY}:mr:{CHANGE_ID}",
        execution_identity=identity,
        authorized_head_sha=identity.repository_revision.head_sha,
    )


def _state(
    connection: sqlite3.Connection, *, tenant_id: str = TENANT, **kwargs: object
) -> SqliteSCMRunState:
    return SqliteSCMRunState(connection, tenant_id=tenant_id, initialize=True, **kwargs)  # type: ignore[arg-type]


def _connection(path: str = ":memory:") -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    return connection


def test_configuration_is_validated() -> None:
    with pytest.raises(TypeError):
        SqliteSCMRunState("not-a-connection", tenant_id=TENANT)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SqliteSCMRunState(_connection(), tenant_id="bad tenant")
    with pytest.raises(TypeError):
        SqliteSCMRunState(_connection(), tenant_id=TENANT, max_runs=0)
    with pytest.raises(TypeError):
        SqliteSCMRunState(_connection(), tenant_id=TENANT, max_deliveries=-1)


def test_schema_install_is_idempotent() -> None:
    connection = _connection()
    SqliteSCMRunState.install_schema(connection)
    SqliteSCMRunState.install_schema(connection)
    tables = {
        row["name"]
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert any("scm" in name for name in tables)
    assert _state(connection) is not None


def test_admission_is_admitted_and_exposes_durable_target() -> None:
    state = _state(_connection())
    receipt = state.admit(_request(), current_head_sha=HEAD)
    assert receipt.disposition is AdmissionDisposition.ADMITTED
    assert receipt.head_sha == HEAD

    target = state.provider_target(receipt.run_id)
    assert isinstance(target, SCMProviderTarget)
    assert target.provider == PROVIDER
    assert target.repository_id == REPOSITORY
    assert target.change_id == CHANGE_ID
    assert target.installation_id == REPOSITORY
    assert target.change_id == CHANGE_ID
    assert target.execution_identity_hash == receipt.execution_identity_hash


def test_same_delivery_replays_its_cached_receipt() -> None:
    """A repeated delivery id returns the recorded receipt, not a new admission."""

    state = _state(_connection())
    first = state.admit(_request(), current_head_sha=HEAD)
    replay = state.admit(_request(), current_head_sha=HEAD)
    assert replay.disposition is AdmissionDisposition.ADMITTED
    assert replay.run_id == first.run_id
    assert replay.state_version == first.state_version


def test_semantic_duplicate_from_another_delivery_is_reported() -> None:
    """A new delivery describing the same run is DUPLICATE, not a second run."""

    state = _state(_connection())
    first = state.admit(_request(), current_head_sha=HEAD)
    duplicate = state.admit(_request(delivery_id="delivery-0002"), current_head_sha=HEAD)
    assert duplicate.disposition is AdmissionDisposition.DUPLICATE
    assert duplicate.run_id == first.run_id
    assert duplicate.execution_identity_hash == first.execution_identity_hash


def test_conflicting_delivery_reuse_is_rejected() -> None:
    state = _state(_connection())
    state.admit(_request(), current_head_sha=HEAD)
    with pytest.raises(SCMRunStateError) as error:
        state.admit(_request(identity=_identity(base_sha=None)), current_head_sha=HEAD)
    assert error.value.code is SCMRunStateErrorCode.DELIVERY_CONFLICT


def test_stale_head_admission_is_superseded() -> None:
    state = _state(_connection())
    receipt = state.admit(_request(), current_head_sha=OTHER_HEAD)
    assert receipt.disposition is AdmissionDisposition.SUPERSEDED
    with pytest.raises(SCMRunStateError):
        state.provider_target(receipt.run_id)


def test_authorized_publication_then_supersession_after_head_move() -> None:
    state = _state(_connection())
    run_id = state.admit(_request(), current_head_sha=HEAD).run_id
    authorized = state.authorize_publication(run_id, current_head_sha=HEAD)
    assert authorized.disposition is PublicationDisposition.AUTHORIZED
    assert authorized.current_head_sha == HEAD

    moved = state.authorize_publication(run_id, current_head_sha=OTHER_HEAD)
    assert moved.disposition is PublicationDisposition.SUPERSEDED
    assert moved.current_head_sha == OTHER_HEAD


def test_completion_records_outcome_and_replays_duplicate() -> None:
    state = _state(_connection())
    run_id = state.admit(_request(), current_head_sha=HEAD).run_id
    completed = state.complete(run_id, AuditRunOutcome.PASS, current_head_sha=HEAD)
    assert completed.disposition is PublicationDisposition.COMPLETED
    assert completed.outcome is AuditRunOutcome.PASS

    replay = state.complete(run_id, AuditRunOutcome.PASS, current_head_sha=HEAD)
    assert replay.disposition is PublicationDisposition.DUPLICATE
    assert replay.outcome is AuditRunOutcome.PASS


def test_conflicting_completion_outcome_is_rejected() -> None:
    state = _state(_connection())
    run_id = state.admit(_request(), current_head_sha=HEAD).run_id
    state.complete(run_id, AuditRunOutcome.PASS, current_head_sha=HEAD)
    with pytest.raises(SCMRunStateError):
        state.complete(run_id, AuditRunOutcome.FAIL, current_head_sha=HEAD)


def test_superseded_outcome_and_stale_completion_are_rejected() -> None:
    state = _state(_connection())
    run_id = state.admit(_request(), current_head_sha=HEAD).run_id
    with pytest.raises(SCMRunStateError):
        state.complete(run_id, AuditRunOutcome.SUPERSEDED, current_head_sha=HEAD)

    state.admit(
        _request(
            delivery_id="delivery-moved", identity=_identity(head_sha=OTHER_HEAD, base_sha=BASE)
        ),
        current_head_sha=OTHER_HEAD,
    )
    superseded = state.complete(run_id, AuditRunOutcome.PASS, current_head_sha=OTHER_HEAD)
    assert superseded.disposition is PublicationDisposition.SUPERSEDED
    assert superseded.outcome is AuditRunOutcome.SUPERSEDED

    # Supersession is terminal and idempotent: a later outcome does not reopen it.
    again = state.complete(run_id, AuditRunOutcome.FAIL, current_head_sha=OTHER_HEAD)
    assert again.disposition is PublicationDisposition.SUPERSEDED
    assert again.outcome is AuditRunOutcome.SUPERSEDED


def test_tenant_instances_are_isolated() -> None:
    connection = _connection()
    first = _state(connection, tenant_id=TENANT)
    run_id = first.admit(_request(), current_head_sha=HEAD).run_id

    other = _state(connection, tenant_id=OTHER_TENANT)
    with pytest.raises(SCMRunStateError):
        other.provider_target(run_id)
    other_run = other.admit(
        _request(delivery_id="delivery-9999", identity=_identity(tenant_id=OTHER_TENANT)),
        current_head_sha=HEAD,
    )
    assert other_run.disposition is AdmissionDisposition.ADMITTED
    assert other_run.run_id != run_id
    with pytest.raises(SCMRunStateError):
        first.provider_target(other_run.run_id)

    assert first.provider_target(run_id).repository_id == REPOSITORY


def test_state_survives_reconnect(tmp_path: Path) -> None:
    path = tmp_path / "scm-state.sqlite"
    connection = _connection(str(path))
    state = _state(connection)
    run_id = state.admit(_request(), current_head_sha=HEAD).run_id
    state.complete(run_id, AuditRunOutcome.INDETERMINATE, current_head_sha=HEAD)
    connection.close()

    reopened = _connection(str(path))
    restored = _state(reopened)
    target = restored.provider_target(run_id)
    assert target.execution_identity_hash == _identity().execution_identity_hash
    duplicate = restored.admit(_request(delivery_id="delivery-0002"), current_head_sha=HEAD)
    assert duplicate.disposition is AdmissionDisposition.DUPLICATE
    assert duplicate.run_id == run_id
    replay = restored.admit(_request(), current_head_sha=HEAD)
    assert replay.run_id == run_id
    reopened.close()


def test_run_capacity_is_fail_closed() -> None:
    state = _state(_connection(), max_runs=1)
    state.admit(_request(), current_head_sha=HEAD)
    with pytest.raises(SCMRunStateError):
        state.admit(
            _request(delivery_id="delivery-0002", identity=_identity(base_sha=None)),
            current_head_sha=HEAD,
        )


def test_unknown_run_reports_run_unknown() -> None:
    state = _state(_connection())
    with pytest.raises(SCMRunStateError) as error:
        state.provider_target("scm-run-unknown")
    assert error.value.code is SCMRunStateErrorCode.RUN_UNKNOWN
