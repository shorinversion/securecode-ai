"""P5.5 authenticated GitHub webhook and exact-SHA admission contracts."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field

import pytest
from securecode_ai.adapters.github_app import (
    GITHUB_APP_OPTIONAL_PERMISSIONS,
    GITHUB_APP_REQUIRED_PERMISSIONS,
    GithubAppAdapter,
    GithubAppError,
    GithubAppErrorCode,
    GithubWebhookDelivery,
    github_app_permissions,
)
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AuditRunOutcome,
    ComponentPin,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core.scm_run_state import (
    AdmissionDisposition,
    PublicationDisposition,
    SCMRunState,
)

HEAD_A = "a" * 40
HEAD_B = "b" * 40
HASH = "c" * 64
SECRET = b"unit-webhook-secret"


@dataclass
class HeadResolver:
    current_head: str = HEAD_A
    calls: list[tuple[str, str]] = field(default_factory=list)

    def __call__(self, installation_id: str, repository_id: str) -> str:
        self.calls.append((installation_id, repository_id))
        return self.current_head


def _identity(*, head_sha: str = HEAD_A) -> RunExecutionIdentity:
    component = ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id="component",
        component_version="1.0.0",
        content_sha256=HASH,
    )
    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            scm_provider="github",
            repository_id="repository-1",
            head_sha=head_sha,
        ),
        stage_catalogue=component,
        workflow=component,
        policy=component,
        configuration=component,
        provider_profile=component,
        capability_profile=component,
        egress_profile=component,
    )


def _body(*, head_sha: str = HEAD_A, repository_id: str = "repository-1") -> bytes:
    return json.dumps(
        {
            "action": "synchronize",
            "installation": {"id": "installation-1"},
            "repository": {"id": repository_id},
            "pull_request": {"head": {"sha": head_sha}},
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _delivery(
    delivery_id: str = "delivery-1",
    *,
    body: bytes | None = None,
    identity: RunExecutionIdentity | None = None,
    signature: str | None = None,
) -> GithubWebhookDelivery:
    raw_body = body or _body()
    computed_signature = "sha256=" + hmac.new(SECRET, raw_body, hashlib.sha256).hexdigest()
    return GithubWebhookDelivery(
        delivery_id=delivery_id,
        event="pull_request",
        signature_sha256=signature or computed_signature,
        raw_body=raw_body,
        execution_identity=identity or _identity(),
    )


def _adapter(resolver: HeadResolver | None = None) -> tuple[GithubAppAdapter, HeadResolver]:
    selected = resolver or HeadResolver()
    return (
        GithubAppAdapter(
            webhook_secret=SECRET,
            run_state=SCMRunState(),
            head_resolver=selected,
        ),
        selected,
    )


def test_signed_delivery_admits_one_exact_sha_run_and_replay_is_idempotent() -> None:
    adapter, resolver = _adapter()
    delivery = _delivery()

    first = adapter.receive(delivery)
    duplicate = adapter.receive(delivery)

    assert first.admission.disposition is AdmissionDisposition.ADMITTED
    assert duplicate.admission.disposition is AdmissionDisposition.DUPLICATE
    assert duplicate.admission.run_id == first.admission.run_id
    assert resolver.calls == [("installation-1", "repository-1")] * 2


def test_invalid_raw_signature_does_not_parse_or_resolve_head() -> None:
    adapter, resolver = _adapter()
    delivery = _delivery(signature="sha256=" + "0" * 64)

    with pytest.raises(GithubAppError) as error:
        adapter.receive(delivery)

    assert error.value.code is GithubAppErrorCode.AUTHENTICATION_FAILED
    assert resolver.calls == []


def test_signed_delivery_replay_with_different_bytes_fails_closed() -> None:
    adapter, _ = _adapter()
    adapter.receive(_delivery())
    # Same delivery ID and identity, but different signed bytes: the durable run
    # state binds the delivery digest and must reject the replay.
    replay_body = _body().replace(b'"synchronize"', b'"opened"')

    with pytest.raises(GithubAppError) as error:
        adapter.receive(_delivery(body=replay_body))

    assert error.value.code is GithubAppErrorCode.STATE_REJECTED

    with pytest.raises(GithubAppError) as mismatch:
        adapter.receive(_delivery(body=_body(head_sha=HEAD_B)))

    assert mismatch.value.code is GithubAppErrorCode.IDENTITY_MISMATCH


def test_signed_payload_identity_mismatch_never_reaches_head_resolver() -> None:
    adapter, resolver = _adapter()
    delivery = _delivery(body=_body(repository_id="repository-other"))

    with pytest.raises(GithubAppError) as error:
        adapter.receive(delivery)

    assert error.value.code is GithubAppErrorCode.IDENTITY_MISMATCH
    assert resolver.calls == []


def test_ref_move_returns_superseded_without_admitting_a_run() -> None:
    adapter, _ = _adapter(HeadResolver(current_head=HEAD_B))

    receipt = adapter.receive(_delivery())

    assert receipt.admission.disposition is AdmissionDisposition.SUPERSEDED
    with pytest.raises(GithubAppError) as error:
        adapter.authorize_publication(receipt.admission.run_id)
    assert error.value.code is GithubAppErrorCode.RUN_UNKNOWN


def test_publication_refreshes_trusted_head_and_supersedes_late_result() -> None:
    resolver = HeadResolver()
    adapter, _ = _adapter(resolver)
    receipt = adapter.receive(_delivery())
    resolver.current_head = HEAD_B

    completed = adapter.complete(receipt.admission.run_id, AuditRunOutcome.PASS)

    assert completed.disposition is PublicationDisposition.SUPERSEDED


def test_permission_manifest_exposes_optional_sarif_capability_separately() -> None:
    default = github_app_permissions()
    sarif = github_app_permissions(enable_sarif=True)

    assert default == GITHUB_APP_REQUIRED_PERMISSIONS
    assert "security_events" not in default
    assert sarif == {**GITHUB_APP_REQUIRED_PERMISSIONS, **GITHUB_APP_OPTIONAL_PERMISSIONS}
