"""P5.10 fork and untrusted contributor launch policy contracts."""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
from typing import Any

from securecode_ai.adapters.github_app import GithubAppAdapter, GithubWebhookDelivery
from securecode_ai.adapters.untrusted_contribution import (
    ContributionTrust,
    CredentialInventoryAttestation,
    SCMContributionLaunchPublisher,
    SCMContributionLaunchRequest,
    TrustedSCMContributionMetadata,
    WorkerEgressPolicy,
    WorkerLaunchDenial,
    WorkerLaunchDisposition,
)
from securecode_ai.core.scm_run_state import SCMRunState

ROOT = Path(__file__).resolve().parents[2]
SECRET = b"untrusted-contribution-webhook-secret"
HEAD = "a" * 40
BASE = "b" * 40
NEW_HEAD = "c" * 40
HASH = "d" * 64


def _fixture() -> Any:
    path = ROOT / "tests" / "unit" / "test_ci_worker.py"
    spec = importlib.util.spec_from_file_location("p510_worker_fixture", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("P5.1 fixture unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _inventory(*, canary: bool = False) -> CredentialInventoryAttestation:
    return CredentialInventoryAttestation(
        inventory_sha256=HASH,
        scm_write_credentials_present=False,
        backend_credentials_present=False,
        provider_credentials_present=False,
        deployment_credentials_present=False,
        secret_canary_present=canary,
        unknown_credential_present=False,
    )


def _metadata(
    *,
    fork: bool = False,
    trusted: bool = True,
    known: bool = True,
    base_sha: str = BASE,
    head_sha: str = HEAD,
) -> TrustedSCMContributionMetadata:
    return TrustedSCMContributionMetadata(
        tenant_id="tenant-1",
        base_repository_id="repo-1",
        head_repository_id="fork-repo" if fork else "repo-1",
        base_sha=base_sha,
        head_sha=head_sha,
        is_fork=fork,
        contributor_metadata_known=known,
        contributor_trusted=trusted,
    )


def _admit(identity: Any) -> tuple[GithubAppAdapter, str, dict[str, str]]:
    source = {"head": HEAD}
    adapter = GithubAppAdapter(
        webhook_secret=SECRET,
        run_state=SCMRunState(),
        head_resolver=lambda _installation, _repository: source["head"],
    )
    raw = json.dumps(
        {
            "action": "synchronize",
            "installation": {"id": "installation-1"},
            "repository": {"id": identity.repository_revision.repository_id},
            "pull_request": {"head": {"sha": HEAD}},
        },
        separators=(",", ":"),
    ).encode()
    receipt = adapter.receive(
        GithubWebhookDelivery(
            delivery_id="delivery-1",
            event="pull_request",
            signature_sha256="sha256=" + hmac.new(SECRET, raw, hashlib.sha256).hexdigest(),
            raw_body=raw,
            execution_identity=identity,
        )
    )
    return adapter, receipt.admission.run_id, source


def _request(
    run_id: str,
    identity: Any,
    *,
    metadata: TrustedSCMContributionMetadata | None = None,
    inventory: CredentialInventoryAttestation | None = None,
    publication: bool = False,
) -> SCMContributionLaunchRequest:
    return SCMContributionLaunchRequest(
        scm_run_id=run_id,
        execution_identity=identity,
        scm_metadata=metadata or _metadata(),
        credential_inventory=inventory or _inventory(),
        requests_scm_publication=publication,
    )


def test_fork_isolated_launch_has_no_credentials_or_host_access() -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)

    receipt = SCMContributionLaunchPublisher(adapter).project(
        _request(run_id, identity, metadata=_metadata(fork=True, trusted=False))
    )

    assert receipt.disposition is WorkerLaunchDisposition.CREATED
    assert receipt.trust is ContributionTrust.UNTRUSTED_FORK
    assert receipt.projection is not None
    projection = receipt.projection
    assert projection.egress_policy is WorkerEgressPolicy.AIR_GAPPED
    assert projection.read_only_checkout
    assert projection.isolated_scratch
    assert not projection.credentials_available
    assert not projection.scm_write_authority
    assert not projection.backend_authority
    assert not projection.provider_authority
    assert not projection.deployment_authority
    assert not projection.docker_socket_mounted
    assert not projection.host_network
    assert not projection.parent_namespaces_shared
    assert not projection.arbitrary_mounts
    assert not receipt.source_disclosed
    assert not receipt.credentials_disclosed


def test_same_repository_trusted_launch_is_least_privilege_and_idempotent() -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)
    publisher = SCMContributionLaunchPublisher(adapter)
    request = _request(run_id, identity)

    first = publisher.project(request)
    duplicate = publisher.project(request)

    assert first.trust is ContributionTrust.TRUSTED_SAME_REPOSITORY
    assert first.disposition is WorkerLaunchDisposition.CREATED
    assert duplicate.disposition is WorkerLaunchDisposition.IDEMPOTENT
    assert first.projection is not None
    assert not first.projection.credentials_available
    assert first.projection.environment == tuple(
        sorted(first.projection.environment, key=lambda item: item.name)
    )


def test_unknown_metadata_canary_and_publication_request_are_denied_before_launch() -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)
    publisher = SCMContributionLaunchPublisher(adapter)

    unknown = publisher.project(_request(run_id, identity, metadata=_metadata(known=False)))
    canary = publisher.project(_request(run_id, identity, inventory=_inventory(canary=True)))
    publication = publisher.project(_request(run_id, identity, publication=True))

    assert unknown.denial is WorkerLaunchDenial.UNKNOWN_TRUST
    assert canary.denial is WorkerLaunchDenial.CREDENTIAL_INVENTORY_FAILED
    assert publication.denial is WorkerLaunchDenial.SCM_PUBLICATION_FORBIDDEN
    assert all(item.projection is None for item in (unknown, canary, publication))


def test_identity_mismatch_and_stale_head_deny_launch() -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, source = _admit(identity)
    publisher = SCMContributionLaunchPublisher(adapter)

    mismatch = publisher.project(_request(run_id, identity, metadata=_metadata(base_sha="e" * 40)))
    source["head"] = NEW_HEAD
    stale = publisher.project(_request(run_id, identity))

    assert mismatch.denial is WorkerLaunchDenial.IDENTITY_MISMATCH
    assert stale.disposition is WorkerLaunchDisposition.SUPERSEDED
    assert stale.projection is None


def test_divergent_trust_metadata_conflicts_for_one_run_identity() -> None:
    identity = _fixture()._admitted_run().execution_identity
    adapter, run_id, _ = _admit(identity)
    publisher = SCMContributionLaunchPublisher(adapter)

    created = publisher.project(_request(run_id, identity))
    conflict = publisher.project(_request(run_id, identity, metadata=_metadata(trusted=False)))

    assert created.disposition is WorkerLaunchDisposition.CREATED
    assert conflict.disposition is WorkerLaunchDisposition.CONFLICT
    assert conflict.projection is None
