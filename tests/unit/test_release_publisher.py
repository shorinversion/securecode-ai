"""P9.9 immutable release publication boundary contracts."""

from __future__ import annotations

from securecode_ai.core.release_candidate import ReleaseArtifact, ReleaseCandidate
from securecode_ai.core.release_publisher import (
    AuthorizedPublishRequest,
    PublishAuthorization,
    ReleasePublishDisposition,
    ReleasePublisher,
    RemoteRelease,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64
HASH_F = "f" * 64


def _candidate() -> ReleaseCandidate:
    return ReleaseCandidate.build(
        version="v1.0.0",
        source_tree_sha256=HASH_A,
        closure_activation_sha256=HASH_B,
        sbom_sha256=HASH_C,
        provenance_sha256=HASH_D,
        checksums_sha256=HASH_E,
        server_image_digest=HASH_F,
        worker_image_digest=HASH_A,
        artifacts=(ReleaseArtifact("bundle-1", HASH_B, HASH_C),),
        release_signature_sha256=HASH_D,
    )


class _Provider:
    def __init__(self, existing: RemoteRelease | None = None, *, partial: bool = False) -> None:
        self.existing = existing
        self.partial = partial
        self.created = 0

    def get_tag(
        self,
        _tag: str,
        authorization: PublishAuthorization | None = None,
    ) -> RemoteRelease | None:
        assert authorization is not None
        return self.existing

    def create_release(self, request: AuthorizedPublishRequest) -> RemoteRelease:
        self.created += 1
        plan = request.plan
        return RemoteRelease(
            plan.tag,
            "remote-1",
            plan.candidate_sha256,
            plan.artifact_checksums if not self.partial else (),
            not self.partial,
        )


def _authorized(
    publisher: ReleasePublisher, candidate: ReleaseCandidate
) -> AuthorizedPublishRequest:
    plan = publisher.dry_run(candidate)
    return AuthorizedPublishRequest(
        plan,
        PublishAuthorization(
            "release-auth-1",
            "PUBLISH",
            "release-authorizer",
            plan.candidate_sha256,
            4_000_000_000,
            "release-key-1",
            "publish-nonce-0001",
            HASH_F,
            HASH_E,
        ),
    )


def test_dry_run_and_explicit_authorized_publish_bind_every_immutable_release_field() -> None:
    candidate = _candidate()
    provider = _Provider()
    publisher = ReleasePublisher(provider)
    receipt = publisher.publish(_authorized(publisher, candidate))

    assert receipt.disposition is ReleasePublishDisposition.PUBLISHED
    assert receipt.remote_candidate_sha256 == candidate.candidate_sha256
    assert receipt.artifact_checksums == (HASH_B,)
    assert provider.created == 1
    assert not receipt.source_disclosed


def test_existing_exact_tag_is_idempotent_and_divergent_tag_never_overwrites() -> None:
    candidate = _candidate()
    publisher = ReleasePublisher(_Provider())
    request = _authorized(publisher, candidate)
    exact = RemoteRelease(
        request.plan.tag,
        "remote-1",
        request.plan.candidate_sha256,
        request.plan.artifact_checksums,
        True,
    )
    idempotent = ReleasePublisher(_Provider(exact)).publish(request)
    conflict = ReleasePublisher(
        _Provider(
            RemoteRelease(
                request.plan.tag, "remote-2", HASH_A, request.plan.artifact_checksums, True
            )
        )
    ).publish(request)

    assert idempotent.disposition is ReleasePublishDisposition.IDEMPOTENT
    assert conflict.disposition is ReleasePublishDisposition.CONFLICT


def test_partial_remote_publication_is_error_not_success() -> None:
    candidate = _candidate()
    publisher = ReleasePublisher(_Provider(partial=True))

    receipt = publisher.publish(_authorized(publisher, candidate))

    assert receipt.disposition is ReleasePublishDisposition.ERROR
