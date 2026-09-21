"""Restart-safe publication after a connected worker reaches terminal state."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from typing import cast

from securecode_ai.contracts import AuditRunOutcome
from securecode_ai.core.scm_run_state import (
    PublicationDisposition,
    SCMRunPublicationReceipt,
    SCMRunStateError,
    SCMRunStateErrorCode,
)

from .ports import (
    ControlPlaneService,
    ServiceRequest,
    ServiceResponse,
    ServiceUnavailableError,
)
from .scm_completion_models import (
    GitHubCheckWriterPort,
    GithubHeadResolver,
    GitlabHeadResolver,
    GitlabStatusWriterPort,
    SCMCompletionDisposition,
    SCMCompletionError,
    SCMCompletionReceipt,
    SCMPublicationStorePort,
    SCMRunStateCompletionPort,
    audit_outcome,
    github_projection,
    gitlab_projection,
    gitlab_target,
    receipt_id,
    validate_head,
)
from .scm_publication_store import SCMPublicationTarget


class SCMCompletionPublicationService:
    """Publish one advisory provider status for an exact durable run binding."""

    __slots__ = (
        "_github_head",
        "_github_writer",
        "_gitlab_head",
        "_gitlab_writer",
        "_publications",
        "_run_state",
    )

    def __init__(
        self,
        *,
        publications: SCMPublicationStorePort,
        run_state: SCMRunStateCompletionPort,
        github_head: GithubHeadResolver | None = None,
        github_writer: GitHubCheckWriterPort | None = None,
        gitlab_head: GitlabHeadResolver | None = None,
        gitlab_writer: GitlabStatusWriterPort | None = None,
    ) -> None:
        if (
            publications is None
            or run_state is None
            or (github_head is None) is not (github_writer is None)
            or (gitlab_head is None) is not (gitlab_writer is None)
            or (github_head is not None and not callable(github_head))
            or (gitlab_head is not None and not callable(gitlab_head))
        ):
            raise TypeError("SCM completion dependency is missing")
        self._publications = publications
        self._run_state = run_state
        self._github_head = github_head
        self._github_writer = github_writer
        self._gitlab_head = gitlab_head
        self._gitlab_writer = gitlab_writer

    def publish_if_bound(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
        worker_outcome: object,
    ) -> SCMCompletionReceipt:
        """Finish SCM state and publish, or replay the durable result."""

        try:
            target = self._publications.load(tenant_id=tenant_id, run_id=run_id)
        except Exception:
            raise SCMCompletionError("SCM publication state is unavailable") from None
        if target is None:
            recovered = self._recover_target(
                tenant_id=tenant_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                worker_outcome=worker_outcome,
            )
            if recovered is None:
                return SCMCompletionReceipt(
                    run_id,
                    SCMCompletionDisposition.NOT_BOUND,
                    None,
                    None,
                )
            target, publication = recovered
            outcome = audit_outcome(worker_outcome)
        else:
            publication = None
            outcome = audit_outcome(worker_outcome)
        self._require_binding(target, execution_identity_hash)
        replay = self._replay(target, outcome)
        if replay is not None:
            if target.publication_state == "PUBLISHED":
                replay_head = self._current_head(target)
                if replay_head != target.head_sha:
                    self._confirm_superseded(target, replay_head)
                    return self._stale_replay(target)
            return replay

        current_head = (
            publication.current_head_sha if publication is not None else self._current_head(target)
        )
        if publication is None:
            publication = self._complete_state(target, outcome, current_head)
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            return self._record_stale(target)
        self._require_completed(publication, target, outcome, current_head)

        write_status, observed_head = self._publish(target, outcome)
        if write_status == "STALE":
            stale_head = observed_head or self._current_head(target)
            self._confirm_superseded(target, stale_head)
            return self._record_stale(target)
        if write_status != "WRITTEN":
            raise SCMCompletionError("SCM publication failed")
        persisted_head = self._current_head(target)
        if persisted_head != target.head_sha:
            self._confirm_superseded(target, persisted_head)
            return self._record_stale(target)
        return self._record_published(target, outcome)

    def _recover_target(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
        worker_outcome: object,
    ) -> tuple[SCMPublicationTarget, SCMRunPublicationReceipt] | None:
        try:
            provider_target = self._run_state.provider_target(run_id)
        except SCMRunStateError as error:
            if error.code is SCMRunStateErrorCode.RUN_UNKNOWN:
                return None
            raise SCMCompletionError("SCM run binding is unavailable") from None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise SCMCompletionError("SCM run binding is unavailable") from None
        provider = getattr(provider_target, "provider", None)
        installation_id = getattr(provider_target, "installation_id", None)
        repository_id = getattr(provider_target, "repository_id", None)
        change_id = getattr(provider_target, "change_id", None)
        bound_identity = getattr(provider_target, "execution_identity_hash", None)
        if (
            provider not in {"github", "gitlab"}
            or any(type(value) is not str for value in (installation_id, repository_id, change_id))
            or bound_identity != execution_identity_hash
        ):
            raise SCMCompletionError("SCM run binding conflicts")
        installation_id = cast(str, installation_id)
        repository_id = cast(str, repository_id)
        change_id = cast(str, change_id)
        outcome = audit_outcome(worker_outcome)
        provisional = SCMPublicationTarget(
            tenant_id=tenant_id,
            run_id=run_id,
            provider=provider,
            installation_id=installation_id,
            repository_id=repository_id,
            change_id=change_id,
            head_sha="0" * 40,
            execution_identity_hash=execution_identity_hash,
        )
        current_head = self._current_head(provisional)
        publication = self._complete_state(provisional, outcome, current_head)
        target = SCMPublicationTarget(
            tenant_id=tenant_id,
            run_id=run_id,
            provider=provider,
            installation_id=installation_id,
            repository_id=repository_id,
            change_id=change_id,
            head_sha=publication.head_sha,
            execution_identity_hash=execution_identity_hash,
        )
        try:
            self._publications.bind(target)
        except Exception:
            raise SCMCompletionError("SCM publication target was not stored") from None
        return target, publication

    def _current_head(self, target: SCMPublicationTarget) -> str:
        try:
            if target.provider == "github":
                if self._github_head is None:
                    raise SCMCompletionError("SCM provider is not configured")
                value = self._github_head(
                    target.installation_id,
                    target.repository_id,
                    target.change_id,
                )
            elif target.provider == "gitlab":
                if self._gitlab_head is None:
                    raise SCMCompletionError("SCM provider is not configured")
                value = self._gitlab_head(target.repository_id, target.change_id)
            else:
                raise SCMCompletionError("SCM publication target is invalid")
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except SCMCompletionError:
            raise
        except Exception:
            raise SCMCompletionError("SCM current head is unavailable") from None
        return validate_head(value)

    def _complete_state(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
        current_head: str,
    ) -> SCMRunPublicationReceipt:
        try:
            if outcome is AuditRunOutcome.SUPERSEDED:
                publication = self._run_state.authorize_publication(
                    target.run_id,
                    current_head_sha=current_head,
                )
                if publication.disposition is not PublicationDisposition.SUPERSEDED:
                    raise SCMCompletionError("SCM supersession is not current")
                return publication
            return self._run_state.complete(
                target.run_id,
                outcome,
                current_head_sha=current_head,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except SCMCompletionError:
            raise
        except Exception:
            raise SCMCompletionError("SCM run completion failed") from None

    def _publish(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
    ) -> tuple[str, str | None]:
        identifier = receipt_id(target)
        try:
            if target.provider == "github":
                if self._github_writer is None:
                    raise SCMCompletionError("SCM provider is not configured")
                receipt = self._github_writer.write_pull_request_check(
                    installation_id=target.installation_id,
                    repository_id=target.repository_id,
                    change_id=target.change_id,
                    expected_head=target.head_sha,
                    external_id=identifier,
                    projection=github_projection(target, outcome),
                    delivery_key=identifier,
                )
                status = _attribute_value(receipt, "status")
                if status == "WRITTEN":
                    _github_remote_check_id(receipt)
                    return "WRITTEN", None
                if status == "STALE_SUPPRESSED":
                    return "STALE", None
                return "FAILED", None
            if self._gitlab_writer is None:
                raise SCMCompletionError("SCM provider is not configured")
            receipt = self._gitlab_writer.publish_external_status(
                gitlab_target(target),
                gitlab_projection(target, outcome),
            )
            status = _attribute_value(receipt, "status")
            if status in {"SUCCEEDED", "IDEMPOTENT"}:
                return "WRITTEN", None
            if status == "STALE":
                observed = getattr(receipt, "observed_head_sha", None)
                return "STALE", validate_head(observed)
            return "FAILED", None
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except SCMCompletionError:
            raise
        except Exception:
            raise SCMCompletionError("SCM publication failed") from None

    def _confirm_superseded(
        self,
        target: SCMPublicationTarget,
        current_head: str,
    ) -> None:
        if current_head == target.head_sha:
            raise SCMCompletionError("SCM stale publication is inconsistent")
        try:
            receipt = self._run_state.authorize_publication(
                target.run_id,
                current_head_sha=current_head,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise SCMCompletionError("SCM supersession failed") from None
        if (
            receipt.disposition is not PublicationDisposition.SUPERSEDED
            or receipt.current_head_sha != current_head
            or receipt.head_sha != target.head_sha
            or receipt.execution_identity_hash != target.execution_identity_hash
        ):
            raise SCMCompletionError("SCM supersession failed")

    def _record_stale(self, target: SCMPublicationTarget) -> SCMCompletionReceipt:
        identifier = receipt_id(target)
        self._record(
            target,
            outcome=AuditRunOutcome.SUPERSEDED,
            stale=True,
            identifier=identifier,
        )
        return SCMCompletionReceipt(
            target.run_id,
            SCMCompletionDisposition.STALE,
            AuditRunOutcome.SUPERSEDED,
            identifier,
        )

    @staticmethod
    def _stale_replay(target: SCMPublicationTarget) -> SCMCompletionReceipt:
        return SCMCompletionReceipt(
            target.run_id,
            SCMCompletionDisposition.STALE,
            AuditRunOutcome.SUPERSEDED,
            target.receipt_id,
        )

    def _record_published(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
    ) -> SCMCompletionReceipt:
        identifier = receipt_id(target)
        self._record(target, outcome=outcome, stale=False, identifier=identifier)
        return SCMCompletionReceipt(
            target.run_id,
            SCMCompletionDisposition.PUBLISHED,
            outcome,
            identifier,
        )

    def _record(
        self,
        target: SCMPublicationTarget,
        *,
        outcome: AuditRunOutcome,
        stale: bool,
        identifier: str,
    ) -> None:
        try:
            stored = self._publications.record(
                target=target,
                outcome=outcome.value,
                stale=stale,
                receipt_id=identifier,
            )
        except Exception:
            raise SCMCompletionError("SCM publication receipt was not stored") from None
        expected_state = "STALE" if stale else "PUBLISHED"
        if (
            stored.publication_state != expected_state
            or stored.outcome != outcome.value
            or stored.receipt_id != identifier
        ):
            raise SCMCompletionError("SCM publication receipt conflicts")

    @staticmethod
    def _require_binding(
        target: SCMPublicationTarget,
        execution_identity_hash: str,
    ) -> None:
        if target.execution_identity_hash != execution_identity_hash:
            raise SCMCompletionError("SCM completion identity conflicts")

    @staticmethod
    def _replay(
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
    ) -> SCMCompletionReceipt | None:
        if target.publication_state == "PENDING":
            return None
        if target.publication_state == "PUBLISHED":
            expected = outcome
        elif target.publication_state == "STALE":
            expected = AuditRunOutcome.SUPERSEDED
        else:
            raise SCMCompletionError("SCM publication state is invalid")
        if target.outcome != expected.value or target.receipt_id != receipt_id(target):
            raise SCMCompletionError("SCM publication receipt conflicts")
        return SCMCompletionReceipt(
            target.run_id,
            SCMCompletionDisposition.REPLAYED,
            expected,
            target.receipt_id,
        )

    @staticmethod
    def _require_completed(
        receipt: SCMRunPublicationReceipt,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
        current_head: str,
    ) -> None:
        if (
            receipt.disposition
            not in {PublicationDisposition.COMPLETED, PublicationDisposition.DUPLICATE}
            or receipt.run_id != target.run_id
            or receipt.execution_identity_hash != target.execution_identity_hash
            or receipt.head_sha != target.head_sha
            or receipt.current_head_sha != current_head
            or current_head != target.head_sha
            or receipt.outcome is not outcome
        ):
            raise SCMCompletionError("SCM run completion conflicts")


class SCMCompletionPublicationHandler:
    """Attach SCM publication to an idempotent worker completion handler."""

    __slots__ = ("_fallback", "_publisher")

    def __init__(
        self,
        *,
        publisher: SCMCompletionPublicationService,
        fallback: ControlPlaneService,
    ) -> None:
        if not isinstance(publisher, SCMCompletionPublicationService) or not hasattr(
            fallback, "dispatch"
        ):
            raise TypeError("SCM completion handler dependencies are invalid")
        self._publisher = publisher
        self._fallback = fallback

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        response = await self._fallback.dispatch(request)
        terminal = _terminal_request(request)
        if terminal is None or not _successful_terminal_response(response, terminal[0]):
            return response
        run_id, execution_identity_hash, outcome = terminal
        try:
            self._publisher.publish_if_bound(
                tenant_id=request.identity.tenant_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                worker_outcome=outcome,
            )
        except SCMCompletionError:
            raise ServiceUnavailableError() from None
        except Exception:
            raise ServiceUnavailableError() from None
        return response


def _terminal_request(request: ServiceRequest) -> tuple[str, str, str] | None:
    if request.action != "worker_sessions.complete":
        return None
    document = request.document
    if not isinstance(document, Mapping):
        return None
    run_id = document.get("run_id")
    identity_hash = document.get("execution_identity_hash")
    outcome = document.get("outcome")
    if not all(type(value) is str and value for value in (run_id, identity_hash, outcome)):
        return None
    return cast(str, run_id), cast(str, identity_hash), cast(str, outcome)


def _successful_terminal_response(response: ServiceResponse, run_id: str) -> bool:
    return (
        response.status == 200
        and response.document.get("terminal") is True
        and response.document.get("run_id") == run_id
    )


def _attribute_value(value: object, name: str) -> str:
    attribute = getattr(value, name, None)
    if isinstance(attribute, StrEnum):
        return attribute.value
    if type(attribute) is str:
        return attribute
    raise SCMCompletionError("SCM writer receipt is invalid")


def _github_remote_check_id(value: object) -> str:
    identifier = getattr(value, "remote_check_id", None)
    if (
        type(identifier) is not str
        or not identifier.isascii()
        or not identifier.isdecimal()
        or identifier.startswith("0")
        or len(identifier) > 20
    ):
        raise SCMCompletionError("SCM writer receipt is invalid")
    return identifier


__all__ = [
    "SCMCompletionPublicationHandler",
    "SCMCompletionPublicationService",
]
