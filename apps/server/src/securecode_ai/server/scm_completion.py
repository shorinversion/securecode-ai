"""Restart-safe publication after a connected worker reaches terminal state."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from enum import StrEnum
from typing import cast

from securecode_ai.adapters.github_annotations import GithubAnnotationReceipt
from securecode_ai.contracts import AuditRunOutcome
from securecode_ai.core.scm_policy import ScmPolicyDecision, ScmPolicyEnforcement, ScmPolicyMode
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
    GithubAnnotationReceiptResolver,
    GitHubCheckWriterPort,
    GitHubCommentWriterPort,
    GithubHeadResolver,
    GithubSarifArtifactResolver,
    GithubSarifWriterPort,
    GitlabHeadResolver,
    GitlabStatusWriterPort,
    GitlabTerminalPublication,
    GitlabTerminalPublicationResolver,
    PolicyDecisionResolver,
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
    scm_publication_outcome,
    validate_head,
)
from .scm_publication_store import SCMPublicationTarget


class SCMCompletionPublicationService:
    """Publish one policy-evaluated provider status for an exact durable run binding."""

    __slots__ = (
        "_github_annotation_receipt",
        "_github_comment_writer",
        "_github_head",
        "_github_sarif_artifact",
        "_github_sarif_writer",
        "_github_writer",
        "_gitlab_head",
        "_gitlab_terminal_publication",
        "_gitlab_writer",
        "_policy_decisions",
        "_publications",
        "_run_state",
        "_waiver_exception_resolver",
        "_waiver_revision_resolver",
    )

    def __init__(
        self,
        *,
        publications: SCMPublicationStorePort,
        run_state: SCMRunStateCompletionPort,
        github_head: GithubHeadResolver | None = None,
        github_writer: GitHubCheckWriterPort | None = None,
        github_comment_writer: GitHubCommentWriterPort | None = None,
        github_annotation_receipt: GithubAnnotationReceiptResolver | None = None,
        github_sarif_writer: GithubSarifWriterPort | None = None,
        github_sarif_artifact: GithubSarifArtifactResolver | None = None,
        gitlab_head: GitlabHeadResolver | None = None,
        gitlab_writer: GitlabStatusWriterPort | None = None,
        gitlab_terminal_publication: GitlabTerminalPublicationResolver | None = None,
        policy_decisions: PolicyDecisionResolver | None = None,
        waiver_exception_resolver: Callable[[str, str, str, ScmPolicyDecision], bool] | None = None,
        waiver_revision_resolver: Callable[[str, str, str], str] | None = None,
    ) -> None:
        try:
            run_state_tenant_id = getattr(run_state, "tenant_id", None)
        except Exception:
            run_state_tenant_id = None
        if (
            publications is None
            or run_state is None
            or type(run_state_tenant_id) is not str
            or not run_state_tenant_id
            or (github_head is None) is not (github_writer is None)
            or (gitlab_head is None) is not (gitlab_writer is None)
            or (github_comment_writer is not None and github_writer is None)
            or (github_annotation_receipt is not None and github_comment_writer is None)
            or (github_sarif_artifact is not None and github_sarif_writer is None)
            or (github_head is not None and not callable(github_head))
            or (gitlab_head is not None and not callable(gitlab_head))
            or (
                gitlab_terminal_publication is not None
                and not callable(gitlab_terminal_publication)
            )
            or (policy_decisions is not None and not callable(policy_decisions))
            or (waiver_exception_resolver is not None and not callable(waiver_exception_resolver))
            or (waiver_revision_resolver is not None and not callable(waiver_revision_resolver))
            or (github_annotation_receipt is not None and not callable(github_annotation_receipt))
            or (github_sarif_artifact is not None and not callable(github_sarif_artifact))
        ):
            raise TypeError("SCM completion dependency is missing")
        self._publications = publications
        self._run_state = run_state
        self._policy_decisions = policy_decisions
        self._waiver_exception_resolver = waiver_exception_resolver
        self._waiver_revision_resolver = waiver_revision_resolver
        self._github_comment_writer = github_comment_writer
        self._github_annotation_receipt = github_annotation_receipt
        self._github_sarif_writer = github_sarif_writer
        self._github_sarif_artifact = github_sarif_artifact
        self._github_head = github_head
        self._github_writer = github_writer
        self._gitlab_head = gitlab_head
        self._gitlab_terminal_publication = gitlab_terminal_publication
        self._gitlab_writer = gitlab_writer

    def publish_if_bound(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
        worker_outcome: object,
        allow_waiver_update: bool = False,
    ) -> SCMCompletionReceipt:
        """Finish SCM state and publish, or replay the durable result."""

        try:
            state_tenant_id = getattr(self._run_state, "tenant_id", None)
        except Exception:
            raise SCMCompletionError("SCM run binding conflicts") from None
        if state_tenant_id != tenant_id:
            raise SCMCompletionError("SCM run binding conflicts")
        audit = audit_outcome(worker_outcome)
        outcome, waiver_applied, waiver_revision, advisory_findings = self._publication_outcome(
            tenant_id=tenant_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            audit=audit,
        )
        completion_outcome = audit if waiver_applied else outcome
        try:
            target = self._publications.load(tenant_id=tenant_id, run_id=run_id)
        except Exception:
            raise SCMCompletionError("SCM publication state is unavailable") from None
        if target is None:
            recovered = self._recover_target(
                tenant_id=tenant_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                outcome=completion_outcome,
            )
            if recovered is None:
                return SCMCompletionReceipt(
                    run_id,
                    SCMCompletionDisposition.NOT_BOUND,
                    None,
                    None,
                )
            target, publication = recovered
        else:
            publication = None
        self._require_binding(target, execution_identity_hash)
        target = self._remember_pending_outcome(target, audit)
        waiver_update = False
        if target.publication_state != "PENDING" and target.outcome != outcome.value:
            waiver_update = allow_waiver_update and self._is_waiver_update(
                target=target,
                outcome=outcome,
                audit=audit,
            )
            if not waiver_update:
                raise SCMCompletionError("SCM publication receipt conflicts")
            replay = None
        else:
            replay = self._replay(target, outcome)
        if replay is not None:
            if target.publication_state == "PUBLISHED":
                replay_head = self._current_head(target)
                if replay_head != target.head_sha:
                    self._confirm_superseded(target, replay_head)
                    return self._stale_replay(target)
            return replay

        annotation_receipt = (
            self._annotation_receipt(target, audit)
            if publication is None and target.outcome is None
            else None
        )
        current_head = (
            publication.current_head_sha if publication is not None else self._current_head(target)
        )
        if publication is None:
            publication = self._complete_state(target, completion_outcome, current_head)
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            self._require_superseded(publication, target)
            return self._record_stale(target)
        self._require_completed(publication, target, completion_outcome, current_head)
        if annotation_receipt is None:
            annotation_receipt = self._annotation_receipt(
                target,
                audit,
                publication=publication,
            )
        gitlab_terminal_publication = self._gitlab_terminal_receipt(
            target, audit, outcome, publication
        )
        self._require_gitlab_terminal_receipt(target, outcome, gitlab_terminal_publication)

        write_status, observed_head = self._publish(
            target,
            outcome,
            annotation_receipt,
            gitlab_terminal_publication,
            waiver_applied=waiver_applied,
            waiver_revision=waiver_revision,
            advisory_findings=advisory_findings,
        )
        if write_status == "STALE":
            stale_head = observed_head or self._current_head(target)
            self._confirm_superseded(target, stale_head)
            return self._record_stale(target)
        if write_status == "PENDING":
            # The provider accepted SARIF but has not finished processing it.
            # Keep the publication target PENDING and let the caller retry the
            # same delivery key so GithubSarifPublisher polls its durable
            # upload receipt instead of advertising a completed publication.
            return SCMCompletionReceipt(
                target.run_id,
                SCMCompletionDisposition.PENDING,
                outcome,
                receipt_id(target),
            )
        if write_status != "WRITTEN":
            raise SCMCompletionError("SCM publication failed")
        persisted_head = self._current_head(target)
        if persisted_head != target.head_sha:
            self._confirm_superseded(target, persisted_head)
            return self._record_stale(target)
        return self._record_published(
            target,
            outcome,
            allow_policy_update=waiver_update,
        )

    def reconcile_pending(
        self,
        *,
        tenant_id: str,
        max_items: int = 32,
    ) -> bool:
        """Retry durable asynchronous publications after the worker has left.

        A worker lease only covers execution.  GitHub SARIF processing can
        outlive that lease, so the server periodically reuses the persisted
        audit outcome and the same publication target.  The provider adapter
        owns the delivery key and polls its durable upload row.
        """

        pending = getattr(self._publications, "pending", None)
        if not callable(pending):
            return False
        try:
            targets = pending(tenant_id=tenant_id, limit=max_items)
        except Exception:
            return True
        if type(targets) is not tuple:
            return True
        for target in targets:
            if type(target) is not SCMPublicationTarget or target.outcome is None:
                continue
            try:
                self.publish_if_bound(
                    tenant_id=target.tenant_id,
                    run_id=target.run_id,
                    execution_identity_hash=target.execution_identity_hash,
                    worker_outcome=target.outcome,
                )
            except (KeyboardInterrupt, SystemExit, GeneratorExit):
                raise
            except Exception:
                continue
        try:
            remaining = pending(tenant_id=tenant_id, limit=1)
        except Exception:
            return True
        return bool(remaining)

    def refresh_after_waiver(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
    ) -> SCMCompletionReceipt:
        if self._policy_decisions is None or self._waiver_exception_resolver is None:
            raise SCMCompletionError("waiver policy integration is unavailable")
        try:
            decision = self._policy_decisions(tenant_id, run_id, execution_identity_hash)
        except Exception:
            raise SCMCompletionError("SCM policy decision is unavailable") from None
        if decision is None or decision.observed_audit_outcome is None:
            raise SCMCompletionError("SCM policy decision is unavailable")
        return self.publish_if_bound(
            tenant_id=tenant_id,
            run_id=run_id,
            execution_identity_hash=execution_identity_hash,
            worker_outcome=decision.observed_audit_outcome.value,
            allow_waiver_update=True,
        )

    def _is_waiver_update(
        self,
        *,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
        audit: AuditRunOutcome,
    ) -> bool:
        if (
            target.publication_state != "PUBLISHED"
            or target.outcome not in {AuditRunOutcome.FAIL.value, AuditRunOutcome.PASS.value}
            or outcome not in {AuditRunOutcome.FAIL, AuditRunOutcome.PASS}
            or target.outcome == outcome.value
            or audit is not AuditRunOutcome.FAIL
            or self._policy_decisions is None
            or self._waiver_exception_resolver is None
        ):
            return False
        try:
            decision = self._policy_decisions(
                target.tenant_id,
                target.run_id,
                target.execution_identity_hash,
            )
            if (
                decision is None
                or decision.observed_audit_outcome is not audit
                or decision.enforcement is not ScmPolicyEnforcement.BLOCK
                or decision.error_code is not None
                or not decision.publication_permitted
            ):
                return False
            waived = self._waiver_exception_resolver(
                target.tenant_id,
                target.run_id,
                target.execution_identity_hash,
                decision,
            )
            return type(waived) is bool and (outcome is AuditRunOutcome.PASS) is waived
        except Exception:
            return False

    def _recover_target(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
        outcome: AuditRunOutcome,
    ) -> tuple[SCMPublicationTarget, SCMRunPublicationReceipt] | None:
        try:
            state_tenant_id = getattr(self._run_state, "tenant_id", None)
        except Exception:
            raise SCMCompletionError("SCM run binding conflicts") from None
        if type(state_tenant_id) is not str or state_tenant_id != tenant_id:
            raise SCMCompletionError("SCM run binding conflicts")
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
        if publication.disposition is PublicationDisposition.SUPERSEDED:
            self._require_superseded(publication, target)
        else:
            self._require_completed(publication, target, outcome, current_head)
        try:
            self._publications.bind(target)
        except Exception:
            raise SCMCompletionError("SCM publication target was not stored") from None
        return target, publication

    def _publication_outcome(
        self,
        *,
        tenant_id: str,
        run_id: str,
        execution_identity_hash: str,
        audit: AuditRunOutcome,
    ) -> tuple[AuditRunOutcome, bool, str, bool]:
        """Return the published outcome, waiver state and whether advisory findings exist."""

        waiver_revision = ""
        if self._waiver_revision_resolver is not None:
            try:
                waiver_revision = self._waiver_revision_resolver(
                    tenant_id,
                    run_id,
                    execution_identity_hash,
                )
            except Exception:
                raise SCMCompletionError("SCM waiver state is unavailable") from None
            if (
                type(waiver_revision) is not str
                or len(waiver_revision) != 64
                or any(character not in "0123456789abcdef" for character in waiver_revision)
            ):
                raise SCMCompletionError("SCM waiver state is invalid")
        if self._policy_decisions is None:
            return audit, False, waiver_revision, False
        if audit in {AuditRunOutcome.CANCELLED, AuditRunOutcome.SUPERSEDED}:
            return audit, False, waiver_revision, False
        try:
            decision = self._policy_decisions(tenant_id, run_id, execution_identity_hash)
        except Exception:
            raise SCMCompletionError("SCM policy decision is unavailable") from None
        outcome = scm_publication_outcome(
            audit,
            decision,
            execution_identity_hash=execution_identity_hash,
        )
        if (
            audit is AuditRunOutcome.FAIL
            and decision is not None
            and decision.enforcement is ScmPolicyEnforcement.BLOCK
            and decision.error_code is None
            and decision.publication_permitted
            and self._waiver_exception_resolver is not None
        ):
            try:
                if self._waiver_exception_resolver(
                    tenant_id,
                    run_id,
                    execution_identity_hash,
                    decision,
                ):
                    return AuditRunOutcome.PASS, True, waiver_revision, False
            except Exception:
                raise SCMCompletionError("SCM waiver decision is unavailable") from None
        advisory_findings = (
            audit is AuditRunOutcome.FAIL
            and outcome is AuditRunOutcome.PASS
            and decision is not None
            and decision.mode is ScmPolicyMode.ADVISORY
        )
        return outcome, False, waiver_revision, advisory_findings

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

    def _annotation_receipt(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
        *,
        publication: SCMRunPublicationReceipt | None = None,
    ) -> GithubAnnotationReceipt | None:
        if (
            target.provider != "github"
            or self._github_comment_writer is None
            or self._github_annotation_receipt is None
        ):
            return None
        try:
            if publication is None:
                return self._github_annotation_receipt(target, outcome)
            completed = getattr(self._github_annotation_receipt, "for_completed", None)
            if not callable(completed):
                raise SCMCompletionError("SCM annotation authorization is unavailable")
            receipt: GithubAnnotationReceipt | None = completed(target, outcome, publication)
            return receipt
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise SCMCompletionError("SCM annotation projection failed") from None

    def _gitlab_terminal_receipt(
        self,
        target: SCMPublicationTarget,
        audit: AuditRunOutcome,
        publication_outcome: AuditRunOutcome,
        publication: SCMRunPublicationReceipt,
    ) -> GitlabTerminalPublication | None:
        if target.provider != "gitlab":
            return None
        if (
            publication_outcome is AuditRunOutcome.INDETERMINATE
            and audit is not AuditRunOutcome.INDETERMINATE
        ):
            return None
        if publication_outcome not in {
            AuditRunOutcome.PASS,
            AuditRunOutcome.FAIL,
            AuditRunOutcome.INDETERMINATE,
        }:
            return None
        if (
            audit is AuditRunOutcome.INDETERMINATE
            and publication_outcome is not AuditRunOutcome.INDETERMINATE
        ):
            return None
        if self._gitlab_terminal_publication is None:
            raise SCMCompletionError("SCM provider is not configured")
        try:
            receipt = self._gitlab_terminal_publication(
                target,
                audit,
                publication,
                publication_outcome=publication_outcome,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise SCMCompletionError("SCM terminal projection failed") from None
        if receipt is None:
            return None
        if type(receipt) is not GitlabTerminalPublication:
            raise SCMCompletionError("SCM terminal projection is invalid")
        return receipt

    @staticmethod
    def _require_gitlab_terminal_receipt(
        target: SCMPublicationTarget,
        publication_outcome: AuditRunOutcome,
        receipt: GitlabTerminalPublication | None,
    ) -> None:
        if target.provider != "gitlab":
            if receipt is not None:
                raise SCMCompletionError("SCM terminal projection is invalid")
            return
        if publication_outcome not in {
            AuditRunOutcome.PASS,
            AuditRunOutcome.FAIL,
            AuditRunOutcome.INDETERMINATE,
        }:
            if receipt is not None:
                raise SCMCompletionError("SCM terminal projection is invalid")
            return
        if publication_outcome is AuditRunOutcome.INDETERMINATE and receipt is None:
            return
        if (
            type(receipt) is not GitlabTerminalPublication
            or receipt.authorized_run_id != target.run_id
            or receipt.authorized_identity_hash != target.execution_identity_hash
            or receipt.authorized_head_sha != target.head_sha
            or receipt.summary.head_sha != target.head_sha
            or receipt.summary.execution_identity_hash != target.execution_identity_hash
            or receipt.summary.execution_identity_hash != receipt.authorized_identity_hash
            or any(item.head_sha != target.head_sha for item in receipt.discussions)
        ):
            raise SCMCompletionError("SCM terminal projection conflicts")

    @staticmethod
    def _require_superseded(
        receipt: SCMRunPublicationReceipt,
        target: SCMPublicationTarget,
    ) -> None:
        if (
            receipt.disposition is not PublicationDisposition.SUPERSEDED
            or receipt.run_id != target.run_id
            or receipt.execution_identity_hash != target.execution_identity_hash
            or receipt.head_sha != target.head_sha
            or receipt.current_head_sha == target.head_sha
            or receipt.outcome is not AuditRunOutcome.SUPERSEDED
        ):
            raise SCMCompletionError("SCM run completion conflicts")

    def _publish(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
        annotation_receipt: GithubAnnotationReceipt | None,
        gitlab_terminal_publication: GitlabTerminalPublication | None,
        *,
        waiver_applied: bool = False,
        waiver_revision: str = "",
        advisory_findings: bool = False,
    ) -> tuple[str, str | None]:
        identifier = receipt_id(target)
        delivery_key = (
            identifier
            if not waiver_revision
            else f"{identifier}:{outcome.value.lower()}:{waiver_revision}"
        )
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
                    projection=github_projection(
                        target,
                        outcome,
                        waiver_applied=waiver_applied,
                        advisory_findings=advisory_findings,
                    ),
                    delivery_key=delivery_key,
                )
                status = _attribute_value(receipt, "status")
                if status == "WRITTEN":
                    _github_remote_check_id(receipt)
                    if self._github_comment_writer is not None:
                        projection = github_projection(
                            target,
                            outcome,
                            waiver_applied=waiver_applied,
                            advisory_findings=advisory_findings,
                        )
                        output = projection.get("output")
                        summary = output.get("summary") if type(output) is dict else None
                        if type(summary) is not str:
                            raise SCMCompletionError("SCM comment projection is invalid")
                        comment = self._github_comment_writer.publish(
                            installation_id=target.installation_id,
                            repository_id=target.repository_id,
                            change_id=target.change_id,
                            expected_head=target.head_sha,
                            external_id=identifier,
                            summary=summary,
                            delivery_key=delivery_key + ":summary",
                            annotation_receipt=annotation_receipt,
                        )
                        comment_status = _attribute_value(comment, "status")
                        if comment_status == "STALE_SUPPRESSED":
                            return "STALE", validate_head(self._current_head(target))
                        if comment_status != "WRITTEN":
                            return "FAILED", None
                    sarif = self._publish_github_sarif(
                        target,
                        outcome,
                        delivery_key=delivery_key,
                    )
                    if sarif == "STALE":
                        return sarif, validate_head(self._current_head(target))
                    if sarif == "PENDING":
                        return sarif, None
                    if sarif != "WRITTEN":
                        return "FAILED", None
                    return "WRITTEN", None
                if status == "STALE_SUPPRESSED":
                    return "STALE", None
                return "FAILED", None
            if self._gitlab_writer is None:
                raise SCMCompletionError("SCM provider is not configured")
            receipt = self._gitlab_writer.publish_external_status(
                gitlab_target(target),
                gitlab_projection(
                    target,
                    outcome,
                    waiver_applied=waiver_applied,
                    waiver_revision=waiver_revision,
                ),
            )
            result = self._gitlab_write_result(target, receipt)
            if result[0] == "WRITTEN":
                return self._publish_gitlab_terminal(target, gitlab_terminal_publication)
            return result
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except SCMCompletionError:
            raise
        except Exception:
            raise SCMCompletionError("SCM publication failed") from None

    def _publish_github_sarif(
        self,
        target: SCMPublicationTarget,
        outcome: AuditRunOutcome,
        *,
        delivery_key: str,
    ) -> str:
        if (
            target.provider != "github"
            or outcome
            not in {
                AuditRunOutcome.PASS,
                AuditRunOutcome.FAIL,
                AuditRunOutcome.INDETERMINATE,
            }
            or self._github_sarif_writer is None
        ):
            return "WRITTEN"
        resolver = self._github_sarif_artifact
        if resolver is None:
            raise SCMCompletionError("SCM SARIF artifact resolver is unavailable")
        try:
            artifact = resolver(target)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise SCMCompletionError("SCM SARIF artifact is unavailable") from None
        if artifact is None:
            if outcome is AuditRunOutcome.INDETERMINATE:
                return "WRITTEN"
            raise SCMCompletionError("SCM SARIF artifact is unavailable")
        if (
            type(artifact) is not tuple
            or len(artifact) != 2
            or type(artifact[0]) is not str
            or type(artifact[1]) is not bytes
        ):
            raise SCMCompletionError("SCM SARIF artifact is invalid")
        try:
            receipt = self._github_sarif_writer.publish(
                tenant_id=target.tenant_id,
                run_id=target.run_id,
                execution_identity_hash=target.execution_identity_hash,
                installation_id=target.installation_id,
                repository_id=target.repository_id,
                change_id=target.change_id,
                expected_head=target.head_sha,
                artifact_sha256=artifact[0],
                content=artifact[1],
                delivery_key=delivery_key,
            )
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise SCMCompletionError("SCM SARIF publication failed") from None
        status = _attribute_value(receipt, "status")
        if status == "STALE_SUPPRESSED":
            return "STALE"
        # GitHub accepts SARIF asynchronously.  A 202 response is represented
        # by the transport as PENDING until the processing endpoint reports
        # complete.  Preserve that state so the caller can poll with the same
        # durable idempotency key instead of advertising processing complete.
        if status not in {"WRITTEN", "IDEMPOTENT", "PENDING"}:
            return "FAILED"
        if getattr(receipt, "merge_authority", False) is not False:
            raise SCMCompletionError("SCM SARIF receipt grants merge authority")
        if status == "PENDING":
            return "PENDING"
        return "WRITTEN"

    def _remember_pending_outcome(
        self,
        target: SCMPublicationTarget,
        audit: AuditRunOutcome,
    ) -> SCMPublicationTarget:
        if target.publication_state != "PENDING":
            return target
        mark_pending = getattr(self._publications, "mark_pending", None)
        if not callable(mark_pending):
            return target
        try:
            stored = mark_pending(target=target, outcome=audit.value)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise SCMCompletionError("SCM publication state is unavailable") from None
        if (
            type(stored) is not SCMPublicationTarget
            or stored.publication_state != "PENDING"
            or stored.outcome != audit.value
            or stored.receipt_id is not None
        ):
            raise SCMCompletionError("SCM publication state conflicts")
        return stored

    def _publish_gitlab_terminal(
        self,
        target: SCMPublicationTarget,
        receipt: GitlabTerminalPublication | None,
    ) -> tuple[str, str | None]:
        if receipt is None:
            return "WRITTEN", None
        if self._gitlab_writer is None:
            raise SCMCompletionError("SCM provider is not configured")

        result = self._gitlab_write_result(
            target, self._gitlab_writer.publish_summary(gitlab_target(target), receipt.summary)
        )
        if result[0] != "WRITTEN":
            return result
        for projection in receipt.discussions:
            result = self._gitlab_write_result(
                target, self._gitlab_writer.publish_discussion(gitlab_target(target), projection)
            )
            if result[0] != "WRITTEN":
                return result
        return "WRITTEN", None

    @staticmethod
    def _gitlab_write_result(
        target: SCMPublicationTarget,
        write_receipt: object,
    ) -> tuple[str, str | None]:
        status = _attribute_value(write_receipt, "status")
        expected = getattr(write_receipt, "expected_head_sha", None)
        observed = getattr(write_receipt, "observed_head_sha", None)
        if expected != target.head_sha:
            raise SCMCompletionError("SCM GitLab receipt conflicts")
        if status == "STALE":
            return "STALE", validate_head(observed)
        if status not in {"SUCCEEDED", "IDEMPOTENT"}:
            return "FAILED", None
        if observed != target.head_sha:
            raise SCMCompletionError("SCM GitLab receipt conflicts")
        return "WRITTEN", None

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
        *,
        allow_policy_update: bool = False,
    ) -> SCMCompletionReceipt:
        identifier = receipt_id(target)
        self._record(
            target,
            outcome=outcome,
            stale=False,
            identifier=identifier,
            allow_policy_update=allow_policy_update,
        )
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
        allow_policy_update: bool = False,
    ) -> None:
        try:
            if allow_policy_update:
                stored = self._publications.record(
                    target=target,
                    outcome=outcome.value,
                    stale=stale,
                    receipt_id=identifier,
                    allow_policy_update=True,
                )
            else:
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
            publication = self._publisher.publish_if_bound(
                tenant_id=request.identity.tenant_id,
                run_id=run_id,
                execution_identity_hash=execution_identity_hash,
                worker_outcome=outcome,
            )
            if publication.disposition is SCMCompletionDisposition.PENDING:
                # The queue result is terminal, but asynchronous SARIF
                # processing is not.  Release HTTP idempotency ownership and
                # return a retryable response so the worker re-enters this
                # path and polls the durable upload state with the same key.
                raise ServiceUnavailableError()
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
