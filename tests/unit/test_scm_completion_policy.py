from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from types import SimpleNamespace

import pytest
from securecode_ai.contracts import AuditRunOutcome
from securecode_ai.core.scm_policy import (
    SCM_POLICY_SCHEMA_VERSION,
    ScmPolicyDecision,
    ScmPolicyEnforcement,
    ScmPolicyInputHashes,
    ScmPolicyMode,
)
from securecode_ai.core.scm_run_state import (
    PublicationDisposition,
    SCMRunLifecycle,
    SCMRunPublicationReceipt,
)
from securecode_ai.server.scm_completion import SCMCompletionPublicationService
from securecode_ai.server.scm_completion_models import SCMCompletionError
from securecode_ai.server.scm_publication_store import SCMPublicationTarget

_HEAD = "a" * 40
_IDENTITY_HASH = "c" * 64


def _decision(
    *,
    enforcement: ScmPolicyEnforcement,
    blocks_merge: bool,
    mode: ScmPolicyMode,
    observed: AuditRunOutcome,
    rule_id: str,
) -> ScmPolicyDecision:
    hashes = ScmPolicyInputHashes(
        policy_document_sha256="1" * 64,
        audit_run_sha256="2" * 64,
        execution_identity_sha256=_IDENTITY_HASH,
        baseline_comparison_sha256="3" * 64,
    )
    metadata = {
        "blocks_merge": blocks_merge,
        "enforcement": enforcement.value,
        "error_code": None,
        "input_hashes": {
            "policy_document_sha256": hashes.policy_document_sha256,
            "audit_run_sha256": hashes.audit_run_sha256,
            "execution_identity_sha256": hashes.execution_identity_sha256,
            "baseline_comparison_sha256": hashes.baseline_comparison_sha256,
        },
        "is_passing": observed is AuditRunOutcome.PASS,
        "matched_rule_ids": (rule_id,),
        "mode": mode.value,
        "observed_audit_outcome": observed.value,
        "policy_id": "policy-v1",
        "policy_version": "1.0.0",
        "publication_permitted": True,
        "schema_version": SCM_POLICY_SCHEMA_VERSION,
    }
    digest = hashlib.sha256(
        json.dumps(
            metadata, ensure_ascii=True, allow_nan=False, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
    ).hexdigest()
    return ScmPolicyDecision(
        schema_version=SCM_POLICY_SCHEMA_VERSION,
        policy_id="policy-v1",
        policy_version="1.0.0",
        mode=mode,
        observed_audit_outcome=observed,
        enforcement=enforcement,
        is_passing=observed is AuditRunOutcome.PASS,
        blocks_merge=blocks_merge,
        publication_permitted=True,
        input_hashes=hashes,
        matched_rule_ids=(rule_id,),
        error_code=None,
        decision_sha256=digest,
    )


@dataclass
class _FakePublicationStore:
    target: SCMPublicationTarget

    def bind(self, target: SCMPublicationTarget) -> None:
        self.target = target

    def load(self, *, tenant_id: str, run_id: str) -> SCMPublicationTarget | None:
        if (tenant_id, run_id) != (self.target.tenant_id, self.target.run_id):
            return None
        return self.target

    def pending(self, *, tenant_id: str, limit: int = 32) -> tuple[SCMPublicationTarget, ...]:
        raise AssertionError("pending publications are not exercised by these tests")

    def mark_pending(self, *, target: SCMPublicationTarget, outcome: str) -> SCMPublicationTarget:
        self.target = replace(target, outcome=outcome)
        return self.target

    def record(
        self,
        *,
        target: SCMPublicationTarget,
        outcome: str,
        stale: bool,
        receipt_id: str,
        allow_policy_update: bool = False,
    ) -> SCMPublicationTarget:
        self.target = replace(
            target,
            publication_state="STALE" if stale else "PUBLISHED",
            outcome=outcome,
            receipt_id=receipt_id,
        )
        return self.target


class _FakeRunState:
    tenant_id = "tenant-1"

    def __init__(self) -> None:
        self.outcome: AuditRunOutcome | None = None

    def provider_target(self, _run_id: str) -> object:
        raise AssertionError("existing publication binding should not be recovered")

    def authorize_publication(
        self, _run_id: str, *, current_head_sha: str
    ) -> SCMRunPublicationReceipt:
        del current_head_sha
        raise AssertionError("this test does not exercise supersession")

    def complete(
        self,
        run_id: str,
        outcome: AuditRunOutcome,
        *,
        current_head_sha: str,
    ) -> SCMRunPublicationReceipt:
        self.outcome = outcome
        return SCMRunPublicationReceipt(
            disposition=PublicationDisposition.COMPLETED,
            run_id=run_id,
            execution_identity_hash=_IDENTITY_HASH,
            head_sha=_HEAD,
            current_head_sha=current_head_sha,
            lifecycle=SCMRunLifecycle.COMPLETED,
            outcome=outcome,
            state_version=2,
        )


class _FakeGithubWriter:
    def __init__(self) -> None:
        self.projection: dict[str, object] | None = None

    def write_pull_request_check(self, **kwargs: object) -> object:
        self.projection = kwargs["projection"]  # type: ignore[assignment]
        return SimpleNamespace(status="WRITTEN", remote_check_id="1")


def _service(
    decision: ScmPolicyDecision | None,
) -> tuple[SCMCompletionPublicationService, _FakeRunState, _FakeGithubWriter]:
    target = SCMPublicationTarget(
        tenant_id="tenant-1",
        run_id="run-1",
        provider="github",
        installation_id="install-1",
        repository_id="repo-1",
        change_id="17",
        head_sha=_HEAD,
        execution_identity_hash=_IDENTITY_HASH,
    )
    run_state = _FakeRunState()
    writer = _FakeGithubWriter()
    service = SCMCompletionPublicationService(
        publications=_FakePublicationStore(target),
        run_state=run_state,
        github_head=lambda _installation, _repository, _change: _HEAD,
        github_writer=writer,
        policy_decisions=lambda _tenant, _run, _identity: decision,
    )
    return service, run_state, writer


def test_new_code_legacy_finding_publishes_pass_without_rewriting_audit() -> None:
    decision = _decision(
        enforcement=ScmPolicyEnforcement.ALLOW,
        blocks_merge=False,
        mode=ScmPolicyMode.NEW_CODE,
        observed=AuditRunOutcome.FAIL,
        rule_id="legacy_debt_non_blocking",
    )
    service, run_state, writer = _service(decision)

    receipt = service.publish_if_bound(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity_hash=_IDENTITY_HASH,
        worker_outcome="FAIL",
    )

    assert receipt.outcome is AuditRunOutcome.PASS
    assert run_state.outcome is AuditRunOutcome.PASS
    assert writer.projection is not None
    assert writer.projection["conclusion"] == "success"


def test_missing_policy_receipt_publishes_indeterminate() -> None:
    service, run_state, writer = _service(None)

    receipt = service.publish_if_bound(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity_hash=_IDENTITY_HASH,
        worker_outcome="PASS",
    )

    assert receipt.outcome is AuditRunOutcome.INDETERMINATE
    assert run_state.outcome is AuditRunOutcome.INDETERMINATE
    assert writer.projection is not None
    assert writer.projection["conclusion"] == "action_required"


def test_policy_receipt_identity_mismatch_refuses_publication() -> None:
    decision = _decision(
        enforcement=ScmPolicyEnforcement.BLOCK,
        blocks_merge=True,
        mode=ScmPolicyMode.STRICT,
        observed=AuditRunOutcome.FAIL,
        rule_id="confirmed_finding",
    )
    service, run_state, writer = _service(decision)

    with pytest.raises(SCMCompletionError):
        service.publish_if_bound(
            tenant_id="tenant-1",
            run_id="run-1",
            execution_identity_hash="d" * 64,
            worker_outcome="FAIL",
        )

    assert run_state.outcome is None
    assert writer.projection is None


def test_advisory_findings_publish_neutral_check_without_blocking() -> None:
    decision = _decision(
        enforcement=ScmPolicyEnforcement.ADVISORY,
        blocks_merge=False,
        mode=ScmPolicyMode.ADVISORY,
        observed=AuditRunOutcome.FAIL,
        rule_id="advisory_findings",
    )
    service, run_state, writer = _service(decision)

    receipt = service.publish_if_bound(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity_hash=_IDENTITY_HASH,
        worker_outcome="FAIL",
    )

    assert receipt.outcome is AuditRunOutcome.PASS
    assert run_state.outcome is AuditRunOutcome.PASS
    assert writer.projection is not None
    assert writer.projection["conclusion"] == "neutral"
    output = writer.projection["output"]
    assert isinstance(output, dict)
    assert "advisory" in output["title"]


def test_advisory_clean_run_publishes_success() -> None:
    decision = _decision(
        enforcement=ScmPolicyEnforcement.ADVISORY,
        blocks_merge=False,
        mode=ScmPolicyMode.ADVISORY,
        observed=AuditRunOutcome.PASS,
        rule_id="advisory_clean",
    )
    service, _run_state, writer = _service(decision)

    service.publish_if_bound(
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity_hash=_IDENTITY_HASH,
        worker_outcome="PASS",
    )

    assert writer.projection is not None
    assert writer.projection["conclusion"] == "success"
