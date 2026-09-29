from __future__ import annotations

from dataclasses import replace
from typing import cast

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    FindingGateState,
    FindingVerdict,
    ModelCallStatus,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core.classification import FindingSeverity
from securecode_ai.core.escalation import (
    EscalationCaseError,
    EscalationErrorCode,
    HumanEscalationCase,
    SafeEventLink,
    create_escalation_case,
)
from securecode_ai.core.finding_gate import (
    FindingGateContractError,
    FindingGateDecision,
    FindingGateInput,
    FindingGateReason,
    FindingRoute,
    InvestigationTerminalStatus,
    route_finding,
)
from securecode_ai.core.investigation import (
    AuditorInvestigationReceipt,
    InvestigationBudget,
    InvestigationDisposition,
    InvestigationError,
    InvestigationStopReason,
)
from securecode_ai.core.skeptic import SkepticObjection, SkepticObjectionKind

HEAD = "a" * 40
HASH = "b" * 64


def _identity() -> RunExecutionIdentity:
    def pin(name: str, digest: str) -> ComponentPin:
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=name,
            component_version="1.0.0",
            content_sha256=digest,
        )

    return RunExecutionIdentity.build(
        repository_revision=RepositoryRevision(
            schema_version=CONTRACT_SCHEMA_VERSION,
            tenant_id="tenant-1",
            scm_provider="github",
            repository_id="repo-1",
            head_sha=HEAD,
            base_sha="c" * 40,
        ),
        stage_catalogue=pin("catalogue", HASH),
        workflow=pin("workflow", "c" * 64),
        policy=pin("policy", "d" * 64),
        configuration=pin("config", "e" * 64),
        provider_profile=pin("provider", "f" * 64),
        capability_profile=pin("capability", "1" * 64),
        egress_profile=pin("egress", "2" * 64),
    )


def _decision() -> FindingGateDecision:
    objection = SkepticObjection(SkepticObjectionKind.CONTRADICTORY_EVIDENCE, ("ev-2",))
    return FindingGateDecision(
        candidate_id="candidate-1",
        candidate_version=1,
        head_sha=HEAD,
        severity=FindingSeverity.HIGH,
        known_evidence_ids=("ev-1", "ev-2"),
        route=FindingRoute.HUMAN_ESCALATION,
        finding_gate_state=FindingGateState.INCONCLUSIVE,
        reason=FindingGateReason.HIGH_CRITICAL_CONFLICT,
        auditor_identity="auditor-1",
        auditor_receipt_sha256=HASH,
        auditor_model_call_status=ModelCallStatus.SUCCEEDED,
        auditor_verdict=FindingVerdict.CONFIRMED,
        auditor_cited_evidence_ids=("ev-1",),
        skeptic_identity="skeptic-1",
        skeptic_receipt_sha256="c" * 64,
        skeptic_model_call_status=ModelCallStatus.SUCCEEDED,
        skeptic_verdict=FindingVerdict.REJECTED_WITH_EVIDENCE,
        skeptic_effective_verdict=FindingVerdict.CONFLICTING,
        skeptic_objections=(objection,),
        skeptic_cited_evidence_ids=("ev-2",),
        investigation_terminal_status=InvestigationTerminalStatus.COMPLETED,
    )


def _receipt() -> AuditorInvestigationReceipt:
    return AuditorInvestigationReceipt(
        candidate_id="candidate-1",
        candidate_version=1,
        tenant_id="tenant-1",
        head_sha=HEAD,
        initial_selection_sha256=HASH,
        final_selection_sha256=HASH,
        attempts=(),
        context_rounds=1,
        tokens_used=0,
        tool_calls=0,
        elapsed_ms=0,
        no_progress_count=1,
        final_model_call_status=ModelCallStatus.TIMEOUT,
        finding_verdict=FindingVerdict.NOT_EVALUATED,
        disposition=InvestigationDisposition.INDETERMINATE,
        stop_reason=InvestigationStopReason.NO_NEW_EVIDENCE,
    )


def test_case_is_source_free_and_canonical() -> None:
    case = create_escalation_case(
        _decision(),
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=_identity(),
        investigation_receipt=_receipt(),
        budget=InvestigationBudget(3, 10, 10, 10),
        policy_hashes=(HASH,),
        route_policy_sha256="d" * 64,
    )
    assert case.route is FindingRoute.HUMAN_ESCALATION
    assert case.canonical_bytes() == case.canonical_bytes()
    assert case.case_sha256 == case.case_sha256
    assert b"cursor.execute" not in case.canonical_bytes()
    assert not hasattr(case, "approval") and not hasattr(case, "rejection")


def test_cross_scope_identity_fails_closed() -> None:
    with pytest.raises(EscalationCaseError) as error:
        create_escalation_case(
            _decision(),
            tenant_id="other-tenant",
            run_id="run-1",
            execution_identity=_identity(),
            investigation_receipt=_receipt(),
            budget=InvestigationBudget(3, 10, 10, 10),
        )
    assert error.value.code is EscalationErrorCode.CROSS_SCOPE


def _routed(**overrides: object) -> FindingGateDecision:
    """Derive a decision through the policy; decisions cannot be forged by replace."""

    decision = _decision()
    values = {
        name: getattr(decision, name)
        for name in FindingGateInput.__dataclass_fields__
        if name in FindingGateDecision.__dataclass_fields__
    }
    return route_finding(FindingGateInput(**{**values, **overrides}))


def test_forged_decision_route_is_rejected_by_the_gate_contract() -> None:
    with pytest.raises(FindingGateContractError):
        replace(
            _decision(),
            route=FindingRoute.CONFIRMED,
            finding_gate_state=FindingGateState.BLOCKING,
            reason=FindingGateReason.CONFIRMED,
        )


def test_non_human_route_cannot_create_case() -> None:
    confirmed = _routed(
        skeptic_verdict=FindingVerdict.CONFIRMED,
        skeptic_effective_verdict=FindingVerdict.CONFIRMED,
        skeptic_objections=(),
        skeptic_cited_evidence_ids=(),
    )
    assert confirmed.route is FindingRoute.CONFIRMED
    with pytest.raises(EscalationCaseError):
        create_escalation_case(
            confirmed,
            tenant_id="tenant-1",
            run_id="run-1",
            execution_identity=_identity(),
            investigation_receipt=_receipt(),
            budget=InvestigationBudget(3, 10, 10, 10),
        )


def test_indeterminate_route_is_preserved_as_source_route() -> None:
    indeterminate = _routed(investigation_terminal_status=InvestigationTerminalStatus.NO_PROGRESS)
    assert indeterminate.route is FindingRoute.INDETERMINATE
    assert indeterminate.reason is FindingGateReason.INVESTIGATION_NO_PROGRESS
    case = create_escalation_case(
        indeterminate,
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=_identity(),
        investigation_receipt=_receipt(),
        budget=InvestigationBudget(3, 10, 10, 10),
    )
    assert case.route is FindingRoute.HUMAN_ESCALATION
    assert case.source_route is FindingRoute.INDETERMINATE


def test_complete_budget_is_canonical_and_changes_digest() -> None:
    first = create_escalation_case(
        _decision(),
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=_identity(),
        investigation_receipt=_receipt(),
        budget=InvestigationBudget(3, 10, 10, 10, 2, 2),
    )
    second = create_escalation_case(
        _decision(),
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=_identity(),
        investigation_receipt=_receipt(),
        budget=InvestigationBudget(4, 10, 10, 10, 2, 2),
    )
    assert first.budget.max_context_rounds == 2 and first.budget.max_no_progress == 2
    assert first.canonical_bytes() != second.canonical_bytes()


@pytest.mark.parametrize(
    "values", ((0, 10, 10, 10), (1, 0, 10, 10), (1, 10, 0, 10), (1, 10, 10, 0))
)
def test_budget_constructor_rejects_invalid_limits(values: tuple[int, ...]) -> None:
    with pytest.raises(InvestigationError):
        InvestigationBudget(*values)


def test_direct_case_rejects_malformed_sha_and_tampered_receipt() -> None:
    case = create_escalation_case(
        _decision(),
        tenant_id="tenant-1",
        run_id="run-1",
        execution_identity=_identity(),
        investigation_receipt=_receipt(),
        budget=InvestigationBudget(3, 10, 10, 10),
    )
    with pytest.raises(EscalationCaseError):
        replace(case, auditor_receipt_sha256=cast(str, object()))
    with pytest.raises(EscalationCaseError):
        replace(case, skeptic_receipt_sha256=cast(str, object()))
    with pytest.raises(EscalationCaseError):
        replace(case, policy_hashes=cast(tuple[str, ...], (object(),)))
    with pytest.raises(EscalationCaseError):
        replace(case, investigation_receipt=replace(_receipt(), tenant_id="other"))


def test_event_link_tamper_is_rejected() -> None:
    with pytest.raises(EscalationCaseError):
        HumanEscalationCase(
            schema_version="0.1.0",
            case_id="case-1",
            tenant_id="tenant-1",
            run_id="run-1",
            candidate_id="candidate-1",
            candidate_version=1,
            head_sha=HEAD,
            execution_identity=_identity(),
            route=FindingRoute.HUMAN_ESCALATION,
            source_route=FindingRoute.INDETERMINATE,
            investigation_receipt=_receipt(),
            reason=FindingGateReason.INVESTIGATION_NO_PROGRESS,
            known_evidence_ids=("ev-1",),
            auditor_identity="auditor-1",
            auditor_receipt_sha256=HASH,
            auditor_cited_evidence_ids=("ev-1",),
            auditor_verdict=FindingVerdict.CONFIRMED.value,
            skeptic_identity="skeptic-1",
            skeptic_receipt_sha256=HASH,
            skeptic_cited_evidence_ids=(),
            skeptic_objections=(),
            skeptic_verdict=FindingVerdict.NOT_EVALUATED.value,
            skeptic_effective_verdict=FindingVerdict.NOT_EVALUATED.value,
            investigation_terminal_status="CONTEXT_EXHAUSTED",
            investigation_stop_reason="NO_NEW_EVIDENCE",
            model_non_success_reason="TIMEOUT",
            budget=InvestigationBudget(3, 10, 10, 10),
            no_progress_count=1,
            context_exhausted=True,
            policy_hashes=(),
            route_policy_sha256=None,
            event_chain=(SafeEventLink("event-1", 2, "RUN_STARTED", HASH, None),),
        )
