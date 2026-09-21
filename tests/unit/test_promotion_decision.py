"""P7.16 governed promotion decision contracts."""

from __future__ import annotations

import pytest
from securecode_ai.core.promotion_decision import (
    ParetoEvidence,
    PromotionAction,
    PromotionCandidate,
    PromotionDecisionAuthority,
    PromotionDecisionError,
    PromotionDecisionReceipt,
    PromotionDecisionRequest,
    PromotionEvidenceHashes,
    canonical_decision_json,
    decide_promotion,
)
from securecode_ai.core.promotion_registry import (
    InMemoryPromotionStore,
    PromotionAliasRegistry,
    PromotionRegistryError,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
HASH_E = "e" * 64
HASH_F = "f" * 64
AUTHORITY_KEY = b"promotion-test-authority-key-01x"  # pragma: allowlist secret


def _authority() -> PromotionDecisionAuthority:
    return PromotionDecisionAuthority.create(
        authority_id="promotion-authority-1",
        key=AUTHORITY_KEY,
    )


def _candidate() -> PromotionCandidate:
    return PromotionCandidate("candidate-1", 2, HASH_A, "owner-1", "evaluator-1")


def _evidence() -> PromotionEvidenceHashes:
    return PromotionEvidenceHashes(HASH_A, HASH_B, HASH_C, HASH_D, HASH_E, HASH_F, HASH_A)


def _request(
    authority: PromotionDecisionAuthority,
    *,
    action: PromotionAction = PromotionAction.PROMOTE,
    unsafe: bool = False,
    candidate: PromotionCandidate | None = None,
    reviewer_id: str = "appsec-1",
) -> PromotionDecisionRequest:
    selected = _candidate() if candidate is None else candidate
    evidence = _evidence()
    return PromotionDecisionRequest(
        action,
        "READY",
        selected,
        evidence,
        ParetoEvidence(
            selected.content_sha256,
            0.9,
            10,
            20,
            1 if unsafe else 0,
            0,
            0,
            not unsafe,
        ),
        authority.approve_appsec(
            reviewer_id=reviewer_id,
            approval_sha256=HASH_B,
            candidate=selected,
            evidence=evidence,
        ),
    )


def _decide(
    authority: PromotionDecisionAuthority,
    request: PromotionDecisionRequest,
    *,
    nonce: str,
) -> PromotionDecisionReceipt:
    return decide_promotion(
        request,
        authority=authority,
        target_alias="production-prompt",
        expected_revision=0,
        expected_decision_sha256=None,
        transition_nonce=nonce,
    )


def test_complete_independent_safe_evidence_promotes_with_source_free_canonical_receipt() -> None:
    authority = _authority()
    receipt = _decide(authority, _request(authority), nonce="promotion-safe-0001")
    document = canonical_decision_json(receipt)

    assert receipt.action is PromotionAction.PROMOTE
    assert receipt.source_disclosed is False
    assert "source" in document
    assert "owner-1" not in document
    assert document.endswith("\n")


def test_unsafe_or_incomplete_evidence_becomes_explicit_no_promotion() -> None:
    authority = _authority()
    receipt = _decide(
        authority,
        _request(authority, unsafe=True),
        nonce="promotion-unsafe-01",
    )

    assert receipt.action is PromotionAction.NO_PROMOTION
    assert receipt.reason_code == "MISSING_OR_UNSAFE_EVIDENCE"


@pytest.mark.parametrize("reviewer_id", ["owner-1", "evaluator-1"])
def test_owner_or_evaluator_cannot_supply_independent_appsec_approval(
    reviewer_id: str,
) -> None:
    authority = _authority()

    with pytest.raises(PromotionDecisionError):
        authority.approve_appsec(
            reviewer_id=reviewer_id,
            approval_sha256=HASH_B,
            candidate=_candidate(),
            evidence=_evidence(),
        )


def test_no_promotion_never_changes_alias_and_promote_cas_is_replay_safe() -> None:
    authority = _authority()
    registry = PromotionAliasRegistry(authority, InMemoryPromotionStore())
    no_promotion = _decide(
        authority,
        _request(authority, action=PromotionAction.NO_PROMOTION),
        nonce="no-promotion-0001",
    )
    skipped = registry.compare_and_set(
        alias="production-prompt", expected_revision=0, decision=no_promotion
    )

    promoted = _decide(
        authority,
        _request(authority),
        nonce="promotion-replay-1",
    )
    first = registry.compare_and_set(
        alias="production-prompt", expected_revision=0, decision=promoted
    )
    replay = registry.compare_and_set(
        alias="production-prompt", expected_revision=0, decision=promoted
    )

    assert not skipped.applied
    assert first.alias is not None and first.alias.revision == 1
    assert replay.alias == first.alias

    divergent_candidate = PromotionCandidate("candidate-2", 1, HASH_B, "owner-2", "evaluator-2")
    divergent = _decide(
        authority,
        _request(
            authority,
            candidate=divergent_candidate,
            reviewer_id="appsec-2",
        ),
        nonce="promotion-diverge-1",
    )
    with pytest.raises(PromotionRegistryError):
        registry.compare_and_set(alias="production-prompt", expected_revision=0, decision=divergent)
