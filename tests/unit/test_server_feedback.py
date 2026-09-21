from securecode_ai.server.feedback_repository import FeedbackRepository
from securecode_ai.server.feedback_service import FeedbackService


def test_feedback_has_hashed_rationale_only() -> None:
    value = FeedbackService(FeedbackRepository.in_memory()).submit(
        allowed=True,
        tenant_id="t",
        repository_id="r",
        run_id="run",
        finding_id="f",
        head_sha="a" * 40,
        identity_hash="b" * 64,
        decision="reject",
        reason="false_positive",
        rationale="reason",
    )
    assert "reason" not in repr(value.rationale_sha256)
