"""Authorization boundary and aggregate metrics for AppSec feedback."""

from __future__ import annotations

import hashlib

from .feedback_repository import Feedback, FeedbackConflict, FeedbackRepository


class FeedbackService:
    def __init__(self, repo: FeedbackRepository) -> None:
        if type(repo) is not FeedbackRepository:
            raise TypeError("repo must be a FeedbackRepository")
        self._repo = repo

    @property
    def repo(self) -> FeedbackRepository:
        """Compatibility accessor for existing composition code."""

        return self._repo

    def submit(
        self,
        *,
        allowed: bool,
        tenant_id: str,
        repository_id: str,
        run_id: str,
        finding_id: str,
        head_sha: str,
        identity_hash: str,
        decision: str,
        reason: str,
        rationale: str,
        incident_id: str | None = None,
        expected_version: int = 0,
    ) -> Feedback:
        if allowed is not True or not _safe_rationale(rationale):
            raise FeedbackConflict()
        rationale_sha256 = hashlib.sha256(
            b"securecode-ai/feedback-rationale/v1\x00" + rationale.encode("utf-8")
        ).hexdigest()
        value = Feedback(
            tenant_id=tenant_id,
            repository_id=repository_id,
            run_id=run_id,
            finding_id=finding_id,
            head_sha=head_sha,
            identity_hash=identity_hash,
            decision=decision,
            reason=reason,
            rationale_sha256=rationale_sha256,
            incident_id=incident_id,
        )
        return self._repo.save(value, expected_version=expected_version)

    def metrics(self, tenant_id: str, repository_id: str) -> dict[str, object]:
        values = self._repo.list(tenant_id, repository_id)
        reason_counts = {
            reason: sum(value.reason == reason for value in values)
            for reason in (
                "accepted_risk",
                "false_positive",
                "incident",
                "patch_rejected",
            )
        }
        return {
            "tenant_id": tenant_id,
            "repository_id": repository_id,
            "count": len(values),
            "accepted": sum(value.decision == "accept" for value in values),
            "rejected": sum(value.decision == "reject" for value in values),
            "incidents": sum(value.incident_id is not None for value in values),
            "reason_counts": reason_counts,
            "receipt_hashes": tuple(value.receipt_sha256 for value in values),
        }


def _safe_rationale(value: object) -> bool:
    if not (
        type(value) is str
        and 1 <= len(value) <= 1024
        and not value.isspace()
        and "\x00" not in value
    ):
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


__all__ = ["FeedbackService"]
