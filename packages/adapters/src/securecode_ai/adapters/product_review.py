"""Candidate-local Skeptic and Finding Gate composition for a product flow."""

from __future__ import annotations

from .product_review_contracts import (
    ProductCandidateReviewOutcome,
    ProductReviewFailureCode,
    ProductReviewResult,
    SkepticInvocation,
    SkepticReviewPort,
)
from .product_review_execution import run_product_candidate_review

for _review_type in (
    ProductReviewFailureCode,
    SkepticInvocation,
    SkepticReviewPort,
    ProductCandidateReviewOutcome,
    ProductReviewResult,
):
    _review_type.__module__ = __name__
del _review_type

__all__ = [
    "ProductCandidateReviewOutcome",
    "ProductReviewFailureCode",
    "ProductReviewResult",
    "SkepticInvocation",
    "SkepticReviewPort",
    "run_product_candidate_review",
]
