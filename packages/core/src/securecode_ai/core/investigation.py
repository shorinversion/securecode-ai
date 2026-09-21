"""Bounded, fail-closed Auditor investigation orchestration.

This module consumes the metadata-only P3.1 context and P3.2 parsed Auditor
contract.  It deliberately has no model transport, repository handle, route
selector, filesystem access, or raw output retention.  The host owns all
budgets; a provider can supply only a typed invocation result and a read-only
context port can supply only a next :class:`EvidencePackage`.
"""

from __future__ import annotations

from securecode_ai.contracts import (
    FindingVerdict as FindingVerdict,
)
from securecode_ai.contracts import (
    ModelCallStatus as ModelCallStatus,
)

from .auditor import AuditorResponse as AuditorResponse
from .evidence_package import EvidencePackage as EvidencePackage
from .investigation_models import (
    AuditorAttemptReceipt,
    AuditorInvestigationReceipt,
    AuditorInvocation,
    AuditorInvoker,
    InvestigationBudget,
    InvestigationDisposition,
    InvestigationError,
    InvestigationErrorCode,
    InvestigationStopReason,
    ReadOnlyEvidenceContext,
)
from .investigation_runner import run_auditor_investigation

for _investigation_type in (
    InvestigationError,
    InvestigationBudget,
    AuditorInvocation,
    ReadOnlyEvidenceContext,
    AuditorAttemptReceipt,
    AuditorInvestigationReceipt,
):
    _investigation_type.__module__ = __name__
del _investigation_type
__all__ = [
    "AuditorAttemptReceipt",
    "AuditorInvestigationReceipt",
    "AuditorInvocation",
    "AuditorInvoker",
    "InvestigationBudget",
    "InvestigationDisposition",
    "InvestigationError",
    "InvestigationErrorCode",
    "InvestigationStopReason",
    "ReadOnlyEvidenceContext",
    "run_auditor_investigation",
]
