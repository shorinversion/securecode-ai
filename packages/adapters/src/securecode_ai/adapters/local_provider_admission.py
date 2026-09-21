"""Receipt-bound host admission, not runtime attestation or repository authority.

Only trusted host composition may construct ``TrustedLocalProviderAdmission``
and supply independently reviewed pins. Receipt imports cannot construct that
authority or change its approved hashes. No keys or network effects exist here.
"""

from __future__ import annotations

from .local_provider_admission_models import (
    AdmissionBindings,
    AuditorCandidateEvidence,
    AuditorInvocationEvidence,
    CapabilityCase,
    CapabilityEvidence,
    CoreCase,
    CoreConformanceEvidence,
    EvidenceOrigin,
    HostAdmissionPins,
    LocalProviderAdmissionError,
    LocalProviderEvidenceBundle,
    NativeToolEvidence,
    ReviewedLocalProviderEvidence,
    TrustedLocalProviderAdmission,
    auditor_selection_sha256,
    evidence_receipt_sha256,
)
from .local_provider_admission_models import (
    _digest as _digest,
)

for _admission_type in (
    LocalProviderAdmissionError,
    AdmissionBindings,
    HostAdmissionPins,
    CapabilityEvidence,
    NativeToolEvidence,
    AuditorInvocationEvidence,
    AuditorCandidateEvidence,
    CoreConformanceEvidence,
    LocalProviderEvidenceBundle,
    ReviewedLocalProviderEvidence,
    TrustedLocalProviderAdmission,
):
    _admission_type.__module__ = __name__
del _admission_type
__all__ = [
    "AdmissionBindings",
    "AuditorCandidateEvidence",
    "AuditorInvocationEvidence",
    "CapabilityCase",
    "CapabilityEvidence",
    "CoreCase",
    "CoreConformanceEvidence",
    "EvidenceOrigin",
    "HostAdmissionPins",
    "LocalProviderAdmissionError",
    "LocalProviderEvidenceBundle",
    "NativeToolEvidence",
    "ReviewedLocalProviderEvidence",
    "TrustedLocalProviderAdmission",
    "auditor_selection_sha256",
    "evidence_receipt_sha256",
]
