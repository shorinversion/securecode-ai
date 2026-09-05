"""SecureCode AI CLI composition boundary."""

from .application import (
    FOUNDATION_PROFILE_CONTENT_SHA256,
    FOUNDATION_PROFILE_SELECTOR,
    FoundationDoctor,
    build_foundation_profile,
    main,
)
from .diagnostic import (
    DIAGNOSTIC_RESULT_VERSION,
    DeterministicDiagnostic,
    DiagnosticError,
    DiagnosticErrorCode,
    DiagnosticFacts,
    DiagnosticFactsStatus,
    DiagnosticFormat,
    DiagnosticResult,
    LocalDeterministicDiagnostic,
    UnavailableDeterministicDiagnostic,
    canonical_diagnostic_json,
    run_deterministic_diagnostic,
)

__all__ = [
    "DIAGNOSTIC_RESULT_VERSION",
    "FOUNDATION_PROFILE_CONTENT_SHA256",
    "FOUNDATION_PROFILE_SELECTOR",
    "DeterministicDiagnostic",
    "DiagnosticError",
    "DiagnosticErrorCode",
    "DiagnosticFacts",
    "DiagnosticFactsStatus",
    "DiagnosticFormat",
    "DiagnosticResult",
    "FoundationDoctor",
    "LocalDeterministicDiagnostic",
    "UnavailableDeterministicDiagnostic",
    "build_foundation_profile",
    "canonical_diagnostic_json",
    "main",
    "run_deterministic_diagnostic",
]
