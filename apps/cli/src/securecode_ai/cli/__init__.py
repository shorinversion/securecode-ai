"""SecureCode AI CLI composition boundary."""

from .application import (
    FOUNDATION_PROFILE_CONTENT_SHA256,
    FOUNDATION_PROFILE_SELECTOR,
    FoundationDoctor,
    build_foundation_profile,
    main,
)
from .approval import run_patch_approval_command
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
from .release import ReleaseCliError, run_release_command
from .repair import RepairCli, RepairFormat, RepairOutcome, RepairReceipt, render_receipt

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
    "ReleaseCliError",
    "RepairCli",
    "RepairFormat",
    "RepairOutcome",
    "RepairReceipt",
    "UnavailableDeterministicDiagnostic",
    "build_foundation_profile",
    "canonical_diagnostic_json",
    "main",
    "render_receipt",
    "run_deterministic_diagnostic",
    "run_patch_approval_command",
    "run_release_command",
]
