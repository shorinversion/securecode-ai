"""Bounded hardcoded-secret detection with value-free retained results."""

from __future__ import annotations

from .secret_detection_models import (
    DEFAULT_SECRET_DETECTION_LIMITS,
    ApprovedExternalSecretScanner,
    ExternalSecretDetection,
    ExternalSecretScanRequest,
    ExternalSecretScanResponse,
    SecretCandidate,
    SecretDetectionError,
    SecretDetectionErrorCode,
    SecretDetectionLimits,
    SecretFingerprintKey,
    SecretKind,
    SecretProducer,
    SecretScanResult,
)
from .secret_detection_scan import scan_secrets

for _secret_type in (
    SecretDetectionError,
    SecretDetectionLimits,
    SecretFingerprintKey,
    ExternalSecretDetection,
    ExternalSecretScanRequest,
    ExternalSecretScanResponse,
    SecretCandidate,
    SecretScanResult,
):
    _secret_type.__module__ = __name__
del _secret_type
__all__ = [
    "DEFAULT_SECRET_DETECTION_LIMITS",
    "ApprovedExternalSecretScanner",
    "ExternalSecretDetection",
    "ExternalSecretScanRequest",
    "ExternalSecretScanResponse",
    "SecretCandidate",
    "SecretDetectionError",
    "SecretDetectionErrorCode",
    "SecretDetectionLimits",
    "SecretFingerprintKey",
    "SecretKind",
    "SecretProducer",
    "SecretScanResult",
    "scan_secrets",
]
