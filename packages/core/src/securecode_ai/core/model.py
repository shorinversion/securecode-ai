"""Framework-independent model and egress policy boundary behavior."""

from __future__ import annotations

from .core_model_authorizations import PreContextAuthorization, PreSendAuthorization
from .core_model_issuer import ModelAuthorizationIssuer
from .core_model_protocols import (
    ApprovedProviderRegistry,
    AuthorizationError,
    EgressPolicyEvaluator,
    EgressPolicyRegistry,
    EphemeralModelPayload,
    ModelProvider,
    ModelProviderResult,
    PayloadValidation,
    StructuredPayloadValidator,
    canonical_model_request_hash,
)

for _model_type in (
    ApprovedProviderRegistry,
    PayloadValidation,
    StructuredPayloadValidator,
    EphemeralModelPayload,
    ModelProviderResult,
    ModelProvider,
    EgressPolicyEvaluator,
    AuthorizationError,
    EgressPolicyRegistry,
    PreContextAuthorization,
    PreSendAuthorization,
    ModelAuthorizationIssuer,
):
    _model_type.__module__ = __name__
del _model_type

__all__ = [
    "ApprovedProviderRegistry",
    "AuthorizationError",
    "EgressPolicyEvaluator",
    "EgressPolicyRegistry",
    "EphemeralModelPayload",
    "ModelAuthorizationIssuer",
    "ModelProvider",
    "ModelProviderResult",
    "PayloadValidation",
    "PreContextAuthorization",
    "PreSendAuthorization",
    "StructuredPayloadValidator",
    "canonical_model_request_hash",
]
