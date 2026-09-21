"""Hermetic provider adapter, native-dialect normalization and ephemeral payloads."""

from __future__ import annotations

from securecode_ai.core import (
    PayloadValidation,
    StructuredPayloadValidator,
)

from .model_fake import ScriptedFakeProvider
from .model_harness import (
    AuthorizedProviderHarness,
    ContextBuilder,
    CredentialSupplier,
)
from .model_normalization import normalize_provider_attempt
from .model_parsing import (
    parse_model_call_result,
    parse_model_request,
)
from .model_types import (
    ConnectedChannel,
    EphemeralStructuredPayload,
    HmacContentIdentifier,
    JsonObjectValidator,
    ModelBoundaryError,
    ModelBoundaryExecution,
    NativeTurnBoundaryExecution,
    NormalizedModelAttempt,
    PreparedModelContext,
    ProviderAttempt,
    ProviderAttemptBinding,
    ProviderStreamState,
    TransportFailure,
)

__all__ = [
    "AuthorizedProviderHarness",
    "ConnectedChannel",
    "ContextBuilder",
    "CredentialSupplier",
    "EphemeralStructuredPayload",
    "HmacContentIdentifier",
    "JsonObjectValidator",
    "ModelBoundaryError",
    "ModelBoundaryExecution",
    "NativeTurnBoundaryExecution",
    "NormalizedModelAttempt",
    "PayloadValidation",
    "PreparedModelContext",
    "ProviderAttempt",
    "ProviderAttemptBinding",
    "ProviderStreamState",
    "ScriptedFakeProvider",
    "StructuredPayloadValidator",
    "TransportFailure",
    "normalize_provider_attempt",
    "parse_model_call_result",
    "parse_model_request",
]
