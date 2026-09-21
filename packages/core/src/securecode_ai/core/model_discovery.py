"""Mandatory, bounded model-native discovery over an immutable RepositoryView."""

from __future__ import annotations

from securecode_ai.contracts import ModelDiscoveryReceipt as ModelDiscoveryReceipt
from securecode_ai.contracts import ModelPurpose as ModelPurpose
from securecode_ai.contracts import ModelRole as ModelRole

from .model_discovery_contracts import (
    ModelNativeCandidateDraft,
    ModelNativeDiscoveryBackend,
    ModelNativeDiscoveryError,
    ModelNativeDiscoveryErrorCode,
    ModelNativeDiscoveryOutcome,
    ModelNativeDiscoveryPayload,
    ModelNativeDiscoveryPlan,
    RepositoryToolSession,
)
from .model_discovery_runner import (
    _ReceiptSession,
    run_model_native_discovery,
)

for _discovery_type in (
    ModelNativeDiscoveryErrorCode,
    ModelNativeDiscoveryError,
    ModelNativeCandidateDraft,
    ModelNativeDiscoveryPayload,
    ModelNativeDiscoveryBackend,
    ModelNativeDiscoveryPlan,
    RepositoryToolSession,
    ModelNativeDiscoveryOutcome,
    _ReceiptSession,
):
    _discovery_type.__module__ = __name__
del _discovery_type

__all__ = [
    "ModelNativeCandidateDraft",
    "ModelNativeDiscoveryBackend",
    "ModelNativeDiscoveryError",
    "ModelNativeDiscoveryErrorCode",
    "ModelNativeDiscoveryOutcome",
    "ModelNativeDiscoveryPayload",
    "ModelNativeDiscoveryPlan",
    "RepositoryToolSession",
    "run_model_native_discovery",
]
