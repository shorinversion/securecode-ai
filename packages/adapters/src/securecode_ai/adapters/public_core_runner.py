"""Public synthetic-Core composition through the existing authorization boundary.

This module composes the existing Core ports. Without an injected transport,
run_public_core_case can invoke the configured local provider. An injected
transport remains SIMULATED; this module never qualifies or admits a provider.
"""

from __future__ import annotations

from collections.abc import Callable

from .endpoint import Resolver
from .model import CredentialSupplier
from .remote_provider_budget import RemoteProviderBudgetPort, RemoteProviderCostReceipt
from .openai_compatible_local import OpenAICompatibleLocalHttpConnector
from .product_runtime import AuthorizedLocalModelExecutor
from .public_core_fixtures import build_public_core_fixture as build_public_core_fixture
from .public_core_runner_composition import (
    _executor as _compose_executor,
)
from .public_core_runner_composition import (
    _investigation_budget as _investigation_budget,
)
from .public_core_runner_composition import (
    preflight_public_core_case,
    prepare_public_core_case,
)
from .public_core_runner_loader import (
    load_public_core_inputs,
)
from .public_core_runner_primitives import (
    PinnedLiteralLoopbackResolver,
    PreparedPublicCoreCase,
    PublicCoreArtifactPins,
    PublicCoreDiagnosticSampling,
    PublicCoreHostInputs,
    PublicCoreRunnerError,
    PublicCoreRunResult,
    SystemPublicResolver,
)
from .public_core_runner_runner import run_public_core_case
from .public_discovery_observation import (
    PublicDiscoveryObservationRecorder as PublicDiscoveryObservationRecorder,
)


def _executor(
    *,
    inputs: PublicCoreHostInputs,
    connector: object,
    native: bool,
    resolver: Resolver | None = None,
    credential_supplier: CredentialSupplier | None = None,
    spend_budget: RemoteProviderBudgetPort | None = None,
    cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
) -> AuthorizedLocalModelExecutor:
    """Build an executor while retaining the historical patchable boundary."""

    return _compose_executor(
        inputs=inputs,
        connector=connector,
        native=native,
        resolver=resolver,
        credential_supplier=credential_supplier,
        spend_budget=spend_budget,
        cost_observer=cost_observer,
        connector_factory=OpenAICompatibleLocalHttpConnector,
    )


for _public_core_type in (
    PublicCoreRunnerError,
    PublicCoreDiagnosticSampling,
    PublicCoreArtifactPins,
    PublicCoreHostInputs,
    PinnedLiteralLoopbackResolver,
    SystemPublicResolver,
    PreparedPublicCoreCase,
    PublicCoreRunResult,
):
    _public_core_type.__module__ = __name__
del _public_core_type
__all__ = [
    "PinnedLiteralLoopbackResolver",
    "PreparedPublicCoreCase",
    "PublicCoreArtifactPins",
    "PublicCoreDiagnosticSampling",
    "PublicCoreHostInputs",
    "PublicCoreRunResult",
    "PublicCoreRunnerError",
    "SystemPublicResolver",
    "load_public_core_inputs",
    "preflight_public_core_case",
    "prepare_public_core_case",
    "run_public_core_case",
]
