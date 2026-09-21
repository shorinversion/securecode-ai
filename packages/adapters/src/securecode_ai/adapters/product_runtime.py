"""Authorized product-model ports built on the existing provider harness."""

from __future__ import annotations

from .product_model import MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON
from .product_runtime_auditor import (
    ProductAuditorInvocationObservation,
    ProductAuditorInvoker,
)
from .product_runtime_contracts import (
    _AUDITOR_INSTRUCTIONS as _AUDITOR_INSTRUCTIONS,
)
from .product_runtime_contracts import (
    _DISCOVERY_INSTRUCTIONS as _DISCOVERY_INSTRUCTIONS,
)
from .product_runtime_contracts import (
    PRODUCT_AUDITOR_PROMPT_PIN,
    PRODUCT_DISCOVERY_PROMPT_PIN,
    DiscoveryEvidence,
    EvidenceResolver,
    GuardedEvidenceResolver,
    NativeCycleBudget,
    ProductDiscoveryInvocationObservation,
    RepositoryContextBudgetExhausted,
    ResolvedModelEvidence,
    native_turn_request,
)
from .product_runtime_contracts import (
    _prompt_pin as _prompt_pin,
)
from .product_runtime_contracts import (
    _snapshot_evidence_catalogue as _snapshot_evidence_catalogue,
)
from .product_runtime_discovery import ProductDiscoveryBackend
from .product_runtime_execution import (
    AuthorizedLocalModelExecutor,
)
from .product_runtime_execution import (
    _context as _context,
)
from .product_runtime_execution import (
    _non_success_result as _non_success_result,
)
from .product_runtime_execution import (
    _result_with_calls as _result_with_calls,
)
from .product_runtime_native import (
    dispatch_native_repository_calls,
    native_repository_history,
)
from .product_runtime_support import _draft as _draft

__all__ = [
    "MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON",
    "PRODUCT_AUDITOR_PROMPT_PIN",
    "PRODUCT_DISCOVERY_PROMPT_PIN",
    "AuthorizedLocalModelExecutor",
    "DiscoveryEvidence",
    "EvidenceResolver",
    "GuardedEvidenceResolver",
    "NativeCycleBudget",
    "ProductAuditorInvocationObservation",
    "ProductAuditorInvoker",
    "ProductDiscoveryBackend",
    "ProductDiscoveryInvocationObservation",
    "RepositoryContextBudgetExhausted",
    "ResolvedModelEvidence",
    "dispatch_native_repository_calls",
    "native_repository_history",
    "native_turn_request",
]
