"""Local provider boundary with actual policy refusal and bounded backend I/O.

Refusal belongs to this gateway provider, not to the underlying model. No
capability registry is promoted by starting this service or handling a request.
"""

from __future__ import annotations

import http as http
import threading as threading
import time as time

from .local_provider_gateway_backend import LoopbackOllamaBackend
from .local_provider_gateway_handler import handle_gateway_request
from .local_provider_gateway_server import create_gateway_server
from .local_provider_gateway_transforms import (
    _canonicalize_native_reply as _canonicalize_native_reply,
)
from .local_provider_gateway_transforms import (
    _canonicalize_ollama_native_chat as _canonicalize_ollama_native_chat,
)
from .local_provider_gateway_transforms import (
    _ollama_native_request as _ollama_native_request,
)
from .local_provider_gateway_transforms import (
    _validate_native_transcript as _validate_native_transcript,
)
from .local_provider_gateway_types import (
    GatewayBackend,
    GatewayBudgetMode,
    GatewayExchangeFailure,
    GatewayExchangeObservation,
    GatewayExchangeOperation,
    GatewayExchangePhase,
    GatewayNativeArgumentsShape,
    GatewayNativeEnvelopeShape,
    GatewayNormalizationObservation,
    GatewayPolicy,
    GatewayReply,
    GatewayResponseNormalization,
)

for _gateway_type in (
    GatewayBudgetMode,
    GatewayExchangeFailure,
    GatewayExchangeObservation,
    GatewayExchangeOperation,
    GatewayExchangePhase,
    GatewayNativeArgumentsShape,
    GatewayNativeEnvelopeShape,
    GatewayNormalizationObservation,
    GatewayPolicy,
    GatewayReply,
    GatewayResponseNormalization,
    LoopbackOllamaBackend,
):
    _gateway_type.__module__ = __name__
del _gateway_type

__all__ = [
    "GatewayBackend",
    "GatewayBudgetMode",
    "GatewayExchangeFailure",
    "GatewayExchangeObservation",
    "GatewayExchangeOperation",
    "GatewayExchangePhase",
    "GatewayNativeArgumentsShape",
    "GatewayNativeEnvelopeShape",
    "GatewayNormalizationObservation",
    "GatewayPolicy",
    "GatewayReply",
    "GatewayResponseNormalization",
    "LoopbackOllamaBackend",
    "create_gateway_server",
    "handle_gateway_request",
]
