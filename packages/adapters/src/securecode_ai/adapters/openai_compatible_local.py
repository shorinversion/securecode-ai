"""Bounded direct HTTP transport for an approved local OpenAI-compatible profile.

The connector deliberately receives only the endpoint proof supplied by the
existing provider harness.  It does not resolve names, consult proxy
configuration, follow redirects, or construct an authorization chain.
"""

from __future__ import annotations

from .openai_compatible_local_codec import CancellationProbe
from .openai_compatible_local_transport import OpenAICompatibleLocalHttpConnector, _LocalHttpChannel

OpenAICompatibleLocalHttpConnector.__module__ = __name__
_LocalHttpChannel.__module__ = __name__
__all__ = ["CancellationProbe", "OpenAICompatibleLocalHttpConnector"]
