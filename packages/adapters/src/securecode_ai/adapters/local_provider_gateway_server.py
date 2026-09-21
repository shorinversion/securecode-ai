"""Local provider boundary with actual policy refusal and bounded backend I/O.

Refusal belongs to this gateway provider, not to the underlying model. No
capability registry is promoted by starting this service or handling a request.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, HTTPServer

from .local_provider_gateway_backend import LoopbackOllamaBackend
from .local_provider_gateway_handler import handle_gateway_request
from .local_provider_gateway_transforms import _failure
from .local_provider_gateway_types import (
    GatewayBackend,
    GatewayNormalizationObservation,
    GatewayPolicy,
    GatewayReply,
)


def create_gateway_server(
    policy: GatewayPolicy,
    *,
    port: int,
    backend: GatewayBackend | None = None,
    normalization_observer: Callable[[GatewayNormalizationObservation], None] | None = None,
) -> HTTPServer:
    """Single bounded loopback worker; access logs never include source or keys."""
    if type(port) is not int or not 0 <= port <= 65535 or port == policy.backend_port:
        raise ValueError("invalid gateway listener")
    if normalization_observer is not None and not callable(normalization_observer):
        raise ValueError("invalid gateway normalization observer")
    dispatcher = backend if backend is not None else LoopbackOllamaBackend(policy)

    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            self.request.settimeout(policy.timeout_seconds)
            super().setup()
            self._deadline = time.monotonic() + policy.timeout_seconds
            self._expiry = threading.Timer(policy.timeout_seconds, self._expire)
            self._expiry.daemon = True
            self._expiry.start()

        def _expire(self) -> None:
            # Absolute ingress/response deadline also covers slow header/body trickles.
            with suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)

        def finish(self) -> None:
            self._expiry.cancel()
            with suppress(OSError):
                super().finish()

        def log_message(self, format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            self.connection.settimeout(policy.timeout_seconds)
            if self.path != "/v1/chat/completions" or self.headers.get_all("Transfer-Encoding"):
                self._reply(_failure(400))
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (
                len(lengths) != 1
                or len(lengths[0]) > 10
                or not lengths[0].isascii()
                or not lengths[0].isdecimal()
            ):
                self._reply(_failure(400))
                return
            size = int(lengths[0])
            if not 0 < size <= policy.max_request_bytes:
                self._reply(_failure(413))
                return
            try:
                body = self.rfile.read(size)
                if len(body) != size:
                    self._reply(_failure(400))
                    return
                self._reply(
                    handle_gateway_request(
                        body,
                        policy=policy,
                        backend=dispatcher,
                        deadline=self._deadline,
                        normalization_observer=normalization_observer,
                    )
                )
            except (OSError, ValueError):
                self.close_connection = True

        def _reply(self, reply: GatewayReply) -> None:
            self.close_connection = True
            self.send_response(reply.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply.body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(reply.body)

    return HTTPServer(("127.0.0.1", port), Handler)
