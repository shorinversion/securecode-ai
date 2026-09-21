"""Local provider boundary with actual policy refusal and bounded backend I/O.

Refusal belongs to this gateway provider, not to the underlying model. No
capability registry is promoted by starting this service or handling a request.
"""

from __future__ import annotations

import http.client
import math
import socket
import threading
import time
from collections.abc import Callable
from contextlib import suppress

from .local_provider_gateway_transforms import (
    _canonicalize_ollama_native_chat,
    _exchange_request_sha256,
    _failure,
    _ollama_native_request,
    _operation,
)
from .local_provider_gateway_types import (
    _MAX_RESPONSE_BYTES,
    GatewayExchangeFailure,
    GatewayExchangeObservation,
    GatewayExchangePhase,
    GatewayPolicy,
    GatewayReply,
    _decode,
)


class LoopbackOllamaBackend:
    __slots__ = ("_observer", "_policy")

    def __init__(
        self,
        policy: GatewayPolicy,
        observer: Callable[[GatewayExchangeObservation], None] | None = None,
    ):
        if type(policy) is not GatewayPolicy or (observer is not None and not callable(observer)):
            raise ValueError("invalid loopback backend")
        self._policy = policy
        self._observer = observer

    def dispatch(self, body: bytes, *, timeout_seconds: float) -> GatewayReply:
        deadline = time.monotonic() + timeout_seconds
        if not self._identity_matches(deadline):
            return _failure(502)
        try:
            native_body = _ollama_native_request(body, expected_model_id=self._policy.model_id)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return _failure(502)
        generated = self._exchange(
            "POST",
            "/api/chat",
            native_body,
            deadline=deadline,
            max_bytes=_MAX_RESPONSE_BYTES,
            dispatched=True,
        )
        if generated.status != 200:
            return generated
        if not self._identity_matches(deadline):
            return _failure(502, dispatched=True)
        try:
            return GatewayReply(
                200,
                _canonicalize_ollama_native_chat(
                    generated.body, expected_model_id=self._policy.model_id
                ),
                backend_dispatched=True,
            )
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return _failure(502, dispatched=True)

    def _identity_matches(self, deadline: float) -> bool:
        try:
            version = self._exchange(
                "GET",
                "/api/version",
                None,
                deadline=deadline,
                max_bytes=65536,
                dispatched=False,
            )
            if version.status != 200 or _decode(version.body) != {
                "version": self._policy.backend_version
            }:
                return False
            tags = self._exchange(
                "GET",
                "/api/tags",
                None,
                deadline=deadline,
                max_bytes=1024 * 1024,
                dispatched=False,
            )
            if tags.status != 200:
                return False
            document = _decode(tags.body)
            models = document.get("models")
            if set(document) != {"models"} or not isinstance(models, list) or len(models) > 4096:
                return False
            matches = []
            for model in models:
                if not isinstance(model, dict):
                    return False
                if (
                    model.get("name") == self._policy.model_id
                    or model.get("model") == self._policy.model_id
                ):
                    matches.append(model)
            return (
                len(matches) == 1
                and matches[0].get("name") == self._policy.model_id
                and matches[0].get("model") == self._policy.model_id
                and matches[0].get("digest") == self._policy.model_manifest_sha256
                and time.monotonic() < deadline
            )
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return False

    def _exchange(
        self,
        method: str,
        path: str,
        body: bytes | None,
        *,
        deadline: float,
        max_bytes: int,
        dispatched: bool,
    ) -> GatewayReply:
        started = time.monotonic()
        attempted = False
        phase = GatewayExchangePhase.CONNECT
        observed_http_status: int | None = None
        received_bytes = 0
        response_overflow = False
        failure = GatewayExchangeFailure.NONE
        deadline_expired = False
        reply = _failure(502)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            reply = _failure(504, dispatched=attempted)
            deadline_expired = True
            return self._observe_exchange(
                method=method,
                path=path,
                body=body,
                started=started,
                reply=reply,
                phase=phase,
                observed_http_status=observed_http_status,
                deadline_expired=deadline_expired,
                received_bytes=received_bytes,
                response_overflow=response_overflow,
                failure=GatewayExchangeFailure.TIMEOUT,
            )
        connection = http.client.HTTPConnection(
            "127.0.0.1", self._policy.backend_port, timeout=remaining
        )
        expiry: threading.Timer | None = None
        expiry_fired = threading.Event()
        try:
            connection.connect()
            phase = GatewayExchangePhase.REQUEST
            channel = connection.sock
            if channel is None:
                raise ValueError("gateway backend unavailable")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError

            def expire_backend() -> None:
                expiry_fired.set()
                with suppress(OSError):
                    channel.shutdown(socket.SHUT_RDWR)

            expiry = threading.Timer(remaining, expire_backend)
            expiry.daemon = True
            expiry.start()
            channel.settimeout(remaining)
            attempted = dispatched
            connection.request(
                method,
                path,
                body=body,
                headers={"Content-Type": "application/json", "Connection": "close"},
            )
            channel.settimeout(max(0.001, deadline - time.monotonic()))
            phase = GatewayExchangePhase.HEADERS
            response = connection.getresponse()
            observed_http_status = response.status
            if response.status != 200:
                status = (
                    response.status
                    if response.status in (408, 413, 429, 500, 502, 503, 504)
                    else 502
                )
                reply = _failure(status, dispatched=attempted)
            else:
                chunks = []
                size = 0
                while True:
                    if response.isclosed():
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    channel.settimeout(remaining)
                    phase = GatewayExchangePhase.BODY
                    chunk = response.read1(min(65536, max_bytes + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    received_bytes = size
                    if size > max_bytes:
                        response_overflow = True
                        raise ValueError("gateway backend response exceeds budget")
                    chunks.append(chunk)
                if time.monotonic() > deadline:
                    raise TimeoutError
                phase = GatewayExchangePhase.COMPLETE
                reply = GatewayReply(200, b"".join(chunks), backend_dispatched=attempted)
        except TimeoutError:
            deadline_expired = True
            failure = GatewayExchangeFailure.TIMEOUT
            reply = _failure(504, dispatched=attempted)
        except (OSError, ValueError, http.client.HTTPException):
            failure = GatewayExchangeFailure.TRANSPORT
            reply = _failure(502, dispatched=attempted)
        finally:
            if expiry is not None:
                expiry.cancel()
            connection.close()
            with suppress(OverflowError, ValueError):
                deadline_expired = (
                    deadline_expired or expiry_fired.is_set() or time.monotonic() >= deadline
                )
            if deadline_expired:
                failure = GatewayExchangeFailure.TIMEOUT
            reply = self._observe_exchange(
                method=method,
                path=path,
                body=body,
                started=started,
                reply=reply,
                phase=phase,
                observed_http_status=observed_http_status,
                deadline_expired=deadline_expired,
                received_bytes=received_bytes,
                response_overflow=response_overflow,
                failure=failure,
            )
        return reply

    def _observe_exchange(
        self,
        *,
        method: str,
        path: str,
        body: bytes | None,
        started: float,
        reply: GatewayReply,
        phase: GatewayExchangePhase,
        observed_http_status: int | None,
        deadline_expired: bool,
        received_bytes: int,
        response_overflow: bool,
        failure: GatewayExchangeFailure,
    ) -> GatewayReply:
        observer = self._observer
        if observer is None:
            return reply
        elapsed_ms: int | None
        try:
            elapsed = time.monotonic() - started
            if not math.isfinite(elapsed) or elapsed < 0:
                raise ValueError
            elapsed_ms = int(elapsed * 1000)
        except (OverflowError, ValueError):
            elapsed_ms = None
        try:
            observer(
                GatewayExchangeObservation(
                    policy_sha256=self._policy.content_sha256,
                    request_sha256=_exchange_request_sha256(method, path, body),
                    operation=_operation(method, path),
                    phase=phase,
                    mapped_status=reply.status,
                    observed_http_status=observed_http_status,
                    elapsed_known=elapsed_ms is not None,
                    elapsed_ms=elapsed_ms,
                    deadline_expired=deadline_expired,
                    backend_dispatched=reply.backend_dispatched,
                    received_bytes=received_bytes,
                    response_overflow=response_overflow,
                    failure=failure,
                )
            )
        except Exception:
            if reply.status == 200:
                return _failure(502, dispatched=reply.backend_dispatched)
        return reply
