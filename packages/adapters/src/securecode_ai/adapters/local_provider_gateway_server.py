"""Local provider boundary with actual policy refusal and bounded backend I/O.

Refusal belongs to this gateway provider, not to the underlying model. No
capability registry is promoted by starting this service or handling a request.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import select
import signal
import socket
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from securecode_ai.contracts import ApiDialect, ExecutionBoundary, ProviderKind, ProviderProfile

from .local_provider_gateway_backend import LoopbackOllamaBackend
from .local_provider_gateway_handler import handle_gateway_request
from .local_provider_gateway_transforms import _failure
from .local_provider_gateway_types import (
    _MAX_RESPONSE_BYTES,
    GatewayBackend,
    GatewayExchangeObservation,
    GatewayNormalizationObservation,
    GatewayPolicy,
    GatewayReply,
)

_APPROVED_BACKEND_PORT = 11434
_APPROVED_VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\Z")
_APPROVED_MODEL_DIGEST = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z")
_OBSERVATION_FILENAME = ".securecode-gateway-observation.json"
_MAX_OBSERVATION_BYTES = 65_536


class _ApprovedGatewayLifecycleError(RuntimeError):
    """The host-approved local gateway could not be started or stopped."""


def _approved_gateway_listener(profile: ProviderProfile) -> int:
    if type(profile) is not ProviderProfile:
        raise _ApprovedGatewayLifecycleError
    try:
        endpoint = urlsplit(profile.endpoint.base_url)
        port = endpoint.port
        address = ipaddress.ip_address(profile.endpoint.authority)
    except (TypeError, ValueError):
        raise _ApprovedGatewayLifecycleError from None
    if (
        profile.provider_kind is not ProviderKind.OPENAI_COMPATIBLE_LOCAL
        or profile.api_dialect is not ApiDialect.OPENAI_COMPATIBLE
        or profile.execution_boundary is not ExecutionBoundary.LOCAL_RUNNER
        or profile.credential_ref is not None
        or endpoint.scheme != "http"
        or endpoint.hostname != profile.endpoint.authority
        or profile.endpoint.authority != "127.0.0.1"
        or not address.is_loopback
        or endpoint.path != "/v1"
        or endpoint.username is not None
        or endpoint.password is not None
        or endpoint.query
        or endpoint.fragment
        or port is None
        or port not in profile.endpoint.allowed_ports
        or port == _APPROVED_BACKEND_PORT
    ):
        raise _ApprovedGatewayLifecycleError
    return port


def _approved_gateway_policy(profile: ProviderProfile, backend_version: str) -> GatewayPolicy:
    _approved_gateway_listener(profile)
    if type(backend_version) is not str or _APPROVED_VERSION.fullmatch(backend_version) is None:
        raise _ApprovedGatewayLifecycleError
    try:
        snapshot = profile.model_snapshot
        if type(snapshot) is not str:
            raise ValueError
        match = _APPROVED_MODEL_DIGEST.fullmatch(snapshot)
        if match is None:
            raise ValueError
        return GatewayPolicy(
            model_id=profile.model_id,
            model_manifest_sha256=match.group(1),
            backend_port=_APPROVED_BACKEND_PORT,
            max_output_tokens=profile.capabilities.max_output_tokens,
            timeout_seconds=profile.budgets.timeout_seconds,
            backend_version=backend_version,
        )
    except (TypeError, ValueError):
        raise _ApprovedGatewayLifecycleError from None


@contextmanager
def _running_approved_gateway(
    profile: ProviderProfile,
    backend_version: str,
    *,
    observation_path: Path | None = None,
) -> Iterator[None]:
    """Own the host-approved loopback gateway for one installed CLI scan."""
    from .public_gateway_observation import PublicGatewayExchangeRecorder

    policy = _approved_gateway_policy(profile, backend_version)
    port = _approved_gateway_listener(profile)
    recorder = PublicGatewayExchangeRecorder(policy)

    def observe_exchange(observation: GatewayExchangeObservation) -> None:
        recorder.observe(observation)
        if observation_path is not None:
            _write_gateway_observation(observation_path, recorder.snapshot_document())

    def observe_normalization(observation: GatewayNormalizationObservation) -> None:
        recorder.observe_normalization(observation)
        if observation_path is not None:
            _write_gateway_observation(observation_path, recorder.snapshot_document())

    backend = LoopbackOllamaBackend(policy, observer=observe_exchange)
    try:
        server = create_gateway_server(
            policy,
            port=port,
            backend=backend,
            normalization_observer=observe_normalization,
        )
    except Exception:
        raise _ApprovedGatewayLifecycleError from None

    server_failure = threading.Event()

    def serve() -> None:
        try:
            server.serve_forever()
        except Exception:
            server_failure.set()

    thread = threading.Thread(target=serve, name="securecode-approved-gateway", daemon=True)
    serving_state = getattr(server, "_BaseServer__is_shut_down", None)
    serving = False
    try:
        if not isinstance(serving_state, threading.Event):
            raise _ApprovedGatewayLifecycleError
        try:
            thread.start()
        except Exception:
            raise _ApprovedGatewayLifecycleError from None
        startup_deadline = time.monotonic() + 5.0
        while serving_state.is_set() and thread.is_alive() and time.monotonic() < startup_deadline:
            time.sleep(0.001)
        serving = thread.is_alive() and not serving_state.is_set()
        if not serving or server_failure.is_set():
            raise _ApprovedGatewayLifecycleError

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=policy.timeout_seconds)
        try:
            connection.request("GET", "/health/ready", headers={"Connection": "close"})
            response = connection.getresponse()
            if response.status != 200 or response.read(65) != b'{"ready":true}':
                raise _ApprovedGatewayLifecycleError
        except (OSError, http.client.HTTPException, TimeoutError):
            raise _ApprovedGatewayLifecycleError from None
        finally:
            connection.close()

        yield
        if server_failure.is_set():
            raise _ApprovedGatewayLifecycleError
    finally:
        cleanup_failed = False
        if serving:
            try:
                server.shutdown()
            except Exception:
                cleanup_failed = True
        if thread.ident is not None:
            thread.join(timeout=policy.timeout_seconds + 1.0)
        try:
            server.server_close()
        except Exception:
            cleanup_failed = True
        if observation_path is not None:
            try:
                _write_gateway_observation(observation_path, recorder.snapshot_document())
            except Exception:
                cleanup_failed = True
        if thread.is_alive():
            cleanup_failed = True
        if cleanup_failed:
            raise _ApprovedGatewayLifecycleError


class _GatewayHTTPServer(HTTPServer):
    """Restore signal ownership and stop accepting work on process SIGTERM."""

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        if threading.current_thread() is not threading.main_thread():
            super().serve_forever(poll_interval=poll_interval)
            return
        termination = getattr(signal, "SIGTERM", None)
        if termination is None:
            super().serve_forever(poll_interval=poll_interval)
            return

        previous_handler = signal.getsignal(termination)
        shutdown_thread: threading.Thread | None = None

        def request_shutdown(_signum: int, _frame: object) -> None:
            nonlocal shutdown_thread
            if shutdown_thread is not None:
                return
            shutdown_thread = threading.Thread(
                target=self.shutdown,
                name="securecode-gateway-shutdown",
                daemon=True,
            )
            shutdown_thread.start()

        signal.signal(termination, request_shutdown)
        try:
            super().serve_forever(poll_interval=poll_interval)
        finally:
            signal.signal(termination, previous_handler)
            if shutdown_thread is not None:
                shutdown_thread.join(timeout=1.0)


def create_gateway_server(
    policy: GatewayPolicy,
    *,
    port: int,
    backend: GatewayBackend | None = None,
    exchange_observer: Callable[[GatewayExchangeObservation], None] | None = None,
    normalization_observer: Callable[[GatewayNormalizationObservation], None] | None = None,
) -> HTTPServer:
    """Single bounded loopback worker; access logs never include source or keys."""
    if type(port) is not int or not 0 <= port <= 65535 or port == policy.backend_port:
        raise ValueError("invalid gateway listener")
    if exchange_observer is not None and not callable(exchange_observer):
        raise ValueError("invalid gateway exchange observer")
    if normalization_observer is not None and not callable(normalization_observer):
        raise ValueError("invalid gateway normalization observer")
    if backend is not None and exchange_observer is not None:
        raise ValueError("gateway exchange observer requires the default backend")
    dispatcher = (
        backend
        if backend is not None
        else LoopbackOllamaBackend(policy, observer=exchange_observer)
    )

    class Handler(BaseHTTPRequestHandler):
        def setup(self) -> None:
            self.request.settimeout(policy.timeout_seconds)
            super().setup()
            self._deadline = time.monotonic() + policy.timeout_seconds
            self._cancelled = threading.Event()
            self._expiry = threading.Timer(policy.timeout_seconds, self._expire)
            self._expiry.daemon = True
            self._expiry.start()

        def _expire(self) -> None:
            # Absolute ingress/response deadline also covers slow header/body trickles.
            self._cancelled.set()
            with suppress(OSError):
                self.connection.shutdown(socket.SHUT_RDWR)

        def finish(self) -> None:
            self._expiry.cancel()
            with suppress(OSError):
                super().finish()

        def log_message(self, format: str, *args: object) -> None:
            return

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            # The stdlib HTML error renderer may echo request-line details.
            # Keep malformed HTTP failures in the same fixed, non-echo format.
            status = code if code in {400, 408, 413, 429, 500, 502, 503, 504} else 400
            self._reply(_failure(status))

        def do_GET(self) -> None:
            self.connection.settimeout(policy.timeout_seconds)
            if (
                self.path != "/health/ready"
                or self.headers.get_all("Transfer-Encoding")
                or self.headers.get_all("Content-Length")
            ):
                self._health_reply(404, b'{"ready":false}')
                return
            ready = getattr(dispatcher, "ready", None)
            try:
                result = ready(timeout_seconds=policy.timeout_seconds) if callable(ready) else False
            except Exception:
                result = False
            self._health_reply(
                200 if result is True else 503,
                b'{"ready":true}' if result is True else b'{"ready":false}',
            )

        def _health_reply(self, status: int, body: bytes) -> None:
            self.close_connection = True
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

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
                monitor_stop = threading.Event()
                monitor = threading.Thread(
                    target=self._monitor_client,
                    args=(self.connection, self._cancelled, monitor_stop),
                    name="securecode-gateway-client-watch",
                    daemon=True,
                )
                monitor.start()
                try:
                    reply = handle_gateway_request(
                        body,
                        policy=policy,
                        backend=dispatcher,
                        deadline=self._deadline,
                        cancellation_event=self._cancelled,
                        normalization_observer=normalization_observer,
                    )
                except Exception:
                    reply = _failure(502, dispatched=True)
                finally:
                    monitor_stop.set()
                    monitor.join(timeout=0.2)
                self._reply(reply)
            except (OSError, ValueError):
                self.close_connection = True

        @staticmethod
        def _monitor_client(
            connection: socket.socket,
            cancelled: threading.Event,
            stop: threading.Event,
        ) -> None:
            peek = getattr(socket, "MSG_PEEK", 0)
            while not stop.wait(0.05):
                try:
                    readable, _, _ = select.select([connection], [], [], 0)
                    if not readable:
                        continue
                    if connection.recv(1, peek) == b"":
                        cancelled.set()
                    else:
                        # This endpoint closes after one request, so pipelined
                        # bytes cannot be a second supported exchange.
                        cancelled.set()
                    return
                except (OSError, ValueError):
                    cancelled.set()
                    return

        def _reply(self, reply: GatewayReply) -> None:
            if (
                type(reply) is not GatewayReply
                or type(reply.status) is not int
                or reply.status not in {200, 400, 408, 413, 429, 500, 502, 503, 504}
                or type(reply.body) is not bytes
                or len(reply.body) > _MAX_RESPONSE_BYTES
            ):
                reply = _failure(502)
            self.close_connection = True
            self.send_response(reply.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(reply.body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(reply.body)

    return _GatewayHTTPServer(("127.0.0.1", port), Handler)


def gateway_observation_path(environment: Mapping[str, str]) -> Path:
    """Resolve the local operational artifact used by installed CLI scans."""

    if not isinstance(environment, Mapping):
        raise ValueError("invalid gateway observation environment")
    configured = environment.get("SECURECODE_GATEWAY_OBSERVATION_FILE")
    if configured is not None:
        if (
            type(configured) is not str
            or not configured
            or not os.path.isabs(configured)  # noqa: PTH117  exact os.path semantics on str input
            or Path(configured).name != _OBSERVATION_FILENAME
        ):
            raise ValueError("invalid gateway observation path")
        return Path(configured)
    root = environment.get("SECURECODE_AI_ARTIFACT_ROOT")
    if root is None:
        if os.name == "nt":
            root = os.path.join(  # noqa: PTH118  root must stay a str for validation below
                environment.get("LOCALAPPDATA", ""), "SecureCodeAI", "suggestions"
            )
        else:
            root = os.path.join(  # noqa: PTH118  root must stay a str for validation below
                environment.get(
                    "XDG_DATA_HOME",
                    os.path.expanduser("~/.local/share"),  # noqa: PTH111  str default
                ),
                "securecode-ai",
                "suggestions",
            )
    if type(root) is not str or not root or not os.path.isabs(root):  # noqa: PTH117  str input
        raise ValueError("invalid gateway observation root")
    return Path(root) / _OBSERVATION_FILENAME


def _write_gateway_observation(path: Path, document: Mapping[str, object]) -> None:
    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or path.name != _OBSERVATION_FILENAME
        or not isinstance(document, Mapping)
    ):
        raise ValueError("invalid gateway observation artifact")
    encoded = (
        json.dumps(
            dict(document),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )
    if not 1 <= len(encoded) <= _MAX_OBSERVATION_BYTES:
        raise ValueError("gateway observation artifact is too large")
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or path.is_symlink():
        raise ValueError("gateway observation artifact path is unsafe")
    temporary = parent / f".{path.name}.{os.getpid()}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fsync(descriptor)
    except Exception:
        with suppress(FileNotFoundError):
            temporary.unlink()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        temporary.replace(path)
        with suppress(OSError):
            directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()
