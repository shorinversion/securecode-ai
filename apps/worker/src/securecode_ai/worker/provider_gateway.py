"""Fail-closed entrypoint for the admitted local provider gateway.

The gateway is an installed worker boundary.  Its model, runtime identity and
listener address come only from the protected host anchor and verified image.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import threading
from collections.abc import Sequence
from contextlib import suppress
from pathlib import Path
from typing import Final, TextIO
from urllib.parse import urlsplit

from securecode_ai.adapters.local_product_host import LocalProductHost, load_local_product_host
from securecode_ai.adapters.local_provider_gateway import (
    GatewayExchangeObservation,
    GatewayNormalizationObservation,
    GatewayPolicy,
    GatewayReply,
    create_gateway_server,
)
from securecode_ai.adapters.local_provider_gateway_backend import LoopbackOllamaBackend
from securecode_ai.adapters.local_provider_gateway_server import (
    _write_gateway_observation,
    gateway_observation_path,
)
from securecode_ai.adapters.public_gateway_observation import PublicGatewayExchangeRecorder
from securecode_ai.contracts import ApiDialect, ExecutionBoundary, ProviderKind, ProviderProfile

_BACKEND_PORT: Final = 11434
_OLLAMA_EXECUTABLE: Final = Path("/run/securecode/ollama")
_VERSION: Final = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\Z")
_DIGEST: Final = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z")
_MAX_RUNTIME_BINARY_BYTES: Final = 536_870_912
_O_CLOEXEC: Final = getattr(os, "O_CLOEXEC", 0)
_O_DIRECTORY: Final = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_HELP: Final = """usage: python -m securecode_ai.worker.provider_gateway [--ready]

Start the admitted loopback provider gateway.  --ready validates the approved
backend version and model digest, then exits without starting a listener.
"""


class _GatewayConfigurationError(ValueError):
    """Closed configuration failure that never carries input values."""


class _TenantBoundGatewayBackend:
    """Keep loopback model requests bound to the admitted host tenant."""

    __slots__ = ("_backend", "_tenant_id")

    def __init__(self, backend: object, *, tenant_id: str) -> None:
        if (
            not callable(getattr(backend, "dispatch", None))
            or not isinstance(tenant_id, str)
            or not tenant_id
        ):
            raise _GatewayConfigurationError
        self._backend = backend
        self._tenant_id = tenant_id

    def ready(self, *, timeout_seconds: float) -> bool:
        ready = getattr(self._backend, "ready", None)
        return bool(callable(ready) and ready(timeout_seconds=timeout_seconds) is True)

    def dispatch(self, body: bytes, *, timeout_seconds: float) -> GatewayReply:
        if not self._tenant_matches(body):
            return _tenant_rejection()
        return self._backend.dispatch(body, timeout_seconds=timeout_seconds)

    def dispatch_with_cancellation(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        cancellation_event: threading.Event,
    ) -> GatewayReply:
        if not self._tenant_matches(body):
            return _tenant_rejection()
        dispatch = getattr(self._backend, "dispatch_with_cancellation", None)
        if callable(dispatch):
            return dispatch(
                body,
                timeout_seconds=timeout_seconds,
                cancellation_event=cancellation_event,
            )
        return self._backend.dispatch(body, timeout_seconds=timeout_seconds)

    def _tenant_matches(self, body: bytes) -> bool:
        if type(body) is not bytes or not body:
            return False
        try:
            request = json.loads(body.decode("utf-8"), object_pairs_hook=_closed_object)
            messages = request.get("messages") if type(request) is dict else None
            first = messages[0] if type(messages) is list and messages else None
            content = first.get("content") if type(first) is dict else None
            context = (
                json.loads(content, object_pairs_hook=_closed_object)
                if type(content) is str
                else None
            )
            controls = context.get("trusted_controls") if type(context) is dict else None
            revision = controls.get("source_revision") if type(controls) is dict else None
            return type(revision) is dict and revision.get("tenant_id") == self._tenant_id
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
            return False


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate gateway field")
        document[key] = value
    return document


def _tenant_rejection() -> GatewayReply:
    return GatewayReply(400, b'{"error":"gateway tenant binding rejected"}')


def _approved_host() -> LocalProductHost:
    try:
        host = load_local_product_host()
        profile = host.profile
    except Exception:
        raise _GatewayConfigurationError from None
    if (
        type(profile) is not ProviderProfile
        or profile.provider_kind is not ProviderKind.OPENAI_COMPATIBLE_LOCAL
        or profile.api_dialect is not ApiDialect.OPENAI_COMPATIBLE
        or profile.execution_boundary is not ExecutionBoundary.LOCAL_RUNNER
        or profile.credential_ref is not None
    ):
        raise _GatewayConfigurationError
    return host


def _approved_listener(profile: ProviderProfile) -> int:
    try:
        endpoint = urlsplit(profile.endpoint.base_url)
        port = endpoint.port
    except (TypeError, ValueError):
        raise _GatewayConfigurationError from None
    try:
        address = ipaddress.ip_address(profile.endpoint.authority)
    except ValueError:
        raise _GatewayConfigurationError from None
    if (
        endpoint.scheme != "http"
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
        or port == _BACKEND_PORT
    ):
        raise _GatewayConfigurationError
    return port


def _policy(profile: ProviderProfile, backend_version: str) -> GatewayPolicy:
    _approved_listener(profile)
    if type(backend_version) is not str or _VERSION.fullmatch(backend_version) is None:
        raise _GatewayConfigurationError
    try:
        snapshot = profile.model_snapshot
        if type(snapshot) is not str:
            raise ValueError
        match = _DIGEST.fullmatch(snapshot)
        if match is None:
            raise ValueError
        return GatewayPolicy(
            model_id=profile.model_id,
            model_manifest_sha256=match.group(1),
            backend_port=_BACKEND_PORT,
            max_output_tokens=profile.capabilities.max_output_tokens,
            timeout_seconds=profile.budgets.timeout_seconds,
            backend_version=backend_version,
        )
    except (TypeError, ValueError):
        raise _GatewayConfigurationError from None


def _verify_runtime_binary(expected_sha256: str) -> None:
    """Require the exact host-admitted Ollama executable mounted read-only."""
    descriptor = -1
    parent = -1
    try:
        match = _DIGEST.fullmatch(expected_sha256)
        parts = _OLLAMA_EXECUTABLE.parts
        if (
            match is None
            or not parts
            or parts[0] != os.sep
            or len(parts) < 2
            or not _O_CLOEXEC
            or not _O_DIRECTORY
            or not _O_NOFOLLOW
        ):
            raise _GatewayConfigurationError

        # Resolve every path component beneath a descriptor with NOFOLLOW.
        # Path.resolve() would make a symlink look like the approved target
        # before the final open and would therefore defeat the no-symlink check.
        parent = os.open(os.sep, os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW)
        for component in parts[1:-1]:
            child = os.open(
                component,
                os.O_RDONLY | _O_CLOEXEC | _O_DIRECTORY | _O_NOFOLLOW,
                dir_fd=parent,
            )
            os.close(parent)
            parent = child
        descriptor = os.open(
            parts[-1], os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW, dir_fd=parent
        )
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_mode & 0o022
            or details.st_nlink != 1
            or details.st_mode & 0o111 == 0
            or not 1 <= details.st_size <= _MAX_RUNTIME_BINARY_BYTES
        ):
            raise _GatewayConfigurationError
        list_xattrs = getattr(os, "listxattr", None)
        if not callable(list_xattrs) or list(list_xattrs(descriptor)):
            raise _GatewayConfigurationError
        digest = hashlib.sha256()
        total = 0
        while total <= _MAX_RUNTIME_BINARY_BYTES:
            chunk = os.read(descriptor, min(1_048_576, _MAX_RUNTIME_BINARY_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
        if total != details.st_size or digest.hexdigest() != match.group(1):
            raise _GatewayConfigurationError
    except _GatewayConfigurationError:
        raise
    except Exception:
        raise _GatewayConfigurationError from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent >= 0:
            os.close(parent)


def _backend_ready(policy: GatewayPolicy) -> bool:
    try:
        backend = LoopbackOllamaBackend(policy)
        return backend.ready(timeout_seconds=policy.timeout_seconds)
    except Exception:
        return False


def _observation_path() -> Path:
    """Use the worker data volume for the bounded gateway operational artifact."""

    values = dict(os.environ)
    values.setdefault(
        "SECURECODE_AI_ARTIFACT_ROOT",
        values.get("SECURECODE_DATA_DIR", "/var/lib/securecode"),
    )
    return gateway_observation_path(values)


def _parse(tokens: Sequence[str]) -> bool:
    values = tuple(tokens)
    if values == ("--ready",):
        return True
    if values in {(), ("--help",), ("-h",)}:
        return False
    raise _GatewayConfigurationError


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run the admitted gateway or perform its source-free readiness check."""

    output = sys.stdout if stdout is None else stdout
    errors = sys.stderr if stderr is None else stderr
    tokens = tuple(sys.argv[1:] if argv is None else argv)
    if tokens in {("--help",), ("-h",)}:
        output.write(_HELP)
        return 0
    try:
        ready_only = _parse(tokens)
        host = _approved_host()
        profile = host.profile
        _verify_runtime_binary(host.ollama_artifact_sha256)
        policy = _policy(profile, host.ollama_version)
        if ready_only:
            if not _backend_ready(policy):
                raise _GatewayConfigurationError
            output.write("ready\n")
            return 0
        observation_path = _observation_path()
        recorder = PublicGatewayExchangeRecorder(policy)

        def observe_exchange(observation: GatewayExchangeObservation) -> None:
            recorder.observe(observation)
            _write_gateway_observation(observation_path, recorder.snapshot_document())

        def observe_normalization(observation: GatewayNormalizationObservation) -> None:
            recorder.observe_normalization(observation)
            _write_gateway_observation(observation_path, recorder.snapshot_document())

        backend = _TenantBoundGatewayBackend(
            LoopbackOllamaBackend(policy, observer=observe_exchange),
            tenant_id=host.policy.tenant_scope,
        )
        server = create_gateway_server(
            policy,
            port=_approved_listener(profile),
            backend=backend,
            normalization_observer=observe_normalization,
        )
        try:
            server.serve_forever()
        finally:
            with suppress(Exception):
                server.server_close()
            _write_gateway_observation(observation_path, recorder.snapshot_document())
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        errors.write("provider gateway unavailable\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
