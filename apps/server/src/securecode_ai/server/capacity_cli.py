"""Bounded operator entrypoint for ASGI and connected lifecycle profiles."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, NoReturn, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .bootstrap import build_local_app
from .capacity_profile import (
    MAX_CONCURRENCY,
    MAX_DURATION_SECONDS,
    MAX_ITERATIONS,
    MAX_LIFECYCLE_RUNS,
    MAX_POLL_INTERVAL_SECONDS,
    MAX_SOAK_REQUESTS,
    MIN_POLL_INTERVAL_SECONDS,
    MIN_DURATION_SECONDS,
    WorkerLifecycleRequest,
    profile,
    profile_worker_lifecycle,
    render,
)
from .chaos import ChaosScenario
from .runtime import load_settings
from .secure_files import decode_ascii_secret, read_secret_bytes

_SCHEMA_VERSION: Final = 1
_MAX_OUTPUT_BYTES: Final = 32_768
_MAX_CONNECTED_RESPONSE_BYTES: Final = 1_048_576
_MAX_CONNECTED_REQUEST_BYTES: Final = 1_048_576
_CONNECTED_LOOPBACK_HOSTS: Final = frozenset({"127.0.0.1", "::1", "localhost"})
_CONNECTED_SCHEMES: Final = frozenset({"https", "http"})
_RECEIPT_STATUSES: Final = {
    "GET": frozenset({200}),
    "POST": frozenset({200, 201, 202}),
}
_ROUTES: Final = {
    "live": (ChaosScenario.HEALTH_LIVE, "/api/v1/health/live"),
    "ready": (ChaosScenario.HEALTH_READY, "/api/v1/health/ready"),
}


class _CapacityParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise ValueError("capacity arguments are invalid")


def _parser() -> argparse.ArgumentParser:
    parser = _CapacityParser(
        prog="securecode-capacity",
        description="Run a bounded in-process capacity profile against the real ASGI app.",
    )
    parser.add_argument(
        "--scenario",
        choices=("health", "soak", "cancellation", "worker-lifecycle"),
        default="health",
        help=(
            "profile to run (default: health; soak is duration-bounded; "
            "worker-lifecycle requires a connected control plane)"
        ),
    )
    parser.add_argument(
        "--route",
        choices=tuple(_ROUTES),
        default="live",
        help="read-only health route to exercise (default: live)",
    )
    parser.add_argument(
        "--concurrency",
        type=_bounded_concurrency,
        default=8,
        help=f"parallel ASGI requests, from 1 to {MAX_CONCURRENCY} (default: 8)",
    )
    parser.add_argument(
        "--iterations",
        type=_bounded_iterations,
        default=32,
        help=f"total ASGI requests, from 1 to {MAX_ITERATIONS} (default: 32)",
    )
    parser.add_argument(
        "--duration-seconds",
        type=_bounded_duration,
        default=30.0,
        help=(
            f"maximum soak duration, from {MIN_DURATION_SECONDS:g} to "
            f"{MAX_DURATION_SECONDS:g} seconds (default: 30)"
        ),
    )
    parser.add_argument(
        "--max-requests",
        type=_bounded_soak_requests,
        default=MAX_SOAK_REQUESTS,
        help=(
            "maximum requests in a soak run, from 1 to "
            f"{MAX_SOAK_REQUESTS} (default: {MAX_SOAK_REQUESTS})"
        ),
    )
    parser.add_argument(
        "--lifecycle-runs",
        type=_bounded_lifecycle_runs,
        default=1,
        help=(
            "worker lifecycle submissions, from 1 to "
            f"{MAX_LIFECYCLE_RUNS} (default: 1)"
        ),
    )
    parser.add_argument(
        "--poll-interval-seconds",
        type=_bounded_poll_interval,
        default=0.5,
        help=(
            f"worker lifecycle poll interval, from {MIN_POLL_INTERVAL_SECONDS:g} to "
            f"{MAX_POLL_INTERVAL_SECONDS:g} seconds (default: 0.5)"
        ),
    )
    return parser


def run(arguments: Sequence[str] | None = None, *, output: TextIO | None = None) -> int:
    """Execute one bounded profile and return a process exit status."""

    stream = sys.stdout if output is None else output
    try:
        options = _parser().parse_args(arguments)
        if options.scenario == "worker-lifecycle":
            request = _worker_lifecycle_request(os.environ)
            token = _lifecycle_token(os.environ)
            client = _ConnectedLifecycleClient(
                os.environ["SECURECODE_CONTROL_PLANE_URL"],
                token,
                timeout_seconds=min(options.duration_seconds, 30.0),
            )
            receipt = profile_worker_lifecycle(
                client,
                request,
                runs=options.lifecycle_runs,
                duration_seconds=options.duration_seconds,
                poll_interval_seconds=options.poll_interval_seconds,
            )
            rendered = render(receipt)
            _write_bounded(stream, rendered)
            return 0 if receipt.passed else 1
        health_scenario, path = _ROUTES[options.route]
        scenario = {
            "health": health_scenario,
            "soak": ChaosScenario.SOAK,
            "cancellation": ChaosScenario.CANCEL,
        }[options.scenario]
        settings = load_settings()
        app = build_local_app(settings)
        try:
            receipt = profile(
                app,
                concurrency=options.concurrency,
                iterations=options.iterations,
                requests=(("GET", path, b""),),
                scenarios=(scenario,),
                duration_seconds=options.duration_seconds,
                max_requests=options.max_requests,
            )
        finally:
            asyncio.run(app.shutdown())
        rendered = render(receipt)
        _write_bounded(stream, rendered)
        return 0 if receipt.passed else 1
    except SystemExit:
        raise
    except Exception:
        _write_failure(stream)
        return 1


def main() -> int:
    return run()


def _bounded_concurrency(value: str) -> int:
    return _bounded_integer(value, minimum=1, maximum=MAX_CONCURRENCY)


def _bounded_iterations(value: str) -> int:
    return _bounded_integer(value, minimum=1, maximum=MAX_ITERATIONS)


def _bounded_duration(value: str) -> float:
    if not isinstance(value, str) or not value.isascii():
        raise argparse.ArgumentTypeError("capacity duration is invalid")
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("capacity duration is invalid") from exc
    if (
        not math.isfinite(parsed)
        or not MIN_DURATION_SECONDS <= parsed <= MAX_DURATION_SECONDS
    ):
        raise argparse.ArgumentTypeError("capacity duration is invalid")
    return parsed


def _bounded_soak_requests(value: str) -> int:
    return _bounded_integer(value, minimum=1, maximum=MAX_SOAK_REQUESTS)


def _bounded_lifecycle_runs(value: str) -> int:
    return _bounded_integer(value, minimum=1, maximum=MAX_LIFECYCLE_RUNS)


def _bounded_poll_interval(value: str) -> float:
    if not isinstance(value, str) or not value.isascii():
        raise argparse.ArgumentTypeError("capacity poll interval is invalid")
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("capacity poll interval is invalid") from exc
    if (
        not math.isfinite(parsed)
        or not MIN_POLL_INTERVAL_SECONDS <= parsed <= MAX_POLL_INTERVAL_SECONDS
    ):
        raise argparse.ArgumentTypeError("capacity poll interval is invalid")
    return parsed


def _bounded_integer(value: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, str) or not value.isascii() or not value.isdecimal():
        raise argparse.ArgumentTypeError("capacity bounds are invalid")
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise argparse.ArgumentTypeError("capacity bounds are invalid")
    return parsed


def _worker_lifecycle_request(environment: Mapping[str, str]) -> WorkerLifecycleRequest:
    def required(name: str) -> str:
        value = environment.get(name)
        if type(value) is not str or not value:
            raise ValueError("worker lifecycle configuration is invalid")
        return value

    def optional(name: str) -> str | None:
        value = environment.get(name)
        if value is None:
            return None
        if type(value) is not str or not value:
            raise ValueError("worker lifecycle configuration is invalid")
        return value

    return WorkerLifecycleRequest(
        tenant_id=required("SECURECODE_TENANT_ID"),
        repository_id=required("SECURECODE_REPOSITORY_ID"),
        head_sha=required("SECURECODE_HEAD_SHA"),
        base_sha=optional("SECURECODE_BASE_SHA"),
        change_id=optional("SECURECODE_CHANGE_ID"),
        scm_provider=optional("SECURECODE_SCM_PROVIDER"),
    )


def _lifecycle_token(environment: Mapping[str, str]) -> str:
    direct = environment.get("SECURECODE_CONTROL_PLANE_TOKEN")
    file_name = environment.get("SECURECODE_CONTROL_PLANE_TOKEN_FILE")
    if (direct is None) == (file_name is None):
        raise ValueError("worker lifecycle credentials are invalid")
    if direct is not None:
        token = direct
    else:
        if type(file_name) is not str or not file_name:
            raise ValueError("worker lifecycle credentials are invalid")
        try:
            token = decode_ascii_secret(read_secret_bytes(Path(file_name)))
        except (OSError, ValueError):
            raise ValueError("worker lifecycle credentials are invalid") from None
    if (
        type(token) is not str
        or not 1 <= len(token) <= 8192
        or not token.isascii()
        or any(ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        raise ValueError("worker lifecycle credentials are invalid")
    return token


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


class _ConnectedLifecycleClient:
    """Small server-owned transport for the existing connected wire protocol."""

    __slots__ = ("_base_url", "_token", "_timeout", "_opener")

    def __init__(self, base_url: str, token: str, *, timeout_seconds: float) -> None:
        self._base_url = _safe_connected_base_url(base_url)
        if (
            type(token) is not str
            or not 1 <= len(token) <= 8192
            or not token.isascii()
            or any(ord(character) < 33 or ord(character) > 126 for character in token)
            or type(timeout_seconds) is not float
            or not 0 < timeout_seconds <= 30.0
        ):
            raise ValueError("worker lifecycle transport is invalid")
        self._token = token
        self._timeout = timeout_seconds
        self._opener = build_opener(_NoRedirect)

    def submit(
        self, document: Mapping[str, object], *, idempotency_key: str
    ) -> Mapping[str, object]:
        if not _valid_idempotency_key(idempotency_key):
            raise ValueError("worker lifecycle request is invalid")
        return self._call(
            "POST",
            "/api/v1/runs",
            document=document,
            idempotency_key=idempotency_key,
        )

    def status(self, run_id: str) -> Mapping[str, object]:
        if not _valid_identifier(run_id):
            raise ValueError("worker lifecycle run is invalid")
        return self._call("GET", f"/api/v1/runs/{run_id}", document=None)

    def cancel(
        self, run_id: str, *, if_match: str, idempotency_key: str
    ) -> Mapping[str, object]:
        if (
            not _valid_identifier(run_id)
            or not _valid_version(if_match)
            or not _valid_idempotency_key(idempotency_key)
        ):
            raise ValueError("worker lifecycle cancellation is invalid")
        return self._call(
            "POST",
            f"/api/v1/runs/{run_id}:cancel",
            document={"reason": "operator-requested"},
            idempotency_key=idempotency_key,
            if_match=if_match,
        )

    def _call(
        self,
        method: str,
        path: str,
        *,
        document: Mapping[str, object] | None,
        idempotency_key: str | None = None,
        if_match: str | None = None,
    ) -> dict[str, object]:
        if method not in _RECEIPT_STATUSES or not _valid_api_path(path):
            raise ValueError("worker lifecycle transport is invalid")
        try:
            payload = (
                None
                if document is None
                else json.dumps(
                    document,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )
        except (TypeError, UnicodeEncodeError, ValueError, RecursionError):
            raise ValueError("worker lifecycle request is invalid") from None
        if payload is not None and len(payload) > _MAX_CONNECTED_REQUEST_BYTES:
            raise ValueError("worker lifecycle request is invalid")
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self._token,
            "User-Agent": "securecode-ai-capacity/1.0",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        if if_match is not None:
            headers["If-Match"] = if_match
        request = Request(
            self._base_url + path,
            data=payload,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                body = response.read(_MAX_CONNECTED_RESPONSE_BYTES + 1)
                status = response.status
        except HTTPError as error:
            if 300 <= error.code < 400:
                raise ValueError("worker lifecycle redirect rejected") from None
            if 400 <= error.code < 500:
                raise ValueError("worker lifecycle request rejected") from None
            raise ValueError("worker lifecycle control plane unavailable") from None
        except (OSError, URLError, ValueError):
            raise ValueError("worker lifecycle control plane unavailable") from None
        if (
            status not in _RECEIPT_STATUSES.get(method, frozenset())
            or len(body) > _MAX_CONNECTED_RESPONSE_BYTES
        ):
            raise ValueError("worker lifecycle response is invalid")
        try:
            parsed = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            raise ValueError("worker lifecycle response is invalid") from None
        if type(parsed) is not dict:
            raise ValueError("worker lifecycle response is invalid")
        return parsed


def _safe_connected_base_url(value: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 2048:
        raise ValueError("worker lifecycle URL is invalid")
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ValueError("worker lifecycle URL is invalid") from None
    if (
        parts.scheme not in _CONNECTED_SCHEMES
        or not parts.hostname
        or (port is not None and not 1 <= port <= 65_535)
        or parts.path not in {"", "/"}
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or (parts.scheme == "http" and parts.hostname not in _CONNECTED_LOOPBACK_HOSTS)
    ):
        raise ValueError("worker lifecycle URL is invalid")
    return value.rstrip("/")


def _valid_api_path(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("/api/v1/")
        and ".." not in value
        and "?" not in value
        and "#" not in value
        and len(value) <= 256
    )


def _valid_identifier(value: object) -> bool:
    return (
        type(value) is str
        and value.isascii()
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


def _valid_idempotency_key(value: object) -> bool:
    return (
        isinstance(value, str)
        and _valid_identifier(value)
        and len(value) >= 8
    )


def _valid_version(value: object) -> bool:
    return (
        type(value) is str
        and value.isascii()
        and value.isdecimal()
        and 1 <= len(value) <= 10
        and 1 <= int(value) <= 2_147_483_647
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate JSON key")
        document[key] = value
    return document


def _reject_json_constant(_value: str) -> object:
    raise ValueError("JSON constant is invalid")


def _write_bounded(stream: TextIO, value: str) -> None:
    encoded = value.encode("ascii")
    if len(encoded) > _MAX_OUTPUT_BYTES:
        raise ValueError("capacity receipt is too large")
    stream.write(value)
    stream.write("\n")


def _write_failure(stream: TextIO) -> None:
    value = json.dumps(
        {
            "schema_version": _SCHEMA_VERSION,
            "status": "error",
            "error_code": "CAPACITY_PROFILE_FAILED",
        },
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    _write_bounded(stream, value)


__all__ = ["main", "run"]


if __name__ == "__main__":
    raise SystemExit(main())
