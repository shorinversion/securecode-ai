"""Bounded production OSV batch client that sends package coordinates only."""

from __future__ import annotations

import http.client
import ipaddress
import json
import queue
import socket
import ssl
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass

from .dependency_scanning import (
    OsvAdvisoryRecord,
    OsvBatchRequest,
    OsvBatchResponse,
    OsvPackageResult,
)

_AUTHORITY = "api.osv.dev"
_PATH = "/v1/querybatch"
_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_MAX_QUERIES_PER_BATCH = 1000
_MAX_TOTAL_QUERIES = 10_000
_MAX_ADVISORIES = 10_000
_MAX_ALIASES = 64
_MAX_PAGE_TOKEN_BYTES = 4096
_MAX_PAGES_PER_QUERY = 64
_READ_CHUNK_BYTES = 64 * 1024
_READ_POLL_SECONDS = 0.5
_DEFAULT_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True, slots=True)
class _OsvPage:
    results: tuple[OsvPackageResult, ...]
    next_page_tokens: tuple[str | None, ...]


class BoundedOsvScanner:
    """Query the fixed OSV API without proxies, redirects, source, or credentials."""

    scanner_id = "osv.dev"
    scanner_version = "v1"

    __slots__ = ("_cancelled", "_timeout")

    def __init__(
        self,
        *,
        timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        if (
            type(timeout_seconds) not in (int, float)
            or isinstance(timeout_seconds, bool)
            or not 1.0 <= float(timeout_seconds) <= 30.0
            or (cancelled is not None and not callable(cancelled))
        ):
            raise ValueError("OSV_SCANNER_CONFIGURATION_INVALID")
        self._timeout = float(timeout_seconds)
        self._cancelled = cancelled

    def query_batch(self, request: OsvBatchRequest) -> OsvBatchResponse:
        if type(request) is not OsvBatchRequest or len(request.purls) > _MAX_TOTAL_QUERIES:
            raise ValueError("OSV_REQUEST_INVALID")
        deadline = time.monotonic() + self._timeout
        if self._is_cancelled():
            raise ValueError("OSV_REQUEST_CANCELLED")
        addresses = _resolve_global(deadline)
        results: list[OsvPackageResult] = []
        advisory_count = 0
        for start in range(0, len(request.purls), _MAX_QUERIES_PER_BATCH):
            chunk = OsvBatchRequest(request.purls[start : start + _MAX_QUERIES_PER_BATCH])
            response = self._query_chunk(chunk, addresses, deadline)
            advisory_count += sum(len(item.advisories) for item in response.results)
            if advisory_count > _MAX_ADVISORIES:
                raise ValueError("OSV_RESPONSE_TOO_LARGE")
            results.extend(response.results)
        return OsvBatchResponse(tuple(results))

    def _query_chunk(
        self, request: OsvBatchRequest, addresses: tuple[str, ...], deadline: float
    ) -> OsvBatchResponse:
        pending: tuple[tuple[str, str | None], ...] = tuple((purl, None) for purl in request.purls)
        merged: dict[str, dict[str, OsvAdvisoryRecord]] = {purl: {} for purl in request.purls}
        seen_tokens: dict[str, set[str]] = {purl: set() for purl in request.purls}
        advisory_count = 0
        while pending:
            page = self._query_page(pending, addresses, deadline)
            following: list[tuple[str, str | None]] = []
            for (purl, _), result, token in zip(
                pending, page.results, page.next_page_tokens, strict=True
            ):
                records = merged[purl]
                for advisory in result.advisories:
                    if advisory.advisory_id in records:
                        raise ValueError("OSV_RESPONSE_INVALID")
                    records[advisory.advisory_id] = advisory
                    advisory_count += 1
                    if advisory_count > _MAX_ADVISORIES:
                        raise ValueError("OSV_RESPONSE_TOO_LARGE")
                if token is not None:
                    tokens = seen_tokens[purl]
                    if token in tokens or len(tokens) >= _MAX_PAGES_PER_QUERY - 1:
                        raise ValueError("OSV_RESPONSE_INVALID")
                    tokens.add(token)
                    following.append((purl, token))
            pending = tuple(following)
        return OsvBatchResponse(
            tuple(
                OsvPackageResult(
                    purl, tuple(sorted(records.values(), key=lambda item: item.advisory_id))
                )
                for purl, records in merged.items()
            )
        )

    def _query_page(
        self,
        queries: tuple[tuple[str, str | None], ...],
        addresses: tuple[str, ...],
        deadline: float,
    ) -> _OsvPage:
        body = _request_body(queries)
        last_error: Exception | None = None
        for index, address in enumerate(addresses):
            if self._is_cancelled() or time.monotonic() >= deadline:
                raise ValueError("OSV_REQUEST_CANCELLED")
            try:
                remaining = deadline - time.monotonic()
                attempts_left = len(addresses) - index
                attempt_deadline = time.monotonic() + min(10.0, remaining / attempts_left)
                raw = _exchange(address, body, attempt_deadline, self._is_cancelled)
                return _decode_page(raw, tuple(purl for purl, _ in queries))
            except (OSError, TimeoutError, ValueError, http.client.HTTPException) as error:
                last_error = error
        raise ValueError("OSV_REQUEST_FAILED") from last_error

    def _is_cancelled(self) -> bool:
        try:
            return self._cancelled is not None and self._cancelled()
        except Exception:
            return True


class _PinnedHttpsConnection(http.client.HTTPSConnection):
    __slots__ = ("_address", "_ssl_context")

    def __init__(self, address: str, timeout: float) -> None:
        context = ssl.create_default_context()
        super().__init__(
            _AUTHORITY,
            443,
            timeout=timeout,
            context=context,
        )
        self._address = address
        self._ssl_context = context

    def connect(self) -> None:
        raw = socket.create_connection((self._address, 443), self.timeout)
        try:
            peer = ipaddress.ip_address(raw.getpeername()[0]).compressed
            if peer != self._address:
                raise OSError("OSV_PEER_MISMATCH")
            self.sock = self._ssl_context.wrap_socket(raw, server_hostname=_AUTHORITY)
        except Exception:
            raw.close()
            raise


def _resolve_global(deadline: float) -> tuple[str, ...]:
    results: queue.Queue[object] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            answer: object = socket.getaddrinfo(
                _AUTHORITY, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
        except OSError as error:
            answer = error
        with suppress(queue.Full):
            results.put_nowait(answer)

    worker = threading.Thread(target=resolve, name="securecode-osv-resolver", daemon=True)
    worker.start()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    try:
        answer = results.get(timeout=remaining)
    except queue.Empty:
        raise TimeoutError from None
    if isinstance(answer, OSError) or not isinstance(answer, list):
        raise ValueError("OSV_RESOLUTION_FAILED")
    addresses = set()
    for item in answer:
        if not isinstance(item, tuple) or len(item) != 5 or not isinstance(item[4], tuple):
            raise ValueError("OSV_RESOLUTION_FAILED")
        raw = item[4][0]
        address = ipaddress.ip_address(raw)
        if not address.is_global:
            raise ValueError("OSV_ENDPOINT_DENIED")
        addresses.add(address.compressed)
    if not addresses or len(addresses) > 16:
        raise ValueError("OSV_RESOLUTION_FAILED")
    return tuple(sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, value)))


def _request_body(queries: tuple[tuple[str, str | None], ...]) -> bytes:
    values = []
    for purl, token in queries:
        query: dict[str, object] = {"package": {"purl": purl}}
        if token is not None:
            query["page_token"] = token
        values.append(query)
    body = json.dumps(
        {"queries": values}, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode("ascii")
    if len(body) > _MAX_REQUEST_BYTES:
        raise ValueError("OSV_REQUEST_INVALID")
    return body


def _exchange(
    address: str,
    body: bytes,
    deadline: float,
    cancelled: Callable[[], bool],
) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    connection = _PinnedHttpsConnection(address, remaining)
    try:
        connection.request(
            "POST",
            _PATH,
            body=body,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "Host": _AUTHORITY,
                "User-Agent": "securecode-ai/1.0",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        if response.status != 200 or response.getheader("Location") is not None:
            raise ValueError("OSV_RESPONSE_STATUS_INVALID")
        content_types = response.headers.get_all("Content-Type", [])
        if (
            len(content_types) != 1
            or content_types[0].split(";", 1)[0].strip() != "application/json"
        ):
            raise ValueError("OSV_RESPONSE_TYPE_INVALID")
        lengths = response.headers.get_all("Content-Length", [])
        if lengths:
            if len(lengths) != 1 or not lengths[0].isdigit():
                raise ValueError("OSV_RESPONSE_LENGTH_INVALID")
            if int(lengths[0]) > _MAX_RESPONSE_BYTES:
                raise ValueError("OSV_RESPONSE_TOO_LARGE")
        return _read_body(response, connection, deadline, cancelled)
    finally:
        connection.close()


def _read_body(
    response: http.client.HTTPResponse,
    connection: _PinnedHttpsConnection,
    deadline: float,
    cancelled: Callable[[], bool],
) -> bytes:
    output = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if cancelled():
            raise ValueError("OSV_REQUEST_CANCELLED")
        if remaining <= 0 or connection.sock is None:
            raise TimeoutError
        connection.sock.settimeout(min(_READ_POLL_SECONDS, remaining))
        chunk = response.read1(min(_READ_CHUNK_BYTES, _MAX_RESPONSE_BYTES + 1 - len(output)))
        if not chunk:
            return bytes(output)
        output.extend(chunk)
        if len(output) > _MAX_RESPONSE_BYTES:
            raise ValueError("OSV_RESPONSE_TOO_LARGE")


def _decode_page(raw: bytes, purls: tuple[str, ...]) -> _OsvPage:
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_closed_object)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise ValueError("OSV_RESPONSE_INVALID") from None
    if not isinstance(document, dict) or set(document) != {"results"}:
        raise ValueError("OSV_RESPONSE_INVALID")
    results = document["results"]
    if not isinstance(results, list) or len(results) != len(purls):
        raise ValueError("OSV_RESPONSE_INVALID")
    normalized = []
    next_tokens = []
    advisory_count = 0
    for purl, item in zip(purls, results, strict=True):
        if not isinstance(item, dict) or not set(item).issubset({"vulns", "next_page_token"}):
            raise ValueError("OSV_RESPONSE_INVALID")
        token = item.get("next_page_token")
        if token is not None and (
            not isinstance(token, str)
            or not token
            or len(token.encode("utf-8")) > _MAX_PAGE_TOKEN_BYTES
            or any(ord(character) < 33 or ord(character) > 126 for character in token)
        ):
            raise ValueError("OSV_RESPONSE_INVALID")
        vulnerabilities = item.get("vulns", [])
        if not isinstance(vulnerabilities, list):
            raise ValueError("OSV_RESPONSE_INVALID")
        advisories = []
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError("OSV_RESPONSE_INVALID")
            advisory_id = vulnerability.get("id")
            aliases = vulnerability.get("aliases", [])
            if not isinstance(advisory_id, str) or not isinstance(aliases, list):
                raise ValueError("OSV_RESPONSE_INVALID")
            if len(aliases) > _MAX_ALIASES or any(not isinstance(alias, str) for alias in aliases):
                raise ValueError("OSV_RESPONSE_INVALID")
            advisories.append(OsvAdvisoryRecord(advisory_id, tuple(sorted(set(aliases)))))
            advisory_count += 1
            if advisory_count > _MAX_ADVISORIES:
                raise ValueError("OSV_RESPONSE_TOO_LARGE")
        ordered = tuple(sorted(advisories, key=lambda item: item.advisory_id))
        if len({item.advisory_id for item in ordered}) != len(ordered):
            raise ValueError("OSV_RESPONSE_INVALID")
        normalized.append(OsvPackageResult(purl, ordered))
        next_tokens.append(token)
    return _OsvPage(tuple(normalized), tuple(next_tokens))


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError
        result[key] = value
    return result


__all__ = ["BoundedOsvScanner"]
