"""Bounded HTTP/1.1 bridge for the dependency-free ASGI application."""

from __future__ import annotations

import asyncio
import inspect
import ssl
from contextlib import suppress
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

_MAX_HEADER_BYTES: Final = 65_536
_MAX_BODY_BYTES: Final = 16_777_216
_MAX_HEADERS: Final = 128


@dataclass(frozen=True, slots=True)
class HttpServerLimits:
    max_connections: int = 128
    header_timeout_seconds: float = 10.0
    body_timeout_seconds: float = 30.0
    response_timeout_seconds: float = 30.0
    shutdown_timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        if (
            type(self.max_connections) is not int
            or not 1 <= self.max_connections <= 4096
            or type(self.header_timeout_seconds) is not float
            or not 0.1 <= self.header_timeout_seconds <= 60.0
            or type(self.body_timeout_seconds) is not float
            or not 0.1 <= self.body_timeout_seconds <= 300.0
            or type(self.response_timeout_seconds) is not float
            or not 0.1 <= self.response_timeout_seconds <= 300.0
            or type(self.shutdown_timeout_seconds) is not float
            or not 0.1 <= self.shutdown_timeout_seconds <= 300.0
        ):
            raise ValueError("HTTP server limits are invalid")


class AsgiHttpServer:
    __slots__ = (
        "_app",
        "_limits",
        "_scheme",
        "_semaphore",
        "_server",
        "_connections",
        "_lifecycle_lock",
    )

    def __init__(self, app: object, limits: HttpServerLimits | None = None) -> None:
        if not callable(app):
            raise ValueError("ASGI application is invalid")
        self._app = app
        self._limits = limits or HttpServerLimits()
        self._scheme = "http"
        self._semaphore = asyncio.Semaphore(self._limits.max_connections)
        self._server: asyncio.AbstractServer | None = None
        self._connections: set[asyncio.Task[None]] = set()
        self._lifecycle_lock = asyncio.Lock()

    async def start(
        self,
        host: str,
        port: int,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        async with self._lifecycle_lock:
            if self._server is not None:
                raise RuntimeError("HTTP server is already started")
            startup = getattr(self._app, "startup", None)
            try:
                if callable(startup):
                    result = startup()
                    if inspect.isawaitable(result):
                        await result
                self._scheme = "https" if ssl_context is not None else "http"
                server = await asyncio.start_server(
                    self._handle,
                    host,
                    port,
                    ssl=ssl_context,
                )
            except BaseException:
                shutdown = getattr(self._app, "shutdown", None)
                if callable(shutdown):
                    try:
                        result = shutdown()
                        if inspect.isawaitable(result):
                            await result
                    except BaseException:
                        pass
                raise
            self._server = server

    async def stop(self) -> None:
        async with self._lifecycle_lock:
            server = self._server
            self._server = None
            if server is not None:
                server.close()
                await server.wait_closed()
            try:
                current = asyncio.current_task()
                deadline = (
                    asyncio.get_running_loop().time()
                    + self._limits.shutdown_timeout_seconds
                )
                while True:
                    pending = tuple(
                        task
                        for task in self._connections
                        if task is not current and not task.done()
                    )
                    if not pending:
                        break
                    remaining = deadline - asyncio.get_running_loop().time()
                    if remaining <= 0:
                        for task in pending:
                            task.cancel()
                        await asyncio.gather(*pending, return_exceptions=True)
                        break
                    _, pending_set = await asyncio.wait(pending, timeout=remaining)
                    if pending_set:
                        for task in pending_set:
                            task.cancel()
                        await asyncio.gather(*pending_set, return_exceptions=True)
                        break
            finally:
                shutdown = getattr(self._app, "shutdown", None)
                if callable(shutdown):
                    result = shutdown()
                    if inspect.isawaitable(result):
                        await result

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        over_capacity = False
        if task is not None:
            self._connections.add(task)
            over_capacity = len(self._connections) > self._limits.max_connections
        try:
            if over_capacity:
                try:
                    await asyncio.wait_for(
                        _write_plain_error(writer, 503, "Service Unavailable"),
                        timeout=self._limits.response_timeout_seconds,
                    )
                except (ConnectionError, BrokenPipeError, TimeoutError):
                    pass
                finally:
                    writer.close()
                    with suppress(ConnectionError, BrokenPipeError):
                        await writer.wait_closed()
                return
            async with self._semaphore:
                await self._serve_connection(reader, writer)
        finally:
            if task is not None:
                self._connections.discard(task)

    async def _serve_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            request = await self._read_request(reader)
            if request is None:
                await _write_plain_error(writer, 400, "Bad Request")
                return
            method, path, query, headers, body = request
            response = _ResponseCollector()
            delivered = False
            scope: dict[str, object] = {
                "type": "http",
                "http_version": "1.1",
                "method": method,
                "path": path,
                "query_string": query,
                "headers": headers,
                "scheme": self._scheme,
            }
            peername = writer.get_extra_info("peername")
            if (
                isinstance(peername, tuple)
                and len(peername) >= 2
                and type(peername[0]) is str
                and type(peername[1]) is int
            ):
                scope["client"] = (peername[0], peername[1])

            async def receive() -> dict[str, object]:
                nonlocal delivered
                if delivered:
                    return {"type": "http.disconnect"}
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}

            await self._app(scope, receive, response.send)
            try:
                await asyncio.wait_for(
                    response.write(writer),
                    timeout=self._limits.response_timeout_seconds,
                )
            except TimeoutError:
                return
        except TimeoutError:
            await _write_plain_error(writer, 408, "Request Timeout")
        except (ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            await _write_plain_error(writer, 400, "Bad Request")
        except (ConnectionError, BrokenPipeError):
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            await _write_plain_error(writer, 500, "Internal Server Error")
        finally:
            writer.close()
            with suppress(ConnectionError, BrokenPipeError):
                await writer.wait_closed()

    async def _read_request(
        self,
        reader: asyncio.StreamReader,
    ) -> tuple[str, str, bytes, list[tuple[bytes, bytes]], bytes] | None:
        header_bytes = await asyncio.wait_for(
            reader.readuntil(b"\r\n\r\n"),
            timeout=self._limits.header_timeout_seconds,
        )
        if len(header_bytes) > _MAX_HEADER_BYTES:
            return None
        lines = header_bytes[:-4].split(b"\r\n")
        if not lines or len(lines) > _MAX_HEADERS + 1:
            return None
        try:
            method_bytes, target_bytes, version = lines[0].split(b" ", 2)
            method = method_bytes.decode("ascii")
            target = target_bytes.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            return None
        if (
            version != b"HTTP/1.1"
            or method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}
            or not target.startswith("/")
            or len(target) > 8192
        ):
            return None
        headers: list[tuple[bytes, bytes]] = []
        names: set[bytes] = set()
        content_length = 0
        for line in lines[1:]:
            if b":" not in line:
                return None
            name, value = line.split(b":", 1)
            name = name.strip().lower()
            value = value.strip()
            if (
                not name
                or name in names
                or any(byte < 33 or byte > 126 or byte == 58 for byte in name)
                or any(byte < 32 or byte == 127 for byte in value)
            ):
                return None
            names.add(name)
            headers.append((name, value))
            if name == b"content-length":
                try:
                    raw_length = value.decode("ascii")
                except (ValueError, UnicodeDecodeError):
                    return None
                if (
                    not raw_length
                    or len(raw_length) > 10
                    or not raw_length.isascii()
                    or not raw_length.isdecimal()
                ):
                    return None
                content_length = int(raw_length)
            if name == b"transfer-encoding":
                return None
        if not 0 <= content_length <= _MAX_BODY_BYTES:
            return None
        body = (
            await asyncio.wait_for(
                reader.readexactly(content_length),
                timeout=self._limits.body_timeout_seconds,
            )
            if content_length
            else b""
        )
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
            return None
        return method, parsed.path, parsed.query.encode("ascii"), headers, body


class _ResponseCollector:
    __slots__ = ("body", "headers", "started", "status")

    def __init__(self) -> None:
        self.status = 500
        self.headers: list[tuple[bytes, bytes]] = []
        self.body = bytearray()
        self.started = False

    async def send(self, event: dict[str, object]) -> None:
        event_type = event.get("type")
        if event_type == "http.response.start":
            if self.started:
                raise ValueError("response already started")
            status = event.get("status")
            headers = event.get("headers", [])
            if (
                type(status) is not int
                or not 200 <= status <= 599
                or type(headers) is not list
            ):
                raise ValueError("invalid response start")
            self.status = status
            self.headers = _validated_response_headers(headers)
            self.started = True
            return
        if event_type == "http.response.body" and self.started:
            body = event.get("body", b"")
            if type(body) is not bytes or len(self.body) + len(body) > _MAX_BODY_BYTES:
                raise ValueError("invalid response body")
            self.body.extend(body)
            return
        raise ValueError("invalid ASGI response event")

    async def write(self, writer: asyncio.StreamWriter) -> None:
        if not self.started:
            raise ValueError("response was not started")
        reason = {
            200: "OK",
            201: "Created",
            202: "Accepted",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            408: "Request Timeout",
            409: "Conflict",
            412: "Precondition Failed",
            413: "Content Too Large",
            422: "Unprocessable Content",
            500: "Internal Server Error",
            503: "Service Unavailable",
        }.get(self.status, "Response")
        header_lines = [f"HTTP/1.1 {self.status} {reason}\r\n".encode("ascii")]
        seen: set[bytes] = set()
        for name, value in self.headers:
            lowered = name.lower()
            if lowered == b"content-length":
                try:
                    raw_length = value.decode("ascii")
                except (ValueError, UnicodeDecodeError):
                    raise ValueError("invalid content length") from None
                if (
                    lowered in seen
                    or not raw_length
                    or len(raw_length) > 10
                    or not raw_length.isascii()
                    or not raw_length.isdecimal()
                ):
                    raise ValueError("invalid content length")
                declared_length = int(raw_length)
                if declared_length != len(self.body):
                    raise ValueError("content length does not match response body")
            seen.add(lowered)
            header_lines.append(name + b": " + value + b"\r\n")
        if b"content-length" not in seen:
            header_lines.append(b"content-length: " + str(len(self.body)).encode("ascii") + b"\r\n")
        header_lines.append(b"connection: close\r\n\r\n")
        writer.writelines(header_lines)
        writer.write(bytes(self.body))
        await writer.drain()


def _validated_response_headers(value: list[object]) -> list[tuple[bytes, bytes]]:
    if len(value) > _MAX_HEADERS:
        raise ValueError("too many response headers")
    result: list[tuple[bytes, bytes]] = []
    names: set[bytes] = set()
    total_size = 0
    forbidden = {
        b"connection",
        b"keep-alive",
        b"proxy-connection",
        b"transfer-encoding",
        b"upgrade",
    }
    token_bytes = frozenset(b"!#$%&'*+-.^_`|~")
    for header in value:
        if type(header) is not tuple or len(header) != 2:
            raise ValueError("invalid response header")
        name, content = header
        if (
            type(name) is not bytes
            or type(content) is not bytes
            or not name
            or any(
                not (
                    48 <= byte <= 57
                    or 65 <= byte <= 90
                    or 97 <= byte <= 122
                    or byte in token_bytes
                )
                for byte in name
            )
            or any(
                (byte < 32 and byte != 9) or byte == 127
                for byte in content
            )
        ):
            raise ValueError("invalid response header")
        normalized = name.lower()
        if normalized in forbidden or (
            normalized == b"content-length" and normalized in names
        ):
            raise ValueError("duplicate or hop-by-hop response header")
        total_size += len(name) + len(content) + 4
        if total_size > _MAX_HEADER_BYTES:
            raise ValueError("response headers are too large")
        names.add(normalized)
        result.append((normalized, content))
    return result


async def _write_plain_error(
    writer: asyncio.StreamWriter,
    status: int,
    reason: str,
) -> None:
    body = reason.encode("ascii")
    writer.write(
        f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")
        + b"content-type: text/plain; charset=us-ascii\r\n"
        + b"content-length: "
        + str(len(body)).encode("ascii")
        + b"\r\nconnection: close\r\n\r\n"
        + body
    )
    await writer.drain()


__all__ = ["AsgiHttpServer", "HttpServerLimits"]
