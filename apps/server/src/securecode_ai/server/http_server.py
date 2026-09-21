"""Bounded HTTP/1.1 bridge for the dependency-free ASGI application."""

from __future__ import annotations

import asyncio
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

    def __post_init__(self) -> None:
        if (
            type(self.max_connections) is not int
            or not 1 <= self.max_connections <= 4096
            or type(self.header_timeout_seconds) is not float
            or not 0.1 <= self.header_timeout_seconds <= 60.0
            or type(self.body_timeout_seconds) is not float
            or not 0.1 <= self.body_timeout_seconds <= 300.0
        ):
            raise ValueError("HTTP server limits are invalid")


class AsgiHttpServer:
    __slots__ = ("_app", "_limits", "_scheme", "_semaphore", "_server")

    def __init__(self, app: object, limits: HttpServerLimits | None = None) -> None:
        if not callable(app):
            raise ValueError("ASGI application is invalid")
        self._app = app
        self._limits = limits or HttpServerLimits()
        self._scheme = "http"
        self._semaphore = asyncio.Semaphore(self._limits.max_connections)
        self._server: asyncio.AbstractServer | None = None

    async def start(
        self,
        host: str,
        port: int,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if self._server is not None:
            raise RuntimeError("HTTP server is already started")
        self._scheme = "https" if ssl_context is not None else "http"
        self._server = await asyncio.start_server(
            self._handle,
            host,
            port,
            ssl=ssl_context,
        )

    async def stop(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        async with self._semaphore:
            try:
                request = await self._read_request(reader)
                if request is None:
                    await _write_plain_error(writer, 400, "Bad Request")
                    return
                method, path, query, headers, body = request
                response = _ResponseCollector()
                delivered = False

                async def receive() -> dict[str, object]:
                    nonlocal delivered
                    if delivered:
                        return {"type": "http.disconnect"}
                    delivered = True
                    return {"type": "http.request", "body": body, "more_body": False}

                await self._app(
                    {
                        "type": "http",
                        "http_version": "1.1",
                        "method": method,
                        "path": path,
                        "query_string": query,
                        "headers": headers,
                        "scheme": self._scheme,
                    },
                    receive,
                    response.send,
                )
                await response.write(writer)
            except (TimeoutError, ValueError):
                await _write_plain_error(writer, 400, "Bad Request")
            except (ConnectionError, BrokenPipeError):
                return
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
                    content_length = int(value.decode("ascii"))
                except (ValueError, UnicodeDecodeError):
                    return None
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
            if type(status) is not int or not 100 <= status <= 599 or not isinstance(headers, list):
                raise ValueError("invalid response start")
            self.status = status
            self.headers = list(headers)
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
            409: "Conflict",
            412: "Precondition Failed",
            413: "Content Too Large",
            422: "Unprocessable Content",
            500: "Internal Server Error",
            503: "Service Unavailable",
        }.get(self.status, "Response")
        header_lines = [f"HTTP/1.1 {self.status} {reason}\r\n".encode("ascii")]
        seen = {name.lower() for name, _ in self.headers}
        for name, value in self.headers:
            if b"\r" in name + value or b"\n" in name + value:
                raise ValueError("unsafe response header")
            header_lines.append(name + b": " + value + b"\r\n")
        if b"content-length" not in seen:
            header_lines.append(b"content-length: " + str(len(self.body)).encode("ascii") + b"\r\n")
        header_lines.append(b"connection: close\r\n\r\n")
        writer.writelines(header_lines)
        writer.write(bytes(self.body))
        await writer.drain()


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
