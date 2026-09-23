"""Probe the server readiness endpoint over its local TLS listener."""

from __future__ import annotations

import http.client
import os
import ssl
import sys

_DEFAULT_PORT = 8080


def _server_port() -> int:
    value = os.environ.get("SECURECODE_SERVER_PORT", str(_DEFAULT_PORT))
    if type(value) is not str or not value.isascii() or not value.isdigit():
        raise ValueError("server port is invalid")
    port = int(value)
    if not 1 <= port <= 65_535:
        raise ValueError("server port is invalid")
    return port


def main() -> int:
    try:
        port = _server_port()
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            port,
            timeout=2.0,
            context=ssl._create_unverified_context(),
        )
    except (OSError, ValueError):
        return 1
    try:
        connection.request(
            "GET",
            "/api/v1/health/ready",
            headers={"X-SecureCode-Api-Version": "1.0.0"},
        )
        response = connection.getresponse()
        return 0 if response.status == 200 else 1
    except (OSError, http.client.HTTPException):
        return 1
    finally:
        connection.close()


if __name__ == "__main__":
    sys.exit(main())
