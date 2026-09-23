"""Probe the server readiness endpoint over its local TLS listener."""

from __future__ import annotations

import http.client
import ssl
import sys


def main() -> int:
    connection = http.client.HTTPSConnection(
        "127.0.0.1",
        8080,
        timeout=2.0,
        context=ssl._create_unverified_context(),
    )
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
