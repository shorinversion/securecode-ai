"""Regression tests for the bounded OSV client against real response shapes."""

from __future__ import annotations

import http.client
import io
import json
import time

import pytest
from securecode_ai.adapters import dependency_scanning_osv as osv

# Shape of a real api.osv.dev querybatch answer for pkg:pypi/requests@2.19.0 (2026-09-29).
_REAL_PAGE = json.dumps(
    {
        "results": [
            {
                "vulns": [
                    {"id": "GHSA-9wx4-h78v-vm56", "modified": "2026-09-10T03:50:13.740879Z"},
                    {"id": "PYSEC-2018-28", "modified": "2023-11-08T04:00:04.815794Z"},
                ]
            }
        ]
    }
).encode()


def test_mixed_case_advisory_identifiers_are_accepted() -> None:
    page = osv._decode_page(_REAL_PAGE, ("pkg:pypi/requests@2.19.0",))

    assert [item.advisory_id for item in page.results[0].advisories] == [
        "GHSA-9wx4-h78v-vm56",
        "PYSEC-2018-28",
    ]


class _FakeSocket:
    """In-memory socket that answers like OSV: ``Connection: close`` and a JSON body."""

    def __init__(self) -> None:
        self.closed = False
        self._reply = io.BytesIO(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Content-Length: " + str(len(_REAL_PAGE)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + _REAL_PAGE
        )

    def sendall(self, data: bytes) -> None:
        del data

    def makefile(self, mode: str) -> io.BytesIO:
        assert mode == "rb"
        return self._reply

    def settimeout(self, value: float) -> None:
        if self.closed:
            raise OSError("socket is closed")

    def close(self) -> None:
        self.closed = True


def test_connection_close_response_body_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: getresponse() closed the socket for a ``Connection: close`` reply, so every
    # real OSV request failed before the body was read.
    fake = _FakeSocket()

    class FakeConnection(http.client.HTTPConnection):
        def __init__(self, address: str, timeout: float) -> None:
            super().__init__(address, 443, timeout=timeout)

        def connect(self) -> None:
            self.sock = fake

    monkeypatch.setattr(osv, "_PinnedHttpsConnection", FakeConnection)

    raw = osv._exchange("192.0.2.1", b"{}", time.monotonic() + 5, lambda: False)

    assert raw == _REAL_PAGE
    assert fake.closed
