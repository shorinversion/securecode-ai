from __future__ import annotations

from collections.abc import Mapping

import pytest
from securecode_ai.server.secret_provider_runtime import (
    SubprocessSecretProvider,
    _lease,
)
from securecode_ai.server.subprocess_protocol import PinnedJsonProcess, SubprocessProtocolError


class FakeProcess(PinnedJsonProcess):
    def __init__(self, response: dict[str, object]) -> None:
        self.response = response
        self.requests: list[Mapping[str, object]] = []

    def request(self, document: Mapping[str, object]) -> dict[str, object]:
        self.requests.append(document)
        return self.response


@pytest.mark.parametrize("version", [True, 1.0, "1"])
def test_lease_rejects_non_integer_schema_version(version: object) -> None:
    with pytest.raises(SubprocessProtocolError, match="SECRET_PROVIDER_RESPONSE_INVALID"):
        _lease(
            {
                "expires_at": 2_000_000_000,
                "handle": "x" * 32,
                "schema_version": version,
                "status": "ok",
            }
        )


def test_revoke_rejects_boolean_schema_version() -> None:
    process = FakeProcess({"schema_version": True, "status": "ok"})
    provider = SubprocessSecretProvider(process)

    with pytest.raises(SubprocessProtocolError, match="SECRET_PROVIDER_RESPONSE_INVALID"):
        provider.revoke("grant-1")

    assert process.requests == [{"grant_id": "grant-1", "operation": "revoke", "schema_version": 1}]


def test_revoke_accepts_exact_integer_schema_version() -> None:
    process = FakeProcess({"schema_version": 1, "status": "ok"})

    SubprocessSecretProvider(process).revoke("grant-1")
