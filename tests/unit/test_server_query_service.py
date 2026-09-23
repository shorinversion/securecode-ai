"""P6.9 pagination validation for the source-free query service."""

from __future__ import annotations

import base64
from typing import cast

import pytest
from securecode_ai.server.identity import Principal, Role
from securecode_ai.server.query_service import (
    InMemoryViewRepository,
    QueryService,
    QueryValidationError,
    QueryValidationErrorCode,
)
from securecode_ai.server.views import RunView, ViewOutcome

TENANT = "tenant-a"
REPOSITORY = "repo"
PRINCIPAL = Principal("viewer", TENANT, frozenset({Role.VIEWER}), frozenset({REPOSITORY}))


def _service() -> QueryService:
    runs = tuple(
        RunView(
            TENANT,
            REPOSITORY,
            f"run-{index}",
            "a" * 64,
            "b" * 40,
            ViewOutcome.PASS,
            True,
        )
        for index in range(3)
    )
    return QueryService(InMemoryViewRepository(runs))


def test_pagination_uses_only_canonical_cursors() -> None:
    service = _service()

    first = service.list_runs(PRINCIPAL, REPOSITORY, limit=1)
    first_items = cast(list[dict[str, object]], first["items"])
    assert [item["run_id"] for item in first_items] == ["run-0"]
    cursor = first["next_cursor"]
    assert isinstance(cursor, str)

    second = service.list_runs(PRINCIPAL, REPOSITORY, cursor=cursor, limit=1)
    second_items = cast(list[dict[str, object]], second["items"])
    assert [item["run_id"] for item in second_items] == ["run-1"]


@pytest.mark.parametrize(
    "cursor",
    (
        "invalid",
        "!",
        "MA==",
        base64.urlsafe_b64encode(b"00").decode().rstrip("="),
        base64.urlsafe_b64encode(b"-1").decode().rstrip("="),
        "\u0661",
        "A" * 257,
    ),
)
def test_invalid_cursor_is_rejected_instead_of_restarting_from_zero(cursor: str) -> None:
    with pytest.raises(QueryValidationError) as raised:
        _service().list_runs(PRINCIPAL, REPOSITORY, cursor=cursor, limit=1)

    assert raised.value.code is QueryValidationErrorCode.CURSOR_INVALID


@pytest.mark.parametrize("limit", (0, -1, 101, True, 1.0, "1"))
def test_invalid_limit_is_rejected_instead_of_being_clamped(limit: object) -> None:
    with pytest.raises(QueryValidationError) as raised:
        _service().list_runs(PRINCIPAL, REPOSITORY, limit=limit)  # type: ignore[arg-type]

    assert raised.value.code is QueryValidationErrorCode.LIMIT_INVALID
