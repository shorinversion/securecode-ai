from __future__ import annotations

import asyncio

from securecode_ai.server.composite_service import CompositeService
from securecode_ai.server.ports import ServiceRequest, ServiceResponse, VerifiedIdentity


async def x() -> ServiceResponse:
    request = ServiceRequest(
        "POST",
        "/api/v1/artifacts:authorize",
        "artifacts.authorize",
        VerifiedIdentity("s", "t", frozenset()),
        "k",
        None,
        {},
        {},
        {},
        b"",
    )
    return await CompositeService().dispatch(request)


def test_unavailable_handler_is_safe_503() -> None:
    assert asyncio.run(x()).status == 503
