"""Fail-closed routing across independently composed control-plane services."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .ports import ServiceRequest, ServiceResponse


class Handler(Protocol):
    async def dispatch(self, request: ServiceRequest) -> ServiceResponse: ...


class CompositeService:
    """Select one handler for every admitted action without implicit fallbacks."""

    def __init__(
        self,
        *,
        core: Handler | None = None,
        worker: Handler | None = None,
        github: Handler | None = None,
        gitlab: Handler | None = None,
        optional: Mapping[str, Handler] | None = None,
    ) -> None:
        self._core = core
        self._worker = worker
        self._github = github
        self._gitlab = gitlab
        self._optional = dict(optional or {})

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        handler = self._select(request)
        if handler is None:
            return ServiceResponse(
                503,
                {
                    "error": {
                        "code": "HANDLER_UNAVAILABLE",
                        "message": "requested handler is unavailable",
                    }
                },
            )
        return await handler.dispatch(request)

    def _select(self, request: ServiceRequest) -> Handler | None:
        if request.action.startswith("worker_sessions."):
            return self._worker
        if request.action == "webhooks.github":
            return self._github
        if request.action == "webhooks.gitlab":
            return self._gitlab
        if request.action in _CORE_ACTIONS:
            return self._core
        return self._optional.get(request.action)


_CORE_ACTIONS = frozenset(
    {
        "runs.create",
        "runs.read",
        "runs.cancel",
        "runs.events.read",
        "runs.findings.read",
        "runs.artifacts.read",
        "findings.read",
        "findings.decide",
        "policies.read",
    }
)


__all__ = ["CompositeService", "Handler"]
