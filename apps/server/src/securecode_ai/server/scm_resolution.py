"""Exact revision lookup for SCM-triggered CI workers."""

from __future__ import annotations

import re

from .ports import ControlPlaneService, ServiceRequest, ServiceResponse, ServiceUnavailableError
from .scm_publication_store import SqliteSCMPublicationStore

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")


class SCMRunResolutionHandler:
    """Return only the pending run bound to the caller's tenant and exact SHA."""

    __slots__ = ("_fallback", "_store")

    def __init__(
        self,
        *,
        store: SqliteSCMPublicationStore,
        fallback: ControlPlaneService,
    ) -> None:
        if not isinstance(store, SqliteSCMPublicationStore) or not hasattr(fallback, "dispatch"):
            raise TypeError("SCM run resolution dependencies are invalid")
        self._store = store
        self._fallback = fallback

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action != "scm.runs.resolve":
            response = await self._fallback.dispatch(request)
            if not isinstance(response, ServiceResponse):
                raise ServiceUnavailableError()
            return response
        document = request.document
        if document is None or set(document) != {
            "provider",
            "repository_id",
            "change_id",
            "head_sha",
        }:
            return ServiceResponse(400, {"error": {"code": "INVALID_REQUEST"}})
        provider = document.get("provider")
        repository_id = document.get("repository_id")
        change_id = document.get("change_id")
        head_sha = document.get("head_sha")
        if (
            provider not in {"github", "gitlab"}
            or type(repository_id) is not str
            or _ID.fullmatch(repository_id) is None
            or type(change_id) is not str
            or _ID.fullmatch(change_id) is None
            or type(head_sha) is not str
            or _COMMIT.fullmatch(head_sha) is None
        ):
            return ServiceResponse(400, {"error": {"code": "INVALID_REQUEST"}})
        target = self._store.resolve(
            tenant_id=request.identity.tenant_id,
            provider=provider,
            repository_id=repository_id,
            change_id=change_id,
            head_sha=head_sha,
        )
        if target is None:
            return ServiceResponse(404, {"error": {"code": "RUN_NOT_FOUND"}})
        return ServiceResponse(
            200,
            {
                "execution_identity_hash": target.execution_identity_hash,
                "head_sha": target.head_sha,
                "repository_id": target.repository_id,
                "run_id": target.run_id,
                "schema_version": "1.0.0",
            },
        )


__all__ = ["SCMRunResolutionHandler"]
