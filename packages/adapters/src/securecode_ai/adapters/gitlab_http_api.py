"""Named P7.5 GitLab HTTP client compatibility surface.

The hardened implementation lives in :mod:`gitlab_api`; this module exposes
the product-facing name without creating a second transport or token boundary.
"""

from __future__ import annotations

from .gitlab_api import (
    GitlabAPIError,
    GitlabAPIErrorCode,
    GitlabHTTPRequest,
    GitlabHTTPResponse,
    GitlabRestAPI,
)
from .gitlab_writer import GitlabAuthenticatedAPI

GitlabHttpAPI = GitlabRestAPI
# Keep the acronym spelling available to callers that use the protocol name.
GitlabHTTPAPI = GitlabRestAPI

__all__ = [
    "GitlabAPIError",
    "GitlabAPIErrorCode",
    "GitlabHTTPRequest",
    "GitlabHTTPResponse",
    "GitlabAuthenticatedAPI",
    "GitlabHttpAPI",
    "GitlabHTTPAPI",
]
