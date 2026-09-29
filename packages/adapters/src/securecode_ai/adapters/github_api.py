"""Bounded authenticated GitHub REST transport."""

from __future__ import annotations

import json
import re
import ssl
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPSConnection
from typing import Protocol
from urllib.parse import quote, urlsplit

_MAX_BODY_BYTES = 1_048_576
_INSTALLATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_REPOSITORY_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


class GitHubError(Exception):
    """Redacted GitHub boundary error."""

    def __init__(self, code: str, retryable: bool = False) -> None:
        self.code = code
        self.retryable = retryable
        super().__init__("GitHub request was rejected")


class InstallationTokenProvider(Protocol):
    def token(self, installation_id: str) -> str: ...


@dataclass(frozen=True, slots=True)
class GitHubResponse:
    status: int
    document: dict[str, object] | list[object] | None
    headers: dict[str, str]


class GitHubApi:
    """Perform one authenticated request without redirects or implicit retries."""

    def __init__(self, base_url: str, tokens: InstallationTokenProvider) -> None:
        value = urlsplit(base_url)
        if (
            value.scheme not in {"https", "http"}
            or not value.hostname
            or value.username is not None
            or value.password is not None
            or value.query
            or value.fragment
            or (value.scheme == "http" and value.hostname not in {"127.0.0.1", "::1", "localhost"})
            or not callable(getattr(tokens, "token", None))
        ):
            raise ValueError("unsafe GitHub API configuration")
        self._base = value
        self._base_path = value.path.rstrip("/")
        self._tokens = tokens

    def request(
        self,
        method: str,
        path: str,
        *,
        installation_id: str,
        document: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> GitHubResponse:
        if type(method) is not str or method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise GitHubError("INVALID_METHOD")
        if type(path) is not str or not path.startswith("/") or ".." in path.split("/"):
            raise GitHubError("INVALID_PATH")
        if type(installation_id) is not str or _INSTALLATION_ID.fullmatch(installation_id) is None:
            raise GitHubError("INVALID_INSTALLATION")
        body = _request_body(document)
        try:
            token = self._tokens.token(installation_id)
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            raise
        except Exception:
            raise GitHubError("TOKEN_UNAVAILABLE") from None
        if (
            type(token) is not str
            or not 1 <= len(token) <= 8192
            or any(ord(character) < 33 or ord(character) > 126 for character in token)
        ):
            raise GitHubError("TOKEN_UNAVAILABLE")
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token,
            "User-Agent": "securecode-ai/1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        if idempotency_key is not None:
            if (
                type(idempotency_key) is not str
                or not 1 <= len(idempotency_key) <= 256
                or not idempotency_key.isascii()
            ):
                raise GitHubError("INVALID_IDEMPOTENCY_KEY")
            headers["Idempotency-Key"] = idempotency_key

        connection = self._connection()
        try:
            connection.request(method, self._base_path + path, body, headers)
            response = connection.getresponse()
            raw = response.read(_MAX_BODY_BYTES + 1)
            status = response.status
            response_headers = {key.lower(): value for key, value in response.getheaders()}
        except OSError:
            raise GitHubError("TRANSPORT", True) from None
        finally:
            connection.close()
        if len(raw) > _MAX_BODY_BYTES:
            raise GitHubError("RESPONSE_LIMIT")
        if status in {301, 302, 303, 307, 308}:
            raise GitHubError("REDIRECT_DENIED")
        parsed = _response_document(raw)
        if status >= 400:
            rate_limited = status == 403 and (
                response_headers.get("x-ratelimit-remaining") == "0"
                or "retry-after" in response_headers
            )
            raise GitHubError(
                "HTTP_" + str(status),
                rate_limited or status in {408, 425, 429} or status >= 500,
            )
        return GitHubResponse(status, parsed, response_headers)

    def _connection(self) -> HTTPConnection:
        hostname = self._base.hostname
        if hostname is None:
            raise ValueError("unsafe GitHub API configuration")
        if self._base.scheme == "https":
            return HTTPSConnection(
                hostname,
                self._base.port,
                timeout=15,
                context=ssl.create_default_context(),
            )
        return HTTPConnection(hostname, self._base.port, timeout=15)

    def repository_path_for_id(self, installation_id: str, repository_id: str) -> str:
        """Resolve GitHub's database repository ID to a canonical REST path."""

        if (
            type(installation_id) is not str
            or type(repository_id) is not str
            or _INSTALLATION_ID.fullmatch(installation_id) is None
            or _REPOSITORY_ID.fullmatch(repository_id) is None
        ):
            raise GitHubError("INVALID_REPOSITORY")
        response = self.request(
            "GET",
            "/repositories/" + repository_id,
            installation_id=installation_id,
        )
        document = response.document
        full_name = document.get("full_name") if type(document) is dict else None
        if type(full_name) is not str or full_name.count("/") != 1:
            raise GitHubError("INVALID_REPOSITORY")
        owner, repository = full_name.split("/", 1)
        if any(
            not component
            or component in {".", ".."}
            or len(component) > 100
            or not component.isascii()
            or any(ord(character) < 33 or ord(character) > 126 for character in component)
            for component in (owner, repository)
        ):
            raise GitHubError("INVALID_REPOSITORY")
        return repository_path(owner, repository)


def _request_body(document: dict[str, object] | None) -> bytes | None:
    if document is None:
        return None
    try:
        body = json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise GitHubError("INVALID_DOCUMENT") from None
    if len(body) > _MAX_BODY_BYTES:
        raise GitHubError("BODY_LIMIT")
    return body


def _response_document(raw: bytes) -> dict[str, object] | list[object] | None:
    if not raw:
        return None

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate response key")
            value[key] = item
        return value

    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise GitHubError("INVALID_RESPONSE") from None
    if type(parsed) is dict or type(parsed) is list:
        return parsed
    raise GitHubError("INVALID_RESPONSE")


def repository_path(owner: str, repo: str) -> str:
    if not owner or not repo:
        raise GitHubError("INVALID_REPOSITORY")
    return "/repos/" + quote(owner, safe="") + "/" + quote(repo, safe="")


__all__ = [
    "GitHubApi",
    "GitHubError",
    "GitHubResponse",
    "InstallationTokenProvider",
    "repository_path",
]
