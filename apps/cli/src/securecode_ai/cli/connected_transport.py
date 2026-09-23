"""Connected control-plane transport and bounded wire contracts."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_RESPONSE_BYTES = 1_048_576


INITIAL_POLL_SECONDS = 1.0


MAXIMUM_POLL_SECONDS = 15.0


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


ALLOWED_SCHEMES = frozenset({"https", "http"})


class ConnectedCliErrorCode(StrEnum):
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    UNREACHABLE = "UNREACHABLE"
    REJECTED = "REJECTED"
    PROTOCOL_INVALID = "PROTOCOL_INVALID"
    RUN_NOT_TERMINAL = "RUN_NOT_TERMINAL"


class ConnectedCliError(RuntimeError):
    """Bounded connected-mode failure that never carries credentials or source."""

    __slots__ = ("code",)

    def __init__(self, code: ConnectedCliErrorCode) -> None:
        self.code = code
        super().__init__("connected CLI operation was rejected")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: object, **_kwargs: object) -> None:  # pragma: no cover
        return None


@dataclass(frozen=True, slots=True)
class ConnectedRunRequest:
    """Trusted identity supplied by the operator for one connected submission."""

    tenant_id: str
    repository_id: str
    head_sha: str
    idempotency_key: str
    base_sha: str | None = None
    change_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not _idempotency_key(self.idempotency_key)
            or not _identifier(self.tenant_id)
            or not _identifier(self.repository_id)
            or not _commit(self.head_sha)
            or (self.base_sha is not None and not _commit(self.base_sha))
            or (self.change_id is not None and not _identifier(self.change_id))
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


@dataclass(frozen=True, slots=True)
class ConnectedRunReceipt:
    """Source-free reference for one connected run."""

    run_id: str
    disposition: str
    lifecycle: str
    head_sha: str
    outcome: str | None
    state_version: int

    def document(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "disposition": self.disposition,
            "lifecycle": self.lifecycle,
            "head_sha": self.head_sha,
            "outcome": self.outcome,
            "state_version": self.state_version,
        }


def _identifier(value: str) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


def _safe_query(query: Mapping[str, str] | None) -> str:
    """Render a bounded, encoded query string from validated scalar parameters."""

    if query is None:
        return ""
    if not isinstance(query, Mapping) or len(query) > 8:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    pairs: list[str] = []
    for name, value in query.items():
        if (
            type(name) is not str
            or not name
            or len(name) > 64
            or not all(character.isalnum() or character in "_-" for character in name)
            or type(value) is not str
            or not value
            or len(value) > 256
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        pairs.append(f"{name}={quote(value, safe='')}")
    return "?" + "&".join(sorted(pairs))


def _api_path(value: object) -> bool:
    return (
        type(value) is str
        and value.startswith("/api/v1/")
        and ".." not in value
        and "?" not in value
        and "#" not in value
        and len(value) <= 256
    )


def _idempotency_key(value: object) -> bool:
    return (
        type(value) is str
        and 8 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


def _precondition(value: object) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        return False
    return not any(character in value for character in ("\r", "\n"))


def _commit(value: str) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_base_url(value: str) -> str:
    """Accept only a redirect-free origin; plaintext HTTP stays on loopback."""

    try:
        parts = urlsplit(value)
    except ValueError:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
    if (
        parts.scheme not in ALLOWED_SCHEMES
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or (parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return value.rstrip("/")


class ConnectedApi(Protocol):
    def submit(self, request: ConnectedRunRequest, *, token: str) -> dict[str, object]: ...

    def status(self, run_id: str, *, token: str) -> dict[str, object]: ...

    def cancel(
        self, run_id: str, *, token: str, if_match: str, idempotency_key: str
    ) -> dict[str, object]: ...

    def read(
        self, path: str, *, token: str, query: Mapping[str, str] | None = None
    ) -> dict[str, object]: ...

    def mutate(
        self,
        path: str,
        *,
        document: dict[str, object],
        token: str,
        idempotency_key: str,
        if_match: str | None = None,
    ) -> dict[str, object]: ...


class HttpConnectedApi:
    """Minimal control-plane client: no redirects, bounded body, bearer auth."""

    def __init__(self, base_url: str, *, timeout_seconds: float = 30.0) -> None:
        if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 300:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        self._base_url = _safe_base_url(base_url)
        self._timeout = timeout_seconds
        self._opener = build_opener(_NoRedirect)

    def submit(self, request: ConnectedRunRequest, *, token: str) -> dict[str, object]:
        if not _idempotency_key(request.idempotency_key):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        document: dict[str, object] = {
            "tenant_id": request.tenant_id,
            "repository_id": request.repository_id,
            "head_sha": request.head_sha,
        }
        if request.base_sha is not None:
            document["base_sha"] = request.base_sha
        if request.change_id is not None:
            document["change_id"] = request.change_id
        return self._call(
            "POST",
            "/api/v1/runs",
            document=document,
            token=token,
            idempotency_key=request.idempotency_key,
        )

    def status(self, run_id: str, *, token: str) -> dict[str, object]:
        if not _identifier(run_id):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        return self._call("GET", f"/api/v1/runs/{run_id}", document=None, token=token)

    def read(
        self, path: str, *, token: str, query: Mapping[str, str] | None = None
    ) -> dict[str, object]:
        """Read one bounded document; the path must be an allowlisted API route."""

        if not isinstance(path, str) or not _api_path(path):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        return self._call("GET", path, document=None, token=token, query=_safe_query(query))

    def mutate(
        self,
        path: str,
        *,
        document: dict[str, object],
        token: str,
        idempotency_key: str,
        if_match: str | None = None,
    ) -> dict[str, object]:
        """Perform one mutating call with the headers the server requires."""

        if not _api_path(path) or not _idempotency_key(idempotency_key):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if if_match is not None and not _precondition(if_match):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        return self._call(
            "POST",
            path,
            document=document,
            token=token,
            idempotency_key=idempotency_key,
            if_match=if_match,
        )

    def cancel(
        self, run_id: str, *, token: str, if_match: str, idempotency_key: str
    ) -> dict[str, object]:
        """Cancel one run; the server requires a precondition and an idempotency key."""

        if not _identifier(run_id) or not _precondition(if_match):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _idempotency_key(idempotency_key):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        return self._call(
            "POST",
            f"/api/v1/runs/{run_id}:cancel",
            document={"reason": "operator-requested"},
            token=token,
            idempotency_key=idempotency_key,
            if_match=if_match,
        )

    def _call(
        self,
        method: str,
        path: str,
        *,
        document: dict[str, object] | None,
        token: str,
        idempotency_key: str | None = None,
        if_match: str | None = None,
        query: str = "",
    ) -> dict[str, object]:
        if type(token) is not str or not 1 <= len(token) <= 8192:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if any(ord(character) < 33 or ord(character) > 126 for character in token):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        payload = (
            None
            if document is None
            else json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        )
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
            "User-Agent": "securecode-ai/1.0",
        }
        if payload is not None:
            headers["Content-Type"] = "application/json"
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        if if_match is not None:
            headers["If-Match"] = if_match
        request = Request(
            self._base_url + path + query,
            data=payload,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
        except HTTPError as error:
            raise ConnectedCliError(
                ConnectedCliErrorCode.REJECTED
                if 400 <= error.code < 500
                else ConnectedCliErrorCode.UNREACHABLE
            ) from None
        except (URLError, OSError, ValueError):
            raise ConnectedCliError(ConnectedCliErrorCode.UNREACHABLE) from None
        if status != 200 or len(body) > MAX_RESPONSE_BYTES:
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID) from None
        if not isinstance(parsed, dict):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        return parsed


def _receipt(document: Mapping[str, object]) -> ConnectedRunReceipt:
    run_id = document.get("run_id")
    disposition = document.get("disposition")
    lifecycle = document.get("lifecycle")
    head_sha = document.get("head_sha")
    outcome = document.get("outcome")
    state_version = document.get("state_version")
    if (
        not isinstance(run_id, str)
        or not _identifier(run_id)
        or not isinstance(disposition, str)
        or not isinstance(lifecycle, str)
        or not isinstance(head_sha, str)
        or not _commit(head_sha)
        or (outcome is not None and not isinstance(outcome, str))
        or type(state_version) is not int
        or state_version < 0
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return ConnectedRunReceipt(
        run_id=run_id,
        disposition=disposition,
        lifecycle=lifecycle,
        head_sha=head_sha,
        outcome=outcome,
        state_version=state_version,
    )
