"""P6.6 connected CLI: submit one checkout to a control plane and follow the run.

The connected path never touches source bytes itself: it authenticates to the
control plane, asks it to admit the exact revision, streams the run until a
terminal outcome, and renders a source-free reference for the operator.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_RESPONSE_BYTES = 1_048_576
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
    base_sha: str | None = None
    change_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not _identifier(self.tenant_id)
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


class HttpConnectedApi:
    """Minimal control-plane client: no redirects, bounded body, bearer auth."""

    def __init__(self, base_url: str, *, timeout_seconds: float = 30.0) -> None:
        if type(timeout_seconds) is not float or not 0 < timeout_seconds <= 300:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        self._base_url = _safe_base_url(base_url)
        self._timeout = timeout_seconds
        self._opener = build_opener(_NoRedirect)

    def submit(self, request: ConnectedRunRequest, *, token: str) -> dict[str, object]:
        document: dict[str, object] = {
            "tenant_id": request.tenant_id,
            "repository_id": request.repository_id,
            "head_sha": request.head_sha,
        }
        if request.base_sha is not None:
            document["base_sha"] = request.base_sha
        if request.change_id is not None:
            document["change_id"] = request.change_id
        return self._call("POST", "/api/v1/runs", document=document, token=token)

    def status(self, run_id: str, *, token: str) -> dict[str, object]:
        if not _identifier(run_id):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        return self._call("GET", f"/api/v1/runs/{run_id}", document=None, token=token)

    def _call(
        self,
        method: str,
        path: str,
        *,
        document: dict[str, object] | None,
        token: str,
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
        request = Request(
            self._base_url + path,
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


@dataclass(frozen=True, slots=True)
class ConnectedRunSettings:
    """Operator-supplied connected configuration resolved from the environment."""

    base_url: str
    token: str
    tenant_id: str
    repository_id: str
    head_sha: str
    base_sha: str | None = None
    change_id: str | None = None


def settings_from_environment(
    environment: Mapping[str, str],
) -> ConnectedRunSettings:
    """Read connected-mode settings without ever logging their values."""

    def required(name: str) -> str:
        value = environment.get(name)
        if type(value) is not str or not value:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        return value

    return ConnectedRunSettings(
        base_url=required("SECURECODE_CONTROL_PLANE_URL"),
        token=required("SECURECODE_CONTROL_PLANE_TOKEN"),
        tenant_id=required("SECURECODE_TENANT_ID"),
        repository_id=required("SECURECODE_REPOSITORY_ID"),
        head_sha=required("SECURECODE_HEAD_SHA"),
        base_sha=environment.get("SECURECODE_BASE_SHA") or None,
        change_id=environment.get("SECURECODE_CHANGE_ID") or None,
    )


def run_connected(
    settings: ConnectedRunSettings,
    *,
    api: ConnectedApi | None = None,
    poll_status: bool = True,
    attempts: int = 1,
) -> ConnectedRunReceipt:
    """Submit one revision and (optionally) report its terminal state."""

    if type(attempts) is not int or attempts < 1:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    request = ConnectedRunRequest(
        tenant_id=settings.tenant_id,
        repository_id=settings.repository_id,
        head_sha=settings.head_sha,
        base_sha=settings.base_sha,
        change_id=settings.change_id,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    submission = client.submit(request, token=settings.token)
    receipt = _receipt(submission)
    if not poll_status:
        return receipt
    latest = receipt
    for _ in range(attempts):
        document = client.status(receipt.run_id, token=settings.token)
        latest = _receipt(document)
        if latest.outcome is not None:
            return latest
    if latest.outcome is None:
        raise ConnectedCliError(ConnectedCliErrorCode.RUN_NOT_TERMINAL)
    return latest


def render_receipt(receipt: ConnectedRunReceipt, output: TextIO) -> None:
    """Write the canonical source-free reference for shell consumption."""

    output.write(json.dumps(receipt.document(), sort_keys=True, separators=(",", ":")) + "\n")


def new_idempotency_key() -> str:
    """Reuse one key across retries of the same connected submission."""

    return "cli-" + uuid.uuid4().hex


def parse_connected_arguments(tokens: tuple[str, ...]) -> tuple[Path | None, bool]:
    """Parse `securecode connect [target] [--wait] [--dry-run]`."""

    target: Path | None = None
    wait = False
    for token in tokens:
        if token == "--wait":
            wait = True
        elif token.startswith("-"):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        elif target is None:
            target = Path(token)
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return target, wait


def timestamp() -> str:
    """Canonical UTC timestamp helper shared by connected receipts."""

    return datetime.now(UTC).isoformat()


__all__ = [
    "ConnectedApi",
    "ConnectedCliError",
    "ConnectedCliErrorCode",
    "ConnectedRunReceipt",
    "ConnectedRunRequest",
    "ConnectedRunSettings",
    "HttpConnectedApi",
    "new_idempotency_key",
    "parse_connected_arguments",
    "render_receipt",
    "run_connected",
    "settings_from_environment",
    "timestamp",
]
