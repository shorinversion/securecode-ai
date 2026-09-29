"""Connected control-plane transport and bounded wire contracts."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_RESPONSE_BYTES = 1_048_576
MAX_BINARY_RESPONSE_BYTES = 16_777_216

# Keep operator supplied JSON bounded before it reaches the control plane. The
# server has a larger transport limit, but the CLI must not turn a single
# argument or nested payload into an unbounded request allocation.
MAX_REQUEST_BYTES = 1_048_576

_SUCCESS_STATUSES: dict[str, frozenset[int]] = {
    "GET": frozenset({200}),
    "POST": frozenset({200, 201, 202}),
}


_RECEIPT_TRIPLES = frozenset(
    {
        ("PENDING", "ADMITTED", None),
        ("ADMITTED", "ADMITTED", None),
        ("BLOCKED", "COMPLETED", None),
        ("FAILED", "COMPLETED", None),
        ("COMPLETED", "COMPLETED", "PASS"),
        ("COMPLETED", "COMPLETED", "FAIL"),
        ("COMPLETED", "COMPLETED", "INDETERMINATE"),
        ("COMPLETED", "COMPLETED", "CANCELLED"),
        ("SUPERSEDED", "SUPERSEDED", "SUPERSEDED"),
    }
)


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


class ConnectedOperation(StrEnum):
    """Per-run intent forwarded to the connected worker lease."""

    SCAN = "SCAN"
    REPAIR = "REPAIR"


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
    operation: ConnectedOperation = ConnectedOperation.SCAN
    scm_provider: str | None = None

    def __post_init__(self) -> None:
        if (
            not _idempotency_key(self.idempotency_key)
            or not _identifier(self.tenant_id)
            or not _identifier(self.repository_id)
            or not _commit(self.head_sha)
            or (self.base_sha is not None and not _commit(self.base_sha))
            or (self.change_id is not None and not _identifier(self.change_id))
            or (self.scm_provider is not None and self.scm_provider not in {"github", "gitlab"})
            or type(self.operation) is not ConnectedOperation
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

    @property
    def terminal(self) -> bool:
        """Whether the server has finished the run lifecycle.

        Admission failures are terminal even though they intentionally have no
        worker outcome. Looking only at ``outcome`` would make the CLI poll
        those durable failures until it reports a misleading timeout.
        """

        return self.lifecycle != "ADMITTED"

    def document(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "disposition": self.disposition,
            "lifecycle": self.lifecycle,
            "head_sha": self.head_sha,
            "outcome": self.outcome,
            "state_version": self.state_version,
        }


def _identifier(value: object) -> bool:
    return (
        type(value) is str
        and value.isascii()
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
    total_size = 0
    for name, value in query.items():
        maximum_value_length = 1024 if type(name) is str and name == "cursor" else 256
        if (
            type(name) is not str
            or not name.isascii()
            or not name
            or len(name) > 64
            or not all(character.isalnum() or character in "_-" for character in name)
            or type(value) is not str
            or not value
            or len(value) > maximum_value_length
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        try:
            encoded_value = quote(value, safe="")
        except UnicodeEncodeError:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
        pair = f"{name}={encoded_value}"
        total_size += len(pair) + 1
        if total_size > 4096:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        pairs.append(pair)
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
        and value.isascii()
        and 8 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


def _precondition(value: object) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        return False
    return not any(character in value for character in ("\r", "\n"))


def _version_precondition(
    value: object,
    *,
    minimum: int = 0,
    maximum: int = 2_147_483_647,
) -> bool:
    """Validate the numeric If-Match grammar consumed by server handlers."""

    if not _precondition(value) or type(value) is not str:
        return False
    if value.startswith('W/"') and value.endswith('"'):
        value = value[3:-1]
    elif value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    if not value.isascii() or not value.isdecimal() or len(value) > 10:
        return False
    version = int(value)
    return minimum <= version <= maximum


def _exact_version_precondition(
    value: object,
    *,
    minimum: int = 0,
    maximum: int = 2_147_483_647,
) -> bool:
    """Validate the stricter run-cancellation precondition grammar."""

    if not _precondition(value) or type(value) is not str:
        return False
    # ``runs.cancel`` passes the header through ``service._precondition``,
    # which compares the parsed value to the integer state version and does
    # not accept weak ETags. Other handlers use ``expected_version`` and do
    # accept them, so this stricter check must remain route-specific.
    if value.startswith('W/"') and value.endswith('"'):
        return False
    if value.startswith('"') or value.endswith('"'):
        if len(value) < 3 or not (value.startswith('"') and value.endswith('"')):
            return False
        value = value[1:-1]
    if not value.isascii() or not value.isdecimal() or len(value) > 10:
        return False
    version = int(value)
    return minimum <= version <= maximum


def _commit(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _safe_base_url(value: str) -> str:
    """Accept only a redirect-free origin; plaintext HTTP stays on loopback."""

    if type(value) is not str or not 1 <= len(value) <= 2048:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
    if (
        parts.scheme not in ALLOWED_SCHEMES
        or not parts.hostname
        or (port is not None and not 1 <= port <= 65535)
        or parts.path not in {"", "/"}
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


class ConnectedArtifactApi(ConnectedApi, Protocol):
    def download(self, run_id: str, content_sha256: str, *, token: str) -> bytes: ...

    def download_repair_patch(
        self, run_id: str, finding_id: str, patch_sha256: str, *, token: str
    ) -> bytes: ...


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
        if request.scm_provider is not None:
            document["scm_provider"] = request.scm_provider
        document["operation"] = request.operation.value
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

    def download(self, run_id: str, content_sha256: str, *, token: str) -> bytes:
        """Download one bounded, tenant-bound artifact and verify its digest."""

        if not _identifier(run_id) or not _sha256(content_sha256):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        body, headers = self._call_bytes(
            "GET",
            f"/api/v1/runs/{run_id}/artifacts/{content_sha256}/content",
            token=token,
        )
        if (
            headers.get("content-type") != "application/octet-stream"
            or headers.get("cache-control") != "no-store"
            or headers.get("content-sha256") != content_sha256
            or headers.get("content-length") != str(len(body))
            or not 1 <= len(body) <= MAX_BINARY_RESPONSE_BYTES
            or hashlib.sha256(body).hexdigest() != content_sha256
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        return body

    def download_repair_patch(
        self, run_id: str, finding_id: str, patch_sha256: str, *, token: str
    ) -> bytes:
        """Download one exact repair bundle through its dedicated route."""

        if not _identifier(run_id) or not _identifier(finding_id) or not _sha256(patch_sha256):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        body, headers = self._call_bytes(
            "GET",
            f"/api/v1/runs/{run_id}/repair-patches/{finding_id}/content",
            token=token,
            query={"patch_sha256": patch_sha256},
        )
        digest = hashlib.sha256(body).hexdigest() if body else ""
        if (
            headers.get("content-type") != "application/octet-stream"
            or headers.get("cache-control") != "no-store"
            or headers.get("content-sha256") != digest
            or headers.get("x-securecode-repair-finding") != finding_id
            or headers.get("x-securecode-repair-patch-sha256") != patch_sha256
            or headers.get("content-length") != str(len(body))
            or not 1 <= len(body) <= MAX_BINARY_RESPONSE_BYTES
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        return body

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

        if not _identifier(run_id) or not _exact_version_precondition(if_match, minimum=1):
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
        if method not in _SUCCESS_STATUSES or not _api_path(path):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        try:
            payload = (
                None
                if document is None
                else json.dumps(
                    document,
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("ascii")
            )
        except (TypeError, UnicodeEncodeError, ValueError, RecursionError):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
        if payload is not None and len(payload) > MAX_REQUEST_BYTES:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
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
            if 300 <= error.code < 400:
                code = ConnectedCliErrorCode.PROTOCOL_INVALID
            elif 400 <= error.code < 500:
                code = ConnectedCliErrorCode.REJECTED
            else:
                code = ConnectedCliErrorCode.UNREACHABLE
            raise ConnectedCliError(code) from None
        except (URLError, OSError, ValueError):
            raise ConnectedCliError(ConnectedCliErrorCode.UNREACHABLE) from None
        if (
            status not in _SUCCESS_STATUSES.get(method, frozenset())
            or len(body) > MAX_RESPONSE_BYTES
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        try:
            parsed = json.loads(
                body.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID) from None
        if type(parsed) is not dict:
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        return parsed

    def _call_bytes(
        self,
        method: str,
        path: str,
        *,
        token: str,
        query: Mapping[str, str] | None = None,
    ) -> tuple[bytes, dict[str, str]]:
        if type(token) is not str or not 1 <= len(token) <= 8192:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if any(ord(character) < 33 or ord(character) > 126 for character in token):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if method not in _SUCCESS_STATUSES or not _api_path(path):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        request = Request(
            self._base_url + path + _safe_query(query),
            headers={
                "Accept": "application/octet-stream",
                "Authorization": "Bearer " + token,
                "User-Agent": "securecode-ai/1.0",
            },
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                body = response.read(MAX_BINARY_RESPONSE_BYTES + 1)
                status = response.status
                raw_headers: dict[str, list[str]] = {}
                for name, value in response.headers.items():
                    raw_headers.setdefault(str(name).lower(), []).append(str(value))
                if any(len(values) != 1 for values in raw_headers.values()):
                    raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
                headers = {name: values[0] for name, values in raw_headers.items()}
        except HTTPError as error:
            if 300 <= error.code < 400:
                code = ConnectedCliErrorCode.PROTOCOL_INVALID
            elif 400 <= error.code < 500:
                code = ConnectedCliErrorCode.REJECTED
            else:
                code = ConnectedCliErrorCode.UNREACHABLE
            raise ConnectedCliError(code) from None
        except (URLError, OSError, ValueError):
            raise ConnectedCliError(ConnectedCliErrorCode.UNREACHABLE) from None
        if (
            status not in _SUCCESS_STATUSES.get(method, frozenset())
            or len(body) > MAX_BINARY_RESPONSE_BYTES
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
        return body, headers


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError
        document[key] = value
    return document


def _reject_json_constant(_value: str) -> object:
    raise ValueError


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _receipt(document: Mapping[str, object]) -> ConnectedRunReceipt:
    if not isinstance(document, Mapping):
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    run_id = document.get("run_id")
    state = document.get("state")
    disposition = document.get("disposition", state)
    lifecycle = document.get("lifecycle", state)
    head_sha = document.get("head_sha")
    outcome = document.get("outcome")
    state_version = document.get("state_version", document.get("version"))
    if (
        not isinstance(run_id, str)
        or not _identifier(run_id)
        or not isinstance(disposition, str)
        or not isinstance(lifecycle, str)
        or not isinstance(head_sha, str)
        or not _commit(head_sha)
        or (outcome is not None and not isinstance(outcome, str))
        or type(state_version) is not int
        or not 0 <= state_version <= 2_147_483_647
        or (disposition, lifecycle, outcome) not in _RECEIPT_TRIPLES
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
