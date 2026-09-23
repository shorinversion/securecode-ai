"""P6.6 connected CLI: submit one checkout to a control plane and follow the run.

The connected path never touches source bytes itself: it authenticates to the
control plane, asks it to admit the exact revision, streams the run until a
terminal outcome, and renders a source-free reference for the operator.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol, TextIO
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


@dataclass(frozen=True, slots=True)
class ConnectedRunSettings:
    """Operator-supplied connected configuration resolved from the environment."""

    base_url: str
    token: str
    tenant_id: str
    repository_id: str
    head_sha: str
    idempotency_key: str
    base_sha: str | None = None
    change_id: str | None = None


def settings_from_environment(
    environment: Mapping[str, str],
    *,
    fresh: bool = False,
) -> ConnectedRunSettings:
    """Read connected-mode settings without ever logging their values.

    Unless ``fresh`` is requested, the submission key is derived from the exact
    revision so a retried command resumes the recorded run instead of duplicating
    it; ``SECURECODE_IDEMPOTENCY_KEY`` still overrides both.
    """

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
        idempotency_key=(
            environment.get("SECURECODE_IDEMPOTENCY_KEY")
            or (new_idempotency_key() if fresh else _pending_key(environment))
        ),
        base_sha=environment.get("SECURECODE_BASE_SHA") or None,
        change_id=environment.get("SECURECODE_CHANGE_ID") or None,
    )


def _pending_key(environment: Mapping[str, str]) -> str:
    """Compose the resumable key from the settings the operator supplied."""

    def value(name: str) -> str:
        raw = environment.get(name)
        return raw if isinstance(raw, str) else ""

    material = json.dumps(
        {
            "base_sha": value("SECURECODE_BASE_SHA") or None,
            "change_id": value("SECURECODE_CHANGE_ID") or None,
            "head_sha": value("SECURECODE_HEAD_SHA"),
            "repository_id": value("SECURECODE_REPOSITORY_ID"),
            "tenant_id": value("SECURECODE_TENANT_ID"),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "cli-" + hashlib.sha256(material).hexdigest()[:48]


def run_connected(
    settings: ConnectedRunSettings,
    *,
    api: ConnectedApi | None = None,
    poll_status: bool = True,
    attempts: int = 1,
    sleeper: Callable[[float], None] | None = None,
) -> ConnectedRunReceipt:
    """Submit one revision and (optionally) report its terminal state."""

    if type(attempts) is not int or attempts < 1:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    request = ConnectedRunRequest(
        tenant_id=settings.tenant_id,
        repository_id=settings.repository_id,
        head_sha=settings.head_sha,
        idempotency_key=settings.idempotency_key,
        base_sha=settings.base_sha,
        change_id=settings.change_id,
    )
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    submission = client.submit(request, token=settings.token)
    receipt = _receipt(submission)
    if not poll_status:
        return receipt
    latest = receipt
    delay = INITIAL_POLL_SECONDS
    for attempt in range(attempts):
        document = client.status(receipt.run_id, token=settings.token)
        latest = _receipt(document)
        if latest.outcome is not None:
            return latest
        if attempt + 1 < attempts and sleeper is not None:
            sleeper(delay)
            delay = min(delay * 2, MAXIMUM_POLL_SECONDS)
    if latest.outcome is None:
        raise ConnectedCliError(ConnectedCliErrorCode.RUN_NOT_TERMINAL)
    return latest


def fetch_run(
    settings: ConnectedRunSettings, run_id: str, *, api: ConnectedApi | None = None
) -> ConnectedRunReceipt:
    """Read one run's current durable state without mutating anything."""

    client = api if api is not None else HttpConnectedApi(settings.base_url)
    return _receipt(client.status(run_id, token=settings.token))


def cancel_run(
    settings: ConnectedRunSettings,
    run_id: str,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedRunReceipt:
    """Request cancellation; the caller supplies the observed state precondition."""

    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.cancel(
        run_id,
        token=settings.token,
        if_match=if_match,
        idempotency_key=idempotency_key or new_idempotency_key(),
    )
    return _receipt(document)


def render_receipt(receipt: ConnectedRunReceipt, output: TextIO) -> None:
    """Write the canonical source-free reference for shell consumption."""

    output.write(json.dumps(receipt.document(), sort_keys=True, separators=(",", ":")) + "\n")


def new_idempotency_key() -> str:
    """A fresh key, for callers that explicitly want a new run."""

    return "cli-" + uuid.uuid4().hex


def resumable_idempotency_key(settings: ConnectedRunSettings) -> str:
    """Derive a stable key from the exact submission so retries resume one run.

    Re-running the same command for the same revision therefore replays the
    recorded admission instead of opening a second run, which is what a CI
    job retry needs. Callers that want a genuinely new run generate a fresh key.
    """

    material = json.dumps(
        {
            "base_sha": settings.base_sha,
            "change_id": settings.change_id,
            "head_sha": settings.head_sha,
            "repository_id": settings.repository_id,
            "tenant_id": settings.tenant_id,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return "cli-" + hashlib.sha256(material).hexdigest()[:48]


def parse_run_arguments(tokens: tuple[str, ...]) -> tuple[str, str | None]:
    """Parse `securecode status|cancel <run_id> [--if-match <value>]`."""

    run_id: str | None = None
    if_match: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--if-match":
            if index + 1 >= len(tokens):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            if_match = tokens[index + 1]
            index += 2
            continue
        if token.startswith("-") or run_id is not None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        run_id = token
        index += 1
    if run_id is None or not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if if_match is not None and not _precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, if_match


def parse_connected_arguments(tokens: tuple[str, ...]) -> tuple[Path | None, bool, bool]:
    """Parse `securecode connect [target] [--wait] [--new-run]`."""

    target: Path | None = None
    wait = False
    fresh = False
    for token in tokens:
        if token == "--wait":
            wait = True
        elif token == "--new-run":
            fresh = True
        elif token.startswith("-"):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        elif target is None:
            target = Path(token)
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return target, wait, fresh


def timestamp() -> str:
    """Canonical UTC timestamp helper shared by connected receipts."""

    return datetime.now(UTC).isoformat()


class ResultKind(StrEnum):
    """Readable run outputs exposed by the control plane."""

    FINDINGS = "findings"
    ARTIFACTS = "artifacts"
    EVENTS = "events"

    @property
    def path(self) -> str:
        return f"/api/v1/runs/{{run_id}}/{self.value}"


@dataclass(frozen=True, slots=True)
class ConnectedCollection:
    """One bounded, source-free readout document for a run."""

    run_id: str
    kind: ResultKind
    document: Mapping[str, object]

    def render(self) -> str:
        return json.dumps(self.document, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def fetch_results(
    settings: ConnectedRunSettings,
    run_id: str,
    kind: ResultKind,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read findings, artifacts or events for one run without mutating anything."""

    if not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if type(kind) is not ResultKind:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(kind.path.format(run_id=run_id), token=settings.token)
    if not isinstance(document, Mapping) or not document:
        raise ConnectedCliError(ConnectedCliErrorCode.PROTOCOL_INVALID)
    return ConnectedCollection(run_id=run_id, kind=kind, document=document)


def parse_results_arguments(tokens: tuple[str, ...]) -> tuple[str, ResultKind]:
    """Parse `securecode results <run_id> --kind findings|artifacts|events`."""

    run_id: str | None = None
    kind: ResultKind | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--kind":
            if index + 1 >= len(tokens):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            try:
                kind = ResultKind(tokens[index + 1])
            except ValueError:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
            index += 2
            continue
        if token.startswith("-") or run_id is not None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        run_id = token
        index += 1
    if run_id is None or not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, kind if kind is not None else ResultKind.FINDINGS


@dataclass(frozen=True, slots=True)
class ApprovalDraft:
    """Operator-supplied fields for one approval request."""

    approval_id: str
    repository_id: str
    run_id: str
    finding_id: str
    execution_identity_hash: str
    expires_at: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.approval_id)
            or not _identifier(self.repository_id)
            or not _identifier(self.run_id)
            or not _identifier(self.finding_id)
            or not _sha256(self.execution_identity_hash)
            or not _timestamp(self.expires_at)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _timestamp(value: object) -> bool:
    if type(value) is not str or not 20 <= len(value) <= 40:
        return False
    return value[4] == "-" and value[7] == "-" and "T" in value


def create_approval(
    settings: ConnectedRunSettings,
    draft: ApprovalDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Open one pending approval bound to an exact run and identity."""

    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/approvals",
        document={
            "approval_id": draft.approval_id,
            "repository_id": draft.repository_id,
            "run_id": draft.run_id,
            "finding_id": draft.finding_id,
            "execution_identity_hash": draft.execution_identity_hash,
            "expires_at": draft.expires_at,
        },
        token=settings.token,
        idempotency_key=key,
    )
    return ConnectedCollection(run_id=draft.run_id, kind=ResultKind.FINDINGS, document=document)


def read_approval(
    settings: ConnectedRunSettings,
    approval_id: str,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read one approval's durable state."""

    if not _identifier(approval_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(f"/api/v1/approvals/{approval_id}", token=settings.token)
    return ConnectedCollection(run_id=approval_id, kind=ResultKind.FINDINGS, document=document)


def decide_approval(
    settings: ConnectedRunSettings,
    approval_id: str,
    *,
    approve: bool,
    reason_code: str,
    rationale: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Record an approval decision against the observed state precondition."""

    if not _identifier(approval_id) or not _precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if type(approve) is not bool or not _identifier(reason_code) or not rationale:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if len(reason_code) > 64 or len(rationale) > 1024:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        f"/api/v1/approvals/{approval_id}:decide",
        document={"approve": approve, "reason_code": reason_code, "rationale": rationale},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=approval_id, kind=ResultKind.FINDINGS, document=document)


def parse_approval_arguments(tokens: tuple[str, ...]) -> dict[str, str]:
    """Parse the shared `--flag value` shape used by approval commands."""

    parsed: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("--") or index + 1 >= len(tokens):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        name = token[2:]
        if not name or name in parsed:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        parsed[name] = tokens[index + 1]
        index += 2
    return parsed


def fetch_finding(
    settings: ConnectedRunSettings,
    finding_id: str,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read one finding document by its identifier."""

    if not _identifier(finding_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(f"/api/v1/findings/{finding_id}", token=settings.token)
    return ConnectedCollection(run_id=finding_id, kind=ResultKind.FINDINGS, document=document)


def fetch_policies(
    settings: ConnectedRunSettings,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read the control plane's effective policy documents."""

    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/policies", token=settings.token)
    return ConnectedCollection(run_id="policies", kind=ResultKind.FINDINGS, document=document)


def check_health(
    settings: ConnectedRunSettings,
    *,
    live: bool = False,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Check readiness (default) or liveness of the configured control plane."""

    if type(live) is not bool:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    route = "/api/v1/health/live" if live else "/api/v1/health/ready"
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(route, token=settings.token)
    return ConnectedCollection(run_id="health", kind=ResultKind.FINDINGS, document=document)


def parse_single_argument(tokens: tuple[str, ...]) -> str:
    """Parse exactly one required positional identifier."""

    if len(tokens) != 1 or tokens[0].startswith("-") or not _identifier(tokens[0]):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return tokens[0]


def fetch_events(
    settings: ConnectedRunSettings,
    run_id: str,
    *,
    cursor: str | None = None,
    limit: int | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read one page of a run's event feed, newest cursor supplied by the server."""

    if not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    query: dict[str, str] = {}
    if cursor is not None:
        if not _cursor(cursor):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        query["cursor"] = cursor
    if limit is not None:
        if type(limit) is not int or not 1 <= limit <= 500:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        query["limit"] = str(limit)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(
        f"/api/v1/runs/{run_id}/events",
        token=settings.token,
        query=query or None,
    )
    return ConnectedCollection(run_id=run_id, kind=ResultKind.EVENTS, document=document)


def _cursor(value: object) -> bool:
    """A server-issued page cursor: bounded, URL-safe, opaque to the CLI."""

    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        return False
    return all(character.isalnum() or character in "-_" for character in value)


def parse_event_arguments(tokens: tuple[str, ...]) -> tuple[str, str | None, int | None]:
    """Parse `securecode events <run_id> [--cursor TOKEN] [--limit N]`."""

    run_id: str | None = None
    cursor: str | None = None
    limit: int | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in {"--cursor", "--limit"}:
            if index + 1 >= len(tokens):
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
            value = tokens[index + 1]
            if token == "--cursor":
                if not _cursor(value):
                    raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
                cursor = value
            else:
                if not value.isdigit() or not 1 <= int(value) <= 500:
                    raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
                limit = int(value)
            index += 2
            continue
        if token.startswith("-") or run_id is not None:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        run_id = token
        index += 1
    if run_id is None or not _identifier(run_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return run_id, cursor, limit


def parse_health_arguments(tokens: tuple[str, ...]) -> bool:
    """Parse `securecode health [--live]` and return whether liveness was asked."""

    live = False
    for token in tokens:
        if token == "--live":
            live = True
        else:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return live


def decide_finding(
    settings: ConnectedRunSettings,
    finding_id: str,
    *,
    run_id: str,
    revision_sha: str,
    decision_type: str,
    reason: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Record one human decision on a finding at an exact revision."""

    if not _identifier(finding_id) or not _identifier(run_id) or not _identifier(decision_type):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if not _commit(revision_sha) or not _precondition(if_match) or not reason:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    if len(decision_type) > 64 or len(reason) > 1024:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        f"/api/v1/findings/{finding_id}/decisions",
        document={
            "run_id": run_id,
            "revision_sha": revision_sha,
            "decision_type": decision_type,
            "reason": reason,
        },
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=run_id, kind=ResultKind.FINDINGS, document=document)


@dataclass(frozen=True, slots=True)
class SecretGrantDraft:
    """Operator-supplied reference for one bounded secret grant.

    Only a reference is carried: the CLI never receives, prints or forwards
    secret material, and the control plane resolves the reference itself.
    """

    repository_id: str
    workload_id: str
    reference: str
    purpose: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.repository_id)
            or not _identifier(self.workload_id)
            or not _identifier(self.purpose)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _secret_reference(self.reference):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def _secret_reference(value: object) -> bool:
    """A bounded, printable reference — never a secret value."""

    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return False
    return all(33 <= ord(character) <= 126 for character in value)


def grant_secret(
    settings: ConnectedRunSettings,
    draft: SecretGrantDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Request one bounded secret grant for a workload."""

    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/secret-grants",
        document={
            "repository_id": draft.repository_id,
            "workload_id": draft.workload_id,
            "reference": draft.reference,
            "purpose": draft.purpose,
        },
        token=settings.token,
        idempotency_key=key,
    )
    return ConnectedCollection(
        run_id=draft.workload_id, kind=ResultKind.FINDINGS, document=document
    )


def read_secret_grant(
    settings: ConnectedRunSettings,
    grant_id: str,
    *,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read the durable state of one secret grant."""

    if not _identifier(grant_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(f"/api/v1/secret-grants/{grant_id}", token=settings.token)
    return ConnectedCollection(run_id=grant_id, kind=ResultKind.FINDINGS, document=document)


@dataclass(frozen=True, slots=True)
class BackupDraft:
    """Operator-supplied metadata for one backup request."""

    backup_id: str
    repository_id: str
    component_hashes: tuple[str, ...]
    region: str
    key_reference: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.backup_id)
            or not _identifier(self.repository_id)
            or not _identifier(self.region)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _printable(self.key_reference, maximum=512):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if (
            not isinstance(self.component_hashes, tuple)
            or not 1 <= len(self.component_hashes) <= 10_000
            or len(set(self.component_hashes)) != len(self.component_hashes)
            or any(not _sha256(item) for item in self.component_hashes)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def _text(value: object, *, maximum: int) -> bool:
    """Free text: printable characters and spaces, bounded and control-free."""

    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        return False
    return all(32 <= ord(character) <= 126 for character in value)


def _printable(value: object, *, maximum: int) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        return False
    return all(33 <= ord(character) <= 126 for character in value)


def create_backup(
    settings: ConnectedRunSettings,
    draft: BackupDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Open one backup request over the declared component hashes."""

    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/backups",
        document={
            "backup_id": draft.backup_id,
            "repository_id": draft.repository_id,
            "component_hashes": list(draft.component_hashes),
            "region": draft.region,
            "encryption_key_ref": draft.key_reference,
        },
        token=settings.token,
        idempotency_key=key,
    )
    return ConnectedCollection(run_id=draft.backup_id, kind=ResultKind.FINDINGS, document=document)


def read_backup(
    settings: ConnectedRunSettings, backup_id: str, *, api: ConnectedApi | None = None
) -> ConnectedCollection:
    """Read one backup's durable state."""

    if not _identifier(backup_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/backups/" + backup_id, token=settings.token)
    return ConnectedCollection(run_id=backup_id, kind=ResultKind.FINDINGS, document=document)


def transition_backup(
    settings: ConnectedRunSettings,
    backup_id: str,
    *,
    restore: bool,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Execute a backup, or restore from it, against an exact observed state."""

    if not _identifier(backup_id) or not _precondition(if_match) or type(restore) is not bool:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    action = "restore" if restore else "execute"
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/backups/" + backup_id + ":" + action,
        document={},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=backup_id, kind=ResultKind.FINDINGS, document=document)


@dataclass(frozen=True, slots=True)
class DeletionDraft:
    """Operator-supplied metadata for one erasure request."""

    deletion_id: str
    repository_id: str
    content_sha256: str
    identity_hash: str

    def __post_init__(self) -> None:
        if (
            not _identifier(self.deletion_id)
            or not _identifier(self.repository_id)
            or not _sha256(self.content_sha256)
            or not _sha256(self.identity_hash)
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def create_deletion(
    settings: ConnectedRunSettings,
    draft: DeletionDraft,
    *,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Open one erasure request for an exact stored artifact."""

    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions",
        document={
            "deletion_id": draft.deletion_id,
            "repository_id": draft.repository_id,
            "content_sha256": draft.content_sha256,
            "data_class": "artifact",
            "identity_hash": draft.identity_hash,
        },
        token=settings.token,
        idempotency_key=key,
    )
    return ConnectedCollection(
        run_id=draft.deletion_id, kind=ResultKind.FINDINGS, document=document
    )


def read_deletion(
    settings: ConnectedRunSettings, deletion_id: str, *, api: ConnectedApi | None = None
) -> ConnectedCollection:
    """Read one erasure request's durable state."""

    if not _identifier(deletion_id):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/lifecycle/deletions/" + deletion_id, token=settings.token)
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=document)


def approve_deletion(
    settings: ConnectedRunSettings,
    deletion_id: str,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Approve one erasure request against the exact observed state."""

    if not _identifier(deletion_id) or not _precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions/" + deletion_id + ":approve",
        document={},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=document)


def hold_deletion(
    settings: ConnectedRunSettings,
    deletion_id: str,
    *,
    enabled: bool,
    identity_hash: str,
    reason: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Place or lift a legal hold on one erasure request."""

    if (
        not _identifier(deletion_id)
        or not _precondition(if_match)
        or type(enabled) is not bool
        or not _sha256(identity_hash)
        or not _printable(reason, maximum=1024)
    ):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions/" + deletion_id + ":legal-hold",
        document={"enabled": enabled, "identity_hash": identity_hash, "reason": reason},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=document)


def execute_deletion(
    settings: ConnectedRunSettings,
    deletion_id: str,
    *,
    identity_hash: str,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Execute one approved erasure request; the server fails closed without its executor."""

    if not _identifier(deletion_id) or not _precondition(if_match) or not _sha256(identity_hash):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/lifecycle/deletions/" + deletion_id + ":execute",
        document={"identity_hash": identity_hash},
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=deletion_id, kind=ResultKind.FINDINGS, document=document)


@dataclass(frozen=True, slots=True)
class FeedbackDraft:
    """Operator-supplied review of one finding during a pilot."""

    repository_id: str
    run_id: str
    finding_id: str
    head_sha: str
    identity_hash: str
    decision: str
    reason: str
    rationale: str
    incident_id: str | None = None

    def __post_init__(self) -> None:
        for value in (
            self.repository_id,
            self.run_id,
            self.finding_id,
            self.decision,
            self.reason,
        ):
            if not _identifier(value) or len(value) > 256:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _commit(self.head_sha) or not _sha256(self.identity_hash):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _text(self.rationale, maximum=1024):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if self.incident_id is not None and (
            not _identifier(self.incident_id) or len(self.incident_id) > 256
        ):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def submit_feedback(
    settings: ConnectedRunSettings,
    draft: FeedbackDraft,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Record one reviewer decision and its reason for a finding."""

    if not _precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    document: dict[str, object] = {
        "repository_id": draft.repository_id,
        "run_id": draft.run_id,
        "finding_id": draft.finding_id,
        "head_sha": draft.head_sha,
        "identity_hash": draft.identity_hash,
        "decision": draft.decision,
        "reason": draft.reason,
        "rationale": draft.rationale,
    }
    if draft.incident_id is not None:
        document["incident_id"] = draft.incident_id
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    response = client.mutate(
        "/api/v1/feedback",
        document=document,
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(run_id=draft.run_id, kind=ResultKind.FINDINGS, document=response)


def read_feedback_metrics(
    settings: ConnectedRunSettings,
    *,
    repository_id: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read the pilot feedback metrics the control plane aggregates."""

    query: dict[str, str] = {}
    if repository_id is not None:
        if not _identifier(repository_id):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        query["repository_id"] = repository_id
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read(
        "/api/v1/feedback/metrics",
        token=settings.token,
        query=query or None,
    )
    return ConnectedCollection(run_id="feedback", kind=ResultKind.FINDINGS, document=document)


@dataclass(frozen=True, slots=True)
class AssuranceDraft:
    """Operator-supplied assurance record for one repository."""

    repository_id: str
    identity_hash: str
    record_id: str
    kind: str
    outcome: str
    payload: Mapping[str, object]

    def __post_init__(self) -> None:
        for value in (self.repository_id, self.record_id, self.kind, self.outcome):
            if not _identifier(value) or len(value) > 256:
                raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not _sha256(self.identity_hash):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if not isinstance(self.payload, Mapping) or not self.payload:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        if len(self.payload) > 128:
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)


def append_assurance(
    settings: ConnectedRunSettings,
    draft: AssuranceDraft,
    *,
    if_match: str,
    idempotency_key: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Append one assurance record at an exact observed state."""

    if not _precondition(if_match):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    key = idempotency_key or new_idempotency_key()
    if not _idempotency_key(key):
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.mutate(
        "/api/v1/assurance",
        document={
            "repository_id": draft.repository_id,
            "execution_identity_hash": draft.identity_hash,
            "record_id": draft.record_id,
            "kind": draft.kind,
            "outcome": draft.outcome,
            "payload": dict(draft.payload),
        },
        token=settings.token,
        idempotency_key=key,
        if_match=if_match,
    )
    return ConnectedCollection(
        run_id=draft.repository_id, kind=ResultKind.FINDINGS, document=document
    )


def read_assurance(
    settings: ConnectedRunSettings,
    *,
    repository_id: str | None = None,
    api: ConnectedApi | None = None,
) -> ConnectedCollection:
    """Read the assurance records and failure summary for a repository."""

    query: dict[str, str] = {}
    if repository_id is not None:
        if not _identifier(repository_id):
            raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
        query["repository_id"] = repository_id
    client = api if api is not None else HttpConnectedApi(settings.base_url)
    document = client.read("/api/v1/assurance", token=settings.token, query=query or None)
    return ConnectedCollection(run_id="assurance", kind=ResultKind.FINDINGS, document=document)


def parse_payload(value: str) -> dict[str, object]:
    """Parse one bounded JSON object supplied on the command line."""

    if not isinstance(value, str) or not 2 <= len(value) <= 16_384:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION) from None
    if not isinstance(parsed, dict) or not parsed:
        raise ConnectedCliError(ConnectedCliErrorCode.INVALID_CONFIGURATION)
    return parsed


__all__ = [
    "ApprovalDraft",
    "AssuranceDraft",
    "BackupDraft",
    "ConnectedApi",
    "ConnectedCliError",
    "ConnectedCliErrorCode",
    "ConnectedCollection",
    "ConnectedRunReceipt",
    "ConnectedRunRequest",
    "ConnectedRunSettings",
    "DeletionDraft",
    "FeedbackDraft",
    "HttpConnectedApi",
    "ResultKind",
    "SecretGrantDraft",
    "append_assurance",
    "approve_deletion",
    "cancel_run",
    "check_health",
    "create_approval",
    "create_backup",
    "create_deletion",
    "decide_approval",
    "decide_finding",
    "execute_deletion",
    "fetch_events",
    "fetch_finding",
    "fetch_policies",
    "fetch_results",
    "fetch_run",
    "grant_secret",
    "hold_deletion",
    "new_idempotency_key",
    "parse_approval_arguments",
    "parse_connected_arguments",
    "parse_event_arguments",
    "parse_health_arguments",
    "parse_payload",
    "parse_results_arguments",
    "parse_run_arguments",
    "parse_single_argument",
    "read_approval",
    "read_assurance",
    "read_backup",
    "read_deletion",
    "read_feedback_metrics",
    "read_secret_grant",
    "render_receipt",
    "resumable_idempotency_key",
    "run_connected",
    "settings_from_environment",
    "submit_feedback",
    "timestamp",
    "transition_backup",
]
