"""Approval, finding, policy, health, and event operations."""

from __future__ import annotations

from dataclasses import dataclass

from .connected_runs import (
    ConnectedCollection,
    ConnectedRunSettings,
    ResultKind,
    new_idempotency_key,
)
from .connected_transport import (
    ConnectedApi,
    ConnectedCliError,
    ConnectedCliErrorCode,
    HttpConnectedApi,
    _commit,
    _idempotency_key,
    _identifier,
    _precondition,
)
from .connected_validation import _sha256


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
