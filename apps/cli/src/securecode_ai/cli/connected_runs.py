"""Submission, run lifecycle, and run-result CLI operations."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TextIO

from .connected_transport import (
    INITIAL_POLL_SECONDS,
    MAXIMUM_POLL_SECONDS,
    ConnectedApi,
    ConnectedCliError,
    ConnectedCliErrorCode,
    ConnectedRunReceipt,
    ConnectedRunRequest,
    HttpConnectedApi,
    _identifier,
    _precondition,
    _receipt,
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
