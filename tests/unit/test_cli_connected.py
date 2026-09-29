"""Connected CLI: request validation, parsing, resume semantics and polling."""

from __future__ import annotations

import json
from io import StringIO

import pytest
from securecode_ai.cli.connected import (
    ApprovalDraft,
    BackupDraft,
    ConnectedCliError,
    ConnectedCliErrorCode,
    ConnectedRunRequest,
    ConnectedRunSettings,
    ResultKind,
    cancel_run,
    check_health,
    create_approval,
    create_backup,
    decide_finding,
    fetch_events,
    fetch_finding,
    fetch_results,
    fetch_run,
    new_idempotency_key,
    parse_approval_arguments,
    parse_connected_arguments,
    parse_event_arguments,
    parse_health_arguments,
    parse_payload,
    parse_results_arguments,
    parse_run_arguments,
    parse_single_argument,
    read_approval,
    render_receipt,
    run_connected,
    settings_from_environment,
)

TENANT = "tenant-1"
REPOSITORY = "repo-1"
HEAD = "a" * 40
BASE = "b" * 40
IDENTITY = "c" * 64
ENVIRONMENT = {
    "SECURECODE_CONTROL_PLANE_URL": "http://127.0.0.1:8080",
    "SECURECODE_CONTROL_PLANE_TOKEN": "t" * 20,
    "SECURECODE_TENANT_ID": TENANT,
    "SECURECODE_REPOSITORY_ID": REPOSITORY,
    "SECURECODE_HEAD_SHA": HEAD,
    "SECURECODE_BASE_SHA": BASE,
}


class _Api:
    """Records every call and replays a scripted sequence of documents."""

    def __init__(self, *, outcome: str | None = None, polls: int = 1) -> None:
        self.calls: list[tuple[object, ...]] = []
        self._outcome = outcome
        self._polls = polls

    def _receipt(self, run_id: str = "run-1") -> dict[str, object]:
        return {
            "run_id": run_id,
            "tenant_id": TENANT,
            "repository_id": REPOSITORY,
            "disposition": "ADMITTED",
            "lifecycle": "ADMITTED",
            "head_sha": HEAD,
            "outcome": None,
            "state_version": 1,
        }

    def submit(self, request: ConnectedRunRequest, *, token: str) -> dict[str, object]:
        self.calls.append(("submit", request.idempotency_key, token[:1]))
        return self._receipt()

    def status(self, run_id: str, *, token: str) -> dict[str, object]:
        self.calls.append(("status", run_id))
        document = self._receipt(run_id)
        self._polls -= 1
        if self._polls <= 0:
            document["outcome"] = self._outcome
            document["state_version"] = 3
            if self._outcome is not None:
                document["disposition"] = "COMPLETED"
                document["lifecycle"] = "COMPLETED"
        return document

    def cancel(
        self, run_id: str, *, token: str, if_match: str, idempotency_key: str
    ) -> dict[str, object]:
        self.calls.append(("cancel", run_id, if_match, len(idempotency_key) >= 8))
        return self._receipt(run_id)

    def read(self, path: str, *, token: str, query: object = None) -> dict[str, object]:
        self.calls.append(("read", path, query))
        if path.startswith("/api/v1/approvals/"):
            return self._approval({"approval_id": path.rsplit("/", 1)[-1]})
        return {"items": [], "next_cursor": None}

    def mutate(
        self,
        path: str,
        *,
        document: dict[str, object],
        token: str,
        idempotency_key: str,
        if_match: str | None = None,
    ) -> dict[str, object]:
        self.calls.append(("mutate", path, sorted(document), if_match))
        if path == "/api/v1/backups":
            return {
                "tenant_id": TENANT,
                "backup_id": document["backup_id"],
                "repository_id": document["repository_id"],
                "state": "PLANNED",
                "manifest_sha256": None,
                "component_count": 1,
                "version": 1,
                "backup_verified": False,
                "restore_verified": False,
                "rpo_seconds": None,
                "rto_seconds": None,
                "completed_at": None,
            }
        if path.startswith("/api/v1/approvals"):
            return self._approval(document)
        return dict(document)

    def _approval(self, document: dict[str, object]) -> dict[str, object]:
        return {
            "approval_id": document.get("approval_id", "ap-1"),
            "tenant_id": TENANT,
            "repository_id": document.get("repository_id", REPOSITORY),
            "run_id": document.get("run_id", "run-1"),
            "finding_id": document.get("finding_id", "f-1"),
            "execution_identity_hash": document.get("execution_identity_hash", IDENTITY),
            "patch_sha256": None,
            "validation_result_sha256": None,
            "manifest_sha256": None,
            "patch_status_sha256": None,
            "state": "PENDING",
            "version": 1,
            "expires_at": document.get("expires_at", "2026-09-23T00:00:00+00:00"),
        }


def _settings(**overrides: str) -> ConnectedRunSettings:
    return settings_from_environment({**ENVIRONMENT, **overrides})


# --- configuration -----------------------------------------------------------


def test_missing_settings_are_rejected() -> None:
    required = (
        "SECURECODE_CONTROL_PLANE_URL",
        "SECURECODE_CONTROL_PLANE_TOKEN",
        "SECURECODE_TENANT_ID",
        "SECURECODE_REPOSITORY_ID",
        "SECURECODE_HEAD_SHA",
    )
    for name in required:
        environment = {key: value for key, value in ENVIRONMENT.items() if key != name}
        with pytest.raises(ConnectedCliError) as error:
            settings_from_environment(environment)
        assert error.value.code is ConnectedCliErrorCode.INVALID_CONFIGURATION


def test_optional_settings_may_be_absent() -> None:
    environment = {key: value for key, value in ENVIRONMENT.items() if key != "SECURECODE_BASE_SHA"}
    settings = settings_from_environment(environment)
    assert settings.base_sha is None


def test_resumable_key_is_stable_for_one_revision() -> None:
    first = _settings()
    second = _settings()
    moved = _settings(SECURECODE_HEAD_SHA="d" * 40)
    fresh = settings_from_environment(ENVIRONMENT, fresh=True)
    pinned = _settings(SECURECODE_IDEMPOTENCY_KEY="operator-key-0001")
    assert first.idempotency_key == second.idempotency_key
    assert moved.idempotency_key != first.idempotency_key
    assert fresh.idempotency_key != first.idempotency_key
    assert pinned.idempotency_key == "operator-key-0001"


def test_new_key_is_fresh_each_time() -> None:
    assert new_idempotency_key() != new_idempotency_key()


# --- request validation ------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"tenant_id": ""},
        {"repository_id": "bad repo"},
        {"head_sha": "short"},
        {"head_sha": "A" * 40},
        {"base_sha": "short"},
        {"change_id": ""},
        {"idempotency_key": "short"},
    ],
)
def test_run_request_rejects_invalid_identity(overrides: dict[str, str]) -> None:
    values = {
        "tenant_id": TENANT,
        "repository_id": REPOSITORY,
        "head_sha": HEAD,
        "idempotency_key": "cli-key-0001",
    }
    values.update(overrides)
    with pytest.raises(ConnectedCliError) as error:
        ConnectedRunRequest(
            tenant_id=values["tenant_id"],
            repository_id=values["repository_id"],
            head_sha=values["head_sha"],
            idempotency_key=values["idempotency_key"],
            base_sha=values.get("base_sha"),
            change_id=values.get("change_id"),
        )
    assert error.value.code is ConnectedCliErrorCode.INVALID_CONFIGURATION


# --- parsing -----------------------------------------------------------------


def test_connect_arguments_are_parsed() -> None:
    target, wait, fresh = parse_connected_arguments(("path", "--wait", "--new-run"))
    assert str(target) == "path" and wait and fresh
    with pytest.raises(ConnectedCliError):
        parse_connected_arguments(("a", "b"))


@pytest.mark.parametrize(
    ("tokens", "expected"),
    [
        (("run-1",), ("run-1", None)),
        (("run-1", "--if-match", "3"), ("run-1", "3")),
    ],
)
def test_run_arguments_are_parsed(
    tokens: tuple[str, ...], expected: tuple[str, str | None]
) -> None:
    assert parse_run_arguments(tokens) == expected


@pytest.mark.parametrize(
    "tokens",
    [(), ("run-1", "--if-match"), ("run-1", "--if-match", "v", "extra"), ("-x",)],
)
def test_run_arguments_reject_bad_shapes(tokens: tuple[str, ...]) -> None:
    with pytest.raises(ConnectedCliError):
        parse_run_arguments(tokens)


def test_results_and_event_arguments_are_parsed() -> None:
    assert parse_results_arguments(("run-1", "--kind", "events"))[1] is ResultKind.EVENTS
    assert parse_results_arguments(("run-1",))[1] is ResultKind.FINDINGS
    assert parse_event_arguments(("run-1", "--cursor", "Mg", "--limit", "25")) == (
        "run-1",
        "Mg",
        25,
    )
    for tokens in (
        ("run-1", "--kind", "bogus"),
        ("run-1", "--cursor", "bad cursor"),
        ("run-1", "--limit", "0"),
    ):
        with pytest.raises(ConnectedCliError):
            if "--kind" in tokens:
                parse_results_arguments(tokens)
            else:
                parse_event_arguments(tokens)


def test_approval_arguments_are_parsed() -> None:
    assert parse_approval_arguments(("--a", "1", "--b", "2")) == {"a": "1", "b": "2"}
    for tokens in (("--a",), ("a", "1"), ("--a", "1", "--a", "2")):
        with pytest.raises(ConnectedCliError):
            parse_approval_arguments(tokens)


def test_single_argument_and_health_flags() -> None:
    assert parse_single_argument(("finding-1",)) == "finding-1"
    assert parse_health_arguments(("--live",)) is True
    assert parse_health_arguments(()) is False
    for tokens in ((), ("two", "args"), ("--other",)):
        with pytest.raises(ConnectedCliError):
            parse_single_argument(tokens)
    with pytest.raises(ConnectedCliError):
        parse_health_arguments(("--other",))


@pytest.mark.parametrize("value", ["[]", "not json", "", '{"a": 1', "[1, 2]"])
def test_payload_rejects_non_objects(value: str) -> None:
    with pytest.raises(ConnectedCliError):
        parse_payload(value)


def test_payload_accepts_a_bounded_object() -> None:
    assert parse_payload('{"packages": 12}') == {"packages": 12}


# --- polling -----------------------------------------------------------------


def test_run_connected_returns_the_terminal_receipt() -> None:
    api = _Api(outcome="PASS", polls=2)
    receipt = run_connected(_settings(), api=api, poll_status=True, attempts=5)
    assert receipt.outcome == "PASS"
    assert [call[0] for call in api.calls] == ["submit", "status", "status"]


def test_run_connected_backs_off_between_polls() -> None:
    api = _Api(outcome="FAIL", polls=3)
    delays: list[float] = []
    run_connected(_settings(), api=api, poll_status=True, attempts=5, sleeper=delays.append)
    assert delays == [1.0, 2.0]


def test_run_connected_refuses_a_non_terminal_run() -> None:
    api = _Api(outcome=None, polls=99)
    with pytest.raises(ConnectedCliError) as error:
        run_connected(_settings(), api=api, poll_status=True, attempts=2)
    assert error.value.code is ConnectedCliErrorCode.RUN_NOT_TERMINAL


def test_run_connected_can_skip_polling() -> None:
    api = _Api(outcome="PASS")
    run_connected(_settings(), api=api, poll_status=False)
    assert [call[0] for call in api.calls] == ["submit"]


def test_protocol_violations_are_refused() -> None:
    class _Broken(_Api):
        def submit(self, request: ConnectedRunRequest, *, token: str) -> dict[str, object]:
            return {"run_id": "run-1", "head_sha": "short"}

    with pytest.raises(ConnectedCliError) as error:
        run_connected(_settings(), api=_Broken())
    assert error.value.code is ConnectedCliErrorCode.PROTOCOL_INVALID


def test_receipt_rendering_is_canonical() -> None:
    api = _Api(outcome="PASS")
    receipt = run_connected(_settings(), api=api, poll_status=False)
    stream = StringIO()
    render_receipt(receipt, stream)
    document = json.loads(stream.getvalue())
    assert set(document) == {
        "run_id",
        "disposition",
        "lifecycle",
        "head_sha",
        "outcome",
        "state_version",
    }
    assert stream.getvalue().endswith("\n")


# --- reads and mutations -----------------------------------------------------


def test_reads_use_the_declared_api_paths() -> None:
    api = _Api()
    settings = _settings()
    fetch_run(settings, "run-1", api=api)
    fetch_finding(settings, "f-1", api=api)
    fetch_results(settings, "run-1", ResultKind.ARTIFACTS, api=api)
    fetch_events(settings, "run-1", cursor="Mg", limit=10, api=api)
    check_health(settings, live=True, api=api)
    # run state is read through the dedicated status call; the rest are plain reads
    assert api.calls[0] == ("status", "run-1")
    read_paths = [call[1] for call in api.calls if call[0] == "read"]
    assert read_paths == [
        "/api/v1/findings/f-1",
        "/api/v1/runs/run-1/artifacts",
        "/api/v1/runs/run-1/events",
        "/api/v1/health/live",
    ]
    event_call = next(call for call in api.calls if str(call[1]).endswith("/events"))
    assert event_call[2] == {"cursor": "Mg", "limit": "10"}


def test_cancel_passes_the_precondition_to_the_transport() -> None:
    api = _Api()
    cancel_run(_settings(), "run-1", if_match="2", api=api)
    assert api.calls[0][:3] == ("cancel", "run-1", "2")


def test_http_client_refuses_a_missing_precondition() -> None:
    """The precondition is enforced by the transport, before any request is sent."""

    from securecode_ai.cli.connected import HttpConnectedApi

    client = HttpConnectedApi("http://127.0.0.1:8080")
    with pytest.raises(ConnectedCliError) as error:
        client.cancel("run-1", token="t" * 20, if_match="", idempotency_key="cli-key-0001")
    assert error.value.code is ConnectedCliErrorCode.INVALID_CONFIGURATION
    with pytest.raises(ConnectedCliError):
        client.cancel("run-1", token="t" * 20, if_match="v2", idempotency_key="short")


def test_approval_and_backup_drafts_validate_their_fields() -> None:
    with pytest.raises(ConnectedCliError):
        ApprovalDraft("ap-1", REPOSITORY, "run-1", "f-1", "short", "2026-09-23T00:00:00+00:00")
    with pytest.raises(ConnectedCliError):
        BackupDraft("backup-1", REPOSITORY, ("a" * 63,), "eu-central", "kms://team/backup")
    draft = BackupDraft("backup-1", REPOSITORY, (IDENTITY,), "eu-central", "kms://team/backup")
    api = _Api()
    create_backup(_settings(), draft, api=api)
    assert api.calls[0][1] == "/api/v1/backups"


def test_approval_mutations_use_the_declared_paths() -> None:
    api = _Api()
    settings = _settings()
    create_approval(
        settings,
        ApprovalDraft("ap-1", REPOSITORY, "run-1", "f-1", IDENTITY, "2026-09-23T00:00:00+00:00"),
        api=api,
    )
    read_approval(settings, "ap-1", api=api)
    decide_finding(
        settings,
        "f-1",
        run_id="run-1",
        revision_sha=HEAD,
        decision_type="suppressed",
        reason="accepted-risk",
        if_match="v3",
        api=api,
    )
    assert [call[1] for call in api.calls] == [
        "/api/v1/approvals",
        "/api/v1/approvals/ap-1",
        "/api/v1/findings/f-1/decisions",
    ]
    assert api.calls[2][3] == "v3"
