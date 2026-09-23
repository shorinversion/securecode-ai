"""P5.5/P7.5 webhook intake: signature authentication, exact-head admission, tenancy."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3

import pytest
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    RunExecutionIdentity,
)
from securecode_ai.contracts.domain import ACCEPTED_STAGE_CATALOGUE_PIN
from securecode_ai.server.scm_state import SqliteSCMRunState
from securecode_ai.server.scm_webhooks import (
    GithubWebhookAdapter,
    GitlabWebhookAdapter,
    SCMWebhookError,
    SCMWebhookErrorCode,
    WebhookExecutionPins,
)

TENANT = "tenant-1"
REPOSITORY = "501"
HEAD = "a" * 40
BASE = "b" * 40
OTHER_HEAD = "c" * 40
SECRET = b"github-webhook-secret"
TOKEN = b"gitlab-webhook-token"
HASH_A = "a" * 64
DEFAULT_DELIVERY = "d-1"


def _pin(name: str, digest: str) -> ComponentPin:
    if name == "catalogue":
        component_id, version, accepted = ACCEPTED_STAGE_CATALOGUE_PIN
        return ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=component_id,
            component_version=version,
            content_sha256=accepted,
        )
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=name,
        component_version="1.0.0",
        content_sha256=digest,
    )


def _pins() -> WebhookExecutionPins:
    return WebhookExecutionPins(
        tenant_id=TENANT,
        stage_catalogue=_pin("catalogue", HASH_A),
        workflow=_pin("workflow", HASH_A),
        policy=_pin("policy", "c" * 64),
        configuration=_pin("configuration", "d" * 64),
        provider_profile=_pin("provider", "e" * 64),
        capability_profile=_pin("capability", "f" * 64),
        egress_profile=_pin("egress", "1" * 64),
    )


class _State:
    """Minimal in-memory run state recording every admitted request."""

    def __init__(
        self, *, head_sha: str = HEAD, duplicate: bool = False, stale: bool = False
    ) -> None:
        self.head_sha = head_sha
        self.duplicate = duplicate
        self.stale = stale
        self.admissions: list[object] = []

    def _identity(self, request: object) -> RunExecutionIdentity:
        identity = getattr(request, "execution_identity", None)
        assert isinstance(identity, RunExecutionIdentity)
        return identity

    def _inner(self, request: object) -> object:
        """Return the exact-identity carrier for either provider request shape."""

        if hasattr(request, "execution_identity"):
            return request
        raise AssertionError("admission request must carry an execution identity")

    def authorize_publication(self, run_id: str, *, current_head_sha: str) -> object:
        from securecode_ai.core.scm_run_state import (
            PublicationDisposition,
            SCMRunLifecycle,
            SCMRunPublicationReceipt,
        )

        return SCMRunPublicationReceipt(
            disposition=PublicationDisposition.AUTHORIZED,
            run_id=run_id,
            execution_identity_hash=HASH_A,
            head_sha=current_head_sha,
            current_head_sha=current_head_sha,
            lifecycle=SCMRunLifecycle.ADMITTED,
            outcome=None,
            state_version=1,
        )

    def complete(self, run_id: str, outcome: object, *, current_head_sha: str) -> object:
        from securecode_ai.core.scm_run_state import (
            PublicationDisposition,
            SCMRunLifecycle,
            SCMRunPublicationReceipt,
        )

        return SCMRunPublicationReceipt(
            disposition=PublicationDisposition.COMPLETED,
            run_id=run_id,
            execution_identity_hash=HASH_A,
            head_sha=current_head_sha,
            current_head_sha=current_head_sha,
            lifecycle=SCMRunLifecycle.COMPLETED,
            outcome=outcome,  # type: ignore[arg-type]
            state_version=2,
        )

    def admit(self, request: object, *, current_head_sha: str) -> object:
        from securecode_ai.core.scm_run_state import (
            AdmissionDisposition,
            SCMRunAdmissionReceipt,
            SCMRunLifecycle,
        )

        identity = self._identity(self._inner(request))
        receipt_head = identity.repository_revision.head_sha
        if self.stale:
            return SCMRunAdmissionReceipt(
                disposition=AdmissionDisposition.SUPERSEDED,
                run_id="scm-run-stale",
                execution_identity_hash=identity.execution_identity_hash,
                head_sha=receipt_head,
                lifecycle=SCMRunLifecycle.SUPERSEDED,
                state_version=0,
            )
        self.admissions.append(request)
        disposition = (
            AdmissionDisposition.DUPLICATE if self.duplicate else AdmissionDisposition.ADMITTED
        )
        return SCMRunAdmissionReceipt(
            disposition=disposition,
            run_id="scm-run-1",
            execution_identity_hash=identity.execution_identity_hash,
            head_sha=receipt_head,
            lifecycle=SCMRunLifecycle.ADMITTED,
            state_version=1,
        )


def _github_body(
    *,
    action: str = "opened",
    head_sha: str = HEAD,
    base_sha: str = BASE,
    repository_id: str = REPOSITORY,
) -> bytes:
    return json.dumps(
        {
            "action": action,
            "number": 7,
            "installation": {"id": "installation-1"},
            "repository": {"id": repository_id},
            "pull_request": {
                "number": 7,
                "head": {"sha": head_sha},
                "base": {"sha": base_sha},
            },
        },
        separators=(",", ":"),
    ).encode()


def _github_headers(
    body: bytes, *, event: str = "pull_request", delivery: str = "d-1"
) -> dict[str, str]:
    signature = "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest()
    return {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery,
        "X-Hub-Signature-256": signature,
    }


def _github(
    *, head_sha: str = HEAD, duplicate: bool = False
) -> tuple[GithubWebhookAdapter, _State]:
    state = _State(head_sha=head_sha, duplicate=duplicate)
    adapter = GithubWebhookAdapter(
        webhook_secret=SECRET,
        pins=_pins(),
        run_state=state,  # type: ignore[arg-type]
        head_resolver=lambda _installation, _repository: head_sha,
    )
    return adapter, state


def _gitlab_body(
    *,
    action: str = "open",
    head_sha: str = HEAD,
    source: str = REPOSITORY,
    target: str = REPOSITORY,
    project: str = REPOSITORY,
) -> bytes:
    return json.dumps(
        {
            "object_kind": "merge_request",
            "event_type": "merge_request",
            "project": {"id": project},
            "object_attributes": {
                "action": action,
                "iid": 7,
                "source_project_id": source,
                "target_project_id": target,
                "last_commit": {"id": head_sha},
            },
        },
        separators=(",", ":"),
    ).encode()


def _gitlab_headers(
    body: bytes, *, event: str = "Merge Request Hook", token: bytes = TOKEN
) -> dict[str, str]:
    return {
        "X-Gitlab-Event": event,
        "X-Gitlab-Event-UUID": DEFAULT_DELIVERY,
        "X-Gitlab-Token": token.decode("utf-8"),
    }


def _gitlab(
    *, head_sha: str = HEAD, duplicate: bool = False
) -> tuple[GitlabWebhookAdapter, _State]:
    state = _State(head_sha=head_sha, duplicate=duplicate)
    adapter = GitlabWebhookAdapter(
        webhook_token=TOKEN,
        pins=_pins(),
        run_state=state,  # type: ignore[arg-type]
        head_resolver=lambda _project, _iid: head_sha,
    )
    return adapter, state


# --- configuration -----------------------------------------------------------


def test_pins_reject_invalid_configuration() -> None:
    with pytest.raises(SCMWebhookError) as error:
        WebhookExecutionPins(
            tenant_id="bad tenant",
            stage_catalogue=_pin("catalogue", HASH_A),
            workflow=_pin("workflow", HASH_A),
            policy=_pin("policy", "c" * 64),
            configuration=_pin("configuration", "d" * 64),
            provider_profile=_pin("provider", "e" * 64),
            capability_profile=_pin("capability", "f" * 64),
            egress_profile=_pin("egress", "1" * 64),
        )
    assert error.value.code is SCMWebhookErrorCode.INVALID_CONFIGURATION


def test_pins_build_identity_from_authenticated_metadata() -> None:
    identity = _pins().build_identity(
        scm_provider="github",
        repository_id=REPOSITORY,
        head_sha=HEAD,
        base_sha=BASE,
    )
    revision = identity.repository_revision
    assert revision.tenant_id == TENANT
    assert revision.scm_provider == "github"
    assert revision.repository_id == REPOSITORY
    assert revision.head_sha == HEAD
    assert revision.base_sha == BASE


def test_pins_reject_identity_with_identical_base_and_head() -> None:
    with pytest.raises(SCMWebhookError) as error:
        _pins().build_identity(
            scm_provider="github",
            repository_id=REPOSITORY,
            head_sha=HEAD,
            base_sha=HEAD,
        )
    assert error.value.code is SCMWebhookErrorCode.PAYLOAD_INVALID


@pytest.mark.parametrize(
    "configuration",
    [
        {"webhook_secret": b"", "pins": _pins()},
        {"webhook_secret": "not-bytes", "pins": _pins()},
    ],
)
def test_github_adapter_rejects_invalid_configuration(configuration: dict[str, object]) -> None:
    with pytest.raises(SCMWebhookError) as error:
        GithubWebhookAdapter(
            run_state=_State(),  # type: ignore[arg-type]
            head_resolver=lambda *_: HEAD,
            **configuration,  # type: ignore[arg-type]
        )
    assert error.value.code is SCMWebhookErrorCode.INVALID_CONFIGURATION


# --- GitHub intake -----------------------------------------------------------


def test_github_admits_signed_pull_request() -> None:
    adapter, state = _github()
    body = _github_body()
    receipt = adapter.receive(body, headers=_github_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert receipt.provider == "github"
    assert receipt.event == "pull_request"
    assert receipt.delivery_id == "d-1"
    assert receipt.repository_id == REPOSITORY
    assert receipt.change_id == "7"
    assert receipt.head_sha == HEAD
    assert receipt.base_sha == BASE
    assert len(state.admissions) == 1

    document = receipt.as_document()
    assert document["disposition"] == "ADMITTED"
    assert document["run_id"] == "scm-run-1"
    assert document["change_id"] == "7"


def test_github_rejects_wrong_signature() -> None:
    adapter, state = _github()
    body = _github_body()
    headers = _github_headers(body)
    headers["X-Hub-Signature-256"] = "sha256=" + "0" * 64
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(body, headers=headers, delivery_key=DEFAULT_DELIVERY)
    assert error.value.code is SCMWebhookErrorCode.AUTHENTICATION_FAILED
    assert state.admissions == []


def test_github_rejects_body_that_does_not_match_signature() -> None:
    adapter, _state = _github()
    body = _github_body()
    tampered = body.replace(b'"opened"', b'"reopened"')
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(tampered, headers=_github_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert error.value.code is SCMWebhookErrorCode.AUTHENTICATION_FAILED


@pytest.mark.parametrize("event", ["push", "issues", "pull_request_review"])
def test_github_rejects_other_events(event: str) -> None:
    adapter, _state = _github()
    body = _github_body()
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(
            body, headers=_github_headers(body, event=event), delivery_key=DEFAULT_DELIVERY
        )
    assert error.value.code is SCMWebhookErrorCode.INVALID_HEADERS


@pytest.mark.parametrize("header", ["x-github-event", "x-github-delivery", "x-hub-signature-256"])
def test_github_requires_every_security_header(header: str) -> None:
    adapter, _state = _github()
    body = _github_body()
    headers = _github_headers(body)
    headers.pop({h.lower(): h for h in headers}[header])
    with pytest.raises(SCMWebhookError):
        adapter.receive(body, headers=headers, delivery_key=DEFAULT_DELIVERY)


def test_github_rejects_malformed_signature_shape() -> None:
    adapter, _state = _github()
    body = _github_body()
    headers = _github_headers(body)
    headers["X-Hub-Signature-256"] = "sha256=short"
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(body, headers=headers, delivery_key=DEFAULT_DELIVERY)
    assert error.value.code is SCMWebhookErrorCode.INVALID_HEADERS


@pytest.mark.parametrize("action", ["closed", "labeled", "edited"])
def test_github_rejects_unsupported_actions(action: str) -> None:
    adapter, _state = _github()
    body = _github_body(action=action)
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(body, headers=_github_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert error.value.code is SCMWebhookErrorCode.PAYLOAD_INVALID


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not json",
        b"[]",
        b'{"action":"opened"}',
        b'{"action":"opened","repository":{},"pull_request":{},"installation":{}}',
        b'{"action":"opened","repository":{"id":0},"pull_request":{"head":{"sha":"a"*40}},"installation":{"id":"i"}}',
        b'{"action":"opened","repository":{"id":"501"},"pull_request":{"head":{"sha":"short"}},"installation":{"id":"i"}}',
        b'{"action":"opened","repository":{"id":"501"},"pull_request":{"head":{"sha":"a"*40}},"installation":{"id":""}}',
    ],
)
def test_github_rejects_malformed_payloads(body: bytes) -> None:
    adapter, _state = _github()
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "d-1",
        "X-Hub-Signature-256": "sha256=" + hmac.new(SECRET, body, hashlib.sha256).hexdigest(),
    }
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(body, headers=headers, delivery_key=DEFAULT_DELIVERY)
    assert error.value.code in {
        SCMWebhookErrorCode.PAYLOAD_INVALID,
        SCMWebhookErrorCode.INVALID_HEADERS,
    }


def test_github_rejects_unsafe_or_oversized_body() -> None:
    adapter, _state = _github()
    oversized = b"x" * (65_536 + 1)
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "d-1",
        "X-Hub-Signature-256": "sha256=" + hmac.new(SECRET, oversized, hashlib.sha256).hexdigest(),
    }
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(oversized, headers=headers, delivery_key=DEFAULT_DELIVERY)
    assert error.value.code is SCMWebhookErrorCode.PAYLOAD_INVALID


def test_github_delivery_key_conflict_is_rejected() -> None:
    adapter, _state = _github()
    body = _github_body()
    headers = _github_headers(body, delivery="from-header")
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(body, headers=headers, delivery_key="from-body")
    assert error.value.code is SCMWebhookErrorCode.DELIVERY_CONFLICT


def test_github_delivery_key_must_be_present() -> None:
    adapter, state = _github()
    body = _github_body()
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(body, headers=_github_headers(body), delivery_key=None)
    assert error.value.code is SCMWebhookErrorCode.DELIVERY_CONFLICT
    assert state.admissions == []


def test_github_stale_head_is_superseded_by_signature_authenticated_intake() -> None:
    """A newer live head makes the delivered revision superseded, never silently admitted."""

    state = _State(head_sha=OTHER_HEAD, stale=True)
    adapter = GithubWebhookAdapter(
        webhook_secret=SECRET,
        pins=_pins(),
        run_state=state,  # type: ignore[arg-type]
        head_resolver=lambda _installation, _repository: OTHER_HEAD,
    )
    body = _github_body()
    receipt = adapter.receive(body, headers=_github_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert receipt.head_sha == HEAD
    assert receipt.admission.disposition.value == "SUPERSEDED"
    assert state.admissions == []


def test_github_duplicate_delivery_is_reported() -> None:
    adapter, _state = _github(duplicate=True)
    body = _github_body()
    receipt = adapter.receive(body, headers=_github_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert receipt.admission.disposition.value == "DUPLICATE"


# --- GitLab intake -----------------------------------------------------------


def test_gitlab_admits_trusted_merge_request() -> None:
    adapter, state = _gitlab()
    body = _gitlab_body()
    receipt = adapter.receive(body, headers=_gitlab_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert receipt.provider == "gitlab"
    assert receipt.event == "merge_request"
    assert receipt.delivery_id == DEFAULT_DELIVERY
    assert receipt.repository_id == REPOSITORY
    assert receipt.change_id == "7"
    assert receipt.head_sha == HEAD
    assert receipt.base_sha is None
    assert receipt.installation_id == f"gitlab:{REPOSITORY}"
    assert len(state.admissions) == 1
    admitted = state.admissions[0]
    assert getattr(admitted, "contribution_trust", None) is None
    assert receipt.admission.disposition.value == "ADMITTED"


def test_gitlab_fork_is_admitted_from_an_untrusted_source_project() -> None:
    """A fork delivery is authenticated and admitted as its own head, never trusted silently."""

    adapter, state = _gitlab()
    body = _gitlab_body(source="900")
    receipt = adapter.receive(body, headers=_gitlab_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert receipt.admission.disposition.value == "ADMITTED"
    assert len(state.admissions) == 1
    assert receipt.repository_id == REPOSITORY
    assert receipt.head_sha == HEAD


def test_gitlab_rejects_wrong_token() -> None:
    adapter, state = _gitlab()
    body = _gitlab_body()
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(
            body, headers=_gitlab_headers(body, token=b"wrong-token"), delivery_key=DEFAULT_DELIVERY
        )
    assert error.value.code is SCMWebhookErrorCode.AUTHENTICATION_FAILED
    assert state.admissions == []


def test_gitlab_rejects_non_merge_request_event() -> None:
    adapter, _state = _gitlab()
    body = _gitlab_body()
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(
            body, headers=_gitlab_headers(body, event="Push Hook"), delivery_key=DEFAULT_DELIVERY
        )
    assert error.value.code is SCMWebhookErrorCode.INVALID_HEADERS


@pytest.mark.parametrize("action", ["close", "merge", "approved"])
def test_gitlab_rejects_unsupported_actions(action: str) -> None:
    adapter, _state = _gitlab()
    body = _gitlab_body(action=action)
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(body, headers=_gitlab_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert error.value.code is SCMWebhookErrorCode.PAYLOAD_INVALID


@pytest.mark.parametrize(
    "body",
    [
        b"[]",
        b'{"object_kind":"push"}',
        b'{"object_kind":"merge_request","event_type":"push"}',
        b'{"object_kind":"merge_request","project":{"id":"501"},"object_attributes":{}}',
        b'{"object_kind":"merge_request","project":{"id":"999"},"object_attributes":{"action":"open","iid":"7","source_project_id":"501","target_project_id":"501","last_commit":{"id":"a"*40}}}',
    ],
)
def test_gitlab_rejects_malformed_payloads(body: bytes) -> None:
    adapter, _state = _gitlab()
    with pytest.raises(SCMWebhookError) as error:
        adapter.receive(body, headers=_gitlab_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert error.value.code in {
        SCMWebhookErrorCode.PAYLOAD_INVALID,
        SCMWebhookErrorCode.IDENTITY_MISMATCH,
    }


def test_gitlab_delivery_is_bound_to_one_project_change() -> None:
    """The admitted run is bound to the authenticated project and merge-request id."""

    adapter, state = _gitlab()
    body = _gitlab_body()
    first = adapter.receive(body, headers=_gitlab_headers(body), delivery_key=DEFAULT_DELIVERY)
    second = adapter.receive(
        body,
        headers=dict(_gitlab_headers(body), **{"X-Gitlab-Event-UUID": "uuid-0002"}),
        delivery_key="uuid-0002",
    )
    assert len(state.admissions) == 2
    assert first.admission.run_id == second.admission.run_id
    assert first.installation_id == second.installation_id == f"gitlab:{REPOSITORY}"
    assert first.change_id == second.change_id == "7"


def test_adapters_work_against_durable_state() -> None:
    """The real durable run state (not a stub) accepts webhook intake end to end."""

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    state = SqliteSCMRunState(connection, tenant_id=TENANT, initialize=True)
    adapter = GithubWebhookAdapter(
        webhook_secret=SECRET,
        pins=_pins(),
        run_state=state,
        head_resolver=lambda _installation, _repository: HEAD,
    )
    body = _github_body()
    receipt = adapter.receive(body, headers=_github_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert receipt.admission.disposition.value == "ADMITTED"
    target = state.provider_target(receipt.admission.run_id)
    assert target.provider == "github"
    assert target.repository_id == REPOSITORY

    replay = adapter.receive(body, headers=_github_headers(body), delivery_key=DEFAULT_DELIVERY)
    assert replay.admission.run_id == receipt.admission.run_id
