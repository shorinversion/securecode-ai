"""Authenticated GitHub and GitLab webhook admission for the server boundary.

The adapters authenticate the exact raw body before bounded JSON parsing.  They
derive run identity only from authenticated SCM revision metadata and immutable
server pins, then delegate lifecycle decisions to the existing SCM adapters.
No raw payload, token, signature, title, description, or source is returned.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from securecode_ai.adapters.github_app import (
    MAX_WEBHOOK_BYTES as MAX_GITHUB_WEBHOOK_BYTES,
)
from securecode_ai.adapters.github_app import (
    GithubAppAdapter,
    GithubAppError,
    GithubAppErrorCode,
    GithubWebhookDelivery,
)
from securecode_ai.adapters.gitlab_ci import (
    GitlabCIAdapter,
    GitlabCIAdmissionRequest,
    GitlabCIError,
    GitlabContributionTrust,
)
from securecode_ai.adapters.untrusted_contribution import ContributionTrust
from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ComponentPin,
    RepositoryRevision,
    RunExecutionIdentity,
)
from securecode_ai.core.scm_run_state import SCMRunAdmissionReceipt

from .scm_github_payload import GithubPayloadError, parse_github_payload
from .scm_payload import (
    MAX_JSON_DEPTH,
    MAX_JSON_ITEMS,
    MAX_JSON_SCALAR_BYTES,
    WebhookPayloadError,
    load_webhook_object,
)
from .scm_state import SCMRunStatePort

MAX_WEBHOOK_BYTES: Final = 65_536
_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_COMMIT_SHA: Final = re.compile(r"[0-9a-f]{40}\Z")
_GITHUB_SIGNATURE: Final = re.compile(r"sha256=[0-9a-f]{64}\Z")
_HEADER_NAME: Final = re.compile(r"[a-z0-9!#$%&'*+.^_`|~-]+\Z")
_GITHUB_ACTIONS: Final = frozenset({"opened", "reopened", "synchronize"})
_GITLAB_ACTIONS: Final = frozenset({"open", "reopen", "update"})


class SCMWebhookErrorCode(StrEnum):
    """Stable, source-free reasons for rejecting an SCM webhook."""

    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    INVALID_HEADERS = "INVALID_HEADERS"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    DELIVERY_CONFLICT = "DELIVERY_CONFLICT"
    PAYLOAD_INVALID = "PAYLOAD_INVALID"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    HEAD_UNAVAILABLE = "HEAD_UNAVAILABLE"
    STATE_REJECTED = "STATE_REJECTED"


class SCMWebhookError(ValueError):
    """Safe boundary error that never retains payload or credential material."""

    __slots__ = ("code", "safe_message")

    def __init__(self, code: SCMWebhookErrorCode) -> None:
        if type(code) is not SCMWebhookErrorCode:
            raise TypeError("SCM webhook error code is invalid")
        self.code = code
        self.safe_message = "SCM webhook was rejected"
        super().__init__(self.safe_message)
        self.__cause__ = None
        self.__context__ = None


@dataclass(frozen=True, slots=True)
class WebhookExecutionPins:
    """Server-authoritative execution semantics applied to every admitted webhook."""

    tenant_id: str
    stage_catalogue: ComponentPin
    workflow: ComponentPin
    policy: ComponentPin
    configuration: ComponentPin
    provider_profile: ComponentPin
    capability_profile: ComponentPin
    egress_profile: ComponentPin

    def __post_init__(self) -> None:
        pins = (
            self.stage_catalogue,
            self.workflow,
            self.policy,
            self.configuration,
            self.provider_profile,
            self.capability_profile,
            self.egress_profile,
        )
        if (
            type(self.tenant_id) is not str
            or _ID.fullmatch(self.tenant_id) is None
            or any(type(pin) is not ComponentPin for pin in pins)
        ):
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_CONFIGURATION)

    def build_identity(
        self,
        *,
        scm_provider: str,
        repository_id: str,
        head_sha: str,
        base_sha: str | None = None,
    ) -> RunExecutionIdentity:
        """Bind authenticated revision metadata to immutable server policy pins."""

        try:
            revision = RepositoryRevision(
                schema_version=CONTRACT_SCHEMA_VERSION,
                tenant_id=self.tenant_id,
                scm_provider=scm_provider,
                repository_id=repository_id,
                head_sha=head_sha,
                base_sha=base_sha,
            )
            return RunExecutionIdentity.build(
                repository_revision=revision,
                stage_catalogue=self.stage_catalogue,
                workflow=self.workflow,
                policy=self.policy,
                configuration=self.configuration,
                provider_profile=self.provider_profile,
                capability_profile=self.capability_profile,
                egress_profile=self.egress_profile,
            )
        except (TypeError, ValueError):
            raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID) from None


@dataclass(frozen=True, slots=True)
class WebhookAdmissionReceipt:
    """Metadata-only webhook result suitable for the HTTP response and audit log."""

    provider: str
    event: str
    delivery_id: str
    installation_id: str
    repository_id: str
    change_id: str | None
    head_sha: str
    base_sha: str | None
    admission: SCMRunAdmissionReceipt
    contribution_trust: ContributionTrust = ContributionTrust.UNKNOWN

    def as_document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "provider": self.provider,
            "event": self.event,
            "delivery_id": self.delivery_id,
            "installation_id": self.installation_id,
            "repository_id": self.repository_id,
            "head_sha": self.head_sha,
            "run_id": self.admission.run_id,
            "execution_identity_hash": self.admission.execution_identity_hash,
            "disposition": self.admission.disposition.value,
            "lifecycle": self.admission.lifecycle.value,
            "state_version": self.admission.state_version,
            "superseded_run_ids": list(self.admission.superseded_run_ids),
        }
        if self.change_id is not None:
            document["change_id"] = self.change_id
        return document


class GithubWebhookAdapter:
    """Authenticate GitHub pull-request webhooks and admit exact-SHA runs."""

    __slots__ = ("_adapter", "_pins", "_webhook_secret")

    def __init__(
        self,
        *,
        webhook_secret: bytes,
        pins: WebhookExecutionPins,
        run_state: SCMRunStatePort,
        head_resolver: object,
    ) -> None:
        if (
            type(webhook_secret) is not bytes
            or not webhook_secret
            or len(webhook_secret) > MAX_JSON_SCALAR_BYTES
            or type(pins) is not WebhookExecutionPins
        ):
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_CONFIGURATION)
        try:
            adapter = GithubAppAdapter(
                webhook_secret=webhook_secret,
                run_state=run_state,
                head_resolver=head_resolver,
            )
        except (GithubAppError, TypeError, ValueError):
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_CONFIGURATION) from None
        self._webhook_secret = webhook_secret
        self._pins = pins
        self._adapter = adapter

    async def handle_raw(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str],
        delivery_key: str | None,
    ) -> dict[str, object]:
        return self.receive(body, headers=headers, delivery_key=delivery_key).as_document()

    def receive(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str],
        delivery_key: str | None,
    ) -> WebhookAdmissionReceipt:
        raw_body = _validate_raw_body(body, max_bytes=MAX_GITHUB_WEBHOOK_BYTES)
        admitted_headers = _normalize_headers(headers)
        event = _required_header(admitted_headers, "x-github-event")
        delivery_id = _matched_delivery(
            admitted_headers,
            "x-github-delivery",
            delivery_key,
        )
        signature = _required_header(admitted_headers, "x-hub-signature-256")
        if event != "pull_request" or _GITHUB_SIGNATURE.fullmatch(signature) is None:
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_HEADERS)
        expected = (
            "sha256="
            + hmac.new(
                self._webhook_secret,
                raw_body,
                hashlib.sha256,
            ).hexdigest()
        )
        if not hmac.compare_digest(expected, signature):
            raise SCMWebhookError(SCMWebhookErrorCode.AUTHENTICATION_FAILED)

        payload = _parse_github_payload(raw_body)
        metadata = _github_metadata(payload)
        identity = self._pins.build_identity(
            scm_provider="github",
            repository_id=metadata.repository_id,
            head_sha=metadata.head_sha,
            base_sha=metadata.base_sha,
        )
        try:
            receipt = self._adapter.receive(
                GithubWebhookDelivery(
                    delivery_id=delivery_id,
                    event=event,
                    signature_sha256=signature,
                    raw_body=raw_body,
                    execution_identity=identity,
                )
            )
        except GithubAppError as error:
            raise _github_error(error.code) from None
        return WebhookAdmissionReceipt(
            provider="github",
            event=event,
            delivery_id=delivery_id,
            installation_id=receipt.installation_id,
            repository_id=receipt.repository_id,
            change_id=metadata.change_id,
            head_sha=receipt.head_sha,
            base_sha=metadata.base_sha,
            admission=receipt.admission,
            contribution_trust=metadata.contribution_trust,
        )


class GitlabWebhookAdapter:
    """Authenticate GitLab merge-request webhooks and admit exact-SHA runs."""

    __slots__ = ("_adapter", "_pins", "_webhook_token")

    def __init__(
        self,
        *,
        webhook_token: bytes,
        pins: WebhookExecutionPins,
        run_state: SCMRunStatePort,
        head_resolver: object,
    ) -> None:
        if (
            type(webhook_token) is not bytes
            or not webhook_token
            or len(webhook_token) > MAX_JSON_SCALAR_BYTES
            or type(pins) is not WebhookExecutionPins
        ):
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_CONFIGURATION)
        try:
            adapter = GitlabCIAdapter(run_state=run_state, head_resolver=head_resolver)
        except (GitlabCIError, TypeError, ValueError):
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_CONFIGURATION) from None
        self._webhook_token = webhook_token
        self._pins = pins
        self._adapter = adapter

    async def handle_raw(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str],
        delivery_key: str | None,
    ) -> dict[str, object]:
        return self.receive(body, headers=headers, delivery_key=delivery_key).as_document()

    def receive(
        self,
        body: bytes,
        *,
        headers: Mapping[str, str],
        delivery_key: str | None,
    ) -> WebhookAdmissionReceipt:
        raw_body = _validate_raw_body(body)
        admitted_headers = _normalize_headers(headers)
        event = _required_header(admitted_headers, "x-gitlab-event")
        delivery_id = _matched_delivery(
            admitted_headers,
            "x-gitlab-event-uuid",
            delivery_key,
        )
        token = _required_header(admitted_headers, "x-gitlab-token")
        if event != "Merge Request Hook":
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_HEADERS)
        try:
            token_bytes = token.encode("utf-8", "strict")
        except UnicodeEncodeError:
            raise SCMWebhookError(SCMWebhookErrorCode.AUTHENTICATION_FAILED) from None
        expected_token = hashlib.sha256(self._webhook_token).digest()
        received_token = hashlib.sha256(token_bytes).digest()
        if not hmac.compare_digest(expected_token, received_token):
            raise SCMWebhookError(SCMWebhookErrorCode.AUTHENTICATION_FAILED)

        payload = _parse_payload(raw_body)
        metadata = _gitlab_metadata(payload)
        identity = self._pins.build_identity(
            scm_provider="gitlab",
            repository_id=metadata.target_project_id,
            head_sha=metadata.head_sha,
        )
        same_project = metadata.source_project_id == metadata.target_project_id
        trust = (
            GitlabContributionTrust.TRUSTED
            if same_project
            else GitlabContributionTrust.UNTRUSTED_FORK
        )
        contribution_trust = (
            ContributionTrust.TRUSTED_SAME_REPOSITORY
            if same_project
            else ContributionTrust.UNTRUSTED_FORK
        )
        pipeline_id = "event-" + hashlib.sha256(delivery_id.encode("ascii")).hexdigest()[:32]
        try:
            receipt = self._adapter.admit(
                GitlabCIAdmissionRequest(
                    pipeline_id=pipeline_id,
                    job_id="webhook",
                    project_id=metadata.target_project_id,
                    merge_request_iid=metadata.change_id,
                    source_project_id=metadata.source_project_id,
                    target_project_id=metadata.target_project_id,
                    contribution_trust=trust,
                    execution_identity=identity,
                )
            )
        except GitlabCIError as error:
            raise _gitlab_error(error) from None
        return WebhookAdmissionReceipt(
            provider="gitlab",
            event="merge_request",
            delivery_id=delivery_id,
            installation_id=f"gitlab:{receipt.project_id}",
            repository_id=receipt.project_id,
            change_id=receipt.merge_request_iid,
            head_sha=receipt.head_sha,
            base_sha=None,
            admission=receipt.admission,
            contribution_trust=contribution_trust,
        )


@dataclass(frozen=True, slots=True)
class _GithubMetadata:
    repository_id: str
    change_id: str | None
    head_sha: str
    base_sha: str | None
    contribution_trust: ContributionTrust


@dataclass(frozen=True, slots=True)
class _GitlabMetadata:
    target_project_id: str
    source_project_id: str
    change_id: str
    head_sha: str


def _github_metadata(payload: Mapping[str, object]) -> _GithubMetadata:
    if payload.get("action") not in _GITHUB_ACTIONS:
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
    repository_id = _positive_identifier(_object(payload, "repository").get("id"))
    pull_request = _object(payload, "pull_request")
    head = _object(pull_request, "head")
    head_sha = _commit_sha(head.get("sha"))
    base = _object(pull_request, "base") if "base" in pull_request else {}
    base_value = base.get("sha")
    base_sha = None if base_value is None else _commit_sha(base_value)
    head_repository = head.get("repo")
    base_repository = base.get("repo")
    if type(head_repository) is dict and type(base_repository) is dict:
        head_repository_id = _positive_identifier(head_repository.get("id"))
        base_repository_id = _positive_identifier(base_repository.get("id"))
        if base_repository_id != repository_id:
            raise SCMWebhookError(SCMWebhookErrorCode.IDENTITY_MISMATCH)
        if head_repository_id != base_repository_id:
            trust = ContributionTrust.UNTRUSTED_FORK
        elif pull_request.get("author_association") in {
            "OWNER",
            "MEMBER",
            "COLLABORATOR",
        }:
            trust = ContributionTrust.TRUSTED_SAME_REPOSITORY
        else:
            trust = ContributionTrust.UNTRUSTED_SAME_REPOSITORY
    else:
        trust = ContributionTrust.UNKNOWN
    change_value = payload.get("number", pull_request.get("number"))
    change_id = None if change_value is None else _positive_identifier(change_value)
    _positive_identifier(_object(payload, "installation").get("id"))
    return _GithubMetadata(repository_id, change_id, head_sha, base_sha, trust)


def _gitlab_metadata(payload: Mapping[str, object]) -> _GitlabMetadata:
    if payload.get("object_kind") != "merge_request":
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
    event_type = payload.get("event_type")
    if event_type is not None and event_type != "merge_request":
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
    project_id = _positive_identifier(_object(payload, "project").get("id"))
    attributes = _object(payload, "object_attributes")
    if attributes.get("action") not in _GITLAB_ACTIONS:
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
    target_project_id = _positive_identifier(attributes.get("target_project_id"))
    source_project_id = _positive_identifier(attributes.get("source_project_id"))
    if project_id != target_project_id:
        raise SCMWebhookError(SCMWebhookErrorCode.IDENTITY_MISMATCH)
    return _GitlabMetadata(
        target_project_id=target_project_id,
        source_project_id=source_project_id,
        change_id=_positive_identifier(attributes.get("iid")),
        head_sha=_commit_sha(_object(attributes, "last_commit").get("id")),
    )


def _validate_raw_body(body: bytes, *, max_bytes: int = MAX_WEBHOOK_BYTES) -> bytes:
    if type(body) is not bytes or not body or len(body) > max_bytes:
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
    return body


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(headers, Mapping) or len(headers) > 64:
        raise SCMWebhookError(SCMWebhookErrorCode.INVALID_HEADERS)
    normalized: dict[str, str] = {}
    for raw_name, value in headers.items():
        if type(raw_name) is not str or type(value) is not str:
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_HEADERS)
        name = raw_name.lower()
        try:
            value_size = len(value.encode("utf-8"))
        except UnicodeEncodeError:
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_HEADERS) from None
        if (
            _HEADER_NAME.fullmatch(name) is None
            or name in normalized
            or not value
            or value_size > MAX_JSON_SCALAR_BYTES
            or "\r" in value
            or "\n" in value
        ):
            raise SCMWebhookError(SCMWebhookErrorCode.INVALID_HEADERS)
        normalized[name] = value
    return normalized


def _required_header(headers: Mapping[str, str], name: str) -> str:
    value = headers.get(name)
    if value is None:
        raise SCMWebhookError(SCMWebhookErrorCode.INVALID_HEADERS)
    return value


def _matched_delivery(
    headers: Mapping[str, str],
    header_name: str,
    delivery_key: str | None,
) -> str:
    header_delivery = _required_header(headers, header_name)
    if (
        type(delivery_key) is not str
        or _ID.fullmatch(delivery_key) is None
        or _ID.fullmatch(header_delivery) is None
        or not hmac.compare_digest(delivery_key, header_delivery)
    ):
        raise SCMWebhookError(SCMWebhookErrorCode.DELIVERY_CONFLICT)
    return delivery_key


def _parse_payload(raw_body: bytes) -> dict[str, object]:
    try:
        return load_webhook_object(raw_body)
    except WebhookPayloadError:
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID) from None


def _parse_github_payload(raw_body: bytes) -> dict[str, object]:
    try:
        return parse_github_payload(raw_body)
    except GithubPayloadError:
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID) from None


def _object(value: Mapping[str, object], name: str) -> dict[str, object]:
    item = value.get(name)
    if type(item) is not dict:
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
    return item


def _positive_identifier(value: object) -> str:
    if type(value) is int and value > 0:
        identifier = str(value)
    elif type(value) is str:
        identifier = value
    else:
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
    if _ID.fullmatch(identifier) is None:
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
    return identifier


def _commit_sha(value: object) -> str:
    if type(value) is not str or _COMMIT_SHA.fullmatch(value) is None:
        raise SCMWebhookError(SCMWebhookErrorCode.PAYLOAD_INVALID)
    return value


def _github_error(code: GithubAppErrorCode) -> SCMWebhookError:
    mapping = {
        GithubAppErrorCode.INVALID_CONFIGURATION: SCMWebhookErrorCode.INVALID_CONFIGURATION,
        GithubAppErrorCode.AUTHENTICATION_FAILED: SCMWebhookErrorCode.AUTHENTICATION_FAILED,
        GithubAppErrorCode.DELIVERY_INVALID: SCMWebhookErrorCode.INVALID_HEADERS,
        GithubAppErrorCode.PAYLOAD_INVALID: SCMWebhookErrorCode.PAYLOAD_INVALID,
        GithubAppErrorCode.IDENTITY_MISMATCH: SCMWebhookErrorCode.IDENTITY_MISMATCH,
        GithubAppErrorCode.HEAD_UNAVAILABLE: SCMWebhookErrorCode.HEAD_UNAVAILABLE,
        GithubAppErrorCode.STATE_REJECTED: SCMWebhookErrorCode.STATE_REJECTED,
        GithubAppErrorCode.RUN_UNKNOWN: SCMWebhookErrorCode.STATE_REJECTED,
    }
    return SCMWebhookError(mapping[code])


def _gitlab_error(error: GitlabCIError) -> SCMWebhookError:
    name = error.code.value
    if name == "HEAD_UNAVAILABLE":
        code = SCMWebhookErrorCode.HEAD_UNAVAILABLE
    elif name == "IDENTITY_MISMATCH":
        code = SCMWebhookErrorCode.IDENTITY_MISMATCH
    elif name == "INVALID_CONFIGURATION":
        code = SCMWebhookErrorCode.INVALID_CONFIGURATION
    elif name == "INVALID_REQUEST":
        code = SCMWebhookErrorCode.PAYLOAD_INVALID
    else:
        code = SCMWebhookErrorCode.STATE_REJECTED
    return SCMWebhookError(code)


__all__ = [
    "MAX_JSON_DEPTH",
    "MAX_JSON_ITEMS",
    "MAX_JSON_SCALAR_BYTES",
    "MAX_WEBHOOK_BYTES",
    "GithubWebhookAdapter",
    "GitlabWebhookAdapter",
    "SCMWebhookError",
    "SCMWebhookErrorCode",
    "WebhookAdmissionReceipt",
    "WebhookExecutionPins",
]
