"""HTTP handlers for pilot feedback and source-free assurance evidence."""

from __future__ import annotations

from dataclasses import asdict
from typing import cast

from .assurance_reports import (
    AssurancePinsProvider,
    AssuranceReportError,
    UnavailableAssurancePinsProvider,
)
from .assurance_repository import AssuranceConflict, AssuranceRecord
from .assurance_service import AssuranceService
from .assurance_verifiers import (
    AssuranceVerifierRegistry,
    AssuranceVerifierRegistryError,
)
from .feedback_repository import FeedbackConflict
from .feedback_service import FeedbackService
from .operations_handler_common import (
    CONFLICT,
    FORBIDDEN,
    INVALID_REQUEST,
    PRECONDITION_FAILED,
    document,
    error,
    expected_version,
    matches_tenant,
    optional_string,
    query_value,
    repository_allowed,
    response,
    string,
)
from .ports import ServiceRequest, ServiceResponse


class FeedbackOperationsHandler:
    def __init__(self, service: FeedbackService) -> None:
        if type(service) is not FeedbackService:
            raise TypeError("service must be a FeedbackService")
        self._service = service

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action == "feedback.submit":
            return self._submit(request)
        if request.action == "feedback.metrics.read":
            return self._metrics(request)
        return error(503, "HANDLER_UNAVAILABLE", "requested handler is unavailable")

    def _submit(self, request: ServiceRequest) -> ServiceResponse:
        value = document(
            request,
            required=frozenset(
                {
                    "repository_id",
                    "run_id",
                    "finding_id",
                    "head_sha",
                    "identity_hash",
                    "decision",
                    "reason",
                    "rationale",
                }
            ),
            optional=frozenset({"incident_id", "tenant_id"}),
        )
        version = expected_version(request)
        if value is None or not matches_tenant(value, request.identity):
            return INVALID_REQUEST
        if version is None:
            return PRECONDITION_FAILED
        if version != 0:
            return PRECONDITION_FAILED
        fields = tuple(
            string(value, name, maximum=1024 if name == "rationale" else 256)
            for name in (
                "repository_id",
                "run_id",
                "finding_id",
                "head_sha",
                "identity_hash",
                "decision",
                "reason",
                "rationale",
            )
        )
        if any(item is None for item in fields):
            return INVALID_REQUEST
        (
            repository_id,
            run_id,
            finding_id,
            head_sha,
            identity_hash,
            decision,
            reason,
            rationale,
        ) = (cast(str, item) for item in fields)
        incident_id = optional_string(value, "incident_id")
        if value.get("incident_id") is not None and incident_id is None:
            return INVALID_REQUEST
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        try:
            stored = self._service.submit(
                allowed=True,
                tenant_id=request.identity.tenant_id,
                repository_id=repository_id,
                run_id=run_id,
                finding_id=finding_id,
                head_sha=head_sha,
                identity_hash=identity_hash,
                decision=decision,
                reason=reason,
                rationale=rationale,
                incident_id=incident_id,
                expected_version=version,
            )
        except (FeedbackConflict, TypeError, ValueError):
            return CONFLICT
        return response(201, asdict(stored), version=stored.version)

    def _metrics(self, request: ServiceRequest) -> ServiceResponse:
        if set(request.query) != {"repository_id"}:
            return INVALID_REQUEST
        repository_id = query_value(request, "repository_id")
        if repository_id is None:
            return INVALID_REQUEST
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        try:
            metrics = self._service.metrics(
                request.identity.tenant_id,
                repository_id,
            )
        except (FeedbackConflict, TypeError, ValueError):
            return CONFLICT
        return response(200, metrics)


class AssuranceOperationsHandler:
    def __init__(
        self,
        service: AssuranceService,
        verifiers: AssuranceVerifierRegistry | None = None,
        pins_provider: AssurancePinsProvider | None = None,
    ) -> None:
        if (
            type(service) is not AssuranceService
            or (verifiers is not None and type(verifiers) is not AssuranceVerifierRegistry)
            or (pins_provider is not None and not callable(getattr(pins_provider, "resolve", None)))
        ):
            raise TypeError("assurance handler configuration is invalid")
        self._service = service
        self._verifiers = AssuranceVerifierRegistry.deny_all() if verifiers is None else verifiers
        self._pins_provider = (
            UnavailableAssurancePinsProvider() if pins_provider is None else pins_provider
        )

    async def dispatch(self, request: ServiceRequest) -> ServiceResponse:
        if request.action == "assurance.append":
            return self._append(request)
        if request.action == "assurance.read":
            return self._read(request)
        return error(503, "HANDLER_UNAVAILABLE", "requested handler is unavailable")

    def _append(self, request: ServiceRequest) -> ServiceResponse:
        value = document(
            request,
            required=frozenset(
                {
                    "repository_id",
                    "execution_identity_hash",
                    "record_id",
                    "kind",
                    "outcome",
                    "verifier_sha256",
                    "payload",
                }
            ),
            optional=frozenset({"tenant_id"}),
        )
        sequence = expected_version(request)
        if value is None or not matches_tenant(value, request.identity):
            return INVALID_REQUEST
        if sequence is None:
            return PRECONDITION_FAILED
        fields = tuple(
            string(value, name)
            for name in (
                "repository_id",
                "execution_identity_hash",
                "record_id",
                "kind",
                "outcome",
                "verifier_sha256",
            )
        )
        payload = value.get("payload")
        if any(item is None for item in fields) or type(payload) is not dict:
            return INVALID_REQUEST
        (
            repository_id,
            identity_hash,
            record_id,
            kind,
            outcome,
            verifier_sha256,
        ) = (cast(str, item) for item in fields)
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        try:
            bound_verifier_sha256 = self._verifiers.bind(
                request.identity.subject_id,
                verifier_sha256,
            )
        except AssuranceVerifierRegistryError:
            return FORBIDDEN
        try:
            current = self._service.report_inputs(
                tenant_id=request.identity.tenant_id,
                repository_id=repository_id,
                execution_identity_hash=identity_hash,
            )
            if current.get("denominator") != sequence:
                return PRECONDITION_FAILED
            stored = self._service.append_attempt(
                AssuranceRecord(
                    tenant_id=request.identity.tenant_id,
                    repository_id=repository_id,
                    execution_identity_hash=identity_hash,
                    record_id=record_id,
                    kind=kind,
                    outcome=outcome,
                    verifier_id=request.identity.subject_id,
                    verifier_sha256=bound_verifier_sha256,
                    payload=payload,
                ),
                expected_sequence=sequence,
            )
        except (AssuranceConflict, TypeError, ValueError):
            return CONFLICT
        return response(201, self._record_view(stored), version=stored.sequence)

    def _read(self, request: ServiceRequest) -> ServiceResponse:
        if set(request.query) not in (
            {"repository_id", "execution_identity_hash"},
            {"repository_id", "execution_identity_hash", "view"},
        ):
            return INVALID_REQUEST
        repository_id = query_value(request, "repository_id")
        identity_hash = query_value(request, "execution_identity_hash")
        if repository_id is None or identity_hash is None:
            return INVALID_REQUEST
        view = query_value(request, "view")
        if view is not None and view != "report":
            return INVALID_REQUEST
        if not repository_allowed(request.identity, repository_id):
            return FORBIDDEN
        if view == "report":
            try:
                report = self._service.report(
                    tenant_id=request.identity.tenant_id,
                    repository_id=repository_id,
                    execution_identity_hash=identity_hash,
                    pins_provider=self._pins_provider,
                )
            except (AssuranceReportError, TypeError, ValueError):
                return error(
                    503,
                    "ASSURANCE_PINS_UNAVAILABLE",
                    "authoritative assurance pins are unavailable",
                )
            except AssuranceConflict:
                return CONFLICT
            return response(200, asdict(report))
        try:
            inputs = self._service.report_inputs(
                tenant_id=request.identity.tenant_id,
                repository_id=repository_id,
                execution_identity_hash=identity_hash,
            )
        except (AssuranceConflict, TypeError, ValueError):
            return CONFLICT
        if not _report_matches_scope(
            inputs,
            tenant_id=request.identity.tenant_id,
            repository_id=repository_id,
            execution_identity_hash=identity_hash,
        ):
            return CONFLICT
        sequence = inputs.get("denominator")
        return response(200, inputs, version=sequence if type(sequence) is int else None)

    @staticmethod
    def _record_view(value: AssuranceRecord) -> dict[str, object]:
        return {
            "tenant_id": value.tenant_id,
            "repository_id": value.repository_id,
            "execution_identity_hash": value.execution_identity_hash,
            "record_id": value.record_id,
            "kind": value.kind,
            "outcome": value.outcome,
            "verifier_id": value.verifier_id,
            "verifier_sha256": value.verifier_sha256,
            "sequence": value.sequence,
            "previous_hash": value.previous_hash,
            "record_hash": value.record_hash,
        }


def _report_matches_scope(
    value: object,
    *,
    tenant_id: str,
    repository_id: str,
    execution_identity_hash: str,
) -> bool:
    """Reject a service response that is not bound to the requested scope."""

    return (
        type(value) is dict
        and value.get("tenant_id") == tenant_id
        and value.get("repository_id") == repository_id
        and value.get("execution_identity_hash") == execution_identity_hash
        and type(value.get("records")) is tuple
        and type(value.get("denominator")) is int
        and type(value.get("successful")) is int
        and type(value.get("failed_or_incomplete")) is int
        and type(value.get("ledger_head_sha256")) is str
        and type(value.get("complete")) is bool
        and value.get("authority") == "SUPPORTING_EVIDENCE_ONLY"
    )


__all__ = ["AssuranceOperationsHandler", "FeedbackOperationsHandler"]
