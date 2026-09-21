"""Compose actual product-flow receipts into a conservative Core audit run.

The adapter deliberately does not fill gaps in the accepted stage catalogue.
It returns a typed obstacle when immutable upstream receipts cannot be represented
by the frozen public ``CoverageManifest`` contract.
"""

from __future__ import annotations

import re

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CandidateInterpretationReceipt,
    CandidateOrigin,
    ComponentPin,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    RunExecutionIdentity,
)
from securecode_ai.contracts.domain_primitives import ACCEPTED_STAGE_CATALOGUE_PIN
from securecode_ai.core.evidence_package import EvidenceContextRef, EvidencePackage
from securecode_ai.core.investigation import (
    AuditorAttemptReceipt,
    AuditorInvestigationReceipt,
)

from .native_sources import NativeSourceCatalogue
from .product_audit_common import _receipt_id, _request_sha256, _terminal_output_sha256
from .product_audit_types import (
    ProductAuditFindingMetadata,
    ProductAuditHostInputs,
    ProductAuditObstacle,
    ProductAuditStateObservation,
    ProductDiscoveryCandidateMapping,
    _AuditObstacle,
)
from .product_model import AUDITOR_WIRE_PIN
from .product_review import ProductReviewResult
from .product_runtime import PRODUCT_AUDITOR_PROMPT_PIN, ProductAuditorInvocationObservation
from .product_scan import (
    ProductCandidateFlow,
    ProductCandidatePreparationFailure,
)


def _require_scan_operation(host: ProductAuditHostInputs) -> None:
    if type(host.operation) is not str or host.operation != "scan":
        raise _AuditObstacle(
            "PRODUCT_OPERATION_UNSUPPORTED", "scan-only executor cannot complete repair requests"
        )


def _probe_current_state(host: ProductAuditHostInputs) -> ProductAuditStateObservation:
    if host.state_probe is None:
        raise _AuditObstacle(
            "PRODUCT_AUDIT_STATE_UNAVAILABLE", "host state observation unavailable"
        )
    try:
        state = host.state_probe.observe(
            run_id=host.run_id, execution_identity=host.execution_identity
        )
    except Exception:
        raise _AuditObstacle(
            "PRODUCT_AUDIT_STATE_UNAVAILABLE", "host state observation unavailable"
        ) from None
    if (
        type(state) is not ProductAuditStateObservation
        or state.run_id != host.run_id
        or state.execution_identity_hash != host.execution_identity.execution_identity_hash
        or type(state.current_head_sha) is not str
        or re.fullmatch(r"[0-9a-f]{40}", state.current_head_sha) is None
        or type(state.cancelled) is not bool
        or type(state.reporting_allowed) is not bool
    ):
        raise _AuditObstacle("PRODUCT_AUDIT_STATE_INVALID", "host state binding invalid")
    if state.current_head_sha != host.execution_identity.repository_revision.head_sha:
        raise _AuditObstacle("PRODUCT_AUDIT_SUPERSEDED", "execution revision is no longer current")
    if state.cancelled:
        raise _AuditObstacle("PRODUCT_AUDIT_CANCELLED", "execution cancelled")
    return state


def _validate_host(
    flow: ProductCandidateFlow, review: ProductReviewResult, host: ProductAuditHostInputs
) -> None:
    if (
        type(flow) is not ProductCandidateFlow
        or type(review) is not ProductReviewResult
        or type(host) is not ProductAuditHostInputs
        or type(host.execution_identity) is not RunExecutionIdentity
        or type(host.discovery_request) is not ModelRequest
        or type(host.auditor) is not ComponentPin
        or type(host.source_catalogue) is not NativeSourceCatalogue
        or type(host.auditor_observations) is not tuple
        or type(host.finding_metadata) is not tuple
        or type(host.report_tools) is not tuple
        or any(
            type(item) is not ProductAuditorInvocationObservation
            for item in host.auditor_observations
        )
        or any(type(item) is not ProductAuditFindingMetadata for item in host.finding_metadata)
        or any(type(item) is not ComponentPin for item in host.report_tools)
        or host.completed_at < host.created_at
    ):
        raise ValueError
    request = ModelRequest.model_validate_json(host.discovery_request.model_dump_json())
    if (
        request.run_id != host.run_id
        or request.execution_identity != host.execution_identity
        or request.role is not ModelRole.DISCOVERY
        or request.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY
        or request.tenant_id != flow.graph.tenant_id
        or request.head_sha != flow.graph.head_sha
        or flow.discovery.receipt.tenant_id != request.tenant_id
        or flow.discovery.receipt.head_sha != request.head_sha
        or flow.discovery.receipt.model_profile != request.provider_profile
        or flow.discovery.receipt.prompt != request.prompt
        or host.source_catalogue.snapshot.head_sha != request.head_sha
        or any(anchor.tenant_id != request.tenant_id for anchor in host.source_catalogue.anchors)
        or host.execution_identity.repository_revision.tenant_id != request.tenant_id
        or host.execution_identity.repository_revision.head_sha != request.head_sha
        or host.execution_identity.stage_catalogue.model_dump(mode="python")
        != ComponentPin(
            schema_version=CONTRACT_SCHEMA_VERSION,
            component_id=ACCEPTED_STAGE_CATALOGUE_PIN[0],
            component_version=ACCEPTED_STAGE_CATALOGUE_PIN[1],
            content_sha256=ACCEPTED_STAGE_CATALOGUE_PIN[2],
        ).model_dump(mode="python")
    ):
        raise ValueError
    # This revalidates immutable intake bytes and language indexes.  It does not
    # create an intake or language-discovery stage receipt.
    host.source_catalogue.repository_view()


def _model_candidate_mismatch(flow: ProductCandidateFlow) -> ProductAuditObstacle | None:
    mappings = model_discovery_candidate_mappings(flow)
    if type(mappings) is ProductAuditObstacle:
        return mappings
    if type(mappings) is not tuple:
        raise ValueError
    mapped_current_ids = {item.current_candidate_id for item in mappings}
    current_ids = {
        candidate.candidate_id
        for candidate in flow.graph.candidates
        if candidate.candidate_origin in {CandidateOrigin.MODEL_NATIVE, CandidateOrigin.HYBRID}
    }
    if mapped_current_ids != current_ids:
        return ProductAuditObstacle(
            "MODEL_DISCOVERY_CURRENT_CANDIDATE_MISMATCH",
            "some current model-bearing candidates have no immutable discovery predecessor",
        )
    return None


def model_discovery_candidate_mappings(
    flow: ProductCandidateFlow,
) -> tuple[ProductDiscoveryCandidateMapping, ...] | ProductAuditObstacle:
    """Expose immutable lineage mapping without changing receipt or graph IDs."""

    if type(flow) is not ProductCandidateFlow:
        return ProductAuditObstacle("PRODUCT_AUDIT_INPUT_INVALID", "flow is invalid")
    mappings: list[ProductDiscoveryCandidateMapping] = []
    for receipt_id in flow.discovery.receipt.candidate_ids:
        matches = [
            candidate
            for candidate in flow.graph.candidates
            if candidate.candidate_origin in {CandidateOrigin.MODEL_NATIVE, CandidateOrigin.HYBRID}
            and (
                receipt_id == candidate.candidate_id
                or receipt_id
                in {
                    source_id
                    for lineage in candidate.lineage
                    if lineage.lane.value == "model_native"
                    for source_id in lineage.input_candidate_ids
                }
            )
        ]
        if len(matches) != 1:
            return ProductAuditObstacle(
                "MODEL_DISCOVERY_LINEAGE_MAPPING_INVALID",
                "immutable discovery receipt ID has no unique current lineage mapping",
            )
        candidate = matches[0]
        mappings.append(
            ProductDiscoveryCandidateMapping(
                receipt_candidate_id=receipt_id,
                current_candidate_id=candidate.candidate_id,
                current_candidate_version=candidate.candidate_version,
                current_origin=candidate.candidate_origin,
            )
        )
    return tuple(mappings)


def _validate_review(flow: ProductCandidateFlow, review: ProductReviewResult) -> None:
    if (
        review.tenant_id != flow.graph.tenant_id
        or review.head_sha != flow.graph.head_sha
        or review.discovery != flow.discovery
        or len(review.outcomes) != len(flow.graph.candidates)
    ):
        raise ValueError
    expected = [
        (candidate.candidate_id, candidate.candidate_version) for candidate in flow.graph.candidates
    ]
    actual = [(outcome.candidate_id, outcome.candidate_version) for outcome in review.outcomes]
    if actual != expected or any(
        outcome.tenant_id != flow.graph.tenant_id or outcome.head_sha != flow.graph.head_sha
        for outcome in review.outcomes
    ):
        raise ValueError


def _interpretations(
    flow: ProductCandidateFlow, host: ProductAuditHostInputs
) -> tuple[CandidateInterpretationReceipt, ...]:
    observations = _observations_by_attempt(flow, host)
    output: list[CandidateInterpretationReceipt] = []
    for candidate, investigation in zip(flow.graph.candidates, flow.investigations, strict=True):
        if type(investigation) is ProductCandidatePreparationFailure:
            raise _AuditObstacle(
                "AUDITOR_OBSERVATION_MISSING",
                "no actual Auditor request/package observation exists for preparation failure",
            )
        if type(investigation) is not AuditorInvestigationReceipt or not investigation.attempts:
            raise ValueError
        terminal = investigation.attempts[-1]
        observation = observations[
            (candidate.candidate_id, candidate.candidate_version, terminal.attempt)
        ]
        request = observation.request
        if (
            request.provider_profile != host.discovery_request.provider_profile
            or request.prompt != PRODUCT_AUDITOR_PROMPT_PIN
            or request.output_schema != AUDITOR_WIRE_PIN
            or request.run_id != host.run_id
            or request.execution_identity != host.execution_identity
            or observation.package.candidate_id != candidate.candidate_id
            or observation.package.candidate_version != candidate.candidate_version
            or observation.package.tenant_id != candidate.tenant_id
            or observation.package.head_sha != candidate.head_sha
            or observation.package.selection_sha256 != terminal.selection_sha256
            or (
                observation.model_call_status_before_collection is not ModelCallStatus.SUCCEEDED
                and terminal.model_call_status is ModelCallStatus.SUCCEEDED
            )
            or (
                terminal.model_call_status is ModelCallStatus.SUCCEEDED
                and (
                    observation.model_call_status_before_collection is not ModelCallStatus.SUCCEEDED
                    or not observation.schema_valid_result_before_collection
                    or not terminal.schema_valid_result
                )
            )
        ):
            raise ValueError
        succeeded = terminal.model_call_status is ModelCallStatus.SUCCEEDED
        output.append(
            CandidateInterpretationReceipt(
                schema_version=CONTRACT_SCHEMA_VERSION,
                receipt_id=_receipt_id("auditor", candidate.candidate_id),
                tenant_id=candidate.tenant_id,
                candidate_id=candidate.candidate_id,
                candidate_version=candidate.candidate_version,
                head_sha=candidate.head_sha,
                auditor=host.auditor,
                model_profile=request.provider_profile,
                prompt=request.prompt,
                evidence_sha256=observation.package.selection_sha256,
                model_call_status=terminal.model_call_status,
                schema_valid_result=terminal.schema_valid_result,
                verdict_ref=terminal.verdict_id if succeeded else None,
                input_sha256=_request_sha256(request),
                output_sha256=_terminal_output_sha256(terminal) if succeeded else None,
            )
        )
    return tuple(output)


def _observations_by_attempt(
    flow: ProductCandidateFlow, host: ProductAuditHostInputs
) -> dict[tuple[str, int, int], ProductAuditorInvocationObservation]:
    expected: dict[tuple[str, int, int], AuditorAttemptReceipt] = {}
    for candidate, investigation in zip(flow.graph.candidates, flow.investigations, strict=True):
        if type(investigation) is AuditorInvestigationReceipt:
            expected.update(
                ((candidate.candidate_id, candidate.candidate_version, attempt.attempt), attempt)
                for attempt in investigation.attempts
            )
        elif type(investigation) is not ProductCandidatePreparationFailure:
            raise ValueError
    values: dict[tuple[str, int, int], ProductAuditorInvocationObservation] = {}
    for observation in host.auditor_observations:
        request = ModelRequest.model_validate_json(observation.request.model_dump_json())
        package = observation.package
        _validate_observed_package(flow, package)
        key = (package.candidate_id, package.candidate_version, request.attempt)
        attempt = expected.get(key)
        if (
            key in values
            or attempt is None
            or package.selection_sha256 != attempt.selection_sha256
            or (
                attempt.model_call_status is ModelCallStatus.SUCCEEDED
                and (
                    observation.model_call_status_before_collection is not ModelCallStatus.SUCCEEDED
                    or not observation.schema_valid_result_before_collection
                )
            )
            or request.role is not ModelRole.AUDITOR
            or request.mode is not ModelPurpose.CANDIDATE_INVESTIGATION
            or request.tenant_id != flow.graph.tenant_id
            or request.head_sha != flow.graph.head_sha
            or request.run_id != host.run_id
            or request.execution_identity != host.execution_identity
            or package.tenant_id != request.tenant_id
            or package.head_sha != request.head_sha
            or package.model_evidence != request.evidence
        ):
            raise ValueError
        values[key] = observation
    if set(values) != set(expected):
        raise ValueError
    return values


def _validate_observed_package(flow: ProductCandidateFlow, package: EvidencePackage) -> None:
    """Bind observed context to exact graph records without retaining content."""
    package.__post_init__()
    candidate = next(
        (item for item in flow.graph.candidates if item.candidate_id == package.candidate_id), None
    )
    if (
        candidate is None
        or package.candidate_version != candidate.candidate_version
        or package.tenant_id != flow.graph.tenant_id
        or package.head_sha != flow.graph.head_sha
        or package.graph_id != flow.graph.graph_id
        or package.graph_sha256 != flow.graph.graph_sha256
        or {*package.omitted_evidence_ids, *(item.evidence_id for item in package.selected)}
        != set(candidate.evidence_ids)
    ):
        raise ValueError
    records = {item.evidence_id: item for item in flow.graph.evidence}
    for selected in package.selected:
        record = records.get(selected.evidence_id)
        if record is None or record.artifact_ref is None:
            raise ValueError
        artifact = record.artifact_ref
        expected = EvidenceContextRef(
            evidence_id=record.evidence_id,
            content_id=artifact.content_id,
            data_class=record.data_class,
            evidence_sha256=record.evidence_sha256,
            producer_id=record.producer.producer_id,
            producer_version=record.producer.producer_version,
            producer_sha256=record.producer.producer_sha256,
            context_bytes=artifact.size_bytes,
            estimated_tokens=max(1, (artifact.size_bytes + 3) // 4),
        )
        if (
            selected != expected
            or artifact.tenant_id != candidate.tenant_id
            or artifact.data_class is not record.data_class
        ):
            raise ValueError
