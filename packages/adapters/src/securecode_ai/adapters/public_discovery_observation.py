"""Source-free reconciliation for one actual native-discovery invocation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ModelCallResult,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ModelSchemaStatus,
    ModelUsage,
    PreflightEligibility,
)
from securecode_ai.core.model_discovery import (
    ModelNativeDiscoveryOutcome,
    ModelNativeDiscoveryPlan,
)
from securecode_ai.core.tool_policy import RepositoryToolBudget, RepositoryToolScope

from .product_model import DiscoverySchemaRefusalCategory
from .product_runtime import ProductDiscoveryInvocationObservation


class PublicDiscoveryObservationError(ValueError):
    """A source-free native-discovery observation cannot be reconciled."""


@dataclass(frozen=True, slots=True)
class PublicDiscoveryObservationEvidence:
    """Bounded metadata for one callback and its unchanged Core receipt."""

    request_sha256: str
    scope_sha256: str
    input_sha256: str
    repository_view_call_hashes: tuple[str, ...]
    before_collection_status: ModelCallStatus
    before_collection_schema_valid: bool
    schema_refusal_category: DiscoverySchemaRefusalCategory
    token_usage_known: bool
    elapsed_known: bool
    observed_input_tokens: int | None
    observed_output_tokens: int | None
    observed_repository_calls: int
    observed_elapsed_ms: int | None
    observed_budget_exhausted: bool
    final_model_call_status: ModelCallStatus
    final_schema_valid_result: bool
    final_tokens_used: int
    final_repository_calls: int
    final_elapsed_ms: int

    def __post_init__(self) -> None:
        hashes = (self.request_sha256, self.scope_sha256, self.input_sha256)
        if (
            any(not _sha256(value) for value in hashes)
            or type(self.repository_view_call_hashes) is not tuple
            or any(not _sha256(value) for value in self.repository_view_call_hashes)
            or type(self.before_collection_status) is not ModelCallStatus
            or type(self.before_collection_schema_valid) is not bool
            or type(self.schema_refusal_category) is not DiscoverySchemaRefusalCategory
            or type(self.token_usage_known) is not bool
            or type(self.elapsed_known) is not bool
            or (
                self.token_usage_known
                != (
                    self.observed_input_tokens is not None
                    and self.observed_output_tokens is not None
                )
            )
            or (self.elapsed_known != (self.observed_elapsed_ms is not None))
            or any(
                type(value) is not int or value < 0
                for value in (
                    self.observed_repository_calls,
                    self.final_tokens_used,
                    self.final_repository_calls,
                    self.final_elapsed_ms,
                )
            )
            or (
                self.observed_input_tokens is not None
                and (type(self.observed_input_tokens) is not int or self.observed_input_tokens < 0)
            )
            or (
                self.observed_output_tokens is not None
                and (
                    type(self.observed_output_tokens) is not int or self.observed_output_tokens < 0
                )
            )
            or (
                self.observed_elapsed_ms is not None
                and (type(self.observed_elapsed_ms) is not int or self.observed_elapsed_ms < 0)
            )
            or type(self.observed_budget_exhausted) is not bool
            or type(self.final_model_call_status) is not ModelCallStatus
            or type(self.final_schema_valid_result) is not bool
            or (
                self.schema_refusal_category is not DiscoverySchemaRefusalCategory.NOT_OBSERVED
                and (
                    self.before_collection_status is not ModelCallStatus.INVALID_SCHEMA
                    or self.before_collection_schema_valid
                )
            )
        ):
            raise PublicDiscoveryObservationError("invalid public discovery observation")


@dataclass(frozen=True, slots=True)
class _Capture:
    request: ModelRequest
    result: ModelCallResult
    usage: ModelUsage | None
    status: ModelCallStatus
    schema_valid: bool
    schema_refusal_category: DiscoverySchemaRefusalCategory
    call_hashes: tuple[str, ...]
    elapsed_known: bool
    token_usage_known: bool


class PublicDiscoveryObservationRecorder:
    """Bind one callback to a sealed plan, then reconcile its Core receipt.

    This recorder deliberately records the logical adapter result separately
    from Core's receipt. In particular, an observed over-limit duration remains
    visible even when the normative receipt rejects that usage and records its
    own invalid-schema outcome with zero elapsed time.
    """

    __slots__ = (
        "_capture",
        "_failed",
        "_finalized",
        "_plan",
        "_result",
        "_result_key",
    )

    def __init__(self, plan: ModelNativeDiscoveryPlan) -> None:
        try:
            self._plan = _snapshot_plan(plan)
        except (AttributeError, TypeError, ValueError):
            raise PublicDiscoveryObservationError("invalid public discovery plan") from None
        self._capture: _Capture | None = None
        self._failed = False
        self._finalized = False
        self._result: PublicDiscoveryObservationEvidence | None = None
        self._result_key: str | None = None

    def observe(self, observation: ProductDiscoveryInvocationObservation) -> None:
        """Store exactly one post-closure callback; invalid input permanently fails."""

        try:
            if self._failed or self._finalized or self._capture is not None:
                raise ValueError
            self._capture = self._snapshot_capture(observation)
        except (AttributeError, TypeError, ValueError):
            self._failed = True
            raise PublicDiscoveryObservationError("public discovery observation failed") from None

    def finalize(
        self, outcome: ModelNativeDiscoveryOutcome
    ) -> PublicDiscoveryObservationEvidence | None:
        """Reconcile the callback with the actual, already-created Core outcome."""

        try:
            if self._failed or type(outcome) is not ModelNativeDiscoveryOutcome:
                raise ValueError
            key = _outcome_key(outcome)
            if self._finalized:
                if self._result_key != key:
                    raise ValueError
                return self._result
            receipt = outcome.receipt
            plan = self._plan
            if (
                receipt.receipt_id != plan.receipt_id
                or receipt.tenant_id != plan.request.tenant_id
                or receipt.head_sha != plan.request.head_sha
                or receipt.scope_sha256 != plan.scope_sha256
                or receipt.input_sha256 != plan.input_sha256
                or receipt.model_profile != plan.request.provider_profile
                or receipt.prompt != plan.request.prompt
                or any(
                    candidate.tenant_id != plan.request.tenant_id
                    or candidate.head_sha != plan.request.head_sha
                    or not any(lineage.producer == plan.producer for lineage in candidate.lineage)
                    for candidate in outcome.candidates
                )
            ):
                raise ValueError
            capture = self._capture
            if capture is None:
                if plan.preflight_eligibility is not PreflightEligibility.INELIGIBLE:
                    raise ValueError
                self._finalized = True
                self._result_key = key
                return None
            if (
                receipt.repository_view_call_hashes != capture.call_hashes
                or capture.request != plan.request
                or not _result_matches_request(capture.result, plan.request)
                or capture.status is not capture.result.model_call_status
                or capture.schema_valid
                != (capture.result.schema_result.status is ModelSchemaStatus.VALID)
                or (capture.usage is not None and capture.usage != capture.result.usage)
            ):
                raise ValueError
            usage = capture.usage
            if receipt.model_call_status is ModelCallStatus.SUCCEEDED:
                if (
                    capture.status is not ModelCallStatus.SUCCEEDED
                    or not capture.schema_valid
                    or not receipt.schema_valid_result
                    or usage is None
                    or receipt.budget_usage.tokens_used != usage.input_tokens + usage.output_tokens
                    or receipt.budget_usage.repository_calls_used != usage.repository_calls
                    or receipt.budget_usage.elapsed_ms < usage.elapsed_ms
                ):
                    raise ValueError
            elif capture.status is not ModelCallStatus.SUCCEEDED and (
                receipt.model_call_status not in (capture.status, ModelCallStatus.INVALID_SCHEMA)
            ):
                raise ValueError
            observed_overrun = _observed_overrun(
                usage, plan.request, capture.elapsed_known, capture.token_usage_known
            )
            self._result = PublicDiscoveryObservationEvidence(
                request_sha256=_request_sha256(plan.request),
                scope_sha256=plan.scope_sha256,
                input_sha256=plan.input_sha256,
                repository_view_call_hashes=capture.call_hashes,
                before_collection_status=capture.status,
                before_collection_schema_valid=capture.schema_valid,
                schema_refusal_category=capture.schema_refusal_category,
                token_usage_known=capture.token_usage_known,
                elapsed_known=capture.elapsed_known,
                observed_input_tokens=(
                    usage.input_tokens if capture.token_usage_known and usage is not None else None
                ),
                observed_output_tokens=(
                    usage.output_tokens if capture.token_usage_known and usage is not None else None
                ),
                observed_repository_calls=(0 if usage is None else usage.repository_calls),
                observed_elapsed_ms=(
                    usage.elapsed_ms if capture.elapsed_known and usage is not None else None
                ),
                observed_budget_exhausted=observed_overrun,
                final_model_call_status=receipt.model_call_status,
                final_schema_valid_result=receipt.schema_valid_result,
                final_tokens_used=receipt.budget_usage.tokens_used,
                final_repository_calls=receipt.budget_usage.repository_calls_used,
                final_elapsed_ms=receipt.budget_usage.elapsed_ms,
            )
            self._finalized = True
            self._result_key = key
            return self._result
        except (AttributeError, TypeError, ValueError):
            self._failed = True
            raise PublicDiscoveryObservationError(
                "public discovery reconciliation failed"
            ) from None

    def _snapshot_capture(self, observation: ProductDiscoveryInvocationObservation) -> _Capture:
        if type(observation) is not ProductDiscoveryInvocationObservation:
            raise ValueError
        request = ModelRequest.model_validate_json(observation.request.model_dump_json())
        result = ModelCallResult.model_validate_json(
            observation.model_result_before_collection.model_dump_json()
        )
        usage = (
            None
            if observation.usage_before_collection is None
            else ModelUsage.model_validate_json(
                observation.usage_before_collection.model_dump_json()
            )
        )
        if (
            request != self._plan.request
            or request.role is not ModelRole.DISCOVERY
            or request.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY
            or not _result_matches_request(result, request)
            or observation.model_call_status_before_collection is not result.model_call_status
            or observation.schema_valid_result_before_collection
            is not (result.schema_result.status is ModelSchemaStatus.VALID)
            or type(observation.schema_refusal_category) is not DiscoverySchemaRefusalCategory
            or (
                observation.schema_refusal_category
                is not DiscoverySchemaRefusalCategory.NOT_OBSERVED
                and (
                    observation.model_call_status_before_collection
                    is not ModelCallStatus.INVALID_SCHEMA
                    or observation.schema_valid_result_before_collection
                )
            )
            or (usage is not None and usage != result.usage)
            or type(observation.repository_view_call_hashes) is not tuple
            or len(observation.repository_view_call_hashes) > request.budget.max_repository_calls
            or any(not _sha256(value) for value in observation.repository_view_call_hashes)
            or type(observation.elapsed_known) is not bool
            or type(observation.token_usage_known) is not bool
        ):
            raise ValueError
        return _Capture(
            request=request,
            result=result,
            usage=usage,
            status=observation.model_call_status_before_collection,
            schema_valid=observation.schema_valid_result_before_collection,
            schema_refusal_category=observation.schema_refusal_category,
            call_hashes=tuple(observation.repository_view_call_hashes),
            elapsed_known=observation.elapsed_known,
            token_usage_known=observation.token_usage_known,
        )


def source_free_discovery_observation_document(
    evidence: PublicDiscoveryObservationEvidence,
) -> dict[str, object]:
    """Return the fixed serialization whitelist, excluding request/context/source fields."""

    if type(evidence) is not PublicDiscoveryObservationEvidence:
        raise PublicDiscoveryObservationError("invalid public discovery observation")
    return {
        "schema_version": CONTRACT_SCHEMA_VERSION,
        "request_sha256": evidence.request_sha256,
        "scope_sha256": evidence.scope_sha256,
        "input_sha256": evidence.input_sha256,
        "repository_view_call_hashes": list(evidence.repository_view_call_hashes),
        "before_collection": {
            "model_call_status": evidence.before_collection_status.value,
            "schema_valid_result": evidence.before_collection_schema_valid,
            "schema_refusal_category": evidence.schema_refusal_category.value,
            "token_usage_known": evidence.token_usage_known,
            "elapsed_known": evidence.elapsed_known,
            "input_tokens": evidence.observed_input_tokens,
            "output_tokens": evidence.observed_output_tokens,
            "repository_calls": evidence.observed_repository_calls,
            "elapsed_ms": evidence.observed_elapsed_ms,
            "budget_exhausted": evidence.observed_budget_exhausted,
        },
        "final_core_receipt": {
            "model_call_status": evidence.final_model_call_status.value,
            "schema_valid_result": evidence.final_schema_valid_result,
            "tokens_used": evidence.final_tokens_used,
            "repository_calls_used": evidence.final_repository_calls,
            "elapsed_ms": evidence.final_elapsed_ms,
        },
    }


def _snapshot_plan(plan: ModelNativeDiscoveryPlan) -> ModelNativeDiscoveryPlan:
    if type(plan) is not ModelNativeDiscoveryPlan:
        raise ValueError
    request = ModelRequest.model_validate_json(plan.request.model_dump_json())
    scope = RepositoryToolScope(
        plan.scope.tenant_id,
        plan.scope.repository_id,
        plan.scope.head_sha,
        tuple(plan.scope.path_prefixes),
        tuple(plan.scope.evidence_ids),
    )
    budget = RepositoryToolBudget(
        plan.tool_budget.max_calls, plan.tool_budget.max_bytes, plan.tool_budget.max_tokens
    )
    producer = type(plan.producer).model_validate(plan.producer.model_dump(mode="python"))
    return ModelNativeDiscoveryPlan(
        receipt_id=plan.receipt_id,
        request=request,
        preflight_eligibility=plan.preflight_eligibility,
        scope=scope,
        tool_budget=budget,
        producer=producer,
    )


def _result_matches_request(result: ModelCallResult, request: ModelRequest) -> bool:
    return (
        result.request_id == request.request_id
        and result.run_id == request.run_id
        and result.tenant_id == request.tenant_id
        and result.idempotency_key == request.idempotency_key
        and result.attempt == request.attempt
        and result.provider_profile == request.provider_profile
    )


def _observed_overrun(
    usage: ModelUsage | None,
    request: ModelRequest,
    elapsed_known: bool,
    token_usage_known: bool,
) -> bool:
    if usage is None:
        return False
    return (
        (token_usage_known and usage.input_tokens > request.budget.max_input_tokens)
        or (token_usage_known and usage.output_tokens > request.budget.max_output_tokens)
        or usage.repository_calls > request.budget.max_repository_calls
        or (elapsed_known and usage.elapsed_ms > request.budget.timeout_ms)
    )


def _request_sha256(request: ModelRequest) -> str:
    return hashlib.sha256(
        json.dumps(
            request.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _outcome_key(outcome: ModelNativeDiscoveryOutcome) -> str:
    return hashlib.sha256(
        json.dumps(
            {
                "receipt": outcome.receipt.model_dump(mode="json"),
                "candidates": [item.model_dump(mode="json") for item in outcome.candidates],
                "required_terminal_outcome": (
                    None
                    if outcome.required_terminal_outcome is None
                    else outcome.required_terminal_outcome.value
                ),
            },
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


__all__ = [
    "PublicDiscoveryObservationError",
    "PublicDiscoveryObservationEvidence",
    "PublicDiscoveryObservationRecorder",
    "source_free_discovery_observation_document",
]
