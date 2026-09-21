"""Provider-neutral, durable-safe model boundary contracts."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import Field, StrictBool, field_validator, model_validator

from .base import ClosedModel, DataClass, OpaqueId, ReasonCode, SemVer, WireModel
from .config import ApiDialect, EgressProfileId, ExecutionBoundary, ModelPurpose
from .domain import (
    AuditRunOutcome,
    ComponentPin,
    ModelCallStatus,
    RunExecutionIdentity,
)
from .domain_primitives import _canonical_sha256

SafeModelId = Annotated[
    str,
    Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$"),
]
PositiveInt = Annotated[int, Field(strict=True, ge=1, le=9_007_199_254_740_991)]
NonNegativeInt = Annotated[int, Field(strict=True, ge=0, le=9_007_199_254_740_991)]
CommitSha = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
KeyedContentId = Annotated[
    str,
    Field(min_length=5, max_length=128, pattern=r"^kid:[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$"),
]
SafePolicyString = Annotated[
    str,
    Field(min_length=1, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$"),
]
TransformId = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]{0,63}$"),
]


class ModelRole(StrEnum):
    DISCOVERY = "discovery"
    AUDITOR = "auditor"
    SKEPTIC = "skeptic"
    ARCHITECT = "architect"
    EVALUATOR = "evaluator"


class ModelSchemaStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    NOT_VALIDATED = "NOT_VALIDATED"


class EvidenceInputRef(WireModel):
    """Metadata-only model input reference; never embeds evidence content."""

    evidence_id: OpaqueId
    content_id: OpaqueId
    data_class: DataClass

    @field_validator("data_class")
    @classmethod
    def _forbid_restricted(cls, value: DataClass) -> DataClass:
        if value is DataClass.RESTRICTED:
            raise ValueError("restricted evidence cannot cross the model boundary")
        return value


class ModelCallBudget(WireModel):
    max_input_tokens: PositiveInt
    max_output_tokens: PositiveInt
    max_repository_calls: PositiveInt
    max_context_bytes: PositiveInt
    timeout_ms: PositiveInt

    @model_validator(mode="after")
    def _validate_token_shape(self) -> Self:
        if self.max_output_tokens > self.max_input_tokens:
            raise ValueError("model output budget cannot exceed input budget")
        return self


class ModelRequest(WireModel):
    """Immutable public request identity; source and credentials stay out-of-band."""

    request_id: OpaqueId
    run_id: OpaqueId
    tenant_id: OpaqueId
    idempotency_key: OpaqueId
    attempt: PositiveInt
    execution_identity: RunExecutionIdentity
    head_sha: CommitSha
    role: ModelRole
    mode: ModelPurpose
    provider_profile: ComponentPin
    api_dialect: ApiDialect
    model_id: SafeModelId
    prompt: ComponentPin
    output_schema: ComponentPin
    tool_policy: ComponentPin
    repository_scope: ComponentPin
    repository_view_policy: ComponentPin
    evidence: tuple[EvidenceInputRef, ...] = Field(default=(), max_length=4096)
    budget: ModelCallBudget

    @field_validator("evidence")
    @classmethod
    def _canonicalize_evidence(
        cls, value: tuple[EvidenceInputRef, ...]
    ) -> tuple[EvidenceInputRef, ...]:
        ordered = tuple(sorted(value, key=lambda item: item.evidence_id))
        if len({item.evidence_id for item in ordered}) != len(ordered):
            raise ValueError("model evidence identifiers must be unique")
        return ordered

    @model_validator(mode="after")
    def _bind_execution_identity(self) -> Self:
        revision = self.execution_identity.repository_revision
        if self.tenant_id != revision.tenant_id or self.head_sha != revision.head_sha:
            raise ValueError("model request identity does not match the pinned repository revision")
        if self.provider_profile != self.execution_identity.provider_profile:
            raise ValueError("model request provider profile does not match execution identity")
        if self.mode is ModelPurpose.MODEL_NATIVE_DISCOVERY:
            if self.role is not ModelRole.DISCOVERY or self.evidence:
                raise ValueError("model-native discovery starts without scanner evidence")
        elif not self.evidence:
            raise ValueError("non-discovery model work requires evidence references")
        if any(item.data_class is DataClass.RESTRICTED for item in self.evidence):
            raise ValueError("restricted evidence cannot cross the model boundary")
        return self


class NativeOutcomeMetadata(WireModel):
    """Bounded provider-native signals translated into safe reason codes."""

    request_code: ReasonCode
    finish_code: ReasonCode
    refusal_code: ReasonCode | None = None
    filter_code: ReasonCode | None = None


class ModelSchemaResult(WireModel):
    status: ModelSchemaStatus
    error_code: ReasonCode | None = None
    validator: ComponentPin

    @model_validator(mode="after")
    def _validate_error_code(self) -> Self:
        if (self.status is ModelSchemaStatus.VALID) == (self.error_code is not None):
            raise ValueError("valid schema results have no error; other results require one")
        return self


class ModelUsage(WireModel):
    input_tokens: NonNegativeInt
    output_tokens: NonNegativeInt
    repository_calls: NonNegativeInt
    elapsed_ms: NonNegativeInt


class OpaqueContentProvenance(WireModel):
    """Classified opaque identifier; it is deliberately not a raw SHA digest."""

    content_id: KeyedContentId
    tenant_id: OpaqueId
    data_class: DataClass
    validator: ComponentPin

    @field_validator("data_class")
    @classmethod
    def _forbid_restricted(cls, value: DataClass) -> DataClass:
        if value is DataClass.RESTRICTED:
            raise ValueError("restricted content cannot cross the model result boundary")
        return value


class ModelCallResult(WireModel):
    """Durable-safe result metadata, separate from the ephemeral parsed payload."""

    request_id: OpaqueId
    run_id: OpaqueId
    tenant_id: OpaqueId
    idempotency_key: OpaqueId
    attempt: PositiveInt
    provider_profile: ComponentPin
    model_call_status: ModelCallStatus
    native: NativeOutcomeMetadata
    schema_result: ModelSchemaResult
    usage: ModelUsage
    retryable: StrictBool
    content_provenance: OpaqueContentProvenance | None = None
    safe_reason_code: ReasonCode | None = None

    @property
    def status(self) -> ModelCallStatus:
        """Typed convenience alias; the wire field remains model_call_status."""

        return self.model_call_status

    @model_validator(mode="after")
    def _validate_outcome_precedence(self) -> Self:
        if self.model_call_status is ModelCallStatus.SUCCEEDED:
            if (
                self.schema_result.status is not ModelSchemaStatus.VALID
                or self.content_provenance is None
                or self.native.finish_code != "COMPLETE"
                or self.native.refusal_code is not None
                or self.native.filter_code is not None
                or self.safe_reason_code is not None
                or self.retryable
            ):
                raise ValueError("model success requires complete schema-valid unblocked content")
            if self.content_provenance.tenant_id != self.tenant_id:
                raise ValueError("model content provenance must match the result tenant")
            if self.content_provenance.validator != self.schema_result.validator:
                raise ValueError("model content provenance must match the schema validator")
        elif (
            self.schema_result.status is ModelSchemaStatus.VALID
            or self.content_provenance is not None
            or self.safe_reason_code is None
        ):
            raise ValueError("model non-success cannot carry validated content")
        return self


class EgressRuleEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class EgressRule(ClosedModel):
    """Exact typed mirror of one accepted egress-policy rule."""

    rule_id: Annotated[str, Field(pattern=r"^EGR-[A-Z0-9_-]+$", max_length=128)]
    effect: EgressRuleEffect
    data_classes: tuple[DataClass, ...] = Field(max_length=5)
    destinations: tuple[SafePolicyString, ...] = Field(min_length=1, max_length=64)
    purposes: tuple[SafePolicyString, ...] = Field(min_length=1, max_length=16)
    requires_transforms: tuple[TransformId, ...] = Field(default=(), max_length=32)
    max_bytes: NonNegativeInt | None = None
    tenant_admin_approval: StrictBool = False

    @field_validator(
        "data_classes", "destinations", "purposes", "requires_transforms", mode="before"
    )
    @classmethod
    def _canonicalize_sets(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            return value
        if len(value) != len(set(value)):
            raise ValueError("egress rule set-like fields must be unique")
        return tuple(sorted(value, key=str))

    @model_validator(mode="after")
    def _forbid_restricted_allow(self) -> Self:
        if self.effect is EgressRuleEffect.ALLOW and DataClass.RESTRICTED in self.data_classes:
            raise ValueError("egress allow rules cannot authorize restricted data")
        return self


class EgressPolicyDocument(ClosedModel):
    """Canonical immutable mirror of egress-policy.schema.json 0.1.0."""

    schema_version: Annotated[str, Field(pattern=r"^0\.1\.0$")]
    policy_id: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$", max_length=64)]
    policy_version: SemVer
    tenant_scope: Annotated[
        str, Field(min_length=3, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
    ]
    profile: EgressProfileId
    rules: tuple[EgressRule, ...]
    default_effect: Literal["deny"]

    @field_validator("rules", mode="before")
    @classmethod
    def _canonicalize_rules(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            return value
        ordered = tuple(
            sorted(
                value,
                key=lambda item: (
                    item.get("rule_id", "") if isinstance(item, dict) else item.rule_id
                ),
            )
        )
        return ordered

    @model_validator(mode="after")
    def _validate_profile_semantics(self) -> Self:
        rule_ids = [rule.rule_id for rule in self.rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("egress rule identifiers must be unique")
        allow_rules = tuple(rule for rule in self.rules if rule.effect is EgressRuleEffect.ALLOW)
        if self.profile is EgressProfileId.AIR_GAP and allow_rules:
            raise ValueError("air-gap egress policy cannot contain allow rules")
        if self.profile in {
            EgressProfileId.NO_CODE_EGRESS,
            EgressProfileId.METADATA_EXTERNAL,
        } and any(
            DataClass.CONFIDENTIAL_SOURCE in rule.data_classes
            or DataClass.RESTRICTED in rule.data_classes
            for rule in allow_rules
        ):
            raise ValueError("selected egress profile cannot allow source or restricted data")
        return self

    @property
    def selector(self) -> str:
        return f"{self.policy_id}@{self.policy_version}"

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def canonical_content_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class PreflightEligibility(StrEnum):
    ELIGIBLE = "eligible"
    INELIGIBLE = "ineligible"


class PreflightNextAction(StrEnum):
    CONTINUE_DUAL_LANE = "CONTINUE_DUAL_LANE"
    STOP_BEFORE_CONTEXT_OR_NETWORK = "STOP_BEFORE_CONTEXT_OR_NETWORK"


class ModelPreflightRequest(WireModel):
    model_request: ModelRequest
    required_execution_boundary: ExecutionBoundary
    required_data_class: DataClass
    required_purpose: ModelPurpose
    planned_transforms: tuple[TransformId, ...] = Field(max_length=32)
    required_max_bytes: PositiveInt

    @field_validator("planned_transforms", mode="before")
    @classmethod
    def _canonicalize_transforms(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            return value
        if len(value) != len(set(value)):
            raise ValueError("planned egress transforms must be unique")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def _bind_model_request(self) -> Self:
        if self.model_request.mode is not self.required_purpose:
            raise ValueError("preflight purpose must match the model request mode")
        if self.required_data_class is DataClass.RESTRICTED:
            raise ValueError("restricted data cannot enter model preflight")
        if self.required_max_bytes > self.model_request.budget.max_context_bytes:
            raise ValueError("preflight bytes exceed the model request context budget")
        return self


class ModelPreflightResult(WireModel):
    eligibility: PreflightEligibility
    preflight_context_bytes: Literal[0]
    preflight_network_bytes: Literal[0]
    next_action: PreflightNextAction
    deterministic_only_fallback: Literal[False]
    required_terminal_outcome: AuditRunOutcome | None = None
    reason_codes: tuple[ReasonCode, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def _validate_route(self) -> Self:
        if self.eligibility is PreflightEligibility.ELIGIBLE:
            if (
                self.next_action is not PreflightNextAction.CONTINUE_DUAL_LANE
                or self.required_terminal_outcome is not None
                or self.reason_codes
            ):
                raise ValueError("eligible preflight must continue without a terminal outcome")
        elif (
            self.next_action is not PreflightNextAction.STOP_BEFORE_CONTEXT_OR_NETWORK
            or self.required_terminal_outcome is not AuditRunOutcome.INDETERMINATE
            or not self.reason_codes
        ):
            raise ValueError("ineligible preflight requires fail-closed indeterminate routing")
        return self

    def normative_snapshot(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "eligibility": self.eligibility.value,
            "preflight_context_bytes": self.preflight_context_bytes,
            "preflight_network_bytes": self.preflight_network_bytes,
            "next_action": self.next_action.value,
            "deterministic_only_fallback": self.deterministic_only_fallback,
        }
        if self.required_terminal_outcome is not None:
            result["audit_run_outcome"] = self.required_terminal_outcome.value
        return result


class EgressContentRef(WireModel):
    content_id: KeyedContentId
    data_class: DataClass

    @field_validator("data_class")
    @classmethod
    def _forbid_restricted(cls, value: DataClass) -> DataClass:
        if value is DataClass.RESTRICTED:
            raise ValueError("restricted content cannot be authorized for egress")
        return value


class EgressManifest(WireModel):
    request_id: OpaqueId
    run_id: OpaqueId
    tenant_id: OpaqueId
    idempotency_key: OpaqueId
    attempt: PositiveInt
    execution_identity_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    provider_profile: ComponentPin
    policy: ComponentPin
    destination: SafePolicyString
    payload_content_id: KeyedContentId
    content: tuple[EgressContentRef, ...] = Field(min_length=1, max_length=4096)
    applied_transforms: tuple[TransformId, ...] = Field(max_length=32)
    byte_count: NonNegativeInt
    manifest_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]

    @field_validator("content")
    @classmethod
    def _canonicalize_content(
        cls, value: tuple[EgressContentRef, ...]
    ) -> tuple[EgressContentRef, ...]:
        ordered = tuple(sorted(value, key=lambda item: item.content_id))
        if len({item.content_id for item in ordered}) != len(ordered):
            raise ValueError("egress content identifiers must be unique")
        return ordered

    @field_validator("applied_transforms", mode="before")
    @classmethod
    def _canonicalize_transforms(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)):
            return value
        if len(value) != len(set(value)):
            raise ValueError("applied egress transforms must be unique")
        return tuple(sorted(value))

    def _material(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"manifest_sha256"})

    @model_validator(mode="after")
    def _validate_manifest_hash(self) -> Self:
        if self.manifest_sha256 != _canonical_sha256(self._material()):
            raise ValueError("egress manifest hash does not match canonical metadata")
        if any(item.data_class is DataClass.RESTRICTED for item in self.content):
            raise ValueError("restricted content cannot be authorized for egress")
        return self

    @classmethod
    def build(
        cls,
        *,
        model_request: ModelRequest,
        policy: ComponentPin,
        destination: str,
        payload_content_id: str,
        content: tuple[EgressContentRef, ...],
        applied_transforms: tuple[str, ...],
        byte_count: int,
        schema_version: SemVer = "0.2.0",
    ) -> Self:
        canonical_content = tuple(sorted(content, key=lambda item: item.content_id))
        canonical_transforms = tuple(sorted(applied_transforms))
        material = {
            "schema_version": schema_version,
            "extensions": [],
            "request_id": model_request.request_id,
            "run_id": model_request.run_id,
            "tenant_id": model_request.tenant_id,
            "idempotency_key": model_request.idempotency_key,
            "attempt": model_request.attempt,
            "execution_identity_hash": model_request.execution_identity.execution_identity_hash,
            "provider_profile": model_request.provider_profile.model_dump(mode="json"),
            "policy": policy.model_dump(mode="json"),
            "destination": destination,
            "payload_content_id": payload_content_id,
            "content": [item.model_dump(mode="json") for item in canonical_content],
            "applied_transforms": list(canonical_transforms),
            "byte_count": byte_count,
        }
        return cls(
            schema_version=schema_version,
            request_id=model_request.request_id,
            run_id=model_request.run_id,
            tenant_id=model_request.tenant_id,
            idempotency_key=model_request.idempotency_key,
            attempt=model_request.attempt,
            execution_identity_hash=model_request.execution_identity.execution_identity_hash,
            provider_profile=model_request.provider_profile,
            policy=policy,
            destination=destination,
            payload_content_id=payload_content_id,
            content=canonical_content,
            applied_transforms=canonical_transforms,
            byte_count=byte_count,
            manifest_sha256=_canonical_sha256(material),
        )


__all__ = [
    "EgressContentRef",
    "EgressManifest",
    "EgressPolicyDocument",
    "EgressRule",
    "EgressRuleEffect",
    "EvidenceInputRef",
    "ModelCallBudget",
    "ModelCallResult",
    "ModelPreflightRequest",
    "ModelPreflightResult",
    "ModelRequest",
    "ModelRole",
    "ModelSchemaResult",
    "ModelSchemaStatus",
    "ModelUsage",
    "NativeOutcomeMetadata",
    "OpaqueContentProvenance",
    "PreflightEligibility",
    "PreflightNextAction",
]
