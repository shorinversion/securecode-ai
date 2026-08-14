"""Framework-independent model and egress policy boundary behavior."""

from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Final, Protocol, SupportsIndex

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AuditRunOutcome,
    ComponentPin,
    DataClass,
    EgressManifest,
    EgressPolicyDocument,
    EgressRuleEffect,
    ExecutionBoundary,
    ModelCallResult,
    ModelPreflightRequest,
    ModelPreflightResult,
    ModelRequest,
    PreflightEligibility,
    PreflightNextAction,
    ProviderEvidenceStatus,
    ProviderKind,
    ProviderProfile,
    ProviderTrainingUse,
    RepositoryTool,
)

_CLASS_RANK: Final = {
    DataClass.PUBLIC: 0,
    DataClass.INTERNAL_METADATA: 1,
    DataClass.CONFIDENTIAL_SECURITY: 2,
    DataClass.CONFIDENTIAL_SOURCE: 3,
    DataClass.RESTRICTED: 4,
}
_REPOSITORY_TOOLS: Final = frozenset(RepositoryTool)
_PERMIT_SENTINEL: Final = object()


class ApprovedProviderRegistry(Protocol):
    def require_registered(self, supplied: ProviderProfile) -> ProviderProfile: ...


@dataclass(frozen=True, slots=True)
class PayloadValidation:
    accepted: bool
    error_code: str | None
    content_id: str | None
    data_class: DataClass | None
    validator: ComponentPin


class StructuredPayloadValidator(Protocol):
    @property
    def validator(self) -> ComponentPin: ...

    def validate(self, payload: object, *, request: ModelRequest) -> PayloadValidation: ...


class EphemeralModelPayload(Protocol):
    def reveal_for(self, request_id: str) -> object: ...

    def close(self) -> None: ...


class ModelProviderResult(Protocol):
    @property
    def result(self) -> ModelCallResult: ...

    @property
    def payload(self) -> EphemeralModelPayload | None: ...


class ModelProvider(Protocol):
    """One provider attempt; retries and workflow routing remain external."""

    def invoke(
        self,
        *,
        request: ModelRequest,
        authorization: PreSendAuthorization,
        model_issuer: ModelAuthorizationIssuer,
        validator: StructuredPayloadValidator,
    ) -> ModelProviderResult: ...


class EgressPolicyEvaluator(Protocol):
    def authorize_pre_context(
        self,
        preflight: ModelPreflightRequest,
        *,
        profile: ProviderProfile,
        policy: EgressPolicyDocument,
    ) -> PreContextAuthorization: ...

    def authorize_pre_send(
        self,
        pre_context: PreContextAuthorization,
        manifest: EgressManifest,
    ) -> PreSendAuthorization: ...


class AuthorizationError(ValueError):
    """Safe authorization failure with a bounded code and no untrusted data."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class EgressPolicyRegistry:
    """Immutable policy registry backed by canonical bytes, never live model objects."""

    __slots__ = ("_hashes", "_policies")

    _IMMUTABLE_FIELDS: Final = frozenset({"_hashes", "_policies"})

    def __setattr__(self, name: str, value: object) -> None:
        if name in self._IMMUTABLE_FIELDS and hasattr(self, name):
            raise AttributeError("egress policy registry storage is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, policies: Iterable[EgressPolicyDocument]) -> None:
        encoded: dict[str, bytes] = {}
        hashes: dict[str, str] = {}
        for supplied in policies:
            try:
                policy = EgressPolicyDocument.model_validate_json(supplied.canonical_bytes())
            except (AttributeError, TypeError, ValueError):
                raise AuthorizationError("INVALID_EGRESS_POLICY") from None
            selector = policy.selector
            content_hash = policy.canonical_content_hash()
            if selector in hashes and hashes[selector] != content_hash:
                raise AuthorizationError("IMMUTABLE_EGRESS_POLICY_CONFLICT")
            encoded[selector] = policy.canonical_bytes()
            hashes[selector] = content_hash
        self._policies = MappingProxyType(encoded)
        self._hashes = MappingProxyType(hashes)

    def select(self, selector: str) -> EgressPolicyDocument:
        try:
            encoded = self._policies[selector]
            expected_hash = self._hashes[selector]
        except (KeyError, TypeError):
            raise AuthorizationError("UNKNOWN_EGRESS_POLICY") from None
        try:
            policy = EgressPolicyDocument.model_validate_json(encoded)
        except ValueError:
            raise AuthorizationError("EGRESS_POLICY_INTEGRITY_FAILURE") from None
        if policy.canonical_content_hash() != expected_hash:
            raise AuthorizationError("EGRESS_POLICY_INTEGRITY_FAILURE")
        return policy

    def require_registered(self, supplied: EgressPolicyDocument) -> EgressPolicyDocument:
        try:
            candidate = EgressPolicyDocument.model_validate_json(supplied.canonical_bytes())
            approved = self.select(candidate.selector)
        except (AttributeError, TypeError, ValueError):
            raise AuthorizationError("INVALID_EGRESS_POLICY") from None
        if candidate.canonical_content_hash() != approved.canonical_content_hash():
            raise AuthorizationError("IMMUTABLE_EGRESS_POLICY_CONFLICT")
        return approved


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def canonical_model_request_hash(request: ModelRequest) -> str:
    """Return the stable full semantic identity of a revalidated model request."""

    validated = ModelRequest.model_validate_json(request.model_dump_json())
    return _canonical_hash(validated.model_dump(mode="json"))


def _component_pin(identifier: str, version: str, content_hash: str) -> ComponentPin:
    return ComponentPin(
        schema_version=CONTRACT_SCHEMA_VERSION,
        component_id=identifier,
        component_version=version,
        content_sha256=content_hash,
    )


class PreContextAuthorization:
    """Issuer-owned result; only an eligible live instance can authorize send."""

    __slots__ = (
        "_destination",
        "_execution_identity_hash",
        "_issuer_id",
        "_max_bytes",
        "_nonce",
        "_planned_transforms",
        "_policy_hash",
        "_profile_hash",
        "_request_hash",
        "_request_scope",
        "_required_data_class",
        "_result",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("authorization objects are immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        sentinel: object,
        result: ModelPreflightResult,
        issuer_id: str,
        nonce: str | None,
        request_hash: str,
        request_scope: tuple[str, str, str, str, int] | None,
        profile_hash: str,
        policy_hash: str,
        destination: str,
        execution_identity_hash: str,
        required_data_class: DataClass,
        planned_transforms: tuple[str, ...],
        max_bytes: int,
    ) -> None:
        if sentinel is not _PERMIT_SENTINEL:
            raise TypeError("authorization objects are issuer-owned")
        self._result = result
        self._issuer_id = issuer_id
        self._nonce = nonce
        self._request_hash = request_hash
        self._request_scope = request_scope
        self._profile_hash = profile_hash
        self._policy_hash = policy_hash
        self._destination = destination
        self._execution_identity_hash = execution_identity_hash
        self._required_data_class = required_data_class
        self._planned_transforms = planned_transforms
        self._max_bytes = max_bytes

    @property
    def result(self) -> ModelPreflightResult:
        return self._result

    def __repr__(self) -> str:
        return f"PreContextAuthorization({self.result.eligibility.value})"

    def __copy__(self) -> PreContextAuthorization:
        raise TypeError("authorizations cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> PreContextAuthorization:
        del memo
        raise TypeError("authorizations cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("authorizations cannot be serialized")


class PreSendAuthorization:
    """Issuer-owned, single-use proof binding one exact metadata-only manifest."""

    __slots__ = (
        "_attempt",
        "_issuer_id",
        "_manifest_hash",
        "_nonce",
        "_policy_hash",
        "_profile_hash",
        "_request_hash",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if name in self.__slots__ and hasattr(self, name):
            raise AttributeError("authorization objects are immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        sentinel: object,
        issuer_id: str,
        nonce: str,
        request_hash: str,
        profile_hash: str,
        policy_hash: str,
        manifest_hash: str,
        attempt: int,
    ) -> None:
        if sentinel is not _PERMIT_SENTINEL:
            raise TypeError("authorization objects are issuer-owned")
        self._issuer_id = issuer_id
        self._nonce = nonce
        self._request_hash = request_hash
        self._profile_hash = profile_hash
        self._policy_hash = policy_hash
        self._manifest_hash = manifest_hash
        self._attempt = attempt

    @property
    def manifest_hash(self) -> str:
        return self._manifest_hash

    def __repr__(self) -> str:
        return "PreSendAuthorization(<opaque>)"

    def __copy__(self) -> PreSendAuthorization:
        raise TypeError("authorizations cannot be copied")

    def __deepcopy__(self, memo: dict[int, object]) -> PreSendAuthorization:
        del memo
        raise TypeError("authorizations cannot be copied")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("authorizations cannot be serialized")


class ModelAuthorizationIssuer:
    """Trusted two-phase provider/egress evaluator and authorization issuer."""

    __slots__ = (
        "_active_pre_context",
        "_active_pre_send",
        "_consumed_pre_context",
        "_consumed_pre_send",
        "_issuer_id",
        "_policy_registry",
        "_provider_registry",
    )

    def __init__(
        self,
        *,
        provider_registry: ApprovedProviderRegistry,
        policy_registry: EgressPolicyRegistry,
    ) -> None:
        self._provider_registry = provider_registry
        self._policy_registry = policy_registry
        self._issuer_id = secrets.token_hex(16)
        self._active_pre_context: dict[str, PreContextAuthorization] = {}
        self._consumed_pre_context: set[str] = set()
        self._active_pre_send: dict[str, PreSendAuthorization] = {}
        self._consumed_pre_send: set[str] = set()

    def _result(self, *, eligible: bool, reason: str | None = None) -> ModelPreflightResult:
        if eligible:
            return ModelPreflightResult(
                schema_version=CONTRACT_SCHEMA_VERSION,
                eligibility=PreflightEligibility.ELIGIBLE,
                preflight_context_bytes=0,
                preflight_network_bytes=0,
                next_action=PreflightNextAction.CONTINUE_DUAL_LANE,
                deterministic_only_fallback=False,
            )
        return ModelPreflightResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            eligibility=PreflightEligibility.INELIGIBLE,
            preflight_context_bytes=0,
            preflight_network_bytes=0,
            next_action=PreflightNextAction.STOP_BEFORE_CONTEXT_OR_NETWORK,
            deterministic_only_fallback=False,
            required_terminal_outcome=AuditRunOutcome.INDETERMINATE,
            reason_codes=(reason or "PREFLIGHT_INELIGIBLE",),
        )

    def authorize_pre_context(
        self,
        preflight: ModelPreflightRequest,
        *,
        profile: ProviderProfile,
        policy: EgressPolicyDocument,
    ) -> PreContextAuthorization:
        try:
            request = ModelPreflightRequest.model_validate_json(preflight.model_dump_json())
            approved_profile = self._provider_registry.require_registered(profile)
            approved_policy = self._policy_registry.require_registered(policy)
            eligible, max_rule_bytes = self._evaluate(request, approved_profile, approved_policy)
            reason = None if eligible else "PREFLIGHT_INELIGIBLE"
        except Exception:  # all evaluator failures are denial, never permission
            try:
                request = ModelPreflightRequest.model_validate_json(preflight.model_dump_json())
                request_hash = _canonical_hash(request.model_request.model_dump(mode="json"))
            except Exception:
                request_hash = "0" * 64
            result = self._result(eligible=False, reason="PREFLIGHT_EVALUATOR_ERROR")
            return PreContextAuthorization(
                sentinel=_PERMIT_SENTINEL,
                result=result,
                issuer_id=self._issuer_id,
                nonce=None,
                request_hash=request_hash,
                request_scope=None,
                profile_hash="0" * 64,
                policy_hash="0" * 64,
                destination="profile://ineligible",
                execution_identity_hash="0" * 64,
                required_data_class=DataClass.PUBLIC,
                planned_transforms=(),
                max_bytes=0,
            )

        result = self._result(eligible=eligible, reason=reason)
        nonce = secrets.token_hex(24) if eligible else None
        authorization = PreContextAuthorization(
            sentinel=_PERMIT_SENTINEL,
            result=result,
            issuer_id=self._issuer_id,
            nonce=nonce,
            request_hash=_canonical_hash(request.model_request.model_dump(mode="json")),
            request_scope=(
                request.model_request.request_id,
                request.model_request.run_id,
                request.model_request.tenant_id,
                request.model_request.idempotency_key,
                request.model_request.attempt,
            ),
            profile_hash=approved_profile.canonical_content_hash(),
            policy_hash=approved_policy.canonical_content_hash(),
            destination=f"profile://{approved_profile.profile_id}",
            execution_identity_hash=request.model_request.execution_identity.execution_identity_hash,
            required_data_class=request.required_data_class,
            planned_transforms=request.planned_transforms,
            max_bytes=min(request.required_max_bytes, max_rule_bytes),
        )
        if nonce is not None:
            self._active_pre_context[nonce] = authorization
        return authorization

    @staticmethod
    def _evaluate(
        request: ModelPreflightRequest,
        profile: ProviderProfile,
        policy: EgressPolicyDocument,
    ) -> tuple[bool, int]:
        model_request = request.model_request
        provider_pin = _component_pin(
            profile.profile_id, profile.profile_version, profile.canonical_content_hash()
        )
        policy_pin = _component_pin(
            policy.policy_id, policy.policy_version, policy.canonical_content_hash()
        )
        egress_pin = _component_pin(
            policy.profile.value, policy.policy_version, policy.canonical_content_hash()
        )
        destination = f"profile://{profile.profile_id}"
        matching = tuple(
            rule
            for rule in policy.rules
            if request.required_data_class in rule.data_classes
            and request.required_purpose.value in rule.purposes
            and destination in rule.destinations
        )
        matching_deny = any(rule.effect is EgressRuleEffect.DENY for rule in matching)
        matching_allow = tuple(
            rule
            for rule in matching
            if rule.effect is EgressRuleEffect.ALLOW
            and rule.max_bytes is not None
            and rule.max_bytes >= request.required_max_bytes
            and rule.requires_transforms == request.planned_transforms
        )
        capabilities = profile.capabilities
        budgets = profile.budgets
        terms = profile.data_terms
        local_terms = (
            terms.evidence_status is ProviderEvidenceStatus.NOT_APPLICABLE_LOCAL
            and profile.execution_boundary is ExecutionBoundary.LOCAL_RUNNER
            and profile.provider_kind in {ProviderKind.FAKE, ProviderKind.OPENAI_COMPATIBLE_LOCAL}
            and terms.training_use is ProviderTrainingUse.NOT_APPLICABLE_LOCAL
        )
        verified_terms = (
            terms.evidence_status is ProviderEvidenceStatus.VERIFIED
            and bool(terms.residency)
            and terms.retention_seconds is not None
            and terms.training_use is ProviderTrainingUse.NONE_VERIFIED
            and terms.zero_data_retention is not None
            and terms.evidence_ref is not None
            and (
                policy.profile.value != "private_model_zdr"
                or (terms.retention_seconds == 0 and terms.zero_data_retention is True)
            )
        )
        eligible = all(
            (
                model_request.provider_profile == provider_pin,
                model_request.execution_identity.policy == policy_pin,
                model_request.execution_identity.egress_profile == egress_pin,
                model_request.model_id == profile.model_id,
                model_request.api_dialect is profile.api_dialect,
                model_request.attempt <= budgets.max_attempts,
                model_request.budget.max_input_tokens <= capabilities.max_context_tokens,
                model_request.budget.max_output_tokens <= capabilities.max_output_tokens,
                model_request.budget.max_input_tokens + model_request.budget.max_output_tokens
                <= budgets.max_total_tokens,
                model_request.budget.timeout_ms <= budgets.timeout_seconds * 1000,
                capabilities.structured_output,
                capabilities.native_refusal_signal,
                capabilities.native_incomplete_signal,
                capabilities.tool_calling,
                capabilities.source_code_analysis,
                capabilities.repository_tool_calls,
                frozenset(capabilities.repository_tools) == _REPOSITORY_TOOLS,
                _CLASS_RANK[terms.maximum_input_data_class]
                >= _CLASS_RANK[request.required_data_class],
                request.required_purpose in terms.allowed_purposes,
                local_terms or verified_terms,
                profile.execution_boundary is request.required_execution_boundary,
                policy.profile in profile.egress_profiles,
                policy.tenant_scope == model_request.tenant_id,
                request.required_data_class is not DataClass.RESTRICTED,
                not matching_deny,
                bool(matching_allow),
            )
        )
        max_bytes = max((int(rule.max_bytes or 0) for rule in matching_allow), default=0)
        if not eligible:
            max_bytes = 0
        return eligible, int(max_bytes or 0)

    def authorize_pre_send(
        self,
        pre_context: PreContextAuthorization,
        manifest: EgressManifest,
    ) -> PreSendAuthorization:
        nonce = getattr(pre_context, "_nonce", None)
        if (
            not isinstance(nonce, str)
            or getattr(pre_context, "_issuer_id", None) != self._issuer_id
            or nonce in self._consumed_pre_context
            or self._active_pre_context.get(nonce) is not pre_context
            or pre_context.result.eligibility is not PreflightEligibility.ELIGIBLE
        ):
            raise AuthorizationError("INVALID_PRE_CONTEXT_AUTHORIZATION")
        self._active_pre_context.pop(nonce)
        self._consumed_pre_context.add(nonce)
        try:
            actual = EgressManifest.model_validate_json(manifest.model_dump_json())
        except ValueError:
            raise AuthorizationError("INVALID_EGRESS_MANIFEST") from None
        if (
            actual.manifest_sha256 != _canonical_hash(actual._material())
            or actual.destination != pre_context._destination
            or actual.provider_profile.content_sha256 != pre_context._profile_hash
            or actual.policy.content_sha256 != pre_context._policy_hash
            or actual.execution_identity_hash != pre_context._execution_identity_hash
            or actual.applied_transforms != pre_context._planned_transforms
            or actual.byte_count > pre_context._max_bytes
            or any(
                item.data_class is not pre_context._required_data_class for item in actual.content
            )
        ):
            raise AuthorizationError("EGRESS_MANIFEST_SCOPE_MISMATCH")
        manifest_scope = (
            actual.request_id,
            actual.run_id,
            actual.tenant_id,
            actual.idempotency_key,
            actual.attempt,
        )
        if not pre_context._request_hash or manifest_scope != pre_context._request_scope:
            raise AuthorizationError("EGRESS_MANIFEST_SCOPE_MISMATCH")
        send_nonce = secrets.token_hex(24)
        authorization = PreSendAuthorization(
            sentinel=_PERMIT_SENTINEL,
            issuer_id=self._issuer_id,
            nonce=send_nonce,
            request_hash=pre_context._request_hash,
            profile_hash=pre_context._profile_hash,
            policy_hash=pre_context._policy_hash,
            manifest_hash=actual.manifest_sha256,
            attempt=actual.attempt,
        )
        self._active_pre_send[send_nonce] = authorization
        return authorization

    def consume_pre_send(self, authorization: PreSendAuthorization) -> dict[str, Any]:
        """Consume an exact permit once and return only its safe endpoint binding metadata."""

        nonce = getattr(authorization, "_nonce", None)
        if (
            not isinstance(nonce, str)
            or getattr(authorization, "_issuer_id", None) != self._issuer_id
            or nonce in self._consumed_pre_send
            or self._active_pre_send.get(nonce) is not authorization
        ):
            raise AuthorizationError("INVALID_PRE_SEND_AUTHORIZATION")
        self._active_pre_send.pop(nonce)
        self._consumed_pre_send.add(nonce)
        return {
            "request_hash": authorization._request_hash,
            "profile_hash": authorization._profile_hash,
            "policy_hash": authorization._policy_hash,
            "manifest_hash": authorization._manifest_hash,
            "attempt": authorization._attempt,
        }


__all__ = [
    "ApprovedProviderRegistry",
    "AuthorizationError",
    "EgressPolicyEvaluator",
    "EgressPolicyRegistry",
    "EphemeralModelPayload",
    "ModelAuthorizationIssuer",
    "ModelProvider",
    "ModelProviderResult",
    "PayloadValidation",
    "PreContextAuthorization",
    "PreSendAuthorization",
    "StructuredPayloadValidator",
    "canonical_model_request_hash",
]
