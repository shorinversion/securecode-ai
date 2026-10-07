"""Two-phase model and egress authorization issuance."""

from __future__ import annotations

import secrets
from typing import Any, Final
from urllib.parse import urlsplit

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    AuditRunOutcome,
    DataClass,
    EgressManifest,
    EgressPolicyDocument,
    EgressRuleEffect,
    ExecutionBoundary,
    ModelPreflightRequest,
    ModelPreflightResult,
    PreflightEligibility,
    PreflightNextAction,
    ProviderEvidenceStatus,
    ProviderKind,
    ProviderProfile,
    ProviderTrainingUse,
)

from .core_model_authorizations import PreContextAuthorization, PreSendAuthorization
from .core_model_protocols import (
    _CLASS_RANK,
    _PERMIT_SENTINEL,
    _REPOSITORY_TOOLS,
    ApprovedProviderRegistry,
    AuthorizationError,
    EgressPolicyRegistry,
    _canonical_hash,
    _component_pin,
)

# A trial run against an operator-named OpenAI-compatible endpoint (D-118).
OPERATOR_PROFILE_ID: Final = "openai-compatible-operator"
OPERATOR_CONSENT_PREFIX: Final = "consent://operator/openai-compatible/"


def _https_at(base_url: str, authority: str) -> bool:
    try:
        parsed = urlsplit(base_url)
        return parsed.scheme == "https" and parsed.hostname == authority
    except ValueError:
        return False


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
            if any(
                _CLASS_RANK[data_class] >= _CLASS_RANK[request.required_data_class]
                for data_class in rule.data_classes
            )
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
        owner_authorized_terms = (
            policy.profile.value == "managed_scan_opt_in"
            and profile.profile_id == "deepseek-owner-authorized"
            and profile.provider_kind is ProviderKind.OPENAI_COMPATIBLE_REMOTE
            and profile.execution_boundary is ExecutionBoundary.PUBLIC_EXTERNAL
            and profile.endpoint.authority == "api.deepseek.com"
            and profile.endpoint.base_url
            in {"https://api.deepseek.com", "https://api.deepseek.com/v1"}
            and terms.evidence_status is ProviderEvidenceStatus.UNVERIFIED
            and terms.training_use is ProviderTrainingUse.UNKNOWN
            and terms.retention_seconds is None
            and terms.zero_data_retention is None
            and terms.evidence_ref == "consent://project-owner/deepseek-private-source/2026-09-27"
            and bool(matching_allow)
            and all(rule.tenant_admin_approval for rule in matching_allow)
        )
        # The operator of a trial run names an OpenAI-compatible endpoint and supplies its
        # key (D-118). Their explicit choice is the consent; the terms stay unverified and
        # the egress policy, masking and data-class limits apply as to DeepSeek.
        operator_authorized_terms = (
            policy.profile.value == "managed_scan_opt_in"
            and profile.profile_id == OPERATOR_PROFILE_ID
            and profile.provider_kind is ProviderKind.OPENAI_COMPATIBLE_REMOTE
            and profile.execution_boundary is ExecutionBoundary.PUBLIC_EXTERNAL
            and _https_at(profile.endpoint.base_url, profile.endpoint.authority)
            and terms.evidence_status is ProviderEvidenceStatus.UNVERIFIED
            and terms.training_use is ProviderTrainingUse.UNKNOWN
            and terms.retention_seconds is None
            and terms.zero_data_retention is None
            and terms.evidence_ref == OPERATOR_CONSENT_PREFIX + profile.endpoint.authority
            and bool(matching_allow)
            and all(rule.tenant_admin_approval for rule in matching_allow)
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
                local_terms
                or verified_terms
                or owner_authorized_terms
                or operator_authorized_terms,
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
