"""Hermetic provider adapter, native-dialect normalization and ephemeral payloads."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    ApiDialect,
    AuditRunOutcome,
    EgressManifest,
    EgressPolicyDocument,
    ModelAuthorizationIssuer,
    ModelCallStatus,
    ModelPreflightRequest,
    ModelPreflightResult,
    ModelRequest,
    ModelUsage,
    PreflightEligibility,
    PreflightNextAction,
    ProviderKind,
    ProviderProfile,
    StructuredPayloadValidator,
    canonical_model_request_hash,
)

from .config import CredentialLease
from .endpoint import EndpointAuthorizationIssuer, Resolver
from .model_normalization import normalize_provider_attempt
from .model_parsing import _non_success, _nonnegative_int, _parse_json, _transport_status
from .model_types import (
    _MAX_WIRE_INT,
    _NATIVE_RESPONSE_ID,
    ModelBoundaryExecution,
    NativeTurnBoundaryExecution,
    NormalizedModelAttempt,
    PreparedModelContext,
    ProviderAttempt,
    ProviderAttemptBinding,
    _NativeSignals,
    _ProviderConnector,
)
from .native_repository_tools import parse_native_tool_calls
from .remote_provider_budget import RemoteProviderCallContext, RemoteProviderCostReceipt

ContextBuilder = Callable[[], PreparedModelContext]
CredentialSupplier = Callable[[ProviderProfile], CredentialLease | None]


class _RemoteReservation:
    __slots__ = ("execution", "ready", "semantic_hash")

    def __init__(self, semantic_hash: str) -> None:
        self.semantic_hash = semantic_hash
        self.ready = threading.Event()
        self.execution: ModelBoundaryExecution | NativeTurnBoundaryExecution | None = None


class _FakeReservation:
    __slots__ = ("ready", "result", "semantic_hash")

    def __init__(self, semantic_hash: str) -> None:
        self.semantic_hash = semantic_hash
        self.ready = threading.Event()
        self.result: NormalizedModelAttempt | None = None


def _remote_invocation_hash(
    preflight: ModelPreflightRequest,
    profile: ProviderProfile,
    policy: EgressPolicyDocument,
    *,
    native: bool = False,
) -> str:
    material = {
        "mode": "native-turn" if native else "final-response",
        "preflight": preflight.model_dump(mode="json"),
        "profile_hash": profile.canonical_content_hash(),
        "policy_hash": policy.canonical_content_hash(),
    }
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _idempotency_stop(reason_code: str) -> ModelPreflightResult:
    return ModelPreflightResult(
        schema_version=CONTRACT_SCHEMA_VERSION,
        eligibility=PreflightEligibility.INELIGIBLE,
        preflight_context_bytes=0,
        preflight_network_bytes=0,
        next_action=PreflightNextAction.STOP_BEFORE_CONTEXT_OR_NETWORK,
        deterministic_only_fallback=False,
        required_terminal_outcome=AuditRunOutcome.INDETERMINATE,
        reason_codes=(reason_code,),
    )


def _native_turn_execution(
    *,
    preflight: ModelPreflightResult,
    request: ModelRequest,
    profile: ProviderProfile,
    attempt: ProviderAttempt,
    binding: ProviderAttemptBinding,
    validator: StructuredPayloadValidator,
) -> NativeTurnBoundaryExecution:
    def terminal(
        status: ModelCallStatus | None = None, signals: _NativeSignals | None = None
    ) -> NativeTurnBoundaryExecution:
        normalized = (
            normalize_provider_attempt(
                request=request, attempt=attempt, expected_binding=binding, validator=validator
            )
            if status is None
            else _non_success(
                request=request, status=status, elapsed_ms=attempt.elapsed_ms, signals=signals
            )
        )
        return NativeTurnBoundaryExecution(
            preflight,
            elapsed_ms=normalized.result.usage.elapsed_ms,
            terminal=ModelBoundaryExecution(preflight, normalized.result, normalized.payload),
        )

    # Transport/control failures use the unchanged final normalizer. No native
    # selection is released before the issuer binding and wire types are checked.
    if (
        type(attempt.elapsed_ms) is not int
        or not 0 <= attempt.elapsed_ms <= _MAX_WIRE_INT
        or type(attempt.http_status) is not int
        or not 100 <= attempt.http_status <= 599
        or type(attempt.response_bytes) is not bytes
        or type(attempt.redirected) is not bool
        or attempt.dialect is not ApiDialect.OPENAI_COMPATIBLE
        or attempt.dialect is not request.api_dialect
        or binding.request_hash != canonical_model_request_hash(request)
        or binding.profile_hash != profile.canonical_content_hash()
        or binding.profile_hash != request.provider_profile.content_sha256
        or binding.attempt != request.attempt
        or attempt.binding != binding
        or _transport_status(attempt) is not None
    ):
        return terminal()
    try:
        document = _parse_json(attempt.response_bytes)
        choices = document.get("choices")
        if (
            not isinstance(choices, list)
            or len(choices) != 1
            or not isinstance(choices[0], dict)
            or choices[0].get("finish_reason") != "tool_calls"
        ):
            return terminal()
        choice = choices[0]
        message = choice.get("message")
        usage = document.get("usage")
        if (
            set(document) != {"id", "choices", "usage"}
            or not isinstance(document["id"], str)
            or _NATIVE_RESPONSE_ID.fullmatch(document["id"]) is None
            or set(choice) != {"finish_reason", "message"}
            or not isinstance(message, dict)
            or set(message) != {"role", "content", "refusal", "tool_calls"}
            or message["role"] != "assistant"
            or message["content"] is not None
            or message["refusal"] is not None
            or not isinstance(usage, dict)
            or set(usage) != {"prompt_tokens", "completion_tokens"}
        ):
            raise ValueError("native selection control surface is invalid")
        input_tokens = _nonnegative_int(usage["prompt_tokens"])
        output_tokens = _nonnegative_int(usage["completion_tokens"])
        if (
            input_tokens > request.budget.max_input_tokens
            or output_tokens > request.budget.max_output_tokens
            or input_tokens > profile.capabilities.max_context_tokens
            or output_tokens > profile.capabilities.max_output_tokens
            or input_tokens + output_tokens > profile.budgets.max_total_tokens
            or attempt.elapsed_ms > request.budget.timeout_ms
        ):
            return terminal(
                ModelCallStatus.BUDGET_EXHAUSTED,
                _NativeSignals(
                    "COMPATIBLE_RESPONSE",
                    "TOOL_CALLS",
                    None,
                    None,
                    None,
                    input_tokens,
                    output_tokens,
                ),
            )
        selection = parse_native_tool_calls(
            message["tool_calls"],
            head_sha=request.execution_identity.repository_revision.head_sha,
            max_calls=min(4, request.budget.max_repository_calls),
        )
        measured = ModelUsage(
            schema_version=CONTRACT_SCHEMA_VERSION,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            repository_calls=0,
            elapsed_ms=attempt.elapsed_ms,
        )
        return NativeTurnBoundaryExecution(
            preflight, selection=selection, usage=measured, elapsed_ms=attempt.elapsed_ms
        )
    except Exception:
        return terminal(ModelCallStatus.PROVIDER_ERROR)


class AuthorizedProviderHarness:
    """One bounded remote attempt with policy and peer checks before application bytes."""

    __slots__ = ("_endpoint_issuer", "_idempotency", "_idempotency_lock", "_model_issuer")

    def __init__(
        self,
        *,
        model_issuer: ModelAuthorizationIssuer,
        endpoint_issuer: EndpointAuthorizationIssuer,
    ) -> None:
        self._model_issuer = model_issuer
        self._endpoint_issuer = endpoint_issuer
        self._idempotency: dict[str, _RemoteReservation] = {}
        self._idempotency_lock = threading.Lock()

    def _failure(
        self,
        *,
        preflight: ModelPreflightResult,
        request: ModelRequest,
    ) -> ModelBoundaryExecution:
        normalized = _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=0,
        )
        return ModelBoundaryExecution(preflight, normalized.result)

    def _complete(
        self,
        reservation: _RemoteReservation,
        candidate: ModelBoundaryExecution | NativeTurnBoundaryExecution,
    ) -> ModelBoundaryExecution | NativeTurnBoundaryExecution:
        with self._idempotency_lock:
            if reservation.execution is None:
                reservation.execution = candidate
                reservation.ready.set()
            return reservation.execution

    def execute_remote(
        self,
        *,
        preflight: ModelPreflightRequest,
        profile: ProviderProfile,
        policy: EgressPolicyDocument,
        context_builder: ContextBuilder,
        resolver: Resolver,
        connector: _ProviderConnector,
        credential_supplier: CredentialSupplier,
        validator: StructuredPayloadValidator,
        now: float,
        cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    ) -> ModelBoundaryExecution:
        execution = self._execute_authorized_turn(
            preflight=preflight,
            profile=profile,
            policy=policy,
            context_builder=context_builder,
            resolver=resolver,
            connector=connector,
            credential_supplier=credential_supplier,
            validator=validator,
            now=now,
            native=False,
            cost_observer=cost_observer,
        )
        if type(execution) is not ModelBoundaryExecution:
            raise RuntimeError("final provider execution returned the wrong boundary type")
        return execution

    def execute_native_turn(
        self,
        *,
        preflight: ModelPreflightRequest,
        profile: ProviderProfile,
        policy: EgressPolicyDocument,
        context_builder: ContextBuilder,
        resolver: Resolver,
        connector: _ProviderConnector,
        credential_supplier: CredentialSupplier,
        validator: StructuredPayloadValidator,
        now: float,
        cost_observer: Callable[[RemoteProviderCostReceipt], None] | None = None,
    ) -> NativeTurnBoundaryExecution:
        execution = self._execute_authorized_turn(
            preflight=preflight,
            profile=profile,
            policy=policy,
            context_builder=context_builder,
            resolver=resolver,
            connector=connector,
            credential_supplier=credential_supplier,
            validator=validator,
            now=now,
            native=True,
            cost_observer=cost_observer,
        )
        if type(execution) is not NativeTurnBoundaryExecution:
            raise RuntimeError("native provider execution returned the wrong boundary type")
        return execution

    def _execute_authorized_turn(
        self,
        *,
        preflight: ModelPreflightRequest,
        profile: ProviderProfile,
        policy: EgressPolicyDocument,
        context_builder: ContextBuilder,
        resolver: Resolver,
        connector: _ProviderConnector,
        credential_supplier: CredentialSupplier,
        validator: StructuredPayloadValidator,
        now: float,
        native: bool,
        cost_observer: Callable[[RemoteProviderCostReceipt], None] | None,
    ) -> ModelBoundaryExecution | NativeTurnBoundaryExecution:
        def outcome(
            value: ModelBoundaryExecution,
        ) -> ModelBoundaryExecution | NativeTurnBoundaryExecution:
            if not native:
                return value
            return NativeTurnBoundaryExecution(
                value.preflight,
                elapsed_ms=value.result.usage.elapsed_ms if value.result is not None else 0,
                terminal=value,
            )

        request = preflight.model_request
        try:
            invocation_hash = _remote_invocation_hash(preflight, profile, policy, native=native)
        except (TypeError, ValueError):
            authorization = self._model_issuer.authorize_pre_context(
                preflight, profile=profile, policy=policy
            )
            return outcome(ModelBoundaryExecution(authorization.result, None))
        with self._idempotency_lock:
            reservation = self._idempotency.get(request.idempotency_key)
            owner = reservation is None
            if reservation is None:
                reservation = _RemoteReservation(invocation_hash)
                self._idempotency[request.idempotency_key] = reservation
        if not owner:
            if reservation.semantic_hash != invocation_hash:
                return outcome(
                    self._failure(
                        preflight=_idempotency_stop("IDEMPOTENCY_SEMANTIC_CONFLICT"),
                        request=request,
                    )
                )
            if not reservation.ready.wait(timeout=request.budget.timeout_ms / 1000):
                return self._complete(
                    reservation,
                    outcome(
                        self._failure(
                            preflight=_idempotency_stop("IDEMPOTENCY_WAIT_TIMEOUT"),
                            request=request,
                        )
                    ),
                )
            completed = reservation.execution
            if completed is None:
                raise RuntimeError("remote idempotency reservation completed without a result")
            return completed

        authorization = self._model_issuer.authorize_pre_context(
            preflight,
            profile=profile,
            policy=policy,
        )
        decision = authorization.result
        execution: ModelBoundaryExecution | NativeTurnBoundaryExecution
        if decision.eligibility is not PreflightEligibility.ELIGIBLE:
            execution = ModelBoundaryExecution(decision, None)
            return self._complete(reservation, outcome(execution))

        context: PreparedModelContext | None = None
        credential_lease: CredentialLease | None = None
        try:
            if native:
                # This import is deferred because the connector imports boundary DTOs.
                from .openai_compatible_local import OpenAICompatibleLocalHttpConnector

                if type(connector) is OpenAICompatibleLocalHttpConnector:
                    connector = connector.with_output_token_limit(request.budget.max_output_tokens)
            context = context_builder()
            payload_bytes = context.bytes_for(request.request_id)
            manifest = EgressManifest.build(
                model_request=request,
                policy=request.execution_identity.policy,
                destination=f"profile://{profile.profile_id}",
                payload_content_id=context.payload_content_id,
                content=context.content,
                applied_transforms=context.applied_transforms,
                byte_count=len(payload_bytes),
            )
            pre_send = self._model_issuer.authorize_pre_send(authorization, manifest)
            endpoint = self._endpoint_issuer.authorize(
                pre_send,
                model_issuer=self._model_issuer,
                profile=profile,
                resolver=resolver,
                now=now,
            )
            channel = connector.connect(
                ip_address=endpoint.connect_addresses[0],
                port=endpoint.port,
                server_name=endpoint.authority,
                timeout_ms=request.budget.timeout_ms,
            )
            verified = self._endpoint_issuer.verify_peer(
                endpoint,
                connected_peer=channel.peer_ip,
                resolver=resolver,
                now=now,
            )
            binding = ProviderAttemptBinding.from_claim(
                self._endpoint_issuer.consume_verified(verified)
            )
            credential: str | None = None
            if profile.credential_ref is not None:
                credential_lease = credential_supplier(profile)
                if credential_lease is None:
                    raise ValueError("credential supplier did not return a lease")
                credential = credential_lease.reveal_for(
                    profile_selector=profile.selector,
                    authority=profile.endpoint.authority,
                )
            input_token_upper_bound: int | None = None
            if profile.provider_kind is ProviderKind.OPENAI_COMPATIBLE_REMOTE:
                framing_bound = profile.protocol_framing_token_upper_bound
                if type(framing_bound) is not int:
                    raise ValueError("remote protocol token bound is unavailable")
                # SealedRepositoryView uses UTF-8 byte count as a conservative
                # token ceiling.  Add only the explicitly profiled wire
                # framing bound; never substitute a tokenizer heuristic.
                input_token_upper_bound = len(payload_bytes) + framing_bound
            attempt = connector.send(
                channel,
                credential=credential,
                payload=payload_bytes,
                model_id=profile.model_id,
                timeout_ms=request.budget.timeout_ms,
                binding=binding,
                call_budget=RemoteProviderCallContext(
                    run_id=request.run_id,
                    tenant_id=request.tenant_id,
                    request_id=request.request_id,
                    attempt=request.attempt,
                    max_input_tokens=request.budget.max_input_tokens,
                    max_output_tokens=request.budget.max_output_tokens,
                    input_token_upper_bound=input_token_upper_bound,
                ),
            )
            receipt = attempt.cost_receipt
            if attempt.cost_receipt_required:
                if (
                    cost_observer is None
                    or receipt is None
                    or receipt.run_id != request.run_id
                    or receipt.tenant_id != request.tenant_id
                    or receipt.model_id != request.model_id
                    or receipt.request_id != request.request_id
                    or receipt.attempt != request.attempt
                ):
                    raise ValueError("remote cost receipt is not bound to the active run")
                cost_observer(receipt)
            if native:
                execution = _native_turn_execution(
                    preflight=decision,
                    request=request,
                    profile=profile,
                    attempt=attempt,
                    binding=binding,
                    validator=validator,
                )
            else:
                normalized = normalize_provider_attempt(
                    request=request,
                    attempt=attempt,
                    expected_binding=binding,
                    validator=validator,
                )
                execution = ModelBoundaryExecution(decision, normalized.result, normalized.payload)
        except Exception:
            execution = outcome(self._failure(preflight=decision, request=request))
        finally:
            if credential_lease is not None:
                try:
                    credential_lease.close()
                except Exception:
                    execution = outcome(self._failure(preflight=decision, request=request))
            if context is not None:
                try:
                    context.close()
                except Exception:
                    execution = outcome(self._failure(preflight=decision, request=request))
        return self._complete(reservation, execution)
