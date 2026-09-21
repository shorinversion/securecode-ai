"""Hermetic provider adapter, native-dialect normalization and ephemeral payloads."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import replace

from securecode_ai.core import (
    AuthorizationError,
    ModelAuthorizationIssuer,
    ModelCallStatus,
    ModelRequest,
    PreSendAuthorization,
    StructuredPayloadValidator,
    canonical_model_request_hash,
)

from .model_harness import _FakeReservation
from .model_normalization import normalize_provider_attempt
from .model_parsing import _non_success
from .model_types import (
    NormalizedModelAttempt,
    ProviderAttempt,
    ProviderAttemptBinding,
)


class ScriptedFakeProvider:
    """Hermetic exact-request fake: no default success, credential, DNS or network hooks."""

    __slots__ = (
        "_effects",
        "_idempotency",
        "_idempotency_lock",
        "_scripts",
        "effect_count",
    )

    def __init__(self, scripts: dict[str, ProviderAttempt]) -> None:
        self._scripts = dict(scripts)
        self._effects: set[str] = set()
        self._idempotency: dict[str, _FakeReservation] = {}
        self._idempotency_lock = threading.Lock()
        self.effect_count = 0

    def _provider_error(
        self, request: ModelRequest, validator: StructuredPayloadValidator
    ) -> NormalizedModelAttempt:
        del validator
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=0,
        )

    def _complete(
        self,
        reservation: _FakeReservation,
        candidate: NormalizedModelAttempt,
    ) -> NormalizedModelAttempt:
        with self._idempotency_lock:
            if reservation.result is None:
                reservation.result = candidate
                reservation.ready.set()
            return reservation.result

    def invoke(
        self,
        *,
        request: ModelRequest,
        authorization: PreSendAuthorization,
        model_issuer: ModelAuthorizationIssuer,
        validator: StructuredPayloadValidator,
    ) -> NormalizedModelAttempt:
        try:
            request_hash = canonical_model_request_hash(request)
        except ValueError:
            return self._provider_error(request, validator)
        try:
            claim = model_issuer.consume_pre_send(authorization)
        except AuthorizationError:
            return self._provider_error(request, validator)
        if (
            claim["request_hash"] != request_hash
            or claim["profile_hash"] != request.provider_profile.content_sha256
            or int(claim["attempt"]) != request.attempt
        ):
            return self._provider_error(request, validator)
        try:
            binding = ProviderAttemptBinding.from_claim(claim)
        except ValueError:
            return self._provider_error(request, validator)
        semantic_hash = hashlib.sha256(
            (
                request_hash
                + binding.profile_hash
                + binding.policy_hash
                + binding.manifest_hash
                + str(binding.attempt)
            ).encode()
        ).hexdigest()
        with self._idempotency_lock:
            reservation = self._idempotency.get(request.idempotency_key)
            owner = reservation is None
            if reservation is None:
                reservation = _FakeReservation(semantic_hash)
                self._idempotency[request.idempotency_key] = reservation
        if not owner:
            if reservation.semantic_hash != semantic_hash:
                return self._provider_error(request, validator)
            if not reservation.ready.wait(timeout=request.budget.timeout_ms / 1000):
                return self._complete(
                    reservation,
                    self._provider_error(request, validator),
                )
            if reservation.result is None:
                return self._provider_error(request, validator)
            return reservation.result
        attempt = self._scripts.get(request_hash)
        if attempt is None:
            normalized = self._provider_error(request, validator)
        else:
            try:
                with self._idempotency_lock:
                    if request_hash not in self._effects:
                        self._effects.add(request_hash)
                        self.effect_count += 1
                bound_attempt = replace(attempt, binding=binding)
                normalized = normalize_provider_attempt(
                    request=request,
                    attempt=bound_attempt,
                    expected_binding=binding,
                    validator=validator,
                )
            except Exception:
                normalized = self._provider_error(request, validator)
        return self._complete(reservation, normalized)
