"""Hermetic provider adapter, native-dialect normalization and ephemeral payloads."""

from __future__ import annotations

import json

from securecode_ai.core import (
    CONTRACT_SCHEMA_VERSION,
    ApiDialect,
    DataClass,
    ModelCallResult,
    ModelCallStatus,
    ModelRequest,
    ModelSchemaResult,
    ModelSchemaStatus,
    ModelUsage,
    NativeOutcomeMetadata,
    OpaqueContentProvenance,
    PayloadValidation,
    StructuredPayloadValidator,
    canonical_model_request_hash,
)

from .model_parsing import (
    _closed_object,
    _depth,
    _non_success,
    _signals,
    _status,
    _transport_status,
)
from .model_types import (
    _MAX_WIRE_INT,
    EphemeralStructuredPayload,
    HmacContentIdentifier,
    NormalizedModelAttempt,
    ProviderAttempt,
    ProviderAttemptBinding,
    _contains_restricted_material,
)


def normalize_provider_attempt(
    *,
    request: ModelRequest,
    attempt: ProviderAttempt,
    expected_binding: ProviderAttemptBinding,
    validator: StructuredPayloadValidator,
) -> NormalizedModelAttempt:
    """Normalize one bounded native response; every ambiguity fails closed."""

    try:
        expected_request_hash = canonical_model_request_hash(request)
    except ValueError:
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=0,
        )
    elapsed_ms: object = attempt.elapsed_ms
    http_status: object = attempt.http_status
    response_bytes: object = attempt.response_bytes
    redirected: object = attempt.redirected
    dialect: object = attempt.dialect
    if (
        not isinstance(elapsed_ms, int)
        or isinstance(elapsed_ms, bool)
        or not 0 <= elapsed_ms <= _MAX_WIRE_INT
        or (
            http_status is not None
            and (
                not isinstance(http_status, int)
                or isinstance(http_status, bool)
                or not 100 <= http_status <= 599
            )
        )
        or (response_bytes is not None and not isinstance(response_bytes, bytes))
        or not isinstance(redirected, bool)
        or not isinstance(dialect, ApiDialect)
    ):
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=0,
        )
    if (
        expected_binding.request_hash != expected_request_hash
        or expected_binding.profile_hash != request.provider_profile.content_sha256
        or expected_binding.attempt != request.attempt
        or attempt.binding != expected_binding
        or attempt.dialect is not request.api_dialect
    ):
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=attempt.elapsed_ms,
        )
    transport_status = _transport_status(attempt)
    if transport_status is not None:
        return _non_success(
            request=request,
            status=transport_status,
            elapsed_ms=attempt.elapsed_ms,
        )
    try:
        if attempt.response_bytes is None:
            raise ValueError("missing native response")
        signals = _signals(attempt.dialect, attempt.response_bytes)
    except Exception:
        return _non_success(
            request=request,
            status=ModelCallStatus.PROVIDER_ERROR,
            elapsed_ms=attempt.elapsed_ms,
        )
    if (
        signals.input_tokens > request.budget.max_input_tokens
        or signals.output_tokens > request.budget.max_output_tokens
        or signals.input_tokens + signals.output_tokens
        > request.budget.max_input_tokens + request.budget.max_output_tokens
        or attempt.elapsed_ms > request.budget.timeout_ms
    ):
        return _non_success(
            request=request,
            status=ModelCallStatus.BUDGET_EXHAUSTED,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    native_status = _status(signals)
    if native_status is not None:
        return _non_success(
            request=request,
            status=native_status,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    if signals.finish_code != "COMPLETE" or signals.content_text is None:
        return _non_success(
            request=request,
            status=ModelCallStatus.EMPTY_OUTPUT,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    try:
        payload = json.loads(signals.content_text, object_pairs_hook=_closed_object)
        _depth(payload)
    except Exception:
        return _non_success(
            request=request,
            status=ModelCallStatus.INVALID_SCHEMA,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    if payload in ({}, [], None, ""):
        return _non_success(
            request=request,
            status=ModelCallStatus.EMPTY_OUTPUT,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    if _contains_restricted_material(payload):
        return _non_success(
            request=request,
            status=ModelCallStatus.INVALID_SCHEMA,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    try:
        validation = validator.validate(payload, request=request)
        if (
            not isinstance(validation, PayloadValidation)
            or not validation.accepted
            or validation.error_code is not None
            or validation.content_id is None
            or validation.data_class is None
            or validation.data_class is DataClass.RESTRICTED
            or validation.validator != request.output_schema
        ):
            raise ValueError("model payload validation failed")
        content_identifier = getattr(validator, "_content_identifier", None)
        if type(content_identifier) is not HmacContentIdentifier:
            raise ValueError("model payload content verifier unavailable")
        canonicalizer = getattr(validator, "canonical_payload", None)
        if canonicalizer is None:
            retained_payload = json.dumps(
                payload,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        elif callable(canonicalizer):
            retained_payload = canonicalizer(payload, request=request)
        else:
            raise ValueError("model payload canonicalizer invalid")
        if type(retained_payload) is not bytes:
            raise ValueError("model payload canonical bytes invalid")
        retained_object = json.loads(retained_payload, object_pairs_hook=_closed_object)
        _depth(retained_object)
        if (
            retained_object in ({}, [], None, "")
            or _contains_restricted_material(retained_object)
            or json.dumps(
                retained_object,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            != retained_payload
            or not content_identifier.verify(
                tenant_id=request.tenant_id,
                payload=retained_payload,
                content_id=validation.content_id,
            )
        ):
            raise ValueError("model payload content binding mismatch")
        result = ModelCallResult(
            schema_version=CONTRACT_SCHEMA_VERSION,
            request_id=request.request_id,
            run_id=request.run_id,
            tenant_id=request.tenant_id,
            idempotency_key=request.idempotency_key,
            attempt=request.attempt,
            provider_profile=request.provider_profile,
            model_call_status=ModelCallStatus.SUCCEEDED,
            native=NativeOutcomeMetadata(
                schema_version=CONTRACT_SCHEMA_VERSION,
                request_code=signals.request_code,
                finish_code="COMPLETE",
            ),
            schema_result=ModelSchemaResult(
                schema_version=CONTRACT_SCHEMA_VERSION,
                status=ModelSchemaStatus.VALID,
                validator=validation.validator,
            ),
            usage=ModelUsage(
                schema_version=CONTRACT_SCHEMA_VERSION,
                input_tokens=signals.input_tokens,
                output_tokens=signals.output_tokens,
                repository_calls=0,
                elapsed_ms=attempt.elapsed_ms,
            ),
            retryable=False,
            content_provenance=OpaqueContentProvenance(
                schema_version=CONTRACT_SCHEMA_VERSION,
                content_id=validation.content_id,
                tenant_id=request.tenant_id,
                data_class=validation.data_class,
                validator=validation.validator,
            ),
        )
        structured_payload = EphemeralStructuredPayload(
            payload=retained_payload,
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            content_id=validation.content_id,
            content_identifier=content_identifier,
        )
    except Exception:
        return _non_success(
            request=request,
            status=ModelCallStatus.INVALID_SCHEMA,
            elapsed_ms=attempt.elapsed_ms,
            signals=signals,
        )
    return NormalizedModelAttempt(result, structured_payload)
