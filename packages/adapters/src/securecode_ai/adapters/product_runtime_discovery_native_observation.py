"""Native discovery observation and elapsed-time normalization."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from securecode_ai.contracts import ModelCallStatus, ModelRequest, ModelSchemaStatus
from securecode_ai.core.model_discovery import ModelNativeDiscoveryPayload, RepositoryToolSession

from .product_model import DiscoverySchemaRefusalCategory
from .product_runtime_contracts import ProductDiscoveryInvocationObservation
from .product_runtime_execution import _non_success_result, _result_with_calls


class _ElapsedClock(Protocol):
    def elapsed_since(self, started: float) -> int: ...


def _observe_native_payload_impl(
    *,
    executor: _ElapsedClock,
    observer: Callable[[ProductDiscoveryInvocationObservation], object] | None,
    request: ModelRequest,
    tools: RepositoryToolSession,
    started: float,
    payload: ModelNativeDiscoveryPayload,
    elapsed_known: bool,
    token_usage_known: bool,
    schema_refusal_category: DiscoverySchemaRefusalCategory,
) -> ModelNativeDiscoveryPayload:
    """Capture closed native metadata once, before Core turns it into a receipt."""

    result = payload.model_result
    if observer is not None:
        try:
            observer(
                ProductDiscoveryInvocationObservation(
                    request=request,
                    model_result_before_collection=result,
                    usage_before_collection=result.usage,
                    model_call_status_before_collection=result.model_call_status,
                    schema_valid_result_before_collection=(
                        result.schema_result.status is ModelSchemaStatus.VALID
                    ),
                    repository_view_call_hashes=tools.call_hashes,
                    elapsed_known=elapsed_known,
                    token_usage_known=token_usage_known,
                    schema_refusal_category=schema_refusal_category,
                )
            )
        except Exception:
            try:
                observer_elapsed_ms = executor.elapsed_since(started)
            except Exception:
                observer_elapsed_ms = result.usage.elapsed_ms
            return ModelNativeDiscoveryPayload(
                model_result=_non_success_result(
                    request,
                    ModelCallStatus.GUARDRAIL_BLOCKED,
                    result.usage.repository_calls,
                    observer_elapsed_ms,
                    result.native,
                    result.usage,
                ),
                candidates=(),
            )

    elapsed_ms: int | None
    try:
        elapsed_ms = executor.elapsed_since(started)
    except Exception:
        elapsed_ms = None
        elapsed_known = False
    if elapsed_ms is not None:
        result = _result_with_calls(
            result,
            result.usage.repository_calls,
            request=request,
            elapsed_ms=elapsed_ms,
        )
        payload = ModelNativeDiscoveryPayload(
            model_result=result,
            candidates=(payload.candidates if result.status is ModelCallStatus.SUCCEEDED else ()),
        )
    if result.model_call_status is ModelCallStatus.SUCCEEDED and (
        elapsed_ms is None or elapsed_ms >= request.budget.timeout_ms
    ):
        return ModelNativeDiscoveryPayload(
            model_result=_non_success_result(
                request,
                ModelCallStatus.BUDGET_EXHAUSTED,
                result.usage.repository_calls,
                result.usage.elapsed_ms,
                result.native,
                result.usage,
            ),
            candidates=(),
        )
    return payload
