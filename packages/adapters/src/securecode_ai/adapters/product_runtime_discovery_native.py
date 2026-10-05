"""Authorized product-model ports built on the existing provider harness."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import asdict

from securecode_ai.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ArtifactRef,
    DataClass,
    EgressContentRef,
    ModelCallResult,
    ModelCallStatus,
    ModelRequest,
    ModelUsage,
    NativeOutcomeMetadata,
    PreflightEligibility,
)
from securecode_ai.core.model_discovery import (
    ModelNativeDiscoveryPayload,
    RepositoryToolSession,
)
from securecode_ai.core.tool_policy import (
    GuardedToolResult,
    RepositoryToolRequest,
    ToolOutcome,
)

from .model import (
    HmacContentIdentifier,
    PreparedModelContext,
)
from .product_model import (
    MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON,
    DiscoverySchemaRefusalCategory,
    ModelNativeDiscoveryPayloadValidator,
)
from .product_runtime_contracts import (
    DiscoveryEvidence,
    NativeCycleBudget,
    NativeDeadlineExceeded,
    ProductDiscoveryInvocationObservation,
    RepositoryContextBudgetExhausted,
    native_turn_request,
)
from .product_runtime_discovery_native_observation import _observe_native_payload_impl
from .product_runtime_execution import (
    AuthorizedLocalModelExecutor,
    _context,
    _NativeCycleExecution,
    _non_success_result,
    _result_with_calls,
)
from .product_runtime_native import (
    dispatch_native_repository_calls,
    native_repository_history,
)
from .product_runtime_support import _draft


class _ProductDiscoveryNativeCycle:
    __slots__ = ()

    _catalogue: tuple[DiscoveryEvidence, ...]
    _data_class: DataClass
    _executor: AuthorizedLocalModelExecutor
    _key: bytes
    _native_lock: threading.Lock
    _native_results: dict[str, tuple[str, int, tuple[str, ...], ModelNativeDiscoveryPayload]]
    _observer: Callable[[ProductDiscoveryInvocationObservation], None] | None
    _rule_ids: frozenset[str]

    def _discover_native(
        self, *, request: ModelRequest, tools: RepositoryToolSession, started: float
    ) -> ModelNativeDiscoveryPayload:
        semantic = hashlib.sha256(request.model_dump_json().encode()).hexdigest()
        if not self._native_lock.acquire(timeout=request.budget.timeout_ms / 1000):
            return ModelNativeDiscoveryPayload(
                model_result=_non_success_result(
                    request,
                    ModelCallStatus.BUDGET_EXHAUSTED,
                    0,
                    self._executor.elapsed_since(started),
                    None,
                ),
                candidates=(),
            )
        try:
            cached = self._native_results.get(request.idempotency_key)
            if cached is not None:
                pinned, session_id, receipts, payload = cached
                if pinned != semantic or session_id != id(tools) or receipts != tools.call_hashes:
                    return ModelNativeDiscoveryPayload(
                        model_result=_non_success_result(
                            request,
                            ModelCallStatus.PROVIDER_ERROR,
                            0,
                            self._executor.elapsed_since(started),
                            None,
                        ),
                        candidates=(),
                    )
                # Return only durable-safe final metadata/drafts, never a closed
                # ephemeral execution, and do not repeat bootstrap/tool effects.
                return payload
            if len(self._native_results) >= 64:
                return ModelNativeDiscoveryPayload(
                    model_result=_non_success_result(
                        request,
                        ModelCallStatus.BUDGET_EXHAUSTED,
                        0,
                        self._executor.elapsed_since(started),
                        None,
                    ),
                    candidates=(),
                )
            cycle_result = self._run_native_cycle(request=request, tools=tools, started=started)
            payload = self._observe_native_payload(
                request=request,
                tools=tools,
                started=started,
                payload=cycle_result.payload,
                elapsed_known=cycle_result.elapsed_known,
                token_usage_known=cycle_result.token_usage_known,
                schema_refusal_category=cycle_result.schema_refusal_category,
            )
            self._native_results[request.idempotency_key] = (
                semantic,
                id(tools),
                tools.call_hashes,
                payload,
            )
            return payload
        finally:
            self._native_lock.release()

    def _observe_native_payload(
        self,
        *,
        request: ModelRequest,
        tools: RepositoryToolSession,
        started: float,
        payload: ModelNativeDiscoveryPayload,
        elapsed_known: bool,
        token_usage_known: bool,
        schema_refusal_category: DiscoverySchemaRefusalCategory,
    ) -> ModelNativeDiscoveryPayload:
        return _observe_native_payload_impl(
            executor=self._executor,
            observer=self._observer,
            request=request,
            tools=tools,
            started=started,
            payload=payload,
            elapsed_known=elapsed_known,
            token_usage_known=token_usage_known,
            schema_refusal_category=schema_refusal_category,
        )

    def _run_native_cycle(
        self, *, request: ModelRequest, tools: RepositoryToolSession, started: float
    ) -> _NativeCycleExecution:
        before_calls = tools.calls_used
        input_tokens = output_tokens = 0
        seed = bytearray()
        history: list[dict[str, object]] = []
        repository_results: dict[RepositoryToolRequest, GuardedToolResult] = {}
        seed_refs: tuple[EgressContentRef, ...] = ()
        tool_refs: dict[str, EgressContentRef] = {}
        seen_call_ids: set[str] = set()
        successful_native_inspections = 0
        # One malformed final answer (for example a tool call written as text with an
        # unknown tool name) is answered by repeating the same turn once.
        regenerations_left = 1
        by_id = {item.evidence_id: item for item in self._catalogue}
        guided_first_request = self._catalogue[0].request
        validator = ModelNativeDiscoveryPayloadValidator(
            content_identifier=HmacContentIdentifier(self._key),
            rule_ids=self._rule_ids,
            evidence_ids=frozenset(by_id),
            expected_tenant_id=request.tenant_id,
            expected_head_sha=request.head_sha,
        )
        metadata: NativeOutcomeMetadata | None = None
        terminal_payload = None
        context_failure: ModelCallStatus | None = None
        provider_usage_known = False

        def measured_usage() -> ModelUsage:
            return ModelUsage(
                schema_version=CONTRACT_SCHEMA_VERSION,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                repository_calls=0,
                elapsed_ms=self._executor.elapsed_since(started),
            )

        def failure(
            status: ModelCallStatus,
            category: DiscoverySchemaRefusalCategory = DiscoverySchemaRefusalCategory.NOT_OBSERVED,
        ) -> _NativeCycleExecution:
            elapsed_known = True
            try:
                usage = measured_usage()
            except Exception:
                status = ModelCallStatus.PROVIDER_ERROR
                elapsed_known = False
                usage = ModelUsage(
                    schema_version=CONTRACT_SCHEMA_VERSION,
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    repository_calls=0,
                    elapsed_ms=0,
                )
            if (
                usage.elapsed_ms > request.budget.timeout_ms
                or tools.calls_used - before_calls > request.budget.max_repository_calls
            ):
                status = ModelCallStatus.BUDGET_EXHAUSTED
            return _NativeCycleExecution(
                payload=ModelNativeDiscoveryPayload(
                    model_result=_non_success_result(
                        request,
                        status,
                        tools.calls_used - before_calls,
                        usage.elapsed_ms,
                        metadata,
                        usage,
                    ),
                    candidates=(),
                ),
                elapsed_known=elapsed_known,
                token_usage_known=provider_usage_known,
                schema_refusal_category=category,
            )

        try:
            if tools.has_non_success:
                return failure(tools.failure_status)
            cycle = NativeCycleBudget(request.budget, now=self._executor.clock, started_at=started)

            def build_seed() -> None:
                nonlocal seed_refs
                entries: list[tuple[str, ArtifactRef, bytes]] = []
                unique_requests = []
                for item in self._catalogue:
                    if item.request not in unique_requests:
                        unique_requests.append(item.request)
                cycle.reserve_repository_calls(
                    sum(request not in repository_results for request in unique_requests)
                )
                for item in self._catalogue:
                    result = repository_results.get(item.request)
                    if result is None:
                        cycle._check()
                        result = tools.dispatch(item.request)
                        repository_results[item.request] = result
                        if result.output is not None:
                            cycle.record_context_bytes(result.output.byte_count)
                    if result.receipt.outcome is not ToolOutcome.SUCCEEDED or result.output is None:
                        raise ValueError("native seed read is unavailable")
                    output = result.output
                    if (
                        output.content_sha256 != item.read_artifact.content_sha256
                        or output.byte_count != item.read_artifact.size_bytes
                        or item.read_artifact.tenant_id != request.tenant_id
                        or item.tenant_id != request.tenant_id
                        or item.head_sha != request.head_sha
                        or item.request.arguments.head_sha != request.head_sha
                    ):
                        raise ValueError("native seed read identity mismatch")
                    entries.append((item.evidence_id, item.read_artifact, output.content.encode()))
                initial = _context(
                    request=request,
                    entries=tuple(entries),
                    key=self._key,
                    role="discovery",
                    schema=MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON,
                    rule_ids=tuple(sorted(self._rule_ids)),
                    locations=tuple((item.evidence_id, item.location) for item in self._catalogue),
                    guided_first_native_tool_call=guided_first_request,
                )
                try:
                    seed.extend(initial.bytes_for(request.request_id))
                    seed_refs = initial.content
                finally:
                    initial.close()

            def frame_bytes() -> bytes:
                return json.dumps(
                    {"initial_context": json.loads(seed), "tool_history": history},
                    sort_keys=True,
                    ensure_ascii=True,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode("ascii")

            def prepared(turn: ModelRequest, frame: bytes) -> PreparedModelContext:
                if len(frame) > min(128 * 1024, turn.budget.max_context_bytes):
                    raise RepositoryContextBudgetExhausted("native frame exceeds byte budget")
                refs = {ref.content_id: ref for ref in seed_refs}
                for content_id, ref in tool_refs.items():
                    if content_id in refs and refs[content_id] != ref:
                        raise ValueError("native content identity collision")
                    refs[content_id] = ref
                return PreparedModelContext(
                    payload=frame,
                    content=tuple(refs.values()),
                    applied_transforms=("bounded_repository_view",),
                    request_id=turn.request_id,
                    tenant_id=turn.tenant_id,
                    content_identifier=HmacContentIdentifier(self._key),
                )

            for ordinal in range(16):
                turn_id = f"native-cycle-turn:{ordinal}"
                budget = cycle.begin_turn(turn_id)
                turn_started = self._executor.clock()
                if ordinal == 0:
                    turn = request

                    def build_first(selected: ModelRequest = turn) -> PreparedModelContext:
                        nonlocal context_failure
                        try:
                            build_seed()
                            return prepared(selected, frame_bytes())
                        except RepositoryContextBudgetExhausted:
                            context_failure = ModelCallStatus.BUDGET_EXHAUSTED
                            raise

                    context_builder = build_first
                else:
                    frame = frame_bytes()
                    turn = native_turn_request(
                        request,
                        ordinal=ordinal,
                        budget=budget,
                        frame=frame,
                        content_key=self._key,
                    )

                    def build_following(
                        selected: ModelRequest = turn, payload: bytes = frame
                    ) -> PreparedModelContext:
                        return prepared(selected, payload)

                    context_builder = build_following
                execution = self._executor.execute_native(
                    request=turn,
                    validator=validator,
                    context_builder=context_builder,
                    started_at=started if ordinal == 0 else turn_started,
                )
                terminal = execution.terminal
                usage = (
                    execution.usage
                    if terminal is None
                    else (terminal.result.usage if terminal.result is not None else None)
                )
                if terminal is not None:
                    terminal_payload = terminal.payload
                    if terminal.result is not None:
                        metadata = terminal.result.native
                if context_failure is not None:
                    return failure(context_failure)
                if usage is None or (
                    terminal is not None
                    and (
                        terminal.result is None
                        or terminal.result.native.request_code == "NO_NATIVE_RESPONSE"
                    )
                ):
                    # A later failed turn makes aggregate provider-token usage
                    # unknown even if earlier selections were measured.
                    provider_usage_known = False
                    status = (
                        ModelCallStatus.GUARDRAIL_BLOCKED
                        if execution.preflight.eligibility is PreflightEligibility.INELIGIBLE
                        else ModelCallStatus.PROVIDER_ERROR
                    )
                    return failure(status)
                provider_usage_known = True
                # Actual provider token usage is retained even when accounting
                # detects exhaustion; selections themselves contribute no reads.
                input_tokens += usage.input_tokens
                output_tokens += usage.output_tokens
                cycle.record_usage(turn_id, usage)
                if terminal is not None:
                    if terminal.result is None:
                        return failure(ModelCallStatus.PROVIDER_ERROR)
                    if successful_native_inspections < 1:
                        return failure(ModelCallStatus.GUARDRAIL_BLOCKED)
                    checked = _result_with_calls(
                        terminal.result,
                        0,
                        request=turn,
                        elapsed_ms=self._executor.elapsed_since(turn_started),
                    )
                    drafts = None
                    if checked.status is ModelCallStatus.SUCCEEDED and terminal.payload is not None:
                        try:
                            wire = validator.parse(terminal.payload.reveal_for(turn.request_id))
                            drafts = tuple(_draft(item, by_id, request) for item in wire)
                        except Exception:
                            drafts = None
                    malformed = drafts is None and checked.status in {
                        ModelCallStatus.SUCCEEDED,
                        ModelCallStatus.INVALID_SCHEMA,
                        ModelCallStatus.EMPTY_OUTPUT,
                    }
                    if malformed and regenerations_left and ordinal < 15:
                        regenerations_left -= 1
                        if terminal_payload is not None:
                            terminal_payload.close()
                            terminal_payload = None
                        continue
                    if checked.status is not ModelCallStatus.SUCCEEDED:
                        return failure(checked.status, validator.last_schema_refusal_category)
                    if drafts is None:
                        return failure(ModelCallStatus.INVALID_SCHEMA)
                    total = measured_usage()
                    if (
                        total.input_tokens > request.budget.max_input_tokens
                        or total.output_tokens > request.budget.max_output_tokens
                        or total.elapsed_ms > request.budget.timeout_ms
                        or tools.has_non_success
                    ):
                        return failure(
                            tools.failure_status
                            if tools.has_non_success
                            else ModelCallStatus.BUDGET_EXHAUSTED
                        )
                    result = ModelCallResult(
                        schema_version=CONTRACT_SCHEMA_VERSION,
                        request_id=request.request_id,
                        run_id=request.run_id,
                        tenant_id=request.tenant_id,
                        idempotency_key=request.idempotency_key,
                        attempt=request.attempt,
                        provider_profile=request.provider_profile,
                        model_call_status=ModelCallStatus.SUCCEEDED,
                        native=checked.native,
                        schema_result=checked.schema_result,
                        usage=ModelUsage(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            input_tokens=total.input_tokens,
                            output_tokens=total.output_tokens,
                            repository_calls=tools.calls_used - before_calls,
                            elapsed_ms=total.elapsed_ms,
                        ),
                        retryable=False,
                        content_provenance=checked.content_provenance,
                    )
                    return _NativeCycleExecution(
                        payload=ModelNativeDiscoveryPayload(model_result=result, candidates=drafts),
                        elapsed_known=True,
                        token_usage_known=True,
                        schema_refusal_category=DiscoverySchemaRefusalCategory.NOT_OBSERVED,
                    )
                calls = execution.selection
                if not calls or any(call.call_id in seen_call_ids for call in calls):
                    return failure(ModelCallStatus.PROVIDER_ERROR)
                if ordinal == 0 and (len(calls) != 1 or calls[0].request != guided_first_request):
                    return failure(ModelCallStatus.GUARDRAIL_BLOCKED)
                call_cap = max(16, request.budget.max_repository_calls)
                if (
                    len(history) + len(calls) + 1 > 2 * call_cap
                    or len(seen_call_ids) + len(calls) > call_cap
                ):
                    raise RepositoryContextBudgetExhausted("native history budget exhausted")
                uncached_requests = {
                    call.request for call in calls if call.request not in repository_results
                }
                if uncached_requests:
                    cycle.reserve_repository_calls(len(uncached_requests))
                wire_calls = [
                    {
                        "id": call.call_id,
                        "type": "function",
                        "function": {
                            "name": call.request.tool.value,
                            "arguments": json.dumps(asdict(call.request.arguments)),
                        },
                    }
                    for call in calls
                ]
                batch = dispatch_native_repository_calls(
                    wire_calls,
                    head_sha=request.head_sha,
                    tools=tools,
                    max_calls=min(4, turn.budget.max_repository_calls),
                    before_dispatch=cycle._check,
                    result_cache=repository_results,
                )
                for guarded in batch.results:
                    if guarded.output is not None:
                        cycle.record_context_bytes(guarded.output.byte_count)
                if not batch.is_complete:
                    return failure(tools.failure_status)
                added_history = native_repository_history(
                    batch, head_sha=request.head_sha, data_class=self._data_class
                )
                identifier = HmacContentIdentifier(self._key)
                try:
                    for entry in added_history[1:]:
                        content = str(entry["content"]).encode("utf-8")
                        content_id = identifier.identify(
                            tenant_id=request.tenant_id, payload=content
                        )
                        tool_refs[content_id] = EgressContentRef(
                            schema_version=CONTRACT_SCHEMA_VERSION,
                            content_id=content_id,
                            data_class=self._data_class,
                        )
                finally:
                    identifier.close()
                history.extend(added_history)
                seen_call_ids.update(call.call_id for call in calls)
                successful_native_inspections += len(batch.calls)
            return failure(ModelCallStatus.BUDGET_EXHAUSTED)
        except NativeDeadlineExceeded as error:
            if error.usage is not None:
                input_tokens += error.usage.input_tokens
                output_tokens += error.usage.output_tokens
            else:
                provider_usage_known = False
            return failure(ModelCallStatus.BUDGET_EXHAUSTED)
        except RepositoryContextBudgetExhausted:
            return failure(ModelCallStatus.BUDGET_EXHAUSTED)
        except Exception:
            # An adapter/executor exception after earlier measured turns means
            # the aggregate provider counters are incomplete.
            provider_usage_known = False
            return failure(
                tools.failure_status if tools.has_non_success else ModelCallStatus.PROVIDER_ERROR
            )
        finally:
            if terminal_payload is not None:
                terminal_payload.close()
            for index in range(len(seed)):
                seed[index] = 0
            history.clear()
