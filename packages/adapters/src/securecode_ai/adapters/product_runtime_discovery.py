"""Authorized product-model ports built on the existing provider harness."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from collections.abc import Callable

from securecode_ai.contracts import (
    ArtifactRef,
    DataClass,
    ModelCallResult,
    ModelCallStatus,
    ModelPurpose,
    ModelRequest,
    ModelRole,
    ModelUsage,
    SourceLocation,
)
from securecode_ai.core.model_discovery import (
    ModelNativeCandidateDraft,
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
    MODEL_NATIVE_DISCOVERY_WIRE_PIN,
    MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON,
    ModelNativeDiscoveryPayloadValidator,
)
from .product_runtime_contracts import (
    PRODUCT_DISCOVERY_PROMPT_PIN,
    DiscoveryEvidence,
    ProductDiscoveryInvocationObservation,
    RepositoryContextBudgetExhausted,
)
from .product_runtime_discovery_native import _ProductDiscoveryNativeCycle
from .product_runtime_execution import (
    AuthorizedLocalModelExecutor,
    _context,
    _non_success_result,
    _result_with_calls,
)
from .product_runtime_support import _draft

_MAX_REGENERATIONS = 2
_REGENERATE_ON = frozenset(
    {ModelCallStatus.SUCCEEDED, ModelCallStatus.INVALID_SCHEMA, ModelCallStatus.EMPTY_OUTPUT}
)


def regeneration_request(
    original: ModelRequest, *, content_key: bytes, ordinal: int = 1
) -> ModelRequest:
    """A repeated call for the same discovery request under its own keyed identity.

    Budget leases and egress authorizations are keyed by request id, so a repeated
    call needs a fresh one; the result is then bound back to ``original``.
    """
    if (
        type(original) is not ModelRequest
        or type(content_key) is not bytes
        or len(content_key) < 32
        or type(ordinal) is not int
        or not 1 <= ordinal <= _MAX_REGENERATIONS
    ):
        raise ValueError("regeneration bindings are invalid")
    material = json.dumps(
        {
            "domain": "securecode-regeneration-v1",
            "ordinal": ordinal,
            "original": original.model_dump(mode="json"),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    identity = hmac.new(content_key, material, hashlib.sha256).hexdigest()
    value = original.model_dump(mode="json")
    value["request_id"] = f"regeneration:{identity}"
    value["idempotency_key"] = f"regeneration-idempotency:{identity}"
    return ModelRequest.model_validate_json(json.dumps(value))


def _rebind_result(
    result: ModelCallResult, *, request: ModelRequest, earlier: ModelUsage
) -> ModelCallResult:
    """Report the repeated call as the original request, counting both calls' tokens."""
    value = result.model_dump(mode="json")
    value.update(
        request_id=request.request_id,
        run_id=request.run_id,
        tenant_id=request.tenant_id,
        idempotency_key=request.idempotency_key,
        attempt=request.attempt,
        provider_profile=request.provider_profile.model_dump(mode="json"),
    )
    value["usage"]["input_tokens"] += earlier.input_tokens
    value["usage"]["output_tokens"] += earlier.output_tokens
    return ModelCallResult.model_validate_json(json.dumps(value))


class ProductDiscoveryBackend(_ProductDiscoveryNativeCycle):
    """Core discovery port that reads the selected scope only after preflight."""

    __slots__ = (
        "_catalogue",
        "_data_class",
        "_executor",
        "_key",
        "_native_cycle",
        "_native_lock",
        "_native_results",
        "_observer",
        "_rule_ids",
    )

    def __init__(
        self,
        *,
        executor: AuthorizedLocalModelExecutor,
        catalogue: tuple[DiscoveryEvidence, ...],
        rule_ids: frozenset[str],
        content_key: bytes,
        native_cycle: bool = False,
        data_class: DataClass = DataClass.CONFIDENTIAL_SOURCE,
        observer: Callable[[ProductDiscoveryInvocationObservation], None] | None = None,
    ) -> None:
        if (
            type(executor) is not AuthorizedLocalModelExecutor
            or type(catalogue) is not tuple
            or not catalogue
            or len({item.evidence_id for item in catalogue}) != len(catalogue)
            or type(rule_ids) is not frozenset
            or not rule_ids
            or type(content_key) is not bytes
            or len(content_key) < 32
            or type(native_cycle) is not bool
            or type(data_class) is not DataClass
            or data_class not in {DataClass.PUBLIC, DataClass.CONFIDENTIAL_SOURCE}
            or any(
                item.source_artifact.data_class is not data_class
                or item.read_artifact.data_class is not data_class
                for item in catalogue
            )
            or (observer is not None and not callable(observer))
        ):
            raise ValueError("discovery backend is invalid")
        self._executor = executor
        self._catalogue = tuple(
            DiscoveryEvidence(
                evidence_id=item.evidence_id,
                tenant_id=item.tenant_id,
                head_sha=item.head_sha,
                location=SourceLocation.model_validate(item.location.model_dump(mode="python")),
                source_artifact=ArtifactRef.model_validate(
                    item.source_artifact.model_dump(mode="python")
                ),
                read_artifact=ArtifactRef.model_validate(
                    item.read_artifact.model_dump(mode="python")
                ),
                request=item.request,
            )
            for item in catalogue
        )
        self._data_class = data_class
        self._rule_ids = frozenset(rule_ids)
        self._key = bytes(content_key)
        self._native_cycle = native_cycle
        self._observer = observer
        self._native_lock = threading.Lock()
        self._native_results: dict[
            str, tuple[str, int, tuple[str, ...], ModelNativeDiscoveryPayload]
        ] = {}

    def with_anchors(self, anchors: tuple[DiscoveryEvidence, ...]) -> ProductDiscoveryBackend:
        """Return a backend whose seed reads ``anchors`` in place of the same evidence ids.

        The host passes anchors bound to masked windows of files with detected secrets:
        ids, locations and read requests are unchanged, only the read artifacts differ.
        """

        replacements = {anchor.evidence_id: anchor for anchor in anchors}
        if type(anchors) is not tuple or any(
            type(anchor) is not DiscoveryEvidence for anchor in anchors
        ):
            raise ValueError("discovery anchors are invalid")
        catalogue = tuple(replacements.get(item.evidence_id, item) for item in self._catalogue)
        if any(
            new.location != old.location or new.request != old.request
            for new, old in zip(catalogue, self._catalogue, strict=True)
        ):
            raise ValueError("discovery anchor replacement is invalid")
        if catalogue == self._catalogue:
            return self
        clone = object.__new__(ProductDiscoveryBackend)
        for name in self.__slots__:
            object.__setattr__(clone, name, getattr(self, name))
        clone._catalogue = catalogue
        clone._native_lock = threading.Lock()
        clone._native_results = {}
        return clone

    def discover(
        self, *, request: ModelRequest, tools: RepositoryToolSession
    ) -> ModelNativeDiscoveryPayload:
        if type(request) is not ModelRequest or type(tools) is not RepositoryToolSession:
            raise ValueError("discovery request is invalid")
        request = ModelRequest.model_validate_json(request.model_dump_json())
        started = self._executor.clock()
        if (
            request.role is not ModelRole.DISCOVERY
            or request.mode is not ModelPurpose.MODEL_NATIVE_DISCOVERY
            or request.output_schema != MODEL_NATIVE_DISCOVERY_WIRE_PIN
            or request.prompt != PRODUCT_DISCOVERY_PROMPT_PIN
            or request.evidence
            or any(
                item.tenant_id != request.tenant_id or item.head_sha != request.head_sha
                for item in self._catalogue
            )
        ):
            if self._native_cycle:
                return ModelNativeDiscoveryPayload(
                    model_result=_non_success_result(
                        request, ModelCallStatus.INVALID_SCHEMA, 0, 0, None
                    ),
                    candidates=(),
                )
            raise ValueError("discovery request bindings are invalid")
        if self._native_cycle:
            return self._discover_native(request=request, tools=tools, started=started)
        by_id = {item.evidence_id: item for item in self._catalogue}
        before_calls = tools.calls_used
        ceiling_hit = False
        validator = ModelNativeDiscoveryPayloadValidator(
            content_identifier=HmacContentIdentifier(self._key),
            rule_ids=self._rule_ids,
            evidence_ids=frozenset(by_id),
            expected_tenant_id=request.tenant_id,
            expected_head_sha=request.head_sha,
        )

        reads: list[tuple[RepositoryToolRequest, GuardedToolResult]] = []

        def build_for(active: ModelRequest) -> Callable[[], PreparedModelContext]:
            def build() -> PreparedModelContext:
                nonlocal ceiling_hit
                entries: list[tuple[str, ArtifactRef, bytes]] = []
                for item in self._catalogue:
                    cached = next(
                        (result for selected, result in reads if selected == item.request), None
                    )
                    if (
                        cached is None
                        and tools.calls_used - before_calls >= request.budget.max_repository_calls
                    ):
                        ceiling_hit = True
                        raise RepositoryContextBudgetExhausted(
                            "discovery context tool ceiling exhausted"
                        )
                    result = cached
                    if result is None:
                        result = tools.dispatch(item.request)
                        reads.append((item.request, result))
                    if result.receipt.outcome is not ToolOutcome.SUCCEEDED or result.output is None:
                        raise ValueError("required discovery evidence was not read")
                    output = result.output
                    if (
                        output.content_sha256 != item.read_artifact.content_sha256
                        or output.byte_count != item.read_artifact.size_bytes
                        or item.read_artifact.tenant_id != request.tenant_id
                        or item.tenant_id != request.tenant_id
                        or item.head_sha != request.head_sha
                        or getattr(item.request.arguments, "head_sha", None) != request.head_sha
                    ):
                        raise ValueError("discovery evidence identity mismatch")
                    entries.append((item.evidence_id, item.read_artifact, output.content.encode()))
                if tools.calls_used - before_calls > request.budget.max_repository_calls:
                    ceiling_hit = True
                    raise RepositoryContextBudgetExhausted(
                        "discovery context tool ceiling exhausted"
                    )
                return _context(
                    request=active,
                    entries=tuple(entries),
                    key=self._key,
                    role="discovery",
                    schema=MODEL_NATIVE_DISCOVERY_WIRE_SCHEMA_JSON,
                    rule_ids=tuple(sorted(self._rule_ids)),
                    locations=tuple((item.evidence_id, item.location) for item in self._catalogue),
                )

            return build

        def attempt(
            active: ModelRequest,
        ) -> tuple[ModelCallResult | None, object, tuple[ModelNativeCandidateDraft, ...] | None]:
            """One model call; drafts are None when the answer is unusable."""
            execution = self._executor.execute(
                request=active,
                validator=validator,
                context_builder=build_for(active),
                started_at=started,
            )
            drafts = None
            try:
                if (
                    execution.result is not None
                    and execution.result.model_call_status is ModelCallStatus.SUCCEEDED
                    and execution.payload is not None
                ):
                    try:
                        wire = validator.parse(execution.payload.reveal_for(active.request_id))
                        drafts = tuple(_draft(item, by_id, request) for item in wire)
                    except Exception:
                        drafts = None
            finally:
                if execution.payload is not None:
                    execution.payload.close()
            return execution.result, execution.preflight, drafts

        result, preflight, drafts = attempt(request)
        for ordinal in range(1, _MAX_REGENERATIONS + 1):
            if (
                drafts is not None
                or ceiling_hit
                or result is None
                or result.model_call_status not in _REGENERATE_ON
            ):
                break
            # A malformed answer says nothing about the code: ask again with the same
            # context under a fresh request identity, then report one call.
            earlier = result
            retry, preflight, drafts = attempt(
                regeneration_request(request, content_key=self._key, ordinal=ordinal)
            )
            result = (
                None
                if retry is None
                else _rebind_result(retry, request=request, earlier=earlier.usage)
            )
        failed = (
            drafts is None
            and result is not None
            and (result.model_call_status is ModelCallStatus.SUCCEEDED)
        )
        bound = _result_with_calls(
            result,
            tools.calls_used - before_calls,
            request=request,
            failed=failed,
            preflight=preflight,
            elapsed_ms=self._executor.elapsed_since(started),
            budget_exhausted=ceiling_hit,
        )
        if drafts is None or bound.model_call_status is not ModelCallStatus.SUCCEEDED:
            return ModelNativeDiscoveryPayload(
                model_result=bound
                if bound.model_call_status is not ModelCallStatus.SUCCEEDED
                else _result_with_calls(
                    result,
                    tools.calls_used - before_calls,
                    request=request,
                    failed=True,
                    preflight=preflight,
                    elapsed_ms=self._executor.elapsed_since(started),
                    budget_exhausted=ceiling_hit,
                ),
                candidates=(),
            )
        return ModelNativeDiscoveryPayload(model_result=bound, candidates=drafts)
